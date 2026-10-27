"""Exposure probes (S1/S15): real local HTTP servers; signatures, safety, state, R10, auto-verification."""

import http.server
import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sentinel import config, coverage, probes, runner
from sentinel.cli import main
from sentinel.config import Settings
from sentinel.incidents import lifecycle
from sentinel.simulation import scenarios
from sentinel.simulation.fakes import fake_google_key
from sentinel.store.db import Store

NOW = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)
FAKE_SECRET = fake_google_key()  # inside the served files: must never leak into anything we keep

ENV_BODY = f"GEMINI_API_KEY={FAKE_SECRET}\nDB_HOST=localhost\n".encode()
GIT_CONFIG = b"[core]\n\trepositoryformatversion = 0\n"
SQL_DUMP = b"-- MySQL dump 10.13\nCREATE TABLE users (id int);\n"
ZIP = b"PK\x03\x04" + b"\x00" * 40
SQLITE = b"SQLite format 3\x00" + b"\x00" * 40
SPA_HTML = b"<!doctype html><html><body>single page app</body></html>"


class Handler(http.server.BaseHTTPRequestHandler):
    routes: dict[str, tuple[int, bytes]]
    catch_all: bytes | None
    redirect_to: str | None
    hits: list[str]
    ranges: list[str | None]

    def do_GET(self) -> None:
        self.hits.append(self.path)
        self.ranges.append(self.headers.get("Range"))
        if self.redirect_to:
            self.send_response(302)
            self.send_header("Location", self.redirect_to)
            self.end_headers()
            return
        status, body = self.routes.get(self.path, (404, b""))
        if status == 404 and self.catch_all is not None:
            status, body = 200, self.catch_all  # SPA-style: 200 for everything
        self.send_response(status)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:  # silence
        pass


@dataclass
class Srv:
    url: str
    handler: type[Handler]

    @property
    def routes(self) -> dict[str, tuple[int, bytes]]:
        return self.handler.routes  # mutate in place to "fix" or "break" the host live


@contextmanager
def serve(
    routes: dict[str, tuple[int, bytes]] | None = None,
    catch_all: bytes | None = None,
    redirect_to: str | None = None,
) -> Iterator[Srv]:
    handler = type(
        "H",
        (Handler,),
        {
            "routes": dict(routes or {}),
            "catch_all": catch_all,
            "redirect_to": redirect_to,
            "hits": [],
            "ranges": [],
        },
    )
    server = http.server.HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield Srv(f"http://127.0.0.1:{server.server_port}", handler)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def probe_paths(base: str) -> dict[str, probes.Exposure]:
    found, _reachable = probes.probe_host(base, probes.make_fetcher(allow_http=True), pause=0)
    return {e.path: e for e in found}


FETCH = probes.make_fetcher(allow_http=True, timeout=2.0)


# signatures and detection --------------------------------------------------------------------------
def test_exposed_files_are_detected_by_shape() -> None:
    routes = {
        "/.env": (200, ENV_BODY),
        "/.git/config": (200, GIT_CONFIG),
        "/backup.sql": (200, SQL_DUMP),
        "/backup.zip": (200, ZIP),
        "/db.sqlite": (200, SQLITE),
    }
    with serve(routes) as srv:
        found = probe_paths(srv.url)
    assert set(found) == {"/.env", "/.git/config", "/backup.sql", "/backup.zip", "/db.sqlite"}
    assert found["/.env"].severity == "critical" and found["/.env"].scenario == "S1"
    assert found["/backup.sql"].scenario == "S15" and found["/.git/config"].severity == "high"


def test_clean_host_has_no_findings_and_only_the_fixed_paths_are_requested() -> None:
    with serve() as srv:
        assert probe_paths(srv.url) == {}
        requested = list(srv.handler.hits)
        ranges = set(srv.handler.ranges)
    assert sorted(requested) == sorted(p.path for p in probes.PROBES)  # nothing else, no crawling
    assert ranges == {f"bytes=0-{probes.MAX_BYTES - 1}"}  # only the first bytes are asked for


def test_catch_all_spa_does_not_cause_false_positives() -> None:
    """A host that answers 200 + HTML for every path must not look exposed."""
    with serve(catch_all=SPA_HTML) as srv:
        assert probe_paths(srv.url) == {}


@pytest.mark.parametrize("status", [401, 403, 404, 410, 500])
def test_error_statuses_are_never_exposure(status: int) -> None:
    with serve({"/.env": (status, ENV_BODY)}) as srv:
        assert "/.env" not in probe_paths(srv.url)


def test_env_shape_requires_real_lines_not_html() -> None:
    assert probes._env_like(b"KEY=value\nexport OTHER=1\n# comment\n")
    assert not probes._env_like(b"<html><body>KEY=value</body></html>")
    assert not probes._env_like(b"just some prose without assignments\n")
    assert not probes._env_like(b"")


def test_redirects_are_never_followed() -> None:
    with serve({"/.env": (200, ENV_BODY)}) as target:
        with serve(redirect_to=target.url + "/.env") as redirecting:
            assert probe_paths(redirecting.url) == {}  # a 302 is not an exposure
        assert target.handler.hits == []  # the redirect target was never contacted


def test_only_the_first_bytes_are_read() -> None:
    with serve({"/.env": (200, ENV_BODY * 100)}) as srv:
        result = FETCH(srv.url + "/.env")
    assert result.status == 200 and len(result.body) <= probes.MAX_BYTES


def test_a_silent_host_is_abandoned_after_a_few_requests() -> None:
    calls: list[str] = []

    def dead(url: str) -> probes.Fetch:
        calls.append(url)
        return probes.Fetch(None, b"", "TimeoutError")

    found, reachable = probes.probe_host("https://down.invalid", dead, pause=0)
    assert found == [] and reachable is False and len(calls) == probes.MAX_SILENT  # not 22 timeouts


def test_a_host_that_answers_late_is_still_fully_probed() -> None:
    answers = iter([None, None] + [404] * 40)  # two misses, then it answers: keep going

    def flaky(url: str) -> probes.Fetch:
        status = next(answers)
        return probes.Fetch(status, b"", None if status else "TimeoutError")

    found, reachable = probes.probe_host("https://flaky.invalid", flaky, pause=0)
    assert reachable is True and found == []


def test_unreachable_host_is_inconclusive_not_clear() -> None:
    found, reachable = probes.probe_host("http://127.0.0.1:9", FETCH, pause=0, only=("X01", "X05"))
    assert found == [] and reachable is False
    state, status = probes.reprobe("http://127.0.0.1:9", "/.env", FETCH)
    assert state == "inconclusive" and status is None


# target validation (safety) -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com",
        "http://example.com",  # needs allow_http
        "https://user:pass@example.com",
        "https://example.com/some/path",
        "https://example.com?x=1",
        "https://example.com:99999",
        "https:///nohost",
        "https://169.254.169.254",  # cloud metadata
        "",
    ],
)
def test_unsafe_targets_are_refused(url: str) -> None:
    with pytest.raises(probes.ProbeError):
        probes.normalize_target(url)


def test_valid_targets() -> None:
    assert probes.normalize_target("https://example.com/") == "https://example.com"
    assert probes.normalize_target("https://example.com:8443") == "https://example.com:8443"
    assert probes.normalize_target("http://127.0.0.1:80", allow_http=True) == "http://127.0.0.1:80"
    assert probes.asset_id_for_host("https://Example.com:8443") == "host-example-com-8443"


def test_probe_list_is_fixed_small_and_has_no_literal_key_header() -> None:
    assert len(probes.PROBES) <= 25 and len({p.id for p in probes.PROBES}) == len(probes.PROBES)
    source = Path(probes.__file__).read_text(encoding="utf-8")
    header = "BEGIN " + "RSA PRIVATE KEY"  # built at runtime: no literal key header on disk
    assert header not in source


# config: ownership must be confirmed ---------------------------------------------------------------------
def test_config_requires_ownership_confirmation(tmp_path: Path) -> None:
    cfg = tmp_path / "c.toml"
    cfg.write_text('[[probes.hosts]]\nurl = "https://example.com"\n')
    with pytest.raises(ValueError, match="confirm_ownership"):
        config.load(cfg)
    cfg.write_text('[[probes.hosts]]\nurl = "https://example.com"\nconfirm_ownership = true\n')
    assert config.load(cfg).probe_hosts == (config.ProbeHost("https://example.com", False),)
    cfg.write_text('[[probes.hosts]]\nurl = "http://x.test"\nconfirm_ownership = true\n')
    with pytest.raises(probes.ProbeError):
        config.load(cfg)  # plain http without allow_http


# state, events, no content kept ------------------------------------------------------------------------------
def test_collect_emits_events_registers_asset_and_keeps_no_content(tmp_path: Path) -> None:
    store = Store(tmp_path / "s.db")
    with serve({"/.env": (200, ENV_BODY), "/.git/config": (200, GIT_CONFIG)}) as srv:
        events, cleared, reachable, snap = probes.collect(store, srv.url, NOW, FETCH, pause=0)
    assert reachable and cleared == []
    assert {e["attributes"]["path"] for e in events} == {"/.env", "/.git/config"}
    assert all(store.add_event(e) for e in events)
    assert any(a["asset_type"] == "server" and a["owner"] is None for a in store.assets())
    blob = json.dumps(events) + json.dumps(snap) + json.dumps(store.assets())
    assert FAKE_SECRET not in blob and "DB_HOST" not in blob  # content never kept


def test_rerun_is_idempotent_and_cleared_exposures_are_reported(tmp_path: Path) -> None:
    store = Store(tmp_path / "s.db")
    with serve({"/.env": (200, ENV_BODY)}) as srv:
        events, _, _, snap = probes.collect(store, srv.url, NOW, FETCH, pause=0)
        assert sum(store.add_event(e) for e in events) == 1
        store.put_doc("snapshots", probes.snapshot_key(srv.url), snap)
        events, _, _, snap = probes.collect(store, srv.url, NOW, FETCH, pause=0)
        assert sum(store.add_event(e) for e in events) == 0  # deterministic ids: no duplicates
        store.put_doc("snapshots", probes.snapshot_key(srv.url), snap)
        srv.routes.pop("/.env")  # the owner fixes it
        events, cleared, reachable, _ = probes.collect(store, srv.url, NOW, FETCH, pause=0)
    assert events == [] and cleared == ["/.env"] and reachable


def test_an_unreachable_host_does_not_clear_previous_exposures(tmp_path: Path) -> None:
    store = Store(tmp_path / "s.db")
    store.put_doc(
        "snapshots", probes.snapshot_key("http://127.0.0.1:9"), {"exposed": ["/.env"], "time": "t"}
    )
    _, cleared, reachable, snap = probes.collect(store, "http://127.0.0.1:9", NOW, FETCH, pause=0)
    assert (
        not reachable and cleared == [] and snap["exposed"] == ["/.env"]
    )  # silence proves nothing


def test_run_gates_by_interval_and_reports_unreachable_hosts(tmp_path: Path) -> None:
    home = tmp_path / "home"
    store = Store(home / "sentinel.db")
    with serve({"/.env": (200, ENV_BODY)}) as srv:
        settings = Settings(probe_hosts=(config.ProbeHost(srv.url, True),), probe_interval_hours=24)
        first = runner.run_once(store, home, settings, NOW, scan=False, probe_pause=0)
        label = next(k for k in first["health"] if k.startswith("probes:"))
        assert first["health"][label] == "ok" and len(first["incidents_created"]) == 1
        again = runner.run_once(store, home, settings, NOW, scan=False, probe_pause=0)
        assert again["events_stored"] == 0  # inside the interval: not probed again
        assert len(srv.handler.hits) == len(probes.PROBES)  # exactly one sweep
    dead = Settings(probe_hosts=(config.ProbeHost("http://127.0.0.1:9", True),))
    res = runner.run_once(store, home, dead, NOW, scan=False, probe_pause=0)
    assert res["health"][next(k for k in res["health"] if k.startswith("probes:"))].startswith(
        "error"
    )


# R10 incident and automatic verification ---------------------------------------------------------------------------
def open_incident(tmp_path: Path, base: str) -> tuple[Store, str]:
    store = Store(tmp_path / "s.db")
    events, _, _, snap = probes.collect(store, base, NOW, FETCH, pause=0)
    for e in events:
        store.add_event(e)
    store.put_doc("snapshots", probes.snapshot_key(base), snap)
    [iid] = lifecycle.open_incidents(store, NOW)
    return store, iid


def test_r10_incident_has_facts_hypothesis_and_plan(tmp_path: Path) -> None:
    with serve({"/.env": (200, ENV_BODY)}) as srv:
        store, iid = open_incident(tmp_path, srv.url)
    inc = store.get_doc("incidents", iid)
    assert inc is not None and inc["rule_id"] == "R10" and inc["severity"] == "critical"
    assert inc["is_test"] is False and "no authentication" in inc["facts"][0]
    assert any("unknown" in h for h in inc["hypotheses"])
    assert "the shape of an env file" in inc["facts"][0]  # article agrees with the noun
    # Unknowns are about THIS kind of incident, not a provider-activity placeholder.
    assert any("access logs" in u for u in inc["unknowns"])
    assert not any("provider" in u for u in inc["unknowns"])
    steps = {s["step"]: s for s in inc["response_plan"]}
    assert steps["verify_path_closed"]["response_class"] == "investigate_first"
    assert steps["block_path"]["response_class"] == "approval_required"
    assert FAKE_SECRET not in json.dumps(inc)


def test_verify_probe_fails_while_exposed_and_passes_once_fixed(tmp_path: Path) -> None:
    with serve({"/.env": (200, ENV_BODY)}) as srv:
        store, iid = open_incident(tmp_path, srv.url)
        passed, evidence = runner.verify_probe(store, iid, "me", NOW, FETCH)
        assert passed is False and "STILL SERVED" in evidence
        incident = store.get_doc("incidents", iid)
        assert incident is not None
        step = next(s for s in incident["response_plan"] if s["step"] == "verify_path_closed")
        assert step["state"] == "verification_failed"  # a failed check keeps the step open

        srv.routes.pop("/.env")  # the owner removes the file
        passed, evidence = runner.verify_probe(store, iid, "me", NOW, FETCH)
        assert passed is True and "HTTP 404" in evidence and "no longer served" in evidence
        assert FAKE_SECRET not in evidence
    incident = store.get_doc("incidents", iid)
    assert incident is not None
    assert (
        next(s for s in incident["response_plan"] if s["step"] == "verify_path_closed")["state"]
        == "verified"
    )


def test_unreachable_host_cannot_verify_a_fix(tmp_path: Path) -> None:
    """A network error proves nothing: verification must FAIL, never pass."""
    with serve({"/.env": (200, ENV_BODY)}) as srv:
        store, iid = open_incident(tmp_path, srv.url)
    passed, evidence = runner.verify_probe(store, iid, "me", NOW, FETCH)  # server is gone now
    assert passed is False and "inconclusive" in evidence and "network error" in evidence


def test_incident_closes_only_after_all_required_steps_including_the_reprobe(
    tmp_path: Path,
) -> None:
    with serve({"/.env": (200, ENV_BODY)}) as srv:
        store, iid = open_incident(tmp_path, srv.url)
        lifecycle.approve(store, iid, "block_path", "me", NOW)
        lifecycle.verify(
            store, iid, "block_path", "me", NOW, passed=True, evidence="removed from web root"
        )
        lifecycle.approve(store, iid, "rotate_exposed_secrets", "me", NOW)
        lifecycle.verify(
            store, iid, "rotate_exposed_secrets", "me", NOW, passed=True, evidence="rotated all"
        )
        lifecycle.verify(
            store, iid, "review_access_logs", "me", NOW, passed=True, evidence="no foreign hits"
        )
        with pytest.raises(lifecycle.IncidentError):
            lifecycle.close(store, iid, "me", NOW)  # the re-probe has not passed yet
        srv.routes.pop("/.env")
        assert runner.verify_probe(store, iid, "me", NOW, FETCH)[0] is True
    closed = lifecycle.close(store, iid, "me", NOW)
    assert closed["verified"] is True


def test_verify_probe_is_for_r10_only(tmp_path: Path) -> None:
    store = Store(tmp_path / "s.db")
    for e in scenarios.canary("decoy", NOW):
        store.add_event(e)
    [iid] = lifecycle.open_incidents(store, NOW)
    with pytest.raises(ValueError, match="R10"):
        runner.verify_probe(store, iid, "me", NOW, FETCH)


# CLI ---------------------------------------------------------------------------------------------------------------------
def test_cli_requires_ownership_flag_and_reports(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cfg = str(tmp_path / "none.toml")
    home = str(tmp_path / "home")
    with serve({"/.env": (200, ENV_BODY)}) as srv:
        no_flag = main(["--home", home, "probe", "--url", srv.url, "--allow-http", "--config", cfg])
        assert no_flag == 1 and "i-own-this" in capsys.readouterr().err
        assert srv.handler.hits == []  # without the flag nothing was contacted
        code = main(["--home", home, "probe", "--url", srv.url, "--i-own-this", "--allow-http",
                     "--pause", "0", "--fail-on", "critical", "--record", "--config", cfg])  # fmt: skip
        out = capsys.readouterr()
        assert code == 1 and "/.env" in out.out and "CRITICAL" in out.out
        assert FAKE_SECRET not in out.out + out.err
        assert Store(Path(home) / "sentinel.db").events(event_type="exposed_service")
    assert main(["--home", home, "probe", "--config", cfg]) == 1  # nothing configured


def test_coverage_registry_knows_the_producer_and_the_auto_verifier() -> None:
    assert "exposed_service" in coverage.REAL_PRODUCERS
    report = coverage.build_report(None, set())
    assert "exposed_service" not in report["event_types_with_no_producer"]
    r10 = next(r for r in report["scenarios"] if r["rule"] == "R10")
    assert r10["logic_verified_simulated"] and r10["auto_verifiable_steps"] == 1
