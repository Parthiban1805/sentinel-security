"""Asset graph: observed edges, documented edges, reach / reached-by, producers (v0.7c, ADR-0018)."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from sentinel.cli import main
from sentinel.inventory import graph
from sentinel.inventory.blast import blast_radius, link
from sentinel.simulation.fakes import fake_google_key
from sentinel.store.db import Store

T0 = datetime(2026, 11, 5, 9, 0, tzinfo=UTC)
DEPLOY = graph.workflow_asset_id("repo-demo", "deploy.yml")
LINT = graph.workflow_asset_id("repo-demo", "lint.yaml")
CI = graph.workflow_asset_id("repo-demo", "ci.yml")


def asset(asset_id: str, asset_type: str = "repository", importance: str = "medium", **kw: Any):
    return {
        "asset_id": asset_id,
        "asset_type": asset_type,
        "name": asset_id,
        "owner": None,
        "importance": importance,
        "monitoring": "none",
        "recovery_method": None,
        "approved": False,
        "last_seen": "2026-11-05T09:00:00Z",
        **kw,
    }


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "sentinel.db")


def edges_of(store: Store, asset_id: str) -> list[dict[str, Any]]:
    found = next(a for a in store.assets() if a["asset_id"] == asset_id)
    return sorted(found.get("access_edges", []), key=lambda e: e["target_asset_id"])


# observed edges ------------------------------------------------------------------
def test_observed_edges_are_added_with_source_and_origin(store: Store) -> None:
    for a in (asset("a"), asset("b"), asset("c")):
        store.upsert_asset(a)
    result = graph.set_observed_edges(store, "a", "test_source", [("b", "x"), ("c", "y")], T0)
    assert (result.added, result.removed, result.skipped) == (2, 0, 0)
    edges = edges_of(store, "a")
    assert [e["target_asset_id"] for e in edges] == ["b", "c"]
    assert all(e["origin"] == "observed" and e["source"] == "test_source" for e in edges)
    assert all(e["last_seen"] == "2026-11-05T09:00:00Z" for e in edges)


def test_producer_replaces_only_its_own_observed_edges(store: Store) -> None:
    documented = {"target_asset_id": "b", "permission": "admin", "origin": "documented"}
    other = {"target_asset_id": "c", "permission": "x", "origin": "observed", "source": "other"}
    store.upsert_asset(asset("a", access_edges=[documented, other]))
    for a in (asset("b"), asset("c"), asset("d")):
        store.upsert_asset(a)
    graph.set_observed_edges(store, "a", "mine", [("d", "x")], T0)
    result = graph.set_observed_edges(store, "a", "mine", [], T0 + timedelta(hours=1))
    assert result.removed == 1
    edges = edges_of(store, "a")
    assert documented in edges and other in edges
    assert not any(e.get("source") == "mine" for e in edges)


def test_edge_to_unknown_asset_is_skipped_never_invented(store: Store) -> None:
    store.upsert_asset(asset("a"))
    result = graph.set_observed_edges(store, "a", "mine", [("ghost", "x")], T0)
    assert result.skipped == 1 and result.added == 0
    assert edges_of(store, "a") == []
    assert {a["asset_id"] for a in store.assets()} == {"a"}


def test_observed_edges_on_unknown_asset_raise(store: Store) -> None:
    with pytest.raises(KeyError):
        graph.set_observed_edges(store, "nope", "mine", [], T0)


def test_unchanged_refresh_writes_no_audit_entry(store: Store) -> None:
    store.upsert_asset(asset("a"))
    store.upsert_asset(asset("b"))
    graph.set_observed_edges(store, "a", "mine", [("b", "x")], T0)
    before = len(store.audit())
    graph.set_observed_edges(store, "a", "mine", [("b", "x")], T0 + timedelta(hours=1))
    assert len(store.audit()) == before
    assert edges_of(store, "a")[0]["last_seen"] == "2026-11-05T10:00:00Z"  # seen again


# documented edges ----------------------------------------------------------------
def test_documented_edge_is_audited(store: Store) -> None:
    store.upsert_asset(asset("a"))
    store.upsert_asset(asset("b"))
    graph.add_documented_edge(store, "a", "b", "deploys", "Parthiban", T0)
    edge = edges_of(store, "a")[0]
    assert edge["origin"] == "documented" and edge["permission"] == "deploys"
    assert edge["source"] == "human"
    last = store.audit()[-1]
    assert last["action"] == "edge_add" and last["actor"] == "Parthiban"


def test_documented_edge_refuses_credential_shaped_text(store: Store) -> None:
    store.upsert_asset(asset("a"))
    store.upsert_asset(asset("b"))
    with pytest.raises(ValueError):
        graph.add_documented_edge(store, "a", "b", fake_google_key(), "Parthiban", T0)
    assert edges_of(store, "a") == []


def test_documented_edge_needs_known_assets(store: Store) -> None:
    store.upsert_asset(asset("a"))
    with pytest.raises(KeyError):
        graph.add_documented_edge(store, "a", "ghost", "x", "Parthiban", T0)


def test_documented_edge_is_not_removed_by_a_producer(store: Store) -> None:
    store.upsert_asset(asset("a"))
    store.upsert_asset(asset("b"))
    graph.add_documented_edge(store, "a", "b", "deploys", "Parthiban", T0)
    graph.set_observed_edges(store, "a", "human", [], T0)  # even a producer named "human"
    assert len(edges_of(store, "a")) == 1


# reach / reached-by --------------------------------------------------------------
def chain(store: Store) -> None:
    """a -documented-> b -observed-> c -observed-> d, plus a cycle d -> a."""
    store.upsert_asset(
        asset(
            "a", access_edges=[{"target_asset_id": "b", "permission": "p1", "origin": "documented"}]
        )
    )
    store.upsert_asset(
        asset(
            "b",
            "ci_workflow",
            access_edges=[{"target_asset_id": "c", "permission": "p2", "origin": "observed"}],
        )
    )
    store.upsert_asset(
        asset(
            "c",
            "cloud_account",
            "critical",
            access_edges=[{"target_asset_id": "d", "permission": "p3", "origin": "observed"}],
        )
    )
    store.upsert_asset(
        asset(
            "d", access_edges=[{"target_asset_id": "a", "permission": "p4", "origin": "observed"}]
        )
    )


def test_reach_walks_paths_with_basis_labels(store: Store) -> None:
    chain(store)
    result = graph.reach(store, "a")
    nodes = {n["asset_id"]: n for n in result["nodes"]}
    assert list(nodes) == ["b", "c", "d"]  # sorted by depth; the start is not listed; cycle safe
    assert nodes["b"]["basis"] == "documented" and nodes["b"]["depth"] == 1
    assert nodes["c"]["basis"] == "mixed" and nodes["c"]["path"] == ["a", "b", "c"]
    assert nodes["c"]["permission"] == "p2" and nodes["c"]["via"] == "b"
    assert result["max_importance"] == "critical"
    assert result["truncated"] is False
    assert result["hypothesis"] is True


def test_reach_respects_depth_limit(store: Store) -> None:
    chain(store)
    result = graph.reach(store, "a", max_depth=1)
    assert [n["asset_id"] for n in result["nodes"]] == ["b"]
    assert result["truncated"] is True


def test_reach_lists_dangling_edges(store: Store) -> None:
    store.upsert_asset(
        asset(
            "a",
            access_edges=[{"target_asset_id": "gone", "permission": "x", "origin": "documented"}],
        )
    )
    result = graph.reach(store, "a")
    assert result["nodes"] == [] and result["dangling"] == ["gone"]


def test_reached_by_walks_backwards(store: Store) -> None:
    chain(store)
    result = graph.reached_by(store, "c")
    nodes = {n["asset_id"]: n for n in result["nodes"]}
    assert nodes["b"]["depth"] == 1 and nodes["a"]["depth"] == 2
    assert nodes["a"]["path"] == ["a", "b", "c"]  # path reads in the direction of access
    assert nodes["d"]["depth"] == 3


def test_reach_from_a_credential_starts_at_its_links(store: Store) -> None:
    chain(store)
    link(store, "cred-fp-abcd1234", "b", "read", "Parthiban", T0)
    result = graph.reach(store, "cred-fp-abcd1234")
    ids = [n["asset_id"] for n in result["nodes"]]
    assert ids[0] == "b" and "c" in ids
    first = result["nodes"][0]
    assert first["basis"] == "documented" and first["permission"] == "read"


def test_reach_unknown_start_raises(store: Store) -> None:
    with pytest.raises(KeyError):
        graph.reach(store, "nothing-here")


def test_reach_is_deterministic(store: Store) -> None:
    chain(store)
    assert graph.reach(store, "a") == graph.reach(store, "a")


# producers -----------------------------------------------------------------------
def write_workflow(repo: Path, name: str, text: str) -> None:
    folder = repo / ".github" / "workflows"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / name).write_text(text, encoding="utf-8")


def test_agent_edges_point_at_registered_servers(store: Store) -> None:
    store.upsert_asset(asset("agent-claude-code-x", "ai_agent"))
    store.upsert_asset(asset("mcp-github", "mcp_server"))
    result = graph.refresh_agent_edges(store, "agent-claude-code-x", ["mcp-github", "mcp-gone"], T0)
    assert result.added == 1 and result.skipped == 1
    edge = edges_of(store, "agent-claude-code-x")[0]
    assert edge == {
        "target_asset_id": "mcp-github",
        "permission": "can_call",
        "origin": "observed",
        "source": "mcp_config",
        "last_seen": "2026-11-05T09:00:00Z",
    }


def test_workflows_become_assets_with_secret_names_only(store: Store, tmp_path: Path) -> None:
    repo = tmp_path / "demo"
    fake = fake_google_key()  # a literal value in a workflow must never reach the store
    write_workflow(
        repo,
        "deploy.yml",
        "jobs:\n  d:\n    steps:\n"
        "      - run: echo ${{ secrets.GEMINI_API_KEY }}\n"
        "      - run: echo ${{ secrets['DEPLOY_TOKEN'] }}\n"
        "      - run: echo ${{ secrets.GITHUB_TOKEN }}\n"
        f"        env:\n          INLINE: {fake}\n",
    )
    write_workflow(repo, "lint.yaml", "jobs:\n  l:\n    steps:\n      - run: ruff check .\n")
    store.upsert_asset(asset("repo-demo", attributes={"path": str(repo)}))

    scan = graph.discover_workflows(store, "repo-demo", repo, T0)

    assert scan.workflows == [DEPLOY, LINT]
    assets = {a["asset_id"]: a for a in store.assets()}
    deploy = assets[DEPLOY]
    assert deploy["asset_type"] == "ci_workflow" and deploy["owner"] is None
    assert deploy["attributes"]["secret_refs"] == ["DEPLOY_TOKEN", "GEMINI_API_KEY"]
    assert deploy["attributes"]["uses_github_token"] is True
    assert deploy["attributes"]["file"] == ".github/workflows/deploy.yml"
    assert deploy["importance"] == "high"  # references secrets
    assert assets[LINT]["importance"] == "medium"
    targets = [e["target_asset_id"] for e in edges_of(store, "repo-demo")]
    assert targets == [DEPLOY, LINT]
    assert all(e["permission"] == "runs_workflow" for e in edges_of(store, "repo-demo"))
    dump = json.dumps(store.assets()) + json.dumps(store.audit())
    assert fake not in dump and fake[:12] not in dump


def test_credential_shaped_secret_name_is_dropped(store: Store, tmp_path: Path) -> None:
    repo = tmp_path / "demo"
    weird = "A1b2" + fake_google_key()[4:].replace("-", "_")  # high-entropy "name"
    write_workflow(
        repo, "ci.yml", f"run: echo ${{{{ secrets.{weird} }}}} ${{{{ secrets.OK_NAME }}}}\n"
    )
    store.upsert_asset(asset("repo-demo", attributes={"path": str(repo)}))
    scan = graph.discover_workflows(store, "repo-demo", repo, T0)
    wf = next(a for a in store.assets() if a["asset_id"] == CI)
    assert wf["attributes"]["secret_refs"] == ["OK_NAME"]
    assert scan.dropped_names == 1
    assert weird not in json.dumps(store.assets())


def test_removed_workflow_loses_its_edge(store: Store, tmp_path: Path) -> None:
    repo = tmp_path / "demo"
    write_workflow(repo, "ci.yml", "run: true\n")
    store.upsert_asset(asset("repo-demo", attributes={"path": str(repo)}))
    graph.discover_workflows(store, "repo-demo", repo, T0)
    (repo / ".github" / "workflows" / "ci.yml").unlink()
    graph.discover_workflows(store, "repo-demo", repo, T0 + timedelta(days=1))
    assert edges_of(store, "repo-demo") == []
    assert any(a["asset_id"] == CI for a in store.assets())  # asset kept


def test_workflow_rediscovery_keeps_human_settings(store: Store, tmp_path: Path) -> None:
    repo = tmp_path / "demo"
    write_workflow(repo, "ci.yml", "run: true\n")
    store.upsert_asset(asset("repo-demo", attributes={"path": str(repo)}))
    graph.discover_workflows(store, "repo-demo", repo, T0)
    wf = next(a for a in store.assets() if a["asset_id"] == CI)
    store.upsert_asset({**wf, "owner": "Parthiban", "approved": True, "importance": "critical"})
    graph.discover_workflows(store, "repo-demo", repo, T0 + timedelta(days=1))
    wf = next(a for a in store.assets() if a["asset_id"] == CI)
    assert (wf["owner"], wf["approved"], wf["importance"]) == ("Parthiban", True, "critical")


def test_oversized_workflow_is_skipped(store: Store, tmp_path: Path) -> None:
    repo = tmp_path / "demo"
    write_workflow(repo, "big.yml", "#" * (graph.MAX_WORKFLOW_BYTES + 1))
    store.upsert_asset(asset("repo-demo", attributes={"path": str(repo)}))
    scan = graph.discover_workflows(store, "repo-demo", repo, T0)
    assert scan.workflows == [] and scan.skipped_files == 1


def test_blast_radius_now_follows_observed_edges(store: Store, tmp_path: Path) -> None:
    repo = tmp_path / "demo"
    write_workflow(repo, "ci.yml", "run: echo ${{ secrets.X }}\n")
    store.upsert_asset(asset("repo-demo", attributes={"path": str(repo)}))
    graph.discover_workflows(store, "repo-demo", repo, T0)
    link(store, "cred-fp-abcd1234", "repo-demo", "read", "Parthiban", T0)
    possible = blast_radius(store, "cred-fp-abcd1234")["possible_access"]
    assert [p["asset_id"] for p in possible] == [CI]
    assert possible[0]["origin"] == "observed"


# CLI -----------------------------------------------------------------------------
def test_cli_graph_refresh_and_reach(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = tmp_path / "home"
    home.mkdir()
    store = Store(home / "sentinel.db")
    repo = tmp_path / "demo"
    write_workflow(repo, "ci.yml", "run: echo ${{ secrets.X }}\n")
    store.upsert_asset(asset("repo-demo", attributes={"path": str(repo)}))

    assert main(["--home", str(home), "graph", "refresh"]) == 0
    out = capsys.readouterr().out
    assert "repo-demo: 1 workflow(s)" in out

    assert main(["--home", str(home), "graph", "reach", "repo-demo"]) == 0
    out = capsys.readouterr().out
    assert CI in out and "observed" in out and "hypothesis" in out

    assert main(["--home", str(home), "graph", "reached-by", CI, "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert [n["asset_id"] for n in data["nodes"]] == ["repo-demo"]


def test_cli_inventory_edge(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = tmp_path / "home"
    home.mkdir()
    store = Store(home / "sentinel.db")
    store.upsert_asset(asset("a"))
    store.upsert_asset(asset("b"))
    args = ["--home", str(home), "inventory", "edge", "a", "b", "--permission", "deploys"]
    assert main([*args, "--actor", "Parthiban"]) == 0
    assert "documented" in capsys.readouterr().out
    assert edges_of(store, "a")[0]["origin"] == "documented"


# review fixes (2026-11-05 security review of ADR-0018) ------------------------------
def demo_repo(store: Store, tmp_path: Path, asset_id: str = "repo-demo") -> Path:
    repo = tmp_path / asset_id
    (repo / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    store.upsert_asset(asset(asset_id, attributes={"path": str(repo)}))
    return repo


def test_hostile_workflow_text_is_scanned_in_linear_time(store: Store, tmp_path: Path) -> None:
    import time

    repo = demo_repo(store, tmp_path)
    budget = graph.MAX_WORKFLOW_BYTES - 10
    write_workflow(repo, "a.yml", "${{" * (budget // 3))  # no closing braces at all
    write_workflow(repo, "b.yml", ("${{ x " + "}" * 1) * (budget // 7))  # unbalanced
    write_workflow(repo, "c.yml", "secrets." * (budget // 8))  # no expression
    started = time.monotonic()
    scan = graph.discover_workflows(store, "repo-demo", repo, T0)
    assert time.monotonic() - started < 5
    assert len(scan.workflows) == 3


def test_all_secrets_patterns_raise_importance(store: Store, tmp_path: Path) -> None:
    repo = demo_repo(store, tmp_path)
    write_workflow(
        repo, "call.yml", "jobs:\n  c:\n    uses: ./.github/x.yml\n    secrets: inherit\n"
    )
    write_workflow(repo, "dump.yml", "run: echo '${{ toJSON(secrets) }}'\n")
    write_workflow(repo, "none.yml", "run: echo secrets are fine\n")
    graph.discover_workflows(store, "repo-demo", repo, T0)
    found = {a["asset_id"]: a for a in store.assets()}
    for name in ("call.yml", "dump.yml"):
        wf = found[graph.workflow_asset_id("repo-demo", name)]
        assert wf["attributes"]["uses_all_secrets"] is True and wf["importance"] == "high"
    none = found[graph.workflow_asset_id("repo-demo", "none.yml")]
    assert none["attributes"]["uses_all_secrets"] is False and none["importance"] == "medium"


def test_similar_file_names_and_repos_never_share_an_id(store: Store, tmp_path: Path) -> None:
    ids = {
        graph.workflow_asset_id("repo-demo", "deploy.yml"),
        graph.workflow_asset_id("repo-demo", "deploy_.yml"),
        graph.workflow_asset_id("repo-demo", "deploy-.yml"),
        graph.workflow_asset_id("repo-a", "b-ci.yml"),
        graph.workflow_asset_id("repo-a-b", "ci.yml"),
    }
    assert len(ids) == 5
    repo = demo_repo(store, tmp_path)
    write_workflow(repo, "deploy.yml", "run: echo ${{ secrets.REAL }}\n")
    write_workflow(repo, "deploy_.yml", "run: true\n")
    graph.discover_workflows(store, "repo-demo", repo, T0)
    real = next(a for a in store.assets() if a["asset_id"] == DEPLOY)
    assert real["attributes"]["secret_refs"] == ["REAL"]


def test_existing_asset_with_the_id_is_never_taken_over(store: Store, tmp_path: Path) -> None:
    repo = demo_repo(store, tmp_path)
    write_workflow(repo, "ci.yml", "run: true\n")
    store.upsert_asset(asset(CI, "database", "critical", owner="Parthiban", approved=True))
    scan = graph.discover_workflows(store, "repo-demo", repo, T0)
    assert scan.collisions == 1 and scan.workflows == []
    kept = next(a for a in store.assets() if a["asset_id"] == CI)
    assert kept["asset_type"] == "database"
    assert any("collision" in w for w in scan.warnings())


def test_only_yml_and_yaml_count_as_workflows(store: Store, tmp_path: Path) -> None:
    repo = demo_repo(store, tmp_path)
    for name in ("x.yhtml", "a.y.xml", "notes.txt", "ok.YML"):
        write_workflow(repo, name, "run: true\n")
    scan = graph.discover_workflows(store, "repo-demo", repo, T0)
    assert scan.workflows == [graph.workflow_asset_id("repo-demo", "ok.YML")]


def test_workflow_file_count_is_capped(
    store: Store, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(graph, "MAX_WORKFLOW_FILES", 3)
    repo = demo_repo(store, tmp_path)
    for i in range(5):
        write_workflow(repo, f"w{i}.yml", "run: true\n")
    scan = graph.discover_workflows(store, "repo-demo", repo, T0)
    assert len(scan.workflows) == 3
    assert scan.over_cap is True  # listing stopped one past the cap
    assert any("more than 3 workflow files" in w for w in scan.warnings())


def test_credential_shaped_file_name_is_skipped(store: Store, tmp_path: Path) -> None:
    repo = demo_repo(store, tmp_path)
    name = fake_google_key() + ".yml"
    write_workflow(repo, name, "run: true\n")
    scan = graph.discover_workflows(store, "repo-demo", repo, T0)
    assert scan.workflows == [] and scan.skipped_files == 1
    assert name[:12] not in json.dumps(store.assets())


def _link_dir(link: Path, target: Path) -> None:
    """A directory link: a junction on Windows (no privilege needed), else a symlink."""
    import os

    try:
        if os.name == "nt":
            import _winapi  # private module: skip rather than fail if a Python upgrade drops it

            _winapi.CreateJunction(str(target), str(link))
        else:
            link.symlink_to(target, target_is_directory=True)
    except (ImportError, AttributeError, OSError):
        pytest.skip("cannot create a directory link on this machine")


@pytest.mark.parametrize("linked", [".github", "workflows"])
def test_linked_folder_out_of_the_repo_is_not_followed(
    store: Store, tmp_path: Path, linked: str
) -> None:
    outside = tmp_path / "outside"
    (outside / "workflows").mkdir(parents=True)
    (outside / "workflows" / "evil.yml").write_text("run: ${{ secrets.OUTSIDE }}\n", "utf-8")
    write_workflow(outside, "evil.yml", "run: ${{ secrets.OUTSIDE }}\n")
    repo = tmp_path / "repo-demo"
    repo.mkdir()
    store.upsert_asset(asset("repo-demo", attributes={"path": str(repo)}))
    if linked == ".github":
        _link_dir(repo / ".github", outside / ".github")
    else:
        (repo / ".github").mkdir()
        _link_dir(repo / ".github" / "workflows", outside / "workflows")
    scan = graph.discover_workflows(store, "repo-demo", repo, T0)
    assert scan.workflows == [] and scan.skipped_files >= 1
    assert "OUTSIDE" not in json.dumps(store.assets())


def test_linked_workflow_file_is_not_followed(store: Store, tmp_path: Path) -> None:
    outside = tmp_path / "outside.yml"
    outside.write_text("run: ${{ secrets.OUTSIDE }}\n", "utf-8")
    repo = demo_repo(store, tmp_path)
    try:
        (repo / ".github" / "workflows" / "evil.yml").symlink_to(outside)
    except OSError:
        pytest.skip("this OS account cannot create file symlinks")
    scan = graph.discover_workflows(store, "repo-demo", repo, T0)
    assert scan.workflows == [] and scan.skipped_files == 1


def test_reached_by_lists_linked_credentials(store: Store) -> None:
    chain(store)
    link(store, "cred-fp-abcd1234", "b", "read", "Parthiban", T0)
    result = graph.reached_by(store, "c")
    cred = next(n for n in result["nodes"] if n["asset_id"] == "cred-fp-abcd1234")
    assert cred["asset_type"] == "credential" and cred["importance"] is None
    assert cred["path"] == ["cred-fp-abcd1234", "b", "c"]
    assert cred["origin"] == "documented"  # the link a person confirmed
    assert cred["basis"] == "mixed"  # b -> c is observed


def test_reached_by_a_credential_says_why(store: Store) -> None:
    chain(store)
    link(store, "cred-fp-abcd1234", "b", "read", "Parthiban", T0)
    with pytest.raises(KeyError, match="is a credential"):
        graph.reached_by(store, "cred-fp-abcd1234")


def test_dangling_edge_past_the_limit_is_not_truncation(store: Store) -> None:
    store.upsert_asset(
        asset("a", access_edges=[{"target_asset_id": "b", "permission": "x", "origin": "observed"}])
    )
    store.upsert_asset(
        asset(
            "b", access_edges=[{"target_asset_id": "gone", "permission": "x", "origin": "observed"}]
        )
    )
    result = graph.reach(store, "a", max_depth=1)
    assert result["truncated"] is False and result["dangling"] == ["gone"]


def test_documented_edge_wins_the_shown_path(store: Store) -> None:
    store.upsert_asset(asset("b"))
    store.upsert_asset(
        asset(
            "a",
            access_edges=[
                {"target_asset_id": "b", "permission": "x", "origin": "observed", "source": "s"},
                {"target_asset_id": "b", "permission": "x", "origin": "documented"},
            ],
        )
    )
    assert graph.reach(store, "a")["nodes"][0]["basis"] == "documented"


def test_agent_edge_is_dropped_when_server_leaves_config(store: Store) -> None:
    store.upsert_asset(asset("agent-claude-code-x", "ai_agent"))
    store.upsert_asset(asset("mcp-github", "mcp_server"))
    graph.refresh_agent_edges(store, "agent-claude-code-x", ["mcp-github"], T0)
    result = graph.refresh_agent_edges(store, "agent-claude-code-x", [], T0)
    assert result.removed == 1 and edges_of(store, "agent-claude-code-x") == []


def test_cli_output_never_carries_a_value_from_a_workflow(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    store = Store(home / "sentinel.db")
    repo = demo_repo(store, tmp_path)
    fake = fake_google_key()
    write_workflow(repo, "ci.yml", f"env:\n  K: {fake}\nrun: echo ${{{{ secrets.X }}}}\n")
    for argv in (["graph", "refresh"], ["graph", "reach", "repo-demo"]):
        assert main(["--home", str(home), *argv]) == 0
    assert main(["--home", str(home), "graph", "reach", "repo-demo", "--json"]) == 0
    out = capsys.readouterr().out
    assert fake not in out and fake[:12] not in out


# re-review fixes ---------------------------------------------------------------------
def test_unclosed_opener_cannot_hide_a_real_reference(store: Store, tmp_path: Path) -> None:
    repo = demo_repo(store, tmp_path)
    padding = "x" * (graph.MAX_EXPRESSION_CHARS + 10)
    write_workflow(repo, "ci.yml", f"# ${{{{ {padding}\nrun: echo ${{{{ secrets.REAL }}}}\n")
    graph.discover_workflows(store, "repo-demo", repo, T0)
    wf = next(a for a in store.assets() if a["asset_id"] == CI)
    assert wf["attributes"]["secret_refs"] == ["REAL"]


def test_padded_inherit_line_is_still_seen(store: Store, tmp_path: Path) -> None:
    repo = demo_repo(store, tmp_path)
    pad = " " * (graph.MAX_EXPRESSION_CHARS + 10)
    write_workflow(repo, "ci.yml", f"jobs:\n  c:\n{pad}secrets: inherit  # {'y' * 3000}\n")
    graph.discover_workflows(store, "repo-demo", repo, T0)
    wf = next(a for a in store.assets() if a["asset_id"] == CI)
    assert wf["attributes"]["uses_all_secrets"] is True


def test_oversize_expression_is_counted_and_warned(store: Store, tmp_path: Path) -> None:
    repo = demo_repo(store, tmp_path)
    body = " secrets.HIDDEN " + "z" * (graph.MAX_EXPRESSION_CHARS + 10)
    write_workflow(repo, "ci.yml", f"run: ${{{{{body}}}}}\n")
    scan = graph.discover_workflows(store, "repo-demo", repo, T0)
    assert scan.unscanned_expressions == 1
    assert any("may be missing" in w for w in scan.warnings())


def test_changed_workflow_loses_its_approval(store: Store, tmp_path: Path) -> None:
    repo = demo_repo(store, tmp_path)
    write_workflow(repo, "ci.yml", "run: true\n")
    graph.discover_workflows(store, "repo-demo", repo, T0)
    wf = next(a for a in store.assets() if a["asset_id"] == CI)
    store.upsert_asset({**wf, "approved": True, "owner": "Parthiban"})
    graph.discover_workflows(store, "repo-demo", repo, T0)  # unchanged: approval kept
    assert next(a for a in store.assets() if a["asset_id"] == CI)["approved"] is True
    write_workflow(repo, "ci.yml", "run: echo changed\n")
    graph.discover_workflows(store, "repo-demo", repo, T0 + timedelta(hours=1))
    wf = next(a for a in store.assets() if a["asset_id"] == CI)
    assert wf["approved"] is False and wf["owner"] == "Parthiban"
    assert any(e["action"] == "workflow_approval_cleared" for e in store.audit())
