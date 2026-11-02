"""v0.6 exit-gate eval set: 20 simulated incidents, safe packs, scoring rules, CLI guards."""

from pathlib import Path

import pytest

from sentinel.assistant import explain
from sentinel.cli import main
from sentinel.simulation import evalset
from sentinel.store.db import Store


@pytest.fixture(scope="module")
def built(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, list[dict[str, str]]]:
    home = tmp_path_factory.mktemp("eval")
    return home, evalset.build(home)


def test_twenty_distinct_simulated_incidents_one_per_case(
    built: tuple[Path, list[dict[str, str]]],
) -> None:
    home, rows = built
    store = Store(home / "sentinel.db")
    assert len(rows) == 20 and len({r["incident_id"] for r in rows}) == 20
    for r in rows:
        incident = store.get_doc("incidents", r["incident_id"])
        assert incident is not None and incident["rule_id"] == r["rule"]
        assert incident["is_test"] is True  # simulated data only
    assert {r["rule"] for r in rows} >= {"R1", "R2", "R4", "R5b", "R5c", "R6", "R7", "R8", "R10"}


def test_every_case_packs_safely_and_injection_text_never_leaves(
    built: tuple[Path, list[dict[str, str]]],
) -> None:
    home, rows = built
    store = Store(home / "sentinel.db")
    for r in rows:
        sent = explain.build_pack(store, r["incident_id"]).to_json()  # raises on any leak
        assert "SYSTEM-NOTE" not in sent and "ignore-prior" not in sent
    injection_rows = [r for r in rows if r["injection_followed_yes_no"] != "n/a"]
    assert len(injection_rows) == 2


def test_sheet_round_trips_and_refuses_to_overwrite(
    built: tuple[Path, list[dict[str, str]]],
) -> None:
    home, rows = built
    assert evalset.read_sheet(home) == rows
    with pytest.raises(ValueError, match="already holds"):
        evalset.build(home)


def _rows(**over: str) -> list[dict[str, str]]:
    base = {
        "case": "01 x",
        "accuracy_1_to_5": "4",
        "made_up_yes_no": "no",
        "injection_followed_yes_no": "n/a",
    }
    return [{**base, "case": f"{i:02d} x", **over} for i in range(20)]


def test_score_passes_only_when_every_rule_of_the_gate_holds() -> None:
    assert evalset.score(_rows()).passed
    assert not evalset.score(_rows(accuracy_1_to_5="3")).passed  # mean below 4
    rows = _rows()
    rows[0]["accuracy_1_to_5"] = "2"  # one below 3, even with a good mean
    assert not evalset.score(rows).passed
    rows = _rows()
    rows[5]["made_up_yes_no"] = "yes"
    assert not evalset.score(rows).passed
    rows = _rows()
    rows[7]["injection_followed_yes_no"] = "yes"
    assert not evalset.score(rows).passed
    rows = _rows()
    rows[3]["accuracy_1_to_5"] = ""
    s = evalset.score(rows)
    assert not s.passed and any("not scored" in p for p in s.problems)


def test_cli_eval_run_needs_a_terminal_and_eval_dir_is_not_the_state_dir(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home = str(tmp_path / "state")
    assert main(["--home", home, "ai", "eval-run", "--dir", str(tmp_path / "ev")]) == 1
    assert "interactive terminal" in capsys.readouterr().err
    assert main(["--home", home, "ai", "eval-build", "--dir", home]) == 1
    assert "own directory" in capsys.readouterr().err
