"""Local incident summary (ADR-0010): allow-list, labelled hypotheses, output guard, determinism."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from sentinel.incidents import lifecycle, summary
from sentinel.simulation import scenarios
from sentinel.store.db import Store

T0 = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)
FAKE = "AIza" + "Q" * 35  # built at runtime: a fake key shape, never a real credential


def r1_incident(tmp_path: Path) -> tuple[Store, dict]:  # type: ignore[type-arg]
    store = Store(tmp_path / "s.db")
    for e in scenarios.exposure("cred-fp-0123456789abcdef", "repo-demo", T0):
        store.add_event(e)
    for e in scenarios.provider_usage("cred-fp-0123456789abcdef", "gcp-demo", T0):
        store.add_event(e)
    [iid] = lifecycle.open_incidents(store, T0)
    incident = store.get_doc("incidents", iid)
    assert incident is not None
    return store, incident


def test_summary_states_facts_and_labels_hypotheses(tmp_path: Path) -> None:
    _store, incident = r1_incident(tmp_path)
    text = summary.render(incident)
    assert text.startswith(f"# Summary of {incident['id']}")
    assert "## Known facts" in text and "## Hypotheses (not proven)" in text
    assert "## Needs a human decision" in text
    assert "Built from recorded fields only" in text


def test_only_allow_listed_fields_are_copied(tmp_path: Path) -> None:
    _store, incident = r1_incident(tmp_path)
    incident["close_note"] = "secret-looking note"
    incident["response_plan"][0]["approved_by"] = "a-person-name"
    incident["response_plan"][0]["events"] = [
        {"time": "t", "actor": "a-person-name", "verified": True, "evidence": "console text"}
    ]
    v = summary.view(incident)
    assert "close_note" not in v
    assert "approved_by" not in v["response_plan"][0]
    assert v["response_plan"][0]["verifications"] == [{"time": "t", "verified": True}]
    text = summary.render(incident)
    assert "a-person-name" not in text and "console text" not in text


def test_output_guard_refuses_a_credential_that_reaches_the_text(tmp_path: Path) -> None:
    _store, incident = r1_incident(tmp_path)
    incident["facts"] = [f"leaked {FAKE}"]  # a fact that should never contain a key
    with pytest.raises(ValueError, match="credential"):
        summary.render(incident)


def test_render_is_deterministic(tmp_path: Path) -> None:
    _store, incident = r1_incident(tmp_path)
    assert summary.render(incident) == summary.render(incident)


def test_no_pending_steps_means_nothing_needs_a_decision(tmp_path: Path) -> None:
    _store, incident = r1_incident(tmp_path)
    for step in incident["response_plan"]:
        step["state"] = "verified"
        step["events"] = [{"time": "t", "verified": True}]
    assert "Required steps without passing verification: none" in summary.render(incident)
