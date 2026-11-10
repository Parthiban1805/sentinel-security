"""Session taint markers (v0.7e F1, ADR-0027): the "lethal trifecta" state shared by the hooks."""

import hashlib
import json
import os
import time
from pathlib import Path

import pytest

from sentinel import sessiontaint as st

ROOT = Path(__file__).resolve().parents[2]


def test_the_hook_copy_is_identical() -> None:
    copy = ROOT / "docs" / "patches" / "agent-gateway" / "_taint.py"
    assert copy.read_bytes() == (ROOT / "sentinel" / "sessiontaint.py").read_bytes()


def test_a_new_session_is_clean(tmp_path: Path) -> None:
    assert st.legs(str(tmp_path), "s-1") == set()
    assert st.tainted(str(tmp_path), "s-1") is False


def test_marking_both_legs_taints_only_that_session(tmp_path: Path) -> None:
    home = str(tmp_path)
    assert st.mark(home, "s-1", "U", "OG-10") is True
    assert st.tainted(home, "s-1") is False
    assert st.mark(home, "s-1", "S", "OG-01") is True
    assert st.legs(home, "s-1") == {"U", "S"} and st.tainted(home, "s-1") is True
    assert st.tainted(home, "s-2") is False


def test_a_leg_is_set_once_and_keeps_its_first_rule(tmp_path: Path) -> None:
    home = str(tmp_path)
    assert st.mark(home, "s-1", "S", "OG-01") is True
    assert st.mark(home, "s-1", "S", "OG-99") is False
    marker = json.loads(st.marker_path(home, "s-1", "S").read_text(encoding="utf-8"))
    assert marker["rule"] == "OG-01" and set(marker) == {"leg", "rule", "time"}


def test_the_session_id_is_stored_only_as_the_decision_log_hash(tmp_path: Path) -> None:
    home = str(tmp_path)
    st.mark(home, "secret-looking-session-id", "U", "OG-10")
    key = hashlib.sha256(b"secret-looking-session-id").hexdigest()[:16]
    names = [p.name for p in (tmp_path / st.DIR_NAME).iterdir()]
    assert names == [f"{key}.U"]


def test_unknown_legs_are_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="leg"):
        st.mark(str(tmp_path), "s-1", "X", "OG-01")


def test_a_marker_that_cannot_be_checked_counts_as_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_stat = os.stat

    def broken(path: object, *args: object, **kwargs: object) -> os.stat_result:
        if str(path).endswith((".U", ".S")):
            raise PermissionError("denied")
        return real_stat(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "stat", broken)
    assert st.tainted(str(tmp_path), "s-1") is True  # fail closed: unknown counts as tainted


def test_prune_removes_only_old_markers(tmp_path: Path) -> None:
    home = str(tmp_path)
    st.mark(home, "old", "U", "OG-10")
    st.mark(home, "new", "U", "OG-10")
    old = st.marker_path(home, "old", "U")
    stale = time.time() - 15 * 86400
    os.utime(old, (stale, stale))
    assert st.prune(home, days=14) == 1
    assert not old.exists() and st.legs(home, "new") == {"U"}


def test_prune_without_a_folder_is_a_no_op(tmp_path: Path) -> None:
    assert st.prune(str(tmp_path / "missing")) == 0


def test_a_marker_folder_that_is_a_file_raises(tmp_path: Path) -> None:
    """On Windows a marker under a FILE reads as 'not found': that must not open the gate."""
    (tmp_path / st.DIR_NAME).write_text("planted", encoding="utf-8")
    with pytest.raises(OSError, match="not a folder"):
        st.tainted(str(tmp_path), "s-1")
    with pytest.raises(OSError):
        st.mark(str(tmp_path), "s-1", "U", "OG-10")
