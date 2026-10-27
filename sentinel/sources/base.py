"""Shared collector behaviour: state (cursors, baselines, snapshots) is committed only AFTER the
events it produced were stored, so a storage failure can never silently skip a detection."""

from typing import Any

from sentinel.store.db import Store


class DeferredState:
    def __init__(self) -> None:
        self._pending: list[tuple[str, str, dict[str, Any]]] = []

    def defer(self, table: str, key: str, body: dict[str, Any]) -> None:
        """Remember a state write; the last write per (table, key) wins."""
        self._pending = [p for p in self._pending if (p[0], p[1]) != (table, key)]
        self._pending.append((table, key, body))

    def commit(self, store: Store) -> None:
        for table, key, body in self._pending:
            store.put_doc(table, key, body)
        self._pending = []

    def discard(self) -> None:
        self._pending = []
