"""SQLite store for events and assets. Only schema-validated records are written."""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from sentinel.events.schema import format_time, validate_asset, validate_event

_DDL = """
CREATE TABLE IF NOT EXISTS events (
    event_id   TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    time       TEXT NOT NULL,
    is_test    INTEGER NOT NULL,
    body       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(time);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE TABLE IF NOT EXISTS assets (
    asset_id TEXT PRIMARY KEY,
    body     TEXT NOT NULL
);
"""


class Store:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._path = path
        with self._connect() as conn:
            conn.executescript(_DDL)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._path)

    def add_event(self, event: dict[str, Any]) -> bool:
        """Store a validated event. Returns False if the event_id already exists."""
        validate_event(event)
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT OR IGNORE INTO events VALUES (?, ?, ?, ?, ?)",
                (
                    event["event_id"],
                    event["event_type"],
                    event["time"],
                    int(event["is_test"]),
                    json.dumps(event, sort_keys=True),
                ),
            )
            return cur.rowcount == 1

    def events(
        self,
        *,
        event_type: str | None = None,
        since: datetime | None = None,
        include_test: bool = True,
    ) -> list[dict[str, Any]]:
        sql = "SELECT body FROM events WHERE 1=1"
        params: list[Any] = []
        if event_type is not None:
            sql += " AND event_type = ?"
            params.append(event_type)
        if since is not None:
            sql += " AND time >= ?"
            params.append(format_time(since))
        if not include_test:
            sql += " AND is_test = 0"
        sql += " ORDER BY time, event_id"
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [json.loads(row[0]) for row in rows]

    def upsert_asset(self, asset: dict[str, Any]) -> None:
        validate_asset(asset)
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO assets VALUES (?, ?)",
                (asset["asset_id"], json.dumps(asset, sort_keys=True)),
            )

    def assets(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT body FROM assets ORDER BY asset_id").fetchall()
        return [json.loads(row[0]) for row in rows]
