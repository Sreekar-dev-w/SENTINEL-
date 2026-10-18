"""Small SQLite snapshot store for single-node SENTINEL deployments."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from threading import RLock


class SnapshotDatabase:
    """Persist JSON snapshots in one application-owned SQLite database."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._connection = sqlite3.connect(self.path, check_same_thread=False)
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS sentinel_snapshots ("
            "kind TEXT NOT NULL, record_id TEXT NOT NULL, payload TEXT NOT NULL, "
            "PRIMARY KEY (kind, record_id))"
        )
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS sentinel_schema (version INTEGER NOT NULL)"
        )
        if self._connection.execute("SELECT COUNT(*) FROM sentinel_schema").fetchone()[0] == 0:
            self._connection.execute("INSERT INTO sentinel_schema(version) VALUES (1)")
        self._connection.commit()

    def load(self, kind: str) -> list[tuple[str, str]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT record_id, payload FROM sentinel_snapshots WHERE kind = ? ORDER BY record_id",
                (kind,),
            ).fetchall()
        return [(str(record_id), str(payload)) for record_id, payload in rows]

    def save(self, kind: str, record_id: str, payload: str) -> None:
        with self._lock:
            self._connection.execute(
                "INSERT INTO sentinel_snapshots(kind, record_id, payload) VALUES (?, ?, ?) "
                "ON CONFLICT(kind, record_id) DO UPDATE SET payload = excluded.payload",
                (kind, record_id, payload),
            )
            self._connection.commit()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> "SnapshotDatabase":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()


__all__ = ["SnapshotDatabase"]
