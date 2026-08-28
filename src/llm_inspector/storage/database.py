"""
Lightweight SQLite persistence for targets, scans, tool calls, and findings.

This is intentionally simple (stdlib sqlite3, JSON columns for nested data)
rather than an ORM, because the goal of this pass is a correct, working
single-user local tool. See EXTENDED_README.md for what swapping this for
a real multi-user database would require.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    budget TEXT NOT NULL,
    usage TEXT,
    FOREIGN KEY (target_id) REFERENCES targets (id)
);

CREATE TABLE IF NOT EXISTS tool_calls (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    tool_name TEXT NOT NULL,
    arguments TEXT NOT NULL,
    result TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans (id)
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    data TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans (id)
);
"""


class Database:
    def __init__(self, path: Path):
        self.path = path
        with self._conn() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # ---- targets ----
    def upsert_target(self, target_id: str, data: dict[str, Any], created_at: str) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO targets (id, data, created_at) VALUES (?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET data=excluded.data",
                (target_id, json.dumps(data), created_at),
            )

    def get_target(self, target_id: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT data FROM targets WHERE id = ?", (target_id,)
            ).fetchone()
            return json.loads(row["data"]) if row else None

    def list_targets(self) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT data FROM targets ORDER BY created_at DESC"
            ).fetchall()
            return [json.loads(r["data"]) for r in rows]

    # ---- scans ----
    def create_scan(
        self, scan_id: str, target_id: str, started_at: str, budget: dict[str, Any]
    ) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO scans (id, target_id, status, started_at, budget) "
                "VALUES (?, ?, 'running', ?, ?)",
                (scan_id, target_id, started_at, json.dumps(budget)),
            )

    def finish_scan(
        self, scan_id: str, status: str, finished_at: str, usage: dict[str, Any]
    ) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE scans SET status=?, finished_at=?, usage=? WHERE id=?",
                (status, finished_at, json.dumps(usage), scan_id),
            )

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
            return dict(row) if row else None

    def list_scans(self, target_id: str | None = None) -> list[dict[str, Any]]:
        with self._conn() as conn:
            if target_id:
                rows = conn.execute(
                    "SELECT * FROM scans WHERE target_id=? ORDER BY started_at DESC",
                    (target_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM scans ORDER BY started_at DESC"
                ).fetchall()
            return [dict(r) for r in rows]

    # ---- tool calls ----
    def log_tool_call(
        self,
        call_id: str,
        scan_id: str,
        seq: int,
        tool_name: str,
        arguments: dict[str, Any],
        result: dict[str, Any] | None,
        started_at: str,
        finished_at: str | None,
    ) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO tool_calls (id, scan_id, seq, tool_name, arguments, "
                "result, started_at, finished_at) VALUES (?,?,?,?,?,?,?,?)",
                (
                    call_id,
                    scan_id,
                    seq,
                    tool_name,
                    json.dumps(arguments),
                    json.dumps(result) if result is not None else None,
                    started_at,
                    finished_at,
                ),
            )

    def list_tool_calls(self, scan_id: str) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM tool_calls WHERE scan_id=? ORDER BY seq ASC",
                (scan_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    # ---- findings ----
    def save_finding(
        self, finding_id: str, scan_id: str, data: dict[str, Any], created_at: str
    ) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO findings (id, scan_id, data, created_at) VALUES (?,?,?,?)",
                (finding_id, scan_id, json.dumps(data), created_at),
            )

    def list_findings(self, scan_id: str) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT data FROM findings WHERE scan_id=? ORDER BY created_at ASC",
                (scan_id,),
            ).fetchall()
            return [json.loads(r["data"]) for r in rows]
