"""SQLite persistence. WAL mode. Worker writes, API reads."""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any

from app import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    resolved_ips TEXT NOT NULL,          -- JSON list
    status TEXT NOT NULL DEFAULT 'queued', -- queued|running|done|failed
    progress INTEGER NOT NULL DEFAULT 0,
    started_at REAL,
    finished_at REAL,
    error TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    kind TEXT NOT NULL,                  -- port|dns|banner|cve
    data TEXT NOT NULL,                  -- JSON blob
    created_at REAL NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
"""


def connect(db_path: Path | None = None) -> sqlite3.Connection:
    path = db_path or config.DB_PATH
    conn = sqlite3.connect(str(path), timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db(db_path: Path | None = None) -> None:
    with connect(db_path) as conn:
        conn.executescript(SCHEMA)


def new_scan(target: str, resolved_ips: list[str], db_path: Path | None = None) -> str:
    scan_id = uuid.uuid4().hex[:12]
    with connect(db_path) as conn:
        conn.execute(
            "INSERT INTO scans (id, target, resolved_ips, status, progress) VALUES (?,?,?,?,?)",
            (scan_id, target, json.dumps(resolved_ips), "queued", 0),
        )
    return scan_id


def update_scan(
    scan_id: str,
    *,
    status: str | None = None,
    progress: int | None = None,
    error: str | None = None,
    db_path: Path | None = None,
) -> None:
    fields, values = [], []
    if status is not None:
        fields.append("status=?"); values.append(status)
        if status == "running":
            fields.append("started_at=?"); values.append(time.time())
        if status in ("done", "failed"):
            fields.append("finished_at=?"); values.append(time.time())
    if progress is not None:
        fields.append("progress=?"); values.append(progress)
    if error is not None:
        fields.append("error=?"); values.append(error)
    if not fields:
        return
    values.append(scan_id)
    with connect(db_path) as conn:
        conn.execute(f"UPDATE scans SET {', '.join(fields)} WHERE id=?", values)


def add_finding(scan_id: str, kind: str, data: dict[str, Any],
                db_path: Path | None = None) -> None:
    with connect(db_path) as conn:
        conn.execute(
            "INSERT INTO findings (scan_id, kind, data, created_at) VALUES (?,?,?,?)",
            (scan_id, kind, json.dumps(data), time.time()),
        )


def get_scan(scan_id: str, db_path: Path | None = None) -> dict | None:
    with connect(db_path) as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    return dict(row) if row else None


def list_scans(limit: int = 50, db_path: Path | None = None) -> list[dict]:
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY COALESCE(started_at, 0) DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_findings(scan_id: str, db_path: Path | None = None) -> list[dict]:
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT kind, data, created_at FROM findings WHERE scan_id=? ORDER BY id",
            (scan_id,),
        ).fetchall()
    return [{"kind": r["kind"], "data": json.loads(r["data"]), "created_at": r["created_at"]}
            for r in rows]
