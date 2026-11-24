"""SQLite persistence for assessment jobs and completed results."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

from app.core.config import DATABASE, DATA_DIR


class JobConflict(Exception):
    pass


def _connect() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


def initialize():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with _connect() as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute(
            """CREATE TABLE IF NOT EXISTS assessments (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                filename TEXT NOT NULL,
                device TEXT,
                score INTEGER,
                payload TEXT,
                status TEXT NOT NULL DEFAULT 'completed',
                error TEXT,
                source TEXT NOT NULL DEFAULT 'OFFLINE',
                assessment_type TEXT NOT NULL DEFAULT 'AUDIT',
                routeros_version TEXT,
                target TEXT,
                stage TEXT,
                audit_status TEXT,
                cve_status TEXT
            )"""
        )
        columns = {row["name"] for row in db.execute("PRAGMA table_info(assessments)")}
        if "status" not in columns:
            db.execute("ALTER TABLE assessments ADD COLUMN status TEXT NOT NULL DEFAULT 'completed'")
        if "error" not in columns:
            db.execute("ALTER TABLE assessments ADD COLUMN error TEXT")
        if "source" not in columns:
            db.execute("ALTER TABLE assessments ADD COLUMN source TEXT NOT NULL DEFAULT 'OFFLINE'")
        if "target" not in columns:
            db.execute("ALTER TABLE assessments ADD COLUMN target TEXT")
        if "assessment_type" not in columns:
            db.execute("ALTER TABLE assessments ADD COLUMN assessment_type TEXT NOT NULL DEFAULT 'AUDIT'")
        if "routeros_version" not in columns:
            db.execute("ALTER TABLE assessments ADD COLUMN routeros_version TEXT")
        if "stage" not in columns:
            db.execute("ALTER TABLE assessments ADD COLUMN stage TEXT")
        if "audit_status" not in columns:
            db.execute("ALTER TABLE assessments ADD COLUMN audit_status TEXT")
        if "cve_status" not in columns:
            db.execute("ALTER TABLE assessments ADD COLUMN cve_status TEXT")
        db.execute(
            """UPDATE assessments SET status='failed', stage='failed',
               error='Application restarted before this assessment completed.'
               WHERE status IN ('queued','running')"""
        )


def create_pending(
    aid: str, filename: str, source: str = "OFFLINE", target: str | None = None,
    assessment_type: str = "AUDIT", routeros_version: str | None = None,
) -> None:
    created = datetime.now(timezone.utc).isoformat()
    with _connect() as db:
        db.execute(
            """INSERT INTO assessments
               (id,created_at,filename,status,source,target,stage,assessment_type,routeros_version)
               VALUES (?,?,?,'queued',?,?,'queued',?,?)""",
            (aid, created, filename, source, target, assessment_type, routeros_version),
        )


def create_live_pending(
    aid: str, filename: str, target: str, max_concurrent: int,
    assessment_type: str = "AUDIT",
) -> None:
    created = datetime.now(timezone.utc).isoformat()
    with _connect() as db:
        db.execute("BEGIN IMMEDIATE")
        duplicate = db.execute(
            """SELECT id FROM assessments
               WHERE source='SSH' AND target=? AND assessment_type=? AND status IN ('queued','running')""",
            (target, assessment_type),
        ).fetchone()
        if duplicate:
            raise JobConflict("A security scan for this router is already running.")
        active = db.execute(
            "SELECT COUNT(*) FROM assessments WHERE source='SSH' AND status IN ('queued','running')"
        ).fetchone()[0]
        if active >= max_concurrent:
            raise JobConflict("The live-audit concurrency limit has been reached. Try again after a job completes.")
        db.execute(
            """INSERT INTO assessments
               (id,created_at,filename,status,source,target,stage,assessment_type,audit_status,cve_status)
               VALUES (?,?,?,'queued','SSH',?,'validating_connection',?,?,?)""",
            (aid, created, filename, target, assessment_type,
             "queued" if assessment_type == "SCAN" else None,
             "queued" if assessment_type == "SCAN" else None),
        )


def set_running(aid: str) -> None:
    with _connect() as db:
        db.execute("UPDATE assessments SET status='running', error=NULL WHERE id=?", (aid,))


def update_stage(aid: str, stage: str) -> None:
    with _connect() as db:
        db.execute("UPDATE assessments SET stage=? WHERE id=?", (stage, aid))


def update_component(aid: str, component: str, status_value: str) -> None:
    if component not in {"audit", "cve"}:
        raise ValueError("Unknown scan component")
    column = "audit_status" if component == "audit" else "cve_status"
    with _connect() as db:
        db.execute(f"UPDATE assessments SET {column}=? WHERE id=?", (status_value, aid))


def complete(aid: str, result: dict) -> None:
    with _connect() as db:
        db.execute(
            """UPDATE assessments
               SET created_at=?, device=?, score=?, payload=?, status='completed', stage='completed', error=NULL,
                   routeros_version=?, assessment_type=?
               WHERE id=?""",
            (
                result["created_at"], result["device"].get("identity"),
                result.get("summary", {}).get("score"), json.dumps(result, ensure_ascii=False),
                result.get("routeros_version") or result.get("device", {}).get("routeros_version"),
                result.get("assessment_type", "AUDIT"), aid,
            ),
        )


def fail(aid: str, message: str) -> None:
    with _connect() as db:
        db.execute("UPDATE assessments SET status='failed', stage='failed', error=? WHERE id=?", (message[:1000], aid))


def status(aid: str) -> dict | None:
    with _connect() as db:
        row = db.execute(
            """SELECT id,status,error,source,target,stage,assessment_type,routeros_version,
                      audit_status,cve_status
               FROM assessments WHERE id=?""", (aid,)
        ).fetchone()
    return dict(row) if row else None


def get(aid: str) -> dict | None:
    with _connect() as db:
        row = db.execute("SELECT payload FROM assessments WHERE id=? AND status='completed'", (aid,)).fetchone()
    return json.loads(row["payload"]) if row and row["payload"] else None

