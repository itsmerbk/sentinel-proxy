import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "sentinel_audit.db"


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def init_db() -> None:
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                stage TEXT NOT NULL,
                target TEXT NOT NULL,
                payload_preview TEXT NOT NULL,
                decision TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                matched_rules TEXT NOT NULL,
                latency_ms REAL NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_logs(decision);"
        )


def log_event(
    stage: str,
    target: str,
    payload_preview: str,
    decision: str,
    risk_score: int,
    matched_rules: list[str],
    latency_ms: float,
) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    preview = payload_preview.replace("\n", " ")[:90]
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO audit_logs
            (timestamp, stage, target, payload_preview, decision, risk_score, matched_rules, latency_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now,
                stage,
                target,
                preview,
                decision,
                risk_score,
                json.dumps(matched_rules),
                round(latency_ms, 3),
            ),
        )


def get_summary_stats() -> dict:
    with get_connection() as conn:
        total = conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
        blocked = conn.execute(
            "SELECT COUNT(*) FROM audit_logs WHERE decision = 'BLOCK'"
        ).fetchone()[0]
        avg_latency = conn.execute(
            "SELECT COALESCE(AVG(latency_ms), 0.0) FROM audit_logs"
        ).fetchone()[0]
    return {
        "total_inspected": total,
        "blocked": blocked,
        "allowed": total - blocked,
        "avg_latency_ms": round(avg_latency, 2),
    }


def get_recent_logs(limit: int = 12) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(row) for row in rows]
