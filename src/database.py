import sqlite3
import os
from datetime import datetime, timedelta

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "vt_cache.db")

CACHE_EXPIRY_DAYS = 30


def _get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # WAL mode allows concurrent reads while a write is in progress,
    # which prevents the background auto-scan thread from blocking API handlers.
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    with _get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vt_cache (
                url         TEXT PRIMARY KEY,
                malicious   INTEGER NOT NULL DEFAULT 0,
                suspicious  INTEGER NOT NULL DEFAULT 0,
                harmless    INTEGER NOT NULL DEFAULT 0,
                undetected  INTEGER NOT NULL DEFAULT 0,
                scanned_at  TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scanned_emails (
                uid        TEXT PRIMARY KEY,
                scanned_at TEXT NOT NULL
            )
        """)
        conn.commit()
    print(f"[DB] SQLite cache initialised at {DB_PATH}")


def get_cached_result(url: str) -> dict | None:
    with _get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM vt_cache WHERE url = ?", (url,)
        ).fetchone()

        if not row:
            return None

        scanned_at = datetime.fromisoformat(row["scanned_at"])
        if datetime.now() - scanned_at > timedelta(days=CACHE_EXPIRY_DAYS):
            conn.execute("DELETE FROM vt_cache WHERE url = ?", (url,))
            conn.commit()
            return None

        return {
            "url":        row["url"],
            "malicious":  row["malicious"],
            "suspicious": row["suspicious"],
            "harmless":   row["harmless"],
            "undetected": row["undetected"],
            "cached":     True,
            "scanned_at": row["scanned_at"],
        }


def save_result(url: str, result: dict):
    with _get_connection() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO vt_cache
                (url, malicious, suspicious, harmless, undetected, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            url,
            result.get("malicious", 0),
            result.get("suspicious", 0),
            result.get("harmless", 0),
            result.get("undetected", 0),
            datetime.now().isoformat(),
        ))
        conn.commit()


def delete_cached_result(url: str):
    with _get_connection() as conn:
        conn.execute("DELETE FROM vt_cache WHERE url = ?", (url,))
        conn.commit()


def is_email_scanned(uid: str) -> bool:
    with _get_connection() as conn:
        row = conn.execute(
            "SELECT uid FROM scanned_emails WHERE uid = ?", (uid,)
        ).fetchone()
    return row is not None


def save_scanned_email(uid: str):
    with _get_connection() as conn:
        conn.execute("""
            INSERT OR IGNORE INTO scanned_emails (uid, scanned_at)
            VALUES (?, ?)
        """, (uid, datetime.now().isoformat()))
        conn.commit()
