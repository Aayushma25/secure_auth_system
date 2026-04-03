




import logging
import logging.handlers
import os
import time
from typing import Optional

from database import db_cursor
from security import compute_record_hmac

# ---------------------------------------------------------------------------
# File-based rotating logger (independent of DB)
# ---------------------------------------------------------------------------

LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

_file_logger = logging.getLogger("fintech.audit.file")
_file_logger.setLevel(logging.INFO)

_handler = logging.handlers.RotatingFileHandler(
    os.path.join(LOG_DIR, "audit.log"),
    maxBytes=5 * 1024 * 1024,   # 5 MB per file
    backupCount=10,              # keep 10 rotated files
    encoding="utf-8",
)
_handler.setFormatter(logging.Formatter(
    "%(asctime)s | %(message)s", datefmt="%Y-%m-%dT%H:%M:%S"
))
_file_logger.addHandler(_handler)
_file_logger.propagate = False   # don't double-print to root logger

# Console logger for the application
logging.basicConfig(
    level=logging.WARNING,
    format="%(levelname)s | %(name)s | %(message)s",
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def log_event(
    event_type: str,
    outcome: str,
    username: Optional[str] = None,
    user_id: Optional[int] = None,
    detail: Optional[str] = None,
) -> None:
    """
    Record one security event.

    outcome must be: 'success' | 'failure' | 'info'

    The detail string must NEVER contain passwords, tokens, or secrets.
    Callers are responsible for sanitising before passing detail.
    """
    ts = time.time()

    # 1 — Write to file log immediately (survives DB corruption)
    _file_logger.info(
        "%-35s | %-8s | user=%-20s | uid=%-6s | %s",
        event_type,
        outcome.upper(),
        username or "-",
        str(user_id) if user_id else "-",
        detail or "",
    )

    # 2 — Write to DB with HMAC
    row = {
        "timestamp":  ts,
        "event_type": event_type,
        "username":   username,
        "user_id":    user_id,
        "outcome":    outcome,
        "detail":     detail or "",
    }
    mac = compute_record_hmac(row)

    try:
        with db_cursor() as cur:
            cur.execute("""
                INSERT INTO audit_log
                    (timestamp, event_type, username, user_id, outcome, detail, hmac)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (ts, event_type, username, user_id, outcome, detail or "", mac))
    except Exception as exc:
        # If DB write fails, the file log still has the record.
        _file_logger.error("AUDIT_DB_WRITE_FAILED | %s", exc)


def get_recent_events(limit: int = 50) -> list[dict]:
    """Retrieve the most recent audit events, newest first."""
    with db_cursor() as cur:
        cur.execute("""
            SELECT id, timestamp, event_type, username, user_id, outcome, detail, hmac
            FROM audit_log
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        rows = cur.fetchall()
    return [dict(r) for r in rows]


def get_user_events(username: str, limit: int = 20) -> list[dict]:
    """Retrieve events for a specific user."""
    with db_cursor() as cur:
        cur.execute("""
            SELECT id, timestamp, event_type, username, outcome, detail
            FROM audit_log
            WHERE username = ?
            ORDER BY id DESC
            LIMIT ?
        """, (username, limit))
        rows = cur.fetchall()
    return [dict(r) for r in rows]


def verify_audit_integrity(limit: int = 100) -> tuple[int, int]:
    """
    Verify HMAC on recent audit rows.
    Returns (total_checked, tampered_count).
    """
    from security import verify_record_hmac
    with db_cursor() as cur:
        cur.execute("""
            SELECT id, timestamp, event_type, username, user_id, outcome, detail, hmac
            FROM audit_log
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        rows = [dict(r) for r in cur.fetchall()]

    tampered = 0
    for row in rows:
        if not verify_record_hmac(row):
            tampered += 1
            _file_logger.error("AUDIT_INTEGRITY_FAIL | row_id=%s", row["id"])

    return len(rows), tampered









