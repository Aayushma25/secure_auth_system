






import hashlib
import os
import secrets
import time
from typing import Optional

from database import db_cursor
from security import (
    hash_password, verify_password, validate_password_strength,
    generate_totp_secret, verify_totp, generate_session_token,
    generate_customer_id, compute_record_hmac, verify_record_hmac,
)
from validators import validate_username, validate_email, validate_phone, validate_full_name
from hmac_refresh import refresh_user_hmac

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 30 * 60   # 30 minutes
SESSION_TTL_SECONDS = 4 * 60 * 60    # 4 hours


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _hash_token(token: str) -> str:
    """Store tokens as SHA-256 so a DB breach doesn't expose active sessions."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _get_user_by_username(username: str) -> Optional[dict]:
    with db_cursor() as cur:
        cur.execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
            (username,)
        )
        row = cur.fetchone()
    return dict(row) if row else None


def _get_user_by_id(user_id: int) -> Optional[dict]:
    with db_cursor() as cur:
        cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# Brute Force Protection
# ---------------------------------------------------------------------------


def _increment_failed_attempts(user_id: int) -> None:
    """Increment failed counter; lock the account if threshold is reached."""
    with db_cursor() as cur:
        cur.execute(
            "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?",
            (user_id,)
        )
        cur.execute("SELECT failed_attempts FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        count = row["failed_attempts"] if row else 0

    if count >= MAX_FAILED_ATTEMPTS:
        locked_until = time.time() + LOCKOUT_DURATION_SECONDS
        with db_cursor() as cur:
            cur.execute(
                "UPDATE users SET is_locked = 1, locked_until = ? WHERE id = ?",
                (locked_until, user_id)
            )
        refresh_user_hmac(user_id)
    else:
        refresh_user_hmac(user_id)  # refresh after failed_attempts increment


def _reset_failed_attempts(user_id: int) -> None:
    with db_cursor() as cur:
        cur.execute(
            "UPDATE users SET failed_attempts = 0, is_locked = 0, locked_until = NULL WHERE id = ?",
            (user_id,)
        )
    refresh_user_hmac(user_id)


def _check_lockout(user: dict) -> tuple[bool, str]:
    """Returns (is_locked: bool, message: str)."""
    if not user["is_locked"]:
        return False, ""
    locked_until = user.get("locked_until") or 0
    remaining = locked_until - time.time()
    if remaining <= 0:
        # Lock has expired — auto-unlock
        _reset_failed_attempts(user["id"])
        return False, ""
    mins = int(remaining // 60) + 1
    return True, f"Account is locked. Try again in {mins} minute(s)."













