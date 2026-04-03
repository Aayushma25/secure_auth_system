






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






