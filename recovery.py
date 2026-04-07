



import hashlib
import time
from typing import Optional

from database import db_cursor

from audit import log_event

MAX_PENDING_TOKENS = 3

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def _get_user_by_email(email: str) -> Optional[dict]:
    """Look up a user via their customer or employee email."""
    email_lc = email.strip().lower()
    with db_cursor() as cur:
        # Try customers table first
        cur.execute("""
            SELECT u.* FROM users u
            JOIN customers c ON c.user_id = u.id
            WHERE c.email = ? COLLATE NOCASE
        """, (email_lc,))
        row = cur.fetchone()
        if row:
            return dict(row)
        # Then employees
        cur.execute("""
            SELECT u.* FROM users u
            JOIN employees e ON e.user_id = u.id
            WHERE e.email = ? COLLATE NOCASE
        """, (email_lc,))
        row = cur.fetchone()
    return dict(row) if row else None


def request_recovery(email: str) -> tuple[bool, str]:
    """
    Initiate account recovery for the given email address.
    Always returns a generic success-sounding message regardless of
    whether the email is registered — prevents email enumeration.
    """
    from validators import validate_email
    ok, msg = validate_email(email)
    if not ok:
        return False, msg

    user = _get_user_by_email(email)

    # --- Generic response to prevent enumeration ---
    generic_msg = (
        "If an account is registered with that email, a recovery code has been generated.\n"
        "Please check the console output (in a real system this would be emailed)."
    )

    if not user:
        # Log the attempt but reveal nothing to the caller
        log_event("RECOVERY_REQUEST", "info", detail=f"email_not_found email_domain={email.split('@')[-1]}")
        return True, generic_msg

     # --- Rate-limit: max 3 pending tokens ---
    now = time.time()
    with db_cursor() as cur:
        cur.execute("""
            SELECT COUNT(*) as cnt FROM recovery_tokens
            WHERE user_id = ? AND used = 0 AND expires_at > ?
        """, (user["id"], now))
        row = cur.fetchone()
    if row and row["cnt"] >= MAX_PENDING_TOKENS:
        log_event("RECOVERY_REQUEST", "failure", username=user["username"],
                  user_id=user["id"], detail="rate_limited")
        return True, generic_msg  # still return generic message
    


    



























