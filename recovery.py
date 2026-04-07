



import hashlib
import time
from typing import Optional

from database import db_cursor

from security import (
    generate_recovery_token, hash_password,
    validate_password_strength, RECOVERY_TTL_SECONDS,
)

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
    


    # --- Generate and store token -----
    token = generate_recovery_token()
    token_hash = _hash_token(token)
    expires_at = now + RECOVERY_TTL_SECONDS

    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO recovery_tokens (user_id, token_hash, expires_at, used, created_at)
            VALUES (?, ?, ?, 0, ?)
        """, (user["id"], token_hash, expires_at, now))

    log_event("RECOVERY_REQUEST", "success", username=user["username"],
              user_id=user["id"])

    # --- In production: send via email. Here: print to console. ---
    print("\n" + "=" * 60)
    print("  [SIMULATED EMAIL — in production this is sent to your inbox]")
    print(f"  Account:        {user['username']}")
    print(f"  Recovery Token: {token}")
    print(f"  Expires in:     60 minutes")
    print("=" * 60 + "\n")

    return True, generic_msg   



def redeem_recovery_token(
    email: str,
    token: str,
    new_password: str,
) -> tuple[bool, str]:
    """
    Validate the recovery token and reset the password.
    Returns (success, message).
    """
    from validators import validate_email
    ok, msg = validate_email(email)
    if not ok:
        return False, msg

    ok, msg = validate_password_strength(new_password)
    if not ok:
        return False, msg

    user = _get_user_by_email(email)
    if not user:
        log_event("RECOVERY_FAILURE", "failure", detail="email_not_found")
        return False, "Invalid email, token, or the token has expired."

    token_hash = _hash_token(token.strip())
    now = time.time()



    with db_cursor() as cur:
        cur.execute("""
            SELECT id, expires_at, used FROM recovery_tokens
            WHERE user_id = ? AND token_hash = ?
        """, (user["id"], token_hash))
        row = cur.fetchone()

    if not row:
        log_event("RECOVERY_FAILURE", "failure", username=user["username"],
                  user_id=user["id"], detail="token_not_found")
        return False, "Invalid email, token, or the token has expired."

    if row["used"]:
        log_event("RECOVERY_FAILURE", "failure", username=user["username"],
                  user_id=user["id"], detail="token_already_used")
        return False, "This recovery token has already been used."

    if row["expires_at"] < now:
        log_event("RECOVERY_FAILURE", "failure", username=user["username"],
                  user_id=user["id"], detail="token_expired")
        return False, "Invalid email, token, or the token has expired."


    # --- All checks passed — reset password ---
    new_hash = hash_password(new_password)

    with db_cursor() as cur:
        # Mark token used
        cur.execute("UPDATE recovery_tokens SET used = 1 WHERE id = ?", (row["id"],))
        # Update password
        cur.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                    (new_hash, user["id"]))
        # Unlock account (in case it was locked)
        cur.execute("""
            UPDATE users SET is_locked = 0, failed_attempts = 0, locked_until = NULL
            WHERE id = ?
        """, (user["id"],))
        # Invalidate all sessions
        cur.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],))



    # Refresh HMAC after user row mutations
    from hmac_refresh import refresh_user_hmac
    refresh_user_hmac(user["id"])

    log_event("RECOVERY_SUCCESS", "success", username=user["username"],
              user_id=user["id"])
    return True, "Password reset successful. All previous sessions have been invalidated."
















