



import hashlib
import time
from typing import Optional

from database import db_cursor


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






























