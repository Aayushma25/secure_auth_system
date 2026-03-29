



import sqlite3
import os
import logging
from contextlib import contextmanager
from typing import Optional

logger = logging.getLogger("fintech.db")

DB_PATH = os.path.join(os.path.dirname(__file__), "fintech_auth.db")


def get_connection() -> sqlite3.Connection:
    """
    Create and open the SQLite database with security-oriented pragmas.
    """
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row          # We can access rows by column name
    conn.execute("PRAGMA journal_mode=WAL") # Can write logging without blocking readers
    conn.execute("PRAGMA foreign_keys=ON")  # enforce foreign key constraints
    conn.execute("PRAGMA secure_delete=ON") # overwrite deleted data with zeros
    return conn


@contextmanager
def db_cursor():

    """Context manager: yields a cursor, commits on success, rolls back on error.
    This ensures that database operations are atomic and that connections are properly closed.
    """
    conn = get_connection()
    try:
        cursor = conn.cursor()
        yield cursor
        conn.commit()
    except Exception as exc:
        conn.rollback()
        logger.error("DB error (rolled back): %s", type(exc).__name__)
        raise
    finally:
        conn.close()



# ---------------------------------------------------------------------------
# Schema creation
# ---------------------------------------------------------------------------


def init_db() -> None:
    """Create all tables if they do not yet exist."""
    with db_cursor() as cur:

        # --- Users (shared authentication record) ---
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            username        TEXT    NOT NULL UNIQUE COLLATE NOCASE,
            password_hash   TEXT    NOT NULL,
            role            TEXT    NOT NULL CHECK(role IN ('customer','employee')),
            totp_secret     TEXT,           -- NULL until MFA is enrolled
            mfa_enabled     INTEGER NOT NULL DEFAULT 0,
            is_locked       INTEGER NOT NULL DEFAULT 0,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until    REAL,           -- Unix timestamp; NULL = not locked
            last_login      REAL,
            created_at      REAL    NOT NULL,
            hmac            TEXT    NOT NULL DEFAULT ''
        )
        """)


         # ---- Customer profiles ----
        cur.execute("""
        CREATE TABLE IF NOT EXISTS customers (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id         INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
            customer_id     TEXT    NOT NULL UNIQUE,   -- CUS-XXXXXXXXXX
            full_name       TEXT    NOT NULL,
            email           TEXT    NOT NULL UNIQUE COLLATE NOCASE,
            phone           TEXT    NOT NULL,
            address         TEXT,
            kyc_status      TEXT    NOT NULL DEFAULT 'pending'
                                CHECK(kyc_status IN ('pending','verified','rejected')),
            created_at      REAL    NOT NULL,
            hmac            TEXT    NOT NULL DEFAULT ''
        )
        """)

        # ---- Employee profiles ----
        cur.execute("""
        CREATE TABLE IF NOT EXISTS employees (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id         INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
            employee_id     TEXT    NOT NULL UNIQUE,   -- EMP-XXXXXXXXXX
            full_name       TEXT    NOT NULL,
            email           TEXT    NOT NULL UNIQUE COLLATE NOCASE,
            phone           TEXT    NOT NULL,
            department      TEXT    NOT NULL,
            job_title       TEXT    NOT NULL,
            access_level    TEXT    NOT NULL DEFAULT 'standard'
                                CHECK(access_level IN ('standard','senior','manager','admin')),
            created_at      REAL    NOT NULL,
            hmac            TEXT    NOT NULL DEFAULT ''
        )
        """)




















