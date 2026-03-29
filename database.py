



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
        












