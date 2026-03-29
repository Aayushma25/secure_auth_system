



import sqlite3
import os
import logging
from contextlib import contextmanager
from typing import Optional

logger = logging.getLogger("fintech.db")

DB_PATH = os.path.join(os.path.dirname(__file__), "fintech_auth.db")









