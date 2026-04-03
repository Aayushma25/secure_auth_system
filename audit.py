




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


