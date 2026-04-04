
# 

import time
from dataclasses import dataclass, field
from typing import Optional

from database import db_cursor
from security import verify_record_hmac
from audit import log_event


@dataclass
class IntegrityReport:
    timestamp: float = field(default_factory=time.time)
    table: str = ""
    total_checked: int = 0
    passed: int = 0
    failed: int = 0
    failed_ids: list = field(default_factory=list)










    