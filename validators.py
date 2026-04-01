
"""
validators.py — Input validation for all user-supplied data.

"""

import re
from typing import Optional

# ---------------------------------------------------------------------------
# Compiled regex patterns (compile once at import time for performance)
# ---------------------------------------------------------------------------

# RFC 5322-simplified: covers 99%+ of real email addresses
_EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
)