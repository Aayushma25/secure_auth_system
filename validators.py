
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

# E.164-style: optional +, then 7–15 digits (allows spaces/hyphens for readability)
_PHONE_RE = re.compile(r"^\+?[\d\s\-\(\)]{7,20}$")

# Username: 3–30 alphanumeric + underscore/hyphen, must start with a letter
_USERNAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_\-]{2,29}$")

# Customer ID: CUS- followed by exactly 12 uppercase hex chars
_CUSTOMER_ID_RE = re.compile(r"^CUS-[0-9A-F]{12}$")

# Employee ID: EMP- followed by exactly 12 uppercase hex chars
_EMPLOYEE_ID_RE = re.compile(r"^EMP-[0-9A-F]{12}$")

# TOTP code: exactly 6 digits
_TOTP_RE = re.compile(r"^\d{6}$")




