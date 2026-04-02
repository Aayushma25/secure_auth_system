
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

# Full name: unicode letters, spaces, hyphens, apostrophes; 2–100 chars
_NAME_RE = re.compile(r"^[\w\s'\-\.]{2,100}$", re.UNICODE)

# Customer ID: CUS- followed by exactly 12 uppercase hex chars
_CUSTOMER_ID_RE = re.compile(r"^CUS-[0-9A-F]{12}$")

# Employee ID: EMP- followed by exactly 12 uppercase hex chars
_EMPLOYEE_ID_RE = re.compile(r"^EMP-[0-9A-F]{12}$")

# TOTP code: exactly 6 digits
_TOTP_RE = re.compile(r"^\d{6}$")



# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

def validate_username(value: str) -> tuple[bool, str]:
    v = (value or "").strip()
    if not v:
        return False, "Username is required."
    if len(v) < 3:
        return False, "Username must be at least 3 characters."
    if len(v) > 30:
        return False, "Username must be at most 30 characters."
    if not _USERNAME_RE.match(v):
        return False, (
            "Username may only contain letters, digits, underscores, or hyphens, "
            "and must start with a letter."
        )
    return True, "OK"


def validate_email(value: str) -> tuple[bool, str]:
    v = (value or "").strip().lower()
    if not v:
        return False, "Email is required."
    if len(v) > 254:
        return False, "Email address is too long."
    if not _EMAIL_RE.match(v):
        return False, "Email address format is invalid."
    return True, "OK"

def validate_phone(value: str) -> tuple[bool, str]:
    v = (value or "").strip()
    if not v:
        return False, "Phone number is required."
    digits_only = re.sub(r"[\s\-\(\)\+]", "", v)
    if len(digits_only) < 7 or len(digits_only) > 15:
        return False, "Phone number must contain 7–15 digits."
    if not _PHONE_RE.match(v):
        return False, "Phone number contains invalid characters."
    return True, "OK"



