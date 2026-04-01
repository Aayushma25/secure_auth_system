





import hashlib
import hmac
import os
import secrets
import struct
import time
import base64
import json
from typing import Optional


# ---------------------------------------------------------------------------
# Password hashing — scrypt
# ---------------------------------------------------------------------------

SCRYPT_N = 16384    # 2^14
                    
SCRYPT_R = 8        # block size
SCRYPT_P = 1        # parallelism
SCRYPT_DKLEN = 64   # derived key length in bytes
SALT_BYTES = 32     # 256-bit random salt


def hash_password(plaintext: str) -> str:
    """
    Hash a password with scrypt + random salt.

    Returns a single storable string:
        "scrypt$<hex_salt>$<hex_derived_key>"

    The format is versioned implicitly by the 'scrypt' prefix so future
    algorithm migrations can be handled transparently.
    """
    if not plaintext:
        raise ValueError("Password must not be empty.")
    salt = os.urandom(SALT_BYTES)
    dk = hashlib.scrypt(
        plaintext.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
    )
    return f"scrypt${salt.hex()}${dk.hex()}"
 

def verify_password(plaintext: str, stored_hash: str) -> bool:
    """
    Constant-time comparison to prevent timing attacks.
    Returns True only if plaintext matches the stored hash.
    """
    try:
        algo, salt_hex, dk_hex = stored_hash.split("$")
        if algo != "scrypt":
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(dk_hex)
        actual = hashlib.scrypt(
            plaintext.encode("utf-8"),
            salt=salt,
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
            dklen=SCRYPT_DKLEN,
        )
        return hmac.compare_digest(expected, actual)  # constant-time
    except Exception:
        return False


def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Enforce NIST SP 800-63B-aligned password policy:
      - Minimum 12 characters
      - At least one uppercase, one lowercase, one digit, one symbol
      - No leading/trailing whitespace (common mistake)
    Returns (ok: bool, reason: str).
    """
    if len(password) < 12:
        return False, "Password must be at least 12 characters long."
    if password != password.strip():
        return False, "Password must not start or end with whitespace."
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter."
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter."
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit."
    if not any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in password):
        return False, "Password must contain at least one special character."
    return True, "OK"
    




















RECOVERY_TOKEN_BYTES = 32   # 256-bit entropy
SESSION_TOKEN_BYTES = 32
RECOVERY_TTL_SECONDS = 3600  # 1 hour


def generate_recovery_token() -> str:
    """URL-safe 256-bit cryptographically secure random token."""
    return secrets.token_urlsafe(RECOVERY_TOKEN_BYTES)

def generate_session_token() -> str:
    """URL-safe 256-bit session identifier."""
    return secrets.token_urlsafe(SESSION_TOKEN_BYTES)

def generate_customer_id() -> str:
    """
    Generate a unique customer ID: 'CUS-' prefix + 12 hex chars (6 random bytes).
    E.g.  CUS-A3F2891C04B7
    """
    return "CUS-" + secrets.token_hex(6).upper()

