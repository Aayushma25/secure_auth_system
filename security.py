





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
    

# ---------------------------------------------------------------------------
# TOTP — RFC 6238 / RFC 4226 (HMAC-Based OTP)
# ---------------------------------------------------------------------------

TOTP_STEP = 30          # seconds per time-step
TOTP_DIGITS = 6         # OTP length
TOTP_WINDOW = 1         # ±1 step tolerance for clock drift
TOTP_SECRET_BYTES = 20  # 160-bit secret (standard for SHA-1 TOTP)


def generate_totp_secret() -> str:
    """
    Generate a new random TOTP secret encoded as base32.
    Base32 is the standard encoding for TOTP QR codes and manual entry.
    """
    raw = os.urandom(TOTP_SECRET_BYTES)
    return base64.b32encode(raw).decode("utf-8")

def _hotp(secret_b32: str, counter: int) -> int:
    """
    RFC 4226 HOTP: HMAC-SHA1 over the counter, then dynamic truncation.
    """
    key = base64.b32decode(secret_b32, casefold=True)
    msg = struct.pack(">Q", counter)                  # big-endian 8-byte counter
    h = hmac.new(key, msg, hashlib.sha1).digest()     # 20-byte HMAC
    offset = h[-1] & 0x0F
    code = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
    return code % (10 ** TOTP_DIGITS)

def generate_totp(secret_b32: str) -> str:
    """Return the current TOTP code as a zero-padded string."""
    counter = int(time.time()) // TOTP_STEP
    return str(_hotp(secret_b32, counter)).zfill(TOTP_DIGITS)


def verify_totp(secret_b32: str, code: str) -> bool:
    """
    Verify a TOTP code within ±TOTP_WINDOW time-steps (handles clock drift).
    Uses constant-time string comparison.
    """
    try:
        counter = int(time.time()) // TOTP_STEP
        for delta in range(-TOTP_WINDOW, TOTP_WINDOW + 1):
            expected = str(_hotp(secret_b32, counter + delta)).zfill(TOTP_DIGITS)
            if hmac.compare_digest(expected, code.strip()):
                return True
        return False
    except Exception:
        return False


def get_totp_uri(secret_b32: str, username: str, issuer: str = "FinTechAuth") -> str:
    """
    Build the otpauth:// URI for QR code generation (e.g. Google Authenticator).
    """
    from urllib.parse import quote
    return (
        f"otpauth://totp/{quote(issuer)}:{quote(username)}"
        f"?secret={secret_b32}&issuer={quote(issuer)}&algorithm=SHA1"
        f"&digits={TOTP_DIGITS}&period={TOTP_STEP}"
    )




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



# ---------------------------------------------------------------------------
# Data integrity — HMAC-SHA256 checksums
# ---------------------------------------------------------------------------

def _integrity_key() -> bytes:
    """
    Load or create a persistent HMAC key stored in a protected local file.
    In production this would be in a secrets manager / HSM.
    """
    key_path = os.path.join(os.path.dirname(__file__), ".integrity_key")
    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            return f.read()
    key = os.urandom(32)
    # Write with restrictive permissions (owner read-only)
    with open(os.open(key_path, os.O_CREAT | os.O_WRONLY, 0o600), "wb") as f:
        f.write(key)
    return key


def compute_record_hmac(record: dict) -> str:
    """
    Compute HMAC-SHA256 over a canonical JSON representation of a record.
    Fields are sorted to ensure deterministic serialisation.
    The 'hmac' field itself is excluded before computation.
    """

    # Exclude 'hmac' (the field being signed) and 'id' (auto-increment PK,
    # unknown at insert time, so it was never part of the original MAC).

    _EXCLUDE = {"hmac", "id"}
    payload = {k: v for k, v in record.items() if k not in _EXCLUDE}
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=True)
    sig = hmac.new(_integrity_key(), canonical.encode("utf-8"), hashlib.sha256)
    return sig.hexdigest()

def verify_record_hmac(record: dict) -> bool:
    """
    Returns True if the stored HMAC matches a freshly computed one.
    Any field tampering will invalidate the MAC.
    """
    stored = record.get("hmac", "")
    expected = compute_record_hmac(record)
    return hmac.compare_digest(stored, expected)










