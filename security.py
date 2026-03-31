





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
    

