



import hashlib
import time
from typing import Optional


MAX_PENDING_TOKENS = 3

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
































