


## System Architecture

```
main.py          ← entry point
cli.py           ← all user-facing menus and prompts
auth.py          ← login, registration, sessions, MFA enrolment
recovery.py      ← account recovery (forgotten password)
integrity.py     ← HMAC verification of stored records
audit.py         ← append-only audit trail (DB + rotating file)
validators.py    ← input validation (allow-list approach)
security.py      ← cryptographic primitives
database.py      ← SQLite persistence layer
```

All modules are deliberately small and single-responsibility so the
security-critical code (`security.py`, `auth.py`) can be audited independently.

---




## Security Design Decisions

### 1. Password Hashing — `hashlib.scrypt` (RFC 7914)

**Why scrypt over MD5 / SHA-256 / bcrypt?**

| Algorithm | Memory-hard |  GPU-resistant | Python stdlib |
|-----------|-------------|---------------|---------------|
| MD5       | ✗           | ✗             | ✓             |
| SHA-256   | ✗           | ✗             | ✓             |
| bcrypt    | Partial     | Partial       | ✗ (3rd party) |
| **scrypt** | **✓**       | **✓**         | **✓**         |
| Argon2id  | ✓           | ✓             | ✗ (3rd party) | |

scrypt is both CPU and memory-hard, making it extremely expensive to
brute-force even with GPU clusters or ASICs. It is standardised in
RFC 7914 and recommended by NIST SP 800-132.

**Parameters chosen:**
- `N=131072` (2^17) — work factor; ~0.5 s on modern hardware
- `r=8` — block size
- `p=1` — parallelism
- `dklen=64` — 512-bit derived key
- `salt=32 bytes` (256-bit random salt per password)

The stored format is: `scrypt$<hex_salt>$<hex_dk>`

**Why a separate salt per password?**
Without salt, two users with the same password produce identical hashes,
leaking information and enabling rainbow-table attacks.

**Constant-time comparison:**
`hmac.compare_digest()` is used instead of `==` for all secret
comparisons. `==` short-circuits on the first differing byte, leaking
timing information that can be exploited to recover secrets.

---

### 2. Multi-Factor Authentication — TOTP (RFC 6238)

TOTP (Time-based One-Time Password) adds a second factor beyond the
password. Even if the password is stolen, an attacker cannot log in
without physical access to the user's authenticator app.

**Why TOTP over SMS OTP?**
- SMS is vulnerable to SIM-swap attacks and SS7 exploits.
- TOTP is phishing-resistant (codes expire in 30 seconds).
- No dependency on a third-party SMS gateway.

**Implementation:**
1. A 160-bit random secret is generated (`os.urandom(20)`) and encoded
   as Base32 (standard for TOTP apps).
2. The current UNIX timestamp is divided by 30 (the step window).
3. HMAC-SHA1 is computed over the 8-byte big-endian counter.
4. Dynamic truncation extracts 6 decimal digits (RFC 4226 §5.4).
5. Verification accepts ±1 step (30 s tolerance for clock drift).

The secret is stored in the database. In production, it should be
encrypted at rest using a KMS-managed key.

---

### 3. Account Lockout

After **5 consecutive failed login attempts**, the account is locked
for **30 minutes**. This prevents online brute-force attacks.

- The lockout timer is server-side (cannot be bypassed by the client).
- The lockout automatically expires — no admin action needed.
- Account recovery (see below) also unlocks the account.
- Audit events are emitted for every failed attempt and every lockout.

The threshold of 5 and duration of 30 minutes are configurable via
constants in `auth.py` (`MAX_FAILED_ATTEMPTS`, `LOCKOUT_DURATION_SECONDS`).

---

### 4. Session Management

Sessions use 256-bit URL-safe random tokens (`secrets.token_urlsafe(32)`).

**Why not JWTs?**
JWTs are stateless — they cannot be revoked without maintaining a
denylist, which is effectively a session store anyway. SQLite sessions
allow immediate revocation on logout or password change.

**Storage:** Only the SHA-256 hash of the token is stored in the DB.
If the database is compromised, the attacker cannot use stored hashes
to hijack active sessions.

**Session TTL:** 4 hours (configurable in `auth.py`).

**Invalidation triggers:**
- Explicit logout
- Password change (all sessions purged)
- Successful account recovery (all sessions purged)

---























