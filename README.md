


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


### 5. Account Recovery

Flow:
1. User provides their registered email address.
2. A 256-bit recovery token is generated and its SHA-256 hash stored.
3. The token is "sent" (console output; in production: via email/SES).
4. User provides the token + new password.
5. Token validity checks: exists, unused, not expired (1 hour TTL).
6. Password is reset; token marked used; all sessions invalidated.
7. Account lockout is cleared.

**Anti-enumeration:** The endpoint always returns a success-sounding
generic message, regardless of whether the email is registered.
This prevents attackers from harvesting valid email addresses by
probing the recovery endpoint.

**Rate limiting:** Max 3 active tokens per user at any time — prevents
token-flooding DoS against the recovery_tokens table.

**Single-use tokens:** Once redeemed, a token can never be reused,
even if an attacker intercepts the original token.

---

### 6. HMAC Data Integrity (Tamper Detection)

Every row in `users`, `customers`, `employees`, and `audit_log` has an
`hmac` column storing `HMAC-SHA256(canonical_json(all_other_fields), key)`.

If anyone edits the database directly (e.g., an insider threat or SQL
injection bypassing the application layer), the HMAC will not match on
the next verification pass.

**Key management:** The HMAC key is stored in `.integrity_key` (owner
read-only, `0600` permissions). In production, this should be in a
secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.).

**Canonical serialisation:** Fields are JSON-serialised with sorted keys
to ensure the MAC is deterministic regardless of dict ordering.

---

### 7. SQL Injection Prevention

**Every** SQL statement in this codebase uses parameterised queries:

```python
# SAFE — parameter passed separately, never interpolated into SQL
cur.execute("SELECT * FROM users WHERE username = ?", (username,))

# NEVER done — this would be vulnerable
cur.execute(f"SELECT * FROM users WHERE username = '{username}'")
```

The SQLite PRAGMA `foreign_keys=ON` is set on every connection.

---

### 8. Input Validation (Allow-list)

All user input is validated before reaching business logic:

| Field       | Rule                                               |
|-------------|----------------------------------------------------|
| Username    | `^[a-zA-Z][a-zA-Z0-9_-]{2,29}$`                  |
| Email       | RFC 5322-simplified regex, max 254 chars           |
| Phone       | 7–15 digits, E.164-style                           |
| Full name   | Unicode letters/spaces/hyphens, 2–100 chars        |
| Password    | 12+ chars, upper+lower+digit+special               |
| Department  | Exact match against a fixed allow-list             |
| TOTP code   | `^\d{6}$`                                          |

**Why allow-lists over deny-lists?**
It is impossible to enumerate all possible malicious inputs.
Defining exactly what is valid (and rejecting everything else) is
inherently more robust.

---

### 9. No Sensitive Data in Logs

The audit system is designed so that secrets **never appear in logs**:

- Passwords are never logged — only "bad_password" as an outcome.
- Session tokens are never logged — only their existence/deletion.
- Recovery tokens are never logged — only their hash.
- The `detail` field in audit events contains only safe, generic info.

---

### 10. Audit Trail

Every security-relevant action produces an audit event with:
- Timestamp (Unix float, UTC)
- Event type (e.g., `AUTH_LOGIN_SUCCESS`)
- Username + user ID
- Outcome (`success` / `failure` / `info`)
- Detail string (sanitised)
- HMAC signature

Events are written to **both** the SQLite `audit_log` table and a
rotating file at `logs/audit.log` (5 MB per file, 10 files retained).
This dual-write means a DB corruption event doesn't destroy the audit
trail.

---


## Feature Reference

### User Roles

#### Customer
- Fields: `customer_id` (auto-generated, e.g. `CUS-A3F2891C04B7`),
  `full_name`, `email`, `phone`, `address`, `kyc_status`
- KYC status tracks `pending → verified → rejected`

#### Employee
- Fields: `employee_id` (auto-generated, e.g. `EMP-B1D8F24A9C3E`),
  `full_name`, `email`, `phone`, `department`, `job_title`, `access_level`
- Departments: Engineering, Finance, Compliance, Risk, Operations,
  Customer Support, Product, HR, Legal, Marketing, Executive
- Access levels: `standard`, `senior`, `manager`, `admin`

### MFA Enrolment

1. Log in → Dashboard → "Enable / Manage MFA"
2. Copy the Base32 secret or OTPAuth URI into an authenticator app
3. Enter the 6-digit code to confirm and activate

### Account Recovery

1. Main menu → "Account Recovery"
2. Enter registered email
3. Copy the printed token (in production: check inbox)
4. Enter token + new password

### Integrity Verification

- **Customers:** Dashboard → "Run Integrity Check" verifies your own records
- **Employees:** Dashboard → "Run Full Integrity Check" verifies all tables

---



## File Structure

```
fintech_auth/
├── main.py          — entry point (Python version check, delegates to cli)
├── cli.py           — all CLI menus, prompts, dashboards
├── auth.py          — registration, login, lockout, sessions, MFA, password change
├── recovery.py      — account recovery (token generation & redemption)
├── integrity.py     — HMAC verification, tamper detection reports
├── audit.py         — dual-write audit trail (SQLite + rotating file)
├── validators.py    — input validation functions (allow-list approach)
├── security.py      — cryptographic primitives (scrypt, TOTP, tokens, HMAC)
├── database.py      — SQLite setup, schema creation, context manager
├── requirements.txt — only colorama
├── README.md        — this file
│
├── fintech_auth.db  — created on first run (SQLite database)
├── .integrity_key   — HMAC key (created on first run, permissions 0600)
└── logs/
    └── audit.log    — rotating audit file log
```

---

## Database Schema

```sql
users           — shared auth record for all roles
customers       — customer profile data
employees       — employee profile data
recovery_tokens — time-limited single-use recovery tokens
sessions        — active session tokens (hashed)
audit_log       — append-only security event log
```

All sensitive tables have an `hmac TEXT` column for integrity verification.

---

## Running & Testing

### First run

```bash
python main.py
# Choose [2] Register → [1] Customer
# Follow the prompts
# Then [1] Login
```





















