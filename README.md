
----------------------------------------------------------------------------------------------------

                             Fintech Secure Authentication System

----------------------------------------------------------------------------------------------------


## Operating System Compatibility

This application supports:

- Windows
- macOS
- Linux

Different launcher scripts are included for different operating systems.

| Operating System | Launcher File |
|---|---|
| Windows | `run.bat` |
| macOS / Linux | `run.sh` |

---

# Running the Application

## Windows

1. Open the project folder
2. Double-click:

```
run.bat
```

OR run from terminal:

```
run.bat
```

---

## macOS / Linux

Open Terminal inside the project directory and run:

```bash
chmod +x run.sh
./run.sh
```

Note:
The executable permission may need to be enabled after downloading the ZIP file from GitHub.

---



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



## Why Python Was Chosen Over C

For the development of this Secure Authentication System, Python was selected instead of C due to several practical and security-oriented advantages.

### 1. Simplicity and Readability

Python has a clear and easy-to-understand syntax, which makes it ideal for implementing authentication logic such as user registration, login validation, and input handling. This improves code maintainability and reduces the chances of logical errors compared to C, which is more complex and verbose.

### 2. Faster Development

Python allows rapid development due to its high-level nature and built-in functionalities. Features like file handling, string manipulation, and modular programming can be implemented with fewer lines of code, enabling efficient project completion within limited time constraints.

### 3. Built-in Security Libraries

Python provides built-in and well-supported libraries (e.g., hashlib) for implementing secure password hashing and encryption. In contrast, C requires manual implementation or external libraries, which increases complexity and the risk of security vulnerabilities.

### 4. Reduced Risk of Memory Errors

C requires manual memory management, which can lead to issues such as buffer overflows and memory leaks—common causes of security vulnerabilities. Python handles memory management automatically, making it a safer choice for building a secure system.

### 5. Better Suitability for CLI Applications

Python is well-suited for building command-line interface (CLI) applications with user-friendly input/output handling. This makes it easier to design an interactive authentication system.

### 6. Strong Community Support

Python has extensive documentation and community support, making it easier to troubleshoot issues and implement best practices in security and software design.

### Conclusion

Overall, Python provides a balance of simplicity, security, and development speed, making it a more suitable choice than C for implementing a secure authentication system in this project.



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
- `N=131072` (2^17) - work factor; ~0.5 s on modern hardware
- `r=8` - block size
- `p=1` - parallelism
- `dklen=64` - 512-bit derived key
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

### 2. Multi-Factor Authentication - TOTP (RFC 6238)

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
- The lockout automatically expires - no admin action needed.
- Account recovery (see below) also unlocks the account.
- Audit events are emitted for every failed attempt and every lockout.

The threshold of 5 and duration of 30 minutes are configurable via
constants in `auth.py` (`MAX_FAILED_ATTEMPTS`, `LOCKOUT_DURATION_SECONDS`).

---

### 4. Session Management

Sessions use 256-bit URL-safe random tokens (`secrets.token_urlsafe(32)`).

**Why not JWTs?**
JWTs are stateless - they cannot be revoked without maintaining a
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

**Rate limiting:** Max 3 active tokens per user at any time - prevents
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

- Passwords are never logged - only "bad_password" as an outcome.
- Session tokens are never logged - only their existence/deletion.
- Recovery tokens are never logged - only their hash.
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






### First run

```bash
python main.py
# Choose [2] Register → [1] Customer
# Follow the prompts
# Then [1] Login
```


## Use of Gen AI

Use of Generative AI
In developing this FinTech Secure Authentication System, I used Chatgpt, a Generative AI assistant by OpenAI, to help design and implement several key parts of the project. Specifically, in security.py, AI helped me implement the password hashing function hash_password() using Python's hashlib.scrypt algorithm, explaining why scrypt is more secure than MD5 or SHA-256 and how to correctly set the parameters like the work factor, salt size, and derived key length. It also helped me implement the entire TOTP multi-factor authentication system from scratch - the _hotp(), generate_totp(), and verify_totp() functions - following the RFC 6238 and RFC 4226 specifications, which I would not have been able to find and implement correctly on my own. In auth.py, AI helped me understand and implement the account lockout mechanism in _increment_failed_attempts(), the timing attack prevention in attempt_login() using a dummy scrypt hash for unknown usernames, and the session token system in _create_session() where only the SHA-256 hash of the token is stored in the database. In recovery.py, AI helped me implement the anti-enumeration protection in request_recovery() and the single-use token system in redeem_recovery_token(). In audit.py, AI helped me set up the dual-write audit trail using Python's RotatingFileHandler class and explained why writing to both the database and a file simultaneously makes the audit evidence more reliable. In integrity.py, AI helped me design the IntegrityReport dataclass and the compute_record_hmac() function in security.py that signs every database row with HMAC-SHA256 so that any tampering with the database can be detected. Overall, AI served as a knowledgeable guide throughout the project - it explained the reasoning behind each security decision, pointed me to the relevant standards and best practices, and helped me write code that I then reviewed, tested, and understood myself. Without AI assistance, implementing correct cryptographic standards like RFC 6238 and following NIST SP 800-63B password guidelines would have been significantly more difficult within the time available for this assignment.


 
## Refrences

1. Percival, C. and Josefsson, S. (2016) *The scrypt Password-Based
   Key Derivation Function*. RFC 7914. IETF.
   https://www.rfc-editor.org/rfc/rfc7914

2. M'Raihi, D. et al. (2011) *TOTP: Time-Based One-Time Password
   Algorithm*. RFC 6238. IETF.
   https://www.rfc-editor.org/rfc/rfc6238

3. M'Raihi, D. et al. (2005) *HOTP: An HMAC-Based One-Time Password
   Algorithm*. RFC 4226. IETF.
   https://www.rfc-editor.org/rfc/rfc4226

4. Krawczyk, H., Bellare, M. and Canetti, R. (1997) *HMAC:
   Keyed-Hashing for Message Authentication*. RFC 2104. IETF.
   https://www.rfc-editor.org/rfc/rfc2104

5. Grassi, P.A. et al. (2017) *NIST SP 800-63B: Digital Identity
   Guidelines*. NIST, U.S. Department of Commerce.
   https://doi.org/10.6028/NIST.SP.800-63b

6. OWASP Foundation (2021) *OWASP Top Ten 2021 — A03: Injection*.
   https://owasp.org/Top10/A03_2021-Injection/

7. Kocher, P.C. (1996) 'Timing Attacks on Implementations of
   Diffie-Hellman, RSA, DSS, and Other Systems', CRYPTO 96,
   Springer, pp. 104-113.
   https://doi.org/10.1007/3-540-68697-5_9

8. ISO/IEC 27001:2013 (2013) *Information Security Management
   Systems: Requirements*. Geneva: ISO.
   https://www.iso.org/standard/54534.html













