
# FinTech Secure Authentication System
## Implementation Checklist

> **Project:** CLI-Based Secure Authentication System for a FinTech Startup  
> **Language:** Python 3.11+  
> **Total Files:** 10 Python source files  
> **Database:** SQLite (auto-created on first run)  
> **Third-party Dependency:** `colorama` only  

---


## 1. Project Structure

- [x] 10 Python source files, each with a single clear responsibility
- [x] `main.py` — entry point and version guard
- [x] `database.py` — database setup and schema
- [x] `security.py` — all cryptographic operations
- [x] `validators.py` — all input validation
- [x] `auth.py` — registration, login, sessions, MFA
- [x] `hmac_refresh.py` — HMAC integrity synchronisation
- [x] `recovery.py` — account recovery tokens
- [x] `audit.py` — security event logging
- [x] `integrity.py` — database tamper detection
- [x] `cli.py` — command-line interface
- [x] `requirements.txt` — only one third-party dependency (`colorama`)
- [x] `README.md` — full project documentation
- [x] `fintech_auth.db` — SQLite database (auto-created on first run)
- [x] `logs/audit.log` — rotating audit log file (auto-created on first run)
- [x] `.integrity_key` — HMAC signing key (auto-created with restricted permissions)



## 2. Language and Version

- [x] Written in Python 3.11+
- [x] Python version enforced at startup — app refuses to run below 3.11
- [x] All security-critical operations use Python Standard Library only
- [x] No external cryptographic packages — zero crypto supply-chain risk


## 3. Database (database.py)

- [x] SQLite database — no server required, zero installation
- [x] 6 tables created automatically on first run:
  - [x] `users` — authentication records for all accounts
  - [x] `customers` — customer profile data
  - [x] `employees` — employee profile data
  - [x] `sessions` — active login sessions
  - [x] `recovery_tokens` — account recovery tokens
  - [x] `audit_log` — all security events
- [x] `PRAGMA foreign_keys = ON` — enforces relationships between tables
- [x] `PRAGMA journal_mode = WAL` — prevents database corruption on crash
- [x] `PRAGMA secure_delete = ON` — overwrites deleted data with zeros on disk
- [x] All SQL queries use parameterised statements — SQL injection structurally impossible
- [x] `CHECK` constraints on `role`, `kyc_status`, `access_level`, `outcome` columns
- [x] `COLLATE NOCASE` on username and email — case-insensitive uniqueness
- [x] `ON DELETE CASCADE` on profile tables — no orphaned records
- [x] `AUTOINCREMENT` primary keys — deleted IDs never reused
- [x] `db_cursor()` context manager — guarantees commit/rollback/close on every operation
- [x] `finally: conn.close()` — database connection always closed, even on exception

---




## 4. Password Security (security.py)

- [x] Passwords hashed using `hashlib.scrypt` (RFC 7914) — memory-hard, GPU-resistant
- [x] Unique 256-bit random salt per password using `os.urandom(32)`
- [x] scrypt parameters: `N=16384`, `r=8`, `p=1`, output `dklen=64` bytes
- [x] Hash stored in self-describing format: `scrypt$<salt_hex>$<dk_hex>`
- [x] Passwords never stored in plaintext — not in database, not in logs
- [x] `hmac.compare_digest()` used for comparison — constant-time, prevents timing attacks
- [x] Password strength policy enforced (NIST SP 800-63B):
  - [x] Minimum 12 characters
  - [x] At least one uppercase letter
  - [x] At least one lowercase letter
  - [x] At least one digit
  - [x] At least one special character
  - [x] No leading or trailing whitespace
- [x] Password reuse prevention — changing to the same password is rejected
- [x] Terminal echo disabled during password entry using `getpass.getpass()`
- [x] Current password required before changing — stolen session cannot change password

---

## 5. User Roles (auth.py)

- [x] Two roles: **Customer** and **Employee**
- [x] Role selected at registration and login via numbered menu
- [x] Role stored in database with `CHECK` constraint enforcement

### Customer Profile Fields
- [x] Auto-generated unique Customer ID: `CUS-XXXXXXXXXXXX` (48-bit random)
- [x] Full name (supports Unicode — Nepali, Arabic, Chinese scripts)
- [x] Email address (unique, case-insensitive)
- [x] Phone number
- [x] Home address (optional)
- [x] KYC status: `pending` / `verified` / `rejected`

### Employee Profile Fields
- [x] Auto-generated unique Employee ID: `EMP-XXXXXXXXXXXX` (48-bit random)
- [x] Full name
- [x] Email address (unique, case-insensitive)
- [x] Phone number
- [x] Department (from 11 allowed options: Engineering, Finance, Compliance, etc.)
- [x] Job title
- [x] Access level: `standard` / `senior` / `manager` / `admin`

---

## 6. Input Validation (validators.py)

- [x] Dedicated `validators.py` — all validation in one auditable place
- [x] Allow-list approach — define what IS valid, reject everything else
- [x] All regex patterns compiled once at module load — never re-created per call
- [x] All validators return `(bool, message)` tuple — no exceptions for invalid input
- [x] Every field validated before reaching business logic or database:
  - [x] **Username:** letters/digits/underscore/hyphen, 3–30 chars, must start with letter
  - [x] **Email:** RFC 5322 simplified format, max 254 characters
  - [x] **Phone:** E.164 format, 7–15 digits, accepts `+`, spaces, hyphens
  - [x] **Full name:** Unicode characters with `re.UNICODE` flag, 2–100 chars
  - [x] **Department:** exact match against fixed 11-item allow-list (set membership)
  - [x] **Job title:** 2–80 characters
  - [x] **TOTP code:** exactly 6 decimal digits
  - [x] **Address:** max 200 characters
  - [x] **Password:** strength checked separately in `security.py`
- [x] `sanitise_for_log()` — removes control characters before any logging (prevents log injection)

---

## 7. Multi-Factor Authentication / MFA (security.py + auth.py)

- [x] TOTP (Time-Based One-Time Password) implemented from scratch
- [x] Follows RFC 6238 (TOTP) and RFC 4226 (HOTP) specifications
- [x] Uses HMAC-SHA1 internally as specified by the RFC standard
- [x] 30-second time window, 6-digit codes
- [x] ±1 window tolerance — accepts codes 30 seconds early or late (handles clock drift)
- [x] Base32-encoded secrets — compatible with Google Authenticator, Authy, 1Password
- [x] `otpauth://` URI generated for QR code scanning
- [x] Two-step enrolment — user must confirm with a valid code before MFA activates
- [x] `hmac.compare_digest()` used for TOTP comparison — constant-time
- [x] Maximum 3 TOTP attempts per login before rejection

---

## 8. Login Security (auth.py)

- [x] Account lockout after **5 consecutive** failed login attempts
- [x] Lockout duration: **30 minutes** — stored server-side, cannot be bypassed
- [x] Auto-unlock when lockout expires — no admin action required
- [x] Timing attack prevention — dummy scrypt hash run for unknown usernames
- [x] Username enumeration prevention — identical error message for all failures
- [x] Two-phase login: password first, then TOTP (if MFA enabled)
- [x] Failed attempt counter reset to zero on successful login
- [x] `last_login` timestamp updated on every successful login
- [x] Role validation — customer cannot log in as employee and vice versa

---

## 9. Session Management (auth.py)

- [x] Session tokens: 256-bit using `secrets.token_urlsafe(32)` — computationally impossible to guess
- [x] Only SHA-256 hash of token stored in database — raw token never persisted
- [x] Sessions expire after **4 hours** (TTL = 14,400 seconds)
- [x] Expired sessions deleted automatically when accessed — no background job needed
- [x] Session immediately invalidated on logout
- [x] All sessions invalidated on password change
- [x] All sessions invalidated on successful account recovery

---

## 10. Account Recovery (recovery.py)

- [x] Recovery tokens: 256-bit using `secrets.token_urlsafe(32)`
- [x] Only SHA-256 hash stored in database — raw token never persisted
- [x] Tokens expire after **1 hour** (TTL = 3,600 seconds)
- [x] Single-use enforcement — token marked `used = 1` immediately on redemption
- [x] Maximum 3 active pending tokens per user — prevents database flooding
- [x] Anti-enumeration — identical response whether email exists or not
- [x] Account lockout cleared on successful recovery
- [x] All sessions invalidated on successful recovery
- [x] New password must meet full strength requirements
- [x] Email lookup searches both customer and employee profile tables

---

## 11. Data Integrity / HMAC Protection (security.py + hmac_refresh.py + integrity.py)

- [x] Every row in `users`, `customers`, `employees`, and `audit_log` has HMAC-SHA256 signature
- [x] HMAC key stored in `.integrity_key` file with `0600` permissions (owner read-only)
- [x] HMAC computed over canonical JSON with `sort_keys=True` — deterministic across versions
- [x] `hmac.compare_digest()` for HMAC comparison — constant-time
- [x] HMAC refreshed automatically after every legitimate database update
- [x] `hmac_refresh.py` centralises all refresh operations — no duplication
- [x] Tampering with any field outside the application causes HMAC mismatch
- [x] `IntegrityReport` dataclass — structured result with `@property ok` getter
- [x] Customers can verify their own records from dashboard
- [x] Employees can run full integrity check across all 4 protected tables

---

## 12. Audit Trail (audit.py)

- [x] Every security event recorded — logins, failures, registrations, logouts, MFA, recovery, integrity
- [x] **Dual-write** — every event written to both SQLite table AND rotating file
- [x] File write happens first — evidence survives database corruption
- [x] Each audit row has its own HMAC signature — log tampering is detectable
- [x] Rotating log files — 5 MB per file, 10 backup files kept (`audit.log.1` through `.10`)
- [x] Sensitive data never in audit logs — passwords, tokens, keys never logged
- [x] `type(exc).__name__` logged, not `str(exc)` — prevents schema details leaking
- [x] ISO 8601 timestamps in log file
- [x] Named logger with `propagate = False` — audit events do not bleed into console output
- [x] Audit DB write failure never crashes authentication — swallowed safely

### Audit Event Types Recorded
- [x] `AUTH_LOGIN_SUCCESS`
- [x] `AUTH_LOGIN_FAILURE`
- [x] `AUTH_LOGOUT`
- [x] `AUTH_MFA_SUCCESS`
- [x] `AUTH_MFA_FAILURE`
- [x] `AUTH_MFA_ENROLL`
- [x] `ACCOUNT_REGISTER`
- [x] `ACCOUNT_LOCK`
- [x] `PASSWORD_CHANGE`
- [x] `SESSION_CREATE`
- [x] `SESSION_EXPIRE`
- [x] `RECOVERY_REQUEST`
- [x] `RECOVERY_SUCCESS`
- [x] `RECOVERY_FAILURE`
- [x] `INTEGRITY_FAIL`
- [x] `INTEGRITY_CHECK`

---

## 13. Object-Oriented Programming Concepts

- [x] `IntegrityReport` — `@dataclass` class with `@property ok` getter and `summary()` method
- [x] `_NoColor` — Null Object pattern using `__getattr__` dunder method (colorama fallback)
- [x] `db_cursor()` — generator-based context manager using `@contextmanager` decorator
- [x] `RotatingFileHandler` — stdlib class instance in `audit.py`
- [x] `logging.Logger` — named logger instance in `audit.py` and `database.py`
- [x] `logging.Formatter` — format instance for ISO 8601 timestamps
- [x] `sqlite3.Connection` — class instance in `database.py`
- [x] `sqlite3.Cursor` — class instance in `database.py`
- [x] `sqlite3.Row` — row factory for name-based column access
- [x] Private functions (`_` prefix) — encapsulates internal logic, limits public surface
- [x] Public functions clearly separated from internal helpers
- [x] Type hints (`Optional`, `tuple[bool, str]`) on all function signatures

---

## 14. Exception Handling

- [x] `db_cursor()` — catches all database exceptions, rolls back, logs class name only
- [x] `verify_password()` — catches all exceptions, returns `False` safely
- [x] `verify_totp()` — catches all exceptions, returns `False` safely
- [x] `register_customer()` — handles `UNIQUE` violations separately from other errors
- [x] `register_employee()` — same pattern as `register_customer()`
- [x] `audit.log_event()` — swallows DB write failures, never crashes authentication
- [x] `integrity.run_full_integrity_check()` — per-table isolation, one bad table does not stop others
- [x] `main.py` — `sys.exit()` for version check, clean message without traceback
- [x] Exception messages never exposed to users — generic safe messages shown
- [x] `str(exc)` never logged — only `type(exc).__name__` to prevent schema leakage

---

## 15. Memory Management

- [x] No database connection leaks — `finally: conn.close()` in `db_cursor()`
- [x] No file handle leaks — `with open()` for all file operations
- [x] No reference cycles — `gc.collect()` returns 0 throughout all operations
- [x] HMAC key not cached in memory — re-read on each call (shorter exposure window)
- [x] Session tokens held only in local variables — never in globals, never on disk
- [x] Recovery tokens freed immediately after function returns
- [x] Generator expressions in password checks — `O(1)` memory, not `O(n)` list
- [x] Regex patterns compiled once at module load — not recreated per call
- [x] Query results bounded with `LIMIT` — prevents loading entire large tables into RAM
- [x] `secure_delete = ON` — deleted data zeroed on disk, not just marked free

---

## 16. CLI Interface (cli.py)

- [x] Colour-coded output: green (success), red (error), yellow (warning), cyan (info)
- [x] Graceful fallback if `colorama` not installed — runs without colours
- [x] Dropdown-style numbered menus for all choices
- [x] Prompts re-ask on invalid input — never crash on bad user entry
- [x] `prompt_validated()` helper — reusable validated input for any field
- [x] `pick_from_menu()` — consistent numbered option selector throughout
- [x] Separate dashboards for Customer and Employee roles
- [x] Screen clears between views for clean presentation
- [x] `getpass.getpass()` — password input with no terminal echo

---

## 17. Secure Coding Practices

### Injection Prevention
- [x] SQL injection — 100% parameterised queries, zero string interpolation in SQL
- [x] Log injection — `sanitise_for_log()` removes control characters before logging

### Timing Attack Prevention
- [x] Password comparison — `hmac.compare_digest()` (constant-time)
- [x] TOTP comparison — `hmac.compare_digest()` (constant-time)
- [x] HMAC comparison — `hmac.compare_digest()` (constant-time)
- [x] Login unknown username — dummy scrypt hash equalises response time

### Enumeration Prevention
- [x] Login — same error message for wrong username and wrong password
- [x] Account recovery — same response whether email exists or not
- [x] Registration — vague message on duplicate username

### Brute Force Prevention
- [x] Account lockout after 5 failures with 30-minute server-side timeout
- [x] scrypt password hashing — slow by design, resists GPU attacks
- [x] 256-bit session and recovery tokens — computationally impossible to guess
- [x] Maximum 3 pending recovery tokens per user

### Data Protection
- [x] Passwords never in logs or error messages
- [x] Tokens never stored in plaintext — SHA-256 hash only
- [x] HMAC key file with `0600` permissions
- [x] `secure_delete = ON` on database — deleted data zeroed on disk

---

## 18. Libraries Used

| # | Library | Type | Purpose |
|---|---------|------|---------|
| 1 | `hashlib` | Standard | scrypt password hashing, SHA-256, SHA-1 for TOTP |
| 2 | `hmac` | Standard | HMAC signatures, constant-time `compare_digest()` |
| 3 | `os` | Standard | `os.urandom()`, file paths, file permissions `0o600` |
| 4 | `secrets` | Standard | `token_urlsafe()` for tokens, `token_hex()` for IDs |
| 5 | `struct` | Standard | Binary packing of TOTP counter (RFC 4226 requirement) |
| 6 | `base64` | Standard | Base32 encoding/decoding of TOTP secrets |
| 7 | `json` | Standard | Canonical serialisation for HMAC computation |
| 8 | `time` | Standard | Unix timestamps for sessions, lockouts, token expiry |
| 9 | `sqlite3` | Standard | Entire database engine |
| 10 | `contextlib` | Standard | `@contextmanager` decorator for `db_cursor()` |
| 11 | `logging` | Standard | Named loggers, log levels, log formatting |
| 12 | `logging.handlers` | Standard | `RotatingFileHandler` — automatic log file rotation |
| 13 | `re` | Standard | Compiled regex patterns for input validation |
| 14 | `getpass` | Standard | Secure password input without terminal echo |
| 15 | `sys` | Standard | Python version check, `sys.exit()` |
| 16 | `dataclasses` | Standard | `@dataclass` and `field()` for `IntegrityReport` |
| 17 | `typing` | Standard | `Optional` type hints on function signatures |
| 18 | `urllib.parse` | Standard | `quote()` for building `otpauth://` URI |
| 19 | `colorama` | **Third-party** | Cross-platform terminal colour codes |

---

## 19. Memory Vulnerability Analysis

| Vulnerability | Applicable to Python? | How Handled |
|---|---|---|
| Memory Leak | Yes | `finally: conn.close()` in `db_cursor()`; `with open()` for files; sessions deleted on logout |
| Use-After-Free | No | Python reference counting — object lives as long as any reference exists |
| Double Free | No | `del` on non-existent name raises `NameError` — no manual memory management |
| Dangling Pointers | No | No raw pointers in Python — names either exist and are valid, or do not exist |
| Buffer Overflow | No (language) / Yes (app) | Python bounds-checks all accesses; `validators.py` enforces max lengths on all fields |
| Allocation Failure | No | Python raises `MemoryError`; caught by `except Exception` in `auth.py`, `database.py`, `audit.py` |

---



*This checklist covers the complete implementation of the Secure Authentication Systemb for FinTech startup .*  
*Every item marked [x] has been fully implemented and tested.*





