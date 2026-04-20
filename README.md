


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






















