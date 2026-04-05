






import hashlib
import os
import secrets
import time
from typing import Optional

from database import db_cursor
from security import (
    hash_password, verify_password, validate_password_strength,
    generate_totp_secret, verify_totp, generate_session_token,
    generate_customer_id, compute_record_hmac, verify_record_hmac,
)
from validators import validate_username, validate_email, validate_phone, validate_full_name
from hmac_refresh import refresh_user_hmac
from audit import log_event

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 30 * 60   # 30 minutes
SESSION_TTL_SECONDS = 4 * 60 * 60    # 4 hours


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _hash_token(token: str) -> str:
    """Store tokens as SHA-256 so a DB breach doesn't expose active sessions."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _get_user_by_username(username: str) -> Optional[dict]:
    with db_cursor() as cur:
        cur.execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
            (username,)
        )
        row = cur.fetchone()
    return dict(row) if row else None


def _get_user_by_id(user_id: int) -> Optional[dict]:
    with db_cursor() as cur:
        cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# Brute Force Protection
# ---------------------------------------------------------------------------


def _increment_failed_attempts(user_id: int) -> None:
    """Increment failed counter; lock the account if threshold is reached."""
    with db_cursor() as cur:
        cur.execute(
            "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?",
            (user_id,)
        )
        cur.execute("SELECT failed_attempts FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        count = row["failed_attempts"] if row else 0

    if count >= MAX_FAILED_ATTEMPTS:
        locked_until = time.time() + LOCKOUT_DURATION_SECONDS
        with db_cursor() as cur:
            cur.execute(
                "UPDATE users SET is_locked = 1, locked_until = ? WHERE id = ?",
                (locked_until, user_id)
            )
        refresh_user_hmac(user_id)
    else:
        refresh_user_hmac(user_id)  # refresh after failed_attempts increment


def _reset_failed_attempts(user_id: int) -> None:
    with db_cursor() as cur:
        cur.execute(
            "UPDATE users SET failed_attempts = 0, is_locked = 0, locked_until = NULL WHERE id = ?",
            (user_id,)
        )
    refresh_user_hmac(user_id)


def _check_lockout(user: dict) -> tuple[bool, str]:
    """Returns (is_locked: bool, message: str)."""
    if not user["is_locked"]:
        return False, ""
    locked_until = user.get("locked_until") or 0
    remaining = locked_until - time.time()
    if remaining <= 0:
        # Lock has expired — auto-unlock
        _reset_failed_attempts(user["id"])
        return False, ""
    mins = int(remaining // 60) + 1
    return True, f"Account is locked. Try again in {mins} minute(s)."


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def register_customer(
    username: str,
    password: str,
    full_name: str,
    email: str,
    phone: str,
    address: str = "",
) -> tuple[bool, str]:
    """
    Create a new customer account.
    Returns (success: bool, message: str).
    Customer ID is auto-generated and returned in the success message.
    """
    # --- Validate all fields ---
    for field, val, fn in [
        ("username", username, validate_username),
        ("full name", full_name, validate_full_name),
        ("email", email, validate_email),
        ("phone", phone, validate_phone),
    ]:
        ok, msg = fn(val)
        if not ok:
            return False, msg

    ok, msg = validate_password_strength(password)
    if not ok:
        return False, msg

    # --- Check uniqueness ---
    existing = _get_user_by_username(username)
    if existing:
        # Deliberately vague message to prevent username enumeration
        return False, "Registration failed. Please choose a different username."

    # --- Persist ---
    now = time.time()
    pw_hash = hash_password(password)
    customer_id = generate_customer_id()

    user_record = {
        "username": username.lower(),
        "password_hash": pw_hash,
        "role": "customer",
        "totp_secret": None,
        "mfa_enabled": 0,
        "is_locked": 0,
        "failed_attempts": 0,
        "locked_until": None,
        "last_login": None,
        "created_at": now,
    }
    user_mac = compute_record_hmac(user_record)

    customer_record_base = {
        "customer_id": customer_id,
        "full_name": full_name.strip(),
        "email": email.strip().lower(),
        "phone": phone.strip(),
        "address": address.strip(),
        "kyc_status": "pending",
        "created_at": now,
    }

    try:
        with db_cursor() as cur:
            cur.execute("""
                INSERT INTO users
                    (username, password_hash, role, totp_secret, mfa_enabled,
                     is_locked, failed_attempts, locked_until, last_login, created_at, hmac)
                VALUES (?, ?, 'customer', NULL, 0, 0, 0, NULL, NULL, ?, '')
            """, (username.lower(), pw_hash, now))
            user_id = cur.lastrowid

            cust_record = {**customer_record_base, "user_id": user_id}
            cust_mac = compute_record_hmac(cust_record)

            cur.execute("""
                INSERT INTO customers
                    (user_id, customer_id, full_name, email, phone, address, kyc_status, created_at, hmac)
                VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)
            """, (
                user_id, customer_id,
                full_name.strip(), email.strip().lower(), phone.strip(),
                address.strip(), now, cust_mac,
            ))

        # Recompute user HMAC from the actual persisted row (all DB columns present)
        from hmac_refresh import refresh_user_hmac
        refresh_user_hmac(user_id)

        log_event("ACCOUNT_REGISTER", "success", username=username, user_id=user_id,
                  detail=f"role=customer customer_id={customer_id}")
        return True, f"Account created. Your Customer ID is: {customer_id}"

    except Exception as exc:
        if "UNIQUE" in str(exc):
            return False, "An account with that email or username already exists."
        log_event("ACCOUNT_REGISTER", "failure", username=username,
                  detail=f"error={type(exc).__name__}")
        return False, "Registration failed due to a system error. Please try again."



def register_employee(
    username: str,
    password: str,
    full_name: str,
    email: str,
    phone: str,
    department: str,
    job_title: str,
    access_level: str = "standard",
) -> tuple[bool, str]:
    """
    Create a new employee account.
    Employee ID is auto-generated.
    """
    from validators import validate_department, validate_job_title

    for field, val, fn in [
        ("username", username, validate_username),
        ("full name", full_name, validate_full_name),
        ("email", email, validate_email),
        ("phone", phone, validate_phone),
        ("department", department, validate_department),
        ("job title", job_title, validate_job_title),
    ]:
        ok, msg = fn(val)
        if not ok:
            return False, msg

    ok, msg = validate_password_strength(password)
    if not ok:
        return False, msg

    if _get_user_by_username(username):
        return False, "Registration failed. Please choose a different username."

    valid_levels = {"standard", "senior", "manager", "admin"}
    if access_level not in valid_levels:
        access_level = "standard"

    now = time.time()
    pw_hash = hash_password(password)
    employee_id = "EMP-" + secrets.token_hex(6).upper()

    user_record = {
        "username": username.lower(),
        "password_hash": pw_hash,
        "role": "employee",
        "created_at": now,
    }
    user_mac = compute_record_hmac(user_record)

    try:
        with db_cursor() as cur:
            cur.execute("""
                INSERT INTO users
                    (username, password_hash, role, totp_secret, mfa_enabled,
                     is_locked, failed_attempts, locked_until, last_login, created_at, hmac)
                VALUES (?, ?, 'employee', NULL, 0, 0, 0, NULL, NULL, ?, '')
            """, (username.lower(), pw_hash, now))
            user_id = cur.lastrowid

            emp_record = {
                "user_id": user_id, "employee_id": employee_id,
                "full_name": full_name.strip(), "email": email.strip().lower(),
                "phone": phone.strip(), "department": department,
                "job_title": job_title.strip(), "access_level": access_level,
                "created_at": now,
            }
            emp_mac = compute_record_hmac(emp_record)

            cur.execute("""
                INSERT INTO employees
                    (user_id, employee_id, full_name, email, phone,
                     department, job_title, access_level, created_at, hmac)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                user_id, employee_id,
                full_name.strip(), email.strip().lower(), phone.strip(),
                department, job_title.strip(), access_level, now, emp_mac,
            ))
        
        # Recompute user HMAC from the actual persisted row (all DB columns present)
        from hmac_refresh import refresh_user_hmac
        refresh_user_hmac(user_id)

        log_event("ACCOUNT_REGISTER", "success", username=username, user_id=user_id,
                  detail=f"role=employee department={department}")
        return True, f"Employee account created. Employee ID: {employee_id}"

    except Exception as exc:
        if "UNIQUE" in str(exc):
            return False, "An account with that email or username already exists."
        log_event("ACCOUNT_REGISTER", "failure", username=username,
                  detail=f"error={type(exc).__name__}")
        return False, "Registration failed due to a system error."


def attempt_login(username: str, password: str) -> tuple[bool, str, Optional[dict]]:
    """
    Phase 1 of login: verify username + password.
    Returns (success, message, user_dict_or_None).
    If MFA is enabled, caller must follow up with verify_mfa_and_create_session().
    """
    user = _get_user_by_username(username)

    if not user:
        # Deliberately slow path to mitigate timing-based enumeration.
        # We still hash to consume ~equal CPU time.
        hash_password("dummy_constant_padding_value_1234!")
        log_event("AUTH_LOGIN_FAILURE", "failure", username=username,
                  detail="user_not_found")
        return False, "Invalid username or password.", None

    locked, lock_msg = _check_lockout(user)
    if locked:
        log_event("AUTH_LOGIN_FAILURE", "failure", username=username,
                  user_id=user["id"], detail="account_locked")
        return False, lock_msg, None

    if not verify_password(password, user["password_hash"]):
        _increment_failed_attempts(user["id"])
        attempts = user["failed_attempts"] + 1
        remaining = MAX_FAILED_ATTEMPTS - attempts
        log_event("AUTH_LOGIN_FAILURE", "failure", username=username,
                  user_id=user["id"], detail=f"bad_password attempt={attempts}")
        if remaining > 0:
            return False, f"Invalid username or password. {remaining} attempt(s) remaining.", None
        else:
            return False, "Too many failed attempts. Account is now locked.", None

    # Password OK
    log_event("AUTH_LOGIN_SUCCESS", "success", username=username, user_id=user["id"])
    return True, "Password verified.", user


def verify_mfa_and_create_session(user: dict, totp_code: str) -> tuple[bool, str, Optional[str]]:
    """
    Phase 2 of login (when MFA is enabled): verify TOTP then issue session.
    Returns (success, message, session_token_or_None).
    """
    from validators import validate_totp_code
    ok, msg = validate_totp_code(totp_code)
    if not ok:
        return False, msg, None

    if not verify_totp(user["totp_secret"], totp_code):
        log_event("AUTH_MFA_FAILURE", "failure", username=user["username"],
                  user_id=user["id"])
        return False, "Invalid OTP code. Please try again.", None

    token = _create_session(user["id"])
    _reset_failed_attempts(user["id"])
    _update_last_login(user["id"])
    log_event("AUTH_MFA_SUCCESS", "success", username=user["username"],
              user_id=user["id"])
    return True, "Login successful.", token


def create_session_no_mfa(user: dict) -> str:
    """Create a session for a user who does not have MFA enabled."""
    token = _create_session(user["id"])
    _reset_failed_attempts(user["id"])
    _update_last_login(user["id"])
    return token





























