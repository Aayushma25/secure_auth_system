


#-----------------------------CLI--------------------------------


import getpass
import os
import sys
import time
from typing import Optional


try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class _NoColor:
        def __getattr__(self, _): return ""
    Fore = Style = _NoColor()


import auth
import recovery
import integrity
import audit
from database import init_db
from validators import (
    validate_username, validate_email, validate_phone,
    validate_full_name, validate_department, validate_job_title,
)
from security import validate_password_strength



# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

BANNER = r"""
       Secure Authentication System  |  FinTech Edition
"""


def clr() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def print_banner() -> None:
    print(Fore.CYAN + BANNER + Style.RESET_ALL)
    print(Fore.YELLOW + "  " + "─" * 58 + Style.RESET_ALL)

def success(msg: str) -> None:
    print(f"\n{Fore.GREEN}  ✔️  {msg}{Style.RESET_ALL}\n")


def error(msg: str) -> None:
    print(f"\n{Fore.RED}  ✖️  {msg}{Style.RESET_ALL}\n")


def info(msg: str) -> None:
    print(f"\n{Fore.CYAN}  ℹ️  {msg}{Style.RESET_ALL}\n")


def warn(msg: str) -> None:
    print(f"\n{Fore.YELLOW}  ⚠️  {msg}{Style.RESET_ALL}\n")


def header(title: str) -> None:
    width = 60
    print(f"\n{Fore.CYAN}{'─' * width}")
    print(f"  {title}")
    print(f"{'─' * width}{Style.RESET_ALL}\n")


def separator() -> None:
    print(Fore.YELLOW + "  " + "─" * 58 + Style.RESET_ALL)


def prompt(label: str, required: bool = True) -> str:
    while True:
        val = input(f"  {Fore.WHITE}{label}{Style.RESET_ALL}: ").strip()
        if val or not required:
            return val
        error("This field is required.")


def prompt_password(label: str = "Password") -> str:
    while True:
        val = getpass.getpass(f"  {label}: ")
        if val:
            return val
        error("Password cannot be empty.")


def pick_from_menu(title: str, options: list[str]) -> int:
    """
    Show a numbered menu and return the 0-based index of the chosen option.
    """
    print(f"\n{Fore.CYAN}  {title}{Style.RESET_ALL}")
    for i, opt in enumerate(options, 1):
        print(f"    {Fore.WHITE}[{i}]{Style.RESET_ALL} {opt}")
    print()
    while True:
        raw = input("  Your choice: ").strip()
        if raw.isdigit():
            idx = int(raw) - 1
            if 0 <= idx < len(options):
                return idx
        error(f"Please enter a number between 1 and {len(options)}.")


def prompt_validated(label: str, validator, required: bool = True) -> str:
    """Repeatedly prompt until validator returns ok=True."""
    while True:
        val = prompt(label, required=required)
        if not val and not required:
            return val
        ok, msg = validator(val)
        if ok:
            return val
        error(msg)


# ---------------------------------------------------------------------------
# Role selection
# ---------------------------------------------------------------------------

ROLES = ["Customer", "Employee"]


def select_role() -> str:
    """Show dropdown-style role picker. Returns 'customer' or 'employee'."""
    idx = pick_from_menu("Select your role:", ROLES)
    return ROLES[idx].lower()



# ---------------------------------------------------------------------------
# Registration flows
# ---------------------------------------------------------------------------

def registration_flow() -> None:
    header("New Account Registration")
    role = select_role()

    if role == "customer":
        _register_customer_flow()
    else:
        _register_employee_flow()


def _register_customer_flow() -> None:
    header("Customer Registration")
    print("  Please provide the following details.\n")

    username = prompt_validated("Username (3-30 chars, starts with a letter)", validate_username)
    full_name = prompt_validated("Full Name", validate_full_name)
    email = prompt_validated("Email Address", validate_email)
    phone = prompt_validated("Phone Number (with country code, e.g. +977-9812345678)", validate_phone)
    address = prompt("Home Address (optional)", required=False)

    print(f"\n  {Fore.CYAN}Choose a strong password.{Style.RESET_ALL}")
    print("  Requirements: 12+ chars, uppercase, lowercase, digit, special char.\n")
    while True:
        password = prompt_password("Password")
        ok, msg = validate_password_strength(password)
        if not ok:
            error(msg)
            continue
        confirm = prompt_password("Confirm Password")
        if password != confirm:
            error("Passwords do not match. Please try again.")
            continue
        break

    info("Creating your account…")
    ok, msg = auth.register_customer(username, password, full_name, email, phone, address)
    if ok:
        success(msg)
        info("You can now log in. We recommend enabling MFA after your first login.")
    else:
        error(msg)


def _register_employee_flow() -> None:
    header("Employee Registration")
    print("  Please provide your employee details.\n")

    username = prompt_validated("Username", validate_username)
    full_name = prompt_validated("Full Name", validate_full_name)
    email = prompt_validated("Work Email", validate_email)
    phone = prompt_validated("Phone Number", validate_phone)

    departments = [
        "Engineering", "Finance", "Compliance", "Risk",
        "Operations", "Customer Support", "Product", "HR",
        "Legal", "Marketing", "Executive",
    ]
    dept_idx = pick_from_menu("Select Department:", departments)
    department = departments[dept_idx]

    job_title = prompt_validated("Job Title", validate_job_title)

    access_levels = ["standard", "senior", "manager", "admin"]
    lvl_idx = pick_from_menu("Access Level:", [l.title() for l in access_levels])
    access_level = access_levels[lvl_idx]

    print(f"\n  {Fore.CYAN}Choose a strong password.{Style.RESET_ALL}")
    print("  Requirements: 12+ chars, uppercase, lowercase, digit, special char.\n")
    while True:
        password = prompt_password("Password")
        ok, msg = validate_password_strength(password)
        if not ok:
            error(msg)
            continue
        confirm = prompt_password("Confirm Password")
        if password != confirm:
            error("Passwords do not match.")
            continue
        break

    info("Creating employee account…")
    ok, msg = auth.register_employee(
        username, password, full_name, email, phone,
        department, job_title, access_level,
    )
    if ok:
        success(msg)
    else:
        error(msg)





# ---------------------------------------------------------------------------
# Login flow
# ---------------------------------------------------------------------------

def login_flow() -> None:
    header("Login")
    role = select_role()

    username = prompt("Username")
    password = prompt_password("Password")

    info("Verifying credentials…")
    ok, msg, user = auth.attempt_login(username, password)

    if not ok:
        error(msg)
        return

    if not user or user.get("role") != role:
        error("Username or password is incorrect, or role mismatch.")
        return

    # --- MFA check ---
    session_token: Optional[str] = None

    if user.get("mfa_enabled"):
        print(f"\n  {Fore.CYAN}Two-Factor Authentication Required{Style.RESET_ALL}")
        info("Open your authenticator app and enter the 6-digit code.")
        for attempt in range(3):
            code = prompt("  Enter OTP code")
            mfa_ok, mfa_msg, token = auth.verify_mfa_and_create_session(user, code)
            if mfa_ok:
                session_token = token
                break
            error(mfa_msg)
            if attempt == 2:
                error("Too many incorrect OTP attempts.")
                return
    else:
        session_token = auth.create_session_no_mfa(user)
        warn("MFA is not enabled on your account. We strongly recommend enabling it.")

    success(f"Welcome, {username}! Login successful.")

    if user["role"] == "customer":
        customer_dashboard(user, session_token)
    else:
        employee_dashboard(user, session_token)









# ---------------------------------------------------------------------------
# Customer dashboard
# ---------------------------------------------------------------------------

def customer_dashboard(user: dict, session_token: str) -> None:
    while True:
        clr()
        print_banner()
        header(f"Customer Dashboard  —  {user['username'].upper()}")

        options = [
            "View My Profile",
            "Enable / Manage MFA",
            "Change Password",
            "View My Activity Log",
            "Run Integrity Check (my records)",
            "Logout",
        ]
        idx = pick_from_menu("What would you like to do?", options)

        if idx == 0:   # View profile
            _show_customer_profile(user["id"])
        elif idx == 1: # MFA
            _mfa_menu(user, session_token)
        elif idx == 2: # Change password
            _change_password_flow(user)
        elif idx == 3: # Activity log
            _show_user_activity(user["username"])
        elif idx == 4: # Integrity check
            _run_self_integrity_check(user["id"])
        elif idx == 5: # Logout
            auth.logout(session_token, user["username"])
            success("You have been logged out.")
            break

        if idx != 5:
            input(f"\n  {Fore.YELLOW}Press Enter to return to the dashboard…{Style.RESET_ALL}")


def _show_customer_profile(user_id: int) -> None:
    header("My Profile")
    profile = auth.get_customer_profile(user_id)
    if not profile:
        error("Could not load profile.")
        return
    fields = [
        ("Customer ID",   profile.get("customer_id", "—")),
        ("Full Name",     profile.get("full_name", "—")),
        ("Email",         profile.get("email", "—")),
        ("Phone",         profile.get("phone", "—")),
        ("Address",       profile.get("address") or "—"),
        ("KYC Status",    profile.get("kyc_status", "—").upper()),
        ("MFA Enabled",   "Yes" if profile.get("mfa_enabled") else "No"),
        ("Member Since",  _fmt_ts(profile.get("reg_date"))),
        ("Last Login",    _fmt_ts(profile.get("last_login"))),
    ]
    for label, value in fields:
        print(f"  {Fore.CYAN}{label:<16}{Style.RESET_ALL}  {value}")










# ---------------------------------------------------------------------------
# Employee dashboard
# ---------------------------------------------------------------------------

def employee_dashboard(user: dict, session_token: str) -> None:
    while True:
        clr()
        print_banner()
        header(f"Employee Dashboard  —  {user['username'].upper()}")

        options = [
            "View My Profile",
            "Enable / Manage MFA",
            "Change Password",
            "View My Activity Log",
            "Run Full Integrity Check (admin-level)",
            "View Recent Audit Trail",
            "Logout",
        ]
        idx = pick_from_menu("What would you like to do?", options)

        if idx == 0:
            _show_employee_profile(user["id"])
        elif idx == 1:
            _mfa_menu(user, session_token)
        elif idx == 2:
            _change_password_flow(user)
        elif idx == 3:
            _show_user_activity(user["username"])
        elif idx == 4:
            _run_full_integrity_check()
        elif idx == 5:
            _show_audit_trail()
        elif idx == 6:
            auth.logout(session_token, user["username"])
            success("You have been logged out.")
            break

        if idx != 6:
            input(f"\n  {Fore.YELLOW}Press Enter to return to the dashboard…{Style.RESET_ALL}")


def _show_employee_profile(user_id: int) -> None:
    header("My Profile")
    profile = auth.get_employee_profile(user_id)
    if not profile:
        error("Could not load profile.")
        return
    fields = [
        ("Employee ID",  profile.get("employee_id", "—")),
        ("Full Name",    profile.get("full_name", "—")),
        ("Email",        profile.get("email", "—")),
        ("Phone",        profile.get("phone", "—")),
        ("Department",   profile.get("department", "—")),
        ("Job Title",    profile.get("job_title", "—")),
        ("Access Level", profile.get("access_level", "—").upper()),
        ("MFA Enabled",  "Yes" if profile.get("mfa_enabled") else "No"),
        ("Joined",       _fmt_ts(profile.get("reg_date"))),
        ("Last Login",   _fmt_ts(profile.get("last_login"))),
    ]
    for label, value in fields:
        print(f"  {Fore.CYAN}{label:<16}{Style.RESET_ALL}  {value}")
































































