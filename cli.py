


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













































































