


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




















































































