


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



























































































