
#----------------------------------------------------------------------------------------------------------------

#---------------   main.py — Entry point for the FinTech Secure Authentication System. ---------------

#------------------------------------------------------------------------------------------------------------------


import sys

if sys.version_info < (3, 11):
    sys.exit("Python 3.11 or later is required.")

from cli import main_menu

if __name__ == "__main__":
    main_menu()
