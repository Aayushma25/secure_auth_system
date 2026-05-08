#!/usr/bin/env bash
# =============================================================================
# run.sh — Executable launcher for the FinTech Secure Authentication System
# =============================================================================
# USAGE (Linux / macOS):
#   chmod +x run.sh       (make it executable — only needed once)
#   ./run.sh              (run the application)
# =============================================================================

echo ""
echo "============================================================"
echo "   FinTech Secure Authentication System"
echo "   Launcher Script for Linux / macOS"
echo "============================================================"
echo ""

# ── Step 1: Check Python is installed ───────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    echo "ERROR: Python 3 is not installed or not in your PATH."
    echo "Please install Python 3.11 or higher from https://www.python.org"
    exit 1
fi

# ── Step 2: Check Python version is 3.11 or higher ──────────────────────────
PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
REQUIRED_MAJOR=3
REQUIRED_MINOR=11

ACTUAL_MAJOR=$(python3 -c "import sys; print(sys.version_info.major)")
ACTUAL_MINOR=$(python3 -c "import sys; print(sys.version_info.minor)")

if [ "$ACTUAL_MAJOR" -lt "$REQUIRED_MAJOR" ] || \
   ([ "$ACTUAL_MAJOR" -eq "$REQUIRED_MAJOR" ] && [ "$ACTUAL_MINOR" -lt "$REQUIRED_MINOR" ]); then
    echo "ERROR: Python $REQUIRED_MAJOR.$REQUIRED_MINOR or higher is required."
    echo "Your Python version: $PYTHON_VERSION"
    echo "Please upgrade from https://www.python.org"
    exit 1
fi

echo "Python version: $PYTHON_VERSION  ✓"

# ── Step 3: Check colorama is installed — install if missing ────────────────
if ! python3 -c "import colorama" &>/dev/null; then
    echo "Installing required dependency: colorama..."
    pip3 install colorama
    if [ $? -ne 0 ]; then
        echo "WARNING: Could not install colorama."
        echo "The application will run without terminal colours."
    fi
else
    echo "colorama: installed  ✓"
fi

# ── Step 4: Move into the project directory ──────────────────────────────────
# Get the directory where this script lives
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Step 5: Check main.py exists ─────────────────────────────────────────────
if [ ! -f "main.py" ]; then
    echo "ERROR: main.py not found in $SCRIPT_DIR"
    echo "Please make sure run.sh is in the same folder as main.py"
    exit 1
fi

echo "Project directory: $SCRIPT_DIR  ✓"
echo ""
echo "Starting application..."
echo "============================================================"
echo ""

# ── Step 6: Run the application ──────────────────────────────────────────────
python3 main.py

# ── Step 7: Exit with the same code as the application ───────────────────────
exit $?
