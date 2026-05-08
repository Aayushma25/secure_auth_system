@echo off
REM =============================================================================
REM run.bat — Executable launcher for the FinTech Secure Authentication System
REM =============================================================================
REM USAGE (Windows):
REM   Double-click run.bat    (from File Explorer)
REM   OR
REM   run.bat                 (from Command Prompt)
REM =============================================================================

echo.
echo ============================================================
echo    FinTech Secure Authentication System
echo    Launcher Script for Windows
echo ============================================================
echo.

REM ── Step 1: Check Python is installed ───────────────────────────────────────
python --version >nul 2>&1
IF ERRORLEVEL 1 (
    echo ERROR: Python is not installed or not in your PATH.
    echo Please install Python 3.11 or higher from https://www.python.org
    echo Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
)

REM ── Step 2: Check Python version is 3.11 or higher ──────────────────────────
FOR /F "tokens=*" %%i IN ('python -c "import sys; print(sys.version_info.major * 100 + sys.version_info.minor)"') DO SET PYVER=%%i

IF %PYVER% LSS 311 (
    FOR /F "tokens=*" %%v IN ('python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"') DO SET PVSTR=%%v
    echo ERROR: Python 3.11 or higher is required.
    echo Your Python version: %PVSTR%
    echo Please upgrade from https://www.python.org
    pause
    exit /b 1
)

FOR /F "tokens=*" %%v IN ('python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')"') DO SET PVFULL=%%v
echo Python version: %PVFULL%  OK

REM ── Step 3: Check colorama is installed — install if missing ────────────────
python -c "import colorama" >nul 2>&1
IF ERRORLEVEL 1 (
    echo Installing required dependency: colorama...
    pip install colorama
    IF ERRORLEVEL 1 (
        echo WARNING: Could not install colorama.
        echo The application will run without terminal colours.
    )
) ELSE (
    echo colorama: installed  OK
)

REM ── Step 4: Move into the project directory ──────────────────────────────────
cd /d "%~dp0"

REM ── Step 5: Check main.py exists ─────────────────────────────────────────────
IF NOT EXIST "main.py" (
    echo ERROR: main.py not found in %~dp0
    echo Please make sure run.bat is in the same folder as main.py
    pause
    exit /b 1
)

echo Project directory: %~dp0  OK
echo.
echo Starting application...
echo ============================================================
echo.

REM ── Step 6: Run the application ──────────────────────────────────────────────
python main.py

REM ── Step 7: Keep window open if there was an error ───────────────────────────
IF ERRORLEVEL 1 (
    echo.
    echo Application exited with an error.
    pause
)

exit /b %ERRORLEVEL%
