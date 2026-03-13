@echo off
:: ============================================================
:: secureChat — Windows one-click launcher
::
:: Double-click this file to start secureChat.
:: Everything is set up automatically:
::   1. Python dependencies are installed
::   2. Tor is found/downloaded and a .onion address is created
::   3. The server starts — no manual configuration needed
::
:: Requirements:
::   - Python 3.9 or newer  (https://www.python.org/downloads/)
::     Tick "Add python.exe to PATH" during installation.
::   - Internet connection on first run only (downloads Tor +
::     Python packages; subsequent runs work fully offline)
:: ============================================================

:: Change to the folder that contains this script so that
:: server.py and all other files are found correctly.
cd /d "%~dp0"

:: ── Check Python ─────────────────────────────────────────────
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo  ERROR: Python was not found on your PATH.
    echo  Please install Python 3.9 or newer from https://www.python.org/downloads/
    echo  Make sure to tick "Add python.exe to PATH" during installation.
    echo.
    pause
    exit /b 1
)

:: ── Start secureChat (zero-config) ───────────────────────────
python run.py

:: Keep the window open after the server exits so you can read any errors.
echo.
echo  Server stopped.
pause
