@echo off
:: ============================================================
:: secureChat — Windows launcher (auto Tor onion URL)
::
:: Double-click this file to:
::   1. Install Python dependencies (automatically)
::   2. Find or download the Tor Expert Bundle (automatically)
::   3. Start Tor and create a public .onion hidden service
::   4. Display your .onion address in this window
::   5. Start the secureChat server
::
:: Requirements:
::   - Python 3.9 or newer  (https://www.python.org/downloads/)
::     Tick "Add python.exe to PATH" during installation.
::   - Internet connection (only needed on first run to download
::     Tor and Python packages; subsequent runs work offline)
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

:: ── Install / update dependencies ────────────────────────────
echo.
echo  Installing / verifying Python dependencies ...
echo  (this is skipped automatically on subsequent runs if already up to date)
echo.
python -m pip install --quiet -r requirements.txt
if %errorlevel% neq 0 (
    echo.
    echo  ERROR: pip install failed.
    echo  Check that you have an internet connection and that
    echo  requirements.txt is present in the same folder as this script.
    echo.
    pause
    exit /b 1
)

:: ── Start secureChat with automatic Tor hidden service ────────
echo.
echo  Starting secureChat with Tor hidden service ...
echo  On first run Tor may take up to 90 seconds to connect.
echo  Your .onion address will appear below once Tor is ready.
echo.
python start_with_tor.py

:: Keep the window open after the server exits so you can read any errors.
echo.
echo  Server stopped.
pause
