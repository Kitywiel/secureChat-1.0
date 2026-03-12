@echo off
:: ============================================================
:: secureChat — Windows launcher
:: Double-click this file (or run it in a Command Prompt) to
:: start the secureChat server on http://127.0.0.1:5000
:: ============================================================

:: Change to the folder that contains this script so that
:: server.py and the database are always found correctly.
cd /d "%~dp0"

:: ── Check Python ────────────────────────────────────────────
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

:: ── Install / update dependencies ───────────────────────────
echo Installing / verifying dependencies...
python -m pip install --quiet -r requirements.txt
if %errorlevel% neq 0 (
    echo.
    echo  ERROR: pip install failed.  Check that you have an internet connection
    echo  and that requirements.txt is present in the same folder as this script.
    echo.
    pause
    exit /b 1
)

:: ── Start the server ────────────────────────────────────────
echo.
echo  secureChat is starting on http://127.0.0.1:5000
echo  To expose over Tor, configure a Tor hidden service (see README.md).
echo  Press Ctrl+C to stop the server.
echo.
python server.py

:: Keep the window open after the server exits so you can read any errors.
echo.
echo  Server stopped.
pause
