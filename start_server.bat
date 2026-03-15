@echo off
cd /d "%~dp0"

:: --port 5000
:: --host 127.0.0.1
:: --db-path C:\path\to\securechat.db

:: --clearnet-path your-custom-or-auto-generated-path
:: --admin-path your-custom-or-auto-generated-path
:: --admin-passcode your-custom-or-auto-generated-passcode
:: --admin-webhook-token your-custom-or-auto-generated-token
:: --mesh-token your-custom-or-auto-generated-token

:: --no-tor
:: --tor-path C:\path\to\tor.exe
:: --onion-address yourhostname.onion

:: --mesh-join http://your-other-server.onion/mesh/peer/connect

:: --mail-domain yourdomain.com
:: --smtp-port 25
:: --relay-secret your-secret-here

:: --auto-update

:: --slow-mode
:: --slow-mode-delay 2.0

:: --ddos-enabled 1
:: --ddos-req-limit 200
:: --ddos-window-sec 10
:: --ddos-ban-sec 300
:: --ddos-auto-lockdown-threshold 50

:: --spam-enabled 1
:: --spam-msg-limit 20
:: --spam-msg-window 10
:: --spam-mail-limit 5
:: --spam-mail-window 60

:: --history-limit 100

:: --mailtm-enabled 1

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

python run.py

echo.
echo  Server stopped.
pause
