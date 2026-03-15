@echo off
cd /d "%~dp0"

:: secureChat — Windows launcher
:: ─────────────────────────────────────────────────────────────────────────────
:: To change a setting, remove the leading "::" from the matching SET line.
:: Full documentation: info-files\start-server-config.md
:: ─────────────────────────────────────────────────────────────────────────────

:: ─── Server ──────────────────────────────────────────────────────────────────
:: SET PORT=5000
:: SET HOST=127.0.0.1
:: SET DB_PATH=C:\path\to\securechat.db

:: ─── Custom / persistent URL paths ──────────────────────────────────────────
:: SET CLEARNET_PATH=your-custom-or-auto-generated-path
:: SET ADMIN_PATH=your-custom-or-auto-generated-path
:: SET ADMIN_PASSCODE=your-custom-or-auto-generated-passcode
:: SET ADMIN_WEBHOOK_TOKEN=your-custom-or-auto-generated-token
:: SET MESH_TOKEN=your-custom-or-auto-generated-token

:: ─── Tor ─────────────────────────────────────────────────────────────────────
:: SET NO_TOR=1
:: SET TOR_PATH=C:\path\to\tor.exe
:: SET ONION_ADDRESS=yourhostname.onion

:: ─── Mesh / Federation ───────────────────────────────────────────────────────
:: SET MESH_JOIN=http://remote-server.onion/mesh/peer/connect

:: ─── Mail / SMTP ─────────────────────────────────────────────────────────────
:: SET MAIL_DOMAIN=yourdomain.com
:: SET SMTP_PORT=25
:: SET RELAY_SECRET=your-secret-here

:: ─── Auto-update ─────────────────────────────────────────────────────────────
:: SET AUTO_UPDATE=1

:: ─── Slow mode ───────────────────────────────────────────────────────────────
:: SET SLOW_MODE=0
:: SET SLOW_MODE_DELAY=2.0

:: ─── DDoS protection ─────────────────────────────────────────────────────────
:: SET DDOS_ENABLED=1
:: SET DDOS_REQ_LIMIT=200
:: SET DDOS_WINDOW_SEC=10
:: SET DDOS_BAN_SEC=300
:: SET DDOS_AUTO_LOCKDOWN_THRESHOLD=50

:: ─── Spam protection ─────────────────────────────────────────────────────────
:: SET SPAM_ENABLED=1
:: SET SPAM_MSG_LIMIT=20
:: SET SPAM_MSG_WINDOW=10
:: SET SPAM_MAIL_LIMIT=5
:: SET SPAM_MAIL_WINDOW=60

:: ─── Chat history ─────────────────────────────────────────────────────────────
:: SET HISTORY_LIMIT=100

:: ─── mail.tm ─────────────────────────────────────────────────────────────────
:: SET MAILTM_ENABLED=1

:: ─────────────────────────────────────────────────────────────────────────────

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
