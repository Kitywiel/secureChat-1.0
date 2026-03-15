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
::
:: ── Configuration ─────────────────────────────────────────────
:: All options below are optional.  secureChat works out-of-the-box
:: without changing anything here.  To activate a setting, remove
:: the leading ":: " from the SET line and set your desired value,
:: then save this file and double-click it to start the server.
:: ============================================================

:: Change to the folder that contains this script so that
:: server.py and all other files are found correctly.
cd /d "%~dp0"

:: ── Server ───────────────────────────────────────────────────
:: TCP port the server listens on (default: 5000)
:: SET PORT=5000

:: Bind interface (default: 127.0.0.1 when Tor is active, 0.0.0.0 otherwise)
:: SET HOST=127.0.0.1

:: Path to the SQLite database file (default: securechat.db next to run.py)
:: SET DB_PATH=C:\path\to\securechat.db

:: ── Custom / persistent URL paths ────────────────────────────
:: By default secureChat auto-generates these secrets on the first run and
:: writes the values back into this file as active SET lines (without ":: ")
:: so the same paths are reused on every subsequent restart.
::
:: You can set a custom value here before the first run — for example a
:: memorable name you want to share with specific people:
::   SET CLEARNET_PATH=MySecureChatServiceName
::   SET ADMIN_PATH=MyPrivateAdminArea
::
:: Rules:
::   CLEARNET_PATH should be hard to guess (at least 20 random-looking chars).
::   ADMIN_PATH    should be very hard to guess (at least 50 random-looking chars).
::   ADMIN_PASSCODE is the password that protects the admin panel.
::   ADMIN_WEBHOOK_TOKEN is the secret that authorises the incoming webhook.
::   MESH_TOKEN is the invite secret for the server-to-server mesh network.
::
:: To rotate a secret, delete its SET line below and restart.

:: Clearnet access URL path (default: auto-generated)
:: SET CLEARNET_PATH=your-custom-or-auto-generated-path

:: Admin panel URL path (default: auto-generated, 200 chars)
:: SET ADMIN_PATH=your-custom-or-auto-generated-path

:: Admin panel passcode (default: auto-generated, 100 chars)
:: SET ADMIN_PASSCODE=your-custom-or-auto-generated-passcode

:: Admin incoming webhook token (default: auto-generated)
:: SET ADMIN_WEBHOOK_TOKEN=your-custom-or-auto-generated-token

:: Mesh network invite secret (default: auto-generated)
:: SET MESH_TOKEN=your-custom-or-auto-generated-token

:: ── Tor ──────────────────────────────────────────────────────
:: Set to 1 to skip Tor even if it is installed (default: not set / Tor enabled)
:: SET NO_TOR=1

:: Absolute path to the tor binary (default: auto-detected)
:: SET TOR_PATH=C:\path\to\tor.exe

:: ── Mesh / Federation ────────────────────────────────────────
:: Automatically join a remote peer at startup.
:: Set both MESH_JOIN and MESH_TOKEN together.
::
:: MESH_JOIN is the full /mesh/peer/connect URL of the remote server.
:: MESH_TOKEN is the MESH_TOKEN printed by the remote server at startup.
::
:: SET MESH_JOIN=http://zn6pflnphvgs5usexqam4q6l55j2nfa6eal2rrofdcq3sbgs57brdeid.onion/mesh/peer/connect
:: (Set MESH_TOKEN in the "Custom URL paths" section above)

:: ── Mail / SMTP ──────────────────────────────────────────────
:: Your real mail domain (e.g. yourdomain.com).
:: Required to accept inbound email directly on port 25.
:: Without this, secureChat uses the automatic mail.tm disposable address.
:: SET MAIL_DOMAIN=yourdomain.com

:: SMTP listen port (default: 25; use 2525 if not running as administrator)
:: SET SMTP_PORT=25

:: ── Relay webhook (IP-private inbound email) ─────────────────
:: Secret shared with your relay service (Mailgun, SendGrid, Cloudflare, ...).
:: Auto-generated if not set; printed to the console at startup.
:: SET RELAY_SECRET=your-secret-here

:: ── Auto-update (git pull) ───────────────────────────────────
:: Set to 1 to automatically run "git pull --ff-only" before starting.
:: Disabled by default. Only works when launched from a git clone.
:: SET AUTO_UPDATE=1

:: ── Slow mode ────────────────────────────────────────────────
:: Set to 1 to start the server with slow mode already active (default: off).
:: SET SLOW_MODE=0

:: Delay in seconds applied to each request while slow mode is active (default: 2.0).
:: SET SLOW_MODE_DELAY=2.0

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
