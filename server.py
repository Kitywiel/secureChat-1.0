#!/usr/bin/env python3
"""
secureChat — end-to-end encrypted chat relay server.

The server acts as a relay: it routes encrypted payloads between WebSocket
peers inside the same room and persists them in a local SQLite database so
that the message history survives server restarts.  It never has access to
plaintext; all encryption and decryption happens in the client browser using
the Web Crypto API.

Usage
-----
    pip install -r requirements.txt
    python server.py                        # listens on 127.0.0.1:5000
    PORT=8080 python server.py              # custom port
    HOST=0.0.0.0 PORT=8080 python server.py # bind all interfaces

Environment variables
---------------------
    DB_PATH        Path to the SQLite database file (default: securechat.db
                   next to server.py)
    HISTORY_LIMIT  Number of messages to store and replay per room
                   (default: 100)

Tor hidden service
------------------
Run the server on 127.0.0.1 (default), then configure a Tor hidden service
to expose it as a .onion address.  See README.md for details, or run
start_server.bat (Windows) for fully automatic setup.
"""

from __future__ import annotations

import asyncio
import collections
import email as _email_lib
import hashlib
import io
import json
import logging
import os
import re
import secrets
import shutil
import sqlite3
import sys
import tempfile
import time
from email import policy as _email_policy
from pathlib import Path

import qrcode
import qrcode.constants
from aiosmtpd.controller import Controller as _SmtpController
from qrcode.image.svg import SvgImage as _QrSvgImage
from aiohttp import web, WSMsgType

try:
    import psutil as _psutil  # type: ignore[import-untyped]
    _PSUTIL_AVAILABLE = True
    # Prime both the system-wide and per-process CPU samplers so that
    # subsequent interval=None calls return meaningful values rather than 0.0.
    _psutil.cpu_percent(interval=None)
    _psutil.Process().cpu_percent(interval=None)
except ImportError:  # pragma: no cover
    _psutil = None  # type: ignore[assignment]
    _PSUTIL_AVAILABLE = False

try:
    import pynvml as _pynvml  # type: ignore[import-untyped]
    _pynvml.nvmlInit()
    _NVML_AVAILABLE = True
except Exception:  # pragma: no cover  # noqa: BLE001
    _pynvml = None  # type: ignore[assignment]
    _NVML_AVAILABLE = False

# ---------------------------------------------------------------------------
# Python version guard — asyncio.to_thread requires 3.9+
# ---------------------------------------------------------------------------
if sys.version_info < (3, 9):
    sys.exit(
        f"secureChat requires Python 3.9 or newer "
        f"(you are running {sys.version}).  "
        f"Please upgrade: https://www.python.org/downloads/"
    )

# ---------------------------------------------------------------------------
# Logging — never log message payloads.
# ---------------------------------------------------------------------------

class _ColourFormatter(logging.Formatter):
    """Apply ANSI colour codes when stderr is a TTY.

    Green   — creation events (room created, server starting, database ready)
    Yellow  — user-join events
    Red     — deletion / expiry / error events
    Purple  — share download events
    Pink    — share upload events
    Blue    — inactive room events
    Cyan    — in-chat file share events
    """

    _GREEN  = "\x1b[32m"
    _YELLOW = "\x1b[33m"
    _RED    = "\x1b[31m"
    _PURPLE = "\x1b[35m"
    _PINK   = "\x1b[95m"
    _BLUE   = "\x1b[34m"
    _CYAN   = "\x1b[36m"
    _ORANGE = "\x1b[38;5;208m"
    _RESET  = "\x1b[0m"

    # Sub-strings matched (lower-cased) against the formatted message
    _CREATION       = frozenset(["room created", "database ready", "securechat starting"])
    _DELETION       = frozenset(["room deleted", "room self-destructed", "cleaned up", "expired"])
    _JOINED         = frozenset(["peer joined"])
    _SHARE_UPLOAD   = frozenset(["share upload"])
    _SHARE_DOWNLOAD = frozenset(["share download"])
    _INACTIVE       = frozenset(["room inactive"])
    _CHAT_FILE      = frozenset(["chat file share"])
    _INBOX_CREATED  = frozenset(["inbox created"])
    _INBOX_MSG      = frozenset(["inbox filled", "inbox email received"])
    _INBOX_READ     = frozenset(["inbox read"])

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        # Only colour output when writing to a real terminal
        if not getattr(sys.stderr, "isatty", lambda: False)():
            return msg
        text = record.getMessage().lower()
        if record.levelno >= logging.WARNING or any(kw in text for kw in self._DELETION):
            return f"{self._RED}{msg}{self._RESET}"
        if any(kw in text for kw in self._SHARE_DOWNLOAD):
            return f"{self._PURPLE}{msg}{self._RESET}"
        if any(kw in text for kw in self._SHARE_UPLOAD):
            return f"{self._PINK}{msg}{self._RESET}"
        if any(kw in text for kw in self._CREATION):
            return f"{self._GREEN}{msg}{self._RESET}"
        if any(kw in text for kw in self._JOINED):
            return f"{self._YELLOW}{msg}{self._RESET}"
        if any(kw in text for kw in self._INACTIVE):
            return f"{self._BLUE}{msg}{self._RESET}"
        if any(kw in text for kw in self._CHAT_FILE):
            return f"{self._CYAN}{msg}{self._RESET}"
        if any(kw in text for kw in self._INBOX_CREATED):
            return f"{self._GREEN}{msg}{self._RESET}"
        if any(kw in text for kw in self._INBOX_MSG):
            return f"{self._ORANGE}{msg}{self._RESET}"
        if any(kw in text for kw in self._INBOX_READ):
            return f"{self._PURPLE}{msg}{self._RESET}"
        return msg


_log_handler = logging.StreamHandler()
_log_handler.setFormatter(_ColourFormatter(
    fmt="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
))
logging.root.setLevel(logging.INFO)
logging.root.addHandler(_log_handler)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
# Resolve __file__ to an absolute path so that relative invocations (e.g.
# "python server.py" from a different working directory on Windows) still
# place the database next to server.py rather than in the current directory.
_HERE = Path(__file__).resolve().parent

STATIC_DIR = _HERE / "static"

# Database — path defaults to the same directory as server.py
DB_PATH = Path(os.environ.get("DB_PATH", str(_HERE / "securechat.db")))

# Maximum messages stored *and* replayed per room.  Oldest messages are
# pruned automatically when the limit is exceeded.
HISTORY_LIMIT = int(os.environ.get("HISTORY_LIMIT", "100"))

# Maximum lengths enforced server-side (defence-in-depth; client also limits)
MAX_ROOM_ID_LEN = 64
MAX_DISPLAY_NAME_LEN = 32
MAX_IV_LEN = 24          # 12 raw bytes → 16 base64 chars; 24 allows padding variants
MAX_CIPHERTEXT_LEN = 8192  # ~6 KiB plaintext after base64 expansion

# In-chat file/image relay limits (files are never persisted)
# 50 MiB plaintext → ~67 MiB after AES-GCM + base64 encoding; large files are
# routed through the share system on the client side (no WebSocket involvement).
MAX_FILE_CIPHERTEXT_LEN = 68_000_000  # base64+AES-GCM limit; ≈50 MiB plaintext before encoding
MAX_MIME_LEN = 64                    # characters in a MIME type string
MAX_CHAT_FILENAME_LEN = 200          # characters in an in-chat attachment filename

# File-share constants
MAX_UPLOAD_BYTES = 10 * 1024 * 1024 * 1024  # 10 GB per file
MAX_FILENAME_LEN = 200                       # characters in the sanitised filename
_SHARE_TOKEN_BYTES = 32                      # 256-bit token → 43-char URL-safe base64

# Inbox constants
_INBOX_TOKEN_BYTES = 16                      # 128-bit token → ~22-char URL-safe base64 local part
MAX_INBOX_MESSAGE_LEN = 65536                # max bytes per message body

# Mesh peer security constants
# Limit the size of payloads that a remote peer can send to prevent amplification
# attacks and memory exhaustion.  The payload is a JSON-encoded chat message which
# is at most a few hundred KiB even for in-chat file transfers.
MAX_MESH_PAYLOAD_LEN = 100_000_000          # 100 MiB hard cap on the raw payload string
MAX_MESH_ROOM_ID_LEN = MAX_ROOM_ID_LEN      # reuse same room-id limit
INBOX_MIN_TTL_MINUTES = 1                    # minimum lifetime in minutes
INBOX_MAX_TTL_MINUTES = 1440                 # maximum lifetime in minutes (24 h)
INBOX_DEFAULT_TTL_MINUTES = 60              # default lifetime in minutes
# Real-email SMTP support — set MAIL_DOMAIN to your MX-pointed domain to enable inbound SMTP.
# SMTP_PORT defaults to 25; use a higher port (e.g. 2525) when running without root privileges.
MAIL_DOMAIN: str = os.environ.get("MAIL_DOMAIN", "")
SMTP_PORT: int = int(os.environ.get("SMTP_PORT", "25"))

# IP-privacy relay webhook support.
# Set RELAY_SECRET to a shared secret you configure in Mailgun / SendGrid / Cloudflare.
# When set, POST /inbox/relay only processes requests that include this secret.
# Leave unset to disable the relay endpoint entirely.
RELAY_SECRET: str = os.environ.get("RELAY_SECRET", "")

# ---------------------------------------------------------------------------
# mail.tm — free real-email integration (no DNS, no payment required).
# mail.tm provides public disposable addresses (@mail.tm, @bugfoo.com, etc.)
# that any server on the internet (Discord, Google, GitHub, …) can deliver to.
# Enabled automatically when neither MAIL_DOMAIN nor RELAY_SECRET is set,
# or force-disable with MAILTM_ENABLED=0.
# ---------------------------------------------------------------------------
MAILTM_API = "https://api.mail.tm"
# Opt-out: set MAILTM_ENABLED=0 to disable the mail.tm integration.
MAILTM_ENABLED: bool = os.environ.get("MAILTM_ENABLED", "1") not in ("0", "false", "no")

# Room-create / passcode constants
MAX_PASSCODE_LEN = 64                  # characters in a room or share passcode
MAX_DESTRUCT_MINUTES = 1440            # 24 hours maximum
MAX_WEBHOOK_URL_LEN = 512              # characters in a webhook URL

# Admin panel constants
# The admin panel is served on the SAME port as the main site, but hidden behind
# a 200-character randomly-generated URL path segment and a 100-character passcode.
# ADMIN_PORT is kept for backwards-compatibility but is no longer used.
ADMIN_SESSION_TTL = 3600               # 1 hour
ADMIN_LOGIN_RATE_WINDOW = 60           # seconds to track failed login attempts
ADMIN_LOGIN_MAX_ATTEMPTS = 10          # max failed attempts per IP in that window
_ADMIN_PASSCODE: str = ""              # set at startup (see _init_admin_credentials())
_ADMIN_PATH: str = ""                  # 200-char random URL segment, set at startup
_ADMIN_SESSIONS: dict[str, float] = {}  # token → expires_at
_ADMIN_WEBHOOK_TOKEN: str = ""         # set at startup (incoming webhook secret token)
# Brute-force rate-limiter: IP → list of failure timestamps (sliding window)
_ADMIN_LOGIN_FAILURES: dict[str, list[float]] = {}
# Hard-cap lockout: IP → unlock_timestamp.  Set after ADMIN_LOGIN_HARD_CAP cumulative
# failures within ADMIN_LOGIN_HARD_CAP_WINDOW seconds; prevents indefinite retry loops.
ADMIN_LOGIN_HARD_CAP = 30             # cumulative failures that trigger the hard lockout
ADMIN_LOGIN_HARD_CAP_WINDOW = 86400   # seconds over which cumulative failures are counted (24 h)
ADMIN_LOGIN_HARD_CAP_DURATION = 3600  # how long (seconds) the hard lockout lasts (1 h)
_ADMIN_LOGIN_HARD_LOCKOUT: dict[str, float] = {}  # IP → unlock_at

# Clearnet public access path — a 100-character randomly-generated URL path segment.
# Traffic from the server is routed through the 6-proxy SOCKS5 chain defined below.
# The clearnet path is set at startup (see _init_clearnet_path()).
_CLEARNET_PATH: str = ""               # 100-char random URL segment, set at startup

# Minimal HTML gate page returned when a share-download requires a passcode.
# {error} is replaced with either an empty string or an <p class="err">…</p> element.
_PASSCODE_GATE_PAGE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>secureChat — Enter Passcode</title>
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#0d0d0d;color:#e8e8e8;font-family:"Segoe UI",system-ui,sans-serif;
      display:flex;align-items:center;justify-content:center;min-height:100vh;padding:1rem}}
.card{{background:#1a1a1a;border:1px solid #2e2e2e;border-radius:12px;
       padding:2rem 1.75rem;width:100%;max-width:380px}}
h1{{font-size:1.2rem;margin-bottom:1rem}}
label{{display:block;font-size:.85rem;color:#888;margin-bottom:.35rem}}
input{{width:100%;padding:.65rem .75rem;background:#0d0d0d;border:1px solid #2e2e2e;
       border-radius:8px;color:#e8e8e8;font-size:1rem;margin-bottom:1rem}}
input:focus{{outline:none;border-color:#00c896}}
button{{width:100%;padding:.65rem;background:#00c896;border:none;border-radius:8px;
        color:#000;font-size:1rem;font-weight:700;cursor:pointer}}
button:hover{{background:#00a87e}}
.err{{color:#ff5555;font-size:.85rem;margin-bottom:.75rem}}
</style>
</head>
<body>
<div class="card">
  <h1>🔒 Passcode Required</h1>
  <form method="POST">
    <label for="pc">Enter the passcode to download this file:</label>
    <input type="password" id="pc" name="passcode" autofocus required />
    {error}
    <button type="submit">Download File ↓</button>
  </form>
</div>
</body>
</html>
"""

# HTML page served when downloading an E2EE-encrypted file.  The page reads the
# AES-GCM key and IV from the URL fragment (#key=…&iv=…&name=…), fetches the raw
# ciphertext from ?raw=1, decrypts it in the browser, and triggers a save.
_E2EE_DECRYPT_PAGE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>secureChat — Secure Download</title>
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#0d0d0d;color:#e8e8e8;font-family:"Segoe UI",system-ui,sans-serif;
      display:flex;align-items:center;justify-content:center;min-height:100vh;padding:1rem}}
.card{{background:#1a1a1a;border:1px solid #2e2e2e;border-radius:12px;
       padding:2rem 1.75rem;width:100%;max-width:420px;text-align:center}}
h1{{font-size:1.2rem;margin-bottom:1rem}}
#status{{font-size:.9rem;color:#aaa;margin-top:.75rem}}
.err{{color:#ff5555}}
.ok{{color:#00c896}}
</style>
</head>
<body>
<div class="card">
  <h1>🔒 E2EE Secure Download</h1>
  <p id="status">Decrypting file…</p>
</div>
<script>
(async()=>{{
  const p=new URLSearchParams(location.hash.slice(1));
  const keyB64=p.get('key'),ivB64=p.get('iv'),fname=p.get('name')||'file';
  const st=document.getElementById('status');
  if(!keyB64||!ivB64){{
    st.className='err';
    st.textContent='⚠️ Missing decryption key. Make sure you are using the full URL including the #fragment.';
    return;
  }}
  try{{
    const keyBytes=Uint8Array.from(atob(keyB64),c=>c.charCodeAt(0));
    const ivBytes=Uint8Array.from(atob(ivB64),c=>c.charCodeAt(0));
    const key=await crypto.subtle.importKey('raw',keyBytes,'AES-GCM',false,['decrypt']);
    const resp=await fetch(location.pathname+'?raw=1');
    if(!resp.ok){{st.className='err';st.textContent='⚠️ File not found or already downloaded.';return;}}
    const cipher=new Uint8Array(await resp.arrayBuffer());
    const plain=await crypto.subtle.decrypt({{name:'AES-GCM',iv:ivBytes}},key,cipher);
    const a=document.createElement('a');
    a.href=URL.createObjectURL(new Blob([plain]));
    a.download=decodeURIComponent(fname);
    document.body.appendChild(a);a.click();
    setTimeout(()=>URL.revokeObjectURL(a.href),15000);
    st.className='ok';st.textContent='✅ File decrypted and downloaded successfully.';
  }}catch(err){{
    st.className='err';st.textContent='⚠️ Decryption failed: '+err.message;
  }}
}})();
</script>
</body>
</html>
"""

# Onion address — admin sets this so generated invite links carry the .onion hostname
ONION_ADDRESS: str | None = os.environ.get("ONION_ADDRESS")

# Room ID: allow alphanumeric, hyphens, underscores only
_ROOM_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")

# In-memory room registry: room_id → {websocket, ...}
rooms: dict[str, set[web.WebSocketResponse]] = {}

# In-memory room-metadata registry — only for rooms created via POST /room/create.
# room_id → {"passcode_hash": str | None, "expires_at": float | None}
_room_meta: dict[str, dict] = {}

# In-memory file-share slot registry
# token → {"tmp_dir": Path, "filename": str, "size": int, "expires_at": float}
_share_slots: dict[str, dict] = {}

# Inbox registry
# token → {
#   "messages":   list[{body, email_from, subject, content_type, received_at}],
#   "expires_at": float,   # Unix timestamp — inbox is destroyed at this time
# }
# Inboxes accept unlimited messages and allow unlimited reads until the TTL expires.
_inbox_slots: dict[str, dict] = {}
# Tracks which inbox tokens have already emitted their first-read log line.
_inbox_logged_tokens: set[str] = set()

# Lockdown state — set True by admin panel; cleared by admin panel deactivate.
# While active, all non-admin HTTP/WS requests are redirected to the lockdown page.
_lockdown_active: bool = False

# SMTP controller instance (started when MAIL_DOMAIN is set)
_smtp_controller: _SmtpController | None = None

# ---------------------------------------------------------------------------
# DDoS protection — IP-based sliding-window rate limiter
# ---------------------------------------------------------------------------
# Configurable via environment variables:
#   DDOS_REQ_LIMIT   – max requests per window (default 200)
#   DDOS_WINDOW_SEC  – sliding window in seconds (default 10)
#   DDOS_BAN_SEC     – how long an IP stays banned (default 300)
#   DDOS_AUTO_LOCKDOWN_THRESHOLD – unique IPs banned before auto-lockdown (default 50)
#   DDOS_ENABLED     – set to "0" to disable (default enabled)

DDOS_ENABLED: bool = os.environ.get("DDOS_ENABLED", "1") not in ("0", "false", "no")
DDOS_REQ_LIMIT: int = int(os.environ.get("DDOS_REQ_LIMIT", "200"))
DDOS_WINDOW_SEC: float = float(os.environ.get("DDOS_WINDOW_SEC", "10"))
DDOS_BAN_SEC: float = float(os.environ.get("DDOS_BAN_SEC", "300"))
DDOS_AUTO_LOCKDOWN_THRESHOLD: int = int(os.environ.get("DDOS_AUTO_LOCKDOWN_THRESHOLD", "50"))

# IP → deque of request timestamps (sliding window)
_ddos_req_timestamps: dict[str, collections.deque] = collections.defaultdict(
    lambda: collections.deque()
)
# IP → ban expiry timestamp
_ddos_banned: dict[str, float] = {}
# Total DDoS events ever detected (for stats)
_ddos_events_total: int = 0
# IP → ban count (to detect repeat offenders)
_ddos_ban_count: dict[str, int] = collections.defaultdict(int)


def _ddos_check_ip(ip: str) -> bool:
    """Return True if the request from *ip* should be blocked.

    Also updates the sliding window and issues a ban when the threshold is
    exceeded.  Thread-safe enough for CPython (GIL protects dict mutations).
    """
    global _ddos_events_total, _lockdown_active  # noqa: PLW0603
    if not DDOS_ENABLED:
        return False

    now = time.time()

    # Check existing ban first
    ban_exp = _ddos_banned.get(ip)
    if ban_exp is not None:
        if now < ban_exp:
            return True   # still banned
        # Ban expired — lift it
        del _ddos_banned[ip]
        _ddos_req_timestamps.pop(ip, None)

    # Slide the window: remove timestamps older than DDOS_WINDOW_SEC
    dq = _ddos_req_timestamps[ip]
    cutoff = now - DDOS_WINDOW_SEC
    while dq and dq[0] < cutoff:
        dq.popleft()

    dq.append(now)

    if len(dq) > DDOS_REQ_LIMIT:
        # Ban this IP
        _ddos_banned[ip] = now + DDOS_BAN_SEC
        _ddos_ban_count[ip] += 1
        _ddos_events_total += 1
        logger.warning(
            "🛡️  DDoS detected — ip=%s  reqs_in_window=%d  ban_count=%d  ban_until=%s",
            ip, len(dq), _ddos_ban_count[ip],
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + DDOS_BAN_SEC)),
        )

        # Auto-lockdown when too many unique IPs are banned simultaneously
        active_bans = sum(1 for exp in _ddos_banned.values() if exp > now)
        if active_bans >= DDOS_AUTO_LOCKDOWN_THRESHOLD and not _lockdown_active:
            _lockdown_active = True
            logger.warning(
                "🔴 AUTO-LOCKDOWN triggered — %d IPs simultaneously banned "
                "(threshold=%d)",
                active_bans, DDOS_AUTO_LOCKDOWN_THRESHOLD,
            )

        return True

    return False


@web.middleware
async def _ddos_middleware(request: web.Request, handler):
    """Drop requests from banned / rate-exceeded IPs with HTTP 429."""
    ip = request.remote or "unknown"
    # Normalise IPv6-mapped IPv4 addresses (e.g. ::ffff:1.2.3.4 → 1.2.3.4)
    if ip.startswith("::ffff:"):
        ip = ip[7:]

    if _ddos_check_ip(ip):
        raise web.HTTPTooManyRequests(
            reason="Too many requests — you have been temporarily banned"
        )
    return await handler(request)


def _ddos_get_stats() -> dict:
    """Return a snapshot of current DDoS protection statistics."""
    now = time.time()
    active_bans = {ip: exp for ip, exp in _ddos_banned.items() if exp > now}
    return {
        "enabled": DDOS_ENABLED,
        "req_limit_per_window": DDOS_REQ_LIMIT,
        "window_sec": DDOS_WINDOW_SEC,
        "ban_duration_sec": DDOS_BAN_SEC,
        "auto_lockdown_threshold": DDOS_AUTO_LOCKDOWN_THRESHOLD,
        "total_ddos_events": _ddos_events_total,
        "currently_banned_count": len(active_bans),
        "currently_banned_ips": [
            {"ip": ip, "expires_at": exp, "ban_count": _ddos_ban_count[ip]}
            for ip, exp in sorted(active_bans.items(), key=lambda kv: -kv[1])
        ],
    }


def _ddos_unban_ip(ip: str) -> bool:
    """Remove *ip* from the ban list.  Returns True if the IP was banned."""
    if ip in _ddos_banned:
        del _ddos_banned[ip]
        _ddos_req_timestamps.pop(ip, None)
        logger.info("🛡️  DDoS ban lifted manually  ip=%s", ip)
        return True
    return False


# ---------------------------------------------------------------------------
# Spam detection — chat messages and inbound SMTP
# ---------------------------------------------------------------------------
# Configurable via environment variables:
#   SPAM_MSG_LIMIT    – max chat messages per window per session (default 20)
#   SPAM_MSG_WINDOW   – window in seconds (default 10)
#   SPAM_MAIL_LIMIT   – max inbound emails per sender per window (default 5)
#   SPAM_MAIL_WINDOW  – window in seconds (default 60)
#   SPAM_ENABLED      – set to "0" to disable (default enabled)

SPAM_ENABLED: bool = os.environ.get("SPAM_ENABLED", "1") not in ("0", "false", "no")
SPAM_MSG_LIMIT: int = int(os.environ.get("SPAM_MSG_LIMIT", "20"))
SPAM_MSG_WINDOW: float = float(os.environ.get("SPAM_MSG_WINDOW", "10"))
SPAM_MAIL_LIMIT: int = int(os.environ.get("SPAM_MAIL_LIMIT", "5"))
SPAM_MAIL_WINDOW: float = float(os.environ.get("SPAM_MAIL_WINDOW", "60"))

# session_id (object id of the WebSocket) → deque of message timestamps
_spam_msg_timestamps: dict[int, collections.deque] = collections.defaultdict(
    lambda: collections.deque()
)
# email sender address → deque of receipt timestamps
_spam_mail_timestamps: dict[str, collections.deque] = collections.defaultdict(
    lambda: collections.deque()
)
# Total spam events detected
_spam_msg_events_total: int = 0
_spam_mail_events_total: int = 0


def _spam_check_chat(ws_id: int) -> bool:
    """Return True (and log) if the WebSocket session identified by *ws_id* is spamming.

    Uses a sliding window over SPAM_MSG_WINDOW seconds.
    """
    global _spam_msg_events_total  # noqa: PLW0603
    if not SPAM_ENABLED:
        return False

    now = time.time()
    dq = _spam_msg_timestamps[ws_id]
    cutoff = now - SPAM_MSG_WINDOW
    while dq and dq[0] < cutoff:
        dq.popleft()
    dq.append(now)

    if len(dq) > SPAM_MSG_LIMIT:
        _spam_msg_events_total += 1
        logger.warning(
            "🚫 Chat spam detected  ws_id=%d  msgs_in_window=%d",
            ws_id, len(dq),
        )
        return True
    return False


def _spam_check_mail(sender: str) -> bool:
    """Return True (and log) if *sender* is sending too many inbound emails.

    Uses a sliding window over SPAM_MAIL_WINDOW seconds.
    """
    global _spam_mail_events_total  # noqa: PLW0603
    if not SPAM_ENABLED:
        return False

    # Normalise the sender key — lower-cased, strip display-name
    key = sender.lower()
    # Strip display-name like "Alice <alice@example.com>"
    m = re.search(r"<([^>]+)>", key)
    if m:
        key = m.group(1)

    now = time.time()
    dq = _spam_mail_timestamps[key]
    cutoff = now - SPAM_MAIL_WINDOW
    while dq and dq[0] < cutoff:
        dq.popleft()
    dq.append(now)

    if len(dq) > SPAM_MAIL_LIMIT:
        _spam_mail_events_total += 1
        logger.warning(
            "🚫 Mail spam detected  sender=%s  mails_in_window=%d",
            key, len(dq),
        )
        return True
    return False


def _spam_get_stats() -> dict:
    """Return a snapshot of current spam detection statistics."""
    return {
        "enabled": SPAM_ENABLED,
        "chat_msg_limit_per_window": SPAM_MSG_LIMIT,
        "chat_msg_window_sec": SPAM_MSG_WINDOW,
        "mail_limit_per_window": SPAM_MAIL_LIMIT,
        "mail_window_sec": SPAM_MAIL_WINDOW,
        "total_chat_spam_events": _spam_msg_events_total,
        "total_mail_spam_events": _spam_mail_events_total,
        "active_chat_sessions_tracked": len(_spam_msg_timestamps),
        "active_mail_senders_tracked": len(_spam_mail_timestamps),
    }


# ---------------------------------------------------------------------------
# Slow mode — admin-controlled global request delay
# ---------------------------------------------------------------------------
# Configurable via environment variables:
#   SLOW_MODE         – start in slow mode ("1" / "true" / "yes"); default off
#   SLOW_MODE_DELAY   – delay in seconds applied to each request (default 2.0)

SLOW_MODE_DELAY: float = float(os.environ.get("SLOW_MODE_DELAY", "2.0"))

# Valid service-target tokens for per-service slow mode.
# "all" means every non-admin, non-static request is delayed.
SLOW_MODE_ALL_TARGETS: frozenset[str] = frozenset(
    {"all", "chat", "chat_creation", "file_sharing", "mail"}
)

# Current state — can be toggled at runtime via the admin API
_slow_mode_active: bool = os.environ.get("SLOW_MODE", "").strip().lower() in ("1", "true", "yes")

# Which service targets are currently slowed.  Empty set == same as {"all"}.
_slow_mode_targets: set[str] = set()


def _path_matches_slow_targets(path: str, targets: set[str]) -> bool:
    """Return True if the request path falls within one of the active slow targets."""
    effective = targets if targets else {"all"}
    if "all" in effective:
        return True
    if "chat" in effective and path == "/ws":
        return True
    if "chat_creation" in effective and (
        path == "/room/create" or path.startswith("/room/")
    ):
        return True
    if "file_sharing" in effective and path.startswith("/share"):
        return True
    if "mail" in effective and path.startswith("/inbox"):
        return True
    return False


@web.middleware
async def _slow_mode_middleware(request: web.Request, handler):
    """Introduce a configurable delay on matching requests when slow mode is active."""
    if not _slow_mode_active:
        return await handler(request)

    # Let admin routes and static assets pass through undelayed so the admin
    # panel remains fully usable even when slow mode is active.
    path = request.path.rstrip("/")
    admin_prefix = f"/{_ADMIN_PATH}"
    if path.startswith(admin_prefix) or path == admin_prefix:
        return await handler(request)
    if path.startswith("/static"):
        return await handler(request)

    if _path_matches_slow_targets(path, _slow_mode_targets):
        await asyncio.sleep(SLOW_MODE_DELAY)
    return await handler(request)


def _slow_mode_status() -> dict:
    """Return a JSON-serialisable snapshot of slow mode state."""
    return {
        "active": _slow_mode_active,
        "delay_sec": SLOW_MODE_DELAY,
        "targets": sorted(_slow_mode_targets) if _slow_mode_targets else ["all"],
    }

# ---------------------------------------------------------------------------
# Global statistics counters
# ---------------------------------------------------------------------------

_stats: dict[str, int | float] = {
    "rooms_created_total": 0,
    "files_uploaded_count": 0,
    "files_uploaded_bytes": 0,
    "files_downloaded_count": 0,
    "files_downloaded_bytes": 0,
    "chat_files_shared": 0,
}

# ---------------------------------------------------------------------------
# SSE log sink — broadcasts log records to admin live-log clients
# ---------------------------------------------------------------------------

# Each connected SSE client gets its own Queue; the handler fans out to all of them.
_log_sse_clients: list[asyncio.Queue] = []
_admin_event_loop: asyncio.AbstractEventLoop | None = None  # set in on_startup callback within build_admin_app
# Ring buffer of the last 200 formatted log lines — replayed to new SSE clients
# so the Live Logs panel shows recent history even before they connected.
_log_recent: collections.deque = collections.deque(maxlen=200)

class _SseLogHandler(logging.Handler):
    """Forward log records to every connected SSE client (non-blocking, fan-out)."""

    def emit(self, record: logging.LogRecord) -> None:
        msg = self.format(record)
        # Always store in the ring buffer (no event-loop dependency needed).
        _log_recent.append(msg)
        if not _log_sse_clients or _admin_event_loop is None:
            return
        try:
            if _admin_event_loop.is_running():
                for q in list(_log_sse_clients):
                    _admin_event_loop.call_soon_threadsafe(q.put_nowait, msg)
        except Exception:
            pass

# ---------------------------------------------------------------------------
# Database helpers — synchronous, executed in a thread-pool via asyncio.to_thread
# ---------------------------------------------------------------------------


def _init_db_sync(path: Path) -> None:
    """Create the messages table and index if they do not exist."""
    con = sqlite3.connect(path)
    try:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                room       TEXT    NOT NULL,
                ts         REAL    NOT NULL,
                sender     TEXT    NOT NULL,
                iv         TEXT    NOT NULL,
                ciphertext TEXT    NOT NULL
            )
            """
        )
        con.execute(
            "CREATE INDEX IF NOT EXISTS idx_messages_room_id ON messages(room, id)"
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS metrics_history (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                ts           REAL    NOT NULL,
                cpu_pct      REAL,
                ram_pct      REAL,
                disk_pct     REAL,
                active_rooms INTEGER
            )
            """
        )
        con.execute(
            "CREATE INDEX IF NOT EXISTS idx_metrics_ts ON metrics_history(ts)"
        )
        con.commit()
    finally:
        con.close()


def _save_message_sync(
    path: Path,
    room_id: str,
    sender: str,
    iv: str,
    ciphertext: str,
    limit: int,
) -> None:
    """Insert a message and prune old rows so the room stays within *limit*."""
    con = sqlite3.connect(path)
    try:
        con.execute(
            "INSERT INTO messages (room, ts, sender, iv, ciphertext) VALUES (?, ?, ?, ?, ?)",
            (room_id, time.time(), sender, iv, ciphertext),
        )
        # Keep only the latest `limit` messages per room
        con.execute(
            """
            DELETE FROM messages
             WHERE room = ?
               AND id NOT IN (
                     SELECT id FROM messages
                      WHERE room = ?
                      ORDER BY id DESC
                      LIMIT ?
                   )
            """,
            (room_id, room_id, limit),
        )
        con.commit()
    finally:
        con.close()


def _get_history_sync(path: Path, room_id: str, limit: int) -> list[dict]:
    """Return up to *limit* stored messages for *room_id* in chronological order."""
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute(
            """
            SELECT ts, sender, iv, ciphertext
              FROM messages
             WHERE room = ?
             ORDER BY id DESC
             LIMIT ?
            """,
            (room_id, limit),
        ).fetchall()
    finally:
        con.close()
    # Reverse so oldest message comes first
    return [
        {
            "ts": r["ts"],
            "sender": r["sender"],
            "iv": r["iv"],
            "ciphertext": r["ciphertext"],
        }
        for r in reversed(rows)
    ]


def _delete_room_history_sync(path: Path, room_id: str) -> None:
    """Delete all stored messages for *room_id* (called on self-destruct)."""
    con = sqlite3.connect(path)
    try:
        con.execute("DELETE FROM messages WHERE room = ?", (room_id,))
        con.commit()
    finally:
        con.close()


def _wipe_all_data_sync(path: Path) -> None:
    """Delete every message in the DB.  Called during lockdown activation."""
    con = sqlite3.connect(path)
    try:
        con.execute("DELETE FROM messages")
        con.commit()
    finally:
        con.close()


def _hash_passcode(passcode: str) -> str:
    """Return the hex SHA-256 digest of a room passcode."""
    return hashlib.sha256(passcode.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Async wrappers around the synchronous DB helpers
# ---------------------------------------------------------------------------


async def init_db(path: Path) -> None:
    await asyncio.to_thread(_init_db_sync, path)


async def save_message(
    path: Path,
    room_id: str,
    sender: str,
    iv: str,
    ciphertext: str,
    limit: int = HISTORY_LIMIT,
) -> None:
    await asyncio.to_thread(_save_message_sync, path, room_id, sender, iv, ciphertext, limit)


async def get_history(
    path: Path,
    room_id: str,
    limit: int = HISTORY_LIMIT,
) -> list[dict]:
    return await asyncio.to_thread(_get_history_sync, path, room_id, limit)


# ---------------------------------------------------------------------------
# WebSocket handler
# ---------------------------------------------------------------------------


async def ws_handler(request: web.Request) -> web.WebSocketResponse:
    """Handle one WebSocket connection for its entire lifetime."""
    ws = web.WebSocketResponse(heartbeat=30)
    await ws.prepare(request)

    db_path: Path = request.app["db_path"]
    room_id: str | None = None

    try:
        async for msg in ws:
            if msg.type != WSMsgType.TEXT:
                if msg.type in (WSMsgType.ERROR, WSMsgType.CLOSE):
                    break
                continue

            try:
                data: dict = json.loads(msg.data)
            except (json.JSONDecodeError, ValueError):
                continue

            msg_type = data.get("type", "")

            # ── join ──────────────────────────────────────────────────────
            if msg_type == "join" and room_id is None:
                candidate = str(data.get("room", ""))
                if not _ROOM_RE.match(candidate):
                    await ws.send_str(
                        json.dumps({"type": "error", "reason": "invalid_room_id"})
                    )
                    continue

                # Check room metadata if this room was created via /room/create
                meta = _room_meta.get(candidate)
                if meta:
                    # Reject if the room has already expired
                    if meta.get("expires_at") and time.time() > meta["expires_at"]:
                        await ws.send_str(
                            json.dumps({"type": "error", "reason": "room_expired"})
                        )
                        break
                    # Enforce passcode
                    if meta.get("passcode_hash"):
                        provided = str(data.get("passcode", "")).strip()
                        if not provided or _hash_passcode(provided) != meta["passcode_hash"]:
                            await ws.send_str(
                                json.dumps({"type": "error", "reason": "wrong_passcode"})
                            )
                            break

                room_id = candidate
                rooms.setdefault(room_id, set()).add(ws)
                logger.info(
                    "peer joined  room=%s  peers=%d",
                    room_id,
                    len(rooms[room_id]),
                )

                # Fire webhook for join event
                webhook_url = (_room_meta.get(room_id) or {}).get("webhook_url") or ""
                if webhook_url:
                    asyncio.ensure_future(_fire_webhook(
                        webhook_url, "peer_joined",
                        {"room": room_id, "peers": len(rooms[room_id])},
                    ))

                # Send stored history to the newly joined peer only.
                # History is only kept for passcode-protected rooms.
                if _room_meta.get(room_id, {}).get("passcode_hash"):
                    try:
                        history = await get_history(db_path, room_id)
                        if history:
                            await ws.send_str(
                                json.dumps({"type": "history", "messages": history})
                            )
                    except Exception as exc:  # noqa: BLE001
                        logger.warning("failed to load history  room=%s  error=%s", room_id, exc)

                # Inform the peer about the self-destruct deadline (if any)
                if meta and meta.get("expires_at"):
                    remaining = max(0.0, meta["expires_at"] - time.time())
                    await ws.send_str(json.dumps({
                        "type": "destruct_info",
                        "expires_at": meta["expires_at"],
                        "remaining": remaining,
                    }))

                await _broadcast_system(room_id)

            # ── message ───────────────────────────────────────────────────
            elif msg_type == "message" and room_id is not None:
                # Spam detection — drop messages from sessions that exceed the
                # configured rate limit.  The WebSocket object id is used as the
                # session key; it is unique for the lifetime of the connection.
                if _spam_check_chat(id(ws)):
                    await ws.send_str(json.dumps({
                        "type": "error",
                        "reason": "rate_limited",
                        "detail": "Too many messages — slow down",
                    }))
                    continue

                iv = str(data.get("iv", ""))
                ciphertext = str(data.get("ciphertext", ""))
                sender = str(data.get("sender", ""))[:MAX_DISPLAY_NAME_LEN]

                # Basic sanity checks — reject obviously malformed payloads
                if len(iv) > MAX_IV_LEN or len(ciphertext) > MAX_CIPHERTEXT_LEN:
                    continue

                # Persist before relaying — only for passcode-protected rooms.
                # Rooms without a passcode do not store message history.
                if _room_meta.get(room_id, {}).get("passcode_hash"):
                    try:
                        await save_message(db_path, room_id, sender, iv, ciphertext)
                    except Exception as exc:  # noqa: BLE001
                        logger.warning(
                            "failed to save message  room=%s  error=%s", room_id, exc
                        )

                relay = json.dumps(
                    {
                        "type": "message",
                        "iv": iv,
                        "ciphertext": ciphertext,
                        "sender": sender,
                    }
                )
                # Relay to all other peers; sender renders its own message locally.
                await _broadcast_to_room(room_id, relay, exclude=ws)

            # ── file (in-chat attachment) ──────────────────────────────────
            elif msg_type == "file" and room_id is not None:
                # Spam detection for file uploads (share the same chat limiter)
                if _spam_check_chat(id(ws)):
                    await ws.send_str(json.dumps({
                        "type": "error",
                        "reason": "rate_limited",
                        "detail": "Too many file uploads — slow down",
                    }))
                    continue

                iv         = str(data.get("iv", ""))
                ciphertext = str(data.get("ciphertext", ""))
                sender     = str(data.get("sender", ""))[:MAX_DISPLAY_NAME_LEN]
                filename   = str(data.get("filename", "file"))[:MAX_CHAT_FILENAME_LEN]
                mime       = str(data.get("mime", "application/octet-stream"))[:MAX_MIME_LEN]
                one_time   = bool(data.get("one_time", False))
                nsfw       = bool(data.get("nsfw", False))

                # Reject obviously malformed or oversized payloads.
                # File attachments are never persisted — always ephemeral.
                if len(iv) > MAX_IV_LEN or len(ciphertext) > MAX_FILE_CIPHERTEXT_LEN:
                    continue

                relay = json.dumps({
                    "type": "file",
                    "iv": iv,
                    "ciphertext": ciphertext,
                    "filename": filename,
                    "mime": mime,
                    "sender": sender,
                    "one_time": one_time,
                    "nsfw": nsfw,
                })
                await _broadcast_to_room(room_id, relay, exclude=ws)
                _stats["chat_files_shared"] += 1
                logger.info(
                    "chat file share  room=%s  file=%s  sender=%s  one_time=%s  nsfw=%s",
                    room_id, filename, sender, one_time, nsfw,
                )

    finally:
        # Clean up regardless of how the connection closed
        if room_id and room_id in rooms:
            rooms[room_id].discard(ws)
            if rooms[room_id]:
                await _broadcast_system(room_id)
            else:
                del rooms[room_id]
                # A room that was created with a passcode or self-destruct timer
                # retains its metadata so it can be rejoined later — do NOT treat
                # it as permanently deleted.
                meta = _room_meta.get(room_id)
                if meta:
                    logger.info("room inactive (retained)  room=%s", room_id)
                else:
                    logger.info("room deleted  room=%s", room_id)

    return ws


# ---------------------------------------------------------------------------
# Broadcast helpers
# ---------------------------------------------------------------------------


async def _broadcast_system(room_id: str) -> None:
    count = len(rooms.get(room_id, set()))
    payload = json.dumps({"type": "system", "users": count})
    await _broadcast_to_room(room_id, payload)


async def _broadcast_to_room(
    room_id: str,
    payload: str,
    *,
    exclude: web.WebSocketResponse | None = None,
    _from_peer: bool = False,
) -> None:
    peers = list(rooms.get(room_id, set()))
    for peer in peers:
        if peer is exclude or peer.closed:
            continue
        try:
            await peer.send_str(payload)
        except Exception:  # noqa: BLE001
            pass
    # Forward to mesh peers (but not when the message already came from a peer,
    # to avoid infinite forwarding loops)
    if not _from_peer and _mesh_peers:
        asyncio.ensure_future(_forward_to_peers(room_id, payload))


# ---------------------------------------------------------------------------
# HTTP handlers
# ---------------------------------------------------------------------------


async def index_handler(request: web.Request) -> web.FileResponse:
    return web.FileResponse(STATIC_DIR / "index.html")


async def _blocked_static_handler(request: web.Request) -> web.Response:  # noqa: ARG001
    """Return 404 for static files that must never be served directly.

    admin.html contains the admin-panel template and must only be served
    through _admin_index_handler (which injects the secret path and adds
    security headers).  Serving the raw file via /static/ would disclose
    the admin panel's existence and all its API endpoints to any visitor.
    """
    raise web.HTTPNotFound()


# ---------------------------------------------------------------------------
# File-share helpers and handlers
# ---------------------------------------------------------------------------


def _sanitize_filename(name: str) -> str:
    """Return a safe filename with path components and dangerous chars removed."""
    # Strip directory separators (handles both UNIX and Windows paths)
    name = os.path.basename(name.replace("\\", "/"))
    # Allow alphanumeric, dots, hyphens, underscores, spaces; replace the rest
    name = re.sub(r"[^\w.\- ]", "_", name)
    # Strip leading/trailing dots and spaces (avoids hidden-files and whitespace names)
    name = name.strip(". ")
    return (name or "file")[:MAX_FILENAME_LEN]


def _rmtree(path: Path) -> None:
    """Remove a directory tree, ignoring errors."""
    shutil.rmtree(path, ignore_errors=True)


async def share_upload_handler(request: web.Request) -> web.Response:
    """POST /share/upload?ttl=<hours> — receive a file, return a one-time download URL."""
    # ── TTL ──────────────────────────────────────────────────────────────
    try:
        ttl_hours = int(request.query.get("ttl", "1"))
    except ValueError:
        ttl_hours = 1
    ttl_hours = max(1, min(24, ttl_hours))

    # ── Early size rejection ──────────────────────────────────────────────
    cl = request.content_length
    if cl is not None and cl > MAX_UPLOAD_BYTES:
        raise web.HTTPRequestEntityTooLarge()

    if not request.content_type.startswith("multipart/"):
        raise web.HTTPBadRequest(reason="Expected multipart/form-data")

    reader = await request.multipart()
    tmp_dir = Path(tempfile.mkdtemp(prefix="sc_share_"))
    try:
        # Find the "file" part
        file_part = await reader.next()
        if file_part is None or file_part.name != "file":
            raise web.HTTPBadRequest(reason="Expected a 'file' field")

        filename = _sanitize_filename(file_part.filename or "file")
        dest = tmp_dir / filename

        # Stream directly to disk (enforcing limit) to support large files
        total = 0
        with dest.open("wb") as f_out:
            while True:
                chunk = await file_part.read_chunk(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_UPLOAD_BYTES:
                    raise web.HTTPRequestEntityTooLarge()
                f_out.write(chunk)

        # Optionally read the "passcode" field that follows the file
        passcode = ""
        try:
            next_part = await reader.next()
            if next_part is not None and next_part.name == "passcode":
                raw = await next_part.read(decode=True)
                passcode = raw.decode("utf-8", errors="replace")[:MAX_PASSCODE_LEN].strip()
        except Exception:  # noqa: BLE001
            pass

        token = secrets.token_urlsafe(_SHARE_TOKEN_BYTES)
        expires_at = time.time() + ttl_hours * 3600
        # Mark the slot as E2EE-encrypted if the uploader set the "e=1" query param.
        encrypted = request.query.get("e", "0") == "1"
        _share_slots[token] = {
            "tmp_dir": tmp_dir,
            "filename": filename,
            "size": total,
            "expires_at": expires_at,
            "passcode_hash": _hash_passcode(passcode) if passcode else None,
            "encrypted": encrypted,
        }
        _stats["files_uploaded_count"] += 1
        _stats["files_uploaded_bytes"] += total
        logger.info("share upload  file=%s  size=%d  ttl=%dh  passcode=%s",
                    filename, total, ttl_hours, bool(passcode))
        return web.json_response(
            {
                "download_url": f"/share/download/{token}",
                "filename": filename,
                "size": total,
                "expires_at": expires_at,
            }
        )
    except web.HTTPException:
        await asyncio.to_thread(_rmtree, tmp_dir)
        raise
    except Exception as exc:  # noqa: BLE001
        await asyncio.to_thread(_rmtree, tmp_dir)
        logger.error("share upload error: %s", exc)
        raise web.HTTPInternalServerError()


async def share_download_handler(request: web.Request) -> web.StreamResponse:
    """GET /share/download/{token} — one-time download; temp files destroyed afterwards.

    For E2EE-encrypted slots (slot["encrypted"] is True):
      * Plain GET returns the JS decrypt page (slot not consumed).
      * GET ?raw=1 returns the raw ciphertext bytes (slot consumed once).
    For unencrypted slots:
      * If the slot requires a passcode, an HTML gate page is returned.
      * Otherwise, the file is streamed immediately (one-time).
    """
    token = request.match_info["token"]
    slot = _share_slots.get(token)

    if slot is None:
        raise web.HTTPNotFound(reason="Link not found or already used")

    if time.time() > slot["expires_at"]:
        _share_slots.pop(token, None)
        await asyncio.to_thread(_rmtree, slot["tmp_dir"])
        raise web.HTTPGone(reason="Download link has expired")

    # ── E2EE encrypted slot ──────────────────────────────────────────────
    if slot.get("encrypted"):
        # ?raw=1: serve the raw ciphertext bytes (one-time, consumes the slot)
        if request.query.get("raw") == "1":
            return await _stream_share_file(token, slot, request)
        # Plain GET: serve the client-side decrypt page (slot not consumed)
        return web.Response(
            body=_E2EE_DECRYPT_PAGE,
            content_type="text/html",
        )

    # ── Plain (unencrypted) slot ─────────────────────────────────────────
    # If the slot is protected by a passcode, return the gate page without
    # consuming the slot (so the user can try the passcode via POST).
    if slot.get("passcode_hash"):
        return web.Response(
            body=_PASSCODE_GATE_PAGE.format(error=""),
            content_type="text/html",
        )

    # No passcode — stream the file immediately (one-time).
    return await _stream_share_file(token, slot, request)


async def share_download_post_handler(request: web.Request) -> web.StreamResponse:
    """POST /share/download/{token} — verify passcode and deliver the file once."""
    token = request.match_info["token"]
    slot = _share_slots.get(token)

    if slot is None:
        raise web.HTTPNotFound(reason="Link not found or already used")

    if time.time() > slot["expires_at"]:
        _share_slots.pop(token, None)
        await asyncio.to_thread(_rmtree, slot["tmp_dir"])
        raise web.HTTPGone(reason="Download link has expired")

    # This endpoint only makes sense for passcode-protected slots.
    if not slot.get("passcode_hash"):
        raise web.HTTPMethodNotAllowed(method="POST", allowed_methods=["GET"])

    # Read the submitted passcode from a standard URL-encoded form.
    form = await request.post()
    provided = str(form.get("passcode", "")).strip()
    if not provided or _hash_passcode(provided) != slot["passcode_hash"]:
        error_html = '<p class="err">❌ Wrong passcode. Please try again.</p>'
        return web.Response(
            body=_PASSCODE_GATE_PAGE.format(error=error_html),
            content_type="text/html",
            status=403,
        )

    # Correct passcode — stream the file (one-time).
    return await _stream_share_file(token, slot, request)


async def _stream_share_file(
    token: str,
    slot: dict,
    request: web.Request,
) -> web.StreamResponse:
    """Pop *token* from _share_slots, stream the file in chunks, then delete the temp dir."""
    # Remove slot before streaming — guarantees one-time use even on concurrent requests.
    _share_slots.pop(token, None)
    tmp_dir: Path = slot["tmp_dir"]
    filename: str = slot["filename"]
    size: int = slot["size"]
    filepath = tmp_dir / filename

    if not filepath.is_file():
        await asyncio.to_thread(_rmtree, tmp_dir)
        raise web.HTTPNotFound(reason="File not found")

    try:
        response = web.StreamResponse(
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Type": "application/octet-stream",
                "Content-Length": str(size),
                "X-Content-Type-Options": "nosniff",
            }
        )
        await response.prepare(request)
        # Stream file in 256 KiB chunks to support large files without loading
        # the entire file into RAM.
        def _iter_file(path: Path, chunk_size: int = 262144):
            with path.open("rb") as fh:
                while True:
                    data = fh.read(chunk_size)
                    if not data:
                        break
                    yield data

        for chunk in await asyncio.to_thread(list, _iter_file(filepath)):
            await response.write(chunk)
        await response.write_eof()
        _stats["files_downloaded_count"] += 1
        _stats["files_downloaded_bytes"] += size
        logger.info("share download complete  file=%s  size=%d", filename, size)
        return response
    finally:
        await asyncio.to_thread(_rmtree, tmp_dir)


async def _cleanup_expired_share_slots() -> None:
    """Background task: sweep expired share slots every 5 minutes."""
    while True:
        await asyncio.sleep(300)
        now = time.time()
        expired = [t for t, s in list(_share_slots.items()) if now > s["expires_at"]]
        for t in expired:
            slot = _share_slots.pop(t, None)
            if slot:
                await asyncio.to_thread(_rmtree, slot["tmp_dir"])
        if expired:
            logger.info("cleaned up %d expired share slot(s)", len(expired))


# ---------------------------------------------------------------------------
# One-time inbox handlers
# ---------------------------------------------------------------------------
# Workflow:
#   1. Creator:  POST /inbox/create  → {"address": "token@domain",
#                                        "drop_url": "…/inbox/<token>/drop",
#                                        "read_url": "…/inbox/<token>/read",
#                                        "expires_at": <unix-ts>}
#   2. Sender (HTTP):  POST /inbox/<token>/drop  {body: {"message": "…"}}
#                      → 200 {"ok": true}  (only once — subsequent posts return 409)
#      Sender (SMTP):  Send real email to <token>@MAIL_DOMAIN (if MAIL_DOMAIN is set)
#      Sender (web):   POST /inbox/<token>/drop  (HTTP form, no email account needed)
#      Sender (real):  Any email server can deliver to <address>@mail.tm (auto-provisioned)
#   3. Recipient:      GET /inbox/<token>/read  → 200 {"message": "…", …} (one-time)
#                      Returns 204 if nothing deposited yet, 410 if expired/used.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Outbound HTTP proxy helper
#
# Non-Tor clearnet services (mail.tm, mesh peers on clearnet) are routed
# through a SOCKS5 proxy chain so the server's real IP is never exposed:
#
#   1st choice: Tor SOCKS5 (127.0.0.1:9050) — already running for hidden-service.
#               This gives 3-hop anonymity with no data sent to any agency.
#   Fallback  : a curated list of well-known free public SOCKS5 proxies.
#   Last resort: direct connection (no proxy).
#
# Mesh peers that use .onion addresses are automatically handled by Tor.
# ---------------------------------------------------------------------------

# Free public SOCKS5 proxies — tried in order after Tor.
# These are long-running, widely-tested free proxies (no payment, no signup).
# Six proxies are listed so the clearnet service always has a full 6-hop chain
# to fall back to when Tor is unavailable.
_FREE_SOCKS5_PROXIES: list[str] = [
    # Free public SOCKS5 proxies removed — they are unreliable and frequently offline.
    # Outbound connections now use Tor (socks5://127.0.0.1:9050) when available,
    # falling back to direct connections.  Set SOCKS5_PROXY env var to supply your
    # own proxy (e.g. "socks5://127.0.0.1:9050").
]

# In-process cache: last verified proxy URL (or empty string = direct)
_proxy_cache: str = ""
_proxy_cache_ts: float = 0.0
_PROXY_CACHE_TTL: float = 300.0  # re-probe every 5 minutes

# Per-proxy health state: True = online, False = offline.
# Populated lazily; absent key means "unknown" (treated as online).
_proxy_health: dict[str, bool] = {}
_PROXY_WATCHDOG_INTERVAL: float = 60.0  # re-check every 60 seconds


async def _proxy_watchdog_task() -> None:
    """Background task: health-check every proxy every 60 s.

    When a proxy changes state (online → offline or vice-versa) the change is
    printed to the console immediately so the operator can see which relays are
    alive.  When a proxy goes offline the in-process proxy cache is invalidated
    so the next outbound request picks the next available relay automatically.
    """
    global _proxy_cache, _proxy_cache_ts  # noqa: PLW0603

    while True:
        await asyncio.sleep(_PROXY_WATCHDOG_INTERVAL)
        changed = False
        for proxy_url in _FREE_SOCKS5_PROXIES:
            was_online = _proxy_health.get(proxy_url, True)
            now_online = await _probe_proxy(proxy_url, timeout=8.0)
            if was_online != now_online:
                _proxy_health[proxy_url] = now_online
                changed = True
                status = "ONLINE  ✓" if now_online else "OFFLINE ✗"
                print("", flush=True)
                print("=" * 72, flush=True)
                print(f"  PROXY STATUS CHANGE", flush=True)
                print("=" * 72, flush=True)
                print(f"  Proxy  : {proxy_url}", flush=True)
                print(f"  Status : {status}", flush=True)
                print("=" * 72, flush=True)
                print("", flush=True)
            else:
                _proxy_health[proxy_url] = now_online

        # If any proxy went offline, invalidate the cache so the next request
        # re-selects the best currently-online proxy.
        if changed:
            _proxy_cache = ""
            _proxy_cache_ts = 0.0


async def _make_proxied_session(timeout: float = 15.0):
    """Return an aiohttp ClientSession routed through the best available proxy.

    Priority:
      1. Tor SOCKS5 at 127.0.0.1:9050  (3-hop onion routing, no agency logging)
      2. Free public SOCKS5 proxies    (tried in order, skipping offline ones)
      3. Direct connection             (fallback — real IP visible)

    The result is cached for _PROXY_CACHE_TTL seconds so every outbound call
    does not re-probe the proxy.  The cache is per-process in-memory only.
    A proxy known to be offline (via _proxy_health) is skipped instantly
    without issuing a network probe.
    """
    global _proxy_cache, _proxy_cache_ts  # noqa: PLW0603
    import time as _time  # noqa: PLC0415

    now = _time.time()
    if now - _proxy_cache_ts < _PROXY_CACHE_TTL:
        # Re-validate cache entry: if that proxy is now offline, drop the cache
        if _proxy_health.get(_proxy_cache, True):
            return _build_session(_proxy_cache, timeout)
        # Cached proxy went offline — fall through to re-probe
        _proxy_cache_ts = 0.0

    # Probe Tor first, then only the online free proxies, then direct.
    # Proxies absent from _proxy_health are treated as potentially online.
    online_free = [p for p in _FREE_SOCKS5_PROXIES if _proxy_health.get(p, True)]
    candidates = ["socks5://127.0.0.1:9050"] + online_free + [""]
    chosen = ""
    for proxy_url in candidates:
        if await _probe_proxy(proxy_url, timeout=5.0):
            chosen = proxy_url
            break

    _proxy_cache = chosen
    _proxy_cache_ts = now
    if chosen:
        logger.debug("outbound proxy selected: %s", chosen[:40])
    else:
        logger.debug("outbound proxy: direct (no proxy available)")
    return _build_session(chosen, timeout)


def _build_session(proxy_url: str, timeout: float):
    """Build an aiohttp ClientSession with the given SOCKS5 proxy (or direct)."""
    import aiohttp as _aiohttp  # noqa: PLC0415
    t = _aiohttp.ClientTimeout(total=timeout)
    if not proxy_url:
        return _aiohttp.ClientSession(timeout=t)
    try:
        from aiohttp_socks import ProxyConnector  # noqa: PLC0415
        connector = ProxyConnector.from_url(proxy_url)
        return _aiohttp.ClientSession(connector=connector, timeout=t)
    except Exception:  # noqa: BLE001
        # aiohttp-socks not installed or proxy URL invalid — fall back to direct
        return _aiohttp.ClientSession(timeout=t)


async def _probe_proxy(proxy_url: str, timeout: float = 5.0) -> bool:
    """Return True if we can reach api.mail.tm through *proxy_url* (or direct)."""
    import aiohttp as _aiohttp  # noqa: PLC0415
    try:
        sess = _build_session(proxy_url, timeout)
        async with sess:
            async with sess.get(
                f"{MAILTM_API}/domains",
                timeout=_aiohttp.ClientTimeout(total=timeout),
                allow_redirects=False,
            ) as r:
                return r.status < 500
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# mail.tm helpers — free real-email provisioning
# ---------------------------------------------------------------------------

async def _mailtm_get_domain() -> str | None:
    """Return the first active mail.tm domain, or None on failure."""
    try:
        async with await _make_proxied_session() as sess:
            async with sess.get(f"{MAILTM_API}/domains") as r:
                if r.status != 200:
                    return None
                data = await r.json()
                # API returns {"hydra:member": [...], ...}
                members = data.get("hydra:member") or data.get("member") or []
                for item in members:
                    if item.get("isActive"):
                        return item["domain"]
    except Exception:  # noqa: BLE001
        pass
    return None


async def _mailtm_create_account(address: str, password: str) -> bool:
    """Create a mail.tm account.  Returns True on success."""
    try:
        async with await _make_proxied_session() as sess:
            async with sess.post(
                f"{MAILTM_API}/accounts",
                json={"address": address, "password": password},
            ) as r:
                return r.status in (200, 201)
    except Exception:  # noqa: BLE001
        return False


async def _mailtm_get_token(address: str, password: str) -> str | None:
    """Obtain a JWT bearer token for a mail.tm account."""
    try:
        async with await _make_proxied_session() as sess:
            async with sess.post(
                f"{MAILTM_API}/token",
                json={"address": address, "password": password},
            ) as r:
                if r.status == 200:
                    data = await r.json()
                    return data.get("token")
    except Exception:  # noqa: BLE001
        pass
    return None


async def _mailtm_fetch_messages(bearer_token: str, seen_ids: set) -> list[dict]:
    """Fetch unread messages from mail.tm; return a list of new message dicts."""
    results: list[dict] = []
    try:
        async with await _make_proxied_session() as sess:
            async with sess.get(
                f"{MAILTM_API}/messages",
                headers={"Authorization": f"Bearer {bearer_token}"},
            ) as r:
                if r.status != 200:
                    return results
                data = await r.json()
                members = data.get("hydra:member") or data.get("member") or []
                for m in members:
                    mid = m.get("id", "")
                    if mid in seen_ids:
                        continue
                    seen_ids.add(mid)
                    # Fetch full message for body
                    async with sess.get(
                        f"{MAILTM_API}/messages/{mid}",
                        headers={"Authorization": f"Bearer {bearer_token}"},
                    ) as mr:
                        if mr.status != 200:
                            continue
                        full = await mr.json()
                    body_html = full.get("html", [""])[0] if full.get("html") else ""
                    body_text = full.get("text") or ""
                    body = body_html or body_text or "(empty)"
                    results.append({
                        "body":         body,
                        "email_from":   (full.get("from") or {}).get("address") or None,
                        "subject":      full.get("subject") or None,
                        "content_type": "text/html" if body_html else "text/plain",
                        "received_at":  time.time(),
                    })
    except Exception:  # noqa: BLE001
        pass
    return results


async def _mailtm_provision(inbox_token_bytes: int) -> dict | None:
    """Create a fresh mail.tm mailbox.  Returns slot extras or None on failure."""
    domain = await _mailtm_get_domain()
    if not domain:
        return None
    local = secrets.token_urlsafe(inbox_token_bytes)[:16].lower()
    address = f"{local}@{domain}"
    password = secrets.token_urlsafe(24)
    ok = await _mailtm_create_account(address, password)
    if not ok:
        return None
    bearer = await _mailtm_get_token(address, password)
    if not bearer:
        return None
    return {
        "mailtm_address": address,
        "mailtm_bearer":  bearer,
        "mailtm_seen":    set(),
    }


async def _mailtm_poll_all_inboxes() -> None:
    """Background task: poll mail.tm for new messages every 30 seconds."""
    while True:
        await asyncio.sleep(30)
        for slot in list(_inbox_slots.values()):
            bearer = slot.get("mailtm_bearer")
            if not bearer:
                continue
            if time.time() > slot.get("expires_at", 0):
                continue
            seen: set = slot.setdefault("mailtm_seen", set())
            new_msgs = await _mailtm_fetch_messages(bearer, seen)
            for msg in new_msgs:
                slot["messages"].append(msg)
                logger.info(
                    "mail.tm message received  from=%.40s  subject=%r",
                    msg.get("email_from") or "",
                    (msg.get("subject") or "")[:60],
                )


class InboxSmtpHandler:
    """aiosmtpd message handler — receives inbound SMTP and stores messages in inbox slots.

    This handler runs in the aiosmtpd Controller's own thread/event-loop.
    Appending to ``slot["messages"]`` is GIL-protected in CPython and safe for
    concurrent access from the SMTP thread and the aiohttp event-loop thread.
    """

    async def handle_RCPT(
        self, server, session, envelope, address: str, rcpt_options
    ) -> str:
        """Accept mail only for tokens that map to an active inbox slot."""
        local = address.split("@")[0]
        slot = _inbox_slots.get(local)
        if slot is None or time.time() > slot["expires_at"]:
            return "550 5.1.1 User unknown or inbox unavailable"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope) -> str:
        """Parse the raw email and append its body to the matching inbox slot(s)."""
        raw = envelope.content
        if isinstance(raw, bytes):
            msg = _email_lib.message_from_bytes(raw, policy=_email_policy.default)
        else:
            msg = _email_lib.message_from_string(raw, policy=_email_policy.default)

        subject = str(msg.get("Subject", "(no subject)"))
        from_addr = str(msg.get("From", "(unknown sender)"))

        # Spam detection — drop messages from senders that exceed the rate limit
        if _spam_check_mail(from_addr):
            return "450 4.7.1 Too many messages from this sender — try again later"

        body_text = ""
        body_html = ""
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                disp = str(part.get_content_disposition() or "")
                if "attachment" in disp:
                    continue
                if ct == "text/plain" and not body_text:
                    try:
                        body_text = part.get_content()
                    except Exception:  # noqa: BLE001
                        body_text = (part.get_payload(decode=True) or b"").decode(
                            "utf-8", errors="replace"
                        )
                elif ct == "text/html" and not body_html:
                    try:
                        body_html = part.get_content()
                    except Exception:  # noqa: BLE001
                        body_html = (part.get_payload(decode=True) or b"").decode(
                            "utf-8", errors="replace"
                        )
        else:
            ct = msg.get_content_type()
            if ct == "text/html":
                try:
                    body_html = msg.get_content()
                except Exception:  # noqa: BLE001
                    body_html = (msg.get_payload(decode=True) or b"").decode(
                        "utf-8", errors="replace"
                    )
            else:
                try:
                    body_text = msg.get_content()
                except Exception:  # noqa: BLE001
                    body_text = (msg.get_payload(decode=True) or b"").decode(
                        "utf-8", errors="replace"
                    )

        body = body_html or body_text or "(empty message)"

        for rcpt in envelope.rcpt_tos:
            local = rcpt.split("@")[0]
            slot = _inbox_slots.get(local)
            if slot is None or time.time() > slot["expires_at"]:
                continue
            slot["messages"].append({
                "body":         body,
                "email_from":   from_addr,
                "subject":      subject,
                "content_type": "text/html" if body_html else "text/plain",
                "received_at":  time.time(),
            })
            logger.info(
                "inbox email received  token=…%s  from=%.40s  subject=%r",
                local[-6:],
                from_addr,
                subject[:60],
            )

        return "250 Message accepted for delivery"

async def inbox_create_handler(request: web.Request) -> web.Response:
    """POST /inbox/create — allocate a new inbox that accepts unlimited messages.

    Accepts optional JSON body::

        {"ttl_minutes": 60}   # 1–1440, default 60

    When neither MAIL_DOMAIN nor RELAY_SECRET is configured, a real
    mail.tm mailbox is provisioned automatically (free, no DNS needed).
    Any server on the internet — Discord, Google, GitHub, etc. — can
    send email directly to the returned address.

    Returns::

        {
          "address":       "abc123@mail.tm",   # real deliverable email address
          "drop_url":      "/inbox/<token>/drop",
          "read_url":      "/inbox/<token>/read",
          "reader_url":    "/inbox/<token>",
          "expires_at":    <unix-timestamp>,
          "smtp_enabled":  true|false,
          "relay_enabled": true|false,
          "mailtm_enabled": true|false,
        }
    """
    try:
        body = await request.json()
    except Exception:
        body = {}
    ttl_minutes = int(body.get("ttl_minutes", INBOX_DEFAULT_TTL_MINUTES))
    ttl_minutes = max(INBOX_MIN_TTL_MINUTES, min(ttl_minutes, INBOX_MAX_TTL_MINUTES))
    ttl_seconds = ttl_minutes * 60
    token = secrets.token_urlsafe(_INBOX_TOKEN_BYTES)
    expires_at = time.time() + ttl_seconds
    slot: dict = {
        "messages":   [],
        "expires_at": expires_at,
    }
    _inbox_slots[token] = slot

    # ── Determine the real email address ──────────────────────────────────
    mailtm_enabled = False
    if MAIL_DOMAIN:
        # Local SMTP — use the configured domain
        address = f"{token}@{MAIL_DOMAIN}"
    elif MAILTM_ENABLED:
        # Auto-provision a free mail.tm mailbox so any server can deliver here
        mailtm_extras = await _mailtm_provision(_INBOX_TOKEN_BYTES)
        if mailtm_extras:
            slot.update(mailtm_extras)
            address = mailtm_extras["mailtm_address"]
            mailtm_enabled = True
            logger.info("mail.tm inbox provisioned  address=%s  ttl=%dm", address, ttl_minutes)
        else:
            # mail.tm unavailable — fall back to request host
            mail_host = request.host or "localhost"
            address = f"{token}@{mail_host}"
            logger.warning("mail.tm provisioning failed — inbox will be HTTP-drop only")
    else:
        mail_host = request.host or "localhost"
        address = f"{token}@{mail_host}"

    if not mailtm_enabled:
        logger.info("inbox created  address=%.6s@…  ttl=%dm", token, ttl_minutes)

    return web.json_response({
        "address":        address,
        "drop_url":       f"/inbox/{token}/drop",
        "read_url":       f"/inbox/{token}/read",
        "reader_url":     f"/inbox/{token}",
        "expires_at":     expires_at,
        "smtp_enabled":   bool(MAIL_DOMAIN),
        "relay_enabled":  bool(RELAY_SECRET),
        "mailtm_enabled": mailtm_enabled,
    })


async def inbox_drop_handler(request: web.Request) -> web.Response:
    """POST /inbox/{token}/drop — sender deposits a message (unlimited deposits allowed)."""
    token = request.match_info["token"]
    slot = _inbox_slots.get(token)
    if slot is None:
        raise web.HTTPNotFound(reason="Inbox not found")
    if time.time() > slot["expires_at"]:
        _inbox_slots.pop(token, None)
        raise web.HTTPGone(reason="Inbox has expired")
    try:
        body = await request.json()
    except Exception:
        raise web.HTTPBadRequest(reason="JSON body required")
    message = str(body.get("message", "")).strip()
    if not message:
        raise web.HTTPBadRequest(reason="message field must not be empty")
    if len(message) > MAX_INBOX_MESSAGE_LEN:
        raise web.HTTPRequestEntityTooLarge(
            max_size=MAX_INBOX_MESSAGE_LEN,
            actual_size=len(message),
        )
    slot["messages"].append({
        "body":         message,
        "email_from":   None,
        "subject":      None,
        "content_type": "text/plain",
        "received_at":  time.time(),
    })
    logger.info("inbox filled  token=…%s", token[-6:])
    return web.json_response({"ok": True})


async def inbox_read_handler(request: web.Request) -> web.Response:
    """GET /inbox/{token}/read — JSON API: return all messages in the inbox.

    Inbox is NOT destroyed on read.  It auto-expires at its TTL.
    Response::

        {
          "messages": [
            {"body": "…", "email_from": "…", "subject": "…",
             "content_type": "text/plain|text/html", "received_at": <unix-ts>},
            …
          ],
          "expires_at": <unix-ts>,
          "count": <int>
        }
    """
    token = request.match_info["token"]
    slot = _inbox_slots.get(token)
    if slot is None:
        raise web.HTTPGone(reason="Inbox not found or expired")
    if time.time() > slot["expires_at"]:
        _inbox_slots.pop(token, None)
        raise web.HTTPGone(reason="Inbox has expired")
    if token not in _inbox_logged_tokens:
        _inbox_logged_tokens.add(token)
        logger.info("inbox read  token=…%s  count=%d", token[-6:], len(slot["messages"]))
    return web.json_response({
        "messages":   slot["messages"],
        "expires_at": slot["expires_at"],
        "count":      len(slot["messages"]),
    })


async def inbox_read_page_handler(request: web.Request) -> web.Response:
    """GET /inbox/{token} — serve the full HTML mail-reader page."""
    token = request.match_info["token"]
    slot = _inbox_slots.get(token)
    if slot is None or time.time() > slot["expires_at"]:
        _inbox_slots.pop(token, None)
        raise web.HTTPGone(reason="Inbox not found or expired")
    mail_host = MAIL_DOMAIN or request.host or "localhost"
    address = f"{token}@{mail_host}"
    html = (STATIC_DIR / "mail_read.html").read_text(encoding="utf-8")
    html = html.replace("__INBOX_TOKEN__", token)
    html = html.replace("__INBOX_ADDRESS__", address)
    html = html.replace("__INBOX_EXPIRES_AT__", str(slot["expires_at"]))
    return web.Response(text=html, content_type="text/html")


async def inbox_drop_page_handler(request: web.Request) -> web.Response:
    """GET /inbox/{token}/drop — serve the sender HTML page."""
    token = request.match_info["token"]
    slot = _inbox_slots.get(token)
    if slot is None or time.time() > slot["expires_at"]:
        _inbox_slots.pop(token, None)
        raise web.HTTPGone(reason="Inbox not found or expired")
    host = MAIL_DOMAIN or request.host or "localhost"
    address = f"{token}@{host}"
    html = (STATIC_DIR / "inbox.html").read_text(encoding="utf-8")
    html = html.replace("__INBOX_TOKEN__", token)
    html = html.replace("__INBOX_ADDRESS__", address)
    html = html.replace("__INBOX_EXPIRES_AT__", str(slot["expires_at"]))
    return web.Response(text=html, content_type="text/html")


async def inbox_relay_handler(request: web.Request) -> web.Response:
    """POST /inbox/relay — IP-privacy relay webhook endpoint.

    Instead of running a direct SMTP listener (which exposes this server's IP),
    you can point your domain's MX records at a relay service (Mailgun, SendGrid,
    Cloudflare Email Workers, ImprovMX, ForwardEmail, etc.) and have the relay
    POST inbound emails here over HTTPS.  Your IP only needs to be reachable on
    port 443 — it never appears in MX records.

    Requires ``RELAY_SECRET`` environment variable to be set.  The secret must be
    present in the request (checked against the ``X-Relay-Secret`` header, a
    ``secret`` query-string parameter, or a ``secret`` JSON body field).

    Supported relay payload formats
    --------------------------------
    **Generic JSON** (recommended — works with any relay via a custom worker)::

        {
            "secret":       "<RELAY_SECRET>",
            "token":        "<inbox-token>",   # the local-part of the address
            "from":         "alice@example.com",
            "subject":      "Hello",
            "body":         "Plain-text body",   # or "html": "<b>HTML body</b>"
            "html":         "<b>HTML body</b>"   # optional; takes precedence over body
        }

    **Mailgun Inbound Routes** (application/x-www-form-urlencoded or multipart/form-data)::

        recipient=<token>@mail.example.com
        sender=alice@example.com
        subject=Hello
        body-plain=Plain text
        body-html=<b>HTML</b>   # optional

    **SendGrid Inbound Parse Webhook** (multipart/form-data)::

        to=<token>@mail.example.com
        from=alice@example.com
        subject=Hello
        text=Plain text
        html=<b>HTML</b>   # optional

    Returns 200 ``{"ok": true}`` on success.  Returns 403 if the secret is wrong,
    404 if the inbox token is not found / expired, 400 for malformed payloads.
    """
    if not RELAY_SECRET:
        raise web.HTTPNotFound()  # endpoint doesn't exist unless configured

    # ── Authenticate ────────────────────────────────────────────────────────
    # Accept the secret via header, query-string, or body field.
    provided_secret = (
        request.headers.get("X-Relay-Secret", "")
        or request.rel_url.query.get("secret", "")
    )

    ct = request.content_type or ""
    raw_body: bytes = await request.read()

    # Parse body depending on content type
    json_body: dict = {}
    form_data: dict = {}

    if "json" in ct:
        try:
            import json as _json
            json_body = _json.loads(raw_body) if raw_body else {}
        except Exception:
            raise web.HTTPBadRequest(reason="Invalid JSON body")
    elif "form" in ct or "multipart" in ct:
        try:
            post = await request.post()
            form_data = dict(post)
        except Exception:
            raise web.HTTPBadRequest(reason="Could not parse form body")
    # else: body may carry the secret in headers / query-string only

    if not provided_secret:
        # Fall back to body fields
        provided_secret = (
            json_body.get("secret", "")
            or str(form_data.get("secret", ""))
        )

    # Constant-time comparison to prevent timing attacks
    import hmac as _hmac
    if not _hmac.compare_digest(
        provided_secret.encode("utf-8"),
        RELAY_SECRET.encode("utf-8"),
    ):
        logger.warning("inbox relay auth failed  remote=%s", request.remote)
        raise web.HTTPForbidden(reason="Invalid relay secret")

    # ── Extract fields ───────────────────────────────────────────────────────
    if json_body:
        # Generic JSON format
        token      = str(json_body.get("token") or "").strip()
        from_addr  = str(json_body.get("from") or json_body.get("sender") or "").strip()
        subject    = str(json_body.get("subject") or "").strip()
        body_html  = str(json_body.get("html") or "").strip()
        body_text  = str(json_body.get("body") or json_body.get("text") or "").strip()
    elif form_data:
        # Mailgun: recipient=token@domain  sender=  subject=  body-plain=  body-html=
        # SendGrid: to=token@domain  from=  subject=  text=  html=
        raw_to     = str(form_data.get("recipient") or form_data.get("to") or "").strip()
        token      = raw_to.split("@")[0] if "@" in raw_to else raw_to
        from_addr  = str(form_data.get("sender") or form_data.get("from") or "").strip()
        subject    = str(form_data.get("subject") or "").strip()
        body_html  = str(form_data.get("body-html") or form_data.get("html") or "").strip()
        body_text  = str(form_data.get("body-plain") or form_data.get("text") or "").strip()
    else:
        raise web.HTTPBadRequest(reason="Unsupported content type; send JSON or form data")

    if not token:
        raise web.HTTPBadRequest(reason="Missing inbox token (recipient/to/token field)")

    # ── Deposit into inbox ───────────────────────────────────────────────────
    slot = _inbox_slots.get(token)
    if slot is None or time.time() > slot["expires_at"]:
        _inbox_slots.pop(token, None)
        raise web.HTTPNotFound(reason="Inbox not found or expired")

    body = body_html or body_text or "(empty message)"
    if len(body) > MAX_INBOX_MESSAGE_LEN:
        body = body[:MAX_INBOX_MESSAGE_LEN]

    slot["messages"].append({
        "body":         body,
        "email_from":   from_addr or None,
        "subject":      subject or None,
        "content_type": "text/html" if body_html else "text/plain",
        "received_at":  time.time(),
    })
    logger.info(
        "inbox relay received  token=…%s  from=%.40s  subject=%r",
        token[-6:],
        from_addr,
        subject[:60],
    )
    return web.json_response({"ok": True})


async def _cleanup_expired_inbox_slots() -> None:
    """Background task: sweep expired inbox slots every 5 minutes."""
    while True:
        await asyncio.sleep(300)
        now = time.time()
        expired = [t for t, s in list(_inbox_slots.items()) if now > s["expires_at"]]
        for t in expired:
            _inbox_slots.pop(t, None)
            _inbox_logged_tokens.discard(t)
        if expired:
            logger.info("cleaned up %d expired inbox slot(s)", len(expired))


# ---------------------------------------------------------------------------
# Room-create and server-info handlers
# ---------------------------------------------------------------------------


async def room_create_handler(request: web.Request) -> web.Response:
    """POST /room/create — register a room with optional passcode and self-destruct timer."""
    try:
        body = await request.json()
    except Exception:
        raise web.HTTPBadRequest(reason="JSON body required")

    passcode = str(body.get("passcode") or "").strip()[:MAX_PASSCODE_LEN]
    try:
        destruct_minutes = int(body.get("destruct_minutes", 0))
    except (ValueError, TypeError):
        destruct_minutes = 0
    destruct_minutes = max(0, min(MAX_DESTRUCT_MINUTES, destruct_minutes))

    # Webhook URL — validated to start with http/https and within length limit
    webhook_url = str(body.get("webhook_url") or "").strip()[:MAX_WEBHOOK_URL_LEN]
    if webhook_url and not re.match(r"^https?://", webhook_url):
        webhook_url = ""

    # Generate a unique room ID (16-char hex)
    for _ in range(20):
        room_id = secrets.token_hex(8)
        if room_id not in _room_meta and room_id not in rooms:
            break

    expires_at = (time.time() + destruct_minutes * 60) if destruct_minutes > 0 else None
    passcode_hash = _hash_passcode(passcode) if passcode else None

    # Generate a delete code (returned to creator only; stored as a hash)
    delete_code = secrets.token_urlsafe(9)  # ~12 URL-safe chars
    delete_code_hash = _hash_passcode(delete_code)

    _room_meta[room_id] = {
        "passcode_hash": passcode_hash,
        "expires_at": expires_at,
        "delete_code_hash": delete_code_hash,
        "webhook_url": webhook_url or None,
    }
    _stats["rooms_created_total"] += 1
    logger.info(
        "room created  room=%s  passcode=%s  destruct=%dm  webhook=%s",
        room_id,
        bool(passcode),
        destruct_minutes,
        bool(webhook_url),
    )
    return web.json_response({
        "room_id": room_id,
        "expires_at": expires_at,
        "delete_code": delete_code,
    })


async def room_delete_handler(request: web.Request) -> web.Response:
    """POST /room/{room_id}/delete — destroy a room and all associated data.

    If the room was created with a delete code the request body must supply it::

        {"delete_code": "<code>"}
    """
    room_id = request.match_info["room_id"]
    if not _ROOM_RE.match(room_id):
        raise web.HTTPBadRequest(reason="Invalid room ID")

    # Read optional JSON body for delete code verification
    try:
        body = await request.json()
    except Exception:
        body = {}

    meta = _room_meta.get(room_id)
    # Always require the delete code for any registered room.
    # Using `is not None` (rather than truthiness) means an empty-but-present
    # meta dict is also guarded.  If delete_code_hash is somehow absent from
    # the metadata we deny the request rather than allowing a silent bypass.
    if meta is not None:
        expected_hash = meta.get("delete_code_hash")
        provided_code = str(body.get("delete_code", "")).strip()
        if not expected_hash or not provided_code or _hash_passcode(provided_code) != expected_hash:
            raise web.HTTPForbidden(reason="Wrong or missing delete code")

    # Remove room metadata
    _room_meta.pop(room_id, None)

    # Delete stored messages from DB
    db_path: Path = request.app["db_path"]
    try:
        await asyncio.to_thread(_delete_room_history_sync, db_path, room_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("failed to delete room history  room=%s  error=%s", room_id, exc)

    # Notify connected peers and disconnect them.
    # Pop the room BEFORE closing peers so that the ws_handler cleanup
    # does not find the room and emit a spurious "room deleted" log entry.
    if room_id in rooms:
        await _broadcast_to_room(room_id, json.dumps({"type": "destruct"}))
        peers_to_close = list(rooms.pop(room_id))
        for peer in peers_to_close:
            try:
                await peer.close()
            except Exception:  # noqa: BLE001
                pass

    logger.info("room deleted  room=%s  (manual delete)", room_id)
    return web.json_response({"ok": True})


async def server_info_handler(request: web.Request) -> web.Response:
    """GET /api/server-info — return public server information (onion address if known)."""
    onion = ONION_ADDRESS
    if not onion:
        # Try well-known Tor hidden-service hostname file locations
        for candidate in [
            Path("/var/lib/tor/hidden_service/hostname"),
            Path("/etc/tor/hidden_service/hostname"),
            _HERE / "tor" / "hidden_service" / "hostname",
        ]:
            if candidate.exists():
                try:
                    onion = candidate.read_text().strip() or None
                except Exception:  # noqa: BLE001
                    pass
                break
    return web.json_response({"onion": onion, "mail_domain": MAIL_DOMAIN or None, "relay_enabled": bool(RELAY_SECRET)})


async def qrcode_handler(request: web.Request) -> web.Response:
    """GET /api/qrcode?data=<url> — return a QR code SVG for the given URL."""
    data = request.query.get("data", "").strip()
    if not data:
        raise web.HTTPBadRequest(reason="data parameter is required")
    if len(data) > 2048:
        raise web.HTTPBadRequest(reason="data too long (max 2048 chars)")

    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(image_factory=_QrSvgImage)
    buf = io.BytesIO()
    img.save(buf)
    return web.Response(
        body=buf.getvalue(),
        content_type="image/svg+xml",
        headers={"Cache-Control": "no-store"},
    )


async def _cleanup_expired_rooms(db_path: Path) -> None:
    """Background task: self-destruct expired rooms every 30 seconds."""
    while True:
        await asyncio.sleep(30)
        now = time.time()
        expired = [
            r for r, m in list(_room_meta.items())
            if m.get("expires_at") and now > m["expires_at"]
        ]
        for room_id in expired:
            _room_meta.pop(room_id, None)
            if room_id in rooms:
                await _broadcast_to_room(room_id, json.dumps({"type": "destruct"}))
                for peer in list(rooms.get(room_id, set())):
                    try:
                        await peer.close()
                    except Exception:  # noqa: BLE001
                        pass
                rooms.pop(room_id, None)
            try:
                await asyncio.to_thread(_delete_room_history_sync, db_path, room_id)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "failed to delete room history  room=%s  error=%s", room_id, exc
                )
            logger.info("room self-destructed  room=%s", room_id)


# ---------------------------------------------------------------------------
# Webhook helper
# ---------------------------------------------------------------------------


async def _fire_webhook(url: str, event: str, data: dict) -> None:
    """POST a JSON event payload to *url*; all errors are silently swallowed."""
    if not url:
        return
    try:
        from aiohttp import ClientSession, ClientTimeout
        payload = {"event": event, "ts": time.time(), **data}
        timeout = ClientTimeout(total=8)
        async with ClientSession(timeout=timeout) as session:
            await session.post(url, json=payload)
    except Exception:  # noqa: BLE001
        pass


# ---------------------------------------------------------------------------
# Admin panel — served on the SAME port/URL as the main site, behind a
# 200-character random path prefix and a 100-character passcode.
# ---------------------------------------------------------------------------


def _make_admin_session() -> str:
    """Generate a new admin session token."""
    return secrets.token_hex(32)


def _valid_admin_session(request: web.Request) -> bool:
    """Return True if the request carries a valid, non-expired admin session cookie."""
    token = request.cookies.get("admin_session", "")
    exp = _ADMIN_SESSIONS.get(token)
    if exp is None:
        return False
    if time.time() > exp:
        _ADMIN_SESSIONS.pop(token, None)
        return False
    return True


def _add_admin_security_headers(resp: web.Response) -> None:
    """Apply security headers to every admin response."""
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Pragma"] = "no-cache"
    # Tight CSP: admin panel only needs inline scripts (already in admin.html)
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; "
        "img-src 'self' data:; "
        "object-src 'none'; "
        "frame-ancestors 'none';"
    )


async def _admin_login_handler(request: web.Request) -> web.Response:
    """POST /{path}/login — verify passcode; set session cookie on success."""
    # ── Rate-limiting ─────────────────────────────────────────────────────────
    ip = request.remote or "unknown"
    now = time.time()

    # Hard-cap lockout: once an IP accumulates ADMIN_LOGIN_HARD_CAP failures
    # within the hard-cap window, it is blocked for ADMIN_LOGIN_HARD_CAP_DURATION
    # seconds.  This prevents indefinite 60-second retry loops.
    unlock_at = _ADMIN_LOGIN_HARD_LOCKOUT.get(ip, 0.0)
    if now < unlock_at:
        logger.warning("admin login hard-locked  ip=%s  unlock_in=%.0fs", ip, unlock_at - now)
        raise web.HTTPTooManyRequests(reason="Too many failed attempts — try again later")

    failures = _ADMIN_LOGIN_FAILURES.get(ip, [])
    # Purge timestamps outside the sliding window
    failures = [t for t in failures if now - t < ADMIN_LOGIN_RATE_WINDOW]
    if len(failures) >= ADMIN_LOGIN_MAX_ATTEMPTS:
        logger.warning("admin login rate-limited  ip=%s", ip)
        raise web.HTTPTooManyRequests(reason="Too many failed attempts — wait before retrying")
    # ── Passcode check ────────────────────────────────────────────────────────
    try:
        body = await request.json()
    except Exception:
        raise web.HTTPBadRequest(reason="JSON body required")
    provided = str(body.get("passcode", ""))
    # Always call compare_digest (even for empty input) to prevent timing side-channels.
    if not secrets.compare_digest(provided, _ADMIN_PASSCODE):
        failures.append(now)
        _ADMIN_LOGIN_FAILURES[ip] = failures
        # Check if the cumulative failure count over the hard-cap window has been exceeded
        recent_all = [t for t in failures if now - t < ADMIN_LOGIN_HARD_CAP_WINDOW]
        if len(recent_all) >= ADMIN_LOGIN_HARD_CAP:
            _ADMIN_LOGIN_HARD_LOCKOUT[ip] = now + ADMIN_LOGIN_HARD_CAP_DURATION
            _ADMIN_LOGIN_FAILURES.pop(ip, None)
            logger.warning(
                "admin login hard-locked  ip=%s  failures=%d  locked_for=%ds",
                ip, len(recent_all), ADMIN_LOGIN_HARD_CAP_DURATION,
            )
        else:
            logger.warning("admin login failed  ip=%s  attempts=%d", ip, len(failures))
        raise web.HTTPForbidden(reason="Wrong passcode")
    # Success — clear failure and lockout records for this IP
    _ADMIN_LOGIN_FAILURES.pop(ip, None)
    _ADMIN_LOGIN_HARD_LOCKOUT.pop(ip, None)
    # Single-session: invalidate all previous sessions so that any other
    # browser or device that held an old token is automatically logged out.
    _ADMIN_SESSIONS.clear()
    token = _make_admin_session()
    _ADMIN_SESSIONS[token] = time.time() + ADMIN_SESSION_TTL
    resp = web.json_response({"ok": True})
    resp.set_cookie(
        "admin_session",
        token,
        # No max_age → session cookie: expires when the browser is closed.
        # This prevents auto-login on any device after a browser restart.
        httponly=True,
        # Set the Secure flag only when the login request itself arrived over
        # HTTPS (request.secure is True).  HTTP and .onion connections are
        # plaintext at the TCP layer but .onion is end-to-end encrypted by
        # Tor, so we don't force Secure=True there — doing so would break
        # .onion-only deployments.
        secure=request.secure,
        samesite="Strict",
    )
    _add_admin_security_headers(resp)
    return resp


async def _admin_index_handler(request: web.Request) -> web.Response:
    """GET /{path}/ — return admin panel HTML with the admin path injected."""
    html = (STATIC_DIR / "admin.html").read_text(encoding="utf-8")
    # Inject the admin path as a JS constant so all fetch() calls use the right URLs.
    # The placeholder __ADMIN_PATH__ is replaced once at serve time.
    html = html.replace("__ADMIN_PATH__", _ADMIN_PATH)
    # Sanity-check that the replacement actually happened — if the placeholder is
    # still present the admin JS would send requests to a literal bad URL.
    if "__ADMIN_PATH__" in html:
        logger.error("admin.html placeholder was not replaced — _ADMIN_PATH may be empty")
        raise web.HTTPInternalServerError(reason="Admin panel misconfigured")
    resp = web.Response(text=html, content_type="text/html")
    _add_admin_security_headers(resp)
    return resp


def _get_sys_metrics() -> dict:
    """Return CPU, RAM, disk, and (if available) GPU metrics as a dict.

    CPU and RAM figures reflect the server *process* only so that the admin
    panel shows what secureChat itself is consuming rather than the total load
    of the host machine.  Disk usage remains system-wide because the process
    does not have its own filesystem.

    All values that cannot be collected are omitted from the returned dict so
    the caller can check their presence before rendering them.
    """
    metrics: dict = {}

    if _PSUTIL_AVAILABLE:
        try:
            proc = _psutil.Process()
            cpu_count = _psutil.cpu_count(logical=True) or 1
            # proc.cpu_percent() can exceed 100 on multi-core systems; normalise
            # to 0-100 so the progress bar and colour thresholds work correctly.
            raw_cpu = proc.cpu_percent(interval=None)
            metrics["sys_cpu_percent"] = min(round(raw_cpu / cpu_count, 1), 100.0)
            mem = proc.memory_info()
            total_ram = _psutil.virtual_memory().total
            metrics["sys_ram_used"]     = mem.rss
            metrics["sys_ram_total"]    = total_ram
            metrics["sys_ram_percent"]  = round(mem.rss / total_ram * 100, 1) if total_ram else 0.0
            du = _psutil.disk_usage("/")
            metrics["sys_disk_percent"] = du.percent
            metrics["sys_disk_total"]   = du.total
            metrics["sys_disk_used"]    = du.used
        except Exception:  # pragma: no cover  # noqa: BLE001
            pass

    if _NVML_AVAILABLE:
        gpus = []
        try:
            count = _pynvml.nvmlDeviceGetCount()
            for i in range(count):
                handle = _pynvml.nvmlDeviceGetHandleByIndex(i)
                name   = _pynvml.nvmlDeviceGetName(handle)
                if isinstance(name, bytes):
                    name = name.decode()
                util   = _pynvml.nvmlDeviceGetUtilizationRates(handle)
                mem    = _pynvml.nvmlDeviceGetMemoryInfo(handle)
                try:
                    temp = _pynvml.nvmlDeviceGetTemperature(
                        handle, _pynvml.NVML_TEMPERATURE_GPU
                    )
                except Exception:  # noqa: BLE001
                    temp = None
                gpus.append({
                    "name":         name,
                    "load_percent": util.gpu,
                    "mem_total":    mem.total,
                    "mem_used":     mem.used,
                    "mem_percent":  round(mem.used / mem.total * 100, 1) if mem.total else 0,
                    "temp_c":       temp,
                })
        except Exception:  # pragma: no cover  # noqa: BLE001
            pass
        if gpus:
            metrics["sys_gpus"] = gpus

    return metrics


async def _admin_stats_handler(request: web.Request) -> web.Response:
    """GET /{path}/api/stats — return current server stats as JSON."""
    if not _valid_admin_session(request):
        raise web.HTTPUnauthorized()
    now = time.time()
    open_rooms = set(rooms.keys())
    meta_rooms = set(_room_meta.keys())
    inactive_rooms = meta_rooms - open_rooms

    # Rooms by destruct timer label
    by_destruct: dict[str, int] = {}
    for rid, meta in _room_meta.items():
        exp = meta.get("expires_at")
        if exp:
            remaining = max(0.0, exp - now)
            h = remaining / 3600
            if h <= 0.5:
                label = "< 30 min"
            elif h <= 1:
                label = "1 h"
            elif h <= 2:
                label = "2 h"
            elif h <= 4:
                label = "4 h"
            elif h <= 8:
                label = "8 h"
            else:
                label = "24 h"
        else:
            label = "Never"
        by_destruct[label] = by_destruct.get(label, 0) + 1

    resp = web.json_response({
        **_stats,
        "open_rooms": len(open_rooms),
        "inactive_rooms": len(inactive_rooms),
        "invite_rooms": len(meta_rooms),
        "open_file_transfers": len(_share_slots),
        "rooms_by_destruct": by_destruct,
        **_get_sys_metrics(),
    })
    _add_admin_security_headers(resp)
    return resp


async def _admin_webhook_info_handler(request: web.Request) -> web.Response:
    """GET /{path}/api/webhook-info — return incoming webhook URL (requires auth)."""
    if not _valid_admin_session(request):
        raise web.HTTPUnauthorized()
    resp = web.json_response({"webhook_token": _ADMIN_WEBHOOK_TOKEN})
    _add_admin_security_headers(resp)
    return resp


async def _admin_logs_sse_handler(request: web.Request) -> web.StreamResponse:
    """GET /{path}/api/logs — SSE stream of live log records (requires auth)."""
    if not _valid_admin_session(request):
        raise web.HTTPUnauthorized()
    # Snapshot the ring buffer BEFORE registering the per-client queue so
    # there is no gap: the snapshot covers history up to this moment and the
    # queue captures every message from this moment forward.
    recent_snapshot = list(_log_recent)
    # Each client gets its own queue so that all connected clients receive every message.
    q: asyncio.Queue = asyncio.Queue(maxsize=1000)
    _log_sse_clients.append(q)
    response = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Accel-Buffering"] = "no"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    await response.prepare(request)
    await response.write(b"retry: 3000\n\n")
    # Replay recent log history so the Live Logs panel is not empty on first connect.
    for msg in recent_snapshot:
        safe = msg.replace("\n", " ").replace("\r", " ")
        await response.write(f"event: log\ndata: {safe}\n\n".encode())
    try:
        while True:
            try:
                msg = await asyncio.wait_for(q.get(), timeout=15)
                safe = msg.replace("\n", " ").replace("\r", " ")
                await response.write(f"event: log\ndata: {safe}\n\n".encode())
            except asyncio.TimeoutError:
                await response.write(b": keepalive\n\n")
    except (ConnectionResetError, asyncio.CancelledError):
        pass
    finally:
        try:
            _log_sse_clients.remove(q)
        except ValueError:
            pass
    return response


async def _admin_ddos_stats_handler(request: web.Request) -> web.Response:
    """GET /{path}/api/ddos-stats — return DDoS protection statistics."""
    if not _valid_admin_session(request):
        raise web.HTTPUnauthorized()
    resp = web.json_response({
        "ddos": _ddos_get_stats(),
        "spam": _spam_get_stats(),
    })
    _add_admin_security_headers(resp)
    return resp


async def _admin_ddos_unban_handler(request: web.Request) -> web.Response:
    """POST /{path}/api/ddos-unban — manually lift a DDoS ban.

    Body: ``{"ip": "1.2.3.4"}``
    """
    if not _valid_admin_session(request):
        raise web.HTTPUnauthorized()
    try:
        body = await request.json()
    except Exception:
        raise web.HTTPBadRequest(reason="Invalid JSON")
    ip = str(body.get("ip", "")).strip()
    if not ip:
        raise web.HTTPBadRequest(reason="'ip' field is required")
    unbanned = _ddos_unban_ip(ip)
    resp = web.json_response({"unbanned": unbanned, "ip": ip})
    _add_admin_security_headers(resp)
    return resp


async def _slow_mode_status_handler(request: web.Request) -> web.Response:
    """GET /api/slow-mode — public endpoint that returns current slow-mode state.

    This endpoint intentionally requires NO authentication so that the chat
    frontend can poll it to show or hide the slow-mode banner.
    """
    resp = web.json_response(_slow_mode_status())
    _add_admin_security_headers(resp)
    return resp


async def _admin_slow_mode_handler(request: web.Request) -> web.Response:
    """POST /{admin_path}/api/slow-mode — toggle slow mode on or off.

    Body (optional JSON):
      ``{"active": true}``              — force enable/disable
      ``{"targets": ["chat", "mail"]}`` — restrict which services are slowed
      Valid target tokens: "all", "chat", "chat_creation", "file_sharing", "mail"
      An empty targets list or omitting targets means "all" services.

    Without a body the current active state is flipped.
    Requires an active admin session.
    """
    global _slow_mode_active, _slow_mode_targets  # noqa: PLW0603
    if not _valid_admin_session(request):
        raise web.HTTPUnauthorized()

    try:
        body = await request.json()
        if "active" in body:
            _slow_mode_active = bool(body["active"])
        else:
            _slow_mode_active = not _slow_mode_active
        if "targets" in body:
            raw = body["targets"]
            if isinstance(raw, list):
                valid = {str(t).strip().lower() for t in raw} & SLOW_MODE_ALL_TARGETS
                _slow_mode_targets = valid
    except Exception:
        # No body or invalid JSON — just toggle
        _slow_mode_active = not _slow_mode_active

    state = "enabled" if _slow_mode_active else "disabled"
    logger.warning("SLOW MODE %s via admin panel", state.upper())
    resp = web.json_response(_slow_mode_status())
    _add_admin_security_headers(resp)
    return resp


async def _admin_shutdown_handler(request: web.Request) -> web.Response:
    """POST /{path}/api/shutdown — emergency shutdown."""
    if not _valid_admin_session(request):
        raise web.HTTPUnauthorized()
    logger.warning("EMERGENCY SHUTDOWN triggered via admin panel")
    # os._exit is intentional here: this is an *emergency* shutdown that must
    # terminate the process immediately, bypassing the event loop's normal cleanup
    # to prevent any in-flight tasks from delaying the stop.
    asyncio.get_running_loop().call_later(0.5, os._exit, 0)  # noqa: SLF001
    resp = web.json_response({"ok": True, "msg": "Shutting down…"})
    _add_admin_security_headers(resp)
    return resp


async def _admin_incoming_webhook_handler(request: web.Request) -> web.Response:
    """POST /{path}/webhook/{token} — incoming webhook from an external service.

    Any service that knows the webhook token can POST a JSON payload here.
    The event is logged immediately and appears in the live-log SSE stream.
    No admin session is required — the token in the URL path acts as authentication.
    """
    token = request.match_info["token"]
    if not token or not secrets.compare_digest(token, _ADMIN_WEBHOOK_TOKEN):
        raise web.HTTPUnauthorized(reason="Invalid webhook token")
    try:
        body = await request.json()
    except Exception:
        body = {}
    event = str(body.get("event", "webhook"))
    logger.info("incoming webhook  event=%s  source=%s  payload=%s",
                event, request.remote, json.dumps(body))
    resp = web.json_response({"ok": True, "received": True})
    _add_admin_security_headers(resp)
    return resp


def _init_admin_credentials() -> tuple[str, str]:
    """Generate (or read from env) admin path and passcode; print both to console.

    Returns:
        (admin_path, admin_passcode) — both are ready to use as URL/auth values.
    """
    # ── Path (200 random URL-safe characters) ─────────────────────────────────
    path = os.environ.get("ADMIN_PATH", "").strip()
    if not path:
        # secrets.token_urlsafe(150) returns exactly ceil(150*4/3) = 200 base64 chars.
        # The [:200] slice is defensive in case the formula changes in a future Python.
        path = secrets.token_urlsafe(150)[:200]

    # ── Passcode (100 characters) ──────────────────────────────────────────────
    pc = os.environ.get("ADMIN_PASSCODE", "").strip()
    if not pc:
        # secrets.token_urlsafe(75) returns exactly 100 base64 chars.
        pc = secrets.token_urlsafe(75)[:100]

    # ── Print both prominently to the console ──────────────────────────────────
    print("", flush=True)
    print("=" * 72, flush=True)
    print("  ADMIN PANEL CREDENTIALS — store these securely", flush=True)
    print("=" * 72, flush=True)
    print(f"  Admin URL path : /{path}/", flush=True)
    print(f"  Admin passcode : {pc}", flush=True)
    print("=" * 72, flush=True)
    print("", flush=True)
    logger.info("admin panel ready  (path printed to console at startup)")

    return path, pc


def _init_clearnet_path() -> str:
    """Generate (or read from env) the 100-character clearnet URL path segment.

    The clearnet path is a security-through-obscurity access URL for the main
    chat interface over the regular internet.  Outbound connections from the
    server use Tor (if running locally at 127.0.0.1:9050) or direct connection
    as a fallback.  Set SOCKS5_PROXY in the environment to route through a
    specific proxy.

    The path is printed to the console at startup and must be kept private.
    Set CLEARNET_PATH in the environment to pin a specific path across restarts.

    Returns:
        The 100-character URL-safe path string (no leading/trailing slashes).
    """
    path = os.environ.get("CLEARNET_PATH", "").strip()
    if not path:
        # secrets.token_urlsafe(75) returns exactly 100 URL-safe base64 characters.
        path = secrets.token_urlsafe(75)[:100]

    print("", flush=True)
    print("=" * 72, flush=True)
    print("  CLEARNET ACCESS URL — share only over a secure channel", flush=True)
    print("=" * 72, flush=True)
    print(f"  Secret path    : /{path}/", flush=True)
    print(f"  Proxy          : Tor (127.0.0.1:9050) if available, else direct", flush=True)
    print("=" * 72, flush=True)
    print("", flush=True)
    logger.info("clearnet access path ready  (printed to console at startup)")

    return path


async def _probe_clearnet_exit_ip() -> None:
    """Fetch and print the public exit IP through Tor or direct connection.

    Tries Tor (127.0.0.1:9050) first, then direct.  Prints the exit IP so the
    operator can verify how outbound traffic is routed.

    This runs as a background task from on_startup so it does not delay server
    boot.  If no connection is available a warning is printed.
    """
    # ip-reflection services that return just the raw IP text
    ip_services = [
        "https://api.ipify.org",
        "https://checkip.amazonaws.com",
        "https://icanhazip.com",
    ]
    # Try Tor first, then direct
    candidates = ["socks5://127.0.0.1:9050", ""]

    exit_ip: str | None = None
    used_proxy: str = ""
    for proxy_url in candidates:
        for url in ip_services:
            try:
                sess = _build_session(proxy_url, timeout=10.0)
                async with sess:
                    async with sess.get(url) as resp:
                        if resp.status == 200:
                            exit_ip = (await resp.text()).strip()
                            used_proxy = proxy_url
                            break
            except Exception:  # noqa: BLE001
                continue
        if exit_ip:
            break

    print("", flush=True)
    print("=" * 72, flush=True)
    print("  CLEARNET EXIT IP", flush=True)
    print("=" * 72, flush=True)
    if exit_ip:
        print(f"  Exit IP        : {exit_ip}", flush=True)
        via = used_proxy if used_proxy else "direct (no Tor)"
        print(f"  Via            : {via}", flush=True)
    else:
        print(f"  Exit IP        : (could not reach any IP service)", flush=True)
    print("=" * 72, flush=True)
    print("", flush=True)


def _print_lockdown_console_banner() -> None:
    """Clear the terminal and render a large, unmistakable LOCKDOWN banner."""
    # Clear the screen (works on both POSIX and Windows terminals).
    os.system("cls" if os.name == "nt" else "clear")  # noqa: S605, S607
    RED = "\033[1;31m"
    RESET = "\033[0m"
    banner = r"""
██╗      ██████╗  ██████╗██╗  ██╗██████╗  ██████╗ ██╗    ██╗███╗   ██╗
██║     ██╔═══██╗██╔════╝██║ ██╔╝██╔══██╗██╔═══██╗██║    ██║████╗  ██║
██║     ██║   ██║██║     █████╔╝ ██║  ██║██║   ██║██║ █╗ ██║██╔██╗ ██║
██║     ██║   ██║██║     ██╔═██╗ ██║  ██║██║   ██║██║███╗██║██║╚██╗██║
███████╗╚██████╔╝╚██████╗██║  ██╗██████╔╝╚██████╔╝╚███╔███╔╝██║ ╚████║
╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═══╝
"""
    width = 72
    print("\n" * 2, flush=True)
    print(RED + "=" * width + RESET, flush=True)
    print(RED + banner + RESET, flush=True)
    print(RED + "  !! ALL DATA WIPED — ALL CONNECTIONS CLOSED !!" + RESET, flush=True)
    print(RED + "=" * width + RESET, flush=True)
    print("\n" * 2, flush=True)


async def _lockdown_broadcast_task() -> None:
    """Background task: while lockdown is active, emit a warning log every 5 seconds."""
    while True:
        await asyncio.sleep(5)
        if _lockdown_active:
            logger.warning("🔴 LOCKDOWN ACTIVE — server is in lockdown mode")


# ---------------------------------------------------------------------------
# Metrics history — sampled every 10 s, retained 12 months
# ---------------------------------------------------------------------------

def _store_metrics_sample_sync(
    path: Path,
    ts: float,
    cpu: float | None,
    ram: float | None,
    disk: float | None,
    active_rooms: int,
) -> None:
    con = sqlite3.connect(path)
    try:
        con.execute(
            "INSERT INTO metrics_history (ts, cpu_pct, ram_pct, disk_pct, active_rooms)"
            " VALUES (?, ?, ?, ?, ?)",
            (ts, cpu, ram, disk, active_rooms),
        )
        con.commit()
    finally:
        con.close()


def _prune_metrics_sync(path: Path, cutoff: float) -> None:
    con = sqlite3.connect(path)
    try:
        con.execute("DELETE FROM metrics_history WHERE ts < ?", (cutoff,))
        con.commit()
    finally:
        con.close()


def _query_metrics_sync(
    path: Path, since: float, until: float, max_points: int
) -> list[dict]:
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute(
            "SELECT ts, cpu_pct, ram_pct, disk_pct, active_rooms"
            " FROM metrics_history"
            " WHERE ts >= ? AND ts <= ?"
            " ORDER BY ts ASC",
            (since, until),
        ).fetchall()
    finally:
        con.close()

    if not rows:
        return []

    if len(rows) <= max_points:
        return [dict(r) for r in rows]

    # Bucket-average down to max_points
    step = len(rows) / max_points
    result: list[dict] = []
    for i in range(max_points):
        s = int(i * step)
        e = int((i + 1) * step)
        bucket = rows[s:e]
        if not bucket:
            continue

        def _avg(key: str) -> float | None:
            vals = [r[key] for r in bucket if r[key] is not None]
            return round(sum(vals) / len(vals), 1) if vals else None

        rooms_avg = _avg("active_rooms")
        result.append({
            "ts":           bucket[len(bucket) // 2]["ts"],
            "cpu_pct":      _avg("cpu_pct"),
            "ram_pct":      _avg("ram_pct"),
            "disk_pct":     _avg("disk_pct"),
            "active_rooms": round(rooms_avg) if rooms_avg is not None else None,
        })
    return result


async def _metrics_collector_task(db_path: Path) -> None:
    """Sample CPU / RAM / Disk every 10 s and persist for up to 12 months."""
    _SAMPLE_INTERVAL = 10
    _PRUNE_EVERY     = 3600
    _RETENTION       = 365 * 24 * 3600  # 12 months

    last_prune = 0.0
    while True:
        try:
            await asyncio.sleep(_SAMPLE_INTERVAL)
            now = time.time()
            m = _get_sys_metrics()
            await asyncio.to_thread(
                _store_metrics_sample_sync,
                db_path,
                now,
                m.get("sys_cpu_percent"),
                m.get("sys_ram_percent"),
                m.get("sys_disk_percent"),
                len(rooms),
            )
            if now - last_prune >= _PRUNE_EVERY:
                await asyncio.to_thread(_prune_metrics_sync, db_path, now - _RETENTION)
                last_prune = now
        except asyncio.CancelledError:
            raise
        except Exception:  # pragma: no cover  # noqa: BLE001
            pass


async def _admin_metrics_history_handler(request: web.Request) -> web.Response:
    """GET /{admin}/api/metrics-history?range=<seconds> — historical resource metrics."""
    if not _valid_admin_session(request):
        raise web.HTTPUnauthorized()
    try:
        range_secs = int(request.rel_url.query.get("range", "3600"))
    except (ValueError, TypeError):
        range_secs = 3600
    range_secs = max(5, min(range_secs, 365 * 24 * 3600))
    now = time.time()
    rows = await asyncio.to_thread(
        _query_metrics_sync,
        request.app["db_path"],
        now - range_secs,
        now,
        300,
    )
    resp = web.json_response(rows)
    _add_admin_security_headers(resp)
    return resp


def _register_admin_routes(app: web.Application) -> None:
    """Add admin-panel routes to *app* under the secret path prefix."""
    p = _ADMIN_PATH
    app.router.add_get(f"/{p}/", _admin_index_handler)
    app.router.add_get(f"/{p}", _admin_index_handler)
    app.router.add_post(f"/{p}/login", _admin_login_handler)
    app.router.add_get(f"/{p}/api/stats", _admin_stats_handler)
    app.router.add_get(f"/{p}/api/webhook-info", _admin_webhook_info_handler)
    app.router.add_get(f"/{p}/api/logs", _admin_logs_sse_handler)
    app.router.add_post(f"/{p}/api/shutdown", _admin_shutdown_handler)
    app.router.add_post(f"/{p}/webhook/{{token}}", _admin_incoming_webhook_handler)
    app.router.add_post(f"/{p}/api/lockdown", _admin_lockdown_handler)
    app.router.add_get(f"/{p}/api/lockdown", _admin_lockdown_status_handler)
    app.router.add_get(f"/{p}/api/ddos-stats", _admin_ddos_stats_handler)
    app.router.add_post(f"/{p}/api/ddos-unban", _admin_ddos_unban_handler)
    app.router.add_post(f"/{p}/api/slow-mode", _admin_slow_mode_handler)
    app.router.add_get(f"/{p}/api/metrics-history", _admin_metrics_history_handler)


# ---------------------------------------------------------------------------
# Lockdown — wipe-all and block-all feature
# ---------------------------------------------------------------------------

async def _admin_lockdown_handler(request: web.Request) -> web.Response:
    """POST /{admin}/api/lockdown — toggle lockdown on/off.

    Body: ``{"action": "activate"}`` or ``{"action": "deactivate"}``
    Requires an active admin session cookie.
    Returns ``{"lockdown": true|false}``
    """
    global _lockdown_active  # noqa: PLW0603
    if not _valid_admin_session(request):
        raise web.HTTPForbidden(reason="Not authenticated")

    try:
        body = await request.json()
    except Exception:
        body = {}
    action = str(body.get("action", "")).strip().lower()

    if action == "activate":
        _lockdown_active = True
        db_path: Path = request.app["db_path"]

        # 1. Wipe all DB messages
        await asyncio.to_thread(_wipe_all_data_sync, db_path)

        # 2. Delete all share-slot temp files on disk before clearing the registry
        for slot in list(_share_slots.values()):
            tmp_dir: Path | None = slot.get("tmp_dir")
            if tmp_dir is not None:
                try:
                    shutil.rmtree(tmp_dir, ignore_errors=True)
                except Exception:  # noqa: BLE001
                    pass

        # 3. Wipe in-memory data stores
        _inbox_slots.clear()
        _inbox_logged_tokens.clear()
        _share_slots.clear()
        _room_meta.clear()
        # Also clear login failure tracking so the admin can log back in after lockdown
        _ADMIN_LOGIN_FAILURES.clear()
        _ADMIN_LOGIN_HARD_LOCKOUT.clear()

        # 4. Close all open WebSocket connections
        for ws_set in list(rooms.values()):
            for ws in list(ws_set):
                try:
                    await ws.close(message=b"lockdown")
                except Exception:  # noqa: BLE001
                    pass
        rooms.clear()

        logger.warning("🔴 LOCKDOWN ACTIVATED — all data wiped, all connections closed")
        # Print unmistakable lockdown banner to the operator's console.
        _print_lockdown_console_banner()
    elif action == "deactivate":
        _lockdown_active = False
        logger.info("🟢 LOCKDOWN DEACTIVATED")
    else:
        raise web.HTTPBadRequest(reason="action must be 'activate' or 'deactivate'")

    return web.json_response({"lockdown": _lockdown_active})


async def _admin_lockdown_status_handler(request: web.Request) -> web.Response:
    """GET /{admin}/api/lockdown — return current lockdown state (requires auth)."""
    if not _valid_admin_session(request):
        raise web.HTTPForbidden(reason="Not authenticated")
    return web.json_response({"lockdown": _lockdown_active})


@web.middleware
async def _lockdown_middleware(request: web.Request, handler):
    """Block all non-admin requests while lockdown is active."""
    if not _lockdown_active:
        return await handler(request)

    path = request.path.rstrip("/")
    # Allow admin panel routes through (they have the secret path prefix)
    admin_prefix = f"/{_ADMIN_PATH}"
    if path.startswith(admin_prefix) or path == admin_prefix:
        return await handler(request)
    # Also keep static assets reachable so the lockdown page renders correctly
    if path.startswith("/static"):
        return await handler(request)

    # Serve the lockdown page to everything else
    lockdown_html_path = STATIC_DIR.parent / "static" / "lockdown.html"
    if lockdown_html_path.is_file():
        html = lockdown_html_path.read_text(encoding="utf-8")
    else:
        html = "<html><body><h1>🔴 LOCKDOWN ACTIVE</h1><p>This server is in lockdown.</p></body></html>"
    return web.Response(text=html, content_type="text/html", status=503)


# ---------------------------------------------------------------------------
# Legacy build_admin_app() — kept so existing test fixtures still work.
# It now creates a standalone app with hardcoded /admin/* paths for tests;
# the real server mounts admin under _ADMIN_PATH via _register_admin_routes().
# ---------------------------------------------------------------------------

def build_admin_app() -> web.Application:
    """Build a standalone admin Application using fixed /admin/* paths (used by tests)."""
    global _ADMIN_PASSCODE, _ADMIN_PATH, _ADMIN_WEBHOOK_TOKEN  # noqa: PLW0603
    if not _ADMIN_PASSCODE:
        _ADMIN_PATH, _ADMIN_PASSCODE = _init_admin_credentials()
    _ADMIN_WEBHOOK_TOKEN = secrets.token_urlsafe(32)
    print(f"  Admin webhook  : /{_ADMIN_PATH}/webhook/{_ADMIN_WEBHOOK_TOKEN}", flush=True)

    app = web.Application()

    async def on_startup(app: web.Application) -> None:  # noqa: ARG001
        global _admin_event_loop  # noqa: PLW0603
        _admin_event_loop = asyncio.get_running_loop()
        handler = _SseLogHandler()
        handler.setFormatter(logging.Formatter(
            fmt="%(asctime)s  %(levelname)-8s  %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%SZ",
        ))
        logging.root.addHandler(handler)
        logger.info("admin panel ready  (credentials printed to console at startup)")

    app.on_startup.append(on_startup)
    # Register admin routes under the generated path
    _register_admin_routes(app)
    # Also register under fixed /admin/* paths so existing tests work unchanged
    app.router.add_get("/admin/", _admin_index_handler)
    app.router.add_get("/admin", _admin_index_handler)
    app.router.add_post("/admin/login", _admin_login_handler)
    app.router.add_get("/admin/api/stats", _admin_stats_handler)
    app.router.add_get("/admin/api/webhook-info", _admin_webhook_info_handler)
    app.router.add_get("/admin/api/logs", _admin_logs_sse_handler)
    app.router.add_post("/admin/api/shutdown", _admin_shutdown_handler)
    app.router.add_post("/admin/webhook/{token}", _admin_incoming_webhook_handler)
    app.router.add_post("/admin/api/lockdown", _admin_lockdown_handler)
    app.router.add_get("/admin/api/lockdown", _admin_lockdown_status_handler)
    app.router.add_get("/admin/api/ddos-stats", _admin_ddos_stats_handler)
    app.router.add_post("/admin/api/ddos-unban", _admin_ddos_unban_handler)
    app.router.add_post("/admin/api/slow-mode", _admin_slow_mode_handler)
    app.router.add_get("/admin/api/metrics-history", _admin_metrics_history_handler)
    return app


# ---------------------------------------------------------------------------
# Mesh peer federation
# ---------------------------------------------------------------------------
# Each server has a MESH_TOKEN that acts as an invite secret.
# Another server uses POST /mesh/peer/connect to register as a peer.
# Once connected, room messages are forwarded between peers so users on
# different instances can communicate in the same room.
#
# Invite URL:  http://<onion-or-host>/mesh/peer/connect
# Invite token printed at startup by run.py.
# ---------------------------------------------------------------------------

_MESH_TOKEN: str = ""        # Set at startup; printed to console / shown by run.py
_mesh_peers: dict[str, dict] = {}   # peer_id → {url, token, connected_at}


async def mesh_peer_connect_handler(request: web.Request) -> web.Response:
    """POST /mesh/peer/connect — register a remote peer.

    Body::

        {
            "token":    "<MESH_TOKEN of the target server>",
            "peer_url": "http://<other-server>/",
            "peer_token": "<MESH_TOKEN of the connecting server>"
        }

    Returns ``{"ok": true, "peer_id": "…"}`` on success.
    """
    try:
        body = await request.json()
    except Exception:
        raise web.HTTPBadRequest(reason="JSON body required")

    import hmac as _hmac  # noqa: PLC0415
    provided = str(body.get("token", "")).encode()
    expected = _MESH_TOKEN.encode()
    if not expected or not _hmac.compare_digest(provided, expected):
        raise web.HTTPForbidden(reason="Invalid mesh token")

    peer_url = str(body.get("peer_url", "")).strip().rstrip("/")
    peer_token = str(body.get("peer_token", "")).strip()
    if not peer_url:
        raise web.HTTPBadRequest(reason="peer_url required")

    peer_id = secrets.token_hex(16)
    _mesh_peers[peer_id] = {
        "url":          peer_url,
        "token":        peer_token,
        "connected_at": time.time(),
    }
    logger.info("mesh peer connected  peer_id=…%s  url=%s", peer_id[-6:], peer_url[:60])
    return web.json_response({"ok": True, "peer_id": peer_id})


async def mesh_peer_forward_handler(request: web.Request) -> web.Response:
    """POST /mesh/peer/forward — receive a forwarded room message from a peer.

    Body::

        {
            "token":   "<sender's MESH_TOKEN>",
            "room_id": "…",
            "payload": "<JSON string of the message>"
        }

    Security controls
    -----------------
    * The sender token must match a registered peer — prevents unauthenticated writes.
    * room_id is validated against ``MAX_MESH_ROOM_ID_LEN`` — prevents oversized keys.
    * payload is capped at ``MAX_MESH_PAYLOAD_LEN`` bytes — prevents memory exhaustion.
    * The payload is passed to ``_broadcast_to_room`` with ``_from_peer=True`` which
      prevents re-forwarding back to peers (no broadcast loops).
    * The content type of the request body must be ``application/json`` to prevent
      accidental command injection via other content types.
    """
    if not request.content_type.startswith("application/json"):
        raise web.HTTPUnsupportedMediaType(reason="Content-Type must be application/json")

    try:
        body = await request.json()
    except Exception:
        raise web.HTTPBadRequest(reason="JSON body required")

    if not isinstance(body, dict):
        raise web.HTTPBadRequest(reason="JSON object required")

    # Verify the sender is a registered peer (their token must match one we know)
    provided_token = str(body.get("token", ""))
    is_known_peer = any(
        p["token"] == provided_token and provided_token
        for p in _mesh_peers.values()
    )
    if not is_known_peer:
        raise web.HTTPForbidden(reason="Unknown peer token")

    room_id = str(body.get("room_id", "")).strip()
    payload = str(body.get("payload", "")).strip()

    # Enforce size limits to prevent amplification / memory exhaustion
    if not room_id or len(room_id) > MAX_MESH_ROOM_ID_LEN:
        raise web.HTTPBadRequest(reason="Invalid room_id")
    if not payload or len(payload) > MAX_MESH_PAYLOAD_LEN:
        raise web.HTTPBadRequest(reason="payload missing or too large")

    # Validate that room_id only contains safe characters (alphanumeric + limited punctuation)
    # This prevents path traversal and injection via the room identifier.
    import re as _re  # noqa: PLC0415
    if not _re.fullmatch(r"[A-Za-z0-9_\-]{1,64}", room_id):
        raise web.HTTPBadRequest(reason="Invalid room_id format")

    await _broadcast_to_room(room_id, payload, _from_peer=True)
    return web.json_response({"ok": True})


async def mesh_invite_handler(request: web.Request) -> web.Response:
    """GET /mesh/invite — return the mesh invite info (admin-authenticated)."""
    if not _valid_admin_session(request):
        raise web.HTTPForbidden(reason="Not authenticated")
    host = request.host or "localhost"
    scheme = "http"
    if request.secure:
        scheme = "https"
    connect_url = f"{scheme}://{host}/mesh/peer/connect"
    return web.json_response({
        "connect_url":  connect_url,
        "mesh_token":   _MESH_TOKEN,
        "peers":        [
            {"peer_id": pid[-6:], "url": p["url"], "connected_at": p["connected_at"]}
            for pid, p in _mesh_peers.items()
        ],
    })


async def _forward_to_peers(room_id: str, payload: str) -> None:
    """Fire-and-forget: POST a message to every connected mesh peer.

    Peer URLs may be .onion addresses — the proxied session routes them
    through Tor automatically.
    """
    if not _mesh_peers:
        return
    for peer in list(_mesh_peers.values()):
        peer_url = peer["url"].rstrip("/") + "/mesh/peer/forward"
        try:
            async with await _make_proxied_session(timeout=5.0) as sess:
                await sess.post(
                    peer_url,
                    json={"token": _MESH_TOKEN, "room_id": room_id, "payload": payload},
                )
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def build_app(db_path: Path | None = None) -> web.Application:
    global _ADMIN_PASSCODE, _ADMIN_PATH, _ADMIN_WEBHOOK_TOKEN, _MESH_TOKEN, _CLEARNET_PATH  # noqa: PLW0603
    if not _ADMIN_PASSCODE:
        _ADMIN_PATH, _ADMIN_PASSCODE = _init_admin_credentials()
    if not _ADMIN_WEBHOOK_TOKEN:
        _ADMIN_WEBHOOK_TOKEN = secrets.token_urlsafe(32)
    if not _MESH_TOKEN:
        _MESH_TOKEN = secrets.token_urlsafe(32)
    if not _CLEARNET_PATH:
        _CLEARNET_PATH = _init_clearnet_path()

    resolved_db = db_path if db_path is not None else DB_PATH

    # Allow up to MAX_UPLOAD_BYTES for multipart uploads
    app = web.Application(
        client_max_size=MAX_UPLOAD_BYTES,
        middlewares=[_ddos_middleware, _slow_mode_middleware, _lockdown_middleware],
    )
    app["db_path"] = resolved_db

    async def on_startup(app: web.Application) -> None:
        global _admin_event_loop, _smtp_controller  # noqa: PLW0603
        _admin_event_loop = asyncio.get_running_loop()
        # Attach SSE log handler so live-log stream works
        handler = _SseLogHandler()
        handler.setFormatter(logging.Formatter(
            fmt="%(asctime)s  %(levelname)-8s  %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%SZ",
        ))
        logging.root.addHandler(handler)

        await init_db(app["db_path"])
        logger.info("database ready  path=%s", app["db_path"])
        app["_cleanup_share_task"] = asyncio.create_task(_cleanup_expired_share_slots())
        app["_cleanup_inbox_task"] = asyncio.create_task(_cleanup_expired_inbox_slots())
        app["_cleanup_rooms_task"] = asyncio.create_task(
            _cleanup_expired_rooms(app["db_path"])
        )
        app["_lockdown_broadcast_task"] = asyncio.create_task(_lockdown_broadcast_task())
        app["_mailtm_poll_task"] = asyncio.create_task(_mailtm_poll_all_inboxes())
        app["_proxy_watchdog_task"] = asyncio.create_task(_proxy_watchdog_task())
        app["_metrics_collector_task"] = asyncio.create_task(
            _metrics_collector_task(app["db_path"])
        )
        logger.info("admin panel ready  (credentials printed to console at startup)")
        # Probe and print the clearnet exit IP through the last SOCKS5 proxy
        asyncio.create_task(_probe_clearnet_exit_ip())

        # Start the inbound SMTP server when a mail domain is configured
        if MAIL_DOMAIN:
            _smtp_controller = _SmtpController(
                InboxSmtpHandler(),
                hostname="0.0.0.0",
                port=SMTP_PORT,
            )
            _smtp_controller.start()
            logger.info(
                "SMTP inbox server listening  domain=%s  port=%d",
                MAIL_DOMAIN,
                SMTP_PORT,
            )
        else:
            logger.info(
                "SMTP inbox disabled (set MAIL_DOMAIN env var to enable real email)"
            )

    async def on_cleanup(app: web.Application) -> None:
        global _smtp_controller  # noqa: PLW0603
        for key in ("_cleanup_share_task", "_cleanup_inbox_task", "_cleanup_rooms_task", "_lockdown_broadcast_task", "_mailtm_poll_task", "_proxy_watchdog_task", "_metrics_collector_task"):
            task = app.get(key)
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        if _smtp_controller is not None:
            _smtp_controller.stop()
            _smtp_controller = None
            logger.info("SMTP inbox server stopped")

    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    app.router.add_get("/ws", ws_handler)
    app.router.add_get("/", index_handler)
    app.router.add_post("/room/create", room_create_handler)
    app.router.add_post("/room/{room_id}/delete", room_delete_handler)
    app.router.add_get("/api/server-info", server_info_handler)
    app.router.add_get("/api/qrcode", qrcode_handler)
    app.router.add_get("/api/slow-mode", _slow_mode_status_handler)
    app.router.add_post("/share/upload", share_upload_handler)
    app.router.add_get("/share/download/{token}", share_download_handler)
    app.router.add_post("/share/download/{token}", share_download_post_handler)
    # One-time inbox routes
    app.router.add_post("/inbox/create", inbox_create_handler)
    app.router.add_post("/inbox/relay", inbox_relay_handler)
    app.router.add_get("/inbox/{token}", inbox_read_page_handler)
    app.router.add_get("/inbox/{token}/drop", inbox_drop_page_handler)
    app.router.add_post("/inbox/{token}/drop", inbox_drop_handler)
    app.router.add_get("/inbox/{token}/read", inbox_read_handler)
    # Block admin.html from the public static file handler — it must only be
    # served via _admin_index_handler which injects the secret path.
    app.router.add_get("/static/admin.html", _blocked_static_handler)
    app.router.add_static("/static", STATIC_DIR, show_index=False)

    # Mesh peer federation routes
    app.router.add_post("/mesh/peer/connect", mesh_peer_connect_handler)
    app.router.add_post("/mesh/peer/forward", mesh_peer_forward_handler)
    app.router.add_get("/mesh/invite", mesh_invite_handler)

    # Mount admin panel under the secret 200-char path on the same server
    _register_admin_routes(app)

    # Mount clearnet access under the secret 100-char path.
    # This serves the standard chat interface — the path itself provides
    # security-through-obscurity for clearnet deployments.
    cp = _CLEARNET_PATH
    if cp:
        app.router.add_get(f"/{cp}/", index_handler)
        app.router.add_get(f"/{cp}", index_handler)

    return app


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))

    # Initialise admin credentials in the current module's global namespace so
    # that build_app() sees them as already set and does NOT re-initialise.
    # Using `import server as _self` would create a second module copy with
    # fresh (empty) globals, causing credentials to be printed twice.
    _ADMIN_PATH, _ADMIN_PASSCODE = _init_admin_credentials()
    _ADMIN_WEBHOOK_TOKEN = secrets.token_urlsafe(32)
    print(f"  Admin webhook  : /{_ADMIN_PATH}/webhook/{_ADMIN_WEBHOOK_TOKEN}", flush=True)
    _CLEARNET_PATH = _init_clearnet_path()

    logger.info("secureChat starting  host=%s  port=%d", host, port)
    logger.info(
        "Expose via a Tor hidden service for anonymous access — "
        "run  python run.py  for automatic zero-config setup."
    )

    app = build_app()

    async def _run() -> None:
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        site = web.TCPSite(runner, host, port)
        await site.start()
        logger.info("server started  host=%s  port=%d", host, port)
        try:
            await asyncio.Event().wait()          # run forever
        finally:
            await runner.cleanup()

    asyncio.run(_run())
