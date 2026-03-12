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
from pathlib import Path

import qrcode
import qrcode.constants
from qrcode.image.svg import SvgImage as _QrSvgImage
from aiohttp import web, WSMsgType

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
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
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

# File-share constants
MAX_UPLOAD_BYTES = 100 * 1024 * 1024   # 100 MB per file
MAX_FILENAME_LEN = 200                 # characters in the sanitised filename
_SHARE_TOKEN_BYTES = 32                # 256-bit token → 43-char URL-safe base64

# Room-create / passcode constants
MAX_PASSCODE_LEN = 64                  # characters in a room or share passcode
MAX_DESTRUCT_MINUTES = 1440            # 24 hours maximum

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

    finally:
        # Clean up regardless of how the connection closed
        if room_id and room_id in rooms:
            rooms[room_id].discard(ws)
            if rooms[room_id]:
                await _broadcast_system(room_id)
            else:
                del rooms[room_id]
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
) -> None:
    peers = list(rooms.get(room_id, set()))
    for peer in peers:
        if peer is exclude or peer.closed:
            continue
        try:
            await peer.send_str(payload)
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------------------
# HTTP handlers
# ---------------------------------------------------------------------------


async def index_handler(request: web.Request) -> web.FileResponse:
    return web.FileResponse(STATIC_DIR / "index.html")


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

        # Stream into memory (enforcing limit), then write to disk
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = await file_part.read_chunk(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_UPLOAD_BYTES:
                raise web.HTTPRequestEntityTooLarge()
            chunks.append(chunk)

        await asyncio.to_thread(dest.write_bytes, b"".join(chunks))

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
        _share_slots[token] = {
            "tmp_dir": tmp_dir,
            "filename": filename,
            "size": total,
            "expires_at": expires_at,
            "passcode_hash": _hash_passcode(passcode) if passcode else None,
        }
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

    If the slot requires a passcode an HTML gate page is returned instead of the
    file.  The user then submits the passcode via POST to the same URL.
    """
    token = request.match_info["token"]
    slot = _share_slots.get(token)

    if slot is None:
        raise web.HTTPNotFound(reason="Link not found or already used")

    if time.time() > slot["expires_at"]:
        _share_slots.pop(token, None)
        await asyncio.to_thread(_rmtree, slot["tmp_dir"])
        raise web.HTTPGone(reason="Download link has expired")

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
    """Pop *token* from _share_slots, stream the file, then delete the temp dir."""
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
        file_content = await asyncio.to_thread(filepath.read_bytes)
        response = web.StreamResponse(
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Type": "application/octet-stream",
                "Content-Length": str(size),
            }
        )
        await response.prepare(request)
        await response.write(file_content)
        await response.write_eof()
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

    # Generate a unique room ID (16-char hex)
    for _ in range(20):
        room_id = secrets.token_hex(8)
        if room_id not in _room_meta and room_id not in rooms:
            break

    expires_at = (time.time() + destruct_minutes * 60) if destruct_minutes > 0 else None
    passcode_hash = _hash_passcode(passcode) if passcode else None

    _room_meta[room_id] = {
        "passcode_hash": passcode_hash,
        "expires_at": expires_at,
    }
    logger.info(
        "room created  room=%s  passcode=%s  destruct=%dm",
        room_id,
        bool(passcode),
        destruct_minutes,
    )
    return web.json_response({"room_id": room_id, "expires_at": expires_at})


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
    return web.json_response({"onion": onion})


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
# App factory
# ---------------------------------------------------------------------------


def build_app(db_path: Path | None = None) -> web.Application:
    resolved_db = db_path if db_path is not None else DB_PATH

    app = web.Application()
    app["db_path"] = resolved_db

    async def on_startup(app: web.Application) -> None:
        await init_db(app["db_path"])
        logger.info("database ready  path=%s", app["db_path"])
        app["_cleanup_share_task"] = asyncio.create_task(_cleanup_expired_share_slots())
        app["_cleanup_rooms_task"] = asyncio.create_task(
            _cleanup_expired_rooms(app["db_path"])
        )

    async def on_cleanup(app: web.Application) -> None:
        for key in ("_cleanup_share_task", "_cleanup_rooms_task"):
            task = app.get(key)
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    app.router.add_get("/ws", ws_handler)
    app.router.add_get("/", index_handler)
    app.router.add_post("/room/create", room_create_handler)
    app.router.add_get("/api/server-info", server_info_handler)
    app.router.add_get("/api/qrcode", qrcode_handler)
    app.router.add_post("/share/upload", share_upload_handler)
    app.router.add_get("/share/download/{token}", share_download_handler)
    app.router.add_post("/share/download/{token}", share_download_post_handler)
    app.router.add_static("/static", STATIC_DIR, show_index=False)
    return app


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    logger.info("secureChat starting  host=%s  port=%d", host, port)
    logger.info(
        "Expose via a Tor hidden service for anonymous access — "
        "run start_server.bat for automatic setup (Windows)."
    )
    web.run_app(build_app(), host=host, port=port, access_log=None)
