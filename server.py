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
to expose it as a .onion address.  See README.md for details.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sqlite3
import sys
import time
from pathlib import Path

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
MAX_IV_LEN = 24          # 12 raw bytes → 16 base64 chars; allow generous bound
MAX_CIPHERTEXT_LEN = 8192  # ~6 KiB plaintext after base64 expansion

# Room ID: allow alphanumeric, hyphens, underscores only
_ROOM_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")

# In-memory room registry: room_id → {websocket, ...}
rooms: dict[str, set[web.WebSocketResponse]] = {}

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

                room_id = candidate
                rooms.setdefault(room_id, set()).add(ws)
                logger.info(
                    "peer joined  room=%s  peers=%d",
                    room_id,
                    len(rooms[room_id]),
                )

                # Send stored history to the newly joined peer only
                try:
                    history = await get_history(db_path, room_id)
                    if history:
                        await ws.send_str(
                            json.dumps({"type": "history", "messages": history})
                        )
                except Exception as exc:  # noqa: BLE001
                    logger.warning("failed to load history  room=%s  error=%s", room_id, exc)

                await _broadcast_system(room_id)

            # ── message ───────────────────────────────────────────────────
            elif msg_type == "message" and room_id is not None:
                iv = str(data.get("iv", ""))
                ciphertext = str(data.get("ciphertext", ""))
                sender = str(data.get("sender", ""))[:MAX_DISPLAY_NAME_LEN]

                # Basic sanity checks — reject obviously malformed payloads
                if len(iv) > MAX_IV_LEN or len(ciphertext) > MAX_CIPHERTEXT_LEN:
                    continue

                # Persist before relaying (best-effort; relay still happens on error)
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
# App factory
# ---------------------------------------------------------------------------


def build_app(db_path: Path | None = None) -> web.Application:
    resolved_db = db_path if db_path is not None else DB_PATH

    app = web.Application()
    app["db_path"] = resolved_db

    async def on_startup(app: web.Application) -> None:
        await init_db(app["db_path"])
        logger.info("database ready  path=%s", app["db_path"])

    app.on_startup.append(on_startup)
    app.router.add_get("/ws", ws_handler)
    app.router.add_get("/", index_handler)
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
        "Expose via a Tor hidden service for anonymous access (see README.md)."
    )
    web.run_app(build_app(), host=host, port=port, access_log=None)
