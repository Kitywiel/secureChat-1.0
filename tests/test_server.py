"""
Tests for secureChat server.

Covers:
- Room ID validation regex
- broadcast helpers (mocked WebSocket stubs)
- SQLite persistence helpers (_init_db_sync, _save_message_sync, _get_history_sync)
- WebSocket handler join / message / leave lifecycle (via aiohttp test client)
- History replay: messages persisted before a new client joins are sent back
"""

from __future__ import annotations

import json
import re
import pytest
import pytest_asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import server as srv
from server import (
    _ROOM_RE,
    _broadcast_system,
    _broadcast_to_room,
    _get_history_sync,
    _init_db_sync,
    _save_message_sync,
    build_app,
    get_history,
    rooms,
    save_message,
    HISTORY_LIMIT,
)


# ─── Room ID validation ──────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "room_id,expected",
    [
        ("valid-room", True),
        ("ValidRoom123", True),
        ("with_underscore", True),
        ("a" * 64, True),           # max length
        ("a" * 65, False),          # too long
        ("", False),                # empty
        ("has space", False),
        ("has!bang", False),
        ("has/slash", False),
        ("../path-traversal", False),
    ],
)
def test_room_id_regex(room_id: str, expected: bool) -> None:
    assert bool(_ROOM_RE.match(room_id)) is expected


# ─── Broadcast helpers ───────────────────────────────────────────────────────

def _make_ws(closed: bool = False) -> MagicMock:
    """Return a minimal WebSocket stub."""
    ws = MagicMock()
    ws.closed = closed
    ws.send_str = AsyncMock()
    return ws


@pytest.mark.asyncio
async def test_broadcast_to_room_sends_to_all_open_peers() -> None:
    rooms.clear()
    ws_a = _make_ws()
    ws_b = _make_ws()
    rooms["testroom"] = {ws_a, ws_b}

    await _broadcast_to_room("testroom", "hello")

    ws_a.send_str.assert_awaited_once_with("hello")
    ws_b.send_str.assert_awaited_once_with("hello")
    rooms.clear()


@pytest.mark.asyncio
async def test_broadcast_to_room_excludes_sender() -> None:
    rooms.clear()
    ws_a = _make_ws()
    ws_b = _make_ws()
    rooms["testroom"] = {ws_a, ws_b}

    await _broadcast_to_room("testroom", "msg", exclude=ws_a)

    ws_a.send_str.assert_not_awaited()
    ws_b.send_str.assert_awaited_once_with("msg")
    rooms.clear()


@pytest.mark.asyncio
async def test_broadcast_to_room_skips_closed_peers() -> None:
    rooms.clear()
    ws_open = _make_ws(closed=False)
    ws_closed = _make_ws(closed=True)
    rooms["testroom"] = {ws_open, ws_closed}

    await _broadcast_to_room("testroom", "msg")

    ws_open.send_str.assert_awaited_once_with("msg")
    ws_closed.send_str.assert_not_awaited()
    rooms.clear()


@pytest.mark.asyncio
async def test_broadcast_system_includes_user_count() -> None:
    rooms.clear()
    ws_a = _make_ws()
    ws_b = _make_ws()
    rooms["myroom"] = {ws_a, ws_b}

    await _broadcast_system("myroom")

    for ws in (ws_a, ws_b):
        call_args = ws.send_str.await_args
        data = json.loads(call_args[0][0])
        assert data["type"] == "system"
        assert data["users"] == 2

    rooms.clear()


# ─── DB unit tests ───────────────────────────────────────────────────────────

@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    """Return a path to a freshly initialised test database."""
    db = tmp_path / "test.db"
    _init_db_sync(db)
    return db


def test_db_init_creates_table(tmp_db: Path) -> None:
    import sqlite3
    con = sqlite3.connect(tmp_db)
    rows = con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='messages'"
    ).fetchall()
    con.close()
    assert len(rows) == 1


def test_save_and_retrieve_message(tmp_db: Path) -> None:
    _save_message_sync(tmp_db, "room1", "Alice", "iv==", "cipher==", limit=100)
    msgs = _get_history_sync(tmp_db, "room1", limit=100)
    assert len(msgs) == 1
    assert msgs[0]["sender"] == "Alice"
    assert msgs[0]["iv"] == "iv=="
    assert msgs[0]["ciphertext"] == "cipher=="
    assert msgs[0]["ts"] > 0


def test_history_is_chronological(tmp_db: Path) -> None:
    """Messages should be returned oldest-first (chronological order)."""
    for i in range(5):
        _save_message_sync(tmp_db, "room2", f"user{i}", f"iv{i}", f"ct{i}", limit=100)
    msgs = _get_history_sync(tmp_db, "room2", limit=100)
    assert len(msgs) == 5
    # Timestamps should be non-decreasing
    for a, b in zip(msgs, msgs[1:]):
        assert a["ts"] <= b["ts"]


def test_history_limit_prunes_old_messages(tmp_db: Path) -> None:
    """After inserting more messages than the limit, only the latest remain."""
    limit = 5
    for i in range(10):
        _save_message_sync(tmp_db, "roomL", "bot", f"iv{i}", f"ct{i}", limit=limit)
    msgs = _get_history_sync(tmp_db, "roomL", limit=limit)
    assert len(msgs) == limit
    # The oldest stored message should be from the 6th insert (index 5)
    assert msgs[0]["iv"] == "iv5"
    assert msgs[-1]["iv"] == "iv9"


def test_history_empty_room(tmp_db: Path) -> None:
    msgs = _get_history_sync(tmp_db, "nonexistent-room", limit=100)
    assert msgs == []


def test_history_isolated_per_room(tmp_db: Path) -> None:
    _save_message_sync(tmp_db, "roomA", "Alice", "ivA", "ctA", limit=100)
    _save_message_sync(tmp_db, "roomB", "Bob", "ivB", "ctB", limit=100)
    assert len(_get_history_sync(tmp_db, "roomA", limit=100)) == 1
    assert _get_history_sync(tmp_db, "roomA", limit=100)[0]["sender"] == "Alice"
    assert len(_get_history_sync(tmp_db, "roomB", limit=100)) == 1
    assert _get_history_sync(tmp_db, "roomB", limit=100)[0]["sender"] == "Bob"


@pytest.mark.asyncio
async def test_async_save_and_get_history(tmp_db: Path) -> None:
    await save_message(tmp_db, "room3", "Bob", "iv==", "ct==")
    msgs = await get_history(tmp_db, "room3")
    assert len(msgs) == 1
    assert msgs[0]["sender"] == "Bob"


# ─── WebSocket handler (integration) ────────────────────────────────────────

@pytest.fixture
def app(tmp_path: Path):
    return build_app(db_path=tmp_path / "test.db")


@pytest_asyncio.fixture
async def ws_client(app, aiohttp_client):
    client = await aiohttp_client(app)
    return client


@pytest.mark.asyncio
async def test_ws_join_broadcasts_user_count(ws_client) -> None:
    """After joining a room the client should receive a system message."""
    async with ws_client.ws_connect("/ws") as ws:
        await ws.send_str(json.dumps({"type": "join", "room": "roomA"}))
        msg = await ws.receive_json(timeout=2)
        assert msg["type"] == "system"
        assert msg["users"] == 1


@pytest.mark.asyncio
async def test_ws_invalid_room_id_receives_error(ws_client) -> None:
    """Joining with an invalid room ID should return an error message."""
    async with ws_client.ws_connect("/ws") as ws:
        await ws.send_str(json.dumps({"type": "join", "room": "bad room!"}))
        msg = await ws.receive_json(timeout=2)
        assert msg["type"] == "error"
        assert msg["reason"] == "invalid_room_id"


@pytest.mark.asyncio
async def test_ws_message_relayed_to_other_peer(ws_client) -> None:
    """A message from one peer should be relayed to another in the same room."""
    async with ws_client.ws_connect("/ws") as ws1:
        await ws1.send_str(json.dumps({"type": "join", "room": "roomB"}))
        await ws1.receive_json(timeout=2)  # system: 1 user

        async with ws_client.ws_connect("/ws") as ws2:
            await ws2.send_str(json.dumps({"type": "join", "room": "roomB"}))

            # Both peers get the "2 users" system broadcast
            msg1 = await ws1.receive_json(timeout=2)
            msg2 = await ws2.receive_json(timeout=2)
            assert msg1["type"] == "system"
            assert msg2["type"] == "system"
            assert msg1["users"] == 2

            # ws2 sends an encrypted message
            payload = {
                "type": "message",
                "iv": "aGVsbG93b3JsZA==",
                "ciphertext": "c2VjcmV0",
                "sender": "Bob",
            }
            await ws2.send_str(json.dumps(payload))

            # ws1 (the other peer) should receive it
            relayed = await ws1.receive_json(timeout=2)
            assert relayed["type"] == "message"
            assert relayed["iv"] == payload["iv"]
            assert relayed["ciphertext"] == payload["ciphertext"]
            assert relayed["sender"] == "Bob"


@pytest.mark.asyncio
async def test_ws_message_not_echoed_to_sender(ws_client) -> None:
    """The server must NOT echo a message back to the sender."""
    async with ws_client.ws_connect("/ws") as ws1:
        await ws1.send_str(json.dumps({"type": "join", "room": "roomC"}))
        await ws1.receive_json(timeout=2)  # system

        payload = {
            "type": "message",
            "iv": "aGVsbG93b3JsZA==",
            "ciphertext": "c2VjcmV0",
            "sender": "Alice",
        }
        await ws1.send_str(json.dumps(payload))

        # No other peers → ws1 should receive nothing (timeout expected)
        import asyncio
        try:
            await asyncio.wait_for(ws1.receive_json(), timeout=0.4)
            pytest.fail("Sender should not receive its own relayed message")
        except asyncio.TimeoutError:
            pass  # expected


@pytest.mark.asyncio
async def test_ws_user_count_decrements_on_leave(ws_client) -> None:
    """User count broadcast should reflect peers leaving."""
    async with ws_client.ws_connect("/ws") as ws1:
        await ws1.send_str(json.dumps({"type": "join", "room": "roomD"}))
        await ws1.receive_json(timeout=2)

        async with ws_client.ws_connect("/ws") as ws2:
            await ws2.send_str(json.dumps({"type": "join", "room": "roomD"}))
            await ws1.receive_json(timeout=2)  # 2-user broadcast to ws1
            await ws2.receive_json(timeout=2)  # 2-user broadcast to ws2

        # ws2 closes; ws1 should get a system message with users=1
        msg = await ws1.receive_json(timeout=2)
        assert msg["type"] == "system"
        assert msg["users"] == 1


@pytest.mark.asyncio
async def test_ws_history_replayed_on_join(ws_client) -> None:
    """A client joining a room with stored messages receives a history batch."""
    # First client sends a message
    async with ws_client.ws_connect("/ws") as ws1:
        await ws1.send_str(json.dumps({"type": "join", "room": "roomE"}))
        await ws1.receive_json(timeout=2)  # system

        await ws1.send_str(json.dumps({
            "type": "message",
            "iv": "aGVsbG93b3JsZA==",
            "ciphertext": "c2VjcmV0",
            "sender": "Alice",
        }))

    # Second client joins the same room and should receive history
    async with ws_client.ws_connect("/ws") as ws2:
        await ws2.send_str(json.dumps({"type": "join", "room": "roomE"}))

        # May receive history before or after system depending on timing;
        # collect the next two messages
        messages = []
        import asyncio
        for _ in range(2):
            try:
                m = await asyncio.wait_for(ws2.receive_json(), timeout=2)
                messages.append(m)
            except asyncio.TimeoutError:
                break

        types = {m["type"] for m in messages}
        assert "history" in types, f"Expected history in {messages}"
        history_msg = next(m for m in messages if m["type"] == "history")
        assert len(history_msg["messages"]) == 1
        assert history_msg["messages"][0]["iv"] == "aGVsbG93b3JsZA=="
        assert history_msg["messages"][0]["ciphertext"] == "c2VjcmV0"
        assert history_msg["messages"][0]["sender"] == "Alice"


@pytest.mark.asyncio
async def test_ws_no_history_for_empty_room(ws_client) -> None:
    """Joining a room with no history should not send a history message."""
    async with ws_client.ws_connect("/ws") as ws:
        await ws.send_str(json.dumps({"type": "join", "room": "brand-new-room"}))

        import asyncio
        # Only the system message should arrive; no history message
        msg = await asyncio.wait_for(ws.receive_json(), timeout=2)
        assert msg["type"] == "system"

        try:
            extra = await asyncio.wait_for(ws.receive_json(), timeout=0.4)
            assert extra["type"] != "history", "Unexpected history message for empty room"
        except asyncio.TimeoutError:
            pass  # expected — no extra messages
