"""
Tests for secureChat server.

Covers:
- Room ID validation regex
- broadcast helpers (mocked WebSocket stubs)
- WebSocket handler join / message / leave lifecycle (via aiohttp test client)
"""

from __future__ import annotations

import json
import re
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import server as srv
from server import (
    _ROOM_RE,
    _broadcast_system,
    _broadcast_to_room,
    build_app,
    rooms,
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


# ─── WebSocket handler (integration) ────────────────────────────────────────

@pytest.fixture
def app():
    return build_app()


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
