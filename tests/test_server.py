"""
Tests for secureChat server.

Covers:
- Room ID validation regex
- broadcast helpers (mocked WebSocket stubs)
- SQLite persistence helpers (_init_db_sync, _save_message_sync, _get_history_sync)
- WebSocket handler join / message / leave lifecycle (via aiohttp test client)
- History replay: messages persisted before a new client joins are sent back
- File-share endpoints: upload, one-time download, expiry, cleanup
- Room creation, passcode enforcement, self-destruct timer, history deletion
"""

from __future__ import annotations

import json
import re
import time
import pytest
import pytest_asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import aiohttp
import server as srv
from server import (
    _ROOM_RE,
    _broadcast_system,
    _broadcast_to_room,
    _delete_room_history_sync,
    _get_history_sync,
    _hash_passcode,
    _init_db_sync,
    _room_meta,
    _sanitize_filename,
    _save_message_sync,
    _share_slots,
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


# ─── File-share helpers ───────────────────────────────────────────────────────

_EXPIRY_TOLERANCE_S = 5   # seconds of slack for expiry timestamp assertions


@pytest.fixture(autouse=True)
def clear_share_slots():
    """Clear share slots before and after each test."""
    import shutil
    _share_slots.clear()
    yield
    for slot in list(_share_slots.values()):
        shutil.rmtree(slot["tmp_dir"], ignore_errors=True)
    _share_slots.clear()


@pytest.mark.parametrize(
    "name,expected",
    [
        ("report.pdf", "report.pdf"),
        ("../../../etc/passwd", "passwd"),
        ("C:\\Windows\\System32\\evil.exe", "evil.exe"),
        ("hello world.txt", "hello world.txt"),
        ("file<>|.txt", "file___.txt"),
        ("", "file"),
        (".....", "file"),
    ],
)
def test_sanitize_filename(name: str, expected: str) -> None:
    assert _sanitize_filename(name) == expected


# ─── File-share integration tests ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_share_upload_returns_download_url(ws_client) -> None:
    data = aiohttp.FormData()
    data.add_field("file", b"hello file content", filename="test.txt",
                   content_type="text/plain")
    resp = await ws_client.post("/share/upload?ttl=1", data=data)
    assert resp.status == 200
    body = await resp.json()
    assert "download_url" in body
    assert body["download_url"].startswith("/share/download/")
    assert body["filename"] == "test.txt"
    assert body["size"] == len(b"hello file content")
    assert body["expires_at"] > time.time()


@pytest.mark.asyncio
async def test_share_download_delivers_file(ws_client) -> None:
    content = b"secret data"
    data = aiohttp.FormData()
    data.add_field("file", content, filename="secret.bin",
                   content_type="application/octet-stream")
    upload_resp = await ws_client.post("/share/upload?ttl=2", data=data)
    assert upload_resp.status == 200
    body = await upload_resp.json()

    download_resp = await ws_client.get(body["download_url"])
    assert download_resp.status == 200
    downloaded = await download_resp.read()
    assert downloaded == content


@pytest.mark.asyncio
async def test_share_download_is_one_time(ws_client) -> None:
    """After the first download the slot is gone; a second attempt returns 404."""
    data = aiohttp.FormData()
    data.add_field("file", b"once", filename="once.txt", content_type="text/plain")
    upload_resp = await ws_client.post("/share/upload?ttl=1", data=data)
    body = await upload_resp.json()
    url = body["download_url"]

    resp1 = await ws_client.get(url)
    assert resp1.status == 200
    await resp1.read()  # consume body

    resp2 = await ws_client.get(url)
    assert resp2.status == 404


@pytest.mark.asyncio
async def test_share_download_expired_returns_410(ws_client) -> None:
    """Expired slots return HTTP 410 Gone."""
    data = aiohttp.FormData()
    data.add_field("file", b"exp", filename="expired.txt", content_type="text/plain")
    upload_resp = await ws_client.post("/share/upload?ttl=1", data=data)
    body = await upload_resp.json()
    url = body["download_url"]

    # Manually expire the slot
    token = url.rsplit("/", 1)[-1]
    _share_slots[token]["expires_at"] = time.time() - 1

    resp = await ws_client.get(url)
    assert resp.status == 410


@pytest.mark.asyncio
async def test_share_download_invalid_token(ws_client) -> None:
    resp = await ws_client.get("/share/download/no-such-token")
    assert resp.status == 404


@pytest.mark.asyncio
async def test_share_upload_no_file_returns_400(ws_client) -> None:
    data = aiohttp.FormData()
    data.add_field("other", "value")
    resp = await ws_client.post("/share/upload?ttl=1", data=data)
    assert resp.status == 400


@pytest.mark.asyncio
async def test_share_cleans_up_temp_dir_after_download(ws_client) -> None:
    """The temp directory must not exist after a successful download."""
    data = aiohttp.FormData()
    data.add_field("file", b"cleanup check", filename="cleanup.txt",
                   content_type="text/plain")
    upload_resp = await ws_client.post("/share/upload?ttl=1", data=data)
    body = await upload_resp.json()
    url = body["download_url"]
    token = url.rsplit("/", 1)[-1]
    tmp_dir = _share_slots[token]["tmp_dir"]

    resp = await ws_client.get(url)
    assert resp.status == 200
    await resp.read()

    import asyncio
    await asyncio.sleep(0.05)  # allow the server's finally-block to complete
    assert not tmp_dir.exists()


@pytest.mark.asyncio
async def test_share_ttl_clamped(ws_client) -> None:
    """TTL below 1 is raised to 1; TTL above 24 is clamped to 24."""
    data = aiohttp.FormData()
    data.add_field("file", b"x", filename="x.txt", content_type="text/plain")

    resp_low = await ws_client.post("/share/upload?ttl=0", data=data)
    assert resp_low.status == 200
    body_low = await resp_low.json()
    assert body_low["expires_at"] <= time.time() + 3600 + _EXPIRY_TOLERANCE_S

    data2 = aiohttp.FormData()
    data2.add_field("file", b"x", filename="x.txt", content_type="text/plain")
    resp_high = await ws_client.post("/share/upload?ttl=99", data=data2)
    assert resp_high.status == 200
    body_high = await resp_high.json()
    assert body_high["expires_at"] <= time.time() + 24 * 3600 + _EXPIRY_TOLERANCE_S


# ─── Room-meta helpers ────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def clear_room_meta():
    """Ensure _room_meta is empty before/after each test."""
    _room_meta.clear()
    yield
    _room_meta.clear()


def test_hash_passcode_deterministic() -> None:
    """Same passcode always produces the same hash."""
    assert _hash_passcode("secret") == _hash_passcode("secret")


def test_hash_passcode_different_inputs() -> None:
    """Different passcodes produce different hashes."""
    assert _hash_passcode("aaa") != _hash_passcode("bbb")


def test_delete_room_history(tmp_db: Path) -> None:
    """Messages for a room are removed; other rooms are unaffected."""
    _save_message_sync(tmp_db, "del-room", "Alice", "iv1", "ct1", limit=100)
    _save_message_sync(tmp_db, "keep-room", "Bob", "iv2", "ct2", limit=100)
    _delete_room_history_sync(tmp_db, "del-room")
    assert _get_history_sync(tmp_db, "del-room", limit=100) == []
    assert len(_get_history_sync(tmp_db, "keep-room", limit=100)) == 1


# ─── Room-create endpoint ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_room_create_returns_room_id(ws_client) -> None:
    resp = await ws_client.post(
        "/room/create",
        json={"destruct_minutes": 0},
    )
    assert resp.status == 200
    body = await resp.json()
    assert "room_id" in body
    assert len(body["room_id"]) == 16   # 8 hex bytes
    assert body["expires_at"] is None


@pytest.mark.asyncio
async def test_room_create_with_destruct(ws_client) -> None:
    resp = await ws_client.post(
        "/room/create",
        json={"destruct_minutes": 60},
    )
    assert resp.status == 200
    body = await resp.json()
    assert body["expires_at"] is not None
    assert body["expires_at"] > time.time()
    assert body["expires_at"] <= time.time() + 3600 + _EXPIRY_TOLERANCE_S


@pytest.mark.asyncio
async def test_room_create_registers_in_meta(ws_client) -> None:
    resp = await ws_client.post(
        "/room/create",
        json={"passcode": "abc123", "destruct_minutes": 0},
    )
    body = await resp.json()
    room_id = body["room_id"]
    assert room_id in _room_meta
    assert _room_meta[room_id]["passcode_hash"] == _hash_passcode("abc123")
    assert _room_meta[room_id]["expires_at"] is None


@pytest.mark.asyncio
async def test_room_create_bad_body_returns_400(ws_client) -> None:
    resp = await ws_client.post(
        "/room/create",
        data=b"not json",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status == 400


# ─── Server-info endpoint ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_server_info_no_onion(ws_client, monkeypatch) -> None:
    """When ONION_ADDRESS is unset and no hostname file exists, onion is null."""
    monkeypatch.setattr(srv, "ONION_ADDRESS", None)
    resp = await ws_client.get("/api/server-info")
    assert resp.status == 200
    body = await resp.json()
    assert "onion" in body
    # In the test environment there is no Tor hostname file, so expect null
    assert body["onion"] is None


@pytest.mark.asyncio
async def test_server_info_with_onion(ws_client, monkeypatch) -> None:
    """When ONION_ADDRESS is set, it is returned."""
    monkeypatch.setattr(srv, "ONION_ADDRESS", "test1234567890.onion")
    resp = await ws_client.get("/api/server-info")
    assert resp.status == 200
    body = await resp.json()
    assert body["onion"] == "test1234567890.onion"


# ─── WS join with passcode / expiry ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_ws_join_passcode_correct(ws_client) -> None:
    """A client that provides the correct passcode can join."""
    # Register room with passcode
    _room_meta["passcode-room"] = {
        "passcode_hash": _hash_passcode("1234"),
        "expires_at": None,
    }
    async with ws_client.ws_connect("/ws") as ws:
        await ws.send_str(json.dumps({"type": "join", "room": "passcode-room", "passcode": "1234"}))
        msg = await ws.receive_json(timeout=2)
        assert msg["type"] == "system"
        assert msg["users"] == 1


@pytest.mark.asyncio
async def test_ws_join_passcode_wrong(ws_client) -> None:
    """A client that provides the wrong passcode receives an error."""
    _room_meta["secure-room"] = {
        "passcode_hash": _hash_passcode("correct"),
        "expires_at": None,
    }
    async with ws_client.ws_connect("/ws") as ws:
        await ws.send_str(json.dumps({"type": "join", "room": "secure-room", "passcode": "wrong"}))
        msg = await ws.receive_json(timeout=2)
        assert msg["type"] == "error"
        assert msg["reason"] == "wrong_passcode"


@pytest.mark.asyncio
async def test_ws_join_passcode_missing(ws_client) -> None:
    """A client that omits the passcode also gets an error."""
    _room_meta["locked-room"] = {
        "passcode_hash": _hash_passcode("secret"),
        "expires_at": None,
    }
    async with ws_client.ws_connect("/ws") as ws:
        await ws.send_str(json.dumps({"type": "join", "room": "locked-room"}))
        msg = await ws.receive_json(timeout=2)
        assert msg["type"] == "error"
        assert msg["reason"] == "wrong_passcode"


@pytest.mark.asyncio
async def test_ws_join_expired_room(ws_client) -> None:
    """Joining an already-expired room returns room_expired error."""
    _room_meta["dead-room"] = {
        "passcode_hash": None,
        "expires_at": time.time() - 1,   # already expired
    }
    async with ws_client.ws_connect("/ws") as ws:
        await ws.send_str(json.dumps({"type": "join", "room": "dead-room"}))
        msg = await ws.receive_json(timeout=2)
        assert msg["type"] == "error"
        assert msg["reason"] == "room_expired"


@pytest.mark.asyncio
async def test_ws_join_sends_destruct_info(ws_client) -> None:
    """Joining a room with a future expiry should receive a destruct_info message."""
    expires_at = time.time() + 3600
    _room_meta["timed-room"] = {
        "passcode_hash": None,
        "expires_at": expires_at,
    }
    async with ws_client.ws_connect("/ws") as ws:
        await ws.send_str(json.dumps({"type": "join", "room": "timed-room"}))

        import asyncio
        messages = []
        for _ in range(3):
            try:
                m = await asyncio.wait_for(ws.receive_json(), timeout=2)
                messages.append(m)
            except asyncio.TimeoutError:
                break

        types = {m["type"] for m in messages}
        assert "destruct_info" in types, f"Expected destruct_info in {messages}"
        di = next(m for m in messages if m["type"] == "destruct_info")
        assert abs(di["expires_at"] - expires_at) < 1
        assert di["remaining"] > 0
