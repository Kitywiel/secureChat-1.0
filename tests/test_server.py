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
    MAX_FILE_CIPHERTEXT_LEN,
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
    """A client joining a passcode-protected room receives stored history."""
    # Pre-register the room with a passcode so history is persisted
    _room_meta["roomE"] = {"passcode_hash": _hash_passcode("pass"), "expires_at": None}

    # First client sends a message
    async with ws_client.ws_connect("/ws") as ws1:
        await ws1.send_str(json.dumps({"type": "join", "room": "roomE", "passcode": "pass"}))
        await ws1.receive_json(timeout=2)  # system

        await ws1.send_str(json.dumps({
            "type": "message",
            "iv": "aGVsbG93b3JsZA==",
            "ciphertext": "c2VjcmV0",
            "sender": "Alice",
        }))

    # Second client joins the same room and should receive history
    async with ws_client.ws_connect("/ws") as ws2:
        await ws2.send_str(json.dumps({"type": "join", "room": "roomE", "passcode": "pass"}))

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
async def test_ws_messages_not_stored_without_passcode(ws_client) -> None:
    """Messages in a room without a passcode are NOT persisted — no history on rejoin."""
    # Room has no entry in _room_meta (no passcode)
    async with ws_client.ws_connect("/ws") as ws1:
        await ws1.send_str(json.dumps({"type": "join", "room": "open-room"}))
        await ws1.receive_json(timeout=2)  # system

        await ws1.send_str(json.dumps({
            "type": "message",
            "iv": "aGVsbG93b3JsZA==",
            "ciphertext": "c2VjcmV0",
            "sender": "Bob",
        }))

    # Second client joins — must NOT receive any history
    async with ws_client.ws_connect("/ws") as ws2:
        await ws2.send_str(json.dumps({"type": "join", "room": "open-room"}))

        import asyncio
        msg = await asyncio.wait_for(ws2.receive_json(), timeout=2)
        assert msg["type"] == "system"

        # No further messages expected
        try:
            extra = await asyncio.wait_for(ws2.receive_json(), timeout=0.4)
            assert extra["type"] != "history", f"Unexpected history in room without passcode: {extra}"
        except asyncio.TimeoutError:
            pass  # expected


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


# ─── File-share passcode tests ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_share_upload_with_passcode_stores_hash(ws_client) -> None:
    """Upload with a passcode field stores a passcode_hash in the slot."""
    data = aiohttp.FormData()
    data.add_field("file", b"protected content", filename="secret.txt",
                   content_type="text/plain")
    data.add_field("passcode", "hunter2")
    resp = await ws_client.post("/share/upload?ttl=1", data=data)
    assert resp.status == 200
    body = await resp.json()
    token = body["download_url"].rsplit("/", 1)[-1]
    slot = _share_slots[token]
    assert slot["passcode_hash"] is not None
    assert slot["passcode_hash"] == _hash_passcode("hunter2")


@pytest.mark.asyncio
async def test_share_download_passcode_required_returns_gate_page(ws_client) -> None:
    """GET on a passcode-protected slot returns an HTML gate page (slot not consumed)."""
    data = aiohttp.FormData()
    data.add_field("file", b"gated", filename="gated.txt", content_type="text/plain")
    data.add_field("passcode", "s3cr3t")
    upload_resp = await ws_client.post("/share/upload?ttl=1", data=data)
    body = await upload_resp.json()
    url = body["download_url"]

    gate_resp = await ws_client.get(url)
    assert gate_resp.status == 200
    ct = gate_resp.headers.get("Content-Type", "")
    assert "text/html" in ct
    html = await gate_resp.text()
    assert "passcode" in html.lower() or "Passcode" in html

    # Slot must still exist — the GET must not consume it
    token = url.rsplit("/", 1)[-1]
    assert token in _share_slots


@pytest.mark.asyncio
async def test_share_download_post_wrong_passcode_returns_403(ws_client) -> None:
    """POST with wrong passcode returns HTTP 403 and does not consume the slot."""
    data = aiohttp.FormData()
    data.add_field("file", b"wrong", filename="w.txt", content_type="text/plain")
    data.add_field("passcode", "correct")
    upload_resp = await ws_client.post("/share/upload?ttl=1", data=data)
    body = await upload_resp.json()
    url = body["download_url"]
    token = url.rsplit("/", 1)[-1]

    resp = await ws_client.post(url, data={"passcode": "wrong"})
    assert resp.status == 403
    # Slot must still be there
    assert token in _share_slots


@pytest.mark.asyncio
async def test_share_download_post_correct_passcode_delivers_file(ws_client) -> None:
    """POST with correct passcode streams the file and consumes the slot."""
    content = b"super secret bytes"
    data = aiohttp.FormData()
    data.add_field("file", content, filename="p.bin",
                   content_type="application/octet-stream")
    data.add_field("passcode", "mypass")
    upload_resp = await ws_client.post("/share/upload?ttl=1", data=data)
    body = await upload_resp.json()
    url = body["download_url"]

    dl_resp = await ws_client.post(url, data={"passcode": "mypass"})
    assert dl_resp.status == 200
    downloaded = await dl_resp.read()
    assert downloaded == content

    # One-time: slot consumed
    token = url.rsplit("/", 1)[-1]
    assert token not in _share_slots


@pytest.mark.asyncio
async def test_share_download_post_one_time(ws_client) -> None:
    """A second POST with the correct passcode returns 404 (slot already consumed)."""
    data = aiohttp.FormData()
    data.add_field("file", b"x", filename="x.txt", content_type="text/plain")
    data.add_field("passcode", "pass")
    upload_resp = await ws_client.post("/share/upload?ttl=1", data=data)
    body = await upload_resp.json()
    url = body["download_url"]

    resp1 = await ws_client.post(url, data={"passcode": "pass"})
    assert resp1.status == 200
    await resp1.read()

    resp2 = await ws_client.post(url, data={"passcode": "pass"})
    assert resp2.status == 404


@pytest.mark.asyncio
async def test_share_download_no_passcode_still_works_via_get(ws_client) -> None:
    """Files without passcode continue to be served via GET as before."""
    content = b"no password needed"
    data = aiohttp.FormData()
    data.add_field("file", content, filename="open.txt", content_type="text/plain")
    upload_resp = await ws_client.post("/share/upload?ttl=1", data=data)
    body = await upload_resp.json()

    resp = await ws_client.get(body["download_url"])
    assert resp.status == 200
    assert await resp.read() == content


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


# ─── QR code endpoint ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_qrcode_returns_svg(ws_client) -> None:
    """GET /api/qrcode?data=<url> returns HTTP 200 with SVG content."""
    resp = await ws_client.get("/api/qrcode?data=https://example.onion/%23room%3Dabc")
    assert resp.status == 200
    ct = resp.headers.get("Content-Type", "")
    assert "svg" in ct
    body = await resp.text()
    assert body.startswith("<?xml") or "<svg" in body


@pytest.mark.asyncio
async def test_qrcode_no_data_returns_400(ws_client) -> None:
    """GET /api/qrcode with no data parameter returns 400."""
    resp = await ws_client.get("/api/qrcode")
    assert resp.status == 400


@pytest.mark.asyncio
async def test_qrcode_too_long_returns_400(ws_client) -> None:
    """GET /api/qrcode with data longer than 2048 chars returns 400."""
    resp = await ws_client.get("/api/qrcode?data=" + "x" * 2049)
    assert resp.status == 400


@pytest.mark.asyncio
async def test_qrcode_no_cache_header(ws_client) -> None:
    """QR response must carry Cache-Control: no-store."""
    resp = await ws_client.get("/api/qrcode?data=test")
    assert resp.status == 200
    assert "no-store" in resp.headers.get("Cache-Control", "")


# ─── In-chat file relay ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ws_file_relayed_to_other_peer(ws_client) -> None:
    """A type:'file' message sent by one peer is relayed to the other."""
    import asyncio
    async with ws_client.ws_connect("/ws") as ws1:
        await ws1.send_str(json.dumps({"type": "join", "room": "file-room"}))
        await ws1.receive_json(timeout=2)  # system

        async with ws_client.ws_connect("/ws") as ws2:
            await ws2.send_str(json.dumps({"type": "join", "room": "file-room"}))
            await ws1.receive_json(timeout=2)  # system broadcast
            await ws2.receive_json(timeout=2)  # system broadcast

            file_msg = {
                "type": "file",
                "iv": "aGVsbG93b3JsZA==",
                "ciphertext": "c2VjcmV0",
                "filename": "test.png",
                "mime": "image/png",
                "sender": "Alice",
            }
            await ws1.send_str(json.dumps(file_msg))

            relay = await asyncio.wait_for(ws2.receive_json(), timeout=2)
            assert relay["type"] == "file"
            assert relay["filename"] == "test.png"
            assert relay["mime"] == "image/png"
            assert relay["ciphertext"] == "c2VjcmV0"
            assert relay["sender"] == "Alice"


@pytest.mark.asyncio
async def test_ws_file_not_echoed_to_sender(ws_client) -> None:
    """The sender must not receive its own file relay."""
    import asyncio
    async with ws_client.ws_connect("/ws") as ws1:
        await ws1.send_str(json.dumps({"type": "join", "room": "file-echo"}))
        await ws1.receive_json(timeout=2)

        await ws1.send_str(json.dumps({
            "type": "file",
            "iv": "aGVsbG93b3JsZA==",
            "ciphertext": "c2VjcmV0",
            "filename": "test.png",
            "mime": "image/png",
            "sender": "Bob",
        }))

        try:
            extra = await asyncio.wait_for(ws1.receive_json(), timeout=0.3)
            assert extra["type"] != "file", "Sender should not receive its own file relay"
        except asyncio.TimeoutError:
            pass  # expected


@pytest.mark.asyncio
async def test_ws_file_oversized_is_dropped(ws_client) -> None:
    """A file message whose ciphertext exceeds MAX_FILE_CIPHERTEXT_LEN is silently dropped."""
    import asyncio
    async with ws_client.ws_connect("/ws") as ws1:
        await ws1.send_str(json.dumps({"type": "join", "room": "file-big"}))
        await ws1.receive_json(timeout=2)

        async with ws_client.ws_connect("/ws") as ws2:
            await ws2.send_str(json.dumps({"type": "join", "room": "file-big"}))
            await ws1.receive_json(timeout=2)
            await ws2.receive_json(timeout=2)

            # Send an oversized payload
            await ws1.send_str(json.dumps({
                "type": "file",
                "iv": "aGVsbG93b3JsZA==",
                "ciphertext": "x" * (MAX_FILE_CIPHERTEXT_LEN + 1),
                "filename": "huge.bin",
                "mime": "application/octet-stream",
                "sender": "Eve",
            }))

            try:
                msg = await asyncio.wait_for(ws2.receive_json(), timeout=0.4)
                assert msg["type"] != "file", "Oversized file should not be relayed"
            except asyncio.TimeoutError:
                pass  # expected — nothing relayed


@pytest.mark.asyncio
async def test_ws_file_not_persisted_even_with_passcode(ws_client) -> None:
    """File messages must never be stored in the database."""
    _room_meta["file-persist-test"] = {
        "passcode_hash": _hash_passcode("pass"),
        "expires_at": None,
    }
    async with ws_client.ws_connect("/ws") as ws1:
        await ws1.send_str(json.dumps({
            "type": "join", "room": "file-persist-test", "passcode": "pass",
        }))
        await ws1.receive_json(timeout=2)  # system

        await ws1.send_str(json.dumps({
            "type": "file",
            "iv": "aGVsbG93b3JsZA==",
            "ciphertext": "c2VjcmV0",
            "filename": "img.png",
            "mime": "image/png",
            "sender": "Alice",
        }))

    # A second client joining should NOT receive any history containing file data
    import asyncio
    async with ws_client.ws_connect("/ws") as ws2:
        await ws2.send_str(json.dumps({
            "type": "join", "room": "file-persist-test", "passcode": "pass",
        }))
        messages = []
        for _ in range(3):
            try:
                m = await asyncio.wait_for(ws2.receive_json(), timeout=0.4)
                messages.append(m)
            except asyncio.TimeoutError:
                break

        for m in messages:
            if m["type"] == "history":
                for stored in m.get("messages", []):
                    assert stored.get("type") != "file", "File messages must not be persisted"


# ─── Room delete endpoint ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_room_delete_removes_meta_and_history(ws_client, tmp_path) -> None:
    """POST /room/{room_id}/delete removes metadata and stored messages."""
    # Create a room with passcode so messages are stored
    resp = await ws_client.post("/room/create", json={"passcode": "del-test"})
    body = await resp.json()
    room_id = body["room_id"]
    delete_code = body["delete_code"]
    assert room_id in _room_meta

    # Call the delete endpoint with the delete code
    del_resp = await ws_client.post(
        f"/room/{room_id}/delete",
        json={"delete_code": delete_code},
    )
    assert del_resp.status == 200
    del_body = await del_resp.json()
    assert del_body["ok"] is True

    # Metadata must be gone
    assert room_id not in _room_meta


@pytest.mark.asyncio
async def test_room_delete_wrong_code_returns_403(ws_client) -> None:
    """POST /room/{room_id}/delete with wrong delete code returns 403."""
    resp = await ws_client.post("/room/create", json={"passcode": "del-code-test"})
    body = await resp.json()
    room_id = body["room_id"]

    del_resp = await ws_client.post(
        f"/room/{room_id}/delete",
        json={"delete_code": "wrong-code"},
    )
    assert del_resp.status == 403
    # Room should still exist
    assert room_id in _room_meta
    # Cleanup
    _room_meta.pop(room_id, None)


@pytest.mark.asyncio
async def test_room_delete_invalid_id_returns_400(ws_client) -> None:
    """POST /room/<invalid>/delete returns 400."""
    resp = await ws_client.post("/room/invalid room id!/delete")
    assert resp.status == 400


@pytest.mark.asyncio
async def test_room_delete_broadcasts_destruct_to_peers(ws_client) -> None:
    """Deleting a room while peers are connected broadcasts a 'destruct' event."""
    import asyncio
    # Create a room
    resp = await ws_client.post("/room/create", json={"passcode": "del-broadcast"})
    body = await resp.json()
    room_id = body["room_id"]
    delete_code = body["delete_code"]

    async with ws_client.ws_connect("/ws") as ws:
        await ws.send_str(json.dumps({"type": "join", "room": room_id, "passcode": "del-broadcast"}))
        # Drain initial messages (system, possibly destruct_info)
        for _ in range(3):
            try:
                await asyncio.wait_for(ws.receive_json(), timeout=0.5)
            except asyncio.TimeoutError:
                break

        # Delete the room
        await ws_client.post(f"/room/{room_id}/delete", json={"delete_code": delete_code})

        # The peer should receive a 'destruct' message
        try:
            msg = await asyncio.wait_for(ws.receive_json(), timeout=2)
            assert msg["type"] == "destruct"
        except asyncio.TimeoutError:
            pass  # acceptable if the WS closed before message could be read


# ─── File relay nsfw / one_time fields ───────────────────────────────────────

@pytest.mark.asyncio
async def test_ws_file_relays_nsfw_and_one_time_flags(ws_client) -> None:
    """nsfw and one_time flags on a file message are relayed to other peers."""
    import asyncio
    async with ws_client.ws_connect("/ws") as ws1:
        await ws1.send_str(json.dumps({"type": "join", "room": "file-flags"}))
        await ws1.receive_json(timeout=2)

        async with ws_client.ws_connect("/ws") as ws2:
            await ws2.send_str(json.dumps({"type": "join", "room": "file-flags"}))
            await ws1.receive_json(timeout=2)
            await ws2.receive_json(timeout=2)

            file_msg = {
                "type": "file",
                "iv": "aGVsbG93b3JsZA==",
                "ciphertext": "c2VjcmV0",
                "filename": "secret.png",
                "mime": "image/png",
                "sender": "Alice",
                "nsfw": True,
                "one_time": True,
            }
            await ws1.send_str(json.dumps(file_msg))

            relay = await asyncio.wait_for(ws2.receive_json(), timeout=2)
            assert relay["type"] == "file"
            assert relay["nsfw"] is True
            assert relay["one_time"] is True


# ─── Retained room metadata on empty room ─────────────────────────────────────

@pytest.mark.asyncio
async def test_room_meta_retained_when_last_peer_leaves(ws_client) -> None:
    """When the last peer leaves a passcode-protected room, _room_meta is kept."""
    _room_meta["retain-test"] = {
        "passcode_hash": _hash_passcode("keep"),
        "expires_at": None,
    }
    async with ws_client.ws_connect("/ws") as ws:
        await ws.send_str(json.dumps({"type": "join", "room": "retain-test", "passcode": "keep"}))
        await ws.receive_json(timeout=2)  # system

    # After the connection closes, metadata must still be present
    assert "retain-test" in _room_meta, "Room metadata must be retained for passcode-protected rooms"


# ─── Admin panel tests ────────────────────────────────────────────────────────

from server import (
    build_admin_app,
    _ADMIN_SESSIONS,
    _make_admin_session,
    _valid_admin_session,
    _ADMIN_LOGIN_FAILURES,
    ADMIN_LOGIN_MAX_ATTEMPTS,
)
import server as _srv_mod


@pytest.fixture
def admin_app():
    """Return a freshly-built admin application."""
    return build_admin_app()


@pytest_asyncio.fixture
async def admin_client(admin_app, aiohttp_client):
    return await aiohttp_client(admin_app)


async def _login(admin_client) -> None:
    """Helper: perform admin login and set session cookie."""
    resp = await admin_client.post(
        "/admin/login",
        json={"passcode": _srv_mod._ADMIN_PASSCODE},
    )
    assert resp.status == 200


@pytest.mark.asyncio
async def test_admin_html_served(admin_client) -> None:
    """GET /admin/ returns the admin HTML page."""
    resp = await admin_client.get("/admin/")
    assert resp.status == 200
    ct = resp.headers.get("Content-Type", "")
    assert "text/html" in ct


@pytest.mark.asyncio
async def test_admin_login_correct_passcode(admin_client) -> None:
    """POST /admin/login with correct passcode returns 200 and sets session cookie."""
    resp = await admin_client.post(
        "/admin/login",
        json={"passcode": _srv_mod._ADMIN_PASSCODE},
    )
    assert resp.status == 200
    body = await resp.json()
    assert body["ok"] is True
    assert "admin_session" in resp.cookies


@pytest.mark.asyncio
async def test_admin_login_wrong_passcode(admin_client) -> None:
    """POST /admin/login with wrong passcode returns 403."""
    resp = await admin_client.post(
        "/admin/login",
        json={"passcode": "definitely-wrong"},
    )
    assert resp.status == 403


@pytest.mark.asyncio
async def test_admin_stats_requires_auth(admin_client) -> None:
    """GET /admin/api/stats without session returns 401."""
    resp = await admin_client.get("/admin/api/stats")
    assert resp.status == 401


@pytest.mark.asyncio
async def test_admin_stats_with_auth(admin_client) -> None:
    """GET /admin/api/stats with valid session returns stats JSON."""
    await _login(admin_client)
    resp = await admin_client.get("/admin/api/stats")
    assert resp.status == 200
    body = await resp.json()
    assert "open_rooms" in body
    assert "rooms_created_total" in body
    assert "rooms_by_destruct" in body
    # System resource metrics should be present when psutil is installed
    assert "sys_cpu_percent" in body, "sys_cpu_percent missing — is psutil installed?"
    assert "sys_ram_percent" in body
    assert "sys_disk_percent" in body
    assert isinstance(body["sys_cpu_percent"], (int, float))
    assert 0 <= body["sys_ram_percent"] <= 100
    assert 0 <= body["sys_disk_percent"] <= 100


@pytest.mark.asyncio
async def test_admin_webhook_info_requires_auth(admin_client) -> None:
    """GET /admin/api/webhook-info without session returns 401."""
    resp = await admin_client.get("/admin/api/webhook-info")
    assert resp.status == 401


@pytest.mark.asyncio
async def test_admin_webhook_info_returns_token(admin_client) -> None:
    """GET /admin/api/webhook-info returns the webhook token."""
    await _login(admin_client)
    resp = await admin_client.get("/admin/api/webhook-info")
    assert resp.status == 200
    body = await resp.json()
    assert "webhook_token" in body
    assert len(body["webhook_token"]) > 0


@pytest.mark.asyncio
async def test_admin_incoming_webhook_wrong_token(admin_client) -> None:
    """POST /admin/webhook/<wrong-token> returns 401."""
    resp = await admin_client.post(
        "/admin/webhook/not-the-right-token",
        json={"event": "test"},
    )
    assert resp.status == 401


@pytest.mark.asyncio
async def test_admin_incoming_webhook_valid_token(admin_client) -> None:
    """POST /admin/webhook/<valid-token> with correct token returns 200."""
    token = _srv_mod._ADMIN_WEBHOOK_TOKEN
    resp = await admin_client.post(
        f"/admin/webhook/{token}",
        json={"event": "deploy", "version": "1.2.3"},
    )
    assert resp.status == 200
    body = await resp.json()
    assert body["ok"] is True
    assert body["received"] is True


@pytest.mark.asyncio
async def test_admin_incoming_webhook_non_json_body(admin_client) -> None:
    """POST /admin/webhook/<token> with non-JSON body is accepted (body defaults to {})."""
    token = _srv_mod._ADMIN_WEBHOOK_TOKEN
    resp = await admin_client.post(
        f"/admin/webhook/{token}",
        data=b"not json",
        headers={"Content-Type": "text/plain"},
    )
    assert resp.status == 200


@pytest.mark.asyncio
async def test_admin_root_returns_404_or_not_found(admin_client) -> None:
    """GET / on the admin app is not a valid route (admin is at the secret path)."""
    resp = await admin_client.get("/", allow_redirects=False)
    # aiohttp returns 404 for unregistered routes
    assert resp.status == 404



@pytest.mark.asyncio
async def test_admin_html_pre_renders_login_form(admin_client) -> None:
    """Admin HTML body pre-renders the login form so there is no blank-page flash."""
    resp = await admin_client.get("/admin/")
    assert resp.status == 200
    body = await resp.text()
    # The login form must be in the served HTML (not injected by JS after load)
    assert 'id="lf"' in body
    assert 'id="pc"' in body


# ─── New-path admin tests (200-char secret path) ─────────────────────────────

@pytest.mark.asyncio
async def test_admin_path_is_200_chars() -> None:
    """_ADMIN_PATH is exactly 200 URL-safe characters (or set via ADMIN_PATH env)."""
    # After build_admin_app() has been called, _ADMIN_PATH must be populated
    path = _srv_mod._ADMIN_PATH
    assert len(path) == 200, f"Expected 200 chars, got {len(path)}"
    # Must be URL-safe base64 characters (A-Z, a-z, 0-9, -, _)
    import re as _re
    assert _re.fullmatch(r"[A-Za-z0-9_-]+", path), "Path contains non-URL-safe characters"


@pytest.mark.asyncio
async def test_admin_passcode_is_100_chars() -> None:
    """_ADMIN_PASSCODE is exactly 100 characters."""
    pc = _srv_mod._ADMIN_PASSCODE
    assert len(pc) == 100, f"Expected 100 chars, got {len(pc)}"


@pytest.mark.asyncio
async def test_admin_secret_path_returns_html(admin_client) -> None:
    """GET /<secret-path>/ returns the admin HTML page."""
    path = _srv_mod._ADMIN_PATH
    resp = await admin_client.get(f"/{path}/")
    assert resp.status == 200
    ct = resp.headers.get("Content-Type", "")
    assert "text/html" in ct


@pytest.mark.asyncio
async def test_admin_secret_path_has_security_headers(admin_client) -> None:
    """Admin responses carry the required security headers."""
    path = _srv_mod._ADMIN_PATH
    resp = await admin_client.get(f"/{path}/")
    assert resp.status == 200
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert "no-store" in resp.headers.get("Cache-Control", "")
    assert "frame-ancestors" in resp.headers.get("Content-Security-Policy", "")


@pytest.mark.asyncio
async def test_admin_html_injects_path(admin_client) -> None:
    """Admin HTML must not contain the raw placeholder; the actual path is injected."""
    path = _srv_mod._ADMIN_PATH
    resp = await admin_client.get(f"/{path}/")
    assert resp.status == 200
    body = await resp.text()
    assert "__ADMIN_PATH__" not in body, "Placeholder was not replaced by server"
    # The injected path prefix must appear in the page
    assert path in body


@pytest.mark.asyncio
async def test_admin_login_via_secret_path(admin_client) -> None:
    """Login via the secret path works correctly."""
    path = _srv_mod._ADMIN_PATH
    resp = await admin_client.post(
        f"/{path}/login",
        json={"passcode": _srv_mod._ADMIN_PASSCODE},
    )
    assert resp.status == 200
    body = await resp.json()
    assert body["ok"] is True
    assert "admin_session" in resp.cookies


@pytest.mark.asyncio
async def test_admin_login_rate_limited(admin_client) -> None:
    """Too many wrong passcode attempts from the same IP triggers 429."""
    import server as _srv_m
    path = _srv_m._ADMIN_PATH
    # Clear any existing failures first
    _srv_m._ADMIN_LOGIN_FAILURES.clear()
    for _ in range(_srv_m.ADMIN_LOGIN_MAX_ATTEMPTS):
        await admin_client.post(
            f"/{path}/login",
            json={"passcode": "wrong"},
        )
    resp = await admin_client.post(
        f"/{path}/login",
        json={"passcode": "still-wrong"},
    )
    assert resp.status == 429
    _srv_m._ADMIN_LOGIN_FAILURES.clear()


@pytest.mark.asyncio
async def test_admin_security_headers_on_login_response(admin_client) -> None:
    """Successful login response includes security headers."""
    path = _srv_mod._ADMIN_PATH
    resp = await admin_client.post(
        f"/{path}/login",
        json={"passcode": _srv_mod._ADMIN_PASSCODE},
    )
    assert resp.status == 200
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"


# ─── Fix 4: room deletion without key ────────────────────────────────────────

@pytest.mark.asyncio
async def test_room_delete_no_code_returns_403(ws_client) -> None:
    """POST /room/{room_id}/delete without supplying delete_code returns 403.

    A registered room must always require its delete code; omitting the field
    entirely must not allow silent deletion.
    """
    resp = await ws_client.post("/room/create", json={"passcode": "no-code-test"})
    body = await resp.json()
    room_id = body["room_id"]

    # Send request with no delete_code field at all
    del_resp = await ws_client.post(f"/room/{room_id}/delete", json={})
    assert del_resp.status == 403
    # Room must still exist
    assert room_id in _room_meta
    # Cleanup
    _room_meta.pop(room_id, None)


@pytest.mark.asyncio
async def test_room_delete_empty_code_returns_403(ws_client) -> None:
    """POST /room/{room_id}/delete with an empty delete_code string returns 403."""
    resp = await ws_client.post("/room/create", json={"passcode": "empty-code-test"})
    body = await resp.json()
    room_id = body["room_id"]

    del_resp = await ws_client.post(
        f"/room/{room_id}/delete",
        json={"delete_code": ""},
    )
    assert del_resp.status == 403
    assert room_id in _room_meta
    _room_meta.pop(room_id, None)


# ─── Fix 3: admin session is a browser-session cookie ────────────────────────

@pytest.mark.asyncio
async def test_admin_login_cookie_has_no_max_age(admin_client) -> None:
    """Session cookie set on successful login must NOT carry a max-age attribute.

    Without max-age the cookie expires when the browser closes, preventing
    auto-login across browser restarts or on synced browser profiles.
    """
    path = _srv_mod._ADMIN_PATH
    resp = await admin_client.post(
        f"/{path}/login",
        json={"passcode": _srv_mod._ADMIN_PASSCODE},
    )
    assert resp.status == 200
    cookie = resp.cookies.get("admin_session")
    assert cookie is not None
    # A session cookie must not expose a Max-Age (or Expires) attribute.
    cookie_str = str(cookie)
    assert "Max-Age" not in cookie_str and "max-age" not in cookie_str.lower()


@pytest.mark.asyncio
async def test_admin_login_clears_previous_sessions(admin_client) -> None:
    """A new login must invalidate all previous admin session tokens (single-session)."""
    import server as _s
    path = _s._ADMIN_PATH

    # Login once; grab the first token
    await admin_client.post(f"/{path}/login", json={"passcode": _s._ADMIN_PASSCODE})
    first_tokens = set(_s._ADMIN_SESSIONS.keys())
    assert len(first_tokens) == 1

    # Login again; the first token must no longer be valid
    await admin_client.post(f"/{path}/login", json={"passcode": _s._ADMIN_PASSCODE})
    second_tokens = set(_s._ADMIN_SESSIONS.keys())
    assert len(second_tokens) == 1
    # The old token must have been invalidated
    assert not first_tokens & second_tokens, "Old session was not cleared on new login"


# ─── Fix 1: system-resource metrics are per-process ──────────────────────────

@pytest.mark.asyncio
async def test_admin_stats_cpu_percent_within_normalised_range(admin_client) -> None:
    """sys_cpu_percent in /api/stats must be in [0, 100] (normalised per-process)."""
    await _login(admin_client)
    resp = await admin_client.get("/admin/api/stats")
    assert resp.status == 200
    body = await resp.json()
    assert "sys_cpu_percent" in body, "sys_cpu_percent missing — is psutil installed?"
    pct = body["sys_cpu_percent"]
    assert isinstance(pct, (int, float))
    assert 0 <= pct <= 100, f"sys_cpu_percent {pct} is outside the normalised 0-100 range"


# ─── Fix 2: SSE log stream replays recent history ────────────────────────────

@pytest.mark.asyncio
async def test_log_recent_ring_buffer_populated() -> None:
    """_log_recent is populated when log records are emitted via _SseLogHandler."""
    import logging
    import server as _s

    # Attach a temporary handler using the same formatter the real startup uses
    handler = _s._SseLogHandler()
    handler.setFormatter(logging.Formatter(
        fmt="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    ))
    root = logging.getLogger()
    root.addHandler(handler)
    # Use a unique sentinel so we can find it even if the buffer is already full.
    import secrets as _sec
    marker = f"ring-buffer-probe-{_sec.token_hex(8)}"
    try:
        logging.getLogger("test.ring_buffer").info("%s", marker)
    finally:
        root.removeHandler(handler)

    assert any(marker in m for m in _s._log_recent), (
        "_log_recent does not contain the emitted log line"
    )


# ─── One-time inbox tests ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_inbox_create_returns_urls(ws_client) -> None:
    """POST /inbox/create returns address, drop_url, read_url, and expires_at."""
    resp = await ws_client.post("/inbox/create", json={})
    assert resp.status == 200
    body = await resp.json()
    assert "address"    in body
    assert "drop_url"   in body
    assert "read_url"   in body
    assert "expires_at" in body
    assert body["drop_url"].startswith("/inbox/")
    assert body["drop_url"].endswith("/drop")
    assert body["read_url"].endswith("/read")
    # address should be in the form local@host
    assert "@" in body["address"]


@pytest.mark.asyncio
async def test_inbox_create_ttl_minutes(ws_client) -> None:
    """POST /inbox/create respects ttl_minutes (1-1440) and clamps outliers."""
    import server as _s
    import time

    # Custom TTL = 15 minutes
    resp = await ws_client.post("/inbox/create", json={"ttl_minutes": 15})
    body = await resp.json()
    token = body["drop_url"].split("/")[2]
    expected = time.time() + 15 * 60
    assert abs(_s._inbox_slots[token]["expires_at"] - expected) < 5

    # TTL above maximum should be clamped to 1440 min (24 h)
    resp2 = await ws_client.post("/inbox/create", json={"ttl_minutes": 99999})
    body2 = await resp2.json()
    token2 = body2["drop_url"].split("/")[2]
    max_expected = time.time() + 1440 * 60
    assert _s._inbox_slots[token2]["expires_at"] <= max_expected + 5

    # TTL below minimum should be clamped to 1 min
    resp3 = await ws_client.post("/inbox/create", json={"ttl_minutes": 0})
    body3 = await resp3.json()
    token3 = body3["drop_url"].split("/")[2]
    min_expected = time.time() + 1 * 60
    assert abs(_s._inbox_slots[token3]["expires_at"] - min_expected) < 5


@pytest.mark.asyncio
async def test_inbox_drop_and_read_once(ws_client) -> None:
    """Full happy-path: create → drop message → read → messages in list."""
    # Create
    resp = await ws_client.post("/inbox/create", json={})
    body = await resp.json()
    drop_url = body["drop_url"]
    read_url = body["read_url"]

    # Drop a message
    drop_resp = await ws_client.post(drop_url, json={"message": "S3cr3tC0de!"})
    assert drop_resp.status == 200
    assert (await drop_resp.json())["ok"] is True

    # Read — returns messages list, inbox NOT destroyed
    read_resp = await ws_client.get(read_url)
    assert read_resp.status == 200
    read_body = await read_resp.json()
    assert "messages" in read_body
    assert len(read_body["messages"]) == 1
    assert read_body["messages"][0]["body"] == "S3cr3tC0de!"

    # Second read still works (inbox persists until TTL)
    read_resp2 = await ws_client.get(read_url)
    assert read_resp2.status == 200


@pytest.mark.asyncio
async def test_inbox_drop_page_served(ws_client) -> None:
    """GET /inbox/{token}/drop returns the sender HTML page with address/expiry."""
    resp = await ws_client.post("/inbox/create", json={})
    drop_url = (await resp.json())["drop_url"]
    page_resp = await ws_client.get(drop_url)
    assert page_resp.status == 200
    ct = page_resp.headers.get("Content-Type", "")
    assert "text/html" in ct
    text = await page_resp.text()
    assert "Send to Inbox" in text
    # The address placeholder must have been substituted
    assert "__INBOX_ADDRESS__" not in text
    assert "__INBOX_EXPIRES_AT__" not in text


@pytest.mark.asyncio
async def test_inbox_accepts_multiple_messages(ws_client) -> None:
    """Multiple POSTs to /drop on the same inbox are all accepted (no 409)."""
    resp = await ws_client.post("/inbox/create", json={})
    drop_url = (await resp.json())["drop_url"]

    first  = await ws_client.post(drop_url, json={"message": "first"})
    second = await ws_client.post(drop_url, json={"message": "second"})
    assert first.status == 200
    assert second.status == 200

    # Both messages should be stored
    read_url = (await (await ws_client.post("/inbox/create", json={})).json())["drop_url"]
    token = drop_url.split("/")[2]
    import server as _s
    slot = _s._inbox_slots.get(token)
    assert slot is not None
    assert len(slot["messages"]) == 2


@pytest.mark.asyncio
async def test_inbox_read_before_drop_returns_204(ws_client) -> None:
    """GET /read on an empty (unfilled) inbox returns 200 with empty messages list."""
    resp = await ws_client.post("/inbox/create", json={})
    read_url = (await resp.json())["read_url"]
    read_resp = await ws_client.get(read_url)
    assert read_resp.status == 200
    body = await read_resp.json()
    assert body["count"] == 0
    assert body["messages"] == []


@pytest.mark.asyncio
async def test_inbox_empty_message_returns_400(ws_client) -> None:
    """POST /drop with an empty message string returns 400."""
    resp = await ws_client.post("/inbox/create", json={})
    drop_url = (await resp.json())["drop_url"]
    bad = await ws_client.post(drop_url, json={"message": "   "})
    assert bad.status == 400


@pytest.mark.asyncio
async def test_inbox_unknown_token_returns_404(ws_client) -> None:
    """POST /inbox/<bogus>/drop on an unknown token returns 404."""
    resp = await ws_client.post("/inbox/not-a-real-token/drop",
                                json={"message": "hi"})
    assert resp.status == 404


@pytest.mark.asyncio
async def test_inbox_expired_drop_returns_410(ws_client) -> None:
    """POSTing to a manually expired inbox returns 410."""
    import server as _s
    resp = await ws_client.post("/inbox/create", json={"ttl_minutes": 10})
    token = (await resp.json())["drop_url"].split("/")[2]
    # Force expiry
    _s._inbox_slots[token]["expires_at"] = 0.0
    gone = await ws_client.post(f"/inbox/{token}/drop", json={"message": "hi"})
    assert gone.status == 410


# ─── SMTP inbox tests ────────────────────────────────────────────────────────

class FakeEnvelope:
    """Minimal aiosmtpd Envelope stub for unit-testing InboxSmtpHandler."""
    def __init__(self, rcpt_tos: list, content: bytes):
        self.rcpt_tos = rcpt_tos
        self.content = content
        self.mail_from = "sender@example.com"


@pytest.mark.asyncio
async def test_smtp_handler_fills_slot_plaintext(ws_client) -> None:
    """InboxSmtpHandler.handle_DATA appends a plain-text email to the inbox messages list."""
    import server as _s

    resp = await ws_client.post("/inbox/create", json={"ttl_minutes": 10})
    data = await resp.json()
    token = data["drop_url"].split("/")[2]

    raw_email = (
        "From: alice@example.com\r\n"
        "To: {token}@example.com\r\n"
        "Subject: Test verification code\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        "Your code is 123456\r\n"
    ).format(token=token).encode()

    handler = _s.InboxSmtpHandler()
    envelope = FakeEnvelope(rcpt_tos=[f"{token}@example.com"], content=raw_email)
    result = await handler.handle_DATA(None, None, envelope)

    assert result.startswith("250")
    slot = _s._inbox_slots.get(token)
    assert slot is not None
    assert len(slot["messages"]) == 1
    msg = slot["messages"][0]
    assert "123456" in msg["body"]
    assert msg["email_from"] == "alice@example.com"
    assert msg["subject"] == "Test verification code"
    assert msg["content_type"] == "text/plain"


@pytest.mark.asyncio
async def test_smtp_handler_fills_slot_html_email(ws_client) -> None:
    """InboxSmtpHandler.handle_DATA stores HTML content and sets content_type=text/html."""
    import server as _s

    resp = await ws_client.post("/inbox/create", json={"ttl_minutes": 5})
    token = (await resp.json())["drop_url"].split("/")[2]

    raw_email = (
        "From: noreply@discord.com\r\n"
        "To: {token}@mail.example.com\r\n"
        "Subject: Discord verify\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "\r\n"
        "<html><body><p>Your code is <b>654321</b></p></body></html>\r\n"
    ).format(token=token).encode()

    handler = _s.InboxSmtpHandler()
    envelope = FakeEnvelope(rcpt_tos=[f"{token}@mail.example.com"], content=raw_email)
    result = await handler.handle_DATA(None, None, envelope)

    assert result.startswith("250")
    slot = _s._inbox_slots.get(token)
    assert slot is not None
    assert len(slot["messages"]) == 1
    msg = slot["messages"][0]
    assert "654321" in msg["body"]
    assert msg["content_type"] == "text/html"


@pytest.mark.asyncio
async def test_smtp_handler_ignores_unknown_token(ws_client) -> None:
    """InboxSmtpHandler.handle_DATA silently ignores recipients with no matching slot."""
    import server as _s

    raw_email = (
        "From: x@example.com\r\n"
        "To: notavalidtoken@example.com\r\n"
        "Subject: Ignored\r\n"
        "\r\n"
        "body\r\n"
    ).encode()

    handler = _s.InboxSmtpHandler()
    envelope = FakeEnvelope(rcpt_tos=["notavalidtoken@example.com"], content=raw_email)
    result = await handler.handle_DATA(None, None, envelope)
    assert result.startswith("250")  # still returns 250; unknown tokens are silently skipped


@pytest.mark.asyncio
async def test_inbox_read_returns_email_metadata(ws_client) -> None:
    """GET /inbox/{token}/read returns messages list with email_from, subject, content_type."""
    import server as _s

    resp = await ws_client.post("/inbox/create", json={"ttl_minutes": 10})
    data = await resp.json()
    token = data["drop_url"].split("/")[2]

    # Simulate SMTP delivery by calling the handler directly
    raw_email = (
        "From: github@example.com\r\n"
        "To: {token}@example.com\r\n"
        "Subject: GitHub: Verify your email\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        "Click here to verify: https://github.com/verify/abc\r\n"
    ).format(token=token).encode()

    handler = _s.InboxSmtpHandler()
    envelope = FakeEnvelope(rcpt_tos=[f"{token}@example.com"], content=raw_email)
    await handler.handle_DATA(None, None, envelope)

    read_resp = await ws_client.get(f"/inbox/{token}/read")
    assert read_resp.status == 200
    body = await read_resp.json()
    assert "messages" in body
    assert body["count"] == 1
    msg = body["messages"][0]
    assert "body" in msg
    assert msg["email_from"] == "github@example.com"
    assert msg["subject"] == "GitHub: Verify your email"
    assert msg["content_type"] == "text/plain"


@pytest.mark.asyncio
async def test_smtp_handler_handle_rcpt_rejects_unknown_token() -> None:
    """InboxSmtpHandler.handle_RCPT returns 550 for unknown/expired tokens."""
    import server as _s

    handler = _s.InboxSmtpHandler()

    class _FakeEnvelopeRcpt:
        rcpt_tos: list = []

    result = await handler.handle_RCPT(None, None, _FakeEnvelopeRcpt(), "badtoken@x.com", [])
    assert result.startswith("550")


@pytest.mark.asyncio
async def test_smtp_enabled_field_in_create_response(ws_client) -> None:
    """POST /inbox/create always returns smtp_enabled field."""
    resp = await ws_client.post("/inbox/create", json={})
    assert resp.status == 200
    data = await resp.json()
    assert "smtp_enabled" in data
    # In test environment MAIL_DOMAIN is not set, so smtp_enabled should be False
    assert data["smtp_enabled"] is False


@pytest.mark.asyncio
async def test_server_info_includes_mail_domain(ws_client) -> None:
    """GET /api/server-info includes mail_domain field."""
    resp = await ws_client.get("/api/server-info")
    assert resp.status == 200
    data = await resp.json()
    assert "mail_domain" in data
    # In test environment MAIL_DOMAIN is not set
    assert data["mail_domain"] is None


# ---------------------------------------------------------------------------
# Relay webhook endpoint tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_relay_disabled_without_secret(ws_client) -> None:
    """POST /inbox/relay returns 404 when RELAY_SECRET is not configured."""
    import server as _s
    original = _s.RELAY_SECRET
    try:
        _s.RELAY_SECRET = ""
        resp = await ws_client.post("/inbox/relay", json={"token": "x", "body": "hi"})
        assert resp.status == 404
    finally:
        _s.RELAY_SECRET = original


@pytest.mark.asyncio
async def test_relay_rejects_wrong_secret(ws_client) -> None:
    """POST /inbox/relay returns 403 when the secret is wrong."""
    import server as _s
    original = _s.RELAY_SECRET
    try:
        _s.RELAY_SECRET = "correct-secret"
        resp = await ws_client.post(
            "/inbox/relay",
            json={"secret": "wrong-secret", "token": "x", "body": "hi"},
        )
        assert resp.status == 403
    finally:
        _s.RELAY_SECRET = original


@pytest.mark.asyncio
async def test_relay_json_deposits_message(ws_client) -> None:
    """POST /inbox/relay (JSON) deposits a message into the matching inbox."""
    import server as _s
    original = _s.RELAY_SECRET
    try:
        _s.RELAY_SECRET = "test-relay-secret"
        create = await ws_client.post("/inbox/create", json={"ttl_minutes": 10})
        data   = await create.json()
        token  = data["drop_url"].split("/")[2]

        relay_resp = await ws_client.post(
            "/inbox/relay",
            json={
                "secret":  "test-relay-secret",
                "token":   token,
                "from":    "relay@example.com",
                "subject": "Relay test",
                "body":    "Hello from relay",
            },
        )
        assert relay_resp.status == 200
        assert (await relay_resp.json())["ok"] is True

        read_resp = await ws_client.get(f"/inbox/{token}/read")
        body = await read_resp.json()
        assert body["count"] == 1
        msg = body["messages"][0]
        assert msg["body"] == "Hello from relay"
        assert msg["email_from"] == "relay@example.com"
        assert msg["subject"] == "Relay test"
    finally:
        _s.RELAY_SECRET = original


@pytest.mark.asyncio
async def test_relay_json_html_content_type(ws_client) -> None:
    """POST /inbox/relay sets content_type=text/html when html field is present."""
    import server as _s
    original = _s.RELAY_SECRET
    try:
        _s.RELAY_SECRET = "test-relay-secret"
        create = await ws_client.post("/inbox/create", json={"ttl_minutes": 5})
        token  = (await create.json())["drop_url"].split("/")[2]

        await ws_client.post(
            "/inbox/relay",
            json={
                "secret": "test-relay-secret",
                "token":  token,
                "html":   "<b>HTML email</b>",
                "body":   "fallback plain",
            },
        )
        read_resp = await ws_client.get(f"/inbox/{token}/read")
        msg = (await read_resp.json())["messages"][0]
        assert msg["content_type"] == "text/html"
        assert msg["body"] == "<b>HTML email</b>"
    finally:
        _s.RELAY_SECRET = original


@pytest.mark.asyncio
async def test_relay_secret_via_header(ws_client) -> None:
    """POST /inbox/relay accepts the secret in X-Relay-Secret header."""
    import server as _s
    original = _s.RELAY_SECRET
    try:
        _s.RELAY_SECRET = "header-secret"
        create = await ws_client.post("/inbox/create", json={})
        token  = (await create.json())["drop_url"].split("/")[2]

        resp = await ws_client.post(
            "/inbox/relay",
            headers={"X-Relay-Secret": "header-secret"},
            json={"token": token, "body": "from header auth"},
        )
        assert resp.status == 200
    finally:
        _s.RELAY_SECRET = original


@pytest.mark.asyncio
async def test_relay_mailgun_form_format(ws_client) -> None:
    """POST /inbox/relay handles Mailgun-style form-encoded payload."""
    import server as _s
    original = _s.RELAY_SECRET
    try:
        _s.RELAY_SECRET = "mg-secret"
        create = await ws_client.post("/inbox/create", json={})
        token  = (await create.json())["drop_url"].split("/")[2]

        resp = await ws_client.post(
            "/inbox/relay",
            headers={"X-Relay-Secret": "mg-secret"},
            data={
                "recipient":   f"{token}@mail.example.com",
                "sender":      "user@gmail.com",
                "subject":     "Mailgun test",
                "body-plain":  "Mailgun body",
            },
        )
        assert resp.status == 200
        read = await ws_client.get(f"/inbox/{token}/read")
        msgs = (await read.json())["messages"]
        assert len(msgs) == 1
        assert msgs[0]["email_from"] == "user@gmail.com"
        assert msgs[0]["subject"] == "Mailgun test"
    finally:
        _s.RELAY_SECRET = original


@pytest.mark.asyncio
async def test_relay_unknown_token_returns_404(ws_client) -> None:
    """POST /inbox/relay returns 404 for a token that doesn't exist."""
    import server as _s
    original = _s.RELAY_SECRET
    try:
        _s.RELAY_SECRET = "test-secret"
        resp = await ws_client.post(
            "/inbox/relay",
            json={
                "secret": "test-secret",
                "token":  "doesnotexist",
                "body":   "x",
            },
        )
        assert resp.status == 404
    finally:
        _s.RELAY_SECRET = original


@pytest.mark.asyncio
async def test_relay_enabled_field_in_create_response(ws_client) -> None:
    """POST /inbox/create always returns relay_enabled field."""
    resp = await ws_client.post("/inbox/create", json={})
    data = await resp.json()
    assert "relay_enabled" in data


@pytest.mark.asyncio
async def test_server_info_includes_relay_enabled(ws_client) -> None:
    """GET /api/server-info includes relay_enabled field."""
    resp = await ws_client.get("/api/server-info")
    data = await resp.json()
    assert "relay_enabled" in data


# ---------------------------------------------------------------------------
# Lockdown feature tests
# Lockdown feature tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_lockdown_status_requires_auth(ws_client) -> None:
    """GET /{ADMIN_PATH}/api/lockdown returns 403 without session."""
    import server as _s
    ap = _s._ADMIN_PATH
    resp = await ws_client.get(f"/{ap}/api/lockdown")
    assert resp.status == 403


@pytest.mark.asyncio
async def test_lockdown_activate_requires_auth(ws_client) -> None:
    """POST /{ADMIN_PATH}/api/lockdown returns 403 without session."""
    import server as _s
    ap = _s._ADMIN_PATH
    resp = await ws_client.post(f"/{ap}/api/lockdown", json={"action": "activate"})
    assert resp.status == 403


@pytest.mark.asyncio
async def test_lockdown_toggle_and_wipe(ws_client) -> None:
    """Admin can activate lockdown which clears inboxes; deactivate lifts it."""
    import server as _s

    _s._lockdown_active = False
    ap = _s._ADMIN_PATH
    passcode = _s._ADMIN_PASSCODE

    # Login
    login = await ws_client.post(f"/{ap}/login", json={"passcode": passcode})
    assert login.status == 200

    # Create an inbox and deposit a message
    cr = await ws_client.post("/inbox/create", json={})
    token = (await cr.json())["drop_url"].split("/")[2]
    await ws_client.post(f"/inbox/{token}/drop", json={"message": "secret"})

    # Verify inbox has a message
    read = await ws_client.get(f"/inbox/{token}/read")
    assert (await read.json())["count"] == 1

    try:
        # Activate lockdown
        act = await ws_client.post(f"/{ap}/api/lockdown", json={"action": "activate"})
        assert act.status == 200
        assert (await act.json())["lockdown"] is True
        assert _s._lockdown_active is True

        # Inbox should now be wiped
        assert token not in _s._inbox_slots

        # Status endpoint should report lockdown active
        status = await ws_client.get(f"/{ap}/api/lockdown")
        assert (await status.json())["lockdown"] is True

    finally:
        _s._lockdown_active = False

    # Deactivate via API
    _s._lockdown_active = True
    deact = await ws_client.post(f"/{ap}/api/lockdown", json={"action": "deactivate"})
    assert deact.status == 200
    assert (await deact.json())["lockdown"] is False
    assert _s._lockdown_active is False


@pytest.mark.asyncio
async def test_lockdown_blocks_normal_routes(ws_client) -> None:
    """While lockdown is active, non-admin routes return 503."""
    import server as _s

    _s._lockdown_active = True
    try:
        resp = await ws_client.get("/")
        assert resp.status == 503
    finally:
        _s._lockdown_active = False


@pytest.mark.asyncio
async def test_lockdown_allows_admin_routes(ws_client) -> None:
    """While lockdown is active, the admin path itself is not blocked (503)."""
    import server as _s

    _s._lockdown_active = True
    ap = _s._ADMIN_PATH
    try:
        resp = await ws_client.get(f"/{ap}/")
        assert resp.status != 503
    finally:
        _s._lockdown_active = False


@pytest.mark.asyncio
async def test_lockdown_bad_action_returns_400(ws_client) -> None:
    """POST /{ADMIN_PATH}/api/lockdown with unknown action returns 400."""
    import server as _s

    _s._lockdown_active = False
    ap = _s._ADMIN_PATH
    passcode = _s._ADMIN_PASSCODE
    await ws_client.post(f"/{ap}/login", json={"passcode": passcode})

    resp = await ws_client.post(f"/{ap}/api/lockdown", json={"action": "explode"})
    assert resp.status == 400


# ---------------------------------------------------------------------------
# Mesh peer federation tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_mesh_connect_rejects_wrong_token(ws_client) -> None:
    """POST /mesh/peer/connect returns 403 with wrong token."""
    import server as _s
    _s._MESH_TOKEN = "correct-token"
    resp = await ws_client.post(
        "/mesh/peer/connect",
        json={"token": "wrong", "peer_url": "http://peer.onion", "peer_token": "x"},
    )
    assert resp.status == 403


@pytest.mark.asyncio
async def test_mesh_connect_registers_peer(ws_client) -> None:
    """POST /mesh/peer/connect registers a peer and returns peer_id."""
    import server as _s
    _s._MESH_TOKEN = "test-mesh-secret"
    resp = await ws_client.post(
        "/mesh/peer/connect",
        json={"token": "test-mesh-secret", "peer_url": "http://peer.onion", "peer_token": "pt"},
    )
    assert resp.status == 200
    data = await resp.json()
    assert data["ok"] is True
    assert "peer_id" in data
    # Clean up
    _s._mesh_peers.clear()


@pytest.mark.asyncio
async def test_mesh_forward_rejects_unknown_token(ws_client) -> None:
    """POST /mesh/peer/forward returns 403 for unregistered peer token."""
    import server as _s
    _s._mesh_peers.clear()
    resp = await ws_client.post(
        "/mesh/peer/forward",
        json={"token": "unknown", "room_id": "room1", "payload": "{}"},
    )
    assert resp.status == 403


@pytest.mark.asyncio
async def test_mesh_invite_requires_auth(ws_client) -> None:
    """GET /mesh/invite returns 403 without admin session."""
    resp = await ws_client.get("/mesh/invite")
    assert resp.status == 403


@pytest.mark.asyncio
async def test_inbox_create_returns_mailtm_enabled_field(ws_client) -> None:
    """POST /inbox/create returns mailtm_enabled field (False when MAILTM_ENABLED=False)."""
    import server as _s
    original = _s.MAILTM_ENABLED
    try:
        _s.MAILTM_ENABLED = False
        resp = await ws_client.post("/inbox/create", json={})
        data = await resp.json()
        assert "mailtm_enabled" in data
        assert data["mailtm_enabled"] is False
    finally:
        _s.MAILTM_ENABLED = original


# ---------------------------------------------------------------------------
# Outbound proxy helper tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_build_session_direct_returns_session() -> None:
    """_build_session with empty proxy_url returns a plain aiohttp session."""
    import server as _s
    sess = _s._build_session("", 5.0)
    assert sess is not None
    await sess.close()


@pytest.mark.asyncio
async def test_build_session_with_socks5_url() -> None:
    """_build_session with a socks5:// URL returns a session (may fail on connect later)."""
    import server as _s
    sess = _s._build_session("socks5://127.0.0.1:9050", 5.0)
    assert sess is not None
    await sess.close()


@pytest.mark.asyncio
async def test_make_proxied_session_returns_session() -> None:
    """_make_proxied_session() always returns a usable aiohttp ClientSession."""
    import server as _s
    # Force re-probe on this call by expiring the cache
    _s._proxy_cache_ts = 0.0
    _s._proxy_cache = ""
    sess = await _s._make_proxied_session(timeout=3.0)
    assert sess is not None
    await sess.close()


# ---------------------------------------------------------------------------
# mail.tm clearnet-deliverable tests (mocked network)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_inbox_create_mailtm_mocked(ws_client) -> None:
    """When _mailtm_provision is mocked to succeed, POST /inbox/create returns
    mailtm_enabled=True and a real @domain address (not @localhost)."""
    import server as _s

    fake_domain   = "testdomain.example"
    fake_address  = f"abcdef1234567890@{fake_domain}"
    fake_bearer   = "jwt-test-token"

    orig_enabled   = _s.MAILTM_ENABLED
    orig_provision = _s._mailtm_provision

    async def _mock_provision(token_bytes: int):
        return {
            "mailtm_address": fake_address,
            "mailtm_bearer":  fake_bearer,
            "mailtm_seen":    set(),
        }

    try:
        _s.MAILTM_ENABLED   = True
        _s._mailtm_provision = _mock_provision

        resp = await ws_client.post("/inbox/create", json={"ttl_minutes": 30})
        assert resp.status == 200
        body = await resp.json()

        # Must be flagged as a real clearnet-deliverable address
        assert body["mailtm_enabled"] is True

        # Address must be the one returned by mail.tm, not token@localhost
        assert body["address"] == fake_address
        assert "@" in body["address"]
        local, domain = body["address"].split("@", 1)
        assert domain == fake_domain       # real domain, not "localhost"
        assert len(local) >= 8             # non-trivial local part

        # Standard fields still present
        assert body["drop_url"].startswith("/inbox/")
        assert body["read_url"].startswith("/inbox/")
        assert "expires_at" in body
    finally:
        _s.MAILTM_ENABLED   = orig_enabled
        _s._mailtm_provision = orig_provision


@pytest.mark.asyncio
async def test_inbox_create_mailtm_fallback_when_unavailable(ws_client) -> None:
    """When _mailtm_provision returns None (network error), inbox still
    succeeds and mailtm_enabled is False — no crash."""
    import server as _s

    orig_enabled   = _s.MAILTM_ENABLED
    orig_provision = _s._mailtm_provision

    async def _mock_fail(_: int):
        return None  # simulates unreachable mail.tm

    try:
        _s.MAILTM_ENABLED   = True
        _s._mailtm_provision = _mock_fail

        resp = await ws_client.post("/inbox/create", json={"ttl_minutes": 30})
        assert resp.status == 200
        body = await resp.json()

        # Fallback: still works, but address is not a real mail.tm address
        assert body["mailtm_enabled"] is False
        assert "@" in body["address"]
    finally:
        _s.MAILTM_ENABLED   = orig_enabled
        _s._mailtm_provision = orig_provision


# ---------------------------------------------------------------------------
# Clearnet URL path tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_clearnet_path_is_100_chars(ws_client) -> None:
    """_CLEARNET_PATH is exactly 100 URL-safe characters after build_app() is called."""
    import server as _s
    import re as _re
    path = _s._CLEARNET_PATH
    assert len(path) == 100, f"Expected 100 chars, got {len(path)}"
    assert _re.fullmatch(r"[A-Za-z0-9_-]+", path), "Path contains non-URL-safe characters"


@pytest.mark.asyncio
async def test_clearnet_path_serves_index(ws_client) -> None:
    """GET /<clearnet-path>/ returns the chat index page (HTTP 200, text/html)."""
    import server as _s
    path = _s._CLEARNET_PATH
    resp = await ws_client.get(f"/{path}/")
    assert resp.status == 200
    ct = resp.headers.get("Content-Type", "")
    assert "text/html" in ct


@pytest.mark.asyncio
async def test_clearnet_path_serves_index_without_trailing_slash(ws_client) -> None:
    """GET /<clearnet-path> (no trailing slash) also returns the chat page."""
    import server as _s
    path = _s._CLEARNET_PATH
    resp = await ws_client.get(f"/{path}", allow_redirects=False)
    assert resp.status in (200, 301, 302), (
        f"Expected 200 or redirect, got {resp.status}"
    )


@pytest.mark.asyncio
async def test_clearnet_path_is_different_from_admin_path(ws_client) -> None:
    """Clearnet path must not collide with the admin panel path."""
    import server as _s
    assert _s._CLEARNET_PATH != _s._ADMIN_PATH


def test_free_socks5_proxies_count() -> None:
    """_FREE_SOCKS5_PROXIES must have exactly 6 entries for the 6-proxy chain."""
    import server as _s
    assert len(_s._FREE_SOCKS5_PROXIES) == 6, (
        f"Expected 6 proxies, got {len(_s._FREE_SOCKS5_PROXIES)}"
    )


def test_free_socks5_proxies_all_valid_urls() -> None:
    """Every entry in _FREE_SOCKS5_PROXIES must start with socks5://."""
    import server as _s
    for url in _s._FREE_SOCKS5_PROXIES:
        assert url.startswith("socks5://"), f"Not a socks5:// URL: {url}"


@pytest.mark.asyncio
async def test_probe_clearnet_exit_ip_prints_ip(capsys) -> None:
    """_probe_clearnet_exit_ip() prints the exit IP when the proxy responds."""
    import server as _s
    from unittest.mock import AsyncMock, MagicMock, patch

    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.text = AsyncMock(return_value="1.2.3.4\n")
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=False)

    mock_sess = MagicMock()
    mock_sess.get = MagicMock(return_value=mock_resp)
    mock_sess.__aenter__ = AsyncMock(return_value=mock_sess)
    mock_sess.__aexit__ = AsyncMock(return_value=False)

    with patch.object(_s, "_build_session", return_value=mock_sess):
        await _s._probe_clearnet_exit_ip()

    captured = capsys.readouterr()
    assert "1.2.3.4" in captured.out
    assert "Exit IP" in captured.out


@pytest.mark.asyncio
async def test_probe_clearnet_exit_ip_handles_failure(capsys) -> None:
    """_probe_clearnet_exit_ip() prints a warning when all services fail."""
    import server as _s
    from unittest.mock import patch

    def _bad_session(*_a, **_kw):
        raise RuntimeError("no network")

    with patch.object(_s, "_build_session", side_effect=_bad_session):
        await _s._probe_clearnet_exit_ip()

    captured = capsys.readouterr()
    assert "Exit IP" in captured.out
    assert "could not reach" in captured.out.lower() or "Could not reach" in captured.out


def test_init_clearnet_path_console_no_full_url_hint(capsys) -> None:
    """_init_clearnet_path() must NOT print the old 'Full URL hint' placeholder line."""
    import server as _s
    import os

    # Use a fixed path so we can inspect output without randomness
    orig = os.environ.get("CLEARNET_PATH", "")
    os.environ["CLEARNET_PATH"] = "x" * 100
    try:
        _s._init_clearnet_path()
    finally:
        if orig:
            os.environ["CLEARNET_PATH"] = orig
        else:
            os.environ.pop("CLEARNET_PATH", None)

    captured = capsys.readouterr()
    # Old broken line must be gone
    assert "Full URL hint" not in captured.out
    assert "http://<your-public-ip>" not in captured.out
    # New clean lines must be present
    assert "Secret path" in captured.out
    assert "Proxy chain" in captured.out


@pytest.mark.asyncio
async def test_probe_clearnet_exit_ip_uses_last_proxy(capsys) -> None:
    """_probe_clearnet_exit_ip passes _FREE_SOCKS5_PROXIES[-1] to _build_session."""
    import server as _s
    from unittest.mock import AsyncMock, MagicMock, patch

    called_with: list = []

    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.text = AsyncMock(return_value="9.8.7.6")
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=False)

    mock_sess = MagicMock()
    mock_sess.get = MagicMock(return_value=mock_resp)
    mock_sess.__aenter__ = AsyncMock(return_value=mock_sess)
    mock_sess.__aexit__ = AsyncMock(return_value=False)

    def _capture_build_session(proxy_url: str, timeout: float):
        called_with.append(proxy_url)
        return mock_sess

    with patch.object(_s, "_build_session", side_effect=_capture_build_session):
        await _s._probe_clearnet_exit_ip()

    expected = _s._FREE_SOCKS5_PROXIES[-1]
    assert called_with, "_build_session was never called"
    assert called_with[0] == expected, (
    )


# ---------------------------------------------------------------------------
# Proxy watchdog and health-check tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_proxy_watchdog_marks_offline_and_invalidates_cache(capsys) -> None:
    """_proxy_watchdog_task marks a proxy offline and clears the proxy cache."""
    import server as _s
    from unittest.mock import patch, AsyncMock
    import asyncio as _asyncio

    # Simulate all free proxies failing
    probe_calls: list[str] = []

    async def _always_offline(proxy_url: str, timeout: float = 5.0) -> bool:
        probe_calls.append(proxy_url)
        return False

    # Initialise health as all online so we see the state change
    original_health = dict(_s._proxy_health)
    original_cache = _s._proxy_cache
    original_cache_ts = _s._proxy_cache_ts
    for p in _s._FREE_SOCKS5_PROXIES:
        _s._proxy_health[p] = True
    _s._proxy_cache = _s._FREE_SOCKS5_PROXIES[0]
    _s._proxy_cache_ts = 9e18  # far in the future

    try:
        # Patch sleep: first call returns normally (runs the loop body),
        # second call raises CancelledError to stop the loop.
        call_count = 0

        async def _sleep_once(_secs):
            nonlocal call_count
            call_count += 1
            if call_count > 1:
                raise _asyncio.CancelledError

        with patch("server.asyncio.sleep", side_effect=_sleep_once), \
             patch.object(_s, "_probe_proxy", side_effect=_always_offline):
            try:
                await _s._proxy_watchdog_task()
            except _asyncio.CancelledError:
                pass

        # _probe_proxy must have been called once per proxy in _FREE_SOCKS5_PROXIES
        assert len(probe_calls) == len(_s._FREE_SOCKS5_PROXIES), (
            f"Expected {len(_s._FREE_SOCKS5_PROXIES)} probe calls, got {len(probe_calls)}"
        )
        for p in _s._FREE_SOCKS5_PROXIES:
            assert p in probe_calls, f"_probe_proxy was not called for {p}"

        # All proxies should now be marked offline
        for p in _s._FREE_SOCKS5_PROXIES:
            assert _s._proxy_health.get(p) is False, f"Expected {p} to be offline"
        # Cache should have been invalidated
        assert _s._proxy_cache == ""
        assert _s._proxy_cache_ts == 0.0

        captured = capsys.readouterr()
        assert "OFFLINE" in captured.out
    finally:
        _s._proxy_health.clear()
        _s._proxy_health.update(original_health)
        _s._proxy_cache = original_cache
        _s._proxy_cache_ts = original_cache_ts


@pytest.mark.asyncio
async def test_make_proxied_session_skips_offline_proxy() -> None:
    """_make_proxied_session skips proxies marked offline in _proxy_health."""
    import server as _s
    from unittest.mock import patch

    original_health = dict(_s._proxy_health)
    original_cache = _s._proxy_cache
    original_cache_ts = _s._proxy_cache_ts
    try:
        # Mark all free proxies offline
        for p in _s._FREE_SOCKS5_PROXIES:
            _s._proxy_health[p] = False
        # Invalidate the proxy cache so _make_proxied_session re-probes
        _s._proxy_cache = ""
        _s._proxy_cache_ts = 0.0

        probed: list[str] = []

        async def _track_probe(proxy_url: str, timeout: float = 5.0) -> bool:
            probed.append(proxy_url)
            return proxy_url == ""  # only direct succeeds

        with patch.object(_s, "_probe_proxy", side_effect=_track_probe):
            sess = await _s._make_proxied_session(timeout=5.0)
            await sess.close()

        # No offline proxy should have been probed
        for p in _s._FREE_SOCKS5_PROXIES:
            assert p not in probed, f"Offline proxy {p} was probed — should have been skipped"
        # Direct (empty string) should have been chosen
        assert _s._proxy_cache == ""
    finally:
        _s._proxy_health.clear()
        _s._proxy_health.update(original_health)
        _s._proxy_cache = original_cache
        _s._proxy_cache_ts = original_cache_ts


@pytest.mark.asyncio
async def test_probe_clearnet_exit_ip_skips_offline_uses_online(capsys) -> None:
    """_probe_clearnet_exit_ip skips offline proxies and uses the first online one."""
    import server as _s
    from unittest.mock import AsyncMock, MagicMock, patch

    original_health = dict(_s._proxy_health)
    try:
        # Mark all but the first proxy offline
        for p in _s._FREE_SOCKS5_PROXIES:
            _s._proxy_health[p] = False
        _s._proxy_health[_s._FREE_SOCKS5_PROXIES[0]] = True

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value="5.6.7.8")
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_sess = MagicMock()
        mock_sess.get = MagicMock(return_value=mock_resp)
        mock_sess.__aenter__ = AsyncMock(return_value=mock_sess)
        mock_sess.__aexit__ = AsyncMock(return_value=False)

        with patch.object(_s, "_build_session", return_value=mock_sess):
            await _s._probe_clearnet_exit_ip()

        captured = capsys.readouterr()
        assert "5.6.7.8" in captured.out
        assert "Exit IP" in captured.out
    finally:
        _s._proxy_health.clear()
        _s._proxy_health.update(original_health)


def test_proxy_health_dict_exists() -> None:
    """_proxy_health and _proxy_watchdog_task must be defined in server.py."""
    import server as _s
    assert isinstance(_s._proxy_health, dict)
    assert callable(_s._proxy_watchdog_task)
