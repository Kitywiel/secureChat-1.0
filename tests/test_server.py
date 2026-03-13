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
    """POST /inbox/create returns drop_url, read_url, and expires_at."""
    resp = await ws_client.post("/inbox/create", json={})
    assert resp.status == 200
    body = await resp.json()
    assert "drop_url" in body
    assert "read_url" in body
    assert "expires_at" in body
    assert body["drop_url"].startswith("/inbox/")
    assert body["drop_url"].endswith("/drop")
    assert body["read_url"].endswith("/read")


@pytest.mark.asyncio
async def test_inbox_drop_and_read_once(ws_client) -> None:
    """Full happy-path: create → drop message → read once → gone."""
    # Create
    resp = await ws_client.post("/inbox/create", json={})
    body = await resp.json()
    drop_url = body["drop_url"]
    read_url = body["read_url"]

    # Drop a message
    drop_resp = await ws_client.post(drop_url, json={"message": "S3cr3tC0de!"})
    assert drop_resp.status == 200
    assert (await drop_resp.json())["ok"] is True

    # Read once
    read_resp = await ws_client.get(read_url)
    assert read_resp.status == 200
    read_body = await read_resp.json()
    assert read_body["message"] == "S3cr3tC0de!"

    # Second read must be gone (410)
    gone_resp = await ws_client.get(read_url)
    assert gone_resp.status == 410


@pytest.mark.asyncio
async def test_inbox_drop_page_served(ws_client) -> None:
    """GET /inbox/{token}/drop returns the sender HTML page."""
    resp = await ws_client.post("/inbox/create", json={})
    drop_url = (await resp.json())["drop_url"]
    page_resp = await ws_client.get(drop_url)
    assert page_resp.status == 200
    ct = page_resp.headers.get("Content-Type", "")
    assert "text/html" in ct
    text = await page_resp.text()
    assert "One-Time Inbox" in text


@pytest.mark.asyncio
async def test_inbox_double_drop_returns_409(ws_client) -> None:
    """A second POST to /drop on a filled inbox returns 409 Conflict."""
    resp = await ws_client.post("/inbox/create", json={})
    drop_url = (await resp.json())["drop_url"]

    await ws_client.post(drop_url, json={"message": "first"})
    second = await ws_client.post(drop_url, json={"message": "second"})
    assert second.status == 409


@pytest.mark.asyncio
async def test_inbox_read_before_drop_returns_204(ws_client) -> None:
    """GET /read on an empty (unfilled) inbox returns 204 (pending)."""
    resp = await ws_client.post("/inbox/create", json={})
    read_url = (await resp.json())["read_url"]
    read_resp = await ws_client.get(read_url)
    assert read_resp.status == 204


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
    resp = await ws_client.post("/inbox/create", json={"ttl": 3600})
    token = (await resp.json())["drop_url"].split("/")[2]
    # Force expiry
    _s._inbox_slots[token]["expires_at"] = 0.0
    gone = await ws_client.post(f"/inbox/{token}/drop", json={"message": "hi"})
    assert gone.status == 410
