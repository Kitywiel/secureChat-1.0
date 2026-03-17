"""
Tests for local_mesh.py — the local-instance hub.

Covers:
- Instance registration and unregistration
- Chat message fanout (/local/forward)
- Cluster stats aggregation (/local/stats)
"""

from __future__ import annotations

import pytest
import pytest_asyncio

from local_mesh import build_local_mesh_app, _instances


@pytest.fixture
def local_mesh_app():
    """Return a fresh local-mesh hub application with a clean instance registry."""
    _instances.clear()
    app = build_local_mesh_app()
    yield app
    _instances.clear()


@pytest_asyncio.fixture
async def hub_client(local_mesh_app, aiohttp_client):
    return await aiohttp_client(local_mesh_app)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_register_adds_instance(hub_client) -> None:
    """POST /local/register stores the instance and returns ok."""
    resp = await hub_client.post(
        "/local/register",
        json={"instance_id": "aabbccdd", "url": "http://127.0.0.1:5000"},
    )
    assert resp.status == 200
    data = await resp.json()
    assert data["ok"] is True
    assert "aabbccdd" in _instances
    assert _instances["aabbccdd"]["url"] == "http://127.0.0.1:5000"


@pytest.mark.asyncio
async def test_register_missing_fields_returns_400(hub_client) -> None:
    """POST /local/register with missing url or instance_id returns 400."""
    resp = await hub_client.post(
        "/local/register",
        json={"instance_id": "only-id"},
    )
    assert resp.status == 400


@pytest.mark.asyncio
async def test_unregister_removes_instance(hub_client) -> None:
    """DELETE /local/register/{id} removes the instance from the registry."""
    _instances["xyzwtest"] = {"url": "http://127.0.0.1:5001", "registered_at": 0.0}
    resp = await hub_client.delete("/local/register/xyzwtest")
    assert resp.status == 200
    assert "xyzwtest" not in _instances


@pytest.mark.asyncio
async def test_unregister_unknown_id_is_ok(hub_client) -> None:
    """DELETE /local/register/{unknown} returns 200 (idempotent)."""
    resp = await hub_client.delete("/local/register/nonexistent-id")
    assert resp.status == 200


# ---------------------------------------------------------------------------
# Message fanout
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_forward_missing_room_id_returns_400(hub_client) -> None:
    """POST /local/forward without room_id returns 400."""
    resp = await hub_client.post(
        "/local/forward",
        json={"from_instance": "aaa", "payload": "{}"},
    )
    assert resp.status == 400


@pytest.mark.asyncio
async def test_forward_missing_payload_returns_400(hub_client) -> None:
    """POST /local/forward without payload returns 400."""
    resp = await hub_client.post(
        "/local/forward",
        json={"from_instance": "aaa", "room_id": "myroom"},
    )
    assert resp.status == 400


@pytest.mark.asyncio
async def test_forward_with_no_instances_returns_ok(hub_client) -> None:
    """POST /local/forward with no registered instances returns ok (nothing to fan out)."""
    _instances.clear()
    resp = await hub_client.post(
        "/local/forward",
        json={"from_instance": "aaa", "room_id": "room1", "payload": "{}"},
    )
    assert resp.status == 200
    data = await resp.json()
    assert data["ok"] is True


@pytest.mark.asyncio
async def test_forward_excludes_sender(hub_client) -> None:
    """POST /local/forward must not fan out to the sending instance.

    We register the sender and verify that only the *other* instance would
    be in the fanout target list (we mock the HTTP call to check).
    """
    import asyncio
    from unittest.mock import patch, AsyncMock, MagicMock

    received_urls: list[str] = []

    class _FakeResp:
        status = 200
        async def __aenter__(self): return self
        async def __aexit__(self, *_): pass

    class _FakeSess:
        def post(self, url, **kwargs):
            received_urls.append(url)
            return _FakeResp()
        async def __aenter__(self): return self
        async def __aexit__(self, *_): pass

    _instances.clear()
    _instances["sender-id"] = {"url": "http://127.0.0.1:5000", "registered_at": 0.0}
    _instances["other-id"]  = {"url": "http://127.0.0.1:5001", "registered_at": 0.0}

    with patch("local_mesh.aiohttp.ClientSession", return_value=_FakeSess()):
        resp = await hub_client.post(
            "/local/forward",
            json={
                "from_instance": "sender-id",
                "room_id":       "roomXYZ",
                "payload":       '{"type":"message"}',
            },
        )
        assert resp.status == 200
        # Give ensure_future a chance to run
        await asyncio.sleep(0.05)

    # The sender should NOT be in the fanout targets
    assert not any("5000" in u for u in received_urls), \
        "Sender's URL should NOT be in fanout targets"
    # The other instance SHOULD have received it
    assert any("5001" in u for u in received_urls), \
        "Other instance should have received the fanout"


# ---------------------------------------------------------------------------
# Cluster stats
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_stats_returns_empty_when_no_instances(hub_client) -> None:
    """GET /local/stats returns an empty instances list when no instances are registered."""
    _instances.clear()
    resp = await hub_client.get("/local/stats")
    assert resp.status == 200
    data = await resp.json()
    assert "instances" in data
    assert data["instances"] == []


@pytest.mark.asyncio
async def test_stats_marks_unreachable_instance_as_not_ok(hub_client) -> None:
    """GET /local/stats marks an instance that refuses connections as ok=False."""
    _instances.clear()
    # Register an instance on a port nothing is listening on
    _instances["dead-instance"] = {
        "url": "http://127.0.0.1:19999",
        "registered_at": 0.0,
    }
    resp = await hub_client.get("/local/stats")
    assert resp.status == 200
    data = await resp.json()
    assert len(data["instances"]) == 1
    entry = data["instances"][0]
    assert entry["instance_id"] == "dead-instance"
    assert entry["ok"] is False
    assert "error" in entry
