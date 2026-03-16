#!/usr/bin/env python3
"""
local_mesh.py — Local mesh hub for multiple secureChat instances on the same machine.

Runs on 127.0.0.1:LOCAL_MESH_PORT (default 9000) and binds to loopback only so
it is never reachable from the network.

All local server instances register with this hub so they can:
  - Sync chat messages across all URLs instantly (loopback, near-zero latency)
  - Expose aggregated load metrics for the Head admin panel

File sharing across instances uses a shared directory (FILE_STORAGE) that is
written by each server instance directly — the hub is not in the data path for
file I/O.

Usage
-----
    python local_mesh.py                    # port 9000
    LOCAL_MESH_PORT=9001 python local_mesh.py

Environment variables
---------------------
    LOCAL_MESH_PORT   Hub listen port (default: 9000)
    FILE_STORAGE      Shared file storage directory printed at startup for reference
"""

from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path

import aiohttp
from aiohttp import web

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LOCAL_MESH_PORT: int = int(os.environ.get("LOCAL_MESH_PORT", "9000"))
_FILE_STORAGE_PATH = os.environ.get("FILE_STORAGE", "storage")

# Default timeout for outbound HTTP calls to registered instances.
_CLIENT_TIMEOUT_SEC: float = 5.0

# ---------------------------------------------------------------------------
# In-memory registries
# ---------------------------------------------------------------------------

# instance_id → {"url": str, "registered_at": float}
_instances: dict[str, dict] = {}

# ---------------------------------------------------------------------------
# Registration handlers
# ---------------------------------------------------------------------------


async def register_handler(request: web.Request) -> web.Response:
    """POST /local/register — register a local server instance.

    Body::

        {
            "instance_id": "<unique hex>",
            "url":         "http://127.0.0.1:5000",
            "server_name": "<optional display name>"
        }
    """
    try:
        body = await request.json()
    except Exception:
        raise web.HTTPBadRequest(reason="JSON body required")

    instance_id = str(body.get("instance_id", "")).strip()
    url = str(body.get("url", "")).strip().rstrip("/")
    server_name = str(body.get("server_name", "")).strip()

    if not instance_id or not url:
        raise web.HTTPBadRequest(reason="instance_id and url required")

    # Preserve registration time when the instance is re-registering
    # (e.g. after a restart) so the cluster table shows the original join time.
    existing = _instances.get(instance_id)
    registered_at = existing["registered_at"] if existing else time.time()
    _instances[instance_id] = {
        "url": url,
        "server_name": server_name,
        "registered_at": registered_at,
    }
    return web.json_response({"ok": True, "instance_id": instance_id})


async def unregister_handler(request: web.Request) -> web.Response:
    """DELETE /local/register/{instance_id} — unregister a local server instance."""
    instance_id = request.match_info["instance_id"]
    _instances.pop(instance_id, None)
    return web.json_response({"ok": True})


# ---------------------------------------------------------------------------
# Chat message fanout
# ---------------------------------------------------------------------------


async def forward_handler(request: web.Request) -> web.Response:
    """POST /local/forward — fan out a chat message to all other registered instances.

    Body::

        {
            "from_instance": "<sender instance_id>",
            "room_id":       "<room ID>",
            "payload":       "<JSON message string>"
        }

    The hub immediately acknowledges the request and fans out asynchronously.
    """
    try:
        body = await request.json()
    except Exception:
        raise web.HTTPBadRequest(reason="JSON body required")

    from_id = str(body.get("from_instance", "")).strip()
    room_id = str(body.get("room_id", "")).strip()
    payload = str(body.get("payload", "")).strip()

    if not room_id or not payload:
        raise web.HTTPBadRequest(reason="room_id and payload required")

    asyncio.ensure_future(_fanout(from_id, room_id, payload))
    return web.json_response({"ok": True})


async def _fanout(from_id: str, room_id: str, payload: str) -> None:
    """Deliver a message to every registered instance except the sender."""
    targets = [
        (iid, info["url"])
        for iid, info in list(_instances.items())
        if iid != from_id
    ]
    if not targets:
        return
    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=_CLIENT_TIMEOUT_SEC)
    ) as sess:
        for _iid, url in targets:
            try:
                async with sess.post(
                    f"{url}/local-mesh/receive",
                    json={"room_id": room_id, "payload": payload},
                ) as resp:
                    if resp.status >= 400:
                        pass  # instance may be starting up; ignore silently
            except Exception:  # noqa: BLE001
                pass


# ---------------------------------------------------------------------------
# Cluster stats
# ---------------------------------------------------------------------------


async def stats_handler(request: web.Request) -> web.Response:
    """GET /local/stats — poll every registered instance and aggregate stats.

    Each instance exposes ``GET /local-mesh/stats`` (loopback-only).  This
    endpoint collects all responses and returns them as a list so the admin
    panel can display per-instance load figures.
    """
    results: list[dict] = []
    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=_CLIENT_TIMEOUT_SEC)
    ) as sess:
        for iid, info in list(_instances.items()):
            entry: dict = {
                "instance_id": iid,
                "url": info["url"],
                "server_name": info.get("server_name", ""),
                "registered_at": info["registered_at"],
                "ok": False,
            }
            try:
                async with sess.get(f"{info['url']}/local-mesh/stats") as resp:
                    if resp.status == 200:
                        entry.update(await resp.json(content_type=None))
                        entry["ok"] = True
                    else:
                        entry["error"] = f"HTTP {resp.status}"
            except Exception as exc:  # noqa: BLE001
                entry["error"] = str(exc)
            results.append(entry)

    # Compute cluster-wide totals for the admin panel.
    total_inbox_msgs = sum(
        inst.get("inbox_msgs_received_total", 0)
        for inst in results
        if inst.get("ok")
    )

    return web.json_response({
        "instances": results,
        "hub_port": LOCAL_MESH_PORT,
        "file_storage": _FILE_STORAGE_PATH,
        "cluster_inbox_msgs_total": total_inbox_msgs,
    })


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def build_local_mesh_app() -> web.Application:
    """Return the local mesh hub aiohttp Application."""
    app = web.Application()

    app.router.add_post("/local/register", register_handler)
    app.router.add_delete("/local/register/{instance_id}", unregister_handler)
    app.router.add_post("/local/forward", forward_handler)
    app.router.add_get("/local/stats", stats_handler)

    return app


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    host = "127.0.0.1"
    port = LOCAL_MESH_PORT

    storage_abs = Path(_FILE_STORAGE_PATH).resolve()

    print()
    print("=" * 66)
    print("  🕸️   secureChat Local Mesh Hub")
    print(f"  Hub address      : http://{host}:{port}")
    print(f"  Shared storage   : {storage_abs}")
    print()
    print("  Start each server instance with:")
    print(f"    LOCAL_MESH_PORT={port} FILE_STORAGE={_FILE_STORAGE_PATH} python run.py")
    print()
    print("  Instances register automatically on startup.")
    print("  Admin panel → 'Local Cluster' tab shows live instance load.")
    print("  Press Ctrl+C to stop.")
    print("=" * 66)
    print()

    app = build_local_mesh_app()
    web.run_app(app, host=host, port=port, access_log=None)
