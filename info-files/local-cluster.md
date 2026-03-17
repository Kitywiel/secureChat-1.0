# secureChat — Local Cluster Guide

Run multiple secureChat instances on **the same machine** and keep them
perfectly in sync.  Every chat message typed into any instance is instantly
visible in all others.  All instances share the same uploaded files.  A single
admin panel governs the whole cluster.

---

## What is the local cluster?

The local cluster is a way to expose one secureChat installation through
**multiple URLs at the same time** — for example a Tor `.onion` address, a
clearnet path, and a LAN address — without any duplicate data or missed
messages.  Each URL is served by its own server process on a different TCP
port.  A tiny hub (`local_mesh.py`) running on the loopback interface
(`127.0.0.1`) ties them together.

```
┌──────────────────────────────────────────────────────┐
│  Same machine (127.0.0.1 only)                       │
│                                                      │
│   run.py (port 5000)  ──┐                            │
│   run.py (port 5001)  ──┤── local_mesh.py (hub)      │
│   run.py (port 5002)  ──┘   port 9000                │
└──────────────────────────────────────────────────────┘
```

The hub **never** listens on the network — it binds to `127.0.0.1` only, so
it is completely invisible to external clients.

---

## Quick start (two-instance example)

```bash
# Terminal 1 — first instance (also auto-starts the hub)
python run.py --port 5000 --local-mesh-port 9000

# Terminal 2 — second instance (joins the hub started by the first)
python run.py --port 5001 --local-mesh-port 9000
```

That's it.  Both instances share the same chat history and uploaded files
automatically.

> **Note**: you do *not* need to start `local_mesh.py` yourself.  The first
> instance to run detects that the hub is not yet listening on the configured
> port and starts it as a background process automatically.  Every subsequent
> instance simply connects to the already-running hub.

---

## How it works — step by step

### 1. Hub auto-start

When `LOCAL_MESH_PORT` is set, `run.py` checks whether the hub port is already
open.  If not, it spawns `local_mesh.py` as a detached background process
(survives terminal close on both Windows and POSIX).

### 2. Shared storage auto-configuration

`run.py` creates a directory called `.cluster_<port>/` next to itself (e.g.
`.cluster_9000/`).  Unless you provide your own values, it sets:

| Path | Used for |
|---|---|
| `.cluster_9000/files/` | `FILE_STORAGE` — all uploaded shared files |
| `.cluster_9000/securechat.db` | `DB_PATH` — the SQLite chat database |

Because all instances point at the same files and database, room history,
uploaded files, and inbox messages are identical regardless of which URL a
client uses.

### 3. Instance registration

On startup each server registers itself with the hub via
`POST /local/register`, sending:
- a stable `instance_id` (persisted in `.local_instance_<port>.id` so it
  survives restarts and the hub never shows stale duplicates)
- the loopback URL (`http://127.0.0.1:<port>`)
- an optional `server_name` (from the `SERVER_NAME` env var)
- whether it is the main server (`MAIN_SERVER=1`)
- the admin-panel URL (only sent by the main server)

On clean shutdown the instance automatically unregisters itself
(`DELETE /local/register/<id>`).

### 4. Chat message fanout

When a user sends a message through instance A, instance A:

1. Saves the message to the shared SQLite database.
2. Posts `POST /local/forward` to the hub with the room ID and the encrypted
   message payload.

The hub immediately fans the message out to every other registered instance
by posting `POST /local-mesh/receive` on each one.  Those instances push the
message to their connected WebSocket clients in real time.  The whole trip
from one browser to another is loopback-only — no Tor, no internet, near-zero
latency.

### 5. Shared file storage

Files are written directly to `FILE_STORAGE` by whichever instance received
the upload.  Because all instances use the same directory, any instance can
serve the download link regardless of which URL the uploader used.  The hub
plays no part in file I/O.

### 6. Stale-instance eviction

The hub polls every registered instance every 30 seconds (via
`GET /local-mesh/stats`).  If an instance does not respond successfully for
`MESH_EVICT_SEC` seconds (default: 120), the hub removes it from the registry
automatically so the cluster table stays clean.

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `LOCAL_MESH_PORT` | not set (disabled) | Port the hub listens on. Set the same value on every instance in the cluster. |
| `FILE_STORAGE` | auto (``.cluster_<port>/files/``) | Shared directory for uploaded files. Set the same path on every instance. |
| `DB_PATH` | auto (``.cluster_<port>/securechat.db``) | Shared SQLite database. Set the same path on every instance. |
| `SERVER_NAME` | not set | Human-readable label shown next to this instance's URL in the admin panel cluster table. |
| `MAIN_SERVER` | not set | Set to `1` on exactly one instance to make it the head node. Non-main instances redirect admin-panel visitors to the head node. |
| `MESH_EVICT_SEC` | `120` | Seconds of silence before the hub evicts a stale instance. |

### CLI equivalents

```bash
python run.py \
  --port 5000 \
  --local-mesh-port 9000 \
  --file-storage /shared/files \
  --server-name node-1
```

---

## Multi-instance `.env` / `start_server.bat` setup

Copy `.env.example` to `.env` on each instance directory (or use separate
`start_server.bat` files) and uncomment the relevant lines.

**Instance 1 (main / head)**

```ini
PORT=5000
LOCAL_MESH_PORT=9000
SERVER_NAME=node-1
MAIN_SERVER=1
```

**Instance 2**

```ini
PORT=5001
LOCAL_MESH_PORT=9000
SERVER_NAME=node-2
```

**Instance 3**

```ini
PORT=5002
LOCAL_MESH_PORT=9000
SERVER_NAME=node-3
```

Because `FILE_STORAGE` and `DB_PATH` are auto-derived from `LOCAL_MESH_PORT`
when not set explicitly, you usually do not need to configure them at all.

---

## Admin panel — Local Cluster tab

Open the admin panel of the main server
(`http://127.0.0.1:5000/<ADMIN_PATH>/`) and click **Local Cluster**.

The tab shows a live table with one row per registered instance:

| Column | Description |
|---|---|
| Instance | URL + `SERVER_NAME` label |
| Status | ✅ online / ⚠️ error |
| CPU / RAM | Per-process resource usage |
| Rooms | Active chat rooms |
| Files | Shared files in storage |
| Inbox | Inbox messages received |
| Joined | Time the instance first registered |

From the same tab you can:
- **Lock down** a single instance or all instances at once.
- **View live logs** of any instance directly in the browser.

Non-main instances (no `MAIN_SERVER=1`) automatically redirect admin-panel
visitors to the main server's admin URL, so you always end up at the central
management panel.

---

## Persistence across restarts

| What | How it persists |
|---|---|
| Instance identity | `.local_instance_<port>.id` next to `server.py` |
| Chat messages & rooms | Shared `securechat.db` |
| Uploaded files | Shared `FILE_STORAGE` directory |
| Auto-generated secrets | `start_server.bat` (Windows) or `.env` (other) |

A restarted instance re-uses the same `instance_id`, so the cluster table
keeps its original join time rather than showing a second entry.

---

## Troubleshooting

**Hub not starting**

Check that `local_mesh.py` is in the same directory as `run.py`.  Run it
manually to see any errors:

```bash
LOCAL_MESH_PORT=9000 python local_mesh.py
```

**Instance shows as offline in the cluster tab**

The hub polls `http://127.0.0.1:<port>/local-mesh/stats`.  Make sure that port
is actually reachable on loopback and that no firewall is blocking loopback
connections.

**Messages not syncing between instances**

Confirm that every instance has the same `LOCAL_MESH_PORT` value and that the
hub is running.  Check the console log of each instance for lines like:

```
local mesh registered  instance=abc123  hub=http://127.0.0.1:9000
```

**Different chat histories on different instances**

The instances are not sharing the same `DB_PATH`.  Either let `run.py` set it
automatically (don't set `DB_PATH` manually) or set it explicitly to the same
path on every instance.

---

## Architecture reference

```
Client A              Instance A (port 5000)      local_mesh.py hub
(browser)  ─WS──────►  ws_handler                  (port 9000)
                        │ save to shared DB           │
                        │ POST /local/forward ────────►│
                        │                             │ fan-out
                                                      │──► Instance B /local-mesh/receive
                                                      │──► Instance C /local-mesh/receive

Instance B (port 5001)                             Client B
  local_mesh_receive_handler ──► WS push ──────► (browser)
```
