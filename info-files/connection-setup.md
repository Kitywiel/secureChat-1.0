# secureChat — Connection Setup Guide

This guide explains how to connect two or more secureChat instances together
so that users on different servers can chat in the same rooms (mesh federation).

---

## Zero-Config Quick Start

1. Start the server:
   ```
   python run.py
   ```
2. A `.onion` URL is printed at startup (requires Tor to be installed).
3. Share the `.onion` URL with the other party — they open it in Tor Browser.

No accounts, no DNS, no certificates, no port-forwarding needed.

---

## Connecting Two Servers (Mesh)

When you run two separate secureChat instances (on different machines or
networks), you can link them so that messages in any shared room are relayed
between both servers.

### Step 1 — Start both servers

```
# Server A
python run.py --port 5000

# Server B
python run.py --port 5001
```

Each server prints its `.onion` URL and `MESH_TOKEN` at startup.

### Step 2 — Join the mesh

On Server B, run:
```
python run.py --mesh-join http://<Server-A-onion>/mesh/peer/connect \
              --mesh-token <Server-A-MESH_TOKEN>
```

Or set the values in a `.env` file (see `.env.example`):
```
MESH_JOIN=http://<Server-A-onion>/mesh/peer/connect
MESH_TOKEN=<Server-A-MESH_TOKEN>
```

### Step 3 — Done

Both servers will now relay messages to each other.  Any room open on both
servers will share messages in real time.

---

## Tor Setup

secureChat uses Tor to create a hidden-service `.onion` URL that works from
anywhere in the world without exposing your IP address.

### Linux / macOS

```bash
# Debian/Ubuntu
sudo apt install tor

# Fedora / RHEL
sudo dnf install tor

# macOS (Homebrew)
brew install tor
```

Restart your server after installing Tor.

### Windows

`run.py` automatically downloads the Tor Expert Bundle from
`dist.torproject.org` on Windows if Tor is not already installed.

Alternatively, install [Tor Browser](https://www.torproject.org/download/)
and the bundled `tor.exe` will be detected automatically.

### Custom Tor path

Set `TOR_PATH` in your `.env` file:
```
TOR_PATH=/path/to/tor
```

### Disabling Tor

Set `NO_TOR=1` in your `.env` file or pass `--no-tor` on the command line.

---

## LAN / Local Network

Without Tor, the server binds to `0.0.0.0` (all interfaces) and prints its
LAN IP at startup.  Other devices on the same network can connect using the
printed URL.

---

## Port Forwarding (Advanced)

If you want to expose secureChat over the clearnet without Tor:

1. Forward the chosen port (default `5000`) on your router.
2. Start with `--no-tor`.
3. Use the printed LAN IP or your public IP to connect.

> ⚠️  **Warning:** This exposes your public IP to all clients.  Using a
> `.onion` address is strongly recommended for privacy.

---

## Environment Variables

All configuration can be set in a `.env` file next to `run.py`.
See `.env.example` for a full list of supported options.
