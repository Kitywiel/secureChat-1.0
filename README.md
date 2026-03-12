
# secureChat-1.0

A lightweight **end-to-end encrypted (E2EE) chat service** designed to run on
[OnionShare](https://onionshare.org/) or any Tor hidden service, so
conversations stay private even from the server operator.

---

## How it works

```
Browser A                    Server (relay)                 Browser B
─────────────────────────────────────────────────────────────────────
  derive key (PBKDF2)                                  derive key (PBKDF2)
  encrypt msg (AES-GCM)  ──► routes ciphertext ──►  decrypt msg (AES-GCM)
```

* **Key derivation** — each participant derives the same AES-GCM-256 key
  locally from the shared *passphrase* + *room ID* using PBKDF2-SHA-256
  (600 000 iterations, OWASP recommended minimum).
* **Encryption** — every message is encrypted in the browser with a fresh
  random 12-byte IV before it is sent; only the ciphertext reaches the server.
* **The server never has your key** — it only routes `{iv, ciphertext,
  displayName}` tuples.  Even if the server is compromised, message content
  remains private.
* **Persistent history** — the server stores encrypted messages in a local
  SQLite database.  When you (re)join a room, the last 100 messages are
  replayed and decrypted in your browser — so you can catch up after a server
  restart or after closing the tab.

---

## Quick start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Run the server

```bash
python server.py
```

By default the server listens on `127.0.0.1:5000`.  Open
`http://127.0.0.1:5000` in your browser to test locally.

Environment variables:

| Variable        | Default            | Description                                     |
|-----------------|--------------------|-------------------------------------------------|
| `HOST`          | `127.0.0.1`        | Interface to bind                               |
| `PORT`          | `5000`             | TCP port                                        |
| `DB_PATH`       | `./securechat.db`  | Path to the SQLite message store                |
| `HISTORY_LIMIT` | `100`              | Max messages stored and replayed per room       |

---

## Running on OnionShare

OnionShare can expose any local TCP service as a `.onion` address.

### Using the OnionShare GUI

1. Open OnionShare → **"Host a Service"** tab (or use the *Custom* mode).
2. Choose **"Connect to server"** and point it at `127.0.0.1:5000`.
3. Start the OnionShare service — it will display a `.onion` URL.
4. Share the `.onion` URL, the **Room ID**, and the **Passphrase** with your
   contact (through a secure side-channel).

### Using the OnionShare CLI

```bash
# Start secureChat in one terminal
python server.py

# Expose it via OnionShare CLI in another terminal
onionshare --connect-to 127.0.0.1:5000
```

### Manual Tor hidden service

Add the following to your `torrc` and restart Tor:

```
HiddenServiceDir /var/lib/tor/securechat/
HiddenServicePort 80 127.0.0.1:5000
```

The `.onion` address will be in `/var/lib/tor/securechat/hostname`.

---

## Usage

1. Both parties visit the `.onion` URL (or `http://127.0.0.1:5000` for local
   testing) in **Tor Browser** (or any browser for local use).
2. Enter the same **Room ID** and **Passphrase**.
3. Chat — all messages are encrypted before they leave your browser.

> ⚠️ The Room ID and Passphrase must be shared with your contact through a
> separate secure channel *before* you start chatting.

---

## Running tests

```bash
pip install pytest pytest-asyncio aiohttp
pytest tests/
```

---

## Security model

| Threat                            | Mitigation                                          |
|-----------------------------------|-----------------------------------------------------|
| Server reads messages             | Server only sees ciphertext; key never leaves client|
| Server reads stored history       | SQLite stores only ciphertext; server cannot decrypt|
| Server logs traffic               | Access log disabled                                 |
| Weak passphrase                   | PBKDF2-SHA-256, 600 000 iterations                  |
| IV reuse                          | Fresh `crypto.getRandomValues(12 bytes)` per message|
| XSS via display names / messages  | All text set via `textContent`, never `innerHTML`   |
| Path traversal in room IDs        | Allowlist regex `[A-Za-z0-9_-]{1,64}`               |
| Traffic analysis / metadata       | Use Tor Browser + OnionShare to hide IP and timing  |

---

## Project structure

```
secureChat-1.0/
├── server.py          # aiohttp HTTP + WebSocket relay server
├── requirements.txt   # Python dependencies
├── static/
│   ├── index.html     # Chat UI (lobby + chat screens)
│   ├── app.js         # E2EE crypto (Web Crypto API) + WebSocket client
│   └── style.css      # Dark theme
└── tests/
    └── test_server.py # pytest test suite
```
