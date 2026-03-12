
# secureChat-1.0

A lightweight **end-to-end encrypted (E2EE) chat service** that automatically
creates a **public `.onion` address** so you and your contacts can chat
privately over Tor — no manual Tor configuration required.

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
  (600 000 iterations, OWASP-recommended minimum).
* **Encryption** — every message is encrypted in the browser with a fresh
  random 12-byte IV before it is sent; only the ciphertext reaches the server.
* **The server never has your key** — it only routes `{iv, ciphertext,
  displayName}` tuples.  Even if the server is compromised, message content
  remains private.
* **Persistent history** — the server stores encrypted messages in a local
  SQLite database.  When you (re)join a room, the last 100 messages are
  replayed and decrypted in your browser.
* **Automatic public `.onion` address** — `start_server.bat` finds or
  downloads Tor automatically and creates a Tor hidden service, giving you a
  public `.onion` URL without any manual Tor configuration.

---

## Requirements

* **Python 3.9 or newer** — download from <https://www.python.org/downloads/>
  (on Windows, tick *"Add python.exe to PATH"* during installation)
* The packages listed in `requirements.txt` (installed automatically by
  `start_server.bat`)
* An internet connection **on first run** only (to download Tor and Python
  packages; subsequent runs work offline)

---

## Quick start — Windows (recommended)

### One double-click: everything happens automatically

1. Make sure Python 3.9+ is installed and on your `PATH`.
2. Double-click **`start_server.bat`**.

The script will:
* Install Python dependencies automatically.
* Search for `tor.exe` in common locations (Tor Browser, PATH).
* Download the **Tor Expert Bundle** automatically if Tor is not found.
* Start Tor and create a **Tor hidden service** pointing to the local server.
* Display your public **`.onion` address** in the console window.
* Start the secureChat server.

You will see output similar to:

```
============================================================
  secureChat — starting with Tor hidden service
============================================================
  [Tor] Bootstrapped 100%: Done
  ...
============================================================
  🧅  Your public .onion address:

      http://abcdefghijklmnop.onion

  Share this URL (via a separate secure channel) together
  with the Room ID and Passphrase.  Both parties must
  open it in Tor Browser.
============================================================

  Local access:  http://127.0.0.1:5000

  Press Ctrl+C to stop.
```

3. Share the `.onion` URL, a **Room ID**, and a **Passphrase** with your
   contact through a separate secure channel.
4. Both parties open the `.onion` URL in **Tor Browser**, enter the same
   Room ID and Passphrase, and start chatting.

> **Note:** The `.onion` address is stable — it is stored in `tor_hs/` next
> to the script and stays the same every time you restart.

---

## Quick start — Linux / macOS

### 1. Install Tor

```bash
# Debian / Ubuntu
sudo apt install tor

# Fedora
sudo dnf install tor

# macOS (Homebrew)
brew install tor
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the launcher

```bash
python start_with_tor.py
```

The launcher finds `tor` in your PATH, starts it with a hidden-service
configuration, waits for the `.onion` address, prints it, then starts the
chat server.

Alternatively, run just the server (no Tor):

```bash
python server.py
```

---

## Environment variables

| Variable        | Default                          | Description                               |
|-----------------|----------------------------------|-------------------------------------------|
| `HOST`          | `127.0.0.1`                      | Interface to bind (keep as-is for Tor)    |
| `PORT`          | `5000`                           | TCP port                                  |
| `DB_PATH`       | `securechat.db` (beside `server.py`) | Path to the SQLite message store      |
| `HISTORY_LIMIT` | `100`                            | Max messages stored and replayed per room |

---

## How the Tor hidden service is set up

`start_with_tor.py` (called by `start_server.bat`) handles everything:

1. Searches for `tor.exe` / `tor` in:
   - The local `tor/` sub-directory (previously auto-downloaded)
   - Your system `PATH`
   - Tor Browser's default install location (Windows)
2. If Tor is not found on Windows, downloads the **Tor Expert Bundle** from
   `dist.torproject.org` into the `tor/` sub-directory.
3. Launches Tor with:
   ```
   HiddenServiceDir  tor_hs/
   HiddenServicePort 80 127.0.0.1:5000
   ```
4. Waits for Tor to bootstrap and write `tor_hs/hostname`.
5. Prints the `.onion` address and starts the server.

Both `tor/` and `tor_hs/` are listed in `.gitignore` — they are local
runtime artifacts and are not committed to the repository.

---

## Running tests

```bash
pip install pytest pytest-asyncio aiohttp pytest-aiohttp
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
| Traffic analysis / metadata       | Tor hidden service hides server IP and user IPs     |

---

## Project structure

```
secureChat-1.0/
├── server.py            # aiohttp HTTP + WebSocket relay server
├── start_with_tor.py    # finds/downloads Tor, starts hidden service + server
├── start_server.bat     # Windows one-click launcher (calls start_with_tor.py)
├── requirements.txt     # Python dependencies
├── static/
│   ├── index.html       # Chat UI (lobby + chat screens)
│   ├── app.js           # E2EE crypto (Web Crypto API) + WebSocket client
│   └── style.css        # Dark theme
└── tests/
    └── test_server.py   # pytest test suite
```

Runtime directories created automatically (not committed):

```
tor/        Tor Expert Bundle (Windows auto-download)
tor_data/   Tor's internal data directory
tor_hs/     Hidden-service keys + hostname file (.onion address)
```
