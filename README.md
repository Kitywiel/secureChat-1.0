
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

## Requirements

* **Python 3.9 or newer** — download from <https://www.python.org/downloads/>
  (on Windows, tick *"Add python.exe to PATH"* during installation)
* The packages listed in `requirements.txt` (installed automatically by
  `start_server.bat` or manually with `pip install -r requirements.txt`)

---

## Quick start — Windows

### Option A — double-click launcher (recommended)

1. Make sure Python 3.9+ is installed and on your `PATH`.
2. Double-click **`start_server.bat`** in the project folder.
   The script installs dependencies automatically and starts the server.
3. You should see:
   ```
   secureChat is starting on http://127.0.0.1:5000
   ```
4. Open `http://127.0.0.1:5000` in your browser to test locally.

### Option B — Command Prompt

```cmd
cd path\to\secureChat-1.0
pip install -r requirements.txt
python server.py
```

### Option C — PowerShell

```powershell
cd path\to\secureChat-1.0
pip install -r requirements.txt
python server.py
```

### Changing settings on Windows

Use `set` (Command Prompt) or `$env:` (PowerShell) before starting the server:

**Command Prompt:**
```cmd
set PORT=8080
set HISTORY_LIMIT=200
python server.py
```

**PowerShell:**
```powershell
$env:PORT = "8080"
$env:HISTORY_LIMIT = "200"
python server.py
```

---

## Quick start — Linux / macOS

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

---

## Environment variables

| Variable        | Default                       | Description                               |
|-----------------|-------------------------------|-------------------------------------------|
| `HOST`          | `127.0.0.1`                   | Interface to bind                         |
| `PORT`          | `5000`                        | TCP port                                  |
| `DB_PATH`       | `securechat.db` (beside `server.py`) | Path to the SQLite message store |
| `HISTORY_LIMIT` | `100`                         | Max messages stored and replayed per room |

---

## Exposing secureChat over Tor (hidden service)

Running secureChat behind a Tor hidden service hides the server's IP address
from users and gives everyone a `.onion` URL to connect to.

> **Note — OnionShare limitation:** OnionShare (GUI and CLI) is a file-sharing
> and static-website tool.  It **cannot** proxy arbitrary TCP/WebSocket
> traffic to a running Python server.  The `onionshare-cli` command has no
> `--connect-to` flag; you must configure a Tor hidden service directly as
> shown below.

### Step 1 — start secureChat

Double-click `start_server.bat` (or run `python server.py` in a terminal).
Keep this window open; the server must stay running.

### Step 2 — configure a Tor hidden service

#### Windows (Tor Browser)

1. Install [Tor Browser](https://www.torproject.org/download/) if you haven't
   already.
2. Open the `torrc` configuration file.  With a default Tor Browser install on
   Windows it is usually at:
   ```
   C:\Users\<YourUsername>\Desktop\Tor Browser\Browser\TorBrowser\Data\Tor\torrc
   ```
3. Add the following two lines at the end of the file:
   ```
   HiddenServiceDir C:\Users\<YourUsername>\AppData\Roaming\tor\securechat
   HiddenServicePort 80 127.0.0.1:5000
   ```
   Replace `<YourUsername>` with your Windows username.  Tor will create the
   `securechat` directory automatically on first run.
4. Start (or restart) Tor Browser.  Tor will generate a `.onion` address and
   write it to:
   ```
   C:\Users\<YourUsername>\AppData\Roaming\tor\securechat\hostname
   ```
   Open that file in Notepad to read your `.onion` URL.

#### Windows (Tor Expert Bundle)

If you installed the [Tor Expert Bundle](https://www.torproject.org/download/tor/)
instead of Tor Browser, add the same two lines to the `torrc` file you use
with `tor.exe` and restart Tor:

```cmd
tor.exe -f torrc
```

#### Linux / macOS

Add the following to `/etc/tor/torrc` (or `~/.torrc`) and restart Tor:

```
HiddenServiceDir /var/lib/tor/securechat/
HiddenServicePort 80 127.0.0.1:5000
```

```bash
sudo systemctl restart tor   # systemd
# or
brew services restart tor    # macOS Homebrew
```

The `.onion` address will be in `/var/lib/tor/securechat/hostname`.

### Step 3 — share access details

Send your contacts (through a separate secure channel) all three pieces of
information they need to connect:

| What         | Where to find it                           |
|--------------|--------------------------------------------|
| `.onion` URL | in the `hostname` file created by Tor      |
| Room ID      | you choose — any alphanumeric string       |
| Passphrase   | you choose — the shared encryption key     |

### Step 4 — connect

Both parties open the `.onion` URL in **Tor Browser**, enter the same Room ID
and Passphrase, and start chatting.

---

## Usage

1. Both parties visit the `.onion` URL (or `http://127.0.0.1:5000` for local
   testing) in **Tor Browser** (or any browser for local use).
2. Enter the same **Room ID** and **Passphrase**.
3. Chat — all messages are encrypted before they leave your browser.
4. When you rejoin after the server restarts, the last 100 messages will be
   replayed and decrypted automatically in your browser.

> ⚠️ The Room ID and Passphrase must be shared with your contact through a
> separate secure channel *before* you start chatting.

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
| Traffic analysis / metadata       | Use Tor Browser + Tor hidden service to hide IP and timing  |

---

## Project structure

```
secureChat-1.0/
├── server.py          # aiohttp HTTP + WebSocket relay server
├── start_server.bat   # Windows one-click launcher
├── requirements.txt   # Python dependencies
├── static/
│   ├── index.html     # Chat UI (lobby + chat screens)
│   ├── app.js         # E2EE crypto (Web Crypto API) + WebSocket client
│   └── style.css      # Dark theme
└── tests/
    └── test_server.py # pytest test suite
```

