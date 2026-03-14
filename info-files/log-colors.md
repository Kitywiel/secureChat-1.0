# secureChat — Log Colours

The server logger uses colour-coded log events in the admin panel's live log
stream and in the server console to make it easy to spot different types of
activity at a glance.

---

## Colour Key

| Colour | Category | Examples |
|--------|----------|---------|
| 🔴 **Red** | Errors | Internal errors, unexpected exceptions, failed operations |
| 🟠 **Orange / Amber** | Warnings | Slow requests, deprecated usage, non-fatal anomalies |
| 🟡 **Yellow** | Security / Rate limits | Login failures, lockout events, forbidden requests |
| 🟢 **Green** | Connections | New WebSocket connections, successful logins, peer joins |
| 🔵 **Blue** | Messages | Chat messages sent/received, room events |
| 🟣 **Purple** | File downloads | Share-download events, file delivery completions |
| 🩷 **Pink** | File uploads | Share-upload events, file receipt confirmations |
| ⚪ **White / Default** | General info | Server start/stop, configuration, background tasks |
| 🔷 **Cyan** | Mesh / Peer | Mesh peer connects, disconnects, forward events |

---

## Log Levels

| Level | Meaning |
|-------|---------|
| `DEBUG` | Verbose diagnostic output (disabled by default) |
| `INFO` | Normal operational events |
| `WARNING` | Non-critical issues worth investigating |
| `ERROR` | Errors that affect a specific request or operation |
| `CRITICAL` | Severe errors; the server may not continue correctly |

---

## Admin Panel Log Stream

The admin panel (`/{admin_path}/`) includes a live SSE log stream that replays
the last 200 log entries to new clients and streams new entries in real time.

Each log line includes:
* Timestamp (ISO 8601, UTC)
* Log level (colour-coded)
* Logger name
* Message

---

## Console Output

The server console (stdout) receives the same colour-coded log output.
Colour codes use ANSI escape sequences and are automatically disabled when
stdout is redirected to a file (non-TTY).
