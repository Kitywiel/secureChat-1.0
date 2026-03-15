# secureChat — Security Overview

This document describes the security model, protections, and best practices for
operating a secureChat server.

---

## End-to-End Encryption (E2EE)

All chat messages — including files sent in-chat — are encrypted **in the browser
before being sent to the server**.  The server only ever sees opaque ciphertext.

* **Algorithm**: AES-256-GCM
* **Key exchange**: out-of-band (share the room link via a secure channel)
* **IV**: randomly generated per message
* The server never holds plaintext, keys, or IVs in memory or on disk.

---

## Authentication

| Feature | Detail |
|---------|--------|
| Admin panel | Random 100-char passcode + random 200-char URL path, printed once at startup |
| Admin lockout | 10 failures / 15 min → 15-min block; 30 failures / 24 h → 1-h hard block |
| Admin session | Browser-session cookie only (no `max_age`); new login clears all prior sessions |
| Mesh peer | 32-char random token required for every peer connection and forward request |

---

## Mesh Security

* Every mesh peer must authenticate with a secret `MESH_TOKEN`.
* Forwarded payloads are **size-capped** (100 MiB hard limit) to prevent memory exhaustion.
* `room_id` values from peers are validated against a strict alphanumeric regex — prevents injection.
* The `Content-Type` of peer requests must be `application/json` — blocks non-JSON injection vectors.
* Peer payloads are broadcast with `_from_peer=True` which prevents re-forwarding (no loops).

---

## File Sharing

* Uploaded files are stored in a temporary directory with a random one-time token URL.
* Downloads are served with:
  * `Content-Type: application/octet-stream` — no browser-native execution.
  * `Content-Disposition: attachment` — forces a download rather than inline rendering.
  * `X-Content-Type-Options: nosniff` — prevents MIME-type sniffing by browsers.
* Files are deleted from the server immediately after the first successful download.
* Files are **never executed** on the server — the upload endpoint stores raw bytes only.

---

## Network / Transport

* The server is designed to run as a Tor hidden service (`.onion`) so that **no IP
  address is ever exposed** to clients or peers.
* When Tor is unavailable, the server binds to all interfaces on the LAN — keep the
  URL private.
* All outbound mesh/mail calls route through: Tor SOCKS5 → free SOCKS5 → direct.

---

## Input Validation

* All user-supplied strings are length-capped server-side (defence-in-depth).
* Filenames are sanitised before being stored (`_sanitize_filename`).
* Room IDs from mesh peers are validated with a strict `[A-Za-z0-9_\-]{1,64}` regex.

---

## What secureChat Does NOT Provide

* Forward secrecy — if a room key is compromised, past messages (which the server
  never stored as plaintext) are safe, but the key-holder can read future messages.
* Identity verification — there is no PKI.  You must share room links out-of-band
  over a trusted channel.
* Server-side virus scanning — uploaded files are not scanned server-side.  Use a
  local antivirus to scan downloaded files before opening them.

---

## Hardening Checklist

- [ ] Run behind a Tor hidden service (`.onion`) to hide your server IP.
- [ ] Use a strong, unique password for your operating-system user account.
- [ ] Keep the admin panel URL and passcode secret.
- [ ] Set `RELAY_SECRET` in your `.env` file if you use the SMTP relay webhook.
- [ ] Keep Python and system packages up to date.
- [ ] Do not run secureChat as root.
