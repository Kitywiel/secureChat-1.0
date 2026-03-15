# secureChat — Mail / Inbox Information

secureChat has a built-in inbox that can receive real email from any sender on
the internet.  No email account is required to *read* mail — the inbox is
auto-provisioned at startup.

---

## How It Works

### Automatic @mail.tm address (default)

On startup, secureChat automatically registers a disposable email address at
[mail.tm](https://mail.tm) using their free API.  This requires no
configuration — just open the inbox in the UI.

* The address is unique per server instance.
* Messages arrive within seconds.
* Works from any internet-connected secureChat instance.

### Receiving via SMTP relay (IP-private)

For a more permanent address without exposing your server IP, you can use a
relay service (e.g., Mailgun, SendGrid, Cloudflare Email Routing) that accepts
mail on your domain and forwards it to your secureChat via a webhook.

1. Set `RELAY_SECRET` in your `.env` file (or it will be auto-generated at startup).
2. Configure your relay service to POST to:
   ```
   POST http://<your-onion-address>/inbox/relay
   X-Relay-Secret: <RELAY_SECRET>
   ```
3. The relay service forwards the raw email body; secureChat parses it and
   delivers it to the inbox.

### Direct SMTP (exposes server IP)

If you have a domain with MX records pointing at your server, you can accept
email directly on port 25.

1. Set `MAIL_DOMAIN=yourdomain.com` in your `.env` file.
2. Set `SMTP_PORT=25` (or a higher port if you are not running as root).
3. Ensure port 25 is open in your firewall.

> ⚠️  **Warning:** Direct SMTP on port 25 exposes your server's IP address
> to anyone who sends you mail or looks up your MX records.  Use the relay
> approach instead for IP privacy.

---

## Inbox UI

* Click **Inbox** in the main navigation to open the inbox.
* A new disposable address is provisioned automatically on first open.
* Messages are stored locally (in-memory) for the duration of the server session.
* Messages are **not persisted** to disk — they are lost when the server restarts.

---

## Limitations

| Limit | Value |
|-------|-------|
| Max message size | 64 KiB |
| Inbox slots | 50 (oldest messages are dropped when full) |
| Attachment display | HTML and plain-text bodies are displayed inline |

---

## Privacy

* Email metadata (sender, subject, received time) is visible in the inbox UI.
* The mail.tm API is used for auto-provisioning; their privacy policy applies.
* For maximum privacy, use the SMTP relay approach with a mail service that
  respects privacy (e.g., a self-hosted Mailgun-compatible server).
