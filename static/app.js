'use strict';

/**
 * secureChat — client-side E2EE logic
 *
 * Encryption scheme
 * -----------------
 *  1. User supplies a room ID and a shared passphrase.
 *  2. A 256-bit AES-GCM key is derived with PBKDF2-SHA-256
 *     (600 000 iterations, meets the OWASP-recommended minimum).
 *     Salt = SHA-256("secureChat-v1:" + roomId).
 *  3. Every outgoing message is encrypted with a fresh random 12-byte IV.
 *     The IV is sent alongside the ciphertext (base64-encoded).
 *  4. The server only routes {iv, ciphertext, sender}; it never has the key.
 *  5. Past messages are stored (encrypted) on the server and replayed on join
 *     so history survives server restarts.
 *
 * All cryptographic operations use the browser's built-in Web Crypto API
 * (window.crypto.subtle), which is available in all modern browsers.
 */

// ─── Crypto ──────────────────────────────────────────────────────────────────

/**
 * Derive an AES-GCM-256 CryptoKey from a passphrase and roomId via PBKDF2.
 *
 * @param {string} passphrase  The shared secret known only to participants.
 * @param {string} roomId      Room identifier used as part of the salt.
 * @returns {Promise<CryptoKey>}
 */
async function deriveKey(passphrase, roomId) {
  const enc = new TextEncoder();

  // Build a deterministic salt tied to this room so that the same passphrase
  // in different rooms produces different keys.
  const saltRaw = enc.encode('secureChat-v1:' + roomId);
  const saltHash = await crypto.subtle.digest('SHA-256', saltRaw);

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey'],
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: new Uint8Array(saltHash),
      iterations: 600_000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/**
 * Encrypt a plaintext string with AES-GCM using a fresh random IV.
 *
 * @param {CryptoKey} key
 * @param {string} plaintext
 * @returns {Promise<{iv: string, ciphertext: string}>} Base64-encoded pair.
 */
async function encryptMessage(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const cipherBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
  return {
    iv: bufToBase64(iv),
    ciphertext: bufToBase64(new Uint8Array(cipherBuf)),
  };
}

/**
 * Decrypt a base64-encoded {iv, ciphertext} pair.
 * Returns null if decryption fails (wrong key, tampered data, …).
 *
 * @param {CryptoKey} key
 * @param {string} ivB64
 * @param {string} ciphertextB64
 * @returns {Promise<string|null>}
 */
async function decryptMessage(key, ivB64, ciphertextB64) {
  try {
    const iv = base64ToBuf(ivB64);
    const ciphertext = base64ToBuf(ciphertextB64);
    const plainBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      ciphertext,
    );
    return new TextDecoder().decode(plainBuf);
  } catch {
    return null;
  }
}

// ─── Binary ↔ Base64 helpers ─────────────────────────────────────────────────

/** @param {Uint8Array} buf */
function bufToBase64(buf) {
  return btoa(String.fromCharCode(...buf));
}

/** @param {string} b64 */
function base64ToBuf(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

// ─── File encryption helpers ─────────────────────────────────────────────────

/**
 * Encrypt raw bytes with AES-GCM.
 * @param {CryptoKey} key
 * @param {Uint8Array} bytes
 * @returns {Promise<{iv: string, ciphertext: string}>} Base64-encoded pair.
 */
async function encryptFile(key, bytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipherBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes);
  return {
    iv: bufToBase64(iv),
    ciphertext: bufToBase64(new Uint8Array(cipherBuf)),
  };
}

/**
 * Decrypt a base64 AES-GCM ciphertext back to raw bytes.
 * Returns null on failure.
 * @param {CryptoKey} key
 * @param {string} ivB64
 * @param {string} ciphertextB64
 * @returns {Promise<Uint8Array|null>}
 */
async function decryptFile(key, ivB64, ciphertextB64) {
  try {
    const iv = base64ToBuf(ivB64);
    const ciphertext = base64ToBuf(ciphertextB64);
    const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    return new Uint8Array(plainBuf);
  } catch {
    return null;
  }
}

/**
 * Append a file or image bubble to the chat log.
 * Images (png/jpeg/gif/webp) are shown inline; all other types as a download link.
 *
 * @param {string}     sender
 * @param {string}     filename
 * @param {string}     mime
 * @param {Uint8Array} bytes     Decrypted file bytes
 * @param {'outgoing'|'incoming'} kind
 * @param {number|null} [timestamp]
 * @param {boolean} [nsfw]       Blur image until clicked
 * @param {boolean} [oneTime]    Remove message element after first view
 */
function appendFileMessage(sender, filename, mime, bytes, kind, timestamp = null, nsfw = false, oneTime = false) {
  const log = document.getElementById('messages');
  const el  = document.createElement('div');
  el.className = 'message ' + kind + (oneTime ? ' one-time-msg' : '');

  // One-time view: prevent right-click save / context menu
  if (oneTime) {
    el.addEventListener('contextmenu', (e) => e.preventDefault());
  }

  // Header row (sender + timestamp)
  const headerEl = document.createElement('div');
  headerEl.className = 'msg-header';
  const senderEl = document.createElement('span');
  senderEl.className = 'sender';
  senderEl.textContent = sender;
  const timeEl = document.createElement('time');
  timeEl.className = 'timestamp';
  const d = timestamp !== null ? new Date(timestamp * 1000) : new Date();
  timeEl.dateTime = d.toISOString();
  timeEl.textContent = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  headerEl.appendChild(senderEl);
  if (oneTime) {
    const badge = document.createElement('span');
    badge.className = 'once-badge';
    badge.textContent = '👁 once';
    headerEl.appendChild(badge);
  }
  headerEl.appendChild(timeEl);
  el.appendChild(headerEl);

  // Only render as <img> for well-known safe image formats to avoid SVG scripts etc.
  const blob = new Blob([bytes], { type: mime });
  const url  = URL.createObjectURL(blob);

  if (SAFE_IMAGE_MIMES.has(mime)) {
    const img = document.createElement('img');
    img.className = 'message-img' + (nsfw ? ' nsfw' : '');
    img.src   = url;
    img.alt   = filename;
    img.title = filename;
    if (oneTime) {
      img.draggable = false;
      img.addEventListener('contextmenu', (e) => e.preventDefault());
    }

    if (nsfw) {
      // Wrap in container so the overlay sits on top
      const wrapper = document.createElement('div');
      wrapper.className = 'nsfw-wrapper';
      wrapper.appendChild(img);

      const overlay = document.createElement('div');
      overlay.className = 'nsfw-overlay';
      const label = document.createElement('span');
      label.textContent = '🔞 NSFW — click to reveal';
      overlay.appendChild(label);
      wrapper.appendChild(overlay);

      const reveal = () => {
        img.classList.remove('nsfw');
        wrapper.removeChild(overlay);
        if (oneTime) {
          img.addEventListener('click', () => { URL.revokeObjectURL(url); el.remove(); }, { once: true });
        } else {
          img.addEventListener('click', () => window.open(url, '_blank'));
        }
      };
      overlay.addEventListener('click', reveal);
      el.appendChild(wrapper);
    } else {
      if (oneTime) {
        img.addEventListener('click', () => { URL.revokeObjectURL(url); el.remove(); }, { once: true });
      } else {
        img.addEventListener('click', () => window.open(url, '_blank'));
      }
      el.appendChild(img);
    }
  } else {
    const a = document.createElement('a');
    a.className  = 'message-file';
    a.href       = url;
    a.download   = filename;
    a.textContent = `📎 ${filename}`;
    if (oneTime) {
      a.addEventListener('click', () => {
        setTimeout(() => { URL.revokeObjectURL(url); el.remove(); }, 100);
      }, { once: true });
    }
    el.appendChild(a);
  }

  log.appendChild(el);
  log.scrollTop = log.scrollHeight;
}

/**
 * Maximum in-chat attachment size for the E2EE WebSocket path (50 MiB).
 * After AES-GCM encryption + base64 encoding the ciphertext is ~67 MB —
 * matching the server-side MAX_FILE_CIPHERTEXT_LEN (68 MB) limit.
 */
const MAX_CHAT_FILE_BYTES = 50 * 1024 * 1024;

/** Maximum in-chat attachment size for the share-upload path (10 GiB). */
const MAX_CHAT_SHARE_BYTES = 10 * 1024 * 1024 * 1024;

/**
 * Safe image MIME types rendered inline as <img>.
 * Other formats (SVG, HTML, etc.) are shown as download links to prevent
 * script execution from embedded content.
 */
const SAFE_IMAGE_MIMES = new Set(['image/png', 'image/jpeg', 'image/gif', 'image/webp']);

/**
 * Encrypt and send a file over the current WebSocket connection.
 * Files ≤ 50 MB are encrypted client-side (E2EE) and relayed as-is.
 * Files > 50 MB and ≤ 10 GB are uploaded through the share system and a
 * download link is posted in the chat.
 *
 * @param {File}    file
 * @param {boolean} [nsfw]    Mark as NSFW
 * @param {boolean} [oneTime] Mark as one-time view
 */
async function sendFile(file, nsfw = false, oneTime = false) {
  if (!roomKey || !ws || ws.readyState !== WebSocket.OPEN) return;

  if (file.size > MAX_CHAT_SHARE_BYTES) {
    appendMessage('⚠️', `File too large — max 10 GB per attachment (${file.name})`, 'error');
    return;
  }

  // ── Large file path: upload via share system, post link in chat ───────────
  if (file.size > MAX_CHAT_FILE_BYTES) {
    await _sendLargeFileViaShare(file);
    return;
  }

  // ── Small file path: E2EE via WebSocket ───────────────────────────────────
  const mime     = file.type || 'application/octet-stream';
  const filename = file.name || 'file';
  const bytes    = new Uint8Array(await file.arrayBuffer());

  const { iv, ciphertext } = await encryptFile(roomKey, bytes);

  ws.send(JSON.stringify({ type: 'file', iv, ciphertext, filename, mime, sender: displayName, nsfw, one_time: oneTime }));

  // Render own attachment immediately
  appendFileMessage(displayName, filename, mime, bytes, 'outgoing', null, nsfw, oneTime);
}

/**
 * Upload a large file through the share system and post the download link
 * as an encrypted chat message so all room members can access it.
 * The file is encrypted client-side before upload (E2EE); the server only
 * stores the ciphertext.  The decryption key is embedded in the download URL
 * fragment so it is never sent to the server.
 *
 * @param {File} file
 */
async function _sendLargeFileViaShare(file) {
  const chatProgress    = document.getElementById('chat-upload-progress');
  const chatProgressBar = document.getElementById('chat-upload-progress-bar');
  const chatProgressTxt = document.getElementById('chat-upload-progress-text');

  function setProgress(pct, label) {
    chatProgress.classList.remove('hidden');
    chatProgress.setAttribute('aria-valuenow', String(pct));
    chatProgressBar.style.width = pct + '%';
    chatProgressTxt.textContent = label;
  }
  function hideProgress() {
    chatProgress.classList.add('hidden');
    chatProgressBar.style.width = '0%';
    chatProgressTxt.textContent = '';
  }

  appendMessage('📤', `Encrypting & uploading ${file.name} (${_fmtFileSize(file.size)})…`, 'system');
  setProgress(0, `${file.name} — encrypting…`);

  try {
    // ── E2EE: encrypt the file with a fresh random key ────────────────
    const fileKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
    const iv      = crypto.getRandomValues(new Uint8Array(12));
    const bytes   = new Uint8Array(await file.arrayBuffer());
    const cipherBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, fileKey, bytes);

    // Export key for embedding in the URL fragment
    const keyBytes = new Uint8Array(await crypto.subtle.exportKey('raw', fileKey));
    const keyB64   = bufToBase64(keyBytes);
    const ivB64    = bufToBase64(iv);

    setProgress(0, `${file.name} — 0%`);

    const formData = new FormData();
    // Upload the encrypted ciphertext; preserve the original filename for display
    formData.append('file', new Blob([cipherBuf], { type: 'application/octet-stream' }), file.name);

    const result = await uploadWithProgress('/share/upload?ttl=24&e=1', formData, (pct) => {
      setProgress(pct, `${file.name} — ${pct}%`);
    });

    hideProgress();

    if (!result.ok) {
      const reason = await result.text().catch(() => '');
      appendMessage('⚠️', `Upload failed: ${reason || result.status}`, 'error');
      return;
    }

    const data = await result.json();
    // Embed key + IV + original filename in the URL fragment (never sent to server).
    // encodeURIComponent is required because base64 can contain '+' which
    // URLSearchParams (used in the decrypt page) decodes as a space.
    const fragment  = `key=${encodeURIComponent(keyB64)}&iv=${encodeURIComponent(ivB64)}&name=${encodeURIComponent(file.name)}`;
    // Use a path-only URL so the link works regardless of which server URL
    // (onion, LAN, clearnet path) the recipient uses to access the server.
    const downloadUrl = `${data.download_url}#${fragment}`;
    const sizeLabel   = _fmtFileSize(file.size);

    // Post the download link as a regular encrypted chat message
    const linkText = `📎 ${file.name} (${sizeLabel}) — ${downloadUrl}`;
    const { iv: msgIv, ciphertext } = await encryptMessage(roomKey, linkText);
    ws.send(JSON.stringify({ type: 'message', iv: msgIv, ciphertext, sender: displayName }));
    appendMessage(displayName, linkText, 'outgoing');
  } catch (err) {
    hideProgress();
    appendMessage('⚠️', `Upload failed: ${err.message}`, 'error');
  }
}

/** Format a byte count as a human-readable string. */
function _fmtFileSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
  return (bytes / 1073741824).toFixed(2) + ' GB';
}

// ─── UI helpers ───────────────────────────────────────────────────────────────

/** Show one screen, hide the rest. */
function showScreen(id) {
  document.querySelectorAll('.screen').forEach((el) => el.classList.add('hidden'));
  document.getElementById(id).classList.remove('hidden');
}

/**
 * Append a message bubble to the chat log.
 *
 * @param {string} sender
 * @param {string} text
 * @param {'outgoing'|'incoming'|'system'|'error'} kind
 * @param {number|null} [timestamp]  Unix epoch seconds (from server). Omit for current time.
 */
function appendMessage(sender, text, kind, timestamp = null) {
  const log = document.getElementById('messages');
  const el = document.createElement('div');
  el.className = 'message ' + kind;

  if (kind !== 'system' && kind !== 'error') {
    const headerEl = document.createElement('div');
    headerEl.className = 'msg-header';

    const senderEl = document.createElement('span');
    senderEl.className = 'sender';
    senderEl.textContent = sender; // textContent prevents XSS

    const timeEl = document.createElement('time');
    timeEl.className = 'timestamp';
    const d = timestamp !== null ? new Date(timestamp * 1000) : new Date();
    timeEl.dateTime = d.toISOString();
    timeEl.textContent = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    headerEl.appendChild(senderEl);
    headerEl.appendChild(timeEl);
    el.appendChild(headerEl);
  }

  const textEl = document.createElement('span');
  textEl.className = 'text';
  textEl.textContent = text; // textContent prevents XSS
  el.appendChild(textEl);

  log.appendChild(el);
  log.scrollTop = log.scrollHeight;
}

// ─── App state ────────────────────────────────────────────────────────────────

/** @type {WebSocket|null} */
let ws = null;

/** @type {CryptoKey|null} */
let roomKey = null;

let displayName = 'Anonymous';

/** Passcode sent to the server during WebSocket join (server-side auth). */
let roomPasscode = '';

/** Holds data for the room just created, used by the "Join This Room" button. */
let currentCreateRoomData = null;

/** Interval ID for the self-destruct countdown. */
let destructTimerInterval = null;

/** Pending files queued for the next send (cleared after each send). */
/** @type {File[]} */
let pendingFiles = [];

/** The room ID currently joined (used for the delete-room API call). */
let currentRoomId = '';

/** Delete code for the current room (only available if this client created the room). */
let roomDeleteCode = '';

// ─── Random generation helpers ────────────────────────────────────────────────

/** Generate a cryptographically random passphrase (URL-safe base64, 22 chars). */
function randomPassphrase() {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return btoa(String.fromCharCode(...arr))
    .replace(/\+/g, 'x')
    .replace(/\//g, 'y')
    .replace(/=/g, '')
    .slice(0, 22);
}

/** Generate a random 6-digit numeric passcode. */
function randomPasscode() {
  const arr = new Uint32Array(1);
  crypto.getRandomValues(arr);
  return String(arr[0] % 1000000).padStart(6, '0');
}

// ─── URL fragment pre-fill ───────────────────────────────────────────────────

/**
 * Parse the URL fragment (#room=X&pass=Y&code=Z) and pre-fill the join form.
 * Called once on page load so invite links work automatically.
 */
function applyFragmentToJoinForm() {
  const hash = window.location.hash.slice(1);
  if (!hash) return;
  /** @type {Record<string, string>} */
  const params = {};
  hash.split('&').forEach((part) => {
    const eq = part.indexOf('=');
    if (eq > 0) {
      const k = decodeURIComponent(part.slice(0, eq));
      const v = decodeURIComponent(part.slice(eq + 1));
      params[k] = v;
    }
  });
  if (params.room) document.getElementById('room-id').value = params.room;
  if (params.pass) document.getElementById('passphrase').value = params.pass;
  if (params.code) document.getElementById('room-passcode').value = params.code;
}

// ─── Self-destruct timer ──────────────────────────────────────────────────────

/**
 * Start the self-destruct countdown badge in the chat header.
 * @param {number} expiresAt  Unix epoch seconds.
 */
function startDestructTimer(expiresAt) {
  stopDestructTimer();
  const el = document.getElementById('destruct-timer');
  el.classList.remove('hidden');

  const tick = () => {
    const remaining = Math.max(0, expiresAt - Date.now() / 1000);
    const h = Math.floor(remaining / 3600);
    const m = Math.floor((remaining % 3600) / 60);
    const s = Math.floor(remaining % 60);
    let label = '💣 ';
    if (h > 0) label += `${h}h `;
    label += `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
    el.textContent = label;
    if (remaining <= 0) stopDestructTimer();
  };

  tick();
  destructTimerInterval = setInterval(tick, 1000);
}

/** Clear the countdown interval and hide the badge. */
function stopDestructTimer() {
  if (destructTimerInterval !== null) {
    clearInterval(destructTimerInterval);
    destructTimerInterval = null;
  }
  const el = document.getElementById('destruct-timer');
  if (el) el.classList.add('hidden');
}

/**
 * Attach a live countdown to any element.  The interval automatically
 * clears itself once the element is detached from the DOM or time runs out.
 * @param {HTMLElement} el        Element whose textContent will be updated.
 * @param {number}      expiresAt Unix epoch seconds.
 * @returns {number} interval ID
 */
function _attachCountdown(el, expiresAt) {
  let id;
  const tick = () => {
    if (!el.isConnected) { clearInterval(id); return; }
    const remaining = Math.max(0, expiresAt - Date.now() / 1000);
    if (remaining <= 0) {
      el.textContent = '💣 Expired';
      clearInterval(id);
      return;
    }
    const h = Math.floor(remaining / 3600);
    const m = Math.floor((remaining % 3600) / 60);
    const s = Math.floor(remaining % 60);
    let label = '⏱ ';
    if (h > 0) label += `${h}h `;
    label += `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
    el.textContent = label;
  };
  tick();
  id = setInterval(tick, 1000);
  return id;
}

// ─── WebSocket ────────────────────────────────────────────────────────────────

/**
 * Open a WebSocket connection, join a room, and wire up message handling.
 *
 * @param {string} roomId
 */
function connectWs(roomId) {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(`${proto}//${location.host}/ws`);

  ws.addEventListener('open', () => {
    /** @type {Record<string, string>} */
    const joinMsg = { type: 'join', room: roomId };
    if (roomPasscode) joinMsg.passcode = roomPasscode;
    ws.send(JSON.stringify(joinMsg));
  });

  ws.addEventListener('message', async (event) => {
    let data;
    try {
      data = JSON.parse(event.data);
    } catch {
      return;
    }

    if (data.type === 'system') {
      const n = Number(data.users);
      document.getElementById('user-count').textContent = `👤 ${n}`;
      appendMessage('', `${n} user${n !== 1 ? 's' : ''} in room`, 'system');

    } else if (data.type === 'history') {
      // Replay stored messages sent by the server on join
      const msgs = Array.isArray(data.messages) ? data.messages : [];
      const limit = typeof data.save_limit === 'number' ? data.save_limit : null;
      const limitLabel = limit !== null ? ` — saves up to ${limit}` : '';
      if (msgs.length > 0) {
        appendMessage(
          '',
          `── ${msgs.length} stored message${msgs.length !== 1 ? 's' : ''}${limitLabel} ──`,
          'system',
        );
        for (const msg of msgs) {
          const plain = await decryptMessage(roomKey, msg.iv, msg.ciphertext);
          // Show as outgoing if the stored sender name matches the current display name
          const kind = msg.sender === displayName ? 'outgoing' : 'incoming';
          if (plain !== null) {
            appendMessage(msg.sender || 'Unknown', plain, kind, msg.ts);
          } else {
            appendMessage('⚠️', '[Stored message could not be decrypted — wrong passphrase?]', 'error');
          }
        }
        appendMessage('', '── live ──', 'system');
      } else if (limit !== null) {
        appendMessage('', `── no stored messages — saves up to ${limit} ──`, 'system');
      }

    } else if (data.type === 'message') {
      const plain = await decryptMessage(roomKey, data.iv, data.ciphertext);
      if (plain !== null) {
        appendMessage(data.sender || 'Unknown', plain, 'incoming');
      } else {
        appendMessage(
          '⚠️',
          '[Message could not be decrypted — wrong passphrase?]',
          'error',
        );
      }

    } else if (data.type === 'file') {
      const bytes = await decryptFile(roomKey, data.iv, data.ciphertext);
      if (bytes !== null) {
        appendFileMessage(
          data.sender || 'Unknown',
          data.filename || 'file',
          data.mime || 'application/octet-stream',
          bytes,
          'incoming',
          null,
          !!data.nsfw,
          !!data.one_time,
        );
      } else {
        appendMessage('⚠️', '[File could not be decrypted — wrong passphrase?]', 'error');
      }

    } else if (data.type === 'destruct_info') {
      // Server told us this room has a self-destruct deadline
      startDestructTimer(data.expires_at);
      const d = new Date(data.expires_at * 1000);
      appendMessage('', `⏱ Room self-destructs at ${d.toLocaleString()}`, 'system');

    } else if (data.type === 'destruct') {
      // The room has been destroyed — stop the timer and lock the UI
      stopDestructTimer();
      appendMessage('', '💣 Room has self-destructed. All messages have been deleted.', 'system');
      document.getElementById('message-input').disabled = true;
      document.getElementById('send-btn').disabled = true;
      document.getElementById('attach-btn').disabled = true;

    } else if (data.type === 'error') {
      const reason = data.reason || 'unknown';
      const msgs = {
        wrong_passcode: '🔒 Wrong room passcode — access denied.',
        room_expired:   '💣 This room has already self-destructed.',
        invalid_room_id: 'Invalid room ID.',
      };
      appendMessage('⚠️', msgs[reason] ?? `Server error: ${reason}`, 'error');
    }
  });

  ws.addEventListener('close', () => {
    appendMessage('', 'Disconnected from room.', 'system');
    document.getElementById('message-input').disabled = true;
    document.getElementById('send-btn').disabled = true;
    document.getElementById('attach-btn').disabled = true;
  });

  ws.addEventListener('error', () => {
    appendMessage('', 'Connection error — check that the server is running.', 'error');
  });
}

// ─── Event handlers ───────────────────────────────────────────────────────────

/**
 * Enter the chat screen after successful key derivation.
 *
 * @param {string}     roomId
 * @param {CryptoKey}  key
 * @param {string}     name
 * @param {string}     passcode    Server-side room passcode (empty string if none).
 * @param {string}     [deleteCode] Delete code (only available if this client created the room).
 */
function enterRoom(roomId, key, name, passcode, deleteCode = '') {
  roomKey = key;
  displayName = name.slice(0, 32);
  roomPasscode = passcode;
  currentRoomId = roomId;
  roomDeleteCode = deleteCode;
  stopDestructTimer();
  document.getElementById('room-label').textContent = `🔒 ${roomId}`;
  document.getElementById('message-input').disabled = false;
  document.getElementById('send-btn').disabled = false;
  document.getElementById('attach-btn').disabled = false;
  showScreen('chat');
  document.getElementById('message-input').focus();
  connectWs(roomId);
}

document.getElementById('join-form').addEventListener('submit', async (e) => {
  e.preventDefault();

  const nameInput   = /** @type {HTMLInputElement} */ (document.getElementById('display-name'));
  const roomInput   = /** @type {HTMLInputElement} */ (document.getElementById('room-id'));
  const passInput   = /** @type {HTMLInputElement} */ (document.getElementById('passphrase'));
  const codeInput   = /** @type {HTMLInputElement} */ (document.getElementById('room-passcode'));
  const errEl = document.getElementById('join-error');
  const btn   = document.getElementById('join-btn');

  errEl.textContent = '';

  const name       = nameInput.value.trim() || 'Anonymous';
  const roomId     = roomInput.value.trim();
  const passphrase = passInput.value;
  const passcode   = codeInput.value;

  if (!roomId) {
    errEl.textContent = 'Room ID is required.';
    roomInput.focus();
    return;
  }
  if (!/^[A-Za-z0-9_-]+$/.test(roomId)) {
    errEl.textContent = 'Room ID may only contain letters, digits, hyphens, and underscores.';
    roomInput.focus();
    return;
  }
  if (!passphrase) {
    errEl.textContent = 'Passphrase is required.';
    passInput.focus();
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Deriving key…';

  try {
    const key = await deriveKey(passphrase, roomId);
    // Clear passphrase from DOM before switching screen
    passInput.value = '';
    enterRoom(roomId, key, name, passcode);
  } catch (err) {
    errEl.textContent = 'Key derivation failed: ' + err.message;
    passInput.value = '';
  } finally {
    btn.disabled = false;
    btn.textContent = 'Join Room →';
  }
});

document.getElementById('message-form').addEventListener('submit', async (e) => {
  e.preventDefault();

  const input = /** @type {HTMLTextAreaElement} */ (document.getElementById('message-input'));
  const text = input.value.trim();

  // Send any queued files first
  if (pendingFiles.length > 0) {
    const nsfw    = /** @type {HTMLInputElement} */ (document.getElementById('file-nsfw-check')).checked;
    const oneTime = /** @type {HTMLInputElement} */ (document.getElementById('file-once-check')).checked;
    for (const file of pendingFiles) {
      await sendFile(file, nsfw, oneTime);
    }
    clearPendingFiles();
  }

  if (!text || !roomKey || !ws || ws.readyState !== WebSocket.OPEN) return;

  input.value = '';
  input.style.height = 'auto';
  input.focus(); // restore focus so the user can keep typing / pasting

  const { iv, ciphertext } = await encryptMessage(roomKey, text);
  ws.send(JSON.stringify({ type: 'message', iv, ciphertext, sender: displayName }));

  // Show own message immediately without waiting for relay echo.
  appendMessage(displayName, text, 'outgoing');
});

// Enter sends; Shift+Enter inserts a newline.
document.getElementById('message-input').addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    document.getElementById('message-form').dispatchEvent(new Event('submit', { cancelable: true }));
  }
});

// Auto-resize textarea as the user types.
document.getElementById('message-input').addEventListener('input', (e) => {
  const textarea = /** @type {HTMLTextAreaElement} */ (e.target);
  textarea.style.height = 'auto';
  textarea.style.height = `${textarea.scrollHeight}px`;
});

document.getElementById('leave-btn').addEventListener('click', () => {
  if (ws) {
    ws.close();
    ws = null;
  }
  roomKey = null;
  roomPasscode = '';
  currentRoomId = '';
  roomDeleteCode = '';
  stopDestructTimer();
  clearPendingFiles();
  showScreen('lobby');
  document.getElementById('messages').innerHTML = '';
  document.getElementById('join-form').reset();
  document.getElementById('join-error').textContent = '';
  document.getElementById('attach-btn').disabled = true;
});

// ─── In-chat file / image attachments ────────────────────────────────────────

/**
 * Update the file preview area to reflect the current pendingFiles list.
 * Shows the area when files are pending; hides it when empty.
 */
function updateFilePreview() {
  const area = document.getElementById('file-preview-area');
  const list = document.getElementById('file-preview-list');
  list.innerHTML = '';

  if (pendingFiles.length === 0) {
    area.classList.add('hidden');
    return;
  }

  area.classList.remove('hidden');
  pendingFiles.forEach((file, idx) => {
    const item = document.createElement('div');
    item.className = 'file-preview-item';

    const nameEl = document.createElement('span');
    nameEl.textContent = file.name;
    item.appendChild(nameEl);

    const rmBtn = document.createElement('button');
    rmBtn.type = 'button';
    rmBtn.textContent = '✕';
    rmBtn.title = 'Remove';
    rmBtn.addEventListener('click', () => {
      pendingFiles.splice(idx, 1);
      updateFilePreview();
    });
    item.appendChild(rmBtn);
    list.appendChild(item);
  });
}

/** Clear pending files and hide the preview area. */
function clearPendingFiles() {
  pendingFiles = [];
  document.getElementById('file-nsfw-check').checked = false;
  document.getElementById('file-once-check').checked = false;
  updateFilePreview();
}

// Clicking the 📎 button opens the hidden file picker.
document.getElementById('attach-btn').addEventListener('click', () => {
  document.getElementById('chat-file-input').click();
});

// File chosen via the picker — queue for sending on Enter.
document.getElementById('chat-file-input').addEventListener('change', (e) => {
  const input = /** @type {HTMLInputElement} */ (e.target);
  if (!input.files?.length) return;
  for (const file of input.files) {
    pendingFiles.push(file);
  }
  input.value = ''; // reset so the same file can be re-selected
  updateFilePreview();
});

// ─── Paste to attach ─────────────────────────────────────────────────────────
// Pasting an image or file while the message input (or chat screen) is focused
// queues it as a pending attachment instead of inserting raw data into the text.
document.getElementById('message-input').addEventListener('paste', (e) => {
  const items = e.clipboardData?.items;
  if (!items) return;
  const files = [];
  for (const item of items) {
    if (item.kind === 'file') {
      const file = item.getAsFile();
      if (file) files.push(file);
    }
  }
  if (files.length === 0) return;
  e.preventDefault(); // don't paste raw bytes as text
  for (const file of files) {
    pendingFiles.push(file);
  }
  updateFilePreview();
});

// ─── Drag-and-drop to attach ─────────────────────────────────────────────────
// Dragging files onto the chat screen (messages area or message bar) queues
// them as pending attachments and shows a visual drop-zone highlight.
(function () {
  const chatScreen = document.getElementById('chat');

  chatScreen.addEventListener('dragenter', (e) => {
    if (!e.dataTransfer?.types?.includes('Files')) return;
    e.preventDefault();
    chatScreen.classList.add('drag-over');
  });

  chatScreen.addEventListener('dragover', (e) => {
    if (!e.dataTransfer?.types?.includes('Files')) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = 'copy';
  });

  chatScreen.addEventListener('dragleave', (e) => {
    // Only remove the highlight when leaving the chat screen entirely
    // (not when moving between child elements).
    if (!chatScreen.contains(/** @type {Element} */ (e.relatedTarget))) {
      chatScreen.classList.remove('drag-over');
    }
  });

  chatScreen.addEventListener('drop', (e) => {
    e.preventDefault();
    chatScreen.classList.remove('drag-over');
    const files = e.dataTransfer?.files;
    if (!files?.length) return;
    for (const file of files) {
      pendingFiles.push(file);
    }
    updateFilePreview();
  });
}());

// Delete room button — removes all room data from the server and leaves.
document.getElementById('delete-room-btn').addEventListener('click', async () => {
  if (!currentRoomId) return;
  if (!confirm(`Delete room "${currentRoomId}" and all its messages? This cannot be undone.`)) return;

  // Use the stored delete code (available when this client created the room),
  // otherwise prompt the user to enter it manually.
  let deleteCodeToSend = roomDeleteCode;
  if (!deleteCodeToSend) {
    // Prompt user for the delete code if we don't have it stored locally
    const entered = prompt('Enter the room delete code (required to delete this room):');
    if (entered === null) return; // user cancelled
    deleteCodeToSend = entered.trim();
    if (!deleteCodeToSend) {
      alert('A delete code is required to delete this room.');
      return;
    }
  }

  try {
    const resp = await fetch(`/room/${encodeURIComponent(currentRoomId)}/delete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ delete_code: deleteCodeToSend }),
    });
    if (!resp.ok) {
      const reason = await resp.text().catch(() => '');
      alert(`Could not delete room: ${reason || resp.statusText}`);
      return;
    }
  } catch { /* ignore network errors — room may already be gone */ }

  // The server will broadcast a "destruct" event that clears the UI;
  // also clean up locally in case the WS event doesn't arrive in time.
  if (ws) {
    ws.close();
    ws = null;
  }
  roomKey = null;
  roomPasscode = '';
  currentRoomId = '';
  roomDeleteCode = '';
  stopDestructTimer();
  clearPendingFiles();
  showScreen('lobby');
  document.getElementById('messages').innerHTML = '';
  document.getElementById('join-form').reset();
  document.getElementById('join-error').textContent = '';
  document.getElementById('attach-btn').disabled = true;
});

// ─── Share Files ──────────────────────────────────────────────────────────────

/**
 * Upload FormData via XHR with real-time progress reporting.
 *
 * @param {string}   url        POST endpoint
 * @param {FormData} formData
 * @param {function(number): void} onProgress  Called with 0–100 integer percent.
 * @returns {Promise<{ok: boolean, status: number, text: ()=>Promise<string>, json: ()=>Promise<any>}>}
 */
function uploadWithProgress(url, formData, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', url);
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) onProgress(Math.round((e.loaded / e.total) * 100));
    };
    xhr.onload = () => {
      const responseText = xhr.responseText;
      resolve({
        ok: xhr.status >= 200 && xhr.status < 300,
        status: xhr.status,
        text: () => Promise.resolve(responseText),
        json: () => Promise.resolve(JSON.parse(responseText)),
      });
    };
    xhr.onerror = () => reject(new Error(`Upload failed (network error, status: ${xhr.status})`));
    xhr.ontimeout = () => reject(new Error('Upload timed out'));
    xhr.send(formData);
  });
}

/** Reset the share screen to its initial (upload) state. */
function resetShareScreen() {
  document.getElementById('share-form').reset();
  document.getElementById('share-error').textContent = '';
  document.getElementById('share-result').classList.add('hidden');
  document.getElementById('share-upload-area').classList.remove('hidden');
  // Hide the passcode row
  document.getElementById('share-passcode-row').classList.add('hidden');
  // Clear the links container
  document.getElementById('share-links-container').innerHTML = '';
  // Reset progress bar
  const progressWrap = document.getElementById('share-progress');
  if (progressWrap) {
    progressWrap.classList.add('hidden');
    document.getElementById('share-progress-bar').style.width = '0%';
    document.getElementById('share-progress-text').textContent = '';
  }
}

/**
 * Render a single file's result card inside the links container.
 * @param {{download_url: string, filename: string, expires_at: number}} data
 * @param {string} passcode
 */
function _appendShareResult(data, passcode) {
  const container = document.getElementById('share-links-container');
  // Keep as a path-only URL so the link works from any server URL (onion, LAN, etc.).
  // The server already returns a relative path; resolving against the current origin
  // would make the link unusable from a different URL that also reaches this server.
  const downloadUrl = data.download_url;
  const expiresAt = new Date(data.expires_at * 1000);

  const wrap = document.createElement('div');
  wrap.className = 'share-file-result';
  wrap.style.cssText = 'margin-bottom:1.2rem;padding:.85rem;background:#111;border:1px solid #2e2e2e;border-radius:8px';

  const nameEl = document.createElement('p');
  nameEl.style.cssText = 'font-size:.82rem;color:#888;margin-bottom:.4rem';
  nameEl.textContent = `📎 ${data.filename}`;
  wrap.appendChild(nameEl);

  // Link row
  const linkRow = document.createElement('div');
  linkRow.className = 'share-link-row';
  const linkEl = document.createElement('code');
  linkEl.className = 'share-link';
  linkEl.textContent = downloadUrl;
  const copyBtn = document.createElement('button');
  copyBtn.type = 'button';
  copyBtn.className = 'btn-copy';
  copyBtn.textContent = 'Copy';
  copyBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(downloadUrl).then(() => {
      copyBtn.textContent = 'Copied!';
      setTimeout(() => { copyBtn.textContent = 'Copy'; }, 2000);
    }).catch(() => {
      const range = document.createRange();
      range.selectNodeContents(linkEl);
      const sel = window.getSelection();
      if (sel) { sel.removeAllRanges(); sel.addRange(range); }
    });
  });
  linkRow.appendChild(linkEl);
  linkRow.appendChild(copyBtn);
  wrap.appendChild(linkRow);

  // Passcode (if any)
  if (passcode) {
    const pcLabel = document.createElement('p');
    pcLabel.style.cssText = 'font-size:.82rem;color:#888;margin:.6rem 0 .3rem';
    pcLabel.textContent = '🔒 Passcode for this file:';
    wrap.appendChild(pcLabel);
    const pcRow = document.createElement('div');
    pcRow.className = 'share-link-row';
    const pcEl = document.createElement('code');
    pcEl.className = 'share-link';
    pcEl.textContent = passcode;
    const pcCopyBtn = document.createElement('button');
    pcCopyBtn.type = 'button';
    pcCopyBtn.className = 'btn-copy';
    pcCopyBtn.textContent = 'Copy';
    pcCopyBtn.addEventListener('click', () => {
      navigator.clipboard.writeText(passcode).then(() => {
        pcCopyBtn.textContent = 'Copied!';
        setTimeout(() => { pcCopyBtn.textContent = 'Copy'; }, 2000);
      }).catch(() => {
        const range = document.createRange();
        range.selectNodeContents(pcEl);
        const sel = window.getSelection();
        if (sel) { sel.removeAllRanges(); sel.addRange(range); }
      });
    });
    pcRow.appendChild(pcEl);
    pcRow.appendChild(pcCopyBtn);
    wrap.appendChild(pcRow);
  }

  // Expiry note with live countdown
  const expEl = document.createElement('p');
  expEl.className = 'notice';
  expEl.textContent = `⚠️ One-time link — expires ${expiresAt.toLocaleString()} `;
  const shareTimerSpan = document.createElement('span');
  shareTimerSpan.style.cssText = 'margin-left:.4rem;color:#f0a844;font-weight:600';
  expEl.appendChild(shareTimerSpan);
  _attachCountdown(shareTimerSpan, data.expires_at);
  wrap.appendChild(expEl);

  container.appendChild(wrap);
}

document.getElementById('share-files-btn').addEventListener('click', () => {
  resetShareScreen();
  showScreen('share');
});

document.getElementById('share-back-btn').addEventListener('click', () => {
  resetShareScreen();
  showScreen('lobby');
});

document.getElementById('share-again-btn').addEventListener('click', () => {
  resetShareScreen();
});

document.getElementById('share-passcode-check').addEventListener('change', (e) => {
  const row = document.getElementById('share-passcode-row');
  if (/** @type {HTMLInputElement} */ (e.target).checked) {
    row.classList.remove('hidden');
    if (!document.getElementById('share-passcode').value) {
      document.getElementById('share-passcode').value = randomPasscode();
    }
  } else {
    row.classList.add('hidden');
  }
});

document.getElementById('refresh-share-passcode-btn').addEventListener('click', () => {
  document.getElementById('share-passcode').value = randomPasscode();
});

document.getElementById('share-form').addEventListener('submit', async (e) => {
  e.preventDefault();

  const fileInput  = /** @type {HTMLInputElement} */ (document.getElementById('share-file'));
  const ttlSelect  = /** @type {HTMLSelectElement} */ (document.getElementById('share-ttl'));
  const errEl      = document.getElementById('share-error');
  const btn        = document.getElementById('share-btn');
  const usePasscode = /** @type {HTMLInputElement} */ (
    document.getElementById('share-passcode-check')).checked;
  const passcode   = usePasscode
    ? document.getElementById('share-passcode').value.trim()
    : '';

  errEl.textContent = '';

  const files = fileInput.files ? Array.from(fileInput.files) : [];
  if (!files.length) {
    errEl.textContent = 'Please select at least one file.';
    return;
  }

  const MAX_BYTES = 10 * 1024 * 1024 * 1024; // 10 GB
  for (const f of files) {
    if (f.size > MAX_BYTES) {
      errEl.textContent = `"${f.name}" is too large (10 GB maximum per file).`;
      return;
    }
  }

  const ttl = ttlSelect.value;
  btn.disabled = true;
  btn.textContent = `Uploading 0 / ${files.length}…`;

  // Clear previous results
  document.getElementById('share-links-container').innerHTML = '';

  const progressWrap = document.getElementById('share-progress');
  const progressBar  = document.getElementById('share-progress-bar');
  const progressText = document.getElementById('share-progress-text');

  /** Update the progress bar to the given 0–100 percent. */
  function setProgress(pct, label) {
    progressWrap.classList.remove('hidden');
    progressWrap.setAttribute('aria-valuenow', String(pct));
    progressBar.style.width = pct + '%';
    progressText.textContent = label;
  }

  function hideProgress() {
    progressWrap.classList.add('hidden');
    progressBar.style.width = '0%';
    progressText.textContent = '';
  }

  let successCount = 0;
  for (let i = 0; i < files.length; i++) {
    const file = files[i];
    const fileLabel = `${i + 1} / ${files.length}`;
    btn.textContent = `Encrypting ${fileLabel}…`;
    setProgress(0, `${fileLabel} — encrypting…`);

    try {
      // ── E2EE: encrypt each file with a fresh random key ────────────
      const fileKey  = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
      const fileIv   = crypto.getRandomValues(new Uint8Array(12));
      const bytes    = new Uint8Array(await file.arrayBuffer());
      const cipherBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: fileIv }, fileKey, bytes);
      const keyBytes = new Uint8Array(await crypto.subtle.exportKey('raw', fileKey));
      const keyB64   = bufToBase64(keyBytes);
      const ivB64    = bufToBase64(fileIv);

      btn.textContent = `Uploading ${fileLabel}…`;
      setProgress(0, `${fileLabel} — 0%`);

      const formData = new FormData();
      formData.append('file', new Blob([cipherBuf], { type: 'application/octet-stream' }), file.name);
      // passcode is NOT used with E2EE (key is in the URL fragment)

      const resp = await uploadWithProgress(
        `/share/upload?ttl=${encodeURIComponent(ttl)}&e=1`,
        formData,
        (pct) => {
          btn.textContent = `Uploading ${fileLabel} (${pct}%)…`;
          setProgress(pct, `${fileLabel} — ${pct}%`);
        },
      );

      if (!resp.ok) {
        const text = await resp.text();
        errEl.textContent += `\n"${file.name}" failed (${resp.status}): ${text}`;
        continue;
      }

      const data = await resp.json();
      // Append key+IV+filename to the download URL fragment (never sent to server).
      // encodeURIComponent is required because base64 can contain '+' which
      // URLSearchParams (used in the decrypt page) decodes as a space.
      const fragment = `key=${encodeURIComponent(keyB64)}&iv=${encodeURIComponent(ivB64)}&name=${encodeURIComponent(file.name)}`;
      data.download_url = `${data.download_url}#${fragment}`;
      _appendShareResult(data, '');
      successCount++;
    } catch (err) {
      errEl.textContent += `\n"${file.name}" failed: ${err instanceof Error ? err.message : String(err)}`;
    }
  }

  btn.disabled = false;
  btn.textContent = 'Upload & Generate Link';
  hideProgress();

  if (successCount > 0) {
    document.getElementById('share-result').classList.remove('hidden');
    document.getElementById('share-upload-area').classList.add('hidden');
  }
});

// ─── QR Code — removed from share screen (multi-file, links are now inline) ──

// ─── Create Room ──────────────────────────────────────────────────────────────

/** Reset the create-room screen to its initial form state. */
function resetCreateRoomScreen() {
  document.getElementById('create-room-form').reset();
  document.getElementById('create-error').textContent = '';
  document.getElementById('create-room-result').classList.add('hidden');
  document.getElementById('create-room-form-area').classList.remove('hidden');
  document.getElementById('create-passcode-row').classList.add('hidden');
  document.getElementById('create-webhook-row').classList.add('hidden');
  document.getElementById('create-passphrase').value = randomPassphrase();
  // Hide QR container and reset button label
  document.getElementById('create-qr-container').classList.add('hidden');
  document.getElementById('create-qr-btn').textContent = '📱 Show QR Code';
  document.getElementById('create-qr-img').src = '';
  currentCreateRoomData = null;
}

document.getElementById('create-room-btn').addEventListener('click', () => {
  resetCreateRoomScreen();
  showScreen('create-room');
});

document.getElementById('create-back-btn').addEventListener('click', () => {
  showScreen('lobby');
});

document.getElementById('refresh-passphrase-btn').addEventListener('click', () => {
  document.getElementById('create-passphrase').value = randomPassphrase();
});

document.getElementById('refresh-passcode-btn').addEventListener('click', () => {
  document.getElementById('create-passcode').value = randomPasscode();
});

document.getElementById('create-passcode-check').addEventListener('change', (e) => {
  const row = document.getElementById('create-passcode-row');
  if (/** @type {HTMLInputElement} */ (e.target).checked) {
    row.classList.remove('hidden');
    if (!document.getElementById('create-passcode').value) {
      document.getElementById('create-passcode').value = randomPasscode();
    }
  } else {
    row.classList.add('hidden');
  }
});

document.getElementById('create-webhook-check').addEventListener('change', (e) => {
  const row = document.getElementById('create-webhook-row');
  if (/** @type {HTMLInputElement} */ (e.target).checked) {
    row.classList.remove('hidden');
  } else {
    row.classList.add('hidden');
  }
});

document.getElementById('create-room-form').addEventListener('submit', async (e) => {
  e.preventDefault();

  const errEl = document.getElementById('create-error');
  const btn   = document.getElementById('create-room-submit-btn');
  errEl.textContent = '';

  const passphrase = document.getElementById('create-passphrase').value.trim();
  if (!passphrase) {
    errEl.textContent = 'Passphrase is required.';
    return;
  }

  const usePasscode      = document.getElementById('create-passcode-check').checked;
  const passcode         = usePasscode ? document.getElementById('create-passcode').value.trim() : '';
  const destructMinutes  = parseInt(document.getElementById('create-destruct').value, 10);
  const creatorName      = document.getElementById('create-display-name').value.trim() || 'Anonymous';
  const useWebhook       = document.getElementById('create-webhook-check').checked;
  const webhookUrl       = useWebhook ? document.getElementById('create-webhook-url').value.trim() : '';

  btn.disabled = true;
  btn.textContent = 'Creating…';

  try {
    const resp = await fetch('/room/create', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        passcode: passcode || null,
        destruct_minutes: destructMinutes,
        webhook_url: webhookUrl || null,
      }),
    });

    if (!resp.ok) {
      errEl.textContent = `Failed to create room (HTTP ${resp.status}).`;
      return;
    }

    const data = await resp.json();
    const roomId = data.room_id;
    const deleteCode = data.delete_code || '';

    // Build invite fragment — room ID and optional passcode only.
    // The passphrase is intentionally omitted: it must be shared separately
    // (out-of-band) so that the invite link alone cannot decrypt messages.
    const fragParts = [`room=${encodeURIComponent(roomId)}`];
    if (passcode) fragParts.push(`code=${encodeURIComponent(passcode)}`);

    // Use the server's known onion address if available, else fall back to current origin
    let baseUrl = window.location.origin;
    try {
      const infoResp = await fetch('/api/server-info');
      if (infoResp.ok) {
        const info = await infoResp.json();
        if (info.onion) baseUrl = `http://${info.onion}`;
      }
    } catch { /* ignore — not critical */ }

    const inviteUrl = `${baseUrl}/#${fragParts.join('&')}`;

    currentCreateRoomData = { roomId, passphrase, passcode, expiresAt: data.expires_at, creatorName, deleteCode };

    document.getElementById('create-invite-link').textContent = inviteUrl;
    document.getElementById('create-passphrase-display').textContent = passphrase;
    document.getElementById('create-delete-code-display').textContent = deleteCode || '(none)';

    if (data.expires_at) {
      const d = new Date(data.expires_at * 1000);
      document.getElementById('create-expiry').textContent =
        `⏱ Room self-destructs at ${d.toLocaleString()}`;
    } else {
      document.getElementById('create-expiry').textContent = '♾️ Room has no expiry.';
    }

    document.getElementById('create-room-form-area').classList.add('hidden');
    document.getElementById('create-room-result').classList.remove('hidden');

  } catch (err) {
    errEl.textContent = 'Error: ' + (err instanceof Error ? err.message : String(err));
  } finally {
    btn.disabled = false;
    btn.textContent = 'Create Room →';
  }
});

document.getElementById('create-copy-btn').addEventListener('click', () => {
  const linkEl = document.getElementById('create-invite-link');
  const url = linkEl.textContent;
  if (!url) return;
  navigator.clipboard.writeText(url).then(() => {
    const btn = document.getElementById('create-copy-btn');
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = 'Copy'; }, 2000);
  }).catch(() => {
    const range = document.createRange();
    range.selectNodeContents(linkEl);
    const sel = window.getSelection();
    if (sel) { sel.removeAllRanges(); sel.addRange(range); }
  });
});

document.getElementById('create-copy-passphrase-btn').addEventListener('click', () => {
  const el = document.getElementById('create-passphrase-display');
  const text = el.textContent;
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.getElementById('create-copy-passphrase-btn');
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = 'Copy'; }, 2000);
  }).catch(() => {
    const range = document.createRange();
    range.selectNodeContents(el);
    const sel = window.getSelection();
    if (sel) { sel.removeAllRanges(); sel.addRange(range); }
  });
});

document.getElementById('create-join-btn').addEventListener('click', async () => {
  if (!currentCreateRoomData) return;
  const { roomId, passphrase, passcode, creatorName, deleteCode } = currentCreateRoomData;
  const btn = document.getElementById('create-join-btn');
  btn.disabled = true;
  btn.textContent = 'Joining…';
  try {
    const key = await deriveKey(passphrase, roomId);
    enterRoom(roomId, key, creatorName, passcode || '', deleteCode || '');
  } catch (err) {
    document.getElementById('create-error').textContent =
      'Key derivation failed: ' + (err instanceof Error ? err.message : String(err));
    btn.disabled = false;
    btn.textContent = 'Join This Room →';
  }
});

// ─── QR Code toggles ─────────────────────────────────────────────────────────

/**
 * Generic toggle: show/hide the QR code container for a given link.
 * @param {string} btnId       ID of the toggle button
 * @param {string} imgId       ID of the <img> element
 * @param {string} containerId ID of the container div
 * @param {string} url         URL to encode in the QR code
 */
function toggleQr(btnId, imgId, containerId, url) {
  const btn       = document.getElementById(btnId);
  const img       = document.getElementById(imgId);
  const container = document.getElementById(containerId);

  if (container.classList.contains('hidden')) {
    // Show — load the SVG from the server if not already loaded for this URL
    const currentSrc = img.getAttribute('src') || '';
    if (!currentSrc.includes('/api/qrcode')) {
      img.src = '/api/qrcode?data=' + encodeURIComponent(url);
    }
    container.classList.remove('hidden');
    btn.textContent = '📱 Hide QR Code';
  } else {
    container.classList.add('hidden');
    btn.textContent = '📱 Show QR Code';
  }
}

document.getElementById('create-qr-btn').addEventListener('click', () => {
  const inviteUrl = document.getElementById('create-invite-link').textContent;
  if (!inviteUrl) return;
  // Include the passphrase in the QR code so a single scan gives full access.
  // The invite URL is always built with a '#' fragment (e.g., "…/#room=…"), so
  // we safely append the passphrase as an additional fragment parameter.
  const passphrase = document.getElementById('create-passphrase-display').textContent;
  const qrData = passphrase
    ? inviteUrl + '&pass=' + encodeURIComponent(passphrase)
    : inviteUrl;
  toggleQr('create-qr-btn', 'create-qr-img', 'create-qr-container', qrData);
});

// ─── Add copy handler for delete code ─────────────────────────────────────────

document.getElementById('create-copy-delete-code-btn').addEventListener('click', () => {
  const el = document.getElementById('create-delete-code-display');
  const text = el.textContent;
  if (!text || text === '(none)') return;
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.getElementById('create-copy-delete-code-btn');
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = 'Copy'; }, 2000);
  }).catch(() => {
    const range = document.createRange();
    range.selectNodeContents(el);
    const sel = window.getSelection();
    if (sel) { sel.removeAllRanges(); sel.addRange(range); }
  });
});

// ─── Inbox (multi-inbox support) ─────────────────────────────────────────────

// State: list of active inbox objects
const _activeInboxes = [];

// Fetch server-info once to know whether SMTP is configured
fetch('/api/server-info').then(r => r.json()).then(info => {
  if (info.mail_domain) {
    document.getElementById('inbox-smtp-badge').classList.remove('hidden');
  }
}).catch(() => {});

document.getElementById('inbox-btn').addEventListener('click', () => {
  showScreen('inbox');
});

document.getElementById('inbox-back-btn').addEventListener('click', () => {
  showScreen('lobby');
});

document.getElementById('inbox-create-btn').addEventListener('click', async () => {
  const btn = document.getElementById('inbox-create-btn');
  const errEl = document.getElementById('inbox-create-error');
  errEl.textContent = '';
  btn.disabled = true;
  btn.textContent = 'Creating…';

  const ttlMinutes = parseInt(
    /** @type {HTMLSelectElement} */ (document.getElementById('inbox-ttl')).value,
    10,
  );

  try {
    const resp = await fetch('/inbox/create', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ttl_minutes: ttlMinutes }),
    });
    if (!resp.ok) {
      const text = await resp.text().catch(() => resp.statusText);
      throw new Error(text || resp.statusText);
    }
    const data = await resp.json();
    _activeInboxes.unshift(data);  // newest first
    renderInboxList();
  } catch (err) {
    errEl.textContent = 'Failed to create inbox: ' + (err instanceof Error ? err.message : String(err));
  } finally {
    btn.disabled = false;
    btn.textContent = 'Create Inbox →';
  }
});

/** Render the full inbox list. */
function renderInboxList() {
  const listEl = document.getElementById('inbox-list');
  listEl.innerHTML = '';
  if (_activeInboxes.length === 0) return;
  _activeInboxes.forEach((data, idx) => {
    listEl.appendChild(buildInboxCard(data, idx));
  });
}

/**
 * Build a DOM card for a single inbox entry.
 * @param {object} data  — response from POST /inbox/create
 * @param {number} idx   — index into _activeInboxes (for removal)
 * @returns {HTMLElement}
 */
function buildInboxCard(data, idx) {
  const base = window.location.origin;
  // Drop link is shared externally — use a path-only URL so it works from any
  // server URL (onion, LAN, clearnet) the sender uses to reach this server.
  const fullDrop   = data.drop_url;
  const readerUrl  = base + data.reader_url;  // opened locally — full URL fine
  const expiresDate = new Date(data.expires_at * 1000);
  const expiresLabel = expiresDate.toLocaleString();

  const card = document.createElement('div');
  card.className = 'share-result';
  card.style.cssText = 'margin-bottom:1rem;position:relative';

  const clearnetBadge = data.mailtm_enabled
    ? `<span class="inbox-badge inbox-badge--real">✅ Real email — clearnet deliverable (Discord, Google, GitHub, etc.)</span>`
    : `<span class="inbox-badge inbox-badge--drop">⚠️ HTTP-drop only — not a real deliverable email</span>`;

  card.innerHTML = `
    <button type="button" class="inbox-remove-btn" title="Remove from list"
      style="position:absolute;top:.6rem;right:.6rem;background:none;border:none;
             color:#555;cursor:pointer;font-size:1rem;padding:.1rem .3rem">✕</button>

    ${clearnetBadge}
    <p class="share-result-label">📮 Email address</p>
    <div class="share-link-row">
      <code class="share-link inbox-addr-code">${escHtml(data.address)}</code>
      <button type="button" class="btn-copy inbox-copy-addr">Copy</button>
    </div>

    <p class="share-result-label share-result-label--mt">🔗 Drop link (sender) — works from any server URL</p>
    <div class="share-link-row">
      <code class="share-link">${escHtml(fullDrop)}</code>
      <button type="button" class="btn-copy inbox-copy-drop">Copy</button>
    </div>

    <p class="notice" style="margin-top:.5rem">⏰ Expires ${escHtml(expiresLabel)} <span class="inbox-expiry-timer" style="margin-left:.4rem;color:#f0a844;font-weight:600"></span></p>

    <div style="display:flex;gap:.5rem;margin-top:.75rem;flex-wrap:wrap">
      <button type="button" class="inbox-open-reader-btn"
        style="flex:1;padding:.55rem .75rem;background:#1e3a5e;color:#80d4ff;
               border:1px solid #2a5080;border-radius:8px;cursor:pointer;font-size:.88rem;font-weight:600">
        📬 Open Reader →
      </button>
      <button type="button" class="inbox-refresh-btn"
        style="flex:1;padding:.55rem .75rem;background:#1a2e1a;color:#6fcf6f;
               border:1px solid #2d6a2d;border-radius:8px;cursor:pointer;font-size:.88rem;font-weight:600">
        🔄 Check Messages
      </button>
    </div>

    <!-- Inline message preview -->
    <div class="inbox-preview" style="margin-top:.75rem;display:none"></div>
    <div class="inbox-status" style="margin-top:.4rem;font-size:.8rem;color:#666"></div>
  `;

  // Attach live countdown to the expiry timer span
  _attachCountdown(card.querySelector('.inbox-expiry-timer'), data.expires_at);

  // Remove button
  card.querySelector('.inbox-remove-btn').addEventListener('click', () => {
    _activeInboxes.splice(idx, 1);
    renderInboxList();
  });

  // Copy address
  card.querySelector('.inbox-copy-addr').addEventListener('click', () => {
    copyText(data.address, card.querySelector('.inbox-copy-addr'));
  });

  // Copy drop link
  card.querySelector('.inbox-copy-drop').addEventListener('click', () => {
    copyText(fullDrop, card.querySelector('.inbox-copy-drop'));
  });

  // Open full HTML reader in new tab
  card.querySelector('.inbox-open-reader-btn').addEventListener('click', () => {
    window.open(readerUrl, '_blank', 'noopener,noreferrer');
  });

  // Check messages inline
  card.querySelector('.inbox-refresh-btn').addEventListener('click', async () => {
    const refreshBtn = card.querySelector('.inbox-refresh-btn');
    const previewEl  = card.querySelector('.inbox-preview');
    const statusEl   = card.querySelector('.inbox-status');
    refreshBtn.disabled = true;
    refreshBtn.textContent = '⏳ Checking…';
    statusEl.textContent = '';
    try {
      const r = await fetch(data.read_url);
      if (r.status === 410) {
        statusEl.textContent = '⏰ Inbox expired';
        previewEl.style.display = 'none';
        return;
      }
      if (!r.ok) { statusEl.textContent = `Error ${r.status}`; return; }
      const info = await r.json();
      renderInboxPreview(previewEl, info.messages);
      statusEl.textContent = `Last checked: ${new Date().toLocaleTimeString()} — ${info.count} message${info.count !== 1 ? 's' : ''}`;
    } catch (err) {
      statusEl.textContent = `Network error: ${err.message}`;
    } finally {
      refreshBtn.disabled = false;
      refreshBtn.textContent = '🔄 Check Messages';
    }
  });

  return card;
}

/**
 * Render the latest message(s) inside an inbox card's preview div.
 * @param {HTMLElement} previewEl
 * @param {Array} messages
 */
function renderInboxPreview(previewEl, messages) {
  previewEl.innerHTML = '';
  if (!messages || messages.length === 0) {
    previewEl.style.display = 'block';
    previewEl.innerHTML = '<p style="color:#555;font-size:.85rem">No messages yet.</p>';
    return;
  }
  previewEl.style.display = 'block';
  // Show up to 3 most recent messages
  const toShow = [...messages].reverse().slice(0, 3);
  toShow.forEach(m => {
    const wrap = document.createElement('div');
    wrap.style.cssText = 'background:#111;border:1px solid #2a2a2a;border-radius:8px;padding:.6rem .8rem;margin-bottom:.6rem';
    const from    = m.email_from ? `<div style="font-size:.78rem;color:#666"><strong>From:</strong> ${escHtml(m.email_from)}</div>` : '';
    const subject = m.subject    ? `<div style="font-size:.78rem;color:#666"><strong>Subject:</strong> ${escHtml(m.subject)}</div>` : '';
    const ts      = m.received_at ? `<div style="font-size:.72rem;color:#444">${new Date(m.received_at * 1000).toLocaleString()}</div>` : '';

    if (m.content_type === 'text/html') {
      // Use srcdoc instead of a blob: URL so Tor Browser can render HTML emails.
      wrap.innerHTML = `${from}${subject}${ts}`;
      const iframe = document.createElement('iframe');
      iframe.srcdoc = m.body;
      // sandbox="" is maximally restrictive: no scripts, no same-origin, no forms
      iframe.setAttribute('sandbox', '');
      iframe.style.cssText = 'width:100%;min-height:160px;border:none;background:#fff;border-radius:4px;margin-top:.4rem';
      iframe.title = 'Email body';
      wrap.appendChild(iframe);
    } else {
      const pre = document.createElement('pre');
      pre.style.cssText = 'white-space:pre-wrap;word-break:break-word;font-size:.85rem;color:#ccc;margin-top:.35rem;max-height:200px;overflow-y:auto';
      pre.textContent = m.body;
      wrap.innerHTML = `${from}${subject}${ts}`;
      wrap.appendChild(pre);
    }
    previewEl.appendChild(wrap);
  });
  if (messages.length > 3) {
    const more = document.createElement('p');
    more.style.cssText = 'font-size:.8rem;color:#555;text-align:center;margin-top:.3rem';
    more.textContent = `… and ${messages.length - 3} more — open the reader for the full inbox`;
    previewEl.appendChild(more);
  }
}

/** Copy text to clipboard, show feedback on the given button. */
function copyText(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = orig; }, 2000);
  }).catch(() => {
    const r = document.createRange();
    r.selectNodeContents(btn.parentElement.querySelector('code') || btn);
    const s = window.getSelection();
    if (s) { s.removeAllRanges(); s.addRange(r); }
  });
}

/** HTML-escape a string for safe insertion via innerHTML. */
function escHtml(s) {
  return String(s || '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ─── Init ─────────────────────────────────────────────────────────────────────

// On page load, pre-fill the join form from any invite link fragment
applyFragmentToJoinForm();

// ─── Slow-mode banner ─────────────────────────────────────────────────────────
// Poll /api/slow-mode every 10 s to show or hide the persistent amber banner.
const _refreshSlowModeBanner = () => {
  fetch('/api/slow-mode', { cache: 'no-store' })
    .then(r => r.ok ? r.json() : null)
    .then(d => {
      const b = document.getElementById('slow-mode-banner');
      if (!b) return;
      if (d && d.active) {
        const targets = Array.isArray(d.targets) && d.targets.length
          ? d.targets
          : ['all'];
        const label = targets.includes('all')
          ? 'all services'
          : targets.map(t => t.replace(/_/g, ' ')).join(', ');
        b.textContent = `🐢 SLOW MODE ACTIVE — rate-limiting: ${label}`;
        b.style.display = 'block';
      } else {
        b.style.display = 'none';
      }
    })
    .catch(() => {});
};
_refreshSlowModeBanner();
setInterval(_refreshSlowModeBanner, 10000);
