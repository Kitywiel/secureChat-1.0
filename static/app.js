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
      if (msgs.length > 0) {
        appendMessage(
          '',
          `── ${msgs.length} stored message${msgs.length !== 1 ? 's' : ''} ──`,
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
 * @param {string}     passcode  Server-side room passcode (empty string if none).
 */
function enterRoom(roomId, key, name, passcode) {
  roomKey = key;
  displayName = name.slice(0, 32);
  roomPasscode = passcode;
  stopDestructTimer();
  document.getElementById('room-label').textContent = `🔒 ${roomId}`;
  document.getElementById('message-input').disabled = false;
  document.getElementById('send-btn').disabled = false;
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

  if (!text || !roomKey || !ws || ws.readyState !== WebSocket.OPEN) return;

  input.value = '';
  input.style.height = 'auto';

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
  stopDestructTimer();
  showScreen('lobby');
  document.getElementById('messages').innerHTML = '';
  document.getElementById('join-form').reset();
  document.getElementById('join-error').textContent = '';
});

// ─── Share Files ──────────────────────────────────────────────────────────────

/** Reset the share screen to its initial (upload) state. */
function resetShareScreen() {
  document.getElementById('share-form').reset();
  document.getElementById('share-error').textContent = '';
  document.getElementById('share-result').classList.add('hidden');
  document.getElementById('share-upload-area').classList.remove('hidden');
  // Hide the passcode row and result
  document.getElementById('share-passcode-row').classList.add('hidden');
  document.getElementById('share-passcode-result').classList.add('hidden');
  // Hide QR container and reset button label
  document.getElementById('share-qr-container').classList.add('hidden');
  document.getElementById('share-qr-btn').textContent = '📱 Show QR Code';
  document.getElementById('share-qr-img').src = '';
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

  const file = fileInput.files && fileInput.files[0];
  if (!file) {
    errEl.textContent = 'Please select a file.';
    return;
  }

  const MAX_BYTES = 100 * 1024 * 1024; // 100 MB
  if (file.size > MAX_BYTES) {
    errEl.textContent = 'File is too large (100 MB maximum).';
    return;
  }

  const ttl = ttlSelect.value;
  btn.disabled = true;
  btn.textContent = 'Uploading…';

  const formData = new FormData();
  formData.append('file', file);
  if (passcode) formData.append('passcode', passcode);

  try {
    const resp = await fetch(`/share/upload?ttl=${encodeURIComponent(ttl)}`, {
      method: 'POST',
      body: formData,
    });

    if (!resp.ok) {
      const text = await resp.text();
      errEl.textContent = `Upload failed (${resp.status}): ${text}`;
      return;
    }

    const data = await resp.json();
    const downloadUrl = new URL(data.download_url, window.location.href).href;
    const expiresAt = new Date(data.expires_at * 1000);

    document.getElementById('share-link').textContent = downloadUrl;
    document.getElementById('share-expiry').textContent =
      `⚠️ One-time link — expires ${expiresAt.toLocaleString()}`;

    // Show the passcode to the uploader if one was set
    const passcodeResult = document.getElementById('share-passcode-result');
    if (passcode) {
      document.getElementById('share-result-passcode').textContent = passcode;
      passcodeResult.classList.remove('hidden');
    } else {
      passcodeResult.classList.add('hidden');
    }

    document.getElementById('share-result').classList.remove('hidden');
    document.getElementById('share-upload-area').classList.add('hidden');
  } catch (err) {
    errEl.textContent = 'Upload failed: ' + (err instanceof Error ? err.message : String(err));
  } finally {
    btn.disabled = false;
    btn.textContent = 'Upload & Generate Link';
  }
});

document.getElementById('share-copy-btn').addEventListener('click', () => {
  const linkEl = document.getElementById('share-link');
  const url = linkEl.textContent;
  if (!url) return;

  navigator.clipboard.writeText(url).then(() => {
    const btn = document.getElementById('share-copy-btn');
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = 'Copy'; }, 2000);
  }).catch(() => {
    // Fallback: select the text so the user can copy manually
    const range = document.createRange();
    range.selectNodeContents(linkEl);
    const sel = window.getSelection();
    if (sel) {
      sel.removeAllRanges();
      sel.addRange(range);
    }
  });
});

document.getElementById('share-copy-passcode-btn').addEventListener('click', () => {
  const el = document.getElementById('share-result-passcode');
  const text = el.textContent;
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.getElementById('share-copy-passcode-btn');
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = 'Copy'; }, 2000);
  }).catch(() => {
    const range = document.createRange();
    range.selectNodeContents(el);
    const sel = window.getSelection();
    if (sel) { sel.removeAllRanges(); sel.addRange(range); }
  });
});

// ─── Create Room ──────────────────────────────────────────────────────────────

/** Reset the create-room screen to its initial form state. */
function resetCreateRoomScreen() {
  document.getElementById('create-room-form').reset();
  document.getElementById('create-error').textContent = '';
  document.getElementById('create-room-result').classList.add('hidden');
  document.getElementById('create-room-form-area').classList.remove('hidden');
  document.getElementById('create-passcode-row').classList.add('hidden');
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

  btn.disabled = true;
  btn.textContent = 'Creating…';

  try {
    const resp = await fetch('/room/create', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        passcode: passcode || null,
        destruct_minutes: destructMinutes,
      }),
    });

    if (!resp.ok) {
      errEl.textContent = `Failed to create room (HTTP ${resp.status}).`;
      return;
    }

    const data = await resp.json();
    const roomId = data.room_id;

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

    currentCreateRoomData = { roomId, passphrase, passcode, expiresAt: data.expires_at, creatorName };

    document.getElementById('create-invite-link').textContent = inviteUrl;
    document.getElementById('create-passphrase-display').textContent = passphrase;

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
  const { roomId, passphrase, passcode, creatorName } = currentCreateRoomData;
  const btn = document.getElementById('create-join-btn');
  btn.disabled = true;
  btn.textContent = 'Joining…';
  try {
    const key = await deriveKey(passphrase, roomId);
    enterRoom(roomId, key, creatorName, passcode || '');
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
  const url = document.getElementById('create-invite-link').textContent;
  if (!url) return;
  toggleQr('create-qr-btn', 'create-qr-img', 'create-qr-container', url);
});

document.getElementById('share-qr-btn').addEventListener('click', () => {
  const url = document.getElementById('share-link').textContent;
  if (!url) return;
  toggleQr('share-qr-btn', 'share-qr-img', 'share-qr-container', url);
});

// ─── Init ─────────────────────────────────────────────────────────────────────

// On page load, pre-fill the join form from any invite link fragment
applyFragmentToJoinForm();
