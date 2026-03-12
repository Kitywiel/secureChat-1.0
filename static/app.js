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
    ws.send(JSON.stringify({ type: 'join', room: roomId }));
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
    } else if (data.type === 'error') {
      appendMessage('⚠️', `Server error: ${data.reason}`, 'error');
    }
  });

  ws.addEventListener('close', () => {
    appendMessage('', 'Disconnected from room.', 'system');
    document.getElementById('message-input').disabled = true;
  });

  ws.addEventListener('error', () => {
    appendMessage('', 'Connection error — check that the server is running.', 'error');
  });
}

// ─── Event handlers ───────────────────────────────────────────────────────────

document.getElementById('join-form').addEventListener('submit', async (e) => {
  e.preventDefault();

  const nameInput = /** @type {HTMLInputElement} */ (document.getElementById('display-name'));
  const roomInput = /** @type {HTMLInputElement} */ (document.getElementById('room-id'));
  const passInput = /** @type {HTMLInputElement} */ (document.getElementById('passphrase'));
  const errEl = document.getElementById('join-error');
  const btn = document.getElementById('join-btn');

  errEl.textContent = '';

  const name = nameInput.value.trim() || 'Anonymous';
  const roomId = roomInput.value.trim();
  const passphrase = passInput.value;

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
    roomKey = await deriveKey(passphrase, roomId);
  } catch (err) {
    errEl.textContent = 'Key derivation failed: ' + err.message;
    btn.disabled = false;
    btn.textContent = 'Join Room →';
    return;
  } finally {
    // Always clear the passphrase from the DOM as soon as possible.
    passInput.value = '';
  }

  displayName = name.slice(0, 32);
  document.getElementById('room-label').textContent = `🔒 ${roomId}`;
  document.getElementById('message-input').disabled = false;

  showScreen('chat');
  document.getElementById('message-input').focus();
  connectWs(roomId);

  btn.disabled = false;
  btn.textContent = 'Join Room →';
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
  showScreen('lobby');
  document.getElementById('messages').innerHTML = '';
  document.getElementById('join-form').reset();
  document.getElementById('join-error').textContent = '';
});

