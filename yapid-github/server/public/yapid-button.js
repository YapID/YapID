/**
 * YapID Button v4
 * ================
 * - Refresh Tokens (1 Jahr, rotierend)
 * - State-Verifikation (CSRF-Schutz)
 * - Auto-Refresh im Hintergrund
 * - Login-Notification Check
 * - Standard OAuth 2.0 Response Format
 * - iframe Session Check (einmal einloggen, überall drin)
 */

const YAPID_ENDPOINT  = 'https://id.yaphub.xyz';
const YAPID_CHECK_URL = 'https://id.yaphub.xyz/session-check.html';
const CACHE_DB        = 'yapid-v2';

// ── IndexedDB für Token-Speicherung auf der einbettenden Seite ─
async function dbOpen() {
  return new Promise((res, rej) => {
    const r = indexedDB.open(CACHE_DB, 1);
    r.onupgradeneeded = e => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains('tokens')) db.createObjectStore('tokens');
    };
    r.onsuccess = e => res(e.target.result);
    r.onerror   = () => rej(r.error);
  });
}
async function dbGet(key) {
  try {
    const db = await dbOpen();
    return new Promise(res => {
      const r = db.transaction('tokens','readonly').objectStore('tokens').get(key);
      r.onsuccess = () => res(r.result ?? null);
      r.onerror   = () => res(null);
    });
  } catch { return null; }
}
async function dbSet(key, val) {
  try {
    const db = await dbOpen();
    return new Promise(res => {
      const r = db.transaction('tokens','readwrite').objectStore('tokens').put(val, key);
      r.onsuccess = () => res();
      r.onerror   = () => res();
    });
  } catch {}
}
async function dbDel(key) {
  try {
    const db = await dbOpen();
    return new Promise(res => {
      const r = db.transaction('tokens','readwrite').objectStore('tokens').delete(key);
      r.onsuccess = () => res();
      r.onerror   = () => res();
    });
  } catch {}
}

// ── AES-256-GCM für lokale Token-Verschlüsselung ─────────────
async function getEncKey() {
  const existing = await dbGet('_enc_key');
  if (existing) return existing;
  const key = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
  await dbSet('_enc_key', key);
  return key;
}
async function encryptToken(text) {
  const key = await getEncKey();
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const ct  = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, new TextEncoder().encode(text));
  return { iv: Array.from(iv), ct: Array.from(new Uint8Array(ct)) };
}
async function decryptToken(stored) {
  const key = await getEncKey();
  const pt  = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(stored.iv) }, key, new Uint8Array(stored.ct)
  );
  return new TextDecoder().decode(pt);
}

// ── Token Storage ─────────────────────────────────────────────
async function saveTokens(accessToken, refreshToken, sessionData) {
  const encAccess  = await encryptToken(accessToken);
  const encRefresh = await encryptToken(refreshToken);
  await dbSet('tokens', {
    encAccess,
    encRefresh,
    sub:       sessionData.sub,
    expiresIn: sessionData.expires_in,
    savedAt:   Date.now(),
    profile:   sessionData.profile,
    isPremium: sessionData.yapid_premium,
  });
}

async function loadTokens() {
  return dbGet('tokens');
}

async function clearTokens() {
  await dbDel('tokens');
}

async function getAccessToken() {
  const stored = await loadTokens();
  if (!stored) return null;
  try {
    const age       = Date.now() - stored.savedAt;
    const expiresMs = (stored.expiresIn || 3600) * 1000;
    // Token noch gültig (mit 60s Buffer)?
    if (age < expiresMs - 60000) {
      return await decryptToken(stored.encAccess);
    }
    // Token abgelaufen → Refresh
    return await refreshAccessToken(stored);
  } catch { return null; }
}

async function refreshAccessToken(stored) {
  try {
    const refreshToken = await decryptToken(stored.encRefresh);
    const res = await fetch(`${YAPID_ENDPOINT}/auth/refresh`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ refresh_token: refreshToken }),
    });
    if (!res.ok) { await clearTokens(); return null; }
    const data = await res.json();
    await saveTokens(data.access_token, data.refresh_token, data);
    return data.access_token;
  } catch { return null; }
}

// ── iframe Session Manager ────────────────────────────────────
class YapIDSessionManager {
  constructor() {
    this._iframe  = null;
    this._ready   = false;
    this._queue   = [];
    this._pending = new Map();
    this._counter = 0;
    this._initIframe();
  }

  _initIframe() {
    const iframe = document.createElement('iframe');
    iframe.src = YAPID_CHECK_URL;
    iframe.style.cssText = 'position:fixed;width:0;height:0;border:none;opacity:0;pointer-events:none;top:-9999px;left:-9999px';
    iframe.setAttribute('sandbox', 'allow-scripts allow-same-origin');
    document.body.appendChild(iframe);
    this._iframe = iframe;

    window.addEventListener('message', (event) => {
      if (event.origin !== YAPID_ENDPOINT) return;
      const { type, requestId } = event.data || {};
      if (type === 'YAPID_READY') {
        this._ready = true;
        this._queue.forEach(fn => fn());
        this._queue = [];
        return;
      }
      if (requestId && this._pending.has(requestId)) {
        const { resolve } = this._pending.get(requestId);
        this._pending.delete(requestId);
        resolve(event.data);
      }
    });
  }

  _send(message) {
    return new Promise((resolve) => {
      const requestId = (++this._counter) + '_' + Date.now();
      this._pending.set(requestId, { resolve });
      setTimeout(() => {
        if (this._pending.has(requestId)) {
          this._pending.delete(requestId);
          resolve(null);
        }
      }, 8000);
      const send = () => this._iframe.contentWindow.postMessage(
        { ...message, requestId }, YAPID_ENDPOINT
      );
      if (this._ready) send(); else this._queue.push(send);
    });
  }

  async check() {
    const result = await this._send({ type: 'YAPID_CHECK' });
    return result?.session || null;
  }

  async logout() {
    await this._send({ type: 'YAPID_LOGOUT' });
    await clearTokens();
  }
}

let _manager = null;
function getManager() {
  if (!_manager) _manager = new YapIDSessionManager();
  return _manager;
}

// ── State-Verifikation (CSRF-Schutz) ─────────────────────────
function generateState() {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)))
    .map(b => b.toString(16).padStart(2,'0')).join('');
}

// ── Redirect-Return verarbeiten ───────────────────────────────
async function handleRedirectReturn() {
  const hash = window.location.hash;
  if (!hash.includes('yapid_token=')) return null;

  const params       = new URLSearchParams(hash.slice(1));
  const accessToken  = params.get('yapid_token');
  const refreshToken = params.get('yapid_refresh');
  const returnedState = params.get('state');

  if (!accessToken) return null;

  // ── State verifizieren (CSRF-Schutz) ──────────────────────
  const savedState = sessionStorage.getItem('yapid_state');
  sessionStorage.removeItem('yapid_state');
  if (savedState && returnedState && savedState !== returnedState) {
    console.error('[YapID] State mismatch — possible CSRF attack');
    return null;
  }

  // Hash sofort entfernen
  history.replaceState(null, '', window.location.pathname + window.location.search);

  // Token verifizieren
  const res = await fetch(`${YAPID_ENDPOINT}/api/verify`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ access_token: accessToken }),
  }).catch(() => null);

  if (!res?.ok) return null;
  const data = await res.json();
  if (!data.valid) return null;

  // Tokens lokal verschlüsselt speichern
  if (refreshToken) {
    await saveTokens(accessToken, refreshToken, {
      ...data,
      expires_in: data.expires_in || 3600,
    });
  }

  return { ...data, token: accessToken, access_token: accessToken };
}

// ── Login Notification Check ──────────────────────────────────
async function checkNotifications(accessToken) {
  try {
    const res = await fetch(`${YAPID_ENDPOINT}/auth/notifications`, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    if (!res.ok) return;
    const { notifications } = await res.json();
    if (notifications?.length > 0) {
      // Custom Event feuern damit die einbettende Seite reagieren kann
      window.dispatchEvent(new CustomEvent('yapid:security-notice', {
        detail: {
          message:     notifications[0].message,
          logoutAllUrl: `${YAPID_ENDPOINT}/login`,
        }
      }));
    }
  } catch {}
}

// ── Web Component ─────────────────────────────────────────────
class YapIDButton extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
    this._session      = null;
    this._refreshTimer = null;
  }

  connectedCallback() {
    this._render();
    this._init();
  }

  disconnectedCallback() {
    if (this._refreshTimer) clearInterval(this._refreshTimer);
  }

  get theme()  { return this.getAttribute('theme')  || 'dark'; }
  get size()   { return this.getAttribute('size')   || 'medium'; }
  get btnText(){ return this.getAttribute('text')   || 'Sign in with '; }

  _css() {
    const sizes = {
      small:  { p:'6px 14px',  fs:'11px', h:'32px', r:'6px',  g:'6px'  },
      medium: { p:'9px 20px',  fs:'12px', h:'40px', r:'8px',  g:'8px'  },
      large:  { p:'12px 28px', fs:'14px', h:'48px', r:'10px', g:'10px' },
    };
    const themes = {
      dark:   { bg:'#111',    b:'#2a2a2a', c:'#f0f0f0', hb:'#1a1a1a', ac:'#7c3aed', do:'#333' },
      light:  { bg:'#fff',    b:'#e0e0e0', c:'#111',    hb:'#f5f5f5', ac:'#7c3aed', do:'#ccc' },
      purple: { bg:'#7c3aed', b:'#6d28d9', c:'#fff',    hb:'#6d28d9', ac:'#fff',    do:'rgba(255,255,255,.3)' },
    };
    return {
      s: sizes[this.size]   || sizes.medium,
      t: themes[this.theme] || themes.dark,
    };
  }

  _render() {
    const { s, t } = this._css();
    const logoSrc = this.theme === 'light'
      ? `${YAPID_ENDPOINT}/yaphub-dark.png`
      : `${YAPID_ENDPOINT}/yaphub.png`;

    this.shadowRoot.innerHTML = `
      <style>
        @import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@700&display=swap');
        :host { display: inline-block; }
        button {
          display: inline-flex; align-items: center; gap: ${s.g};
          padding: ${s.p}; height: ${s.h};
          background: ${t.bg}; color: ${t.c};
          border: 1px solid ${t.b}; border-radius: ${s.r};
          font-family: 'Space Mono', monospace; font-size: ${s.fs};
          font-weight: 700; cursor: pointer; letter-spacing: .04em;
          transition: all .2s; white-space: nowrap; outline: none;
        }
        button:hover { background: ${t.hb}; border-color: ${t.ac}; }
        button:active { transform: scale(.97); }
        button:disabled { opacity: .5; cursor: not-allowed; transform: none; }
        .logo { width: 35px; height: 35px; object-fit: contain; flex-shrink: 0; }
        .dot { width: 7px; height: 7px; border-radius: 50%; background: ${t.do}; flex-shrink: 0; transition: all .4s; }
        .dot.on { background: #22c55e; box-shadow: 0 0 6px #22c55e; animation: pulse 2s ease infinite; }
        @keyframes pulse { 0%,100%{opacity:1}50%{opacity:.5} }
        .spin { width:12px;height:12px;border:2px solid rgba(255,255,255,.2);border-top-color:${t.c};border-radius:50%;animation:sp .6s linear infinite; }
        @keyframes sp { to { transform: rotate(360deg); } }
      </style>
      <button id="btn" type="button">
        <span class="dot" id="dot"></span>
        <span id="label">${this.btnText}</span>
        <img class="logo" src="${logoSrc}" alt="" id="logo-img">
      </button>
    `;

    this.shadowRoot.getElementById('btn').addEventListener('click', () => this._click());
  }

  async _init() {
    // 1. Redirect-Return mit State-Verifikation
    const fromRedirect = await handleRedirectReturn();
    if (fromRedirect) {
      this._session = fromRedirect;
      this._setOn(fromRedirect);
      this._fire(fromRedirect);
      this._startRefreshTimer();
      checkNotifications(fromRedirect.token);
      return;
    }

    // 2. Lokaler Token vorhanden und noch gültig?
    const localToken = await getAccessToken();
    if (localToken) {
      const res = await fetch(`${YAPID_ENDPOINT}/api/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ access_token: localToken }),
      }).catch(() => null);

      if (res?.ok) {
        const data = await res.json();
        if (data.valid) {
          // Token gültig — UI zeigen aber KEIN Callback (User muss klicken)
          this._session = { ...data, token: localToken, access_token: localToken };
          this._setOn(this._session);
          this._startRefreshTimer();
          return;
        }
      }
      await clearTokens();
    }

    // 3. iframe-Check — Session auf id.yaphub.xyz?
    try {
      const session = await getManager().check();
      if (session) {
        this._session = session;
        this._setOn(session);
        // KEIN _fire — User muss klicken
      } else {
        this._setOff();
      }
    } catch {
      this._setOff();
    }
  }

  _startRefreshTimer() {
    // Token alle 55 Minuten refreshen (vor 1-Stunden-Ablauf)
    if (this._refreshTimer) clearInterval(this._refreshTimer);
    this._refreshTimer = setInterval(async () => {
      const newToken = await getAccessToken();
      if (newToken && this._session) {
        this._session.token        = newToken;
        this._session.access_token = newToken;
      }
    }, 55 * 60 * 1000);
  }

  _setOn(session) {
    const dot   = this.shadowRoot.getElementById('dot');
    const label = this.shadowRoot.getElementById('label');
    if (dot)   dot.classList.add('on');
    if (label) label.textContent = session.profile?.displayName
      || session.yapid_name
      || '';
  }

  _setOff() {
    const dot   = this.shadowRoot.getElementById('dot');
    const label = this.shadowRoot.getElementById('label');
    if (dot)   dot.classList.remove('on');
    if (label) label.textContent = 'Sign in with';
    this._session = null;
    if (this._refreshTimer) clearInterval(this._refreshTimer);
  }

  _click() {
    if (this._session?.access_token) {
      // Hat Token auf dieser Seite → Panel zeigen
      this._panel();
    } else if (this._session) {
      // Eingeloggt aber kein Token auf dieser Seite → Redirect
      this._redirect();
    } else {
      this._redirect();
    }
  }

  _redirect() {
    const state = generateState();
    sessionStorage.setItem('yapid_state', state);
    const url = new URL(`${YAPID_ENDPOINT}/login`);
    url.searchParams.set('redirect', window.location.href.split('#')[0]);
    url.searchParams.set('state', state);
    url.searchParams.set('scope', 'openid profile');
    window.location.href = url.toString();
  }

  _panel() {
    const existing = document.getElementById('_yapid_panel');
    if (existing) { existing.remove(); return; }

    const panel = document.createElement('div');
    panel.id = '_yapid_panel';
    const rect = this.getBoundingClientRect();
    panel.style.cssText = `
      position:fixed;top:${rect.bottom+8}px;left:${rect.left}px;
      background:#111;border:1px solid #2a2a2a;border-radius:10px;
      padding:16px;z-index:999999;min-width:240px;
      font-family:'Space Mono',monospace;font-size:11px;color:#888;
      box-shadow:0 8px 32px rgba(0,0,0,.7);
    `;

    const id      = this._session?.sub || this._session?.accountId || '';
    const premium = this._session?.yapid_premium || this._session?.isPremium;

    panel.innerHTML = `
      <div style="color:#a78bfa;font-weight:700;margin-bottom:6px;font-size:12px;display:flex;align-items:center;gap:6px">
        YapID
        ${premium ? '<span style="font-size:9px;color:#f59e0b;border:1px solid rgba(245,158,11,.3);border-radius:8px;padding:1px 6px">★ Premium</span>' : ''}
      </div>
      <div style="font-size:9px;color:#444;word-break:break-all;margin-bottom:14px;line-height:1.7">${id}</div>
      <button id="_yapid_logout_btn"
        style="width:100%;padding:7px;background:none;border:1px solid #2a2a2a;border-radius:6px;color:#666;font-family:Space Mono,monospace;font-size:10px;cursor:pointer;letter-spacing:.04em;transition:all .15s;margin-bottom:6px"
        onmouseover="this.style.borderColor='#fff';this.style.color='#fff'"
        onmouseout="this.style.borderColor='#2a2a2a';this.style.color='#666'">
        Logout
      </button>
      <button id="_yapid_logout_all_btn"
        style="width:100%;padding:7px;background:none;border:1px solid rgba(239,68,68,.3);border-radius:6px;color:rgba(239,68,68,.7);font-family:Space Mono,monospace;font-size:10px;cursor:pointer;letter-spacing:.04em;transition:all .15s"
        onmouseover="this.style.borderColor='#ef4444';this.style.color='#ef4444'"
        onmouseout="this.style.borderColor='rgba(239,68,68,.3)';this.style.color='rgba(239,68,68,.7)'">
        Logout from all devices
      </button>
    `;

    document.body.appendChild(panel);

    // Logout (nur diese Session)
    panel.querySelector('#_yapid_logout_btn').addEventListener('click', async () => {
      panel.querySelector('#_yapid_logout_btn').textContent = 'Logging out...';
      const token = this._session?.access_token;
      if (token) {
        await fetch(`${YAPID_ENDPOINT}/auth/logout`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ access_token: token }),
        }).catch(() => {});
      }
      await getManager().logout();
      this._setOff();
      panel.remove();
      this.dispatchEvent(new CustomEvent('yapid:logout', { bubbles: true }));
    });

    // Logout all devices
    panel.querySelector('#_yapid_logout_all_btn').addEventListener('click', async () => {
      panel.querySelector('#_yapid_logout_all_btn').textContent = 'Logging out all...';
      const token = this._session?.access_token;
      if (token) {
        await fetch(`${YAPID_ENDPOINT}/auth/logout-all`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ access_token: token }),
        }).catch(() => {});
      }
      await getManager().logout();
      this._setOff();
      panel.remove();
      this.dispatchEvent(new CustomEvent('yapid:logout', { bubbles: true, detail: { allDevices: true } }));
    });

    setTimeout(() => {
      document.addEventListener('click', function h(e) {
        if (!panel.contains(e.target)) { panel.remove(); document.removeEventListener('click', h); }
      });
    }, 100);
  }

  _fire(session) {
    this.dispatchEvent(new CustomEvent('yapid:login', { bubbles: true, detail: session }));
    const cb = this.getAttribute('onlogin');
    if (cb && typeof window[cb] === 'function') window[cb](session);
  }
}

customElements.define('yapid-button', YapIDButton);

// ── Globale Hilfsfunktionen ───────────────────────────────────
window.YapIDVerify = async (token) => {
  const res = await fetch(`${YAPID_ENDPOINT}/api/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ access_token: token }),
  });
  return res.json();
};

window.YapIDGetToken = async () => getAccessToken();