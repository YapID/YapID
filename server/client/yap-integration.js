/**
 * yap-yapid-integration.js
 * ========================
 * Dieses File zeigt wie YAP YapID einbindet.
 * In deinen bestehenden chat.html / widget.html einfügen.
 *
 * Füge diesen Script-Tag IN deinen bestehenden Chat-Code ein:
 *
 *   <script type="module" src="/yap-yapid-integration.js"></script>
 *
 * ODER den Code direkt in dein bestehendes <script type="module"> integrieren.
 */

// ── YapID laden ───────────────────────────────────────────────
import { YapID } from 'https://id.yaphub.xyz/yapid.js';

const yapid = new YapID({ endpoint: 'https://id.yaphub.xyz' });
window._yapid = yapid;

// ── Globale Session-Variable ──────────────────────────────────
let yapidSession = null;

// ── Auto-Login beim Start ────────────────────────────────────
export async function initYapID() {
  try {
    yapidSession = await yapid.autoLogin();
    if (yapidSession) {
      onYapIDLogin(yapidSession);
    } else {
      onYapIDLogout();
    }
  } catch (e) {
    console.warn('[yapid] Auto-login failed:', e.message);
    onYapIDLogout();
  }
}

// ── Callbacks ─────────────────────────────────────────────────

function onYapIDLogin(session) {
  yapidSession = session;

  // 1. YapID-Button im Header aktualisieren
  const btn = document.getElementById('yapid-login-btn');
  if (btn) {
    btn.innerHTML = `<i class="fa-solid fa-circle-check" style="color:#22c55e"></i> ${session.profile?.displayName || session.accountId.slice(0, 8) + '...'}`;
    btn.style.borderColor = 'rgba(124,58,237,.4)';
  }

  // 2. Premium-Badge zeigen
  if (session.isPremium) {
    const badge = document.getElementById('premium-badge');
    if (badge) badge.style.display = 'inline-flex';
  }

  // 3. Anonymen Chat-Namen durch YapID-Namen ersetzen (optional)
  // Den anonName der aktuellen Session auf Display-Name setzen
  if (session.profile?.displayName && typeof anonName !== 'undefined') {
    anonName = session.profile.displayName;
    localStorage.setItem('tc_name', anonName);
  }

  // 4. Custom Event für andere Komponenten
  window.dispatchEvent(new CustomEvent('yapid:login', { detail: session }));

  console.log('[yapid] Logged in:', session.accountId, '| Premium:', session.isPremium);
}

function onYapIDLogout() {
  yapidSession = null;

  const btn = document.getElementById('yapid-login-btn');
  if (btn) {
    btn.innerHTML = '<i class="fa-solid fa-fingerprint"></i> YapID';
    btn.style.borderColor = '';
  }

  const badge = document.getElementById('premium-badge');
  if (badge) badge.style.display = 'none';

  window.dispatchEvent(new CustomEvent('yapid:logout'));
}

// ── Login-Modal öffnen ────────────────────────────────────────
export function openYapIDModal() {
  let modal = document.getElementById('yapid-modal');
  if (!modal) {
    modal = createLoginModal();
    document.body.appendChild(modal);
  }
  modal.style.display = 'flex';
}

function closeYapIDModal() {
  const modal = document.getElementById('yapid-modal');
  if (modal) modal.style.display = 'none';
}

function createLoginModal() {
  const modal = document.createElement('div');
  modal.id = 'yapid-modal';
  modal.style.cssText = `
    position: fixed; inset: 0; background: rgba(0,0,0,.85);
    z-index: 2000; display: flex; align-items: center;
    justify-content: center; padding: 20px;
  `;

  modal.innerHTML = `
    <div style="background:#111;border:1px solid #2e2e2e;border-radius:12px;width:100%;max-width:400px;padding:28px;font-family:'Space Mono',monospace">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
        <span style="font-size:14px;font-weight:700;color:#fff;display:flex;align-items:center;gap:8px">
          🔐 YapID Login
        </span>
        <button onclick="document.getElementById('yapid-modal').style.display='none'"
          style="background:none;border:none;color:#555;font-size:16px;cursor:pointer">✕</button>
      </div>
      <p style="font-size:11px;color:#666;margin-bottom:20px;line-height:1.6">
        Anonymous persistent identity. No email. No password.
      </p>

      <div style="display:flex;gap:0;border:1px solid #2e2e2e;border-radius:6px;overflow:hidden;margin-bottom:20px">
        <button id="ym-tab-login" onclick="ymSwitchTab('login')"
          style="flex:1;padding:9px;font-family:'Space Mono',monospace;font-size:10px;background:#fff;color:#000;border:none;cursor:pointer;font-weight:700">Login</button>
        <button id="ym-tab-create" onclick="ymSwitchTab('create')"
          style="flex:1;padding:9px;font-family:'Space Mono',monospace;font-size:10px;background:none;color:#888;border:none;cursor:pointer">New Account</button>
      </div>

      <div id="ym-section-login">
        <p style="font-size:11px;color:#888;margin-bottom:10px">Enter your 12 words:</p>
        <textarea id="ym-mnemonic-input" rows="3"
          style="width:100%;background:#1a1a1a;border:1px solid #2e2e2e;border-radius:6px;padding:10px;font-family:'Space Mono',monospace;font-size:11px;color:#f0f0f0;resize:none;outline:none;line-height:1.7"
          placeholder="word1 word2 word3 ..."></textarea>
        <button onclick="ymDoLogin()"
          style="width:100%;padding:12px;margin-top:10px;border-radius:6px;border:1px solid #fff;background:#fff;color:#000;font-family:'Space Mono',monospace;font-size:11px;font-weight:700;cursor:pointer">
          Login with 12 Words
        </button>
        <div id="ym-login-status" style="font-size:11px;margin-top:8px;min-height:16px;font-family:'Space Mono',monospace"></div>
      </div>

      <div id="ym-section-create" style="display:none">
        <div id="ym-create-step1">
          <p style="font-size:11px;color:#888;margin-bottom:12px;line-height:1.6">Generate 12 words and write them on paper immediately.</p>
          <button onclick="ymDoCreate()"
            style="width:100%;padding:12px;border-radius:6px;border:1px solid #fff;background:#fff;color:#000;font-family:'Space Mono',monospace;font-size:11px;font-weight:700;cursor:pointer">
            Generate 12 Words
          </button>
          <div id="ym-create-status" style="font-size:11px;margin-top:8px;min-height:16px;font-family:'Space Mono',monospace"></div>
        </div>
        <div id="ym-create-step2" style="display:none">
          <div style="background:rgba(245,158,11,.06);border:1px solid rgba(245,158,11,.25);border-radius:6px;padding:10px 12px;font-size:11px;color:#f59e0b;margin-bottom:12px;line-height:1.6">
            ⚠️ Write these 12 words on paper NOW. You see them only once.
          </div>
          <div id="ym-mnemonic-display"
            style="background:#0a0a0a;border:1px solid rgba(124,58,237,.3);border-radius:6px;padding:14px;font-family:'Space Mono',monospace;font-size:12px;line-height:2;color:#a78bfa;margin-bottom:12px;word-spacing:6px">
          </div>
          <button onclick="ymConfirmMnemonic()"
            style="width:100%;padding:12px;border-radius:6px;border:1px solid #fff;background:#fff;color:#000;font-family:'Space Mono',monospace;font-size:11px;font-weight:700;cursor:pointer">
            ✓ I wrote them — Continue
          </button>
          <div id="ym-confirm-status" style="font-size:11px;margin-top:8px;min-height:16px;font-family:'Space Mono',monospace"></div>
        </div>
      </div>
    </div>
  `;

  return modal;
}

// ── Modal-Funktionen (global, weil im innerHTML) ──────────────
window.ymSwitchTab = function(tab) {
  document.getElementById('ym-section-login').style.display  = tab === 'login'  ? 'block' : 'none';
  document.getElementById('ym-section-create').style.display = tab === 'create' ? 'block' : 'none';
  document.getElementById('ym-tab-login').style.cssText  = tab === 'login'  ? 'flex:1;padding:9px;font-family:Space Mono,monospace;font-size:10px;background:#fff;color:#000;border:none;cursor:pointer;font-weight:700' : 'flex:1;padding:9px;font-family:Space Mono,monospace;font-size:10px;background:none;color:#888;border:none;cursor:pointer';
  document.getElementById('ym-tab-create').style.cssText = tab === 'create' ? 'flex:1;padding:9px;font-family:Space Mono,monospace;font-size:10px;background:#fff;color:#000;border:none;cursor:pointer;font-weight:700' : 'flex:1;padding:9px;font-family:Space Mono,monospace;font-size:10px;background:none;color:#888;border:none;cursor:pointer';
};

window.ymDoLogin = async function() {
  const mnemonic = document.getElementById('ym-mnemonic-input').value.trim();
  const status   = document.getElementById('ym-login-status');
  if (!mnemonic) { status.style.color = '#ef4444'; status.textContent = 'Enter your 12 words'; return; }
  status.style.color = '#888'; status.textContent = 'Logging in...';
  try {
    const session = await yapid.login(mnemonic);
    onYapIDLogin(session);
    closeYapIDModal();
  } catch(e) {
    status.style.color = '#ef4444';
    status.textContent = 'Error: ' + e.message;
  }
};

window.ymDoCreate = async function() {
  const status = document.getElementById('ym-create-status');
  status.style.color = '#888'; status.textContent = 'Generating...';
  try {
    const { mnemonic } = await yapid.createAccount();
    window._yapidPendingMnemonic = mnemonic;
    document.getElementById('ym-mnemonic-display').textContent = mnemonic;
    document.getElementById('ym-create-step1').style.display = 'none';
    document.getElementById('ym-create-step2').style.display = 'block';
    status.textContent = '';
  } catch(e) {
    status.style.color = '#ef4444';
    status.textContent = 'Error: ' + e.message;
  }
};

window.ymConfirmMnemonic = async function() {
  const status = document.getElementById('ym-confirm-status');
  status.style.color = '#888'; status.textContent = 'Logging in...';
  try {
    const session = await yapid.login(window._yapidPendingMnemonic);
    window._yapidPendingMnemonic = null;
    onYapIDLogin(session);
    closeYapIDModal();
  } catch(e) {
    status.style.color = '#ef4444';
    status.textContent = 'Error: ' + e.message;
  }
};

// ── Hilfsfunktionen für YAP-Chat ─────────────────────────────

/** Prüft ob der aktuelle User eingeloggt ist */
export function isLoggedIn() {
  return !!yapidSession;
}

/** Gibt die aktuelle Session zurück */
export function getSession() {
  return yapidSession;
}

/** Gibt den aktuellen JWT-Token zurück (für API-Calls) */
export async function getToken() {
  return yapid.getToken();
}

/** Prüft ob User Premium hat */
export function isPremium() {
  return yapidSession?.isPremium === true;
}

// ── Auto-init ─────────────────────────────────────────────────
initYapID();
