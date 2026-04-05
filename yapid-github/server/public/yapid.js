/**
 * YapID Browser SDK
 * ==================
 * Einbinden auf jeder Seite:
 *
 *   import { YapID } from 'https://id.yaphub.xyz/yapid.js';
 *   const yapid = new YapID();
 *
 * Oder als Script-Tag:
 *   <script src="https://id.yaphub.xyz/yapid.js"></script>
 *   <script>
 *     const yapid = new window.YapID();
 *   </script>
 *
 * Für YAP selbst:
 *   const session = await yapid.autoLogin();
 *   if (session) showPremiumUI(session);
 */

const YAPID_ENDPOINT = 'https://id.yaphub.xyz';
const DB_NAME        = 'yapid-v1';
const DB_VERSION     = 1;
const STORE          = 'keys';

class YapID {
  constructor(options = {}) {
    this.endpoint = (options.endpoint || YAPID_ENDPOINT).replace(/\/$/, '');
    this._db = null;
  }

  // ── IndexedDB Helpers ─────────────────────────────────────────

  async _openDb() {
    if (this._db) return this._db;
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = e => e.target.result.createObjectStore(STORE);
      req.onsuccess  = e => { this._db = e.target.result; resolve(this._db); };
      req.onerror    = () => reject(req.error);
    });
  }

  async _dbSet(key, value) {
    const db = await this._openDb();
    return new Promise((resolve, reject) => {
      const tx  = db.transaction(STORE, 'readwrite');
      const req = tx.objectStore(STORE).put(value, key);
      req.onsuccess = () => resolve();
      req.onerror   = () => reject(req.error);
    });
  }

  async _dbGet(key) {
    const db = await this._openDb();
    return new Promise((resolve, reject) => {
      const tx  = db.transaction(STORE, 'readonly');
      const req = tx.objectStore(STORE).get(key);
      req.onsuccess = () => resolve(req.result ?? null);
      req.onerror   = () => reject(req.error);
    });
  }

  async _dbDelete(key) {
    const db = await this._openDb();
    return new Promise((resolve, reject) => {
      const tx  = db.transaction(STORE, 'readwrite');
      const req = tx.objectStore(STORE).delete(key);
      req.onsuccess = () => resolve();
      req.onerror   = () => reject(req.error);
    });
  }

  // ── AES-256-GCM Non-Extractable Key ──────────────────────────
  // Der Key kann per JavaScript nicht ausgelesen werden.
  // Selbst bei XSS-Angriff ist der Key sicher.

  async _getEncKey() {
    const existing = await this._dbGet('enc-key');
    if (existing) return existing;

    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,  // non-extractable!
      ['encrypt', 'decrypt']
    );

    await this._dbSet('enc-key', key);
    return key;
  }

  async _encrypt(plaintext) {
    const key     = await this._getEncKey();
    const iv      = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(plaintext);
    const ct      = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
    return { iv: Array.from(iv), ct: Array.from(new Uint8Array(ct)) };
  }

  async _decrypt(stored) {
    const key = await this._getEncKey();
    const iv  = new Uint8Array(stored.iv);
    const ct  = new Uint8Array(stored.ct);
    const pt  = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    return new TextDecoder().decode(pt);
  }

  // ── Solana Keypair aus BIP-39 Mnemonic ───────────────────────

  async _mnemonicToKeypair(mnemonic) {
    // BIP-39 → 64-byte seed via PBKDF2
    const enc     = new TextEncoder();
    const keyMat  = await crypto.subtle.importKey(
      'raw', enc.encode(mnemonic), 'PBKDF2', false, ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: enc.encode('yapid-bip39'), iterations: 210000, hash: 'SHA-256' },
      keyMat, 256
    );

    // Dynamisch tweetnacl laden
    const { default: nacl } = await import('https://esm.sh/tweetnacl@1.0.3');
    const keypair = nacl.sign.keyPair.fromSeed(new Uint8Array(bits).slice(0, 32));

    // Base58 encode (Solana-Format)
    const { default: bs58 } = await import('https://esm.sh/bs58@6.0.0');
    return {
      publicKey:  bs58.encode(keypair.publicKey),
      secretKey:  keypair.secretKey,
    };
  }

  async _sign(message, secretKey) {
    const { default: nacl }  = await import('https://esm.sh/tweetnacl@1.0.3');
    const tweetnaclUtilMod   = await import('https://esm.sh/tweetnacl-util@0.15.1');
    const decodeUTF8         = tweetnaclUtilMod.decodeUTF8 || tweetnaclUtilMod.default.decodeUTF8;
    const { default: bs58 }  = await import('https://esm.sh/bs58@6.0.0');
    const sig = nacl.sign.detached(decodeUTF8(message), secretKey);
    return bs58.encode(sig);
  }

  // ── Öffentliche API ───────────────────────────────────────────

  /**
   * Neuen YapID-Account erstellen.
   * Gibt die 12 Wörter zurück — User MUSS sie aufschreiben.
   * Wörter werden NICHT gespeichert.
   *
   * @returns {{ mnemonic: string, publicKey: string }}
   */
  async createAccount() {
    const { generateMnemonic } = await import('https://esm.sh/bip39@3.1.0');
    const mnemonic  = generateMnemonic(128); // 12 Wörter, 128-bit
    const { publicKey } = await this._mnemonicToKeypair(mnemonic);

    // Beim Server registrieren
    const res = await fetch(`${this.endpoint}/auth/register`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ walletAddress: publicKey }),
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Registration failed');

    return {
      mnemonic,
      publicKey,
      warning: 'Write these 12 words on paper. Never store digitally.',
    };
  }

  /**
   * Mit 12 Wörtern anmelden.
   * Signature bleibt im Browser — Mnemonic verlässt das Gerät nie.
   *
   * @param {string} mnemonic - 12 Wörter
   * @returns {{ accountId, isPremium, profile, expiresAt }}
   */
  async login(mnemonic) {
    if (!mnemonic || typeof mnemonic !== 'string') {
      throw new Error('mnemonic required');
    }

    const { publicKey, secretKey } = await this._mnemonicToKeypair(mnemonic.trim());

    // Schritt 1: Auto-Registrierung falls nötig
    await fetch(`${this.endpoint}/auth/register`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ walletAddress: publicKey }),
    });

    // Schritt 2: Challenge holen
    const chalRes  = await fetch(`${this.endpoint}/auth/challenge`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ walletAddress: publicKey }),
    });

    const { challengeId, message: sigMessage } = await chalRes.json();
    if (!challengeId) throw new Error('No challenge received');

    // Schritt 3: Signieren (lokal im Browser)
    const signature = await this._sign(sigMessage, secretKey);

    // Schritt 4: Login
    const loginRes = await fetch(`${this.endpoint}/auth/login`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ walletAddress: publicKey, challengeId, signature }),
    });

    const session = await loginRes.json();
    if (!loginRes.ok) throw new Error(session.error || 'Login failed');

    // Schritt 5: Session-Daten verschlüsselt speichern
    const encryptedToken = await this._encrypt(session.token);
    await this._dbSet('session', {
      accountId:      session.accountId,
      isPremium:      session.isPremium,
      profile:        session.profile,
      expiresAt:      session.expiresAt,
      encryptedToken,
    });

    // Public Key für Auto-Login speichern (kein Mnemonic!)
    const encPubKey = await this._encrypt(publicKey);
    await this._dbSet('pubkey', encPubKey);

    return {
      accountId:  session.accountId,
      isPremium:  session.isPremium,
      profile:    session.profile,
      expiresAt:  session.expiresAt,
    };
  }

  /**
   * Auto-Login — nutzt gespeicherte Session.
   * Kein Mnemonic nötig solange selber Browser.
   * Verifiziert beim Server ob Session noch gültig.
   *
   * @returns {object|null} Session oder null wenn nicht eingeloggt
   */
  async autoLogin() {
    const stored = await this._dbGet('session');
    if (!stored) return null;
    if (stored.expiresAt < Date.now()) {
      await this._dbDelete('session');
      return null;
    }

    // Token entschlüsseln
    let token;
    try {
      token = await this._decrypt(stored.encryptedToken);
    } catch {
      await this._dbDelete('session');
      return null;
    }

    // Beim Server verifizieren
    const res = await fetch(`${this.endpoint}/auth/verify`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ token }),
    });

    if (!res.ok) {
      await this._dbDelete('session');
      return null;
    }

    const data = await res.json();
    if (!data.valid) {
      await this._dbDelete('session');
      return null;
    }

    return {
      accountId:  data.accountId,
      isPremium:  data.isPremium,
      profile:    data.profile,
      expiresAt:  data.expiresAt,
      token,      // für API-Calls der einbettenden Seite
    };
  }

  /**
   * Den aktuellen JWT-Token abrufen.
   * Wird von YAP genutzt um ihn an den Chat-Server zu schicken.
   *
   * @returns {string|null}
   */
  async getToken() {
    const stored = await this._dbGet('session');
    if (!stored || stored.expiresAt < Date.now()) return null;
    try {
      return await this._decrypt(stored.encryptedToken);
    } catch {
      return null;
    }
  }

  /**
   * Prüfen ob User eingeloggt ist (schnell, lokal).
   */
  async isLoggedIn() {
    const stored = await this._dbGet('session');
    return !!stored && stored.expiresAt > Date.now();
  }

  /**
   * Ausloggen.
   */
  async logout() {
    const token = await this.getToken();
    if (token) {
      await fetch(`${this.endpoint}/auth/logout`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ token }),
      }).catch(() => {});
    }
    await this._dbDelete('session');
    await this._dbDelete('pubkey');
  }

  /**
   * Profil aktualisieren (nur Premium).
   */
  async updateProfile({ displayName, profileLink }) {
    const token = await this.getToken();
    if (!token) throw new Error('Not logged in');

    const res = await fetch(`${this.endpoint}/auth/profile`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body:    JSON.stringify({ displayName, profileLink }),
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Update failed');
    return data;
  }
}

// Browser global + ES Module Export
if (typeof window !== 'undefined') window.YapID = YapID;
export { YapID };
export default YapID;
