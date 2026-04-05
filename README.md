# YapID — Identity Server

A privacy-preserving identity provider based on BIP-39 passphrases and Ed25519 cryptography.

Instead of passwords or emails, YapID generates **12 secret words** (a BIP-39 mnemonic) that act as the user's permanent identity. The words never leave the browser — all signing happens locally using the Web Crypto API. The server only ever sees a public key derived from those words, and even that is never stored in plain text.

---

## How it works

### Creating an account
1. YapID generates a **12-word BIP-39 passphrase** in the browser (128-bit entropy)
2. The user writes the words down or downloads a backup card — shown only once, never stored
3. An Ed25519 keypair is derived from the words via PBKDF2 (210,000 iterations, SHA-256)
4. The derived public key is registered on the server as a **salted SHA-256 hash** — the raw public key is never stored

### Logging in
1. The user enters their 12 words
2. The keypair is re-derived locally in the browser
3. YapID requests a **one-time challenge** from the server
4. The browser signs the challenge with the Ed25519 private key — **the words and private key never leave the device**
5. The server verifies the signature and issues a JWT access token + rotating refresh token
6. The session is stored in **IndexedDB** encrypted with AES-256-GCM (non-extractable key) for auto-login on future visits

### Auto-login
On return visits the user does not need to enter their 12 words again. The encrypted session token in IndexedDB is verified against the server silently in the background.

---

## Privacy guarantees

- ✓ No email address, no phone number, no personal data collected
- ✓ The 12-word passphrase never leaves the browser
- ✓ The private key is derived in-browser and used only for signing — never transmitted
- ✓ Only a salted SHA-256 hash of the public key is stored in the database
- ✓ Sessions are stored client-side encrypted with AES-256-GCM (non-extractable key)
- ✓ Replay-attack protection via one-time nullifiers
- ✓ No IP addresses stored

---

## Features

- 🔑 BIP-39 passphrase generation (12 words, 128-bit entropy)
- 🔐 Ed25519 signature verification (Solana-compatible key format)
- 🪙 JWT access tokens (1 hour) + rotating refresh tokens (1 year)
- 🛡 Replay-attack protection via nullifiers
- 👤 Optional display name and profile link (premium accounts)
- 🖼 Deterministic SVG avatar generation (4 styles, no external services)
- 📋 OIDC discovery document at `/.well-known/openid-configuration`
- ⚡ SQLite via better-sqlite3 (WAL mode)
- 🚦 Per-route rate limiting
- 📄 Downloadable backup card (printable HTML, generated entirely client-side)

---

## Requirements

- Node.js 18 or later
- npm

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/yaphub/yapid.git
cd yapid/server

# 2. Install dependencies
npm install

# 3. Create your environment file
cp .env.example .env
```

Open `.env` and fill in all required values — especially the secrets:

```bash
# Generate JWT_SECRET
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

# Generate REFRESH_JWT_SECRET
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

# Generate WALLET_SALT
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

```bash
# 4. Start the server
npm start

# Development mode (auto-restart on file changes)
npm run dev
```

---

## Environment Variables

| Variable             | Required | Description                                                   |
|----------------------|----------|---------------------------------------------------------------|
| `JWT_SECRET`         | ✅       | Secret used to sign access tokens (min 64 chars)             |
| `REFRESH_JWT_SECRET` | ✅       | Secret used to sign refresh tokens (min 64 chars)            |
| `WALLET_SALT`        | ✅       | Salt used when hashing public keys (min 32 chars)            |
| `ISSUER_URL`         | ✅       | Public base URL of your YapID instance (no trailing slash)   |
| `ALLOWED_ORIGINS`    | ✅       | Comma-separated list of allowed CORS origins                 |
| `DB_PATH`            | ❌       | Path to the SQLite database file (default: `data/yapid.db`)  |
| `PORT`               | ❌       | HTTP port (default: `4000`)                                  |
| `HOST`               | ❌       | Bind address (default: `127.0.0.1`)                          |
| `NODE_ENV`           | ❌       | Set to `production` in production environments               |

See `.env.example` for a full template with descriptions.

---

## API Reference

### Authentication

| Method | Endpoint               | Description                                       |
|--------|------------------------|---------------------------------------------------|
| POST   | `/auth/register`       | Register a public key (idempotent)                |
| POST   | `/auth/challenge`      | Request a one-time challenge scope                |
| POST   | `/auth/login`          | Submit Ed25519 signature → receive token pair     |
| POST   | `/auth/refresh`        | Rotate a refresh token → new token pair           |
| POST   | `/auth/verify`         | Introspect an access token                        |
| POST   | `/auth/logout`         | Revoke the current session                        |
| POST   | `/auth/logout-all`     | Revoke all sessions for the account               |
| GET    | `/auth/sessions`       | List active sessions                              |
| GET    | `/auth/notifications`  | Fetch unread login alerts                         |
| POST   | `/auth/profile`        | Update display name / profile link (premium only) |

### Public API

| Method | Endpoint        | Description                                            |
|--------|-----------------|--------------------------------------------------------|
| GET    | `/api/userinfo` | OIDC UserInfo — returns sub and premium status         |
| POST   | `/api/verify`   | Token introspection for server-to-server verification  |
| GET    | `/api/status`   | Health check including database ping                   |

### Avatars

| Method | Endpoint               | Description                               |
|--------|------------------------|-------------------------------------------|
| GET    | `/avatar/:seed`        | Serve a deterministic SVG avatar          |
| GET    | `/avatar/info/styles`  | List available avatar styles              |

Avatar styles: `shapes` (default), `identicon`, `geometric`, `pixel`

Query parameters: `?style=identicon&size=120`

### OIDC Discovery

| Method | Endpoint                             | Description                         |
|--------|--------------------------------------|-------------------------------------|
| GET    | `/.well-known/openid-configuration`  | OpenID Connect discovery document   |

---

## Integrating YapID into your app

### 1. Add the client script

```html
<script type="module" src="https://id.yaphub.xyz/yapid.js"></script>
```

### 2. Create an account

```javascript
import { YapID } from 'https://id.yaphub.xyz/yapid.js';

const yapid = new YapID();

// Generates 12 words — show them to the user immediately
// They are NOT stored anywhere. The user must write them down.
const { mnemonic, publicKey } = await yapid.createAccount();
console.log(mnemonic); // "word1 word2 word3 ..."
```

### 3. Log in with 12 words

```javascript
const session = await yapid.login('word1 word2 word3 ... word12');
// session.accountId  — unique user identifier
// session.isPremium  — boolean
// session.profile    — { displayName, avatarSeed, profileLink }
```

### 4. Auto-login on return visits

```javascript
// No 12 words needed — uses the encrypted session from IndexedDB
const session = await yapid.autoLogin();
if (session) {
  // User is still logged in
}
```

### 5. Verify tokens server-side

```javascript
const response = await fetch('https://id.yaphub.xyz/api/verify', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ access_token: token }),
});

const { valid, accountId, isPremium } = await response.json();
```

---

## Project Structure

```
server/
├── src/
│   ├── server.js           # Express app, middleware, route registration
│   ├── db/
│   │   └── database.js     # SQLite initialisation and schema
│   ├── lib/
│   │   └── crypto.js       # JWT, Ed25519 verification, hashing helpers
│   └── routes/
│       ├── auth.js         # Authentication endpoints
│       ├── api.js          # Public API endpoints
│       └── avatar.js       # SVG avatar generation
├── public/                 # Static files (login page, SDK, assets)
├── client/                 # Integration examples
├── .env.example            # Environment variable template
├── package.json
└── LICENSE
```

---

## License

YapID is licensed under the [Business Source License 1.1](LICENSE).

- **Free to use** for individuals and organizations with annual gross revenue under **USD 20,000**
- **Commercial license required** for organizations above that threshold — contact [legal@yaphub.xyz](mailto:legal@yaphub.xyz)
- On **2030-04-05**, the license automatically converts to **Apache License 2.0**
