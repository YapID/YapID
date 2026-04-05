# YapID — Identity Server

A privacy-preserving, wallet-based identity provider built for the YapHub ecosystem.

YapID lets users log in with their Solana wallet using a challenge–response signature flow — no passwords, no email addresses, no personal data stored. The server issues standard JWT access and refresh tokens following the OpenID Connect (OIDC) specification, making it easy to integrate with any application.

---

## How it works

1. The client requests a **challenge** — a one-time scope string
2. The user **signs** the challenge with their wallet's private key
3. The server **verifies** the Ed25519 signature and issues an access token + refresh token
4. Third-party services can **verify** tokens via `/api/verify` without implementing JWT themselves

The raw wallet address is never stored. Only a salted SHA-256 hash is kept in the database.

---

## Features

- 🔐 Ed25519 wallet signature verification (Solana-compatible)
- 🪙 JWT access tokens (1 hour) + rotating refresh tokens (1 year)
- 🛡 Replay-attack protection via nullifiers
- 👤 Optional display name and profile link (premium accounts)
- 🖼 Deterministic SVG avatar generation (4 styles, no external services)
- 📋 OIDC discovery document at `/.well-known/openid-configuration`
- ⚡ SQLite database via better-sqlite3 (WAL mode)
- 🚦 Per-route rate limiting via express-rate-limit

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

| Variable            | Required | Description                                                  |
|---------------------|----------|--------------------------------------------------------------|
| `JWT_SECRET`        | ✅       | Secret used to sign access tokens (min 64 chars)            |
| `REFRESH_JWT_SECRET`| ✅       | Secret used to sign refresh tokens (min 64 chars)           |
| `WALLET_SALT`       | ✅       | Salt used when hashing wallet addresses (min 32 chars)      |
| `ISSUER_URL`        | ✅       | Public base URL of your YapID instance (no trailing slash)  |
| `ALLOWED_ORIGINS`   | ✅       | Comma-separated list of allowed CORS origins                |
| `DB_PATH`           | ❌       | Path to the SQLite database file (default: `data/yapid.db`) |
| `PORT`              | ❌       | HTTP port (default: `4000`)                                 |
| `HOST`              | ❌       | Bind address (default: `127.0.0.1`)                         |
| `NODE_ENV`          | ❌       | Set to `production` in production environments              |

See `.env.example` for a full template with descriptions.

---

## API Reference

### Authentication

| Method | Endpoint              | Description                                      |
|--------|-----------------------|--------------------------------------------------|
| POST   | `/auth/register`      | Register a wallet address                        |
| POST   | `/auth/challenge`     | Request a one-time challenge scope               |
| POST   | `/auth/login`         | Submit signature → receive token pair            |
| POST   | `/auth/refresh`       | Rotate a refresh token → new token pair          |
| POST   | `/auth/verify`        | Introspect an access token                       |
| POST   | `/auth/logout`        | Revoke the current session                       |
| POST   | `/auth/logout-all`    | Revoke all sessions for the account              |
| GET    | `/auth/sessions`      | List active sessions                             |
| GET    | `/auth/notifications` | Fetch unread login alerts                        |
| POST   | `/auth/profile`       | Update display name / profile link (premium)     |

### Public API

| Method | Endpoint       | Description                                           |
|--------|----------------|-------------------------------------------------------|
| GET    | `/api/userinfo`| OIDC UserInfo — returns sub and premium status        |
| POST   | `/api/verify`  | Token introspection for server-to-server verification |
| GET    | `/api/status`  | Health check including database ping                  |

### Avatars

| Method | Endpoint              | Description                              |
|--------|-----------------------|------------------------------------------|
| GET    | `/avatar/:seed`       | Serve a deterministic SVG avatar         |
| GET    | `/avatar/info/styles` | List available avatar styles             |

Avatar styles: `shapes` (default), `identicon`, `geometric`, `pixel`

Query parameters: `?style=identicon&size=120`

### OIDC Discovery

| Method | Endpoint                            | Description                        |
|--------|-------------------------------------|------------------------------------|
| GET    | `/.well-known/openid-configuration` | OpenID Connect discovery document  |

---

## Integrating YapID

### 1. Add the client script

```html
<script src="https://id.yaphub.xyz/yapid.js"></script>
```

### 2. Trigger the login flow

```javascript
const result = await YapID.login();
// result.access_token  — use this to authenticate requests
// result.accountId     — unique user identifier
// result.isPremium     — boolean
```

### 3. Verify tokens server-side

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
│   ├── server.js          # Express app setup, middleware, routes
│   ├── db/
│   │   └── database.js    # SQLite initialisation and schema
│   ├── lib/
│   │   └── crypto.js      # JWT, Ed25519 verification, hashing
│   └── routes/
│       ├── auth.js        # Authentication endpoints
│       ├── api.js         # Public API endpoints
│       └── avatar.js      # SVG avatar generation
├── public/                # Static files served at /
├── .env.example           # Environment variable template
├── package.json
└── LICENSE
```

---

## License

YapID is licensed under the [Business Source License 1.1](LICENSE).

- **Free to use** for individuals and organizations with annual gross revenue under **USD 20,000**
- **Commercial license required** for organizations above that threshold — contact [legal@yaphub.xyz](mailto:legal@yaphub.xyz)
- On **2030-04-05**, the license automatically converts to **Apache 2.0**
