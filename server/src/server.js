/**
 * YapID — Identity Server
 *
 * A privacy-preserving, wallet-based identity provider.
 * Uses Ed25519 signature verification (Solana-compatible) and
 * issues JWT access/refresh tokens following the OIDC standard.
 *
 * @license BSL-1.1
 */

import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import { rateLimit } from 'express-rate-limit';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

import { authRouter }   from './routes/auth.js';
import { apiRouter }    from './routes/api.js';
import { avatarRouter } from './routes/avatar.js';
import { initDb }       from './db/database.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// App setup
// ---------------------------------------------------------------------------

const app = express();

// Trust the first proxy hop (required when running behind Nginx / Caddy)
app.set('trust proxy', 1);

// Do not advertise the framework
app.disable('x-powered-by');

// ---------------------------------------------------------------------------
// Security headers
// ---------------------------------------------------------------------------

app.use(helmet({
  // CSP is handled by the reverse proxy (Nginx)
  contentSecurityPolicy: false,
  hsts:           { maxAge: 31_536_000, includeSubDomains: true },
  referrerPolicy: { policy: 'no-referrer' },
}));

// ---------------------------------------------------------------------------
// CORS
// ---------------------------------------------------------------------------

const allowedOrigins = (process.env.ALLOWED_ORIGINS || '*')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

app.use(cors({
  origin:         allowedOrigins.length === 1 && allowedOrigins[0] === '*'
                    ? '*'
                    : allowedOrigins,
  methods:        ['GET', 'POST', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// ---------------------------------------------------------------------------
// Body parsing
// ---------------------------------------------------------------------------

app.use(express.json({ limit: '50kb' }));

// ---------------------------------------------------------------------------
// Global rate limit
// ---------------------------------------------------------------------------

app.use(rateLimit({
  windowMs:       15 * 60 * 1000, // 15 minutes
  max:            100,
  standardHeaders: true,
  legacyHeaders:  false,
  keyGenerator:   (req) => req.ip || 'unknown',
  handler:        (_req, res) => res.status(429).json({ error: 'Too many requests' }),
}));

// ---------------------------------------------------------------------------
// Static files
// ---------------------------------------------------------------------------

const PUBLIC_DIR = join(__dirname, '../../public');
app.use(express.static(PUBLIC_DIR));

// ---------------------------------------------------------------------------
// OpenID Connect discovery document
// ---------------------------------------------------------------------------

const ISSUER = process.env.ISSUER_URL || 'https://id.yaphub.xyz';

app.get('/.well-known/openid-configuration', (_req, res) => {
  res.json({
    issuer:                                ISSUER,
    authorization_endpoint:               `${ISSUER}/login`,
    token_endpoint:                        `${ISSUER}/auth/login`,
    token_endpoint_auth_methods_supported: ['none'],
    userinfo_endpoint:                     `${ISSUER}/api/userinfo`,
    revocation_endpoint:                   `${ISSUER}/auth/logout`,
    introspection_endpoint:                `${ISSUER}/api/verify`,
    response_types_supported:             ['token'],
    grant_types_supported:                ['implicit', 'refresh_token'],
    subject_types_supported:              ['public'],
    id_token_signing_alg_values_supported: ['HS256'],
    scopes_supported:                     ['openid', 'profile'],
    claims_supported:                     ['sub', 'iss', 'aud', 'exp', 'iat', 'yapid_premium'],
    yapid_version:                         '2.0.0',
    yapid_privacy_score:                   93,
    yapid_docs:                            `${ISSUER}/integration`,
  });
});

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

app.use('/auth',   authRouter);
app.use('/api',    apiRouter);
app.use('/avatar', avatarRouter);

app.get('/health', (_req, res) =>
  res.json({ ok: true, service: 'yapid', version: '2.0.0' })
);

// ---------------------------------------------------------------------------
// Error handlers
// ---------------------------------------------------------------------------

// Generic error handler — never leak stack traces to clients
app.use((err, _req, res, _next) => {
  console.error('[yapid] Unhandled error:', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 catch-all
app.use((_req, res) => res.status(404).json({ error: 'Not found' }));

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

const PORT = parseInt(process.env.PORT, 10) || 5000;
const HOST = process.env.HOST || '127.0.0.1';

initDb();

app.listen(PORT, HOST, () => {
  console.log(`[yapid] v2.0.0 listening on ${HOST}:${PORT}`);
});
