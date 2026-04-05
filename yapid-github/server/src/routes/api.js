/**
 * YapID — Public API Routes
 *
 * Provides OIDC-compatible endpoints for third-party integrations:
 *
 *  GET  /api/userinfo — return sub and premium status (OIDC standard)
 *  POST /api/verify   — token introspection for server-to-server verification
 *  GET  /api/status   — health / readiness check including database ping
 *
 * @module routes/api
 * @license BSL-1.1
 */

import { Router }    from 'express';
import { rateLimit } from 'express-rate-limit';

import { verifyAccessToken } from '../lib/crypto.js';
import { getDb }             from '../db/database.js';

export const apiRouter = Router();

// ---------------------------------------------------------------------------
// Rate limiter
// ---------------------------------------------------------------------------

const apiLimiter = rateLimit({
  windowMs:        60 * 1000, // 1 minute
  max:             60,
  standardHeaders: true,
  legacyHeaders:   false,
  handler:         (_req, res) => res.status(429).json({ error: 'Too many requests' }),
});

// ---------------------------------------------------------------------------
// GET /api/userinfo
// ---------------------------------------------------------------------------

/**
 * OIDC UserInfo endpoint.
 *
 * Returns the minimal public profile for the authenticated account.
 * Intentionally omits display name and avatar — only sub and premium status
 * are exposed to keep the endpoint privacy-preserving by default.
 *
 * Requires: Authorization: Bearer <access_token>
 */
apiRouter.get('/userinfo', (req, res) => {
  const token = req.headers?.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Authorization header required' });

  const payload = verifyAccessToken(token);
  if (!payload) return res.status(401).json({ error: 'Invalid or expired token' });

  const db      = getDb();
  const account = db.prepare(
    'SELECT id, is_premium, premium_until FROM accounts WHERE id = ?'
  ).get(payload.sub);

  if (!account) return res.status(404).json({ error: 'Account not found' });

  return res.json({
    sub:           account.id,
    yapid_premium: !!(account.is_premium && account.premium_until > Date.now()),
  });
});

// ---------------------------------------------------------------------------
// POST /api/verify
// ---------------------------------------------------------------------------

/**
 * Token introspection endpoint for server-to-server verification.
 *
 * Third-party services can POST an access token here to check whether it
 * is valid, retrieve the account ID, and check premium status — without
 * needing to implement JWT verification themselves.
 *
 * Always returns 200.  Check the `valid` field in the response body.
 *
 * Body: { access_token: string }
 */
apiRouter.post('/verify', apiLimiter, (req, res) => {
  const token = req.body?.access_token || req.body?.token;
  if (!token) return res.json({ valid: false });

  const payload = verifyAccessToken(token);
  if (!payload) return res.json({ valid: false });

  const db      = getDb();
  const session = db.prepare(`
    SELECT s.expires_at, a.is_premium, a.premium_until
    FROM sessions s
    JOIN accounts a ON a.id = s.account_id
    WHERE s.session_id = ? AND s.expires_at > ?
  `).get(payload.sessionId, Date.now());

  if (!session) return res.json({ valid: false });

  const isPremium = !!(session.is_premium && session.premium_until > Date.now());
  const issuer    = process.env.ISSUER_URL || 'https://id.yaphub.xyz';

  return res.json({
    valid:   true,
    // OIDC standard fields
    sub:     payload.sub,
    iss:     issuer,
    scope:   payload.scope || 'openid profile',
    expires_in: Math.max(0, Math.floor((payload.exp * 1000 - Date.now()) / 1000)),
    // YapID custom fields
    yapid_premium: isPremium,
    // Legacy fields — kept for backwards compatibility
    accountId:  payload.sub,
    isPremium,
    sessionId:  payload.sessionId,
  });
});

// ---------------------------------------------------------------------------
// GET /api/status
// ---------------------------------------------------------------------------

/**
 * Lightweight status / readiness endpoint.
 *
 * Returns service metadata and the result of a trivial database ping.
 * Useful for load balancer health checks and uptime monitoring.
 */
apiRouter.get('/status', (_req, res) => {
  let dbOk = false;
  try {
    getDb().prepare('SELECT 1').get();
    dbOk = true;
  } catch {
    // Database not reachable — dbOk stays false
  }

  return res.json({
    service: 'yapid',
    version: '2.0.0',
    ok:      dbOk,
    ts:      new Date().toISOString(),
  });
});
