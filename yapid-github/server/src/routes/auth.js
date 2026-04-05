/**
 * YapID — Authentication Routes
 *
 * Implements a challenge–response login flow using Ed25519 wallet signatures:
 *
 *  1. POST /auth/register   — register a wallet (idempotent)
 *  2. POST /auth/challenge  — request a one-time challenge scope
 *  3. POST /auth/login      — submit signature → receive access + refresh tokens
 *  4. POST /auth/refresh    — rotate a refresh token → new token pair
 *  5. POST /auth/verify     — introspect an access token (server-side check)
 *  6. POST /auth/logout     — revoke a single session
 *  7. POST /auth/logout-all — revoke all sessions for an account
 *  8. GET  /auth/sessions   — list active sessions
 *  9. GET  /auth/notifications — fetch unread login alerts
 * 10. POST /auth/profile    — update display name / profile link (premium)
 *
 * @module routes/auth
 * @license BSL-1.1
 */

import { Router }   from 'express';
import { rateLimit } from 'express-rate-limit';
import { v4 as uuidv4 } from 'uuid';

import { getDb } from '../db/database.js';
import {
  hashWallet,
  verifySignature,
  generateScope,
  validateScope,
  generateNullifier,
  signAccessToken,
  signRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
  generateSessionId,
  generateAvatarSeed,
  ACCESS_TOKEN_TTL_MS,
  REFRESH_TOKEN_TTL_MS,
} from '../lib/crypto.js';

export const authRouter = Router();

// ---------------------------------------------------------------------------
// Rate limiters
// ---------------------------------------------------------------------------

/** Applied to register, challenge, login, and logout-all */
const authLimiter = rateLimit({
  windowMs:        15 * 60 * 1000, // 15 minutes
  max:             20,
  standardHeaders: true,
  legacyHeaders:   false,
  handler:         (_req, res) => res.status(429).json({ error: 'Too many attempts' }),
});

/** Applied to token refresh only */
const refreshLimiter = rateLimit({
  windowMs:        60 * 1000, // 1 minute
  max:             10,
  standardHeaders: true,
  legacyHeaders:   false,
  handler:         (_req, res) => res.status(429).json({ error: 'Too many refresh attempts' }),
});

// ---------------------------------------------------------------------------
// In-memory challenge store (5-minute TTL)
// ---------------------------------------------------------------------------

/**
 * @typedef {object} Challenge
 * @property {string}      scope          - One-time challenge scope string
 * @property {string}      walletHash     - Salted hash of the requesting wallet
 * @property {string|null} accountId      - Resolved account ID (null if not yet registered)
 * @property {string}      requestedScope - OIDC scope string (e.g. "openid profile")
 * @property {number}      expiresAt      - Unix timestamp (ms) after which the challenge is invalid
 */

/** @type {Map<string, Challenge>} */
const challenges = new Map();

// Purge expired challenges every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, value] of challenges) {
    if (value.expiresAt < now) challenges.delete(key);
  }
}, 5 * 60 * 1000);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Extracts the Bearer token from the Authorization header or request body.
 *
 * @param {import('express').Request} req
 * @returns {string|null}
 */
function extractToken(req) {
  const header = req.headers?.authorization;
  if (header?.startsWith('Bearer ')) return header.slice(7);
  return req.body?.access_token || req.body?.token || null;
}

/**
 * Builds the standard token response sent after a successful login or refresh.
 * Includes both OIDC-standard fields and backwards-compatible legacy fields.
 *
 * @param {object} account       - Account row from the database
 * @param {string} sessionId
 * @param {string} accessToken   - Signed JWT
 * @param {string} refreshToken  - Signed JWT
 * @returns {object}
 */
function buildTokenResponse(account, sessionId, accessToken, refreshToken) {
  const now        = Math.floor(Date.now() / 1000);
  const isPremium  = !!(account.is_premium && account.premium_until > Date.now());
  const expiresIn  = Math.floor(ACCESS_TOKEN_TTL_MS / 1000);
  const issuer     = process.env.ISSUER_URL || 'https://id.yaphub.xyz';

  return {
    // Standard OAuth 2.0 / OIDC fields
    access_token:  accessToken,
    refresh_token: refreshToken,
    token_type:    'Bearer',
    expires_in:    expiresIn,
    scope:         'openid profile',

    // Standard OIDC claims (also embedded in the JWT)
    sub: account.id,
    iss: issuer,
    aud: 'yapid-clients',
    iat: now,
    exp: now + expiresIn,

    // YapID custom claims
    yapid_premium: isPremium,
    yapid_avatar:  account.avatar_seed   || null,
    yapid_name:    account.display_name  || null,

    // Legacy fields — kept for backwards compatibility with existing integrations
    accountId: account.id,
    isPremium,
    sessionId,
    profile: {
      displayName: account.display_name || null,
      avatarSeed:  account.avatar_seed  || null,
      profileLink: account.profile_link || null,
    },
  };
}

// ---------------------------------------------------------------------------
// POST /auth/register
// ---------------------------------------------------------------------------

/**
 * Registers a wallet address.  Idempotent — returns { exists: true } if the
 * wallet is already registered without creating a duplicate account.
 */
authRouter.post('/register', authLimiter, (req, res) => {
  const { walletAddress } = req.body;

  if (!walletAddress || typeof walletAddress !== 'string') {
    return res.status(400).json({ error: 'walletAddress is required' });
  }

  // Accept Base58-encoded Ed25519 public keys (Solana address format)
  if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(walletAddress)) {
    return res.status(400).json({ error: 'Invalid wallet address format' });
  }

  const walletHash = hashWallet(walletAddress);
  const db         = getDb();
  const existing   = db.prepare('SELECT id FROM accounts WHERE wallet_hash = ?').get(walletHash);

  if (existing) {
    return res.status(200).json({ success: true, exists: true });
  }

  const id  = uuidv4();
  const now = Date.now();

  db.prepare(`
    INSERT INTO accounts (id, wallet_hash, created_at, last_seen_at, avatar_seed)
    VALUES (?, ?, ?, ?, ?)
  `).run(id, walletHash, now, now, generateAvatarSeed());

  return res.status(201).json({ success: true, exists: false });
});

// ---------------------------------------------------------------------------
// POST /auth/challenge
// ---------------------------------------------------------------------------

/**
 * Issues a one-time challenge scope that the client must sign with their
 * wallet's private key before submitting to /auth/login.
 */
authRouter.post('/challenge', authLimiter, (req, res) => {
  const { walletAddress, scope: requestedScope } = req.body;

  if (!walletAddress || typeof walletAddress !== 'string') {
    return res.status(400).json({ error: 'walletAddress is required' });
  }

  // Validate OIDC scopes — only openid and profile are supported
  const allowedScopes = ['openid', 'profile'];
  const scopes = (requestedScope || 'openid profile')
    .split(' ')
    .filter(s => allowedScopes.includes(s));

  if (!scopes.includes('openid')) scopes.unshift('openid');

  const walletHash  = hashWallet(walletAddress);
  const db          = getDb();
  const account     = db.prepare('SELECT id FROM accounts WHERE wallet_hash = ?').get(walletHash);

  const scope       = generateScope();
  const challengeId = generateSessionId();

  challenges.set(challengeId, {
    scope,
    walletHash,
    accountId:      account?.id ?? null,
    requestedScope: scopes.join(' '),
    expiresAt:      Date.now() + 5 * 60 * 1000,
  });

  return res.json({
    challengeId,
    scope,
    message: `Sign this to login to YapID:\n\n${scope}`,
  });
});

// ---------------------------------------------------------------------------
// POST /auth/login
// ---------------------------------------------------------------------------

/**
 * Verifies the wallet signature against the issued challenge, then issues
 * an access token and a rotating refresh token.
 */
authRouter.post('/login', authLimiter, async (req, res) => {
  const { walletAddress, challengeId, signature } = req.body;

  if (!walletAddress || !challengeId || !signature) {
    return res.status(400).json({ error: 'walletAddress, challengeId, and signature are required' });
  }

  // Validate challenge
  const challenge = challenges.get(challengeId);
  if (!challenge || challenge.expiresAt < Date.now()) {
    return res.status(401).json({ error: 'Challenge expired or not found' });
  }

  // Ensure the challenge belongs to this wallet
  const walletHash = hashWallet(walletAddress);
  if (challenge.walletHash !== walletHash) {
    return res.status(401).json({ error: 'Challenge / wallet mismatch' });
  }

  // Double-check scope TTL
  if (!validateScope(challenge.scope)) {
    challenges.delete(challengeId);
    return res.status(401).json({ error: 'Challenge expired' });
  }

  if (!challenge.accountId) {
    return res.status(401).json({ error: 'Wallet not registered — please register first' });
  }

  // Verify Ed25519 signature
  const sigMessage = `Sign this to login to YapID:\n\n${challenge.scope}`;
  if (!verifySignature(walletAddress, sigMessage, signature)) {
    return res.status(401).json({ error: 'Invalid signature' });
  }

  // Challenge is consumed — remove it immediately
  challenges.delete(challengeId);

  const db = getDb();

  // Replay-attack protection: each scope can only be redeemed once
  const nullifier = generateNullifier(walletHash, challenge.scope);
  if (db.prepare('SELECT nullifier FROM nullifiers WHERE nullifier = ?').get(nullifier)) {
    return res.status(401).json({ error: 'Replay attack detected' });
  }
  db.prepare('INSERT INTO nullifiers (nullifier, account_id, scope, used_at) VALUES (?, ?, ?, ?)')
    .run(nullifier, challenge.accountId, challenge.scope, Date.now());

  // Load full account row
  const account = db.prepare(`
    SELECT id, is_premium, premium_until, display_name, avatar_seed, profile_link
    FROM accounts WHERE id = ?
  `).get(challenge.accountId);

  const now       = Date.now();
  const sessionId = generateSessionId();

  // Sign access token (1 hour)
  const accessToken = signAccessToken({
    sub:           account.id,
    sessionId,
    scope:         challenge.requestedScope || 'openid profile',
    yapid_premium: !!(account.is_premium && account.premium_until > now),
    yapid_avatar:  account.avatar_seed,
    yapid_name:    account.display_name,
  });

  // Sign refresh token (1 year, rotating)
  const refreshTokenId = generateSessionId();
  const refreshToken   = signRefreshToken({
    sub:            account.id,
    sessionId,
    refreshTokenId,
  });

  const refreshExpiresAt = now + REFRESH_TOKEN_TTL_MS;

  // Persist session
  db.prepare(`
    INSERT INTO sessions (session_id, account_id, public_key, expires_at, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(sessionId, account.id, walletAddress, refreshExpiresAt, now);

  // Persist refresh token
  db.prepare(`
    INSERT INTO refresh_tokens (id, session_id, account_id, expires_at, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(refreshTokenId, sessionId, account.id, refreshExpiresAt, now);

  // Update last-seen timestamp
  db.prepare('UPDATE accounts SET last_seen_at = ? WHERE id = ?').run(now, account.id);

  // Notify other active sessions about the new login
  const otherSessions = db.prepare(`
    SELECT DISTINCT account_id FROM sessions
    WHERE account_id = ? AND session_id != ? AND expires_at > ?
  `).all(account.id, sessionId, now);

  if (otherSessions.length > 0) {
    db.prepare(`
      INSERT INTO login_notifications (id, account_id, session_id, message, created_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(
      uuidv4(),
      account.id,
      sessionId,
      `A new login was detected on your YapID account. If this was not you, visit ${process.env.ISSUER_URL || 'https://id.yaphub.xyz'} and use "Logout all devices" immediately.`,
      now
    );
  }

  return res.json(buildTokenResponse(account, sessionId, accessToken, refreshToken));
});

// ---------------------------------------------------------------------------
// POST /auth/refresh
// ---------------------------------------------------------------------------

/**
 * Rotates a refresh token: revokes the submitted token and issues a new
 * access token + refresh token pair.
 */
authRouter.post('/refresh', refreshLimiter, (req, res) => {
  const { refresh_token } = req.body;

  if (!refresh_token) {
    return res.status(400).json({ error: 'refresh_token is required' });
  }

  const payload = verifyRefreshToken(refresh_token);
  if (!payload) {
    return res.status(401).json({ error: 'Invalid or expired refresh token' });
  }

  const db  = getDb();
  const now = Date.now();

  // Verify the token exists in the database and has not been revoked
  const storedToken = db.prepare(`
    SELECT id, session_id, account_id
    FROM refresh_tokens
    WHERE id = ? AND expires_at > ? AND revoked = 0
  `).get(payload.refreshTokenId, now);

  if (!storedToken) {
    return res.status(401).json({ error: 'Refresh token revoked or expired' });
  }

  // Revoke the consumed token
  db.prepare('UPDATE refresh_tokens SET used_at = ?, revoked = 1 WHERE id = ?')
    .run(now, storedToken.id);

  // Load account
  const account = db.prepare(`
    SELECT id, is_premium, premium_until, display_name, avatar_seed, profile_link
    FROM accounts WHERE id = ?
  `).get(storedToken.account_id);

  if (!account) {
    return res.status(401).json({ error: 'Account not found' });
  }

  // Issue new token pair
  const newRefreshTokenId = generateSessionId();

  const newAccessToken = signAccessToken({
    sub:           account.id,
    sessionId:     storedToken.session_id,
    scope:         'openid profile',
    yapid_premium: !!(account.is_premium && account.premium_until > now),
    yapid_avatar:  account.avatar_seed,
    yapid_name:    account.display_name,
  });

  const newRefreshToken = signRefreshToken({
    sub:            account.id,
    sessionId:      storedToken.session_id,
    refreshTokenId: newRefreshTokenId,
  });

  const newRefreshExpiresAt = now + REFRESH_TOKEN_TTL_MS;

  db.prepare(`
    INSERT INTO refresh_tokens (id, session_id, account_id, expires_at, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(newRefreshTokenId, storedToken.session_id, account.id, newRefreshExpiresAt, now);

  db.prepare('UPDATE sessions SET expires_at = ? WHERE session_id = ?')
    .run(newRefreshExpiresAt, storedToken.session_id);

  db.prepare('UPDATE accounts SET last_seen_at = ? WHERE id = ?').run(now, account.id);

  return res.json(buildTokenResponse(account, storedToken.session_id, newAccessToken, newRefreshToken));
});

// ---------------------------------------------------------------------------
// POST /auth/verify
// ---------------------------------------------------------------------------

/**
 * Introspects an access token.  Checks both the JWT signature and the
 * corresponding session record in the database.
 */
authRouter.post('/verify', (req, res) => {
  const token = extractToken(req);
  if (!token) return res.status(400).json({ error: 'access_token is required' });

  const payload = verifyAccessToken(token);
  if (!payload) return res.status(401).json({ error: 'Invalid or expired token' });

  const db      = getDb();
  const session = db.prepare(`
    SELECT s.session_id, s.expires_at,
           a.is_premium, a.premium_until, a.display_name, a.avatar_seed, a.profile_link
    FROM sessions s
    JOIN accounts a ON a.id = s.account_id
    WHERE s.session_id = ? AND s.expires_at > ?
  `).get(payload.sessionId, Date.now());

  if (!session) return res.status(401).json({ error: 'Session not found or expired' });

  const isPremium = !!(session.is_premium && session.premium_until > Date.now());
  const issuer    = process.env.ISSUER_URL || 'https://id.yaphub.xyz';

  return res.json({
    valid:         true,
    // OIDC standard fields
    sub:           payload.sub,
    iss:           issuer,
    scope:         payload.scope || 'openid profile',
    expires_in:    Math.max(0, Math.floor((payload.exp * 1000 - Date.now()) / 1000)),
    // YapID custom fields
    yapid_premium: isPremium,
    yapid_avatar:  session.avatar_seed,
    yapid_name:    session.display_name,
    // Legacy fields
    accountId:     payload.sub,
    isPremium,
    sessionId:     payload.sessionId,
    profile: {
      displayName: session.display_name || null,
      avatarSeed:  session.avatar_seed  || null,
    },
  });
});

// ---------------------------------------------------------------------------
// POST /auth/logout
// ---------------------------------------------------------------------------

/**
 * Revokes the session associated with the provided access token.
 * Always returns 200 — even if the token is already invalid — to prevent
 * information leakage.
 */
authRouter.post('/logout', (req, res) => {
  const token = extractToken(req);

  if (token) {
    const payload = verifyAccessToken(token);
    if (payload?.sessionId) {
      const db = getDb();
      db.prepare('DELETE FROM sessions WHERE session_id = ?').run(payload.sessionId);
      db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE session_id = ?').run(payload.sessionId);
    }
  }

  return res.json({ success: true });
});

// ---------------------------------------------------------------------------
// POST /auth/logout-all
// ---------------------------------------------------------------------------

/**
 * Revokes every session and refresh token belonging to the account.
 * Intended as a "logout from all devices" emergency action.
 */
authRouter.post('/logout-all', authLimiter, (req, res) => {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ error: 'access_token is required' });

  const payload = verifyAccessToken(token);
  if (!payload) return res.status(401).json({ error: 'Invalid token' });

  const db = getDb();
  const { changes: sessionsRevoked } = db.prepare('DELETE FROM sessions WHERE account_id = ?').run(payload.sub);
  const { changes: tokensRevoked   } = db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE account_id = ?').run(payload.sub);

  console.log(
    `[auth] logout-all — account ${payload.sub.slice(0, 8)}: ` +
    `${sessionsRevoked} sessions, ${tokensRevoked} tokens revoked`
  );

  return res.json({
    success:          true,
    sessions_revoked: sessionsRevoked,
    tokens_revoked:   tokensRevoked,
  });
});

// ---------------------------------------------------------------------------
// GET /auth/sessions
// ---------------------------------------------------------------------------

/**
 * Returns a list of the account's active sessions (max 20), newest first.
 * Does not expose any sensitive data — only session IDs and timestamps.
 */
authRouter.get('/sessions', (req, res) => {
  const token = req.headers?.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Authorization header required' });

  const payload = verifyAccessToken(token);
  if (!payload) return res.status(401).json({ error: 'Invalid token' });

  const db       = getDb();
  const sessions = db.prepare(`
    SELECT session_id, created_at, expires_at
    FROM sessions
    WHERE account_id = ? AND expires_at > ?
    ORDER BY created_at DESC
    LIMIT 20
  `).all(payload.sub, Date.now());

  return res.json({
    sessions: sessions.map(s => ({
      sessionId:  s.session_id,
      createdAt:  s.created_at,
      expiresAt:  s.expires_at,
      isCurrent:  s.session_id === payload.sessionId,
    })),
    current: payload.sessionId,
  });
});

// ---------------------------------------------------------------------------
// GET /auth/notifications
// ---------------------------------------------------------------------------

/**
 * Returns unread login notifications for the current account (max 5,
 * from the past 7 days).  Marks them as read after fetching.
 */
authRouter.get('/notifications', (req, res) => {
  const token = req.headers?.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Authorization header required' });

  const payload = verifyAccessToken(token);
  if (!payload) return res.status(401).json({ error: 'Invalid token' });

  const db    = getDb();
  const since = Date.now() - 7 * 24 * 60 * 60 * 1000;

  const notifications = db.prepare(`
    SELECT id, message, created_at, read_at
    FROM login_notifications
    WHERE account_id = ?
      AND session_id != ?
      AND created_at > ?
      AND read_at IS NULL
    ORDER BY created_at DESC
    LIMIT 5
  `).all(payload.sub, payload.sessionId, since);

  // Mark all fetched notifications as read
  if (notifications.length > 0) {
    db.prepare(`
      UPDATE login_notifications SET read_at = ?
      WHERE account_id = ? AND read_at IS NULL
    `).run(Date.now(), payload.sub);
  }

  return res.json({ notifications });
});

// ---------------------------------------------------------------------------
// POST /auth/profile
// ---------------------------------------------------------------------------

/**
 * Updates the display name and/or profile link for the authenticated account.
 * Both fields require an active premium subscription.
 */
authRouter.post('/profile', (req, res) => {
  const token = req.headers?.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Authorization header required' });

  const payload = verifyAccessToken(token);
  if (!payload) return res.status(401).json({ error: 'Invalid token' });

  const { displayName, profileLink } = req.body || {};
  const db      = getDb();
  const account = db.prepare('SELECT id, is_premium, premium_until FROM accounts WHERE id = ?').get(payload.sub);

  if (!account) return res.status(404).json({ error: 'Account not found' });

  const isPremium = !!(account.is_premium && account.premium_until > Date.now());
  const updates   = [];
  const values    = [];

  if (displayName !== undefined) {
    if (!isPremium) return res.status(403).json({ error: 'Premium subscription required' });
    if (typeof displayName !== 'string' || displayName.length > 32) {
      return res.status(400).json({ error: 'displayName must be a string of max 32 characters' });
    }
    updates.push('display_name = ?');
    values.push(displayName || null);
  }

  if (profileLink !== undefined) {
    if (!isPremium) return res.status(403).json({ error: 'Premium subscription required' });
    if (typeof profileLink !== 'string' || profileLink.length > 200) {
      return res.status(400).json({ error: 'profileLink must be a string of max 200 characters' });
    }
    if (profileLink && !profileLink.startsWith('https://')) {
      return res.status(400).json({ error: 'profileLink must start with https://' });
    }
    updates.push('profile_link = ?');
    values.push(profileLink || null);
  }

  if (!updates.length) {
    return res.status(400).json({ error: 'No fields to update' });
  }

  values.push(payload.sub);
  db.prepare(`UPDATE accounts SET ${updates.join(', ')} WHERE id = ?`).run(...values);

  return res.json({ success: true });
});
