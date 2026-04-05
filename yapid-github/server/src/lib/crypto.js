/**
 * YapID — Cryptographic Utilities
 *
 * Handles all cryptographic operations:
 *  - JWT signing and verification (access tokens + refresh tokens)
 *  - Ed25519 wallet signature verification (Solana-compatible)
 *  - Wallet address hashing (salted SHA-256)
 *  - Challenge / scope generation and validation
 *  - Nullifier generation (replay-attack protection)
 *
 * @module lib/crypto
 * @license BSL-1.1
 */

import { createHash, randomBytes } from 'crypto';
import nacl            from 'tweetnacl';
import tweetnaclUtil   from 'tweetnacl-util';
import bs58            from 'bs58';
import jwt             from 'jsonwebtoken';

const { decodeUTF8 } = tweetnaclUtil;

// ---------------------------------------------------------------------------
// Secrets — must be set via environment variables in production
// ---------------------------------------------------------------------------

function requireSecret(envKey, label) {
  const value = process.env[envKey];
  if (value) return value;

  console.warn(`[yapid] WARNING: ${envKey} is not set — using a random ${label}. All tokens will be invalidated on restart.`);
  return randomBytes(64).toString('hex');
}

const JWT_SECRET         = requireSecret('JWT_SECRET',         'access token secret');
const REFRESH_JWT_SECRET = requireSecret('REFRESH_JWT_SECRET', 'refresh token secret');

// ---------------------------------------------------------------------------
// Token TTLs
// ---------------------------------------------------------------------------

/** Access token lifetime: 1 hour */
export const ACCESS_TOKEN_TTL_MS  = 60 * 60 * 1000;

/** Refresh token lifetime: 1 year */
export const REFRESH_TOKEN_TTL_MS = 365 * 24 * 60 * 60 * 1000;

// Shared JWT options applied to both token types
const JWT_BASE_OPTIONS = {
  issuer:   process.env.ISSUER_URL || 'https://id.yaphub.xyz',
  audience: 'yapid-clients',
};

// ---------------------------------------------------------------------------
// Access tokens
// ---------------------------------------------------------------------------

/**
 * Signs a new access token.
 *
 * @param {object} payload - Claims to embed (sub, sessionId, scope, etc.)
 * @returns {string} Signed JWT
 */
export function signAccessToken(payload) {
  return jwt.sign(payload, JWT_SECRET, {
    ...JWT_BASE_OPTIONS,
    expiresIn: `${Math.floor(ACCESS_TOKEN_TTL_MS / 1000)}s`,
  });
}

/**
 * Verifies an access token and returns its decoded payload.
 *
 * @param {string} token
 * @returns {object|null} Decoded payload, or null if invalid / expired
 */
export function verifyAccessToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET, JWT_BASE_OPTIONS);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Refresh tokens
// ---------------------------------------------------------------------------

/**
 * Signs a new refresh token using a separate secret.
 *
 * @param {object} payload - Claims to embed (sub, sessionId, refreshTokenId)
 * @returns {string} Signed JWT
 */
export function signRefreshToken(payload) {
  return jwt.sign(payload, REFRESH_JWT_SECRET, {
    ...JWT_BASE_OPTIONS,
    expiresIn: `${Math.floor(REFRESH_TOKEN_TTL_MS / 1000)}s`,
  });
}

/**
 * Verifies a refresh token and returns its decoded payload.
 *
 * @param {string} token
 * @returns {object|null} Decoded payload, or null if invalid / expired
 */
export function verifyRefreshToken(token) {
  try {
    return jwt.verify(token, REFRESH_JWT_SECRET, JWT_BASE_OPTIONS);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Wallet hashing
// ---------------------------------------------------------------------------

/**
 * Produces a salted SHA-256 hash of a wallet address.
 * The raw wallet address is never stored in the database.
 *
 * @param {string} walletAddress - Base58-encoded public key
 * @returns {string} Hex-encoded hash
 */
export function hashWallet(walletAddress) {
  const salt = process.env.WALLET_SALT || 'yapid_wallet_salt_change_this';
  return createHash('sha256')
    .update(walletAddress + salt)
    .digest('hex');
}

// ---------------------------------------------------------------------------
// Ed25519 signature verification
// ---------------------------------------------------------------------------

/**
 * Verifies an Ed25519 signature produced by a Solana-compatible wallet.
 *
 * @param {string} walletAddress  - Base58-encoded public key
 * @param {string} message        - The plaintext message that was signed
 * @param {string} signatureB58   - Base58-encoded signature
 * @returns {boolean}
 */
export function verifySignature(walletAddress, message, signatureB58) {
  try {
    const publicKeyBytes = bs58.decode(walletAddress);
    const signatureBytes = bs58.decode(signatureB58);
    const messageBytes   = decodeUTF8(message);
    return nacl.sign.detached.verify(messageBytes, signatureBytes, publicKeyBytes);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Challenge / scope
// ---------------------------------------------------------------------------

/**
 * Generates a unique, time-stamped challenge scope string.
 * Format: `yapid:v1:<timestamp>:<32-byte-hex-nonce>`
 *
 * @returns {string}
 */
export function generateScope() {
  const nonce = randomBytes(32).toString('hex');
  return `yapid:v1:${Date.now()}:${nonce}`;
}

/**
 * Validates that a scope string is well-formed and has not expired (5 min TTL).
 *
 * @param {string} scope
 * @returns {boolean}
 */
export function validateScope(scope) {
  try {
    const parts = scope.split(':');
    if (parts.length < 4 || parts[0] !== 'yapid' || parts[1] !== 'v1') return false;
    const age = Date.now() - parseInt(parts[2], 10);
    return age >= 0 && age <= 5 * 60 * 1000;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Nullifier (replay-attack protection)
// ---------------------------------------------------------------------------

/**
 * Derives a deterministic nullifier from a wallet hash and scope.
 * If the same challenge scope is submitted twice, the nullifier will match
 * the stored record and the request will be rejected.
 *
 * @param {string} walletHash - Output of {@link hashWallet}
 * @param {string} scope      - Challenge scope string
 * @returns {string} Hex-encoded SHA-256 hash
 */
export function generateNullifier(walletHash, scope) {
  return createHash('sha256')
    .update(`nullifier:${walletHash}:${scope}`)
    .digest('hex');
}

// ---------------------------------------------------------------------------
// General helpers
// ---------------------------------------------------------------------------

/**
 * Generates a cryptographically random 32-byte session ID.
 *
 * @returns {string} 64-character hex string
 */
export function generateSessionId() {
  return randomBytes(32).toString('hex');
}

/**
 * Generates a short random seed used to produce deterministic avatars.
 *
 * @returns {string} 16-character hex string
 */
export function generateAvatarSeed() {
  return randomBytes(8).toString('hex');
}
