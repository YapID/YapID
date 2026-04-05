/**
 * YapID — Database Layer
 *
 * Initialises a SQLite database via better-sqlite3 and exposes a singleton
 * accessor used throughout the application.
 *
 * Schema overview:
 *  - accounts            — one row per registered wallet (no raw address stored)
 *  - sessions            — active login sessions, keyed by session_id
 *  - refresh_tokens      — rotating refresh tokens with revocation support
 *  - nullifiers          — used challenge scopes (replay-attack protection)
 *  - login_notifications — cross-session new-login alerts
 *  - premium_transactions — audit log for premium purchases
 *
 * @module db/database
 * @license BSL-1.1
 */

import Database  from 'better-sqlite3';
import { mkdirSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join }  from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// Singleton
// ---------------------------------------------------------------------------

/** @type {import('better-sqlite3').Database|undefined} */
let db;

// ---------------------------------------------------------------------------
// Initialisation
// ---------------------------------------------------------------------------

/**
 * Opens (or creates) the SQLite database, applies PRAGMA settings, runs
 * the schema migration, and schedules a periodic cleanup job.
 *
 * Must be called once at application startup before any route handler runs.
 *
 * @returns {import('better-sqlite3').Database}
 */
export function initDb() {
  const dbPath = process.env.DB_PATH
    || join(__dirname, '../../../data/yapid.db');

  mkdirSync(dirname(dbPath), { recursive: true });

  db = new Database(dbPath);

  // Performance and safety settings
  db.pragma('journal_mode = WAL');   // concurrent reads without blocking writes
  db.pragma('synchronous = NORMAL'); // safe after WAL; faster than FULL
  db.pragma('foreign_keys = ON');    // enforce referential integrity

  applySchema();
  scheduleCleanup();

  console.log(`[db] Database ready: ${dbPath}`);
  return db;
}

/**
 * Returns the initialised database instance.
 * Throws if {@link initDb} has not been called yet.
 *
 * @returns {import('better-sqlite3').Database}
 */
export function getDb() {
  if (!db) throw new Error('[db] Database not initialised — call initDb() first.');
  return db;
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

function applySchema() {
  db.exec(`
    -- -----------------------------------------------------------------------
    -- Accounts
    -- -----------------------------------------------------------------------
    -- wallet_hash is a salted SHA-256 of the wallet address.
    -- The raw wallet address is never stored.
    CREATE TABLE IF NOT EXISTS accounts (
      id            TEXT    PRIMARY KEY,
      wallet_hash   TEXT    UNIQUE NOT NULL,
      created_at    INTEGER NOT NULL,
      is_premium    INTEGER DEFAULT 0,
      premium_until INTEGER,
      display_name  TEXT,
      profile_link  TEXT,
      avatar_seed   TEXT,
      last_seen_at  INTEGER
    );

    -- -----------------------------------------------------------------------
    -- Sessions
    -- -----------------------------------------------------------------------
    -- One row per active login.  Expires when the refresh token expires.
    -- public_key stores the wallet address for audit purposes only.
    CREATE TABLE IF NOT EXISTS sessions (
      session_id  TEXT    PRIMARY KEY,
      account_id  TEXT    NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
      public_key  TEXT    NOT NULL,
      expires_at  INTEGER NOT NULL,
      created_at  INTEGER NOT NULL
    );

    -- -----------------------------------------------------------------------
    -- Refresh tokens
    -- -----------------------------------------------------------------------
    -- Tokens are rotated on every refresh request (old token is revoked,
    -- a new one is issued).  revoked = 1 tokens are purged by the cleanup job.
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id          TEXT    PRIMARY KEY,
      session_id  TEXT    NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
      account_id  TEXT    NOT NULL REFERENCES accounts(id)         ON DELETE CASCADE,
      expires_at  INTEGER NOT NULL,
      created_at  INTEGER NOT NULL,
      used_at     INTEGER,
      revoked     INTEGER DEFAULT 0
    );

    -- -----------------------------------------------------------------------
    -- Nullifiers
    -- -----------------------------------------------------------------------
    -- Each challenge scope can only be redeemed once.
    -- Records older than 7 days are purged by the cleanup job.
    CREATE TABLE IF NOT EXISTS nullifiers (
      nullifier   TEXT    PRIMARY KEY,
      account_id  TEXT    NOT NULL REFERENCES accounts(id),
      scope       TEXT    NOT NULL,
      used_at     INTEGER NOT NULL
    );

    -- -----------------------------------------------------------------------
    -- Login notifications
    -- -----------------------------------------------------------------------
    -- Written when a new session is created while other sessions are active.
    -- Surfaced to the user on their next request and then marked as read.
    CREATE TABLE IF NOT EXISTS login_notifications (
      id          TEXT    PRIMARY KEY,
      account_id  TEXT    NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
      session_id  TEXT    NOT NULL,
      message     TEXT    NOT NULL,
      created_at  INTEGER NOT NULL,
      read_at     INTEGER
    );

    -- -----------------------------------------------------------------------
    -- Premium transactions
    -- -----------------------------------------------------------------------
    -- Immutable audit log — rows are never deleted.
    CREATE TABLE IF NOT EXISTS premium_transactions (
      id            TEXT    PRIMARY KEY,
      account_id    TEXT    NOT NULL REFERENCES accounts(id),
      amount_usd    REAL    NOT NULL,
      duration_days INTEGER NOT NULL,
      payment_ref   TEXT,
      created_at    INTEGER NOT NULL
    );

    -- -----------------------------------------------------------------------
    -- Indexes
    -- -----------------------------------------------------------------------
    CREATE INDEX IF NOT EXISTS idx_sessions_account   ON sessions(account_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_expires   ON sessions(expires_at);
    CREATE INDEX IF NOT EXISTS idx_rt_session         ON refresh_tokens(session_id);
    CREATE INDEX IF NOT EXISTS idx_rt_account         ON refresh_tokens(account_id);
    CREATE INDEX IF NOT EXISTS idx_rt_expires         ON refresh_tokens(expires_at);
    CREATE INDEX IF NOT EXISTS idx_nullifiers_account ON nullifiers(account_id);
    CREATE INDEX IF NOT EXISTS idx_notifs_account     ON login_notifications(account_id);
  `);
}

// ---------------------------------------------------------------------------
// Cleanup job
// ---------------------------------------------------------------------------

/**
 * Runs once per hour and removes expired or invalidated records.
 * Keeps the database lean without requiring a manual VACUUM schedule.
 */
function scheduleCleanup() {
  const HOUR_MS        = 60 * 60 * 1000;
  const WEEK_MS        = 7  * 24 * 60 * 60 * 1000;
  const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;

  setInterval(() => {
    const now = Date.now();

    const sessions       = db.prepare('DELETE FROM sessions       WHERE expires_at < ?').run(now);
    const refreshTokens  = db.prepare('DELETE FROM refresh_tokens WHERE expires_at < ? OR revoked = 1').run(now);
    const nullifiers     = db.prepare('DELETE FROM nullifiers      WHERE used_at   < ?').run(now - WEEK_MS);
    const notifications  = db.prepare('DELETE FROM login_notifications WHERE created_at < ?').run(now - THIRTY_DAYS_MS);

    const total = sessions.changes + refreshTokens.changes
                + nullifiers.changes + notifications.changes;

    if (total > 0) {
      console.log(
        `[db] Cleanup: ${sessions.changes} sessions, ` +
        `${refreshTokens.changes} refresh tokens, ` +
        `${nullifiers.changes} nullifiers, ` +
        `${notifications.changes} notifications removed`
      );
    }
  }, HOUR_MS);
}
