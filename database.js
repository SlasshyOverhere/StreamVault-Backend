/**
 * StreamVault Database Module (Turso)
 *
 * Handles persistent user directory for search/discovery.
 * User data (profiles, friends, chat) still lives in Google Drive.
 * This is ONLY for finding users across sessions.
 */

const { createClient } = require('@libsql/client');

let db = null;

const DEFAULT_AI_MAX_CHATS = 10;
const DEFAULT_AI_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

function parsePositiveInt(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : fallback;
}

function asNumber(value, fallback = 0) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function normalizeText(value, maxLen = 512) {
  if (typeof value !== 'string') return '';
  return value.trim().slice(0, maxLen);
}

function asNullableText(value, maxLen = 512) {
  const normalized = normalizeText(value, maxLen);
  return normalized || null;
}

function mapAiUpgradeRequestRow(row) {
  if (!row) return null;
  return {
    id: asNumber(row.id, 0),
    googleId: row.google_id,
    status: row.status,
    requestType: row.request_type || 'referral',
    referral1: row.referral_1,
    referral2: row.referral_2,
    requestReason: row.request_reason || null,
    note: row.note || null,
    entitlementId: row.entitlement_id ? asNumber(row.entitlement_id, 0) : null,
    requestedAt: asNumber(row.requested_at, 0),
    reviewedAt: row.reviewed_at ? asNumber(row.reviewed_at, 0) : null,
    reviewedBy: row.reviewed_by || null,
    reviewNote: row.review_note || null,
    createdAt: asNumber(row.created_at, 0),
    updatedAt: asNumber(row.updated_at, 0),
  };
}

function mapAiEntitlementRow(row) {
  if (!row) return null;
  return {
    id: asNumber(row.id, 0),
    googleId: row.google_id,
    maxChats: asNumber(row.max_chats, 0),
    windowDays: asNumber(row.window_days, 0),
    expiresAt: asNumber(row.expires_at, 0),
    reason: row.reason || null,
    grantedBy: row.granted_by || null,
    requestId: row.request_id ? asNumber(row.request_id, 0) : null,
    revokedAt: row.revoked_at ? asNumber(row.revoked_at, 0) : null,
    revokedBy: row.revoked_by || null,
    revokeReason: row.revoke_reason || null,
    createdAt: asNumber(row.created_at, 0),
    updatedAt: asNumber(row.updated_at, 0),
  };
}

function mapAiChatBanRow(row) {
  if (!row) return null;
  return {
    googleId: row.google_id,
    isActive: Number(row.is_active) === 1,
    bannedAt: asNumber(row.banned_at, 0),
    bannedBy: row.banned_by || null,
    banReason: row.ban_reason || null,
    unbannedAt: row.unbanned_at ? asNumber(row.unbanned_at, 0) : null,
    unbannedBy: row.unbanned_by || null,
    unbanReason: row.unban_reason || null,
    updatedAt: asNumber(row.updated_at, 0),
  };
}

/**
 * Initialize Turso database connection
 */
async function initDatabase() {
  const url = process.env.TURSO_DATABASE_URL;
  const authToken = process.env.TURSO_AUTH_TOKEN;

  if (!url) {
    console.warn('[Database] TURSO_DATABASE_URL not set - user search will be in-memory only');
    return false;
  }

  try {
    db = createClient({
      url,
      authToken
    });

    // Create users table if not exists
    await db.execute(`
      CREATE TABLE IF NOT EXISTS users (
        google_id TEXT PRIMARY KEY,
        username TEXT UNIQUE,
        display_name TEXT,
        email TEXT,
        avatar_url TEXT,
        allow_friend_requests INTEGER DEFAULT 1,
        created_at INTEGER,
        last_seen INTEGER
      )
    `);

    // Create indexes for search
    await db.execute(`
      CREATE INDEX IF NOT EXISTS idx_username ON users(username)
    `);
    await db.execute(`
      CREATE INDEX IF NOT EXISTS idx_display_name ON users(display_name)
    `);
    await db.execute(`
      CREATE INDEX IF NOT EXISTS idx_email ON users(email)
    `);

    // Create persistent AI chat quota table
    await db.execute(`
      CREATE TABLE IF NOT EXISTS ai_chat_limits (
        fingerprint_hash TEXT PRIMARY KEY,
        window_start_ms INTEGER NOT NULL,
        used_count INTEGER NOT NULL DEFAULT 0,
        updated_at INTEGER NOT NULL
      )
    `);
    await db.execute(`
      CREATE INDEX IF NOT EXISTS idx_ai_chat_limits_updated_at ON ai_chat_limits(updated_at)
    `);

    // Upgrade requests submitted by users for higher AI limits
    await db.execute(`
      CREATE TABLE IF NOT EXISTS ai_upgrade_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        google_id TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        request_type TEXT NOT NULL DEFAULT 'referral',
        referral_1 TEXT NOT NULL,
        referral_2 TEXT NOT NULL,
        request_reason TEXT,
        note TEXT,
        entitlement_id INTEGER,
        requested_at INTEGER NOT NULL,
        reviewed_at INTEGER,
        reviewed_by TEXT,
        review_note TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      )
    `);
    await db.execute(`
      CREATE INDEX IF NOT EXISTS idx_ai_upgrade_requests_google_id_requested_at
      ON ai_upgrade_requests(google_id, requested_at)
    `);
    await db.execute(`
      CREATE INDEX IF NOT EXISTS idx_ai_upgrade_requests_status_requested_at
      ON ai_upgrade_requests(status, requested_at)
    `);
    try {
      await db.execute(`
        ALTER TABLE ai_upgrade_requests
        ADD COLUMN request_type TEXT NOT NULL DEFAULT 'referral'
      `);
    } catch (error) {
      const message = String(error?.message || '').toLowerCase();
      if (!message.includes('duplicate column')) {
        throw error;
      }
    }

    // Explicit AI chat bans (used for repeated rejected upgrade requests).
    await db.execute(`
      CREATE TABLE IF NOT EXISTS ai_chat_bans (
        google_id TEXT PRIMARY KEY,
        is_active INTEGER NOT NULL DEFAULT 1,
        banned_at INTEGER NOT NULL,
        banned_by TEXT,
        ban_reason TEXT,
        unbanned_at INTEGER,
        unbanned_by TEXT,
        unban_reason TEXT,
        updated_at INTEGER NOT NULL
      )
    `);
    await db.execute(`
      CREATE INDEX IF NOT EXISTS idx_ai_chat_bans_active_updated_at
      ON ai_chat_bans(is_active, updated_at)
    `);
    try {
      await db.execute(`
        ALTER TABLE ai_upgrade_requests
        ADD COLUMN request_reason TEXT
      `);
    } catch (error) {
      const message = String(error?.message || '').toLowerCase();
      if (!message.includes('duplicate column')) {
        throw error;
      }
    }

    // Entitlements override base AI limits for specific approved users
    await db.execute(`
      CREATE TABLE IF NOT EXISTS ai_entitlements (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        google_id TEXT NOT NULL,
        max_chats INTEGER NOT NULL,
        window_days INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        reason TEXT,
        granted_by TEXT,
        request_id INTEGER,
        revoked_at INTEGER,
        revoked_by TEXT,
        revoke_reason TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      )
    `);
    await db.execute(`
      CREATE INDEX IF NOT EXISTS idx_ai_entitlements_google_id_expires_at
      ON ai_entitlements(google_id, expires_at)
    `);
    await db.execute(`
      CREATE INDEX IF NOT EXISTS idx_ai_entitlements_revoked_at
      ON ai_entitlements(revoked_at)
    `);

    console.log('[Database] Turso connected and initialized');
    return true;
  } catch (error) {
    console.error('[Database] Failed to initialize:', error.message);
    return false;
  }
}

/**
 * Register or update a user in the directory
 */
async function upsertUser(user) {
  if (!db) return false;

  try {
    await db.execute({
      sql: `
        INSERT INTO users (google_id, username, display_name, email, avatar_url, allow_friend_requests, created_at, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(google_id) DO UPDATE SET
          username = excluded.username,
          display_name = excluded.display_name,
          email = excluded.email,
          avatar_url = excluded.avatar_url,
          allow_friend_requests = excluded.allow_friend_requests,
          last_seen = excluded.last_seen
      `,
      args: [
        user.googleId,
        user.username || null,
        user.displayName || null,
        user.email || null,
        user.avatarUrl || null,
        user.allowFriendRequests ? 1 : 0,
        user.createdAt || Date.now(),
        Date.now()
      ]
    });
    return true;
  } catch (error) {
    console.error('[Database] Upsert user error:', error.message);
    return false;
  }
}

/**
 * Search users by username, display name, or email
 */
async function searchUsers(query, excludeGoogleId, limit = 20) {
  if (!db) return [];

  try {
    const searchPattern = `%${query.toLowerCase()}%`;

    const result = await db.execute({
      sql: `
        SELECT google_id, username, display_name, avatar_url
        FROM users
        WHERE google_id != ?
          AND allow_friend_requests = 1
          AND (
            LOWER(username) LIKE ?
            OR LOWER(display_name) LIKE ?
            OR LOWER(email) LIKE ?
          )
        ORDER BY
          CASE
            WHEN LOWER(username) = ? THEN 1
            WHEN LOWER(username) LIKE ? THEN 2
            ELSE 3
          END,
          last_seen DESC
        LIMIT ?
      `,
      args: [
        excludeGoogleId,
        searchPattern,
        searchPattern,
        searchPattern,
        query.toLowerCase(),
        query.toLowerCase() + '%',
        limit
      ]
    });

    return result.rows.map(row => ({
      id: row.google_id,
      username: row.username,
      displayName: row.display_name,
      avatarUrl: row.avatar_url
    }));
  } catch (error) {
    console.error('[Database] Search users error:', error.message);
    return [];
  }
}

/**
 * Get a user by Google ID
 */
async function getUser(googleId) {
  if (!db) return null;

  try {
    const result = await db.execute({
      sql: 'SELECT * FROM users WHERE google_id = ?',
      args: [googleId]
    });

    if (result.rows.length === 0) return null;

    const row = result.rows[0];
    return {
      googleId: row.google_id,
      username: row.username,
      displayName: row.display_name,
      email: row.email,
      avatarUrl: row.avatar_url,
      allowFriendRequests: row.allow_friend_requests === 1,
      createdAt: row.created_at,
      lastSeen: row.last_seen
    };
  } catch (error) {
    console.error('[Database] Get user error:', error.message);
    return null;
  }
}

/**
 * Update user's last seen timestamp
 */
async function updateLastSeen(googleId) {
  if (!db) return false;

  try {
    await db.execute({
      sql: 'UPDATE users SET last_seen = ? WHERE google_id = ?',
      args: [Date.now(), googleId]
    });
    return true;
  } catch (error) {
    console.error('[Database] Update last seen error:', error.message);
    return false;
  }
}

/**
 * Update user's privacy setting for friend requests
 */
async function updateAllowFriendRequests(googleId, allow) {
  if (!db) return false;

  try {
    await db.execute({
      sql: 'UPDATE users SET allow_friend_requests = ? WHERE google_id = ?',
      args: [allow ? 1 : 0, googleId]
    });
    return true;
  } catch (error) {
    console.error('[Database] Update privacy error:', error.message);
    return false;
  }
}

/**
 * Consume one AI chat request from the caller's quota window.
 * This is intentionally atomic so concurrent requests cannot bypass limits.
 */
async function consumeAiChatQuota(fingerprintHash, options = {}) {
  if (!db) {
    return {
      storageAvailable: false,
      allowed: false,
      error: 'AI quota storage unavailable'
    };
  }

  const maxChats = parsePositiveInt(options.maxChats, DEFAULT_AI_MAX_CHATS);
  const windowMs = parsePositiveInt(options.windowMs, DEFAULT_AI_WINDOW_MS);
  const now = asNumber(options.now, Date.now());

  try {
    const result = await db.execute({
      sql: `
        INSERT INTO ai_chat_limits (fingerprint_hash, window_start_ms, used_count, updated_at)
        VALUES (?, ?, 1, ?)
        ON CONFLICT(fingerprint_hash) DO UPDATE SET
          used_count = CASE
            WHEN (? - ai_chat_limits.window_start_ms) >= ? THEN 1
            ELSE ai_chat_limits.used_count + 1
          END,
          window_start_ms = CASE
            WHEN (? - ai_chat_limits.window_start_ms) >= ? THEN ?
            ELSE ai_chat_limits.window_start_ms
          END,
          updated_at = ?
        RETURNING window_start_ms, used_count
      `,
      args: [
        fingerprintHash,
        now,
        now,
        now,
        windowMs,
        now,
        windowMs,
        now,
        now
      ]
    });

    const row = result.rows[0] || {};
    const windowStartMs = asNumber(row.window_start_ms, now);
    const rawUsedCount = asNumber(row.used_count, 0);
    const resetAt = windowStartMs + windowMs;
    const allowed = rawUsedCount <= maxChats;

    return {
      storageAvailable: true,
      allowed,
      limit: maxChats,
      used: Math.min(rawUsedCount, maxChats),
      rawUsed: rawUsedCount,
      remaining: Math.max(0, maxChats - Math.min(rawUsedCount, maxChats)),
      windowStartMs,
      resetAt,
      retryAfterMs: allowed ? 0 : Math.max(1000, resetAt - now)
    };
  } catch (error) {
    console.error('[Database] Consume AI quota error:', error.message);
    return {
      storageAvailable: false,
      allowed: false,
      error: 'AI quota storage error'
    };
  }
}

/**
 * Read AI chat quota status without consuming a request.
 */
async function getAiChatQuota(fingerprintHash, options = {}) {
  if (!db) {
    return {
      storageAvailable: false,
      allowed: false,
      error: 'AI quota storage unavailable'
    };
  }

  const maxChats = parsePositiveInt(options.maxChats, DEFAULT_AI_MAX_CHATS);
  const windowMs = parsePositiveInt(options.windowMs, DEFAULT_AI_WINDOW_MS);
  const now = asNumber(options.now, Date.now());

  try {
    const result = await db.execute({
      sql: `
        SELECT window_start_ms, used_count
        FROM ai_chat_limits
        WHERE fingerprint_hash = ?
      `,
      args: [fingerprintHash]
    });

    if (result.rows.length === 0) {
      return {
        storageAvailable: true,
        allowed: true,
        limit: maxChats,
        used: 0,
        rawUsed: 0,
        remaining: maxChats,
        windowStartMs: now,
        resetAt: now + windowMs,
        retryAfterMs: 0
      };
    }

    const row = result.rows[0];
    const windowStartMs = asNumber(row.window_start_ms, now);
    const rawUsedCount = asNumber(row.used_count, 0);
    const expired = now - windowStartMs >= windowMs;

    if (expired) {
      return {
        storageAvailable: true,
        allowed: true,
        limit: maxChats,
        used: 0,
        rawUsed: 0,
        remaining: maxChats,
        windowStartMs: now,
        resetAt: now + windowMs,
        retryAfterMs: 0
      };
    }

    const clampedUsed = Math.min(rawUsedCount, maxChats);
    const allowed = rawUsedCount < maxChats;
    const resetAt = windowStartMs + windowMs;

    return {
      storageAvailable: true,
      allowed,
      limit: maxChats,
      used: clampedUsed,
      rawUsed: rawUsedCount,
      remaining: Math.max(0, maxChats - clampedUsed),
      windowStartMs,
      resetAt,
      retryAfterMs: allowed ? 0 : Math.max(1000, resetAt - now)
    };
  } catch (error) {
    console.error('[Database] Get AI quota error:', error.message);
    return {
      storageAvailable: false,
      allowed: false,
      error: 'AI quota storage error'
    };
  }
}

async function getActiveAiEntitlement(googleId, options = {}) {
  if (!db) return null;
  const normalizedGoogleId = normalizeText(googleId, 256);
  if (!normalizedGoogleId) return null;

  const now = asNumber(options.now, Date.now());

  try {
    const result = await db.execute({
      sql: `
        SELECT *
        FROM ai_entitlements
        WHERE google_id = ?
          AND revoked_at IS NULL
          AND expires_at > ?
        ORDER BY expires_at DESC, id DESC
        LIMIT 1
      `,
      args: [normalizedGoogleId, now]
    });

    if (result.rows.length === 0) return null;
    return mapAiEntitlementRow(result.rows[0]);
  } catch (error) {
    console.error('[Database] Get active AI entitlement error:', error.message);
    return null;
  }
}

async function createAiEntitlement(googleId, options = {}) {
  if (!db) {
    return {
      ok: false,
      error: 'AI entitlement storage unavailable'
    };
  }

  const normalizedGoogleId = normalizeText(googleId, 256);
  const maxChats = parsePositiveInt(options.maxChats, 0);
  const windowDays = parsePositiveInt(options.windowDays, 0);
  const expiresAt = asNumber(options.expiresAt, 0);
  const now = asNumber(options.now, Date.now());

  if (!normalizedGoogleId || !maxChats || !windowDays || expiresAt <= now) {
    return {
      ok: false,
      error: 'Invalid entitlement payload'
    };
  }

  try {
    const result = await db.execute({
      sql: `
        INSERT INTO ai_entitlements (
          google_id, max_chats, window_days, expires_at, reason, granted_by, request_id, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        RETURNING *
      `,
      args: [
        normalizedGoogleId,
        maxChats,
        windowDays,
        expiresAt,
        asNullableText(options.reason, 1000),
        asNullableText(options.grantedBy, 256),
        options.requestId ? asNumber(options.requestId, 0) : null,
        now,
        now
      ]
    });

    return {
      ok: true,
      entitlement: mapAiEntitlementRow(result.rows[0])
    };
  } catch (error) {
    console.error('[Database] Create AI entitlement error:', error.message);
    return {
      ok: false,
      error: 'Failed to create AI entitlement'
    };
  }
}

async function listAiEntitlements(options = {}) {
  if (!db) return [];

  const now = asNumber(options.now, Date.now());
  const limit = parsePositiveInt(options.limit, 100);
  const effectiveLimit = Math.min(Math.max(limit, 1), 500);
  const status = normalizeText(options.status || 'all', 16).toLowerCase();

  const conditions = [];
  const args = [];

  if (status === 'active') {
    conditions.push('revoked_at IS NULL');
    conditions.push('expires_at > ?');
    args.push(now);
  } else if (status === 'inactive') {
    conditions.push('(revoked_at IS NOT NULL OR expires_at <= ?)');
    args.push(now);
  }

  let sql = 'SELECT * FROM ai_entitlements';
  if (conditions.length > 0) {
    sql += ` WHERE ${conditions.join(' AND ')}`;
  }
  sql += ' ORDER BY created_at DESC LIMIT ?';
  args.push(effectiveLimit);

  try {
    const result = await db.execute({ sql, args });
    return result.rows.map(mapAiEntitlementRow);
  } catch (error) {
    console.error('[Database] List AI entitlements error:', error.message);
    return [];
  }
}

async function getAiUpgradeRequestById(requestId) {
  if (!db) return null;

  const id = asNumber(requestId, 0);
  if (!id) return null;

  try {
    const result = await db.execute({
      sql: 'SELECT * FROM ai_upgrade_requests WHERE id = ?',
      args: [id]
    });
    if (result.rows.length === 0) return null;
    return mapAiUpgradeRequestRow(result.rows[0]);
  } catch (error) {
    console.error('[Database] Get AI upgrade request by id error:', error.message);
    return null;
  }
}

async function getLatestAiUpgradeRequestForUser(googleId) {
  if (!db) return null;
  const normalizedGoogleId = normalizeText(googleId, 256);
  if (!normalizedGoogleId) return null;

  try {
    const result = await db.execute({
      sql: `
        SELECT *
        FROM ai_upgrade_requests
        WHERE google_id = ?
        ORDER BY requested_at DESC, id DESC
        LIMIT 1
      `,
      args: [normalizedGoogleId]
    });
    if (result.rows.length === 0) return null;
    return mapAiUpgradeRequestRow(result.rows[0]);
  } catch (error) {
    console.error('[Database] Get latest AI upgrade request error:', error.message);
    return null;
  }
}

async function createAiUpgradeRequest(googleId, options = {}) {
  if (!db) {
    return {
      ok: false,
      error: 'AI upgrade request storage unavailable'
    };
  }

  const normalizedGoogleId = normalizeText(googleId, 256);
  const requestTypeRaw = normalizeText(options.requestType || 'referral', 32).toLowerCase();
  const requestType = requestTypeRaw === 'additional' ? 'additional' : 'referral';
  let referral1 = normalizeText(options.referral1, 256);
  let referral2 = normalizeText(options.referral2, 256);
  const requestReason = asNullableText(options.requestReason || options.reason, 1000);
  const note = asNullableText(options.note, 1000);
  const now = asNumber(options.now, Date.now());

  if (!normalizedGoogleId) {
    return {
      ok: false,
      error: 'Missing user id'
    };
  }

  if (requestType === 'additional') {
    if (!requestReason) {
      return {
        ok: false,
        error: 'Reason is required for additional rate limit request'
      };
    }
    referral1 = '__additional_request__';
    referral2 = '__additional_request_reason__';
  } else {
    if (!referral1 || !referral2) {
      return {
        ok: false,
        error: 'Two referral values are required'
      };
    }

    if (referral1.toLowerCase() === referral2.toLowerCase()) {
      return {
        ok: false,
        error: 'Referral values must be different'
      };
    }
  }

  try {
    const pendingResult = await db.execute({
      sql: `
        SELECT *
        FROM ai_upgrade_requests
        WHERE google_id = ?
          AND status = 'pending'
        ORDER BY requested_at DESC, id DESC
        LIMIT 1
      `,
      args: [normalizedGoogleId]
    });

    if (pendingResult.rows.length > 0) {
      return {
        ok: false,
        error: 'A pending request already exists',
        code: 'PENDING_EXISTS',
        request: mapAiUpgradeRequestRow(pendingResult.rows[0])
      };
    }

    const insertResult = await db.execute({
      sql: `
        INSERT INTO ai_upgrade_requests (
          google_id, status, request_type, referral_1, referral_2, request_reason, note, requested_at, created_at, updated_at
        )
        VALUES (?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?)
        RETURNING *
      `,
      args: [normalizedGoogleId, requestType, referral1, referral2, requestReason, note, now, now, now]
    });

    return {
      ok: true,
      request: mapAiUpgradeRequestRow(insertResult.rows[0])
    };
  } catch (error) {
    console.error('[Database] Create AI upgrade request error:', error.message);
    return {
      ok: false,
      error: 'Failed to create AI upgrade request'
    };
  }
}

async function listAiUpgradeRequests(options = {}) {
  if (!db) return [];

  const status = normalizeText(options.status || 'all', 16).toLowerCase();
  const googleId = normalizeText(options.googleId || '', 256);
  const limit = parsePositiveInt(options.limit, 100);
  const effectiveLimit = Math.min(Math.max(limit, 1), 500);

  const conditions = [];
  const args = [];

  if (status && status !== 'all') {
    conditions.push('status = ?');
    args.push(status);
  }
  if (googleId) {
    conditions.push('google_id = ?');
    args.push(googleId);
  }

  let sql = 'SELECT * FROM ai_upgrade_requests';
  if (conditions.length > 0) {
    sql += ` WHERE ${conditions.join(' AND ')}`;
  }
  sql += ' ORDER BY requested_at DESC, id DESC LIMIT ?';
  args.push(effectiveLimit);

  try {
    const result = await db.execute({ sql, args });
    return result.rows.map(mapAiUpgradeRequestRow);
  } catch (error) {
    console.error('[Database] List AI upgrade requests error:', error.message);
    return [];
  }
}

async function countRejectedAiUpgradeRequests(googleId) {
  if (!db) return 0;
  const normalizedGoogleId = normalizeText(googleId, 256);
  if (!normalizedGoogleId) return 0;

  try {
    const result = await db.execute({
      sql: `
        SELECT COUNT(*) AS rejected_count
        FROM ai_upgrade_requests
        WHERE google_id = ?
          AND status = 'rejected'
      `,
      args: [normalizedGoogleId]
    });
    if (result.rows.length === 0) return 0;
    const row = result.rows[0] || {};
    return Math.max(0, asNumber(row.rejected_count ?? row.count, 0));
  } catch (error) {
    console.error('[Database] Count rejected AI upgrade requests error:', error.message);
    return 0;
  }
}

async function getAiChatBan(googleId) {
  if (!db) return null;
  const normalizedGoogleId = normalizeText(googleId, 256);
  if (!normalizedGoogleId) return null;

  try {
    const result = await db.execute({
      sql: `
        SELECT *
        FROM ai_chat_bans
        WHERE google_id = ?
        LIMIT 1
      `,
      args: [normalizedGoogleId]
    });
    if (result.rows.length === 0) return null;
    return mapAiChatBanRow(result.rows[0]);
  } catch (error) {
    console.error('[Database] Get AI chat ban error:', error.message);
    return null;
  }
}

async function listAiChatBans(options = {}) {
  if (!db) return [];

  const status = normalizeText(options.status || 'all', 16).toLowerCase();
  const googleId = normalizeText(options.googleId || '', 256);
  const limit = parsePositiveInt(options.limit, 100);
  const effectiveLimit = Math.min(Math.max(limit, 1), 500);

  const conditions = [];
  const args = [];

  if (status === 'banned') {
    conditions.push('is_active = 1');
  } else if (status === 'unbanned') {
    conditions.push('is_active = 0');
  }

  if (googleId) {
    conditions.push('google_id = ?');
    args.push(googleId);
  }

  let sql = 'SELECT * FROM ai_chat_bans';
  if (conditions.length > 0) {
    sql += ` WHERE ${conditions.join(' AND ')}`;
  }
  sql += ' ORDER BY updated_at DESC, banned_at DESC LIMIT ?';
  args.push(effectiveLimit);

  try {
    const result = await db.execute({ sql, args });
    return result.rows.map(mapAiChatBanRow);
  } catch (error) {
    console.error('[Database] List AI chat bans error:', error.message);
    return [];
  }
}

async function setAiChatBan(googleId, options = {}) {
  if (!db) {
    return {
      ok: false,
      error: 'AI ban storage unavailable'
    };
  }

  const normalizedGoogleId = normalizeText(googleId, 256);
  const now = asNumber(options.now, Date.now());
  const bannedBy = asNullableText(options.bannedBy, 256);
  const banReason = asNullableText(options.banReason || options.reason, 1000);
  if (!normalizedGoogleId) {
    return {
      ok: false,
      error: 'Invalid user id'
    };
  }

  try {
    const result = await db.execute({
      sql: `
        INSERT INTO ai_chat_bans (
          google_id, is_active, banned_at, banned_by, ban_reason, unbanned_at, unbanned_by, unban_reason, updated_at
        )
        VALUES (?, 1, ?, ?, ?, NULL, NULL, NULL, ?)
        ON CONFLICT(google_id) DO UPDATE SET
          is_active = 1,
          banned_at = excluded.banned_at,
          banned_by = excluded.banned_by,
          ban_reason = excluded.ban_reason,
          unbanned_at = NULL,
          unbanned_by = NULL,
          unban_reason = NULL,
          updated_at = excluded.updated_at
        RETURNING *
      `,
      args: [normalizedGoogleId, now, bannedBy, banReason, now]
    });

    return {
      ok: true,
      ban: mapAiChatBanRow(result.rows[0])
    };
  } catch (error) {
    console.error('[Database] Set AI chat ban error:', error.message);
    return {
      ok: false,
      error: 'Failed to set AI chat ban'
    };
  }
}

async function clearAiChatBan(googleId, options = {}) {
  if (!db) {
    return {
      ok: false,
      error: 'AI ban storage unavailable'
    };
  }

  const normalizedGoogleId = normalizeText(googleId, 256);
  const now = asNumber(options.now, Date.now());
  const unbannedBy = asNullableText(options.unbannedBy, 256);
  const unbanReason = asNullableText(options.unbanReason || options.reason, 1000);
  if (!normalizedGoogleId) {
    return {
      ok: false,
      error: 'Invalid user id'
    };
  }

  try {
    const existing = await getAiChatBan(normalizedGoogleId);
    if (!existing || !existing.isActive) {
      return {
        ok: true,
        code: 'NOT_BANNED',
        ban: existing || null
      };
    }

    const result = await db.execute({
      sql: `
        UPDATE ai_chat_bans
        SET is_active = 0,
            unbanned_at = ?,
            unbanned_by = ?,
            unban_reason = ?,
            updated_at = ?
        WHERE google_id = ?
        RETURNING *
      `,
      args: [now, unbannedBy, unbanReason, now, normalizedGoogleId]
    });

    return {
      ok: true,
      ban: mapAiChatBanRow(result.rows[0])
    };
  } catch (error) {
    console.error('[Database] Clear AI chat ban error:', error.message);
    return {
      ok: false,
      error: 'Failed to clear AI chat ban'
    };
  }
}

async function reviewAiUpgradeRequest(requestId, options = {}) {
  if (!db) {
    return {
      ok: false,
      error: 'AI upgrade request storage unavailable'
    };
  }

  const id = asNumber(requestId, 0);
  const status = normalizeText(options.status, 32).toLowerCase();
  if (!id || !['approved', 'rejected'].includes(status)) {
    return {
      ok: false,
      error: 'Invalid review payload'
    };
  }

  try {
    const existing = await getAiUpgradeRequestById(id);
    if (!existing) {
      return {
        ok: false,
        error: 'Request not found',
        code: 'NOT_FOUND'
      };
    }

    if (existing.status !== 'pending') {
      return {
        ok: false,
        error: 'Request is not pending',
        code: 'NOT_PENDING',
        request: existing
      };
    }

    const now = asNumber(options.now, Date.now());
    const result = await db.execute({
      sql: `
        UPDATE ai_upgrade_requests
        SET status = ?,
            reviewed_at = ?,
            reviewed_by = ?,
            review_note = ?,
            entitlement_id = ?,
            updated_at = ?
        WHERE id = ?
        RETURNING *
      `,
      args: [
        status,
        now,
        asNullableText(options.reviewedBy, 256),
        asNullableText(options.reviewNote, 1000),
        options.entitlementId ? asNumber(options.entitlementId, 0) : null,
        now,
        id
      ]
    });

    return {
      ok: true,
      request: mapAiUpgradeRequestRow(result.rows[0])
    };
  } catch (error) {
    console.error('[Database] Review AI upgrade request error:', error.message);
    return {
      ok: false,
      error: 'Failed to review AI upgrade request'
    };
  }
}

/**
 * Check if database is connected
 */
function isConnected() {
  return db !== null;
}

module.exports = {
  initDatabase,
  upsertUser,
  searchUsers,
  getUser,
  updateLastSeen,
  updateAllowFriendRequests,
  consumeAiChatQuota,
  getAiChatQuota,
  getActiveAiEntitlement,
  createAiEntitlement,
  listAiEntitlements,
  getAiUpgradeRequestById,
  getLatestAiUpgradeRequestForUser,
  createAiUpgradeRequest,
  listAiUpgradeRequests,
  reviewAiUpgradeRequest,
  countRejectedAiUpgradeRequests,
  getAiChatBan,
  listAiChatBans,
  setAiChatBan,
  clearAiChatBan,
  isConnected
};
