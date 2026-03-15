/**
 * StreamVault Database Module (Turso)
 *
 * Handles persistent social data, AI quota storage, and user discovery.
 * Supports either:
 * - a single Turso database via TURSO_DATABASE_URL / TURSO_AUTH_TOKEN
 * - separate databases via TURSO_USERS_*, TURSO_CHAT_*, TURSO_ACTIVITY_*
 */

const { createClient } = require('@libsql/client');
const { v4: uuidv4 } = require('uuid');

let db = null;
let usersDb = null;
let chatDb = null;
let activityDb = null;

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

function asBooleanNumber(value) {
  return value ? 1 : 0;
}

function parseJsonArray(value) {
  if (!value) return [];
  if (Array.isArray(value)) {
    return value.filter((item) => typeof item === 'string');
  }
  if (typeof value !== 'string') return [];
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.filter((item) => typeof item === 'string') : [];
  } catch {
    return [];
  }
}

function getConfigValue(...keys) {
  for (const key of keys) {
    const value = process.env[key];
    if (typeof value === 'string' && value.trim()) {
      return value.trim();
    }
  }
  return '';
}

function resolveDbConfig(kind) {
  const upper = (kind || '').toUpperCase();
  const url = upper
    ? getConfigValue(
      `TURSO_${upper}_DATABASE_URL`,
      `TURSO_${upper}_DB_URL`
    )
    : getConfigValue('TURSO_DATABASE_URL');
  const authToken = upper
    ? getConfigValue(
      `TURSO_${upper}_AUTH_TOKEN`,
      `TURSO_${upper}_DATABASE_AUTH_TOKEN`,
      'TURSO_AUTH_TOKEN'
    )
    : getConfigValue('TURSO_AUTH_TOKEN');

  return { url, authToken };
}

function createClientIfConfigured(config) {
  if (!config?.url) return null;
  return createClient({
    url: config.url,
    authToken: config.authToken || undefined
  });
}

function getDb(kind = 'users') {
  switch (kind) {
    case 'chat':
      return chatDb || db;
    case 'activity':
      return activityDb || db;
    case 'users':
    default:
      return usersDb || db;
  }
}

async function ensureColumn(client, tableName, columnDefinition) {
  if (!client) return;
  try {
    await client.execute(`ALTER TABLE ${tableName} ADD COLUMN ${columnDefinition}`);
  } catch (error) {
    const message = String(error?.message || '').toLowerCase();
    if (!message.includes('duplicate column')) {
      throw error;
    }
  }
}

async function initializeSchema(client, statements = []) {
  if (!client || statements.length === 0) return;
  for (const statement of statements) {
    await client.execute(statement);
  }
}

function mapMessageRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    senderId: row.sender_id,
    receiverId: row.receiver_id || null,
    text: row.text,
    read: Number(row.read) === 1,
    timestamp: asNumber(row.created_at, 0)
  };
}

function mapActivityRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    type: row.type,
    contentId: row.content_id,
    title: row.title,
    contentType: row.content_type,
    posterPath: row.poster_path || undefined,
    season: row.season === null || row.season === undefined ? undefined : asNumber(row.season, 0),
    episode: row.episode === null || row.episode === undefined ? undefined : asNumber(row.episode, 0),
    duration: row.duration === null || row.duration === undefined ? undefined : asNumber(row.duration, 0),
    genres: parseJsonArray(row.genres),
    timestamp: asNumber(row.created_at, 0),
    userId: row.user_id || undefined,
    userName: row.display_name || undefined,
    userAvatar: row.avatar_url || undefined
  };
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
  const defaultConfig = resolveDbConfig('');
  const usersConfig = resolveDbConfig('USERS');
  const chatConfig = resolveDbConfig('CHAT');
  const activityConfig = resolveDbConfig('ACTIVITY');

  try {
    const defaultClient = createClientIfConfigured(defaultConfig);
    usersDb = createClientIfConfigured(usersConfig) || defaultClient;
    chatDb = createClientIfConfigured(chatConfig) || defaultClient;
    activityDb = createClientIfConfigured(activityConfig) || defaultClient;
    db = defaultClient || usersDb || chatDb || activityDb;

    if (!db && !usersDb && !chatDb && !activityDb) {
      console.warn('[Database] No Turso database configured - persistent social storage disabled');
      return false;
    }

    const schemaStatementsByClient = new Map();
    const queueSchemaStatements = (client, statements) => {
      if (!client || !Array.isArray(statements) || statements.length === 0) return;
      const existing = schemaStatementsByClient.get(client) || [];
      existing.push(...statements);
      schemaStatementsByClient.set(client, existing);
    };

    queueSchemaStatements(getDb('users'), [
      `
      CREATE TABLE IF NOT EXISTS users (
        google_id TEXT PRIMARY KEY,
        username TEXT UNIQUE,
        display_name TEXT,
        email TEXT,
        avatar_url TEXT,
        bio TEXT DEFAULT '',
        location TEXT DEFAULT '',
        allow_friend_requests INTEGER DEFAULT 1,
        created_at INTEGER,
        last_seen INTEGER
      )
    `,
      `
      CREATE TABLE IF NOT EXISTS friendships (
        user_id TEXT NOT NULL,
        friend_id TEXT NOT NULL,
        since INTEGER NOT NULL,
        PRIMARY KEY (user_id, friend_id)
      )
    `,
      `
      CREATE TABLE IF NOT EXISTS friend_requests (
        id TEXT PRIMARY KEY,
        from_id TEXT NOT NULL,
        to_id TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at INTEGER NOT NULL,
        responded_at INTEGER
      )
    `,
      `
      CREATE INDEX IF NOT EXISTS idx_username ON users(username)
    `,
      `
      CREATE INDEX IF NOT EXISTS idx_display_name ON users(display_name)
    `,
      `
      CREATE INDEX IF NOT EXISTS idx_email ON users(email)
    `,
      `
      CREATE INDEX IF NOT EXISTS idx_users_allow_friend_requests ON users(allow_friend_requests)
    `,
      `
      CREATE INDEX IF NOT EXISTS idx_friendships_user ON friendships(user_id)
    `,
      `
      CREATE INDEX IF NOT EXISTS idx_friendships_friend ON friendships(friend_id)
    `,
      `
      CREATE INDEX IF NOT EXISTS idx_friend_requests_to_status ON friend_requests(to_id, status, created_at)
    `,
      `
      CREATE INDEX IF NOT EXISTS idx_friend_requests_from_to_status ON friend_requests(from_id, to_id, status)
    `
    ]);

    queueSchemaStatements(getDb('chat'), [
      `
      CREATE TABLE IF NOT EXISTS messages (
        id TEXT PRIMARY KEY,
        sender_id TEXT NOT NULL,
        receiver_id TEXT NOT NULL,
        text TEXT NOT NULL,
        read INTEGER DEFAULT 0,
        created_at INTEGER NOT NULL
      )
    `,
      `
      CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages(sender_id, receiver_id, created_at)
    `,
      `
      CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages(receiver_id, created_at)
    `,
      `
      CREATE INDEX IF NOT EXISTS idx_messages_unread ON messages(receiver_id, read, created_at)
    `,
      `
      CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id, created_at)
    `,
      `
      CREATE TABLE IF NOT EXISTS message_queue (
        id TEXT PRIMARY KEY,
        receiver_id TEXT NOT NULL,
        message_id TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at INTEGER NOT NULL,
        delivered_at INTEGER
      )
    `,
      `
      CREATE INDEX IF NOT EXISTS idx_message_queue_receiver ON message_queue(receiver_id, status)
    `,
      `
      CREATE INDEX IF NOT EXISTS idx_message_queue_status ON message_queue(status, created_at)
    `
    ]);

    queueSchemaStatements(getDb('activity'), [
      `
      CREATE TABLE IF NOT EXISTS activities (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        type TEXT NOT NULL,
        content_id TEXT NOT NULL,
        title TEXT NOT NULL,
        content_type TEXT NOT NULL,
        poster_path TEXT,
        season INTEGER,
        episode INTEGER,
        duration INTEGER,
        genres TEXT,
        created_at INTEGER NOT NULL
      )
    `,
      `
      CREATE TABLE IF NOT EXISTS watch_stats (
        user_id TEXT PRIMARY KEY,
        movies_watched INTEGER DEFAULT 0,
        episodes_watched INTEGER DEFAULT 0,
        total_watch_time INTEGER DEFAULT 0,
        favorite_genres TEXT,
        updated_at INTEGER NOT NULL
      )
    `,
      `
      CREATE INDEX IF NOT EXISTS idx_activities_user ON activities(user_id, created_at DESC)
    `,
      `
      CREATE INDEX IF NOT EXISTS idx_activities_type ON activities(type, created_at DESC)
    `,
      `
      CREATE INDEX IF NOT EXISTS idx_activities_content ON activities(content_type, created_at DESC)
    `,
      `
      CREATE INDEX IF NOT EXISTS idx_activities_user_type ON activities(user_id, type, created_at DESC)
    `
    ]);

    for (const [client, statements] of schemaStatementsByClient.entries()) {
      await initializeSchema(client, statements);
    }

    await ensureColumn(getDb('users'), 'users', "bio TEXT DEFAULT ''");
    await ensureColumn(getDb('users'), 'users', "location TEXT DEFAULT ''");

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
    console.log(
      `[Database] Clients - users:${!!getDb('users')} chat:${!!getDb('chat')} activity:${!!getDb('activity')}`
    );
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
  const usersClient = getDb('users');
  if (!usersClient) return false;

  try {
    await usersClient.execute({
      sql: `
        INSERT INTO users (google_id, username, display_name, email, avatar_url, bio, location, allow_friend_requests, created_at, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(google_id) DO UPDATE SET
          username = excluded.username,
          display_name = excluded.display_name,
          email = excluded.email,
          avatar_url = excluded.avatar_url,
          bio = COALESCE(excluded.bio, users.bio),
          location = COALESCE(excluded.location, users.location),
          allow_friend_requests = excluded.allow_friend_requests,
          last_seen = excluded.last_seen
      `,
      args: [
        user.googleId,
        user.username || null,
        user.displayName || null,
        user.email || null,
        user.avatarUrl || null,
        asNullableText(user.bio, 1000),
        asNullableText(user.location, 256),
        asBooleanNumber(user.allowFriendRequests !== false),
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
  const usersClient = getDb('users');
  if (!usersClient) return null;

  try {
    const result = await usersClient.execute({
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
      bio: row.bio || '',
      location: row.location || '',
      allowFriendRequests: Number(row.allow_friend_requests) === 1,
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
  const usersClient = getDb('users');
  if (!usersClient) return false;

  try {
    await usersClient.execute({
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
  const usersClient = getDb('users');
  if (!usersClient) return false;

  try {
    await usersClient.execute({
      sql: 'UPDATE users SET allow_friend_requests = ? WHERE google_id = ?',
      args: [asBooleanNumber(allow), googleId]
    });
    return true;
  } catch (error) {
    console.error('[Database] Update privacy error:', error.message);
    return false;
  }
}

async function addFriendship(userId, friendId, since = Date.now()) {
  const usersClient = getDb('users');
  if (!usersClient) return false;

  const normalizedUserId = normalizeText(userId, 256);
  const normalizedFriendId = normalizeText(friendId, 256);
  if (!normalizedUserId || !normalizedFriendId || normalizedUserId === normalizedFriendId) {
    return false;
  }

  try {
    await usersClient.execute({
      sql: 'INSERT OR REPLACE INTO friendships (user_id, friend_id, since) VALUES (?, ?, ?)',
      args: [normalizedUserId, normalizedFriendId, since]
    });
    await usersClient.execute({
      sql: 'INSERT OR REPLACE INTO friendships (user_id, friend_id, since) VALUES (?, ?, ?)',
      args: [normalizedFriendId, normalizedUserId, since]
    });
    return true;
  } catch (error) {
    console.error('[Database] addFriendship failed:', error.message);
    return false;
  }
}

async function removeFriendship(userId, friendId) {
  const usersClient = getDb('users');
  if (!usersClient) return false;

  const normalizedUserId = normalizeText(userId, 256);
  const normalizedFriendId = normalizeText(friendId, 256);
  if (!normalizedUserId || !normalizedFriendId) {
    return false;
  }

  try {
    await usersClient.execute({
      sql: 'DELETE FROM friendships WHERE user_id = ? AND friend_id = ?',
      args: [normalizedUserId, normalizedFriendId]
    });
    await usersClient.execute({
      sql: 'DELETE FROM friendships WHERE user_id = ? AND friend_id = ?',
      args: [normalizedFriendId, normalizedUserId]
    });
    return true;
  } catch (error) {
    console.error('[Database] removeFriendship failed:', error.message);
    return false;
  }
}

async function getFriends(userId) {
  const usersClient = getDb('users');
  if (!usersClient) return [];

  try {
    const result = await usersClient.execute({
      sql: `
        SELECT
          f.friend_id,
          f.since,
          u.display_name,
          u.avatar_url
        FROM friendships f
        LEFT JOIN users u ON f.friend_id = u.google_id
        WHERE f.user_id = ?
        ORDER BY COALESCE(u.display_name, f.friend_id) ASC
      `,
      args: [userId]
    });

    return result.rows.map((row) => ({
      id: row.friend_id,
      name: row.display_name || 'Friend',
      avatar: row.avatar_url || null,
      since: asNumber(row.since, 0)
    }));
  } catch (error) {
    console.error('[Database] getFriends failed:', error.message);
    return [];
  }
}

async function isFriend(userId, friendId) {
  const usersClient = getDb('users');
  if (!usersClient) return false;

  try {
    const result = await usersClient.execute({
      sql: 'SELECT 1 FROM friendships WHERE user_id = ? AND friend_id = ? LIMIT 1',
      args: [userId, friendId]
    });
    return result.rows.length > 0;
  } catch (error) {
    console.error('[Database] isFriend failed:', error.message);
    return false;
  }
}

async function getFriendRequestBetween(fromId, toId) {
  const usersClient = getDb('users');
  if (!usersClient) return null;

  try {
    const result = await usersClient.execute({
      sql: `
        SELECT *
        FROM friend_requests
        WHERE from_id = ? AND to_id = ?
        ORDER BY created_at DESC
        LIMIT 1
      `,
      args: [fromId, toId]
    });

    if (result.rows.length === 0) return null;
    const row = result.rows[0];
    return {
      id: row.id,
      fromId: row.from_id,
      toId: row.to_id,
      status: row.status,
      createdAt: asNumber(row.created_at, 0),
      respondedAt: row.responded_at ? asNumber(row.responded_at, 0) : null
    };
  } catch (error) {
    console.error('[Database] getFriendRequestBetween failed:', error.message);
    return null;
  }
}

async function createFriendRequest(fromId, toId, options = {}) {
  const usersClient = getDb('users');
  if (!usersClient) return null;

  const existing = await getFriendRequestBetween(fromId, toId);
  if (existing?.status === 'pending') {
    return existing;
  }

  const id = normalizeText(options.id, 256) || `req_${Date.now()}_${uuidv4()}`;
  const createdAt = asNumber(options.createdAt, Date.now());

  try {
    await usersClient.execute({
      sql: `
        INSERT INTO friend_requests (id, from_id, to_id, status, created_at, responded_at)
        VALUES (?, ?, ?, 'pending', ?, NULL)
      `,
      args: [id, fromId, toId, createdAt]
    });

    return {
      id,
      fromId,
      toId,
      status: 'pending',
      createdAt,
      respondedAt: null
    };
  } catch (error) {
    console.error('[Database] createFriendRequest failed:', error.message);
    return null;
  }
}

async function getPendingRequests(userId) {
  const usersClient = getDb('users');
  if (!usersClient) return [];

  try {
    const result = await usersClient.execute({
      sql: `
        SELECT
          r.id,
          r.from_id,
          r.created_at,
          u.display_name,
          u.avatar_url
        FROM friend_requests r
        LEFT JOIN users u ON r.from_id = u.google_id
        WHERE r.to_id = ? AND r.status = 'pending'
        ORDER BY r.created_at DESC
      `,
      args: [userId]
    });

    return result.rows.map((row) => ({
      id: row.id,
      fromId: row.from_id,
      fromName: row.display_name || 'Friend',
      fromAvatar: row.avatar_url || null,
      sentAt: asNumber(row.created_at, 0)
    }));
  } catch (error) {
    console.error('[Database] getPendingRequests failed:', error.message);
    return [];
  }
}

async function updateFriendRequestStatus(requestId, status) {
  const usersClient = getDb('users');
  if (!usersClient) return false;

  try {
    await usersClient.execute({
      sql: `
        UPDATE friend_requests
        SET status = ?, responded_at = ?
        WHERE id = ?
      `,
      args: [status, Date.now(), requestId]
    });
    return true;
  } catch (error) {
    console.error('[Database] updateFriendRequestStatus failed:', error.message);
    return false;
  }
}

async function deleteFriendRequest(requestId) {
  const usersClient = getDb('users');
  if (!usersClient) return false;

  try {
    await usersClient.execute({
      sql: 'DELETE FROM friend_requests WHERE id = ?',
      args: [requestId]
    });
    return true;
  } catch (error) {
    console.error('[Database] deleteFriendRequest failed:', error.message);
    return false;
  }
}

async function saveMessage(messageData) {
  const chatClient = getDb('chat');
  if (!chatClient) return null;

  const createdAt = asNumber(messageData.createdAt ?? messageData.created_at, Date.now());
  const payload = {
    id: normalizeText(messageData.id, 256) || uuidv4(),
    senderId: normalizeText(messageData.senderId, 256),
    receiverId: normalizeText(messageData.receiverId, 256),
    text: normalizeText(messageData.text, 2000),
    read: !!messageData.read,
    timestamp: createdAt
  };

  if (!payload.senderId || !payload.receiverId || !payload.text) {
    return null;
  }

  try {
    await chatClient.execute({
      sql: `
        INSERT OR IGNORE INTO messages (id, sender_id, receiver_id, text, read, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `,
      args: [
        payload.id,
        payload.senderId,
        payload.receiverId,
        payload.text,
        asBooleanNumber(payload.read),
        payload.timestamp
      ]
    });
    return payload;
  } catch (error) {
    console.error('[Database] saveMessage failed:', error.message);
    return null;
  }
}

async function getChatHistory(userId1, userId2, options = {}) {
  const chatClient = getDb('chat');
  if (!chatClient) return [];

  const limit = Math.min(Math.max(parsePositiveInt(options.limit, 100), 1), 500);
  const before = options.before ? asNumber(options.before, 0) : null;
  const order = (options.order || 'asc').toLowerCase() === 'desc' ? 'desc' : 'asc';

  try {
    let sql = `
      SELECT id, sender_id, receiver_id, text, read, created_at
      FROM messages
      WHERE (
        (sender_id = ? AND receiver_id = ?) OR
        (sender_id = ? AND receiver_id = ?)
      )
    `;
    const args = [userId1, userId2, userId2, userId1];

    if (before) {
      sql += ' AND created_at < ?';
      args.push(before);
    }

    sql += ' ORDER BY created_at DESC LIMIT ?';
    args.push(limit);

    const result = await chatClient.execute({ sql, args });
    const rows = result.rows.map(mapMessageRow).filter(Boolean);
    return order === 'asc' ? rows.reverse() : rows;
  } catch (error) {
    console.error('[Database] getChatHistory failed:', error.message);
    return [];
  }
}

async function markMessagesAsRead(senderId, receiverId, beforeTimestamp = null) {
  const chatClient = getDb('chat');
  if (!chatClient) return 0;

  try {
    let sql = `
      UPDATE messages
      SET read = 1
      WHERE sender_id = ? AND receiver_id = ? AND read = 0
    `;
    const args = [senderId, receiverId];

    if (beforeTimestamp) {
      sql += ' AND created_at <= ?';
      args.push(beforeTimestamp);
    }

    const result = await chatClient.execute({ sql, args });
    return asNumber(result.rowsAffected, 0);
  } catch (error) {
    console.error('[Database] markMessagesAsRead failed:', error.message);
    return 0;
  }
}

async function getUnreadCount(userId) {
  const chatClient = getDb('chat');
  if (!chatClient) return 0;

  try {
    const result = await chatClient.execute({
      sql: 'SELECT COUNT(*) AS count FROM messages WHERE receiver_id = ? AND read = 0',
      args: [userId]
    });
    return asNumber(result.rows[0]?.count, 0);
  } catch (error) {
    console.error('[Database] getUnreadCount failed:', error.message);
    return 0;
  }
}

async function getUsersWithUnreadMessages(userId) {
  const chatClient = getDb('chat');
  if (!chatClient) return [];

  try {
    const result = await chatClient.execute({
      sql: `
        SELECT sender_id, COUNT(*) AS count, MAX(created_at) AS last_message_at
        FROM messages
        WHERE receiver_id = ? AND read = 0
        GROUP BY sender_id
        ORDER BY last_message_at DESC
      `,
      args: [userId]
    });

    return result.rows.map((row) => ({
      senderId: row.sender_id,
      count: asNumber(row.count, 0),
      lastMessageAt: asNumber(row.last_message_at, 0)
    }));
  } catch (error) {
    console.error('[Database] getUsersWithUnreadMessages failed:', error.message);
    return [];
  }
}

async function queueMessageForDelivery(queueData) {
  const chatClient = getDb('chat');
  if (!chatClient) return false;

  const id = normalizeText(queueData.id, 256) || `queue_${Date.now()}_${uuidv4()}`;
  const receiverId = normalizeText(queueData.receiverId, 256);
  const messageId = normalizeText(queueData.messageId, 256);
  const createdAt = asNumber(queueData.createdAt, Date.now());

  if (!receiverId || !messageId) return false;

  try {
    await chatClient.execute({
      sql: `
        INSERT OR REPLACE INTO message_queue (id, receiver_id, message_id, status, created_at, delivered_at)
        VALUES (?, ?, ?, 'pending', ?, NULL)
      `,
      args: [id, receiverId, messageId, createdAt]
    });
    return true;
  } catch (error) {
    console.error('[Database] queueMessageForDelivery failed:', error.message);
    return false;
  }
}

async function getPendingMessages(userId) {
  const chatClient = getDb('chat');
  if (!chatClient) return [];

  try {
    const result = await chatClient.execute({
      sql: `
        SELECT mq.id AS queue_id, mq.message_id, m.sender_id, m.receiver_id, m.text, m.read, m.created_at
        FROM message_queue mq
        JOIN messages m ON mq.message_id = m.id
        WHERE mq.receiver_id = ? AND mq.status = 'pending'
        ORDER BY m.created_at ASC
      `,
      args: [userId]
    });

    return result.rows.map((row) => ({
      queueId: row.queue_id,
      messageId: row.message_id,
      message: mapMessageRow(row)
    })).filter((item) => item.message);
  } catch (error) {
    console.error('[Database] getPendingMessages failed:', error.message);
    return [];
  }
}

async function markQueuedMessageDelivered(queueId) {
  const chatClient = getDb('chat');
  if (!chatClient) return false;

  try {
    await chatClient.execute({
      sql: `
        UPDATE message_queue
        SET status = 'delivered', delivered_at = ?
        WHERE id = ?
      `,
      args: [Date.now(), queueId]
    });
    return true;
  } catch (error) {
    console.error('[Database] markQueuedMessageDelivered failed:', error.message);
    return false;
  }
}

async function cleanupMessageQueue(olderThanDays = 7) {
  const chatClient = getDb('chat');
  if (!chatClient) return 0;

  try {
    const cutoff = Date.now() - (olderThanDays * 24 * 60 * 60 * 1000);
    const result = await chatClient.execute({
      sql: 'DELETE FROM message_queue WHERE status = ? AND delivered_at < ?',
      args: ['delivered', cutoff]
    });
    return asNumber(result.rowsAffected, 0);
  } catch (error) {
    console.error('[Database] cleanupMessageQueue failed:', error.message);
    return 0;
  }
}

async function logActivity(activityData) {
  const activityClient = getDb('activity');
  if (!activityClient) return null;

  const payload = {
    id: normalizeText(activityData.id, 256) || uuidv4(),
    userId: normalizeText(activityData.userId, 256),
    type: normalizeText(activityData.type, 64),
    contentId: normalizeText(activityData.contentId, 256),
    title: normalizeText(activityData.title, 512),
    contentType: normalizeText(activityData.contentType, 32),
    posterPath: asNullableText(activityData.posterPath, 2048),
    season: activityData.season === undefined ? null : asNumber(activityData.season, 0),
    episode: activityData.episode === undefined ? null : asNumber(activityData.episode, 0),
    duration: activityData.duration === undefined ? null : asNumber(activityData.duration, 0),
    genres: JSON.stringify(Array.isArray(activityData.genres) ? activityData.genres : []),
    timestamp: asNumber(activityData.createdAt ?? activityData.created_at ?? activityData.timestamp, Date.now())
  };

  if (!payload.userId || !payload.type || !payload.contentId || !payload.title || !payload.contentType) {
    return null;
  }

  try {
    await activityClient.execute({
      sql: `
        INSERT OR IGNORE INTO activities (
          id, user_id, type, content_id, title, content_type, poster_path, season, episode, duration, genres, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      args: [
        payload.id,
        payload.userId,
        payload.type,
        payload.contentId,
        payload.title,
        payload.contentType,
        payload.posterPath,
        payload.season,
        payload.episode,
        payload.duration,
        payload.genres,
        payload.timestamp
      ]
    });

    return {
      id: payload.id,
      type: payload.type,
      contentId: payload.contentId,
      title: payload.title,
      contentType: payload.contentType,
      posterPath: payload.posterPath || undefined,
      season: payload.season === null ? undefined : payload.season,
      episode: payload.episode === null ? undefined : payload.episode,
      duration: payload.duration === null ? undefined : payload.duration,
      genres: parseJsonArray(payload.genres),
      timestamp: payload.timestamp,
      userId: payload.userId
    };
  } catch (error) {
    console.error('[Database] logActivity failed:', error.message);
    return null;
  }
}

async function getUserActivities(userId, limit = 50, before = null) {
  const activityClient = getDb('activity');
  if (!activityClient) return [];

  try {
    let sql = 'SELECT * FROM activities WHERE user_id = ?';
    const args = [userId];

    if (before) {
      sql += ' AND created_at < ?';
      args.push(before);
    }

    sql += ' ORDER BY created_at DESC LIMIT ?';
    args.push(Math.min(Math.max(parsePositiveInt(limit, 50), 1), 200));

    const result = await activityClient.execute({ sql, args });
    return result.rows.map(mapActivityRow).filter(Boolean);
  } catch (error) {
    console.error('[Database] getUserActivities failed:', error.message);
    return [];
  }
}

async function getFriendsActivity(userId, friendIds, filters = {}, page = 1, pageSize = 50) {
  const activityClient = getDb('activity');
  if (!activityClient || !Array.isArray(friendIds) || friendIds.length === 0) return [];

  try {
    const safePage = Math.max(parsePositiveInt(page, 1), 1);
    const safePageSize = Math.min(Math.max(parsePositiveInt(pageSize, 50), 1), 100);

    let sql = `
      SELECT a.*, u.display_name, u.avatar_url
      FROM activities a
      LEFT JOIN users u ON a.user_id = u.google_id
      WHERE a.user_id IN (${friendIds.map(() => '?').join(',')})
    `;
    const args = [...friendIds];

    if (filters.contentType) {
      sql += ' AND a.content_type = ?';
      args.push(filters.contentType);
    }
    if (filters.genre) {
      sql += ' AND a.genres LIKE ?';
      args.push(`%${filters.genre}%`);
    }
    if (filters.userId) {
      sql += ' AND a.user_id = ?';
      args.push(filters.userId);
    }

    const offset = (safePage - 1) * safePageSize;
    sql += ' ORDER BY a.created_at DESC LIMIT ? OFFSET ?';
    args.push(safePageSize, offset);

    const result = await activityClient.execute({ sql, args });
    return result.rows.map(mapActivityRow).filter(Boolean);
  } catch (error) {
    console.error('[Database] getFriendsActivity failed:', error.message);
    return [];
  }
}

async function getFriendsActivityCount(userId, friendIds, filters = {}) {
  const activityClient = getDb('activity');
  if (!activityClient || !Array.isArray(friendIds) || friendIds.length === 0) return 0;

  try {
    let sql = `
      SELECT COUNT(*) AS count
      FROM activities a
      WHERE a.user_id IN (${friendIds.map(() => '?').join(',')})
    `;
    const args = [...friendIds];

    if (filters.contentType) {
      sql += ' AND a.content_type = ?';
      args.push(filters.contentType);
    }
    if (filters.genre) {
      sql += ' AND a.genres LIKE ?';
      args.push(`%${filters.genre}%`);
    }
    if (filters.userId) {
      sql += ' AND a.user_id = ?';
      args.push(filters.userId);
    }

    const result = await activityClient.execute({ sql, args });
    return asNumber(result.rows[0]?.count, 0);
  } catch (error) {
    console.error('[Database] getFriendsActivityCount failed:', error.message);
    return 0;
  }
}

async function getWatchStats(userId) {
  const activityClient = getDb('activity');
  if (!activityClient) return null;

  try {
    const result = await activityClient.execute({
      sql: 'SELECT * FROM watch_stats WHERE user_id = ?',
      args: [userId]
    });

    if (result.rows.length === 0) {
      return {
        userId,
        moviesWatched: 0,
        episodesWatched: 0,
        totalWatchTime: 0,
        favoriteGenres: [],
        updatedAt: 0
      };
    }

    const row = result.rows[0];
    return {
      userId,
      moviesWatched: asNumber(row.movies_watched, 0),
      episodesWatched: asNumber(row.episodes_watched, 0),
      totalWatchTime: asNumber(row.total_watch_time, 0),
      favoriteGenres: parseJsonArray(row.favorite_genres),
      updatedAt: asNumber(row.updated_at, 0)
    };
  } catch (error) {
    console.error('[Database] getWatchStats failed:', error.message);
    return null;
  }
}

async function updateWatchStats(statsData) {
  const activityClient = getDb('activity');
  if (!activityClient) return false;

  const payload = {
    userId: normalizeText(statsData.userId, 256),
    moviesWatched: asNumber(statsData.moviesWatched, 0),
    episodesWatched: asNumber(statsData.episodesWatched, 0),
    totalWatchTime: asNumber(statsData.totalWatchTime, 0),
    favoriteGenres: JSON.stringify(Array.isArray(statsData.favoriteGenres) ? statsData.favoriteGenres : []),
    updatedAt: asNumber(statsData.updatedAt, Date.now())
  };

  if (!payload.userId) return false;

  try {
    await activityClient.execute({
      sql: `
        INSERT INTO watch_stats (user_id, movies_watched, episodes_watched, total_watch_time, favorite_genres, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
          movies_watched = excluded.movies_watched,
          episodes_watched = excluded.episodes_watched,
          total_watch_time = excluded.total_watch_time,
          favorite_genres = excluded.favorite_genres,
          updated_at = excluded.updated_at
      `,
      args: [
        payload.userId,
        payload.moviesWatched,
        payload.episodesWatched,
        payload.totalWatchTime,
        payload.favoriteGenres,
        payload.updatedAt
      ]
    });
    return true;
  } catch (error) {
    console.error('[Database] updateWatchStats failed:', error.message);
    return false;
  }
}

async function getGenresFromActivities(userId, friendIds) {
  const activityClient = getDb('activity');
  if (!activityClient || !Array.isArray(friendIds) || friendIds.length === 0) return [];

  try {
    const result = await activityClient.execute({
      sql: `
        SELECT DISTINCT genres
        FROM activities
        WHERE user_id IN (${friendIds.map(() => '?').join(',')})
          AND genres IS NOT NULL
          AND genres != '[]'
      `,
      args: friendIds
    });

    const genres = new Set();
    for (const row of result.rows) {
      for (const genre of parseJsonArray(row.genres)) {
        genres.add(genre);
      }
    }
    return Array.from(genres).sort();
  } catch (error) {
    console.error('[Database] getGenresFromActivities failed:', error.message);
    return [];
  }
}

async function cleanupOldActivities(userId = null, keepCount = 100) {
  const activityClient = getDb('activity');
  if (!activityClient) return 0;

  const safeKeepCount = Math.min(Math.max(parsePositiveInt(keepCount, 100), 1), 500);

  try {
    if (userId) {
      const result = await activityClient.execute({
        sql: `
          DELETE FROM activities
          WHERE user_id = ?
            AND id NOT IN (
              SELECT id FROM (
                SELECT id
                FROM activities
                WHERE user_id = ?
                ORDER BY created_at DESC
                LIMIT ?
              )
            )
        `,
        args: [userId, userId, safeKeepCount]
      });
      return asNumber(result.rowsAffected, 0);
    }

    return 0;
  } catch (error) {
    console.error('[Database] cleanupOldActivities failed:', error.message);
    return 0;
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
  return !!(db || usersDb || chatDb || activityDb);
}

module.exports = {
  initDatabase,
  upsertUser,
  searchUsers,
  getUser,
  updateLastSeen,
  updateAllowFriendRequests,
  addFriendship,
  removeFriendship,
  getFriends,
  isFriend,
  createFriendRequest,
  getPendingRequests,
  getFriendRequestBetween,
  updateFriendRequestStatus,
  deleteFriendRequest,
  saveMessage,
  getChatHistory,
  markMessagesAsRead,
  getUnreadCount,
  getUsersWithUnreadMessages,
  queueMessageForDelivery,
  getPendingMessages,
  markQueuedMessageDelivered,
  cleanupMessageQueue,
  logActivity,
  getUserActivities,
  getFriendsActivity,
  getFriendsActivityCount,
  getWatchStats,
  updateWatchStats,
  getGenresFromActivities,
  cleanupOldActivities,
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
