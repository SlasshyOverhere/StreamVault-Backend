/**
 * StreamVault Database Module (Turso)
 *
 * Handles persistent social data, streaming history, and user discovery.
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
  isConnected
};
