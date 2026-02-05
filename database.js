/**
 * StreamVault Database Module (Turso)
 *
 * Handles persistent user directory for search/discovery.
 * User data (profiles, friends, chat) still lives in Google Drive.
 * This is ONLY for finding users across sessions.
 */

const { createClient } = require('@libsql/client');

let db = null;

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
  isConnected
};
