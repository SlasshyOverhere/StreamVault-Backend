const { Redis } = require('@upstash/redis');

const ROOM_TTL_SECONDS = 24 * 60 * 60;
const EVENTS_TTL_SECONDS = 60 * 60;
const PARTICIPANTS_TTL_SECONDS = 60 * 60;

let redis = null;

function safeParseJson(value, fallback = null) {
  if (value === null || value === undefined || value === '') {
    return fallback;
  }

  if (typeof value !== 'string') {
    return value;
  }

  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function initRedis() {
  const url = (process.env.UPSTASH_REDIS_REST_URL || '').trim();
  const token = (process.env.UPSTASH_REDIS_REST_TOKEN || '').trim();

  if (!url || !token) {
    console.warn('[Redis] UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN not set; Watch Together rooms will remain in-memory');
    return false;
  }

  try {
    redis = new Redis({
      url,
      token,
      automaticDeserialization: false
    });
    console.log('[Redis] Upstash Redis enabled for Watch Together persistence');
    return true;
  } catch (error) {
    console.error('[Redis] Failed to initialize Upstash Redis:', error.message);
    redis = null;
    return false;
  }
}

function isConnected() {
  return redis !== null;
}

async function saveRoomState(roomCode, roomData, ttlSeconds = ROOM_TTL_SECONDS) {
  if (!redis) return false;

  try {
    await redis.setex(`wt:room:${roomCode}`, ttlSeconds, JSON.stringify(roomData));
    return true;
  } catch (error) {
    console.error('[Redis] saveRoomState failed:', error.message);
    return false;
  }
}

async function getRoomState(roomCode) {
  if (!redis) return null;

  try {
    const data = await redis.get(`wt:room:${roomCode}`);
    return safeParseJson(data, null);
  } catch (error) {
    console.error('[Redis] getRoomState failed:', error.message);
    return null;
  }
}

async function deleteRoomState(roomCode) {
  if (!redis) return false;

  try {
    await redis.del(`wt:room:${roomCode}`);
    await redis.del(`wt:room:${roomCode}:events`);
    await redis.del(`wt:room:${roomCode}:participants`);
    return true;
  } catch (error) {
    console.error('[Redis] deleteRoomState failed:', error.message);
    return false;
  }
}

async function updateRoomParticipants(roomCode, participants) {
  if (!redis) return false;

  const room = await getRoomState(roomCode);
  if (!room) return false;

  room.participants = Array.isArray(participants) ? participants : [];
  return saveRoomState(roomCode, room);
}

async function logSyncEvent(roomCode, event) {
  if (!redis) return false;

  try {
    await redis.lpush(
      `wt:room:${roomCode}:events`,
      JSON.stringify({
        timestamp: Date.now(),
        ...event
      })
    );
    await redis.ltrim(`wt:room:${roomCode}:events`, 0, 99);
    await redis.expire(`wt:room:${roomCode}:events`, EVENTS_TTL_SECONDS);
    return true;
  } catch (error) {
    console.error('[Redis] logSyncEvent failed:', error.message);
    return false;
  }
}

async function getSyncEvents(roomCode, limit = 50) {
  if (!redis) return [];

  try {
    const events = await redis.lrange(`wt:room:${roomCode}:events`, 0, Math.max(limit - 1, 0));
    if (!Array.isArray(events)) return [];
    return events
      .map((event) => safeParseJson(event, null))
      .filter(Boolean);
  } catch (error) {
    console.error('[Redis] getSyncEvents failed:', error.message);
    return [];
  }
}

async function acquireRoomLock(roomCode, ttlSeconds = 30) {
  if (!redis) return null;

  try {
    const lockId = `lock_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    const acquired = await redis.set(`wt:lock:${roomCode}`, lockId, { nx: true, ex: ttlSeconds });
    return acquired ? lockId : null;
  } catch (error) {
    console.error('[Redis] acquireRoomLock failed:', error.message);
    return null;
  }
}

async function releaseRoomLock(roomCode, lockId) {
  if (!redis || !lockId) return false;

  try {
    const key = `wt:lock:${roomCode}`;
    const currentLock = await redis.get(key);
    if (currentLock !== lockId) {
      return false;
    }
    await redis.del(key);
    return true;
  } catch (error) {
    console.error('[Redis] releaseRoomLock failed:', error.message);
    return false;
  }
}

async function setRoomParticipant(roomCode, participantId, isOnline, data = {}) {
  if (!redis) return false;

  const key = `wt:room:${roomCode}:participants`;

  try {
    if (isOnline) {
      await redis.hset(key, {
        [participantId]: JSON.stringify({
          id: participantId,
          online: true,
          lastSeen: Date.now(),
          ...data
        })
      });
      await redis.expire(key, PARTICIPANTS_TTL_SECONDS);
      return true;
    }

    await redis.hdel(key, participantId);
    return true;
  } catch (error) {
    console.error('[Redis] setRoomParticipant failed:', error.message);
    return false;
  }
}

async function getRoomParticipants(roomCode) {
  if (!redis) return [];

  try {
    const entries = await redis.hgetall(`wt:room:${roomCode}:participants`);
    if (!entries || typeof entries !== 'object') return [];

    return Object.entries(entries)
      .map(([participantId, value]) => safeParseJson(value, { id: participantId }))
      .filter(Boolean);
  } catch (error) {
    console.error('[Redis] getRoomParticipants failed:', error.message);
    return [];
  }
}

async function electNewHost(roomCode, currentHostId) {
  const room = await getRoomState(roomCode);
  if (!room || !Array.isArray(room.participants)) {
    return null;
  }

  const onlineParticipants = await getRoomParticipants(roomCode);
  const onlineIds = new Set(
    onlineParticipants
      .filter((participant) => participant?.online !== false)
      .map((participant) => participant.id)
  );

  let nextHost = null;
  let earliestJoin = Number.POSITIVE_INFINITY;

  for (const participant of room.participants) {
    if (!participant || participant.id === currentHostId) continue;
    if (!onlineIds.has(participant.id)) continue;

    const joinedAt = Number(participant.joined_at || participant.joinedAt || 0);
    if (!nextHost || joinedAt < earliestJoin) {
      nextHost = participant.id;
      earliestJoin = joinedAt;
    }
  }

  return nextHost;
}

async function listRoomCodes() {
  if (!redis) return [];

  try {
    const keys = await redis.keys('wt:room:*');
    if (!Array.isArray(keys)) return [];

    return keys
      .filter((key) => !key.includes(':events') && !key.includes(':participants'))
      .map((key) => key.replace('wt:room:', ''));
  } catch (error) {
    console.error('[Redis] listRoomCodes failed:', error.message);
    return [];
  }
}

module.exports = {
  initRedis,
  isConnected,
  saveRoomState,
  getRoomState,
  deleteRoomState,
  updateRoomParticipants,
  logSyncEvent,
  getSyncEvents,
  acquireRoomLock,
  releaseRoomLock,
  setRoomParticipant,
  getRoomParticipants,
  electNewHost,
  listRoomCodes
};
