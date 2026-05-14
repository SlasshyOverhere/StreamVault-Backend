const express = require('express');
const cors = require('cors');
const http = require('http');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const social = require('./social');
const database = require('./database');
const redis = require('./redis');

const app = express();
app.disable('x-powered-by');

const PORT = process.env.PORT || 3001;

// Google OAuth credentials (stored securely on server)
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;

// Auto-detect redirect URI from request if not set
const getRedirectUri = (req) => {
  if (process.env.REDIRECT_URI) {
    return process.env.REDIRECT_URI;
  }
  // Fallback: construct from request
  const protocol = req.headers['x-forwarded-proto'] || req.protocol || 'https';
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  return `${protocol}://${host}/auth/callback`;
};

// Scopes for Google Drive-backed features
const DRIVE_SCOPES = [
  'https://www.googleapis.com/auth/drive',
  'https://www.googleapis.com/auth/userinfo.email'
].join(' ');

// Narrower scopes for Social auth only
const SOCIAL_SCOPES = [
  'openid',
  'https://www.googleapis.com/auth/userinfo.email',
  'https://www.googleapis.com/auth/userinfo.profile'
].join(' ');

// ============================================
// TMDB Proxy - Credential Pool (up to 5 keys)
// ============================================

const TMDB_API_BASE = 'https://api.themoviedb.org/3';
const TMDB_MAX_KEYS = 5;
const parseCooldownMs = (rawValue, fallback) => {
  const parsed = Number(rawValue);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
};
const parseNonNegativeInt = (rawValue, fallback) => {
  const parsed = Number(rawValue);
  return Number.isFinite(parsed) && parsed >= 0 ? Math.floor(parsed) : fallback;
};
const parsePositiveInt = (rawValue, fallback) => {
  const parsed = Number(rawValue);
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : fallback;
};
const parsePositiveFloat = (rawValue, fallback) => {
  const parsed = Number(rawValue);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
};
const CORS_ALLOWED_ORIGINS = new Set(splitEnvList(process.env.CORS_ALLOWED_ORIGINS).map((origin) => origin.trim()).filter(Boolean));
const RUNTIME_METRICS_USERNAME = (process.env.RUNTIME_METRICS_USERNAME || 'runtime').trim();
const RUNTIME_METRICS_PASSWORD = (process.env.RUNTIME_METRICS_PASSWORD || '').trim();
const RUNTIME_RATE_WINDOW_MS = parsePositiveInt(process.env.RUNTIME_RATE_WINDOW_MS, 10 * 60 * 1000);
const RUNTIME_RATE_MAX_REQUESTS = parsePositiveInt(process.env.RUNTIME_RATE_MAX_REQUESTS, 300);
const RUNTIME_AUTH_FAIL_WINDOW_MS = parsePositiveInt(process.env.RUNTIME_AUTH_FAIL_WINDOW_MS, 30 * 60 * 1000);
const RUNTIME_AUTH_MAX_FAILS = parsePositiveInt(process.env.RUNTIME_AUTH_MAX_FAILS, 20);
const RUNTIME_AUTH_LOCK_MS = parsePositiveInt(process.env.RUNTIME_AUTH_LOCK_MS, 60 * 60 * 1000);
const RUNTIME_SECURITY_CLEANUP_MS = parsePositiveInt(process.env.RUNTIME_SECURITY_CLEANUP_MS, 10 * 60 * 1000);
const TMDB_RATE_LIMIT_COOLDOWN_MS = parseCooldownMs(process.env.TMDB_RATE_LIMIT_COOLDOWN_MS, 15000);
const TMDB_AUTH_FAILURE_COOLDOWN_MS = parseCooldownMs(process.env.TMDB_AUTH_FAILURE_COOLDOWN_MS, 60000);
const TMDB_SERVER_FAILURE_COOLDOWN_MS = parseCooldownMs(process.env.TMDB_SERVER_FAILURE_COOLDOWN_MS, 3000);
const TMDB_MAX_INFLIGHT_PER_KEY = parseNonNegativeInt(process.env.TMDB_MAX_INFLIGHT_PER_KEY, 0); // 0 = unlimited
const TMDB_PROXY_LOGS_ENABLED = process.env.TMDB_PROXY_LOGS !== '0';
const TMDB_PROXY_DEBUG_ENABLED = process.env.TMDB_PROXY_DEBUG === '1';

const WT_LIVE_LOGS_ENABLED = process.env.WT_LIVE_LOGS === '1';

function isCorsOriginAllowed(origin) {
  if (!origin) return true; // Native clients and curl usually have no Origin.
  if (CORS_ALLOWED_ORIGINS.size === 0) return true;
  return CORS_ALLOWED_ORIGINS.has(origin);
}

app.use(cors({
  origin(origin, callback) {
    callback(null, isCorsOriginAllowed(origin));
  },
}));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

const runtimeRateByIp = new Map();
const runtimeAuthByIp = new Map();

const tokenCache = new Map(); // accessToken -> { userInfo, expiresAt }
const TOKEN_CACHE_TTL = 5 * 60 * 1000; // 5 minutes
const TOKEN_CACHE_MAX_SIZE = 500;

function wtDebugLog(...args) {
  if (!WT_LIVE_LOGS_ENABLED) return;
  console.log(...args);
}

function createTmdbRequestId() {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`;
}

function getClientIp(req) {
  const forwardedFor = req.headers['x-forwarded-for'];
  if (typeof forwardedFor === 'string' && forwardedFor.trim()) {
    return forwardedFor.split(',')[0].trim();
  }
  return req.socket?.remoteAddress || 'unknown';
}

function parseRuntimeBasicAuth(req) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Basic ')) {
    return null;
  }

  try {
    const encoded = authHeader.slice('Basic '.length).trim();
    if (!encoded) return null;
    const decoded = Buffer.from(encoded, 'base64').toString('utf8');
    const separator = decoded.indexOf(':');
    if (separator < 0) return null;

    return {
      username: decoded.slice(0, separator),
      password: decoded.slice(separator + 1),
    };
  } catch {
    return null;
  }
}

function extractBearerToken(req) {
  const authHeader = req.headers.authorization;
  if (typeof authHeader !== 'string' || !authHeader.startsWith('Bearer ')) {
    return '';
  }
  return authHeader.slice('Bearer '.length).trim();
}

function secureTokenEqual(expected, provided) {
  const expectedBuffer = Buffer.from(expected, 'utf8');
  const providedBuffer = Buffer.from(provided, 'utf8');
  if (expectedBuffer.length !== providedBuffer.length) {
    return false;
  }
  return crypto.timingSafeEqual(expectedBuffer, providedBuffer);
}

function hashSha256(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

function normalizeId(value, maxLen = 256) {
  if (typeof value !== 'string') return '';
  return value.trim().slice(0, maxLen);
}

async function resolveGoogleUserFromAccessToken(accessToken) {
  const normalizedToken = normalizeId(accessToken || '', 4096);
  if (!normalizedToken) return null;

  const cached = tokenCache.get(normalizedToken);
  if (cached && Date.now() < cached.expiresAt) {
    return cached.userInfo;
  }

  try {
    const userInfoRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${normalizedToken}` }
    });

    if (!userInfoRes.ok) {
      tokenCache.delete(normalizedToken);
      return null;
    }

    const userInfo = await userInfoRes.json();
    if (!userInfo || typeof userInfo.id !== 'string' || !userInfo.id.trim()) {
      tokenCache.delete(normalizedToken);
      return null;
    }

    if (tokenCache.size >= TOKEN_CACHE_MAX_SIZE) {
      const firstKey = tokenCache.keys().next().value;
      tokenCache.delete(firstKey);
    }
    tokenCache.set(normalizedToken, {
      userInfo,
      expiresAt: Date.now() + TOKEN_CACHE_TTL
    });

    return userInfo;
  } catch {
    return null;
  }
}




function consumeRuntimeRequestRate(ip, now) {
  const existing = runtimeRateByIp.get(ip) || { timestamps: [] };
  existing.timestamps = existing.timestamps.filter((ts) => now - ts < RUNTIME_RATE_WINDOW_MS);
  existing.timestamps.push(now);
  runtimeRateByIp.set(ip, existing);

  if (existing.timestamps.length > RUNTIME_RATE_MAX_REQUESTS) {
    const oldestTs = existing.timestamps[0];
    const retryAfterMs = Math.max(1000, RUNTIME_RATE_WINDOW_MS - (now - oldestTs));
    return { allowed: false, retryAfterMs };
  }

  return { allowed: true };
}

function getRuntimeAuthState(ip) {
  const existing = runtimeAuthByIp.get(ip) || { failedTimestamps: [], lockUntil: 0 };
  runtimeAuthByIp.set(ip, existing);
  return existing;
}

function registerRuntimeAuthFailure(ip, now) {
  const state = getRuntimeAuthState(ip);
  state.failedTimestamps = state.failedTimestamps.filter((ts) => now - ts < RUNTIME_AUTH_FAIL_WINDOW_MS);
  state.failedTimestamps.push(now);

  if (state.failedTimestamps.length >= RUNTIME_AUTH_MAX_FAILS) {
    state.lockUntil = now + RUNTIME_AUTH_LOCK_MS;
    state.failedTimestamps = [];
  }

  runtimeAuthByIp.set(ip, state);
  return state;
}

function clearRuntimeAuthFailures(ip) {
  if (!runtimeAuthByIp.has(ip)) return;
  runtimeAuthByIp.delete(ip);
}

function runtimeMetricsAuth(req, res, next) {
  if (!RUNTIME_METRICS_PASSWORD) {
    return res.status(503).json({ error: 'Runtime metrics password is not configured' });
  }

  const now = Date.now();
  const sourceIp = getClientIp(req);

  const requestRate = consumeRuntimeRequestRate(sourceIp, now);
  if (!requestRate.allowed) {
    const retryAfterSec = Math.ceil(requestRate.retryAfterMs / 1000);
    res.set('Retry-After', String(retryAfterSec));
    console.warn(`[SECURITY] /health/runtime rate limited for IP ${sourceIp} (retry after ${retryAfterSec}s)`);
    return res.status(429).json({ error: 'Too many requests. Try again later.' });
  }

  const authState = getRuntimeAuthState(sourceIp);
  if (authState.lockUntil > now) {
    const retryAfterSec = Math.ceil((authState.lockUntil - now) / 1000);
    res.set('Retry-After', String(retryAfterSec));
    console.warn(`[SECURITY] /health/runtime locked IP ${sourceIp} attempted access during lockout`);
    return res.status(429).json({ error: 'Too many failed login attempts. Try again later.' });
  }

  const credentials = parseRuntimeBasicAuth(req);
  const usernameOk = credentials?.username ? secureTokenEqual(RUNTIME_METRICS_USERNAME, credentials.username) : false;
  const passwordOk = credentials?.password ? secureTokenEqual(RUNTIME_METRICS_PASSWORD, credentials.password) : false;

  if (!usernameOk || !passwordOk) {
    const updatedState = registerRuntimeAuthFailure(sourceIp, now);
    if (updatedState.lockUntil > now) {
      const retryAfterSec = Math.ceil((updatedState.lockUntil - now) / 1000);
      res.set('Retry-After', String(retryAfterSec));
      console.warn(`[SECURITY] /health/runtime locked for IP ${sourceIp} after repeated auth failures`);
      return res.status(429).json({ error: 'Too many failed login attempts. Try again later.' });
    }

    console.warn(`[SECURITY] Unauthorized /health/runtime access attempt from ${sourceIp}`);
    res.set('WWW-Authenticate', 'Basic realm="runtime-metrics", charset="UTF-8"');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  clearRuntimeAuthFailures(sourceIp);
  return next();
}

setInterval(() => {
  const now = Date.now();

  for (const [ip, state] of runtimeRateByIp.entries()) {
    state.timestamps = state.timestamps.filter((ts) => now - ts < RUNTIME_RATE_WINDOW_MS);
    if (state.timestamps.length === 0) {
      runtimeRateByIp.delete(ip);
    } else {
      runtimeRateByIp.set(ip, state);
    }
  }

  for (const [ip, state] of runtimeAuthByIp.entries()) {
    if (state.lockUntil > 0 && state.lockUntil <= now) {
      state.lockUntil = 0;
    }
    state.failedTimestamps = state.failedTimestamps.filter((ts) => now - ts < RUNTIME_AUTH_FAIL_WINDOW_MS);

    if (state.lockUntil <= now && state.failedTimestamps.length === 0) {
      runtimeAuthByIp.delete(ip);
    } else {
      runtimeAuthByIp.set(ip, state);
    }
  }

}, Math.max(60 * 1000, RUNTIME_SECURITY_CLEANUP_MS)).unref?.();

function tmdbLog(level, requestId, message, meta = null) {
  if (!TMDB_PROXY_LOGS_ENABLED) return;

  const prefix = requestId ? `[TMDB][${requestId}]` : '[TMDB]';
  const suffix = meta ? ` ${JSON.stringify(meta)}` : '';
  const line = `${prefix} ${message}${suffix}`;

  if (level === 'error') {
    console.error(line);
    return;
  }
  if (level === 'warn') {
    console.warn(line);
    return;
  }
  console.log(line);
}

function splitEnvList(value) {
  if (!value) return [];
  return value
    .split(/[\n,;]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function isTmdbBearerToken(value) {
  return value.startsWith('eyJ');
}

function collectTmdbCredentialCandidates() {
  const candidates = [];

  // Explicit list vars (comma/newline/semicolon separated)
  candidates.push(...splitEnvList(process.env.TMDB_ACCESS_TOKENS));
  candidates.push(...splitEnvList(process.env.TMDB_API_KEYS));
  candidates.push(...splitEnvList(process.env.TMDB_KEYS));

  // Single value vars
  candidates.push(...splitEnvList(process.env.TMDB_ACCESS_TOKEN));
  candidates.push(...splitEnvList(process.env.TMDB_API_KEY));

  // Numbered vars (e.g. TMDB_ACCESS_TOKEN_1 ... TMDB_ACCESS_TOKEN_5)
  const numbered = Object.entries(process.env)
    .filter(([name, value]) => {
      if (!value) return false;
      return /^(TMDB_ACCESS_TOKEN|TMDB_API_KEY)(?:_?\d+)?$/i.test(name);
    })
    .sort(([a], [b]) => a.localeCompare(b));

  for (const [, value] of numbered) {
    candidates.push(...splitEnvList(value));
  }

  const unique = [];
  const seen = new Set();
  for (const raw of candidates) {
    const value = raw.trim();
    if (!value) continue;
    const type = isTmdbBearerToken(value) ? 'bearer' : 'apiKey';
    const dedupeKey = `${type}:${value}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    unique.push(value);
    if (unique.length >= TMDB_MAX_KEYS) break;
  }

  return unique.map((value, index) => ({
    id: index + 1,
    type: isTmdbBearerToken(value) ? 'bearer' : 'apiKey',
    value,
  }));
}

const tmdbCredentials = collectTmdbCredentialCandidates();
const tmdbCredentialState = tmdbCredentials.map(() => ({
  cooldownUntil: 0,
  inFlight: 0,
  totalRequests: 0,
  totalSuccess: 0,
  totalRateLimited: 0,
  totalFailures: 0,
}));
let tmdbCredentialCursor = 0;

function selectTmdbCredentialIndex(excluded = new Set()) {
  if (tmdbCredentials.length === 0) return null;

  const now = Date.now();
  const total = tmdbCredentials.length;

  let bestReadyIdx = null;
  let bestReadyInFlight = Number.POSITIVE_INFINITY;
  let bestReadyOffset = Number.POSITIVE_INFINITY;

  let bestReadyIgnoringCapIdx = null;
  let bestReadyIgnoringCapInFlight = Number.POSITIVE_INFINITY;
  let bestReadyIgnoringCapOffset = Number.POSITIVE_INFINITY;

  let earliestCooldownIdx = null;
  let earliestCooldownTs = Number.POSITIVE_INFINITY;
  let earliestCooldownOffset = Number.POSITIVE_INFINITY;
  let earliestCooldownInFlight = Number.POSITIVE_INFINITY;

  for (let offset = 0; offset < total; offset++) {
    const idx = (tmdbCredentialCursor + offset) % total;
    if (excluded.has(idx)) continue;

    const state = tmdbCredentialState[idx];
    const inFlight = state.inFlight || 0;
    const isReady = state.cooldownUntil <= now;
    const underCap = TMDB_MAX_INFLIGHT_PER_KEY <= 0 || inFlight < TMDB_MAX_INFLIGHT_PER_KEY;

    if (isReady && underCap) {
      if (
        bestReadyIdx === null ||
        inFlight < bestReadyInFlight ||
        (inFlight === bestReadyInFlight && offset < bestReadyOffset)
      ) {
        bestReadyIdx = idx;
        bestReadyInFlight = inFlight;
        bestReadyOffset = offset;
      }
      continue;
    }

    if (isReady) {
      if (
        bestReadyIgnoringCapIdx === null ||
        inFlight < bestReadyIgnoringCapInFlight ||
        (inFlight === bestReadyIgnoringCapInFlight && offset < bestReadyIgnoringCapOffset)
      ) {
        bestReadyIgnoringCapIdx = idx;
        bestReadyIgnoringCapInFlight = inFlight;
        bestReadyIgnoringCapOffset = offset;
      }
      continue;
    }

    if (
      earliestCooldownIdx === null ||
      state.cooldownUntil < earliestCooldownTs ||
      (state.cooldownUntil === earliestCooldownTs && inFlight < earliestCooldownInFlight) ||
      (state.cooldownUntil === earliestCooldownTs && inFlight === earliestCooldownInFlight && offset < earliestCooldownOffset)
    ) {
      earliestCooldownIdx = idx;
      earliestCooldownTs = state.cooldownUntil;
      earliestCooldownInFlight = inFlight;
      earliestCooldownOffset = offset;
    }
  }

  if (bestReadyIdx !== null) {
    tmdbCredentialCursor = (bestReadyIdx + 1) % total;
    return bestReadyIdx;
  }

  if (bestReadyIgnoringCapIdx !== null) {
    tmdbCredentialCursor = (bestReadyIgnoringCapIdx + 1) % total;
    return bestReadyIgnoringCapIdx;
  }

  if (earliestCooldownIdx !== null) {
    tmdbCredentialCursor = (earliestCooldownIdx + 1) % total;
    return earliestCooldownIdx;
  }

  return null;
}

function sanitizeTmdbPath(rawPath) {
  const path = (rawPath || '').trim().replace(/^\/+/, '');
  if (!path) return null;
  if (path.includes('..') || path.includes('\\')) return null;
  if (path.startsWith('http://') || path.startsWith('https://')) return null;
  return path;
}

function toSearchParams(queryObj = {}) {
  const params = new URLSearchParams();
  for (const [key, rawValue] of Object.entries(queryObj)) {
    if (rawValue === undefined || rawValue === null) continue;
    if (Array.isArray(rawValue)) {
      for (const value of rawValue) {
        if (value !== undefined && value !== null) {
          params.append(key, String(value));
        }
      }
    } else {
      params.append(key, String(rawValue));
    }
  }
  return params;
}

function parseRetryAfterMs(retryAfter) {
  if (!retryAfter) return null;

  const seconds = Number(retryAfter);
  if (Number.isFinite(seconds)) {
    return Math.max(1000, seconds * 1000);
  }

  const dateMs = Date.parse(retryAfter);
  if (Number.isFinite(dateMs)) {
    const deltaMs = dateMs - Date.now();
    if (deltaMs > 0) return deltaMs;
  }

  return null;
}

async function fetchTmdbOnce(path, query, credential) {
  const params = toSearchParams(query);
  params.delete('api_key'); // Never allow clients to force a key

  const url = new URL(`${TMDB_API_BASE}/${path}`);
  url.search = params.toString();

  const headers = {
    Accept: 'application/json',
  };

  if (credential.type === 'bearer') {
    headers.Authorization = `Bearer ${credential.value}`;
  } else {
    url.searchParams.set('api_key', credential.value);
  }

  return fetch(url.toString(), {
    method: 'GET',
    headers,
  });
}

async function fetchTmdbWithFailover(path, query, requestId = null) {
  if (tmdbCredentials.length === 0) {
    tmdbLog('error', requestId, 'TMDB proxy request failed - credential pool is empty');
    return {
      error: {
        status: 503,
        message: 'TMDB credentials are not configured on the backend',
      },
    };
  }

  const attempted = new Set();
  let lastFailure = {
    status: 502,
    message: 'TMDB request failed for all configured credentials',
  };

  for (let attempt = 0; attempt < tmdbCredentials.length; attempt++) {
    const credentialIndex = selectTmdbCredentialIndex(attempted);
    if (credentialIndex === null) break;
    attempted.add(credentialIndex);

    const credential = tmdbCredentials[credentialIndex];
    const state = tmdbCredentialState[credentialIndex];
    const attemptStartedAtMs = Date.now();
    const cooldownRemainingMs = Math.max(0, state.cooldownUntil - attemptStartedAtMs);

    state.inFlight += 1;
    state.totalRequests += 1;

    tmdbLog('info', requestId, 'Trying TMDB credential', {
      attempt: attempt + 1,
      keyId: credential.id,
      keyType: credential.type,
      inFlight: state.inFlight,
      cooldownRemainingMs,
    });

    try {
      const response = await fetchTmdbOnce(path, query, credential);

      if (response.status === 429) {
        const retryAfterMs = parseRetryAfterMs(response.headers.get('retry-after')) || TMDB_RATE_LIMIT_COOLDOWN_MS;
        state.cooldownUntil = Date.now() + retryAfterMs;
        state.totalRateLimited += 1;
        tmdbLog('warn', requestId, 'TMDB rate limit on credential, rotating key', {
          keyId: credential.id,
          keyType: credential.type,
          retryAfterMs,
          inFlight: state.inFlight,
        });
        lastFailure = {
          status: 429,
          message: `TMDB rate limit hit on credential #${credential.id}`,
        };
        continue;
      }

      if (response.status === 401 || response.status === 403) {
        state.cooldownUntil = Date.now() + TMDB_AUTH_FAILURE_COOLDOWN_MS;
        state.totalFailures += 1;
        tmdbLog('warn', requestId, 'TMDB credential rejected, rotating key', {
          keyId: credential.id,
          keyType: credential.type,
          status: response.status,
          cooldownMs: TMDB_AUTH_FAILURE_COOLDOWN_MS,
          inFlight: state.inFlight,
        });
        lastFailure = {
          status: response.status,
          message: `TMDB credential #${credential.id} was rejected`,
        };
        continue;
      }

      if (response.status >= 500) {
        state.cooldownUntil = Date.now() + TMDB_SERVER_FAILURE_COOLDOWN_MS;
        state.totalFailures += 1;
        tmdbLog('warn', requestId, 'TMDB upstream 5xx, rotating key', {
          keyId: credential.id,
          keyType: credential.type,
          status: response.status,
          cooldownMs: TMDB_SERVER_FAILURE_COOLDOWN_MS,
          inFlight: state.inFlight,
        });
        lastFailure = {
          status: response.status,
          message: `TMDB upstream error ${response.status}`,
        };
        continue;
      }

      // Success or non-retryable client error (e.g. 404)
      state.cooldownUntil = 0;
      state.totalSuccess += 1;
      tmdbLog('info', requestId, 'TMDB request completed', {
        keyId: credential.id,
        keyType: credential.type,
        status: response.status,
        attemptsUsed: attempt + 1,
        inFlight: state.inFlight,
      });
      return {
        response,
        credentialId: credential.id,
        credentialType: credential.type,
        attemptsUsed: attempt + 1,
      };
    } catch (error) {
      state.cooldownUntil = Date.now() + TMDB_SERVER_FAILURE_COOLDOWN_MS;
      state.totalFailures += 1;
      tmdbLog('warn', requestId, 'TMDB network error, rotating key', {
        keyId: credential.id,
        keyType: credential.type,
        cooldownMs: TMDB_SERVER_FAILURE_COOLDOWN_MS,
        error: error.message || 'unknown network error',
        inFlight: state.inFlight,
      });
      lastFailure = {
        status: 502,
        message: `TMDB request failed: ${error.message || 'unknown network error'}`,
      };
    } finally {
      state.inFlight = Math.max(0, state.inFlight - 1);
      if (TMDB_PROXY_DEBUG_ENABLED) {
        tmdbLog('info', requestId, 'TMDB credential attempt finished', {
          keyId: credential.id,
          keyType: credential.type,
          inFlight: state.inFlight,
          elapsedMs: Date.now() - attemptStartedAtMs,
        });
      }
    }
  }

  tmdbLog('error', requestId, 'TMDB request failed across credential pool', {
    attempts: attempted.size,
    finalStatus: lastFailure.status,
    finalMessage: lastFailure.message,
  });
  return { error: lastFailure };
}

// ============================================
// Watch Together - Room Management
// ============================================

// In-memory room storage (use Redis in production for scaling)
const rooms = new Map();

// Syncplay-inspired constants
const SYNC_BROADCAST_INTERVAL = 500; // Broadcast state updates every 0.5s
const PING_INTERVAL = 2000; // Ping clients every 2s for RTT measurement
const PING_MOVING_AVG_WEIGHT = 0.85; // Moving average weight for RTT smoothing
const STATE_REPORT_CORRECTION_THRESHOLD = 0.45; // Pull server state toward authority when drift grows
const SYNC_SOURCE_TTL_MS = 12000; // Authority handoff timeout in collaborative mode
const WT_SYNC_MODE = ['host_only', 'collaborative'].includes(process.env.WT_SYNC_MODE)
  ? process.env.WT_SYNC_MODE
  : 'collaborative';
const DISCONNECT_GRACE_MS = 20000; // Keep participant slot for short reconnect window

// Room cleanup interval (remove inactive rooms after 1 hour)
const ROOM_TIMEOUT = 60 * 60 * 1000; // 1 hour
const ROOM_CLEANUP_INTERVAL = 5 * 60 * 1000; // Check every 5 minutes

// Generate a 6-character room code (no ambiguous characters)
function generateRoomCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // No I, O, 0, 1
  let code = '';
  for (let i = 0; i < 6; i++) {
    code += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return code;
}

function normalizeMediaMatchKey(value) {
  if (value === undefined || value === null) {
    return '';
  }
  return value.toString().trim().toLowerCase();
}

function extractMediaMatchKeys(value) {
  const normalized = normalizeMediaMatchKey(value);
  if (!normalized) {
    return [];
  }
  return normalized
    .split('|')
    .map((token) => token.trim())
    .filter(Boolean);
}

function hasMatchingMediaKey(roomKeyValue, joinKeyValue) {
  const roomKeys = extractMediaMatchKeys(roomKeyValue);
  const joinKeys = extractMediaMatchKeys(joinKeyValue);
  if (roomKeys.length === 0 || joinKeys.length === 0) {
    return null;
  }
  const roomSet = new Set(roomKeys);
  return joinKeys.some((key) => roomSet.has(key));
}

function normalizeSyncAction(action) {
  const normalized = (action || '').toString().trim().toLowerCase();
  if (normalized === 'resume') return 'play';
  if (normalized === 'play' || normalized === 'pause' || normalized === 'seek') {
    return normalized;
  }
  return null;
}

function normalizeSyncPosition(position, fallback = 0) {
  const parsed = Number(position);
  if (Number.isFinite(parsed)) {
    return Math.max(0, parsed);
  }
  const fallbackNumber = Number(fallback);
  if (Number.isFinite(fallbackNumber)) {
    return Math.max(0, fallbackNumber);
  }
  return 0;
}

function canParticipantDriveRoomState(room, participantId, participant, now) {
  if (!participant) return false;
  if (room.sync_mode === 'host_only') {
    return participant.is_host;
  }
  if (room.last_sync_from && room.last_sync_at && (now - room.last_sync_at) <= SYNC_SOURCE_TTL_MS) {
    return room.last_sync_from === participantId;
  }
  return participant.is_host;
}

function serializeRoomParticipant(participant) {
  if (!participant) return null;

  return {
    id: participant.id,
    nickname: participant.nickname,
    is_host: !!participant.is_host,
    is_ready: !!participant.is_ready,
    joined_at: Number(participant.joined_at) || Date.now(),
    media_id: participant.media_id ?? null,
    duration: participant.duration ?? null,
    rtt: Number(participant.rtt) || 0,
    rttAvg: Number(participant.rttAvg) || 0,
    lastPosition: Number(participant.lastPosition) || 0,
    lastPaused: participant.lastPaused !== false,
    lastStateReport: Number(participant.lastStateReport) || Date.now(),
    disconnected_at: participant.disconnected_at ?? null
  };
}

function buildPersistedRoomState(room) {
  if (!room) return null;

  return {
    code: room.code,
    media_id: room.media_id,
    media_title: room.media_title,
    media_match_key: room.media_match_key || '',
    host_id: room.host_id,
    state: room.state,
    current_position: getServerPosition(room),
    is_paused: !!room.is_paused,
    position_updated_at: Date.now(),
    sync_mode: room.sync_mode || WT_SYNC_MODE,
    participants: Array.from(room.participants.values())
      .map(serializeRoomParticipant)
      .filter(Boolean),
    created_at: Number(room.created_at) || Date.now(),
    lastActivity: Number(room.lastActivity) || Date.now(),
    last_sync_from: room.last_sync_from || null,
    last_sync_at: Number(room.last_sync_at) || Date.now()
  };
}

function hydrateRecoveredParticipant(participantData) {
  const now = Date.now();

  return {
    id: participantData.id,
    nickname: participantData.nickname,
    is_host: !!participantData.is_host,
    is_ready: !!participantData.is_ready,
    joined_at: Number(participantData.joined_at) || now,
    media_id: participantData.media_id ?? null,
    duration: participantData.duration ?? null,
    ws: null,
    rtt: Number(participantData.rtt) || 0,
    rttAvg: Number(participantData.rttAvg) || 0,
    lastPosition: Number(participantData.lastPosition) || 0,
    lastPaused: participantData.lastPaused !== false,
    lastStateReport: Number(participantData.lastStateReport) || now,
    disconnectTimer: null,
    disconnected_at: participantData.disconnected_at ?? null
  };
}

function hydrateRecoveredRoom(roomData) {
  const participants = new Map();
  for (const participantData of roomData.participants || []) {
    if (!participantData?.id) continue;
    participants.set(participantData.id, hydrateRecoveredParticipant(participantData));
  }

  const room = {
    code: roomData.code,
    media_id: roomData.media_id,
    media_title: roomData.media_title,
    media_match_key: normalizeMediaMatchKey(roomData.media_match_key),
    host_id: roomData.host_id,
    state: roomData.state || 'waiting',
    current_position: normalizeSyncPosition(roomData.current_position, 0),
    is_paused: roomData.is_paused !== false,
    position_updated_at: Number(roomData.position_updated_at) || Date.now(),
    sync_mode: ['host_only', 'collaborative'].includes(roomData.sync_mode) ? roomData.sync_mode : WT_SYNC_MODE,
    participants,
    created_at: Number(roomData.created_at) || Date.now(),
    lastActivity: Number(roomData.lastActivity) || Date.now(),
    last_sync_from: roomData.last_sync_from || roomData.host_id || null,
    last_sync_at: Number(roomData.last_sync_at) || Date.now(),
    syncInterval: null,
    pingInterval: null
  };

  return room;
}

async function persistRoomState(room) {
  if (!redis.isConnected() || !room) return false;
  return redis.saveRoomState(room.code, buildPersistedRoomState(room));
}

async function syncRoomParticipantsInRedis(room) {
  if (!redis.isConnected() || !room) return false;

  const participants = Array.from(room.participants.values())
    .map(serializeRoomParticipant)
    .filter(Boolean);

  await redis.updateRoomParticipants(room.code, participants);

  await Promise.all(
    participants.map((participant) => redis.setRoomParticipant(
      room.code,
      participant.id,
      !participant.disconnected_at,
      {
        nickname: participant.nickname,
        is_host: participant.is_host,
        joined_at: participant.joined_at,
        is_ready: participant.is_ready
      }
    ))
  );

  return true;
}

async function removeRoomParticipantFromRedis(roomCode, participantId) {
  if (!redis.isConnected() || !roomCode || !participantId) return false;
  return redis.setRoomParticipant(roomCode, participantId, false);
}

async function logRoomEvent(roomCode, event) {
  if (!redis.isConnected() || !roomCode || !event) return false;
  return redis.logSyncEvent(roomCode, event);
}

async function deletePersistedRoom(roomCode) {
  if (!redis.isConnected() || !roomCode) return false;
  return redis.deleteRoomState(roomCode);
}

async function generateUniqueRoomCode() {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const candidate = generateRoomCode();
    if (rooms.has(candidate)) {
      continue;
    }

    if (redis.isConnected()) {
      const existingRoom = await redis.getRoomState(candidate);
      if (existingRoom) {
        continue;
      }
    }

    return candidate;
  }

  throw new Error('Failed to generate a unique room code');
}

async function recoverRoomsFromRedis() {
  if (!redis.isConnected()) {
    console.log('[WT] Redis not connected; skipping room recovery');
    return;
  }

  const roomCodes = await redis.listRoomCodes();
  if (!roomCodes.length) {
    console.log('[WT] No persisted Watch Together rooms found');
    return;
  }

  let recoveredCount = 0;

  for (const roomCode of roomCodes) {
    try {
      if (rooms.has(roomCode)) {
        continue;
      }

      const roomData = await redis.getRoomState(roomCode);
      if (!roomData) {
        continue;
      }

      const room = hydrateRecoveredRoom(roomData);
      rooms.set(roomCode, room);
      startRoomSyncTimers(room);
      recoveredCount += 1;
    } catch (error) {
      console.error(`[WT] Failed to recover room ${roomCode}:`, error);
    }
  }

  console.log(`[WT] Recovered ${recoveredCount} room(s) from Redis`);
}

// Clean up inactive rooms
setInterval(async () => {
  const now = Date.now();
  for (const [code, room] of rooms.entries()) {
    if (now - room.lastActivity > ROOM_TIMEOUT) {
      wtDebugLog(`[WT] Cleaning up inactive room: ${code}`);
      stopRoomSyncTimers(room);
      // Close all connections in the room
      for (const participant of room.participants.values()) {
        if (participant.ws && participant.ws.readyState === 1) {
          participant.ws.close(1000, 'Room expired');
        }
      }
      rooms.delete(code);
      await deletePersistedRoom(code);
    }
  }
}, ROOM_CLEANUP_INTERVAL);

// ============================================
// REST Endpoints
// ============================================

// Root - simple response
app.get('/', (req, res) => {
  res.json({
    service: 'StreamVault Auth Server',
    version: '1.2.0',
  });
});

// Health check endpoint for monitoring
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    configured: !!(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET),
  });
});

// Runtime metrics endpoint (protected)
app.get('/health/runtime', runtimeMetricsAuth, (req, res) => {
  const now = Date.now();
  res.json({
    activeRooms: rooms.size,
    onlineUsers: social.onlineUsers.size,
    tmdbCredentials: tmdbCredentials.length,
    tmdbPool: tmdbCredentials.map((credential, index) => ({
      id: credential.id,
      type: credential.type,
      inFlight: tmdbCredentialState[index].inFlight,
      cooldownRemainingMs: Math.max(0, tmdbCredentialState[index].cooldownUntil - now),
      totalRequests: tmdbCredentialState[index].totalRequests,
      totalSuccess: tmdbCredentialState[index].totalSuccess,
      totalRateLimited: tmdbCredentialState[index].totalRateLimited,
      totalFailures: tmdbCredentialState[index].totalFailures,
    })),
  });
});

// TMDB proxy endpoints
app.get('/api/tmdb', (req, res) => {
  res.status(400).json({ error: 'Missing TMDB API path' });
});

// Express 5 requires named wildcard params (path-to-regexp v8).
app.get('/api/tmdb/*tmdbPath', async (req, res) => {
  const requestId = createTmdbRequestId();
  const startMs = Date.now();
  const wildcardPath = req.params?.tmdbPath ?? req.params?.[0];
  const rawPath = Array.isArray(wildcardPath) ? wildcardPath.join('/') : wildcardPath;
  const path = sanitizeTmdbPath(rawPath);

  if (!path) {
    tmdbLog('warn', requestId, 'Rejected TMDB request with invalid path', { rawPath });
    return res.status(400).json({ error: 'Invalid TMDB path' });
  }

  if (TMDB_PROXY_DEBUG_ENABLED) {
    tmdbLog('info', requestId, 'Incoming TMDB proxy request', {
      path,
      queryKeys: Object.keys(req.query || {}),
      poolSize: tmdbCredentials.length,
    });
  }

  const result = await fetchTmdbWithFailover(path, req.query, requestId);
  if (result.error) {
    tmdbLog('error', requestId, 'Returning TMDB proxy error to client', {
      status: result.error.status || 502,
      message: result.error.message,
      durationMs: Date.now() - startMs,
    });
    return res.status(result.error.status || 502).json({ error: result.error.message });
  }

  const { response } = result;
  const contentType = response.headers.get('content-type');
  const cacheControl = response.headers.get('cache-control');
  const payload = Buffer.from(await response.arrayBuffer());

  tmdbLog('info', requestId, 'Returning TMDB proxy response', {
    upstreamStatus: response.status,
    keyId: result.credentialId,
    keyType: result.credentialType,
    attemptsUsed: result.attemptsUsed,
    payloadBytes: payload.length,
    durationMs: Date.now() - startMs,
  });

  if (contentType) res.set('Content-Type', contentType);
  if (cacheControl) res.set('Cache-Control', cacheControl);
  res.status(response.status).send(payload);
});

// ============================================
// Social API Endpoints
// ============================================

// Token verification cache to avoid hitting Google's userinfo API on every request.
// Maps accessToken -> { userInfo, expiresAt }
// Clean up expired tokens periodically
setInterval(() => {
  const now = Date.now();
  for (const [token, entry] of tokenCache) {
    if (now > entry.expiresAt) {
      tokenCache.delete(token);
    }
  }
}, 60 * 1000); // Every 60 seconds

// Auth middleware for social endpoints
const socialAuth = async (req, res, next) => {
  const accessToken = extractBearerToken(req);
  if (!accessToken) {
    return res.status(401).json({ error: 'Missing or invalid authorization header' });
  }

  try {
    const userInfo = await resolveGoogleUserFromAccessToken(accessToken);
    if (!userInfo) {
      return res.status(401).json({ error: 'Invalid access token' });
    }

    req.googleId = userInfo.id;
    req.accessToken = accessToken;
    req.userInfo = userInfo;
    social.touchUserSession(req.googleId, accessToken);
    next();


  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>StreamVault AI Admin</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Manrope:wght@500;700;800&family=JetBrains+Mono:wght@500&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #0f1117;
      --surface: #181c24;
      --surface-2: #1f2530;
      --text: #f3f4f7;
      --muted: #98a2b3;
      --accent: #4cc9f0;
      --ok: #34d399;
      --warn: #fbbf24;
      --bad: #f87171;
      --border: rgba(255, 255, 255, 0.12);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      background: radial-gradient(circle at 10% 0%, rgba(76,201,240,0.16), transparent 35%), radial-gradient(circle at 90% 80%, rgba(52,211,153,0.12), transparent 30%), var(--bg);
      color: var(--text);
      font-family: "Manrope", "Segoe UI", sans-serif;
      padding: 28px;
    }
    .wrap { max-width: 1280px; margin: 0 auto; }
    .head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 16px;
    }
    .title {
      margin: 0;
      font-size: clamp(1.25rem, 2vw, 1.8rem);
      font-weight: 800;
      letter-spacing: 0.01em;
    }
    .sub {
      margin: 6px 0 0;
      color: var(--muted);
      font-size: 0.9rem;
    }
    .bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      flex-wrap: wrap;
      margin-bottom: 18px;
      padding: 12px;
      border: 1px solid var(--border);
      border-radius: 14px;
      background: linear-gradient(160deg, rgba(255,255,255,0.02), rgba(255,255,255,0.06));
      backdrop-filter: blur(8px);
    }
    .filters { display: flex; gap: 8px; flex-wrap: wrap; }
    .filter-tab {
      text-decoration: none;
      color: var(--text);
      border: 1px solid var(--border);
      background: var(--surface);
      border-radius: 999px;
      padding: 8px 14px;
      font-size: 0.82rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      font-weight: 700;
    }
    .filter-tab.active {
      border-color: rgba(76, 201, 240, 0.7);
      box-shadow: 0 0 0 1px rgba(76, 201, 240, 0.25) inset;
      background: rgba(76, 201, 240, 0.15);
    }
    .refresh {
      text-decoration: none;
      color: var(--text);
      border: 1px solid var(--border);
      background: var(--surface);
      border-radius: 10px;
      padding: 8px 12px;
      font-size: 0.82rem;
      font-weight: 700;
    }
    .message {
      margin-bottom: 14px;
      padding: 10px 12px;
      border-radius: 10px;
      font-size: 0.84rem;
      border: 1px solid var(--border);
    }
    .message.ok { background: rgba(52, 211, 153, 0.14); border-color: rgba(52, 211, 153, 0.35); }
    .message.err { background: rgba(248, 113, 113, 0.14); border-color: rgba(248, 113, 113, 0.35); }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 16px; }
    .request-card {
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 14px;
      background: linear-gradient(170deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02));
      backdrop-filter: blur(10px);
    }
    .request-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      margin-bottom: 12px;
    }
    .request-head h3 {
      margin: 0;
      font-size: 0.97rem;
      letter-spacing: 0.03em;
    }
    .status {
      font-size: 0.74rem;
      text-transform: uppercase;
      letter-spacing: 0.09em;
      font-weight: 800;
      border-radius: 999px;
      padding: 6px 10px;
      border: 1px solid transparent;
    }
    .status-pending { color: #fef3c7; background: rgba(251,191,36,0.16); border-color: rgba(251,191,36,0.38); }
    .status-approved { color: #bbf7d0; background: rgba(52,211,153,0.16); border-color: rgba(52,211,153,0.38); }
    .status-rejected { color: #fecaca; background: rgba(248,113,113,0.16); border-color: rgba(248,113,113,0.38); }
    .status-banned { color: #fcd34d; background: rgba(245,158,11,0.2); border-color: rgba(245,158,11,0.45); }
    .status-unbanned { color: #bbf7d0; background: rgba(34,197,94,0.16); border-color: rgba(34,197,94,0.36); }
    .request-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px;
      margin-bottom: 10px;
    }
    .label {
      margin: 0 0 3px;
      color: var(--muted);
      font-size: 0.72rem;
      text-transform: uppercase;
      letter-spacing: 0.07em;
      font-weight: 700;
    }
    .value {
      margin: 0;
      font-size: 0.86rem;
      word-break: break-word;
    }
    .mono {
      font-family: "JetBrains Mono", "Consolas", monospace;
      font-size: 0.8rem;
    }
    .request-meta { margin-bottom: 12px; }
    .request-meta .value { margin-bottom: 8px; }
    .actions { display: grid; gap: 10px; }
    .action-form {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 8px;
      align-items: end;
    }
    .action-form-user {
      grid-template-columns: 1fr auto;
    }
    .action-form label {
      display: grid;
      gap: 4px;
      font-size: 0.72rem;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.06em;
      font-weight: 700;
    }
    .action-form input {
      width: 100%;
      background: var(--surface-2);
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 8px 9px;
      font-size: 0.8rem;
      font-family: "JetBrains Mono", "Consolas", monospace;
    }
    .btn {
      border: 0;
      border-radius: 10px;
      padding: 9px 12px;
      cursor: pointer;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      font-size: 0.72rem;
    }
    .btn-approve { background: linear-gradient(135deg, #34d399, #10b981); color: #041510; }
    .btn-reject { background: linear-gradient(135deg, #f87171, #ef4444); color: #2a0404; }
    .btn-ban { background: linear-gradient(135deg, #f59e0b, #d97706); color: #211006; }
    .btn-unban { background: linear-gradient(135deg, #22c55e, #16a34a); color: #04150b; }
    .empty {
      border: 1px dashed var(--border);
      border-radius: 14px;
      padding: 26px;
      text-align: center;
      color: var(--muted);
      background: rgba(255,255,255,0.03);
    }
    @media (max-width: 980px) {
      body { padding: 16px; }
      .action-form { grid-template-columns: 1fr 1fr; }
      .action-form-user { grid-template-columns: 1fr; }
    }
    @media (max-width: 640px) {
      .request-grid { grid-template-columns: 1fr; }
      .action-form { grid-template-columns: 1fr; }
    }
// Initialize social profile (called after OAuth)
app.post('/api/social/init', socialAuth, async (req, res) => {
  try {
    const profile = await social.initUserSocial(req.googleId, req.accessToken, req.userInfo);
    res.json({ success: true, profile });
  } catch (error) {
    console.error('[Social] Init error:', error);
    res.status(500).json({ error: 'Failed to initialize social profile' });
  }
});

// Get own profile
app.get('/api/social/profile', socialAuth, async (req, res) => {
  try {
    const profile = await social.getProfile(req.googleId, req.accessToken);
    res.json(profile);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get profile' });
  }
});

// Update profile
app.patch('/api/social/profile', socialAuth, async (req, res) => {
  try {
    const {
      displayName,
      avatarUrl,
      bio,
      favoriteGenre,
      location
    } = req.body || {};
    const profile = await social.updateProfile(req.googleId, req.accessToken, {
      displayName,
      avatarUrl,
      bio,
      favoriteGenre,
      location
    });
    res.json(profile);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Update privacy settings
app.patch('/api/social/privacy', socialAuth, async (req, res) => {
  try {
    const profile = await social.updatePrivacySettings(req.googleId, req.accessToken, req.body);
    res.json(profile.privacySettings);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update privacy settings' });
  }
});

// Get friend profile
app.get('/api/social/profile/:userId', socialAuth, async (req, res) => {
  try {
    const profile = await social.getFriendProfile(req.googleId, req.accessToken, req.params.userId);
    if (!profile) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(profile);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get profile' });
  }
});

// Search users
app.get('/api/social/search', socialAuth, async (req, res) => {
  try {
    const { q } = req.query;
    if (!q || q.length < 2) {
      return res.json([]);
    }
    const results = await social.searchUsers(q, req.googleId);
    res.json(results);
  } catch (error) {
    res.status(500).json({ error: 'Search failed' });
  }
});

// Get friends list
app.get('/api/social/friends', socialAuth, async (req, res) => {
  try {
    const friends = await social.getFriends(req.googleId, req.accessToken);
    const online = await social.getOnlineFriends(req.googleId, req.accessToken);
    res.json({ friends, online });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get friends' });
  }
});

// Get pending friend requests
app.get('/api/social/friends/requests', socialAuth, async (req, res) => {
  try {
    const requests = await social.getPendingRequests(req.googleId, req.accessToken);
    res.json(requests);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get friend requests' });
  }
});

// Send friend request
app.post('/api/social/friends/request', socialAuth, async (req, res) => {
  try {
    const { targetUserId } = req.body;
    const profile = await social.getProfile(req.googleId, req.accessToken);

    // Get target user's access token from cache
    const targetProfile = social.userProfiles.get(targetUserId);
    if (!targetProfile) {
      return res.status(404).json({ error: 'User not found or not online' });
    }

    await social.sendFriendRequest(
      req.googleId,
      profile.displayName,
      profile.avatarUrl,
      targetUserId,
      targetProfile.accessToken
    );
    res.json({ success: true });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Accept friend request
app.post('/api/social/friends/accept', socialAuth, async (req, res) => {
  try {
    const { fromUserId } = req.body;
    await social.acceptFriendRequest(req.googleId, req.accessToken, fromUserId);
    res.json({ success: true });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Reject friend request
app.post('/api/social/friends/reject', socialAuth, async (req, res) => {
  try {
    const { fromUserId } = req.body;
    await social.rejectFriendRequest(req.googleId, req.accessToken, fromUserId);
    res.json({ success: true });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Remove friend
app.delete('/api/social/friends/:friendId', socialAuth, async (req, res) => {
  try {
    await social.removeFriend(req.googleId, req.accessToken, req.params.friendId);
    res.json({ success: true });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Log activity
app.post('/api/social/activity', socialAuth, async (req, res) => {
  try {
    const activity = await social.logActivity(req.googleId, req.accessToken, req.body);
    res.json(activity);
  } catch (error) {
    res.status(500).json({ error: 'Failed to log activity' });
  }
});

// Get own activity
app.get('/api/social/activity', socialAuth, async (req, res) => {
  try {
    const activities = await social.getActivity(req.googleId, req.accessToken);
    res.json(activities);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get activity' });
  }
});

// Get friends' activity feed
app.get('/api/social/activity/feed', socialAuth, async (req, res) => {
  try {
    const { contentType, genre, userId, page, pageSize } = req.query;
    const feed = await social.getFriendsActivity(req.googleId, req.accessToken, {
      contentType,
      genre,
      userId,
      page: parsePositiveInt(page, 1),
      pageSize: Math.min(parsePositiveInt(pageSize, 50), 100)
    });
    res.json(feed);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get activity feed' });
  }
});

// Get available genres for activity filtering
app.get('/api/social/activity/genres', socialAuth, async (req, res) => {
  try {
    if (!database.isConnected()) {
      return res.json({ genres: [] });
    }

    const friends = await database.getFriends(req.googleId);
    const friendIds = friends.map((friend) => friend.id).filter(Boolean);

    if (friendIds.length === 0) {
      return res.json({ genres: [] });
    }

    const genres = await database.getGenresFromActivities(req.googleId, friendIds);
    return res.json({ genres });
  } catch (error) {
    console.error('[Social API] Failed to get activity genres:', error);
    return res.status(500).json({ error: 'Failed to get activity genres' });
  }
});

// Sync stats from local app
app.post('/api/social/stats/sync', socialAuth, async (req, res) => {
  try {
    const profile = await social.updateStats(req.googleId, req.accessToken, req.body);
    res.json(profile?.stats || {});
  } catch (error) {
    res.status(500).json({ error: 'Failed to sync stats' });
  }
});

// Get friends currently watching
app.get('/api/social/watching', socialAuth, async (req, res) => {
  try {
    const watching = await social.getFriendsCurrentlyWatching(req.googleId, req.accessToken);
    res.json(watching);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get watching status' });
  }
});

// Get chat history
app.get('/api/social/chat/:friendId', socialAuth, async (req, res) => {
  try {
    const messages = await social.loadChatHistory(req.googleId, req.accessToken, req.params.friendId);
    res.json(messages);
  } catch (error) {
    res.status(500).json({ error: 'Failed to load chat history' });
  }
});

// Get unread chat counts
app.get('/api/social/chat/unread/count', socialAuth, async (req, res) => {
  try {
    if (!database.isConnected()) {
      return res.json({
        totalUnread: 0,
        unreadByUser: {},
        lastMessageAtByUser: {}
      });
    }

    const [totalUnread, unreadUsers] = await Promise.all([
      database.getUnreadCount(req.googleId),
      database.getUsersWithUnreadMessages(req.googleId)
    ]);

    const unreadByUser = {};
    const lastMessageAtByUser = {};

    for (const row of unreadUsers) {
      if (!row?.senderId) continue;
      unreadByUser[row.senderId] = Number(row.count) || 0;
      lastMessageAtByUser[row.senderId] = Number(row.lastMessageAt) || 0;
    }

    return res.json({
      totalUnread,
      unreadByUser,
      lastMessageAtByUser
    });
  } catch (error) {
    console.error('[Social API] Failed to get unread chat counts:', error);
    return res.status(500).json({ error: 'Failed to get unread chat counts' });
  }
});

// Mark chat messages from a friend as read
app.post('/api/social/chat/:friendId/read', socialAuth, async (req, res) => {
  try {
    const marked = await social.markChatMessagesAsRead(req.googleId, req.params.friendId);
    return res.json({ success: true, marked });
  } catch (error) {
    console.error('[Social API] Failed to mark messages as read:', error);
    return res.status(500).json({ error: 'Failed to mark messages as read' });
  }
});

// Send direct message to friend (HTTP fallback + durable write path)
app.post('/api/social/chat/:friendId', socialAuth, async (req, res) => {
  try {
    const friendId = (req.params.friendId || '').trim();
    const text = typeof req.body?.text === 'string' ? req.body.text : '';

    if (!friendId) {
      return res.status(400).json({ error: 'Missing friendId' });
    }

    const savedMessage = await social.saveChatMessage(req.googleId, req.accessToken, friendId, { text });
    if (!savedMessage) {
      return res.status(500).json({ error: 'Failed to save message' });
    }

    social.emitRealtimeChatDelivery(req.googleId, friendId, savedMessage, {
      emitToSender: false
    });

    return res.json({ success: true, message: savedMessage, friendId });
  } catch (error) {
    const message = String(error?.message || '');
    if (message.includes('Can only message friends') || message.includes('Message cannot be empty')) {
      return res.status(400).json({ error: message });
    }
    return res.status(500).json({ error: 'Failed to send message' });
  }
});

// Create a new Watch Together room
app.post('/api/watchtogether/rooms', async (req, res) => {
  try {
    const { media_id, media_title, media_match_key, host_nickname } = req.body;

    if (!media_id || !media_title || !host_nickname) {
      return res.status(400).json({ error: 'media_id, media_title, and host_nickname required' });
    }

    const code = await generateUniqueRoomCode();
    const hostId = uuidv4();
    const now = Date.now();
    const room = {
      code,
      media_id,
      media_title,
      media_match_key: normalizeMediaMatchKey(media_match_key),
      host_id: hostId,
      state: 'waiting',
      current_position: 0,
      is_paused: true,
      position_updated_at: now,
      sync_mode: WT_SYNC_MODE,
      participants: new Map(),
      created_at: now,
      lastActivity: now,
      last_sync_from: hostId,
      last_sync_at: now,
      syncInterval: null,
      pingInterval: null,
    };

    room.participants.set(hostId, {
      id: hostId,
      nickname: host_nickname,
      is_host: true,
      is_ready: false,
      joined_at: now,
      ws: null,
      rtt: 0,
      rttAvg: 0,
      lastPosition: 0,
      lastPaused: true,
      lastStateReport: now,
      disconnectTimer: null,
      disconnected_at: null,
    });

    rooms.set(code, room);
    await persistRoomState(room);
    await syncRoomParticipantsInRedis(room);
    await logRoomEvent(code, {
      type: 'room_created',
      host_id: hostId,
      host_nickname,
      media_title
    });

    wtDebugLog(`[WT] Room created: ${code} by ${host_nickname}`);

    return res.json({
      code,
      host_id: hostId,
      media_id,
      media_title,
      participants: [{
        id: hostId,
        nickname: host_nickname,
        is_host: true,
        is_ready: false
      }]
    });
  } catch (error) {
    console.error('[WT] Failed to create room:', error);
    return res.status(500).json({ error: 'Failed to create room' });
  }
});

// Get room info
app.get('/api/watchtogether/rooms/:code', async (req, res) => {
  const { code } = req.params;
  const normalizedCode = code.toUpperCase();
  let room = rooms.get(normalizedCode);

  if (!room && redis.isConnected()) {
    const persistedRoom = await redis.getRoomState(normalizedCode);
    if (persistedRoom) {
      room = hydrateRecoveredRoom(persistedRoom);
      rooms.set(normalizedCode, room);
      startRoomSyncTimers(room);
    }
  }

  if (!room) {
    return res.status(404).json({ error: 'Room not found' });
  }

  const currentPosition = getServerPosition(room);
  res.json({
    code: room.code,
    media_id: room.media_id,
    media_title: room.media_title,
    host_id: room.host_id,
    state: room.state,
    is_playing: room.state === 'playing',
    current_position: currentPosition,
    participants: Array.from(room.participants.values()).map(p => ({
      id: p.id,
      nickname: p.nickname,
      is_host: p.is_host,
      is_ready: p.is_ready
    }))
  });
});

// Delete/close a room
app.delete('/api/watchtogether/rooms/:code', async (req, res) => {
  const { code } = req.params;
  const normalizedCode = code.toUpperCase();
  const room = rooms.get(normalizedCode);

  if (!room) {
    await deletePersistedRoom(normalizedCode);
    return res.status(404).json({ error: 'Room not found' });
  }

  // Close all WebSocket connections
  for (const participant of room.participants.values()) {
    if (participant.ws && participant.ws.readyState === 1) {
      participant.ws.close(1000, 'Room closed');
    }
  }

  stopRoomSyncTimers(room);
  rooms.delete(normalizedCode);
  await deletePersistedRoom(normalizedCode);
  wtDebugLog(`[WT] Room deleted: ${code}`);

  res.json({ success: true });
});

function redirectToGoogleAuth(req, res, scopes) {
  const redirectUri = getRedirectUri(req);
  const state = req.query.state || 'default';

  // Check if credentials are configured
  if (!GOOGLE_CLIENT_ID) {
    return res.status(500).json({ error: 'GOOGLE_CLIENT_ID not configured' });
  }

  const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  authUrl.searchParams.set('client_id', GOOGLE_CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', scopes);
  authUrl.searchParams.set('access_type', 'offline');
  authUrl.searchParams.set('prompt', 'consent');
  authUrl.searchParams.set('state', state);

  wtDebugLog('Redirecting to Google with redirect_uri:', redirectUri);
  return res.redirect(authUrl.toString());
}

// Step 1: Initiate OAuth flow for Drive-enabled app auth
app.get('/auth/google', (req, res) => {
  return redirectToGoogleAuth(req, res, DRIVE_SCOPES);
});

// Step 1b: Initiate OAuth flow for Social-only auth
app.get('/auth/google/social', (req, res) => {
  return redirectToGoogleAuth(req, res, SOCIAL_SCOPES);
});

// Step 2: Handle Google callback
app.get('/auth/callback', async (req, res) => {
  const redirectUri = getRedirectUri(req);
  const { code, error } = req.query;

  if (error) {
    return res.redirect(`http://localhost:8085/callback?error=${encodeURIComponent(error)}`);
  }

  if (!code) {
    return res.redirect(`http://localhost:8085/callback?error=no_code`);
  }

  try {
    // Exchange code for tokens
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        code: code,
        grant_type: 'authorization_code',
        redirect_uri: redirectUri,
      }),
    });

    const tokens = await tokenResponse.json();

    if (tokens.error) {
      console.error('Token error from Google OAuth:', {
        error: tokens.error,
        error_description: tokens.error_description,
      });
      return res.redirect(`http://localhost:8085/callback?error=${encodeURIComponent(tokens.error_description || tokens.error)}`);
    }

    // Encode tokens as base64 to pass via URL safely
    const tokenData = Buffer.from(JSON.stringify({
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
      expires_in: tokens.expires_in,
      token_type: tokens.token_type,
    })).toString('base64');

    // Redirect to app's localhost callback with tokens
    res.redirect(`http://localhost:8085/callback?tokens=${tokenData}`);

  } catch (err) {
    console.error('Token exchange error:', err);
    res.redirect(`http://localhost:8085/callback?error=token_exchange_failed`);
  }
});

// Step 3: Refresh token endpoint (called directly by app)
app.post('/auth/refresh', async (req, res) => {
  const { refresh_token } = req.body;

  if (!refresh_token) {
    return res.status(400).json({ error: 'refresh_token required' });
  }

  try {
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        refresh_token: refresh_token,
        grant_type: 'refresh_token',
      }),
    });

    const tokens = await tokenResponse.json();

    if (tokens.error) {
      return res.status(400).json({ error: tokens.error });
    }

    res.json({
      access_token: tokens.access_token,
      expires_in: tokens.expires_in,
      token_type: tokens.token_type,
    });

  } catch (err) {
    console.error('Refresh error:', err);
    res.status(500).json({ error: 'refresh_failed' });
  }
});

// ============================================
// HTTP Server & WebSocket Setup
// ============================================

const server = http.createServer(app);

// WebSocket server for Watch Together
const wss = new WebSocketServer({
  noServer: true,
  perMessageDeflate: false
});

// WebSocket server for Social features
const socialWss = new WebSocketServer({
  noServer: true,
  perMessageDeflate: false
});

// Route all upgrade requests manually so only one WebSocketServer handles each socket.
// Having multiple `WebSocketServer({ server, path })` listeners can cause the non-matching
// listener to write an HTTP 400 on an already-upgraded connection.
server.on('upgrade', (req, socket, head) => {
  let pathname = '';
  try {
    pathname = new URL(req.url, `http://${req.headers.host || 'localhost'}`).pathname;
  } catch {
    pathname = req.url?.split('?')[0] || '';
  }

  if (pathname === '/ws/social') {
    socialWss.handleUpgrade(req, socket, head, (ws) => {
      socialWss.emit('connection', ws, req);
    });
    return;
  }

  if (pathname === '/ws/watchtogether' || pathname.startsWith('/ws/watchtogether/')) {
    wss.handleUpgrade(req, socket, head, (ws) => {
      wss.emit('connection', ws, req);
    });
    return;
  }

  socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
  socket.destroy();
});

socialWss.on('connection', async (ws, req) => {
  // Extract access token from query string
  const url = new URL(req.url, `http://${req.headers.host}`);
  const accessToken = url.searchParams.get('token');

  if (!accessToken) {
    ws.close(1008, 'Missing access token');
    return;
  }

  try {
    const userInfo = await resolveGoogleUserFromAccessToken(accessToken);
    if (!userInfo) {
      ws.close(1008, 'Invalid access token');
      return;
    }

    const googleId = userInfo.id;

    wtDebugLog(`[Social WS] User connected: ${userInfo.email}`);

    // Initialize social profile if not exists
    await social.initUserSocial(googleId, accessToken, userInfo);

    // Handle social WebSocket connection
    social.handleSocialConnection(ws, googleId, accessToken);

  } catch (error) {
    console.error('[Social WS] Connection error:', error);
    ws.close(1011, 'Server error');
  }
});

wss.on('connection', (ws, req) => {
  // Extract room code from URL: /ws/watchtogether/ROOMCODE or just /ws/watchtogether for create
  const urlParts = req.url.split('/');
  let roomCode = urlParts[urlParts.length - 1]?.split('?')[0]?.toUpperCase();

  // If roomCode is "watchtogether", it means no room code was provided (creating new room)
  if (roomCode === 'WATCHTOGETHER' || roomCode === '') {
    roomCode = null;
  }

  let participantId = null;
  let currentRoom = null;

  wtDebugLog(`[WT] WebSocket connection, room code: ${roomCode || 'none (will create)'}`);

  ws.on('message', async (data) => {
    try {
      const message = JSON.parse(data.toString());

      // Handle room creation first (no room code needed)
      if (message.type === 'create') {
        const { media_title, media_id, media_match_key, nickname, client_id } = message;

        if (!media_id || !media_title || !nickname) {
          ws.send(JSON.stringify({ type: 'error', message: 'media_id, media_title, and nickname required' }));
          return;
        }

        const newCode = await generateUniqueRoomCode();
        const hostId = client_id || uuidv4();
        const now = Date.now();
        const room = {
          code: newCode,
          media_id,
          media_title,
          media_match_key: normalizeMediaMatchKey(media_match_key),
          host_id: hostId,
          state: 'waiting',
          current_position: 0,
          is_paused: true,
          position_updated_at: now, // Track when position was last set
          sync_mode: WT_SYNC_MODE,
          participants: new Map(),
          created_at: now,
          lastActivity: now,
          last_sync_from: hostId,
          last_sync_at: now,
          syncInterval: null, // Will hold the periodic state broadcast timer
          pingInterval: null, // Will hold the periodic ping timer
        };

        // Add host as first participant
        room.participants.set(hostId, {
          id: hostId,
          nickname: nickname,
          is_host: true,
          is_ready: false,
          joined_at: now,
          ws: ws,
          rtt: 0, // Round-trip time in ms
          rttAvg: 0, // Smoothed RTT (moving average)
          lastPosition: 0, // Last reported position
          lastPaused: true, // Last reported pause state
          lastStateReport: now,
          disconnectTimer: null,
          disconnected_at: null,
        });

        // Start periodic ping + state broadcast for this room
        startRoomSyncTimers(room);

        rooms.set(newCode, room);
        roomCode = newCode;
        currentRoom = room;
        participantId = hostId;

        await persistRoomState(room);
        await syncRoomParticipantsInRedis(room);
        await logRoomEvent(newCode, {
          type: 'room_created',
          host_id: hostId,
          nickname,
          media_title
        });

        wtDebugLog(`[WT] Room created via WebSocket: ${newCode} by ${nickname}`);

        // Send room_created response
        ws.send(JSON.stringify({
          type: 'room_created',
          room: {
            code: newCode,
            host_id: hostId,
            media_id,
            media_title,
            is_playing: false,
            current_position: 0,
            participants: [{
              id: hostId,
              nickname: nickname,
              is_host: true,
              is_ready: false
            }]
          }
        }));
        return;
      }

      // For other messages, we need a room
      let room = roomCode ? rooms.get(roomCode) : currentRoom;

      if (!room && message.type === 'join') {
        // Try to get room from message
        const joinRoomCode = message.room_code?.toUpperCase();
        if (joinRoomCode) {
          room = rooms.get(joinRoomCode);
          roomCode = joinRoomCode;
        }
      }

      if (!room && roomCode && redis.isConnected()) {
        const persistedRoom = await redis.getRoomState(roomCode);
        if (persistedRoom) {
          room = hydrateRecoveredRoom(persistedRoom);
          rooms.set(roomCode, room);
          startRoomSyncTimers(room);
        }
      }

      if (!room) {
        ws.send(JSON.stringify({ type: 'error', message: 'Room not found' }));
        return;
      }

      room.lastActivity = Date.now();
      currentRoom = room;

      switch (message.type) {
        case 'join': {
          // Join room with nickname and client_id
          const { nickname, client_id, media_id, media_title, media_match_key } = message;
          const normalizedNickname = (nickname || '').toString().trim();

          if (!client_id || !normalizedNickname) {
            ws.send(JSON.stringify({ type: 'error', message: 'client_id and nickname are required to join' }));
            break;
          }

          // Enforce media compatibility for consistent sync.
          // Prefer explicit match keys (cloud_file_id, file name, tmdb, title tokens), then title, then legacy media_id.
          const hasMatchingKey = hasMatchingMediaKey(room.media_match_key, media_match_key);
          const normalizedRoomTitle = (room.media_title || '').toString().trim().toLowerCase();
          const normalizedJoinTitle = (media_title || '').toString().trim().toLowerCase();

          if (hasMatchingKey !== null) {
            if (!hasMatchingKey) {
              ws.send(JSON.stringify({
                type: 'error',
                message: `This room is watching a different media item ("${room.media_title}", room media_id: ${room.media_id})`
              }));
              break;
            }
          } else if (normalizedRoomTitle && normalizedJoinTitle) {
            if (normalizedJoinTitle !== normalizedRoomTitle) {
              ws.send(JSON.stringify({
                type: 'error',
                message: `This room is watching a different media item ("${room.media_title}", room media_id: ${room.media_id})`
              }));
              break;
            }
          } else if (media_id !== undefined && Number(media_id) !== Number(room.media_id)) {
            // Backward compatibility for clients that don't send media_title.
            ws.send(JSON.stringify({
              type: 'error',
              message: `This room is watching a different media item (room media_id: ${room.media_id})`
            }));
            break;
          }

          // Check if this is an existing participant reconnecting
          let participant = room.participants.get(client_id);
          let isReconnect = false;

          if (participant) {
            // Reconnecting
            isReconnect = true;
            if (participant.disconnectTimer) {
              clearTimeout(participant.disconnectTimer);
              participant.disconnectTimer = null;
            }
            participant.disconnected_at = null;
            participant.ws = ws;
            participant.nickname = normalizedNickname;
            participantId = client_id;
          } else {
            // New participant
            participantId = client_id || uuidv4();
            participant = {
              id: participantId,
              nickname: normalizedNickname,
              is_host: false,
              is_ready: false,
              joined_at: Date.now(),
              media_id: media_id,
              ws,
              rtt: 0,
              rttAvg: 0,
              lastPosition: 0,
              lastPaused: true,
              lastStateReport: Date.now(),
              disconnectTimer: null,
              disconnected_at: null,
            };
            room.participants.set(participantId, participant);
          }

          currentRoom = room;
          room.lastActivity = Date.now();

          wtDebugLog(`[WT] ${participant.nickname} ${isReconnect ? 'reconnected to' : 'joined'} room ${room.code}`);

          const currentPosition = getServerPosition(room);

          // Send room_joined response to the joining participant
          ws.send(JSON.stringify({
            type: 'room_joined',
            room: {
              code: room.code,
              media_id: room.media_id,
              media_title: room.media_title,
              host_id: room.host_id,
              is_playing: room.state === 'playing',
              current_position: currentPosition,
              participants: Array.from(room.participants.values()).map(p => ({
                id: p.id,
                nickname: p.nickname,
                is_host: p.is_host,
                is_ready: p.is_ready
              }))
            }
          }));

          if (isReconnect) {
            // Send a full room snapshot so clients reflect host/ready state correctly
            broadcastToRoom(room, {
              type: 'room_state',
              room: getRoomState(room)
            });
          } else {
            // Notify others about a new participant
            broadcastToRoom(room, {
              type: 'participant_joined',
              participant: {
                id: participantId,
                nickname: participant.nickname,
                is_host: participant.is_host,
                is_ready: participant.is_ready
              }
            }, participantId);
          }

          await persistRoomState(room);
          await syncRoomParticipantsInRedis(room);
          await logRoomEvent(room.code, {
            type: isReconnect ? 'participant_reconnected' : 'participant_joined',
            participant_id: participantId,
            nickname: participant.nickname
          });
          break;
        }

        case 'ready': {
          // Participant is ready to start
          const participant = room.participants.get(participantId);
          if (participant) {
            room.lastActivity = Date.now();
            participant.is_ready = true;
            if (message.duration !== undefined && message.duration !== null) {
              participant.duration = message.duration;
            }

            wtDebugLog(`[WT] ${participant.nickname} is ready in room ${room.code}`);

            // Broadcast to all including sender
            broadcastToRoom(room, {
              type: 'participant_ready',
              participant_id: participantId,
              duration: message.duration || 0
            });

            // Also send updated room state
            broadcastToRoom(room, {
              type: 'room_state',
              room: getRoomState(room)
            });

            await persistRoomState(room);
            await syncRoomParticipantsInRedis(room);
            await logRoomEvent(room.code, {
              type: 'participant_ready',
              participant_id: participantId,
              duration: message.duration || 0
            });
          }
          break;
        }

        case 'start':
        case 'start_playback': {
          // Only host can start playback
          const participant = room.participants.get(participantId);
          if (!participant || !participant.is_host) {
            ws.send(JSON.stringify({ type: 'error', message: 'Only the host can start playback' }));
            break;
          }

          const allReady = Array.from(room.participants.values()).every(p => p.is_ready);
          if (!allReady) {
            ws.send(JSON.stringify({ type: 'error', message: 'Cannot start until all participants are ready' }));
            break;
          }

          if (participant && participant.is_host) {
            const now = Date.now();
            room.state = 'playing';
            room.is_paused = false;
            room.current_position = normalizeSyncPosition(message.position, 0);
            room.position_updated_at = now;
            room.lastActivity = now;
            room.last_sync_from = participantId;
            room.last_sync_at = now;
            participant.lastPosition = room.current_position;
            participant.lastPaused = false;
            participant.lastStateReport = now;

            wtDebugLog(`[WT] Playback started in room ${room.code}`);

            broadcastToRoom(room, {
              type: 'playback_started',
              position: room.current_position,
              timestamp: now
            });

            await persistRoomState(room);
            await logRoomEvent(room.code, {
              type: 'playback_started',
              participant_id: participantId,
              position: room.current_position
            });
          }
          break;
        }

        case 'sync': {
          // Sync command from a participant (play/pause/seek)
          const { command } = message;
          if (!command) break;
          const participant = room.participants.get(participantId);

          if (!participant) break;
          if (room.sync_mode === 'host_only' && !participant.is_host) {
            // Ignore non-host sync attempts in host-only mode
            break;
          }

          const normalizedAction = normalizeSyncAction(command.action);
          if (!normalizedAction) {
            break;
          }

          const now = Date.now();
          const commandPosition = normalizeSyncPosition(command.position, getServerPosition(room));
          const normalizedCommand = {
            ...command,
            action: normalizedAction,
            position: commandPosition,
          };

          room.current_position = commandPosition;
          room.position_updated_at = now;
          room.lastActivity = now;
          room.last_sync_from = participantId;
          room.last_sync_at = now;

          if (normalizedAction === 'play') {
            room.state = 'playing';
            room.is_paused = false;
            participant.lastPaused = false;
          } else if (normalizedAction === 'pause') {
            room.state = 'paused';
            room.is_paused = true;
            participant.lastPaused = true;
          }
          participant.lastPosition = commandPosition;
          participant.lastStateReport = now;

          // Broadcast to ALL participants (including sender with a flag)
          // Each client uses ignoringOnTheFly to suppress echo
          for (const [id, p] of room.participants) {
            if (p.ws && p.ws.readyState === 1) {
              const msg = {
                type: 'sync',
                command: normalizedCommand,
                from: participantId,
                timestamp: now,
                is_echo: id === participantId, // Let sender know this is their own echo
              };
              p.ws.send(JSON.stringify(msg));
            }
          }

          await persistRoomState(room);
          await logRoomEvent(room.code, {
            type: 'sync',
            participant_id: participantId,
            action: normalizedAction,
            position: commandPosition
          });
          break;
        }

        case 'state_report': {
          // Continuous state report from client (sent every ~1s)
          // This is the Syncplay-style "State" message
          const participant = room.participants.get(participantId);
          if (participant) {
            const now = Date.now();
            room.lastActivity = now;
            const reportPosition = Number(message.position);
            const hasPosition = Number.isFinite(reportPosition);
            const normalizedPosition = hasPosition
              ? normalizeSyncPosition(reportPosition, participant.lastPosition)
              : participant.lastPosition;
            const reportPaused = message.paused !== undefined ? !!message.paused : participant.lastPaused;

            participant.lastPosition = normalizedPosition;
            participant.lastPaused = reportPaused;
            participant.lastStateReport = now;

            if ((room.state === 'playing' || room.state === 'paused')
              && canParticipantDriveRoomState(room, participantId, participant, now)) {
              const serverPos = getServerPosition(room);
              const drift = Math.abs(serverPos - normalizedPosition);
              if (drift > STATE_REPORT_CORRECTION_THRESHOLD || room.is_paused !== reportPaused) {
                room.current_position = normalizedPosition;
                room.position_updated_at = now;
                room.is_paused = reportPaused;
                room.state = reportPaused ? 'paused' : 'playing';
                await persistRoomState(room);
              }
            }
          }
          break;
        }

        case 'ping': {
          // RTT measurement - client sends ping, server responds with pong
          const participant = room.participants.get(participantId);
          if (participant) {
            ws.send(JSON.stringify({
              type: 'pong',
              ping_id: message.ping_id,
              server_time: Date.now(),
              // Include the sender's last known RTT so other clients can use it
              your_rtt: participant.rttAvg,
            }));
          }
          break;
        }

        case 'pong_report': {
          // Client reports its measured RTT after receiving pong
          const participant = room.participants.get(participantId);
          if (participant && message.rtt !== undefined) {
            participant.rtt = message.rtt;
            // Moving average RTT (Syncplay-style)
            if (participant.rttAvg === 0) {
              participant.rttAvg = message.rtt;
            } else {
              participant.rttAvg = participant.rttAvg * PING_MOVING_AVG_WEIGHT
                + message.rtt * (1 - PING_MOVING_AVG_WEIGHT);
            }
          }
          break;
        }

        case 'heartbeat': {
          // Update last activity and optionally sync position
          room.lastActivity = Date.now();
          if (message.position !== undefined) {
            const participant = room.participants.get(participantId);
            if (participant) {
              participant.lastPosition = message.position;
            }
          }
          ws.send(JSON.stringify({ type: 'heartbeat_ack', timestamp: Date.now() }));
          break;
        }

        case 'leave': {
          await handleParticipantLeave(room, participantId);
          break;
        }

        default:
          wtDebugLog(`[WT] Unknown message type: ${message.type}`);
      }
    } catch (err) {
      console.error('[WT] Message parse error:', err);
      ws.send(JSON.stringify({ type: 'error', message: 'Invalid message format' }));
    }
  });

  ws.on('close', async () => {
    wtDebugLog(`[WT] WebSocket closed for participant: ${participantId}`);
    if (currentRoom && participantId) {
      await handleSocketClose(currentRoom, participantId, ws);
    }
  });

  ws.on('error', (err) => {
    console.error('[WT] WebSocket error:', err);
  });
});

// Compute the server's authoritative position by advancing from last known position
function getServerPosition(room) {
  if (room.is_paused || room.state !== 'playing') {
    return room.current_position;
  }
  const elapsed = (Date.now() - room.position_updated_at) / 1000.0;
  return room.current_position + elapsed;
}

// Start periodic sync timers for a room
function startRoomSyncTimers(room) {
  // Clear existing timers if any
  if (room.syncInterval) clearInterval(room.syncInterval);
  if (room.pingInterval) clearInterval(room.pingInterval);

  // Periodic state broadcast: send each client the authoritative position
  // adjusted for their individual RTT (Syncplay-style forward delay)
  room.syncInterval = setInterval(() => {
    if (room.state !== 'playing' && room.state !== 'paused') return;

    const serverPos = getServerPosition(room);
    const now = Date.now();

    for (const [id, participant] of room.participants) {
      if (!participant.ws || participant.ws.readyState !== 1) continue;

      // Calculate forward delay: how far ahead this client should be
      // to compensate for network latency (RTT/2 = one-way delay)
      const forwardDelay = participant.rttAvg / 2000.0; // Convert ms to seconds

      const msg = {
        type: 'state_update',
        position: serverPos + forwardDelay, // Compensate for delivery delay
        paused: room.is_paused,
        server_time: now,
        your_rtt: participant.rttAvg,
        // Include all participants' positions for OSD display
        participants: Array.from(room.participants.values()).map(p => ({
          id: p.id,
          nickname: p.nickname,
          position: p.lastPosition,
          paused: p.lastPaused,
          rtt: Math.round(p.rttAvg),
        })),
      };
      participant.ws.send(JSON.stringify(msg));
    }

    // Advance the server's stored position
    room.current_position = serverPos;
    room.position_updated_at = now;
  }, SYNC_BROADCAST_INTERVAL);

  // Periodic ping for RTT measurement
  room.pingInterval = setInterval(() => {
    const now = Date.now();
    for (const [id, participant] of room.participants) {
      if (!participant.ws || participant.ws.readyState !== 1) continue;

      const pingId = `${id}-${now}`;
      participant.ws.send(JSON.stringify({
        type: 'ping',
        ping_id: pingId,
        server_time: now,
      }));
    }
  }, PING_INTERVAL);
}

// Stop sync timers for a room
function stopRoomSyncTimers(room) {
  if (room.syncInterval) {
    clearInterval(room.syncInterval);
    room.syncInterval = null;
  }
  if (room.pingInterval) {
    clearInterval(room.pingInterval);
    room.pingInterval = null;
  }
  for (const participant of room.participants.values()) {
    if (participant.disconnectTimer) {
      clearTimeout(participant.disconnectTimer);
      participant.disconnectTimer = null;
    }
  }
}

async function handleSocketClose(room, participantId, ws) {
  const participant = room.participants.get(participantId);
  if (!participant) return;

  // If participant already reconnected with a newer socket, ignore stale close.
  if (participant.ws !== ws) {
    return;
  }

  participant.ws = null;
  participant.disconnected_at = Date.now();
  room.lastActivity = Date.now();

  if (participant.disconnectTimer) {
    clearTimeout(participant.disconnectTimer);
  }

  participant.disconnectTimer = setTimeout(() => {
    void handleParticipantLeave(room, participantId);
  }, DISCONNECT_GRACE_MS);

  await persistRoomState(room);
  await syncRoomParticipantsInRedis(room);
  await logRoomEvent(room.code, {
    type: 'participant_disconnected',
    participant_id: participantId,
    nickname: participant.nickname
  });
}

async function handleParticipantLeave(room, participantId) {
  const participant = room.participants.get(participantId);
  if (!participant) return;

  if (participant.disconnectTimer) {
    clearTimeout(participant.disconnectTimer);
    participant.disconnectTimer = null;
  }

  const wasHost = participant.is_host;
  const previousHostId = room.host_id;
  room.participants.delete(participantId);
  room.lastActivity = Date.now();
  if (room.last_sync_from === participantId) {
    room.last_sync_from = null;
    room.last_sync_at = Date.now();
  }

  wtDebugLog(`[WT] ${participant.nickname} left room ${room.code}`);

  // If host left, assign new host or close room
  if (wasHost && room.participants.size > 0) {
    const newHost = room.participants.values().next().value;
    newHost.is_host = true;
    room.host_id = newHost.id;
    if (!room.last_sync_from) {
      room.last_sync_from = newHost.id;
      room.last_sync_at = Date.now();
    }
    wtDebugLog(`[WT] New host: ${newHost.nickname}`);

    await logRoomEvent(room.code, {
      type: 'host_migrated',
      old_host_id: previousHostId,
      new_host_id: newHost.id,
      new_host_nickname: newHost.nickname
    });

    broadcastToRoom(room, {
      type: 'host_migrated',
      old_host_id: previousHostId,
      new_host_id: newHost.id,
      new_host_nickname: newHost.nickname,
      room: getRoomState(room)
    });
  }

  // If room is empty, delete it and stop timers
  if (room.participants.size === 0) {
    stopRoomSyncTimers(room);
    rooms.delete(room.code);
    await logRoomEvent(room.code, {
      type: 'room_deleted',
      reason: 'empty'
    });
    await deletePersistedRoom(room.code);
    wtDebugLog(`[WT] Room ${room.code} deleted (empty)`);
    return;
  }

  await removeRoomParticipantFromRedis(room.code, participantId);
  await persistRoomState(room);
  await syncRoomParticipantsInRedis(room);
  await logRoomEvent(room.code, {
    type: 'participant_left',
    participant_id: participantId,
    nickname: participant.nickname
  });

  // Notify remaining participants
  broadcastToRoom(room, {
    type: 'participant_left',
    participant_id: participantId,
    room: getRoomState(room)
  });
}

function broadcastToRoom(room, message, excludeId = null) {
  const data = JSON.stringify(message);
  for (const [id, participant] of room.participants) {
    if (id !== excludeId && participant.ws && participant.ws.readyState === 1) {
      participant.ws.send(data);
    }
  }
}

function getRoomState(room) {
  const currentPosition = getServerPosition(room);
  return {
    code: room.code,
    media_id: room.media_id,
    media_title: room.media_title,
    host_id: room.host_id,
    state: room.state,
    is_playing: room.state === 'playing',
    current_position: currentPosition,
    participants: Array.from(room.participants.values()).map(p => ({
      id: p.id,
      nickname: p.nickname,
      is_host: p.is_host,
      is_ready: p.is_ready
    }))
  };
}

// Start server
(async () => {
  // Initialize Turso database
  await database.initDatabase();
  redis.initRedis();
  await recoverRoomsFromRedis();

  server.listen(PORT, () => {
    console.log(`StreamVault Auth Server running on port ${PORT}`);
    console.log(`WebSocket endpoint: ws://localhost:${PORT}/ws/watchtogether/{roomCode}`);
    console.log(`Database connected: ${database.isConnected()}`);
    console.log(`Redis connected: ${redis.isConnected()}`);
    if (!RUNTIME_METRICS_PASSWORD) {
      console.warn('[SECURITY] Runtime metrics auth disabled until RUNTIME_METRICS_PASSWORD is configured');
    } else {
      console.log(`[SECURITY] Runtime metrics auth enabled (user: ${RUNTIME_METRICS_USERNAME})`);
      console.log(`[SECURITY] Runtime metrics rate limit: ${RUNTIME_RATE_MAX_REQUESTS} req / ${Math.floor(RUNTIME_RATE_WINDOW_MS / 1000)}s per IP`);
      console.log(`[SECURITY] Runtime metrics brute-force lock: ${RUNTIME_AUTH_MAX_FAILS} failed attempts in ${Math.floor(RUNTIME_AUTH_FAIL_WINDOW_MS / 1000)}s -> lock ${Math.floor(RUNTIME_AUTH_LOCK_MS / 1000)}s`);
    }
    console.log(`[TMDB] Credential pool size: ${tmdbCredentials.length} (max ${TMDB_MAX_KEYS})`);
    if (tmdbCredentials.length > 0) {
      console.log(`[TMDB] Loaded credential slots: ${tmdbCredentials.map((c) => `#${c.id}:${c.type}`).join(', ')}`);
      console.log(`[TMDB] Load balancer: least_inflight (max inflight per key: ${TMDB_MAX_INFLIGHT_PER_KEY || 'unlimited'})`);
      console.log(`[TMDB] Proxy logs enabled: ${TMDB_PROXY_LOGS_ENABLED} (debug: ${TMDB_PROXY_DEBUG_ENABLED})`);
    }
    if (tmdbCredentials.length === 0) {
      console.warn('[TMDB] No TMDB credentials configured. Set TMDB_ACCESS_TOKEN_1..5 or TMDB_ACCESS_TOKENS.');
    }

  });
})();
