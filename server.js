const express = require('express');
const cors = require('cors');
const http = require('http');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const social = require('./social');
const database = require('./database');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

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

// Scopes for Google Drive
const SCOPES = [
  'https://www.googleapis.com/auth/drive',
  'https://www.googleapis.com/auth/userinfo.email'
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
const AI_WRAPPER_URL = (process.env.AI_WRAPPER_URL || '').trim();
const AI_WRAPPER_TIMEOUT_MS = parsePositiveInt(process.env.AI_WRAPPER_TIMEOUT_MS, 30000);
const AI_WRAPPER_AUTH_HEADER = (process.env.AI_WRAPPER_AUTH_HEADER || 'Authorization').trim();
const AI_WRAPPER_AUTH_TOKEN = (process.env.AI_WRAPPER_AUTH_TOKEN || '').trim();
const AI_CLIENT_SIGNATURE_SECRET = (process.env.AI_CLIENT_SIGNATURE_SECRET || '').trim();
const AI_SIGNATURE_MAX_AGE_MS = parsePositiveInt(process.env.AI_SIGNATURE_MAX_AGE_MS, 5 * 60 * 1000);
const AI_NONCE_TTL_MS = parsePositiveInt(process.env.AI_NONCE_TTL_MS, AI_SIGNATURE_MAX_AGE_MS);
const AI_FREE_MAX_CHATS = parsePositiveInt(process.env.AI_FREE_MAX_CHATS, 10);
const AI_FREE_WINDOW_DAYS = parsePositiveInt(process.env.AI_FREE_WINDOW_DAYS, 7);
const AI_FREE_WINDOW_MS = AI_FREE_WINDOW_DAYS * 24 * 60 * 60 * 1000;
const AI_ALLOW_UNPERSISTED_LIMITS = process.env.AI_ALLOW_UNPERSISTED_LIMITS === '1';
const AI_ALLOWED_ORIGINS = new Set(splitEnvList(process.env.AI_ALLOWED_ORIGINS).map((origin) => origin.trim()).filter(Boolean));
const AI_OPENAI_COMPAT_MODE_RAW = (process.env.AI_OPENAI_COMPAT_MODE || '').trim();
const AI_OPENAI_COMPAT_MODE = AI_OPENAI_COMPAT_MODE_RAW === '1';
const AI_DEFAULT_MODEL = (process.env.AI_DEFAULT_MODEL || '').trim();
const AI_BRAND_NAME = (process.env.AI_BRAND_NAME || '').trim();
const AI_APP_DESCRIPTION = (process.env.AI_APP_DESCRIPTION || '').trim();
const AI_ADMIN_API_KEY = (process.env.AI_ADMIN_API_KEY || '').trim();
const AI_UPGRADE_APPROVED_MAX_CHATS = parsePositiveInt(
  process.env.AI_UPGRADE_APPROVED_MAX_CHATS,
  AI_FREE_MAX_CHATS * 2
);
const AI_UPGRADE_APPROVED_WINDOW_DAYS = parsePositiveInt(
  process.env.AI_UPGRADE_APPROVED_WINDOW_DAYS,
  Math.max(1, Math.floor(AI_FREE_WINDOW_DAYS / 2))
);
const AI_UPGRADE_APPROVED_DURATION_DAYS = parsePositiveInt(
  process.env.AI_UPGRADE_APPROVED_DURATION_DAYS,
  30
);
const AI_ADDITIONAL_REQUEST_MIN_WORDS = parsePositiveInt(
  process.env.AI_ADDITIONAL_REQUEST_MIN_WORDS,
  40
);
const AI_ADDITIONAL_REQUEST_MIN_CHARS = parsePositiveInt(
  process.env.AI_ADDITIONAL_REQUEST_MIN_CHARS,
  30
);
const AI_REJECTION_BAN_THRESHOLD = parsePositiveInt(
  process.env.AI_REJECTION_BAN_THRESHOLD,
  3
);
const AI_MOVIE_ONLY_HARDCODED = true;
const AI_MOVIE_WEBSEARCH_ENABLED = true;
const AI_MOVIE_WEB_CONTEXT_TIMEOUT_MS = parsePositiveInt(
  process.env.AI_MOVIE_WEB_CONTEXT_TIMEOUT_MS,
  12000
);
const AI_IMDB_FETCH_TIMEOUT_MS = parsePositiveInt(
  process.env.AI_IMDB_FETCH_TIMEOUT_MS,
  7000
);
const AI_USD_TO_INR_RATE = parsePositiveFloat(process.env.AI_USD_TO_INR_RATE, 83);
const AI_IST_TIMEZONE = 'Asia/Kolkata';
const WT_LIVE_LOGS_ENABLED = process.env.WT_LIVE_LOGS === '1';

const runtimeRateByIp = new Map();
const runtimeAuthByIp = new Map();
const aiNonceCache = new Map(); // nonce -> expiresAt
const aiQuotaFallback = new Map(); // fingerprintHash -> { windowStartMs, usedCount, updatedAt }
const tokenCache = new Map(); // accessToken -> { userInfo, expiresAt }
const TOKEN_CACHE_TTL = 5 * 60 * 1000; // 5 minutes
const TOKEN_CACHE_MAX_SIZE = 500;

function wtDebugLog(...args) {
  if (!WT_LIVE_LOGS_ENABLED) return;
  console.log(...args);
}

function getMissingAiConfig() {
  const missing = [];

  if (!AI_WRAPPER_URL) missing.push('AI_WRAPPER_URL');
  if (!AI_CLIENT_SIGNATURE_SECRET) missing.push('AI_CLIENT_SIGNATURE_SECRET');
  if (!AI_DEFAULT_MODEL) missing.push('AI_DEFAULT_MODEL');
  if (!AI_BRAND_NAME) missing.push('AI_BRAND_NAME');
  if (!AI_APP_DESCRIPTION) missing.push('AI_APP_DESCRIPTION');
  if (!['0', '1'].includes(AI_OPENAI_COMPAT_MODE_RAW)) {
    missing.push('AI_OPENAI_COMPAT_MODE');
  }

  return missing;
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

function createAiRequestId() {
  return `ai-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

function normalizeId(value, maxLen = 256) {
  if (typeof value !== 'string') return '';
  return value.trim().slice(0, maxLen);
}

function normalizeReasonText(value) {
  if (typeof value !== 'string') return '';
  return value
    .normalize('NFKC')
    .replace(/[\u200B-\u200D\uFEFF]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function countWords(value) {
  const normalized = normalizeReasonText(value);
  if (!normalized) return 0;
  const matches = normalized.match(/[\p{L}\p{N}]+(?:['’`-][\p{L}\p{N}]+)*/gu);
  return matches ? matches.length : 0;
}

function countDetailChars(value) {
  const normalized = normalizeReasonText(value);
  return normalized.length;
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

async function resolveOptionalAiGoogleId(req) {
  const accessToken = extractBearerToken(req);
  if (!accessToken) return null;
  const userInfo = await resolveGoogleUserFromAccessToken(accessToken);
  if (!userInfo || typeof userInfo.id !== 'string') return null;
  return userInfo.id;
}

function getAiFingerprint(req) {
  const sourceIp = getClientIp(req);
  const userAgent = normalizeId(req.headers['user-agent'] || '', 512);
  const deviceId = normalizeId(
    req.headers['x-device-id']
    || req.headers['x-hardware-id']
    || req.headers['x-installation-id']
    || '',
    256
  );
  const deviceSignature = normalizeId(
    req.headers['x-device-signature']
    || req.headers['x-client-signature']
    || '',
    256
  );
  const fingerprintMaterial = [
    `ip:${sourceIp}`,
    `device:${deviceId || 'none'}`,
    `signature:${deviceSignature || 'none'}`,
    `ua:${userAgent || 'none'}`
  ].join('|');

  return {
    sourceIp,
    fingerprintHash: hashSha256(fingerprintMaterial),
    hasDeviceId: !!deviceId,
    hasDeviceSignature: !!deviceSignature
  };
}

function addAiQuotaHeaders(res, quota, windowDays = AI_FREE_WINDOW_DAYS) {
  res.set('X-RateLimit-Limit', String(quota.limit));
  res.set('X-RateLimit-Remaining', String(quota.remaining));
  res.set('X-RateLimit-Reset', String(Math.ceil(quota.resetAt / 1000)));
  res.set('X-RateLimit-Window-Days', String(windowDays));
}

function consumeAiChatQuotaFallback(fingerprintHash, now, maxChats, windowMs) {
  const existing = aiQuotaFallback.get(fingerprintHash) || {
    windowStartMs: now,
    usedCount: 0,
    updatedAt: now,
  };

  const expired = now - existing.windowStartMs >= windowMs;
  if (expired) {
    existing.windowStartMs = now;
    existing.usedCount = 0;
  }

  existing.usedCount += 1;
  existing.updatedAt = now;
  aiQuotaFallback.set(fingerprintHash, existing);

  const allowed = existing.usedCount <= maxChats;
  const resetAt = existing.windowStartMs + windowMs;
  const clampedUsed = Math.min(existing.usedCount, maxChats);

  return {
    storageAvailable: true,
    allowed,
    limit: maxChats,
    used: clampedUsed,
    rawUsed: existing.usedCount,
    remaining: Math.max(0, maxChats - clampedUsed),
    windowStartMs: existing.windowStartMs,
    resetAt,
    retryAfterMs: allowed ? 0 : Math.max(1000, resetAt - now),
  };
}

function getAiChatQuotaFallback(fingerprintHash, now, maxChats, windowMs) {
  const existing = aiQuotaFallback.get(fingerprintHash);
  if (!existing || now - existing.windowStartMs >= windowMs) {
    return {
      storageAvailable: true,
      allowed: true,
      limit: maxChats,
      used: 0,
      rawUsed: 0,
      remaining: maxChats,
      windowStartMs: now,
      resetAt: now + windowMs,
      retryAfterMs: 0,
    };
  }

  const clampedUsed = Math.min(existing.usedCount, maxChats);
  const resetAt = existing.windowStartMs + windowMs;
  const allowed = existing.usedCount < maxChats;

  return {
    storageAvailable: true,
    allowed,
    limit: maxChats,
    used: clampedUsed,
    rawUsed: existing.usedCount,
    remaining: Math.max(0, maxChats - clampedUsed),
    windowStartMs: existing.windowStartMs,
    resetAt,
    retryAfterMs: allowed ? 0 : Math.max(1000, resetAt - now),
  };
}

async function consumeAiChatQuota(fingerprintHash, now, options = {}) {
  const maxChats = parsePositiveInt(options.maxChats, AI_FREE_MAX_CHATS);
  const windowMs = parsePositiveInt(options.windowMs, AI_FREE_WINDOW_MS);

  if (database.isConnected()) {
    return database.consumeAiChatQuota(fingerprintHash, {
      now,
      maxChats,
      windowMs,
    });
  }

  if (AI_ALLOW_UNPERSISTED_LIMITS) {
    return consumeAiChatQuotaFallback(fingerprintHash, now, maxChats, windowMs);
  }

  return {
    storageAvailable: false,
    allowed: false,
    error: 'AI quota storage unavailable',
  };
}

async function readAiChatQuota(fingerprintHash, now, options = {}) {
  const maxChats = parsePositiveInt(options.maxChats, AI_FREE_MAX_CHATS);
  const windowMs = parsePositiveInt(options.windowMs, AI_FREE_WINDOW_MS);

  if (database.isConnected()) {
    return database.getAiChatQuota(fingerprintHash, {
      now,
      maxChats,
      windowMs,
    });
  }

  if (AI_ALLOW_UNPERSISTED_LIMITS) {
    return getAiChatQuotaFallback(fingerprintHash, now, maxChats, windowMs);
  }

  return {
    storageAvailable: false,
    allowed: false,
    error: 'AI quota storage unavailable',
  };
}

function toWindowMsFromDays(windowDays) {
  const parsedDays = parsePositiveInt(windowDays, AI_FREE_WINDOW_DAYS);
  return parsedDays * 24 * 60 * 60 * 1000;
}

async function getAiPolicyForRequest(req, now) {
  const basePolicy = {
    googleId: null,
    maxChats: AI_FREE_MAX_CHATS,
    windowDays: AI_FREE_WINDOW_DAYS,
    windowMs: AI_FREE_WINDOW_MS,
    tier: 'free',
    entitlement: null,
    isBanned: false,
    ban: null,
    rejectedRequestCount: 0,
  };

  const googleId = await resolveOptionalAiGoogleId(req);
  if (!googleId) return basePolicy;

  basePolicy.googleId = googleId;
  if (!database.isConnected()) return basePolicy;

  const [entitlement, ban, rejectedRequestCount] = await Promise.all([
    database.getActiveAiEntitlement(googleId, { now }),
    database.getAiChatBan(googleId),
    database.countRejectedAiUpgradeRequests(googleId),
  ]);

  const isBanned = !!(ban && ban.isActive);
  basePolicy.isBanned = isBanned;
  basePolicy.ban = ban || null;
  basePolicy.rejectedRequestCount = Math.max(0, parsePositiveInt(rejectedRequestCount, 0));

  if (!entitlement) return basePolicy;

  const maxChats = parsePositiveInt(entitlement.maxChats, AI_FREE_MAX_CHATS);
  const windowDays = parsePositiveInt(entitlement.windowDays, AI_FREE_WINDOW_DAYS);

  return {
    googleId,
    maxChats,
    windowDays,
    windowMs: toWindowMsFromDays(windowDays),
    tier: 'upgraded',
    entitlement,
    isBanned,
    ban: ban || null,
    rejectedRequestCount: basePolicy.rejectedRequestCount,
  };
}

function isAllowedAiOrigin(req) {
  if (AI_ALLOWED_ORIGINS.size === 0) return true;
  const origin = req.headers.origin;
  if (!origin) return true; // Native clients may omit Origin.
  return AI_ALLOWED_ORIGINS.has(origin);
}

function buildAiSignatureBase(method, path, body, timestamp, nonce) {
  const normalizedMethod = String(method || 'POST').toUpperCase();
  const normalizedPath = String(path || '/api/ai/chat');
  const payload = body === undefined || body === null ? {} : body;
  const bodyHash = hashSha256(JSON.stringify(payload));
  return `${normalizedMethod}\n${normalizedPath}\n${timestamp}\n${nonce}\n${bodyHash}`;
}

function validateAiClientSignature(req, res, next) {
  const missingConfig = getMissingAiConfig();
  if (missingConfig.length > 0) {
    return res.status(503).json({ error: 'AI endpoint is not configured' });
  }
  if (!isAllowedAiOrigin(req)) {
    return res.status(403).json({ error: 'Origin is not allowed for AI endpoint' });
  }

  const requestId = createAiRequestId();
  const sourceIp = getClientIp(req);
  const now = Date.now();

  const timestampRaw = req.headers['x-ai-timestamp'];
  const nonceRaw = req.headers['x-ai-nonce'];
  const signatureRaw = normalizeId(req.headers['x-ai-signature'] || '', 128).toLowerCase();

  const timestamp = Number(timestampRaw);
  if (!Number.isFinite(timestamp)) {
    console.warn(`[SECURITY][${requestId}] Rejected AI request (invalid timestamp) from ${sourceIp}`);
    return res.status(401).json({ error: 'Invalid AI request signature' });
  }

  if (Math.abs(now - timestamp) > AI_SIGNATURE_MAX_AGE_MS) {
    console.warn(`[SECURITY][${requestId}] Rejected AI request (stale timestamp) from ${sourceIp}`);
    return res.status(401).json({ error: 'Expired AI request signature' });
  }

  const nonce = normalizeId(typeof nonceRaw === 'string' ? nonceRaw : '', 128);
  if (!nonce || !/^[a-zA-Z0-9:_-]{8,128}$/.test(nonce)) {
    console.warn(`[SECURITY][${requestId}] Rejected AI request (invalid nonce) from ${sourceIp}`);
    return res.status(401).json({ error: 'Invalid AI request signature' });
  }

  const nonceExpiresAt = aiNonceCache.get(nonce) || 0;
  if (nonceExpiresAt > now) {
    console.warn(`[SECURITY][${requestId}] Rejected AI request (replayed nonce) from ${sourceIp}`);
    return res.status(401).json({ error: 'Invalid AI request signature' });
  }

  if (!signatureRaw || !/^[a-f0-9]{64}$/.test(signatureRaw)) {
    console.warn(`[SECURITY][${requestId}] Rejected AI request (invalid signature format) from ${sourceIp}`);
    return res.status(401).json({ error: 'Invalid AI request signature' });
  }

  const signatureBase = buildAiSignatureBase(req.method, req.path, req.body, timestamp, nonce);
  const expectedSignature = crypto
    .createHmac('sha256', AI_CLIENT_SIGNATURE_SECRET)
    .update(signatureBase, 'utf8')
    .digest('hex');

  if (!secureTokenEqual(expectedSignature, signatureRaw)) {
    console.warn(`[SECURITY][${requestId}] Rejected AI request (signature mismatch) from ${sourceIp}`);
    return res.status(401).json({ error: 'Invalid AI request signature' });
  }

  aiNonceCache.set(nonce, now + AI_NONCE_TTL_MS);
  req.aiRequestId = requestId;
  req.aiSourceIp = sourceIp;
  return next();
}

function resolveAiUpstreamUrl(rawUrl) {
  const trimmed = String(rawUrl || '').trim();
  if (!trimmed) return '';
  if (!AI_OPENAI_COMPAT_MODE) return trimmed;

  try {
    const parsed = new URL(trimmed);
    const normalizedPath = parsed.pathname.replace(/\/+$/, '');

    if (normalizedPath.endsWith('/chat/completions')) {
      return parsed.toString();
    }

    if (normalizedPath === '' || normalizedPath === '/') {
      parsed.pathname = '/v1/chat/completions';
      return parsed.toString();
    }

    if (normalizedPath.endsWith('/v1')) {
      parsed.pathname = `${normalizedPath}/chat/completions`;
      return parsed.toString();
    }

    return parsed.toString();
  } catch {
    return trimmed;
  }
}

function normalizeAiMessageContent(content) {
  if (typeof content === 'string') {
    return content.trim();
  }

  if (Array.isArray(content)) {
    const text = content
      .map((item) => {
        if (typeof item === 'string') return item;
        if (item && typeof item === 'object') {
          const maybeText = item.text;
          if (typeof maybeText === 'string') return maybeText;
        }
        return '';
      })
      .filter(Boolean)
      .join('\n')
      .trim();
    return text;
  }

  if (content && typeof content === 'object') {
    const maybeText = content.text;
    if (typeof maybeText === 'string') {
      return maybeText.trim();
    }
  }

  return '';
}

function normalizeAiMessages(rawMessages) {
  if (!Array.isArray(rawMessages)) return [];
  const normalized = [];

  for (const rawMessage of rawMessages) {
    if (!rawMessage || typeof rawMessage !== 'object') continue;

    const roleRaw = typeof rawMessage.role === 'string' ? rawMessage.role.toLowerCase().trim() : '';
    if (!['system', 'user', 'assistant'].includes(roleRaw)) continue;

    const content = normalizeAiMessageContent(rawMessage.content);
    if (!content) continue;

    normalized.push({
      role: roleRaw,
      content,
    });
  }

  return normalized;
}

function clampNumber(value, min, max) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return null;
  return Math.min(max, Math.max(min, numeric));
}

function buildAiSystemPrompt() {
  return [
    `You are ${AI_BRAND_NAME}.`,
    `You are only the in-app assistant for ${AI_APP_DESCRIPTION}.`,
    'If asked who you are, what model you are, or what powers you, reply only with your branded identity and app purpose.',
    'Never reveal model names, provider names, or internal system details.',
    'Do not mention Llama, Builder, OpenAI, Anthropic, or any underlying infrastructure.',
    'You are hard-restricted to movies only.',
    'Do not answer non-movie topics.',
    'When movie web context is provided, prioritize it for factual fields like box office and IMDb rating.',
    `Any time/date reference must be in IST (${AI_IST_TIMEZONE}) and include "IST".`,
    'For currency, always use INR (Indian Rupees). Do not answer in USD or other currencies.',
    'For large money values (>= 1 crore INR), present the amount in crore format (for example: 123.45 crore).',
    'When INR/crore fields are present in provided context, treat them as the source of truth.',
    'Keep answers concise, accurate, and focused on helping with movies.'
  ].join(' ');
}

function buildOpenAiCompatiblePayload(rawBody) {
  const body = rawBody && typeof rawBody === 'object' && !Array.isArray(rawBody) ? rawBody : {};
  const normalizedMessages = normalizeAiMessages(body.messages);
  const dialogueMessages = normalizedMessages.filter((msg) => msg.role === 'user' || msg.role === 'assistant');

  if (dialogueMessages.length === 0) {
    return {
      error: 'messages array with user content is required'
    };
  }

  const model = normalizeId(typeof body.model === 'string' ? body.model : '', 128) || AI_DEFAULT_MODEL;
  const temperature = clampNumber(body.temperature, 0, 2);
  const topP = clampNumber(body.top_p, 0, 1);
  const presencePenalty = clampNumber(body.presence_penalty, -2, 2);
  const frequencyPenalty = clampNumber(body.frequency_penalty, -2, 2);
  const maxTokensRaw = Number(body.max_tokens ?? body.max_completion_tokens);
  const maxTokens = Number.isFinite(maxTokensRaw) && maxTokensRaw > 0 ? Math.floor(maxTokensRaw) : null;
  const user = normalizeId(typeof body.user === 'string' ? body.user : '', 128);

  const payload = {
    model,
    messages: [
      { role: 'system', content: buildAiSystemPrompt() },
      ...dialogueMessages
    ],
    stream: false,
  };

  if (temperature !== null) payload.temperature = temperature;
  if (topP !== null) payload.top_p = topP;
  if (presencePenalty !== null) payload.presence_penalty = presencePenalty;
  if (frequencyPenalty !== null) payload.frequency_penalty = frequencyPenalty;
  if (maxTokens !== null) payload.max_tokens = maxTokens;
  if (user) payload.user = user;

  return { payload };
}

function getLastUserMessageText(messages) {
  if (!Array.isArray(messages)) return '';
  for (let i = messages.length - 1; i >= 0; i--) {
    const item = messages[i];
    if (!item || typeof item !== 'object') continue;
    if (item.role !== 'user') continue;
    const content = normalizeAiMessageContent(item.content);
    if (content) return content;
  }
  return '';
}

function isIdentityOrModelQuestion(text) {
  if (!text) return false;
  return /(?:who\s+are\s+you|what\s+(?:model|llm)|which\s+model|what\s+are\s+you|are\s+you\s+(?:llama|chatgpt|gpt|claude))/i.test(text);
}

function buildOpenAiTextResponse(text) {
  return {
    id: `chatcmpl-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`,
    object: 'chat.completion',
    created: Math.floor(Date.now() / 1000),
    model: 'streamvault-ai',
    choices: [
      {
        index: 0,
        message: {
          role: 'assistant',
          content: text,
        },
        finish_reason: 'stop',
      }
    ]
  };
}

function buildAiTextResponse(text) {
  if (AI_OPENAI_COMPAT_MODE) {
    return buildOpenAiTextResponse(text);
  }
  return { text };
}

function extractQuestionFromAiMessage(text) {
  const normalized = normalizeAiMessageContent(text);
  if (!normalized) return '';

  const marker = 'User question:';
  const markerIndex = normalized.lastIndexOf(marker);
  if (markerIndex >= 0) {
    const extracted = normalized.slice(markerIndex + marker.length).trim();
    if (extracted) return extracted;
  }

  return normalized;
}

function extractAiLinkedContextRows(text) {
  const normalized = normalizeAiMessageContent(text);
  if (!normalized) return [];

  const match = normalized.match(/CONTEXT_START\s*([\s\S]*?)\s*CONTEXT_END/i);
  if (!match || !match[1]) return [];

  try {
    const parsed = JSON.parse(match[1].trim());
    return Array.isArray(parsed) ? parsed : [];
  } catch (error) {
    return [];
  }
}

function extractLinkedMovieTitleHints(text) {
  const rows = extractAiLinkedContextRows(text);
  if (!Array.isArray(rows) || rows.length === 0) return [];

  const movieHints = [];
  const fallbackHints = [];
  const seen = new Set();

  for (const row of rows) {
    if (!row || typeof row !== 'object') continue;
    const library = row.library && typeof row.library === 'object' ? row.library : null;
    const tmdb = row.tmdb && typeof row.tmdb === 'object' ? row.tmdb : null;

    const mediaTypes = [
      normalizeId(library?.media_type || '', 32).toLowerCase(),
      normalizeId(tmdb?.media_type || '', 32).toLowerCase(),
    ];

    const isMovieLike = mediaTypes.includes('movie');

    const titles = [
      normalizeId(tmdb?.title || '', 120),
      normalizeId(tmdb?.original_title || '', 120),
      normalizeId(library?.title || '', 120),
    ].filter(Boolean);

    for (const title of titles) {
      const key = title.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      if (isMovieLike) {
        movieHints.push(title);
      } else {
        fallbackHints.push(title);
      }

      if (movieHints.length >= 5) {
        return movieHints;
      }
    }
  }

  if (movieHints.length > 0) return movieHints;
  return fallbackHints.slice(0, 5);
}

function extractQuotedTitleCandidate(text) {
  if (!text) return '';
  const quotedMatch = text.match(/["'`“”](.{2,120}?)["'`“”]/);
  if (!quotedMatch || !quotedMatch[1]) return '';
  return normalizeId(quotedMatch[1], 120);
}

function sanitizeMovieSearchQuery(text) {
  const normalized = normalizeId(text || '', 300);
  if (!normalized) return '';

  const withoutAtTags = normalized.replace(/@[A-Za-z0-9_.:-]+/g, ' ');
  const cleaned = withoutAtTags
    .replace(/https?:\/\/\S+/gi, ' ')
    .replace(
      /\b(box\s*office|total\s*collection|worldwide|india|indian|domestic|overseas|gross|revenue|budget|imdb|rating|ratings|collection|score|scores|earn|earned|earnings|how\s+much|what\s+is|what'?s|tell\s+me|about|of|for|movie|film|only|so\s+far|till\s+now)\b/gi,
      ' '
    )
    .replace(/[^\p{L}\p{N}\s\-:]/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  if (cleaned) return normalizeId(cleaned, 120);
  return normalizeId(normalized.replace(/[^\p{L}\p{N}\s\-:]/gu, ' ').replace(/\s+/g, ' ').trim(), 120);
}

function isWeakMovieSearchQuery(query) {
  const normalized = normalizeId(query || '', 160).toLowerCase();
  if (!normalized) return true;

  const tokens = normalized.split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return true;

  const weakTokens = new Set([
    'this', 'that', 'it', 'its', 'movie', 'film',
    'so', 'far', 'now', 'current', 'currently', 'only',
    'what', 'is', 'the', 'a', 'an', 'of', 'for', 'to',
    'box', 'office', 'total', 'collection', 'gross', 'revenue', 'budget',
    'worldwide', 'domestic', 'overseas', 'india', 'indian',
    'earn', 'earned', 'earns', 'earnings',
    'how', 'much', 'did', 'does', 'has', 'have',
    'imdb', 'rating', 'ratings',
  ]);

  const meaningful = tokens.filter((token) => !weakTokens.has(token));
  return meaningful.length === 0;
}

function looksLikeMovieTopic(text) {
  if (!text) return false;
  return /\b(movie|film|cinema|actor|actress|director|box\s*office|collection|gross|revenue|budget|imdb|rating|cast|runtime|release|sequel|franchise|producer|screenplay|plot|worldwide|domestic|india|indian|earn|earned|earnings)\b/i.test(text);
}

function isHardNonMovieTopic(text) {
  if (!text) return false;
  return /\b(tv|show|series|episode|season|anime|song|music|math|code|coding|programming|weather|crypto|stock|politics|science|cricket|football)\b/i.test(text);
}

function toPositiveWholeNumber(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric <= 0) return null;
  return Math.floor(numeric);
}

function convertUsdToInrWhole(usdAmount) {
  const usdWhole = toPositiveWholeNumber(usdAmount);
  if (!usdWhole) return null;
  return Math.round(usdWhole * AI_USD_TO_INR_RATE);
}

function formatInrAmount(amount) {
  const numeric = Number(amount);
  if (!Number.isFinite(numeric) || numeric <= 0) return null;
  return new Intl.NumberFormat('en-IN', {
    style: 'currency',
    currency: 'INR',
    maximumFractionDigits: 0,
  }).format(numeric);
}

function toCroreNumber(amountInr) {
  const inrWhole = toPositiveWholeNumber(amountInr);
  if (!inrWhole) return null;
  const crores = inrWhole / 10000000;
  return Number(crores.toFixed(2));
}

function formatCroreAmount(amountInr) {
  const croreNumber = toCroreNumber(amountInr);
  if (!croreNumber || croreNumber < 1) return null;
  return `${croreNumber.toLocaleString('en-IN', { maximumFractionDigits: 2 })} crore`;
}

function formatIstTimestamp(epochMs) {
  const date = new Date(Number(epochMs) || Date.now());
  const datePart = date.toLocaleDateString('en-IN', { timeZone: AI_IST_TIMEZONE });
  const timePart = date.toLocaleTimeString('en-IN', {
    timeZone: AI_IST_TIMEZONE,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: true,
  });
  return `${datePart} ${timePart} IST`;
}

function parseImdbRatingFromHtml(html) {
  if (typeof html !== 'string' || !html) return null;

  const ratingValueMatch = html.match(/"ratingValue"\s*:\s*"?(?<rating>[0-9.]+)"?/i);
  if (!ratingValueMatch || !ratingValueMatch.groups || !ratingValueMatch.groups.rating) {
    return null;
  }

  const ratingValue = Number(ratingValueMatch.groups.rating);
  if (!Number.isFinite(ratingValue)) return null;

  const ratingCountMatch = html.match(/"ratingCount"\s*:\s*"?(?<count>[0-9,]+)"?/i);
  const ratingCount = ratingCountMatch?.groups?.count
    ? Number(String(ratingCountMatch.groups.count).replace(/,/g, ''))
    : null;

  return {
    value: ratingValue,
    count: Number.isFinite(ratingCount) ? ratingCount : null,
  };
}

async function fetchImdbRating(imdbId, requestId) {
  const normalizedImdbId = normalizeId(imdbId || '', 32);
  if (!/^tt\d{5,}$/.test(normalizedImdbId)) return null;

  const imdbUrl = `https://www.imdb.com/title/${normalizedImdbId}/`;
  const abortController = new AbortController();
  const timeout = setTimeout(() => abortController.abort(), AI_IMDB_FETCH_TIMEOUT_MS);

  try {
    const response = await fetch(imdbUrl, {
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36',
        'Accept-Language': 'en-US,en;q=0.9',
        Accept: 'text/html',
      },
      signal: abortController.signal,
    });

    if (!response.ok) {
      console.warn(`[AI][${requestId}] IMDb fetch failed with status ${response.status} for ${normalizedImdbId}`);
      return null;
    }

    const html = await response.text();
    const parsed = parseImdbRatingFromHtml(html);
    if (!parsed) return null;

    return {
      imdb_id: normalizedImdbId,
      imdb_url: imdbUrl,
      rating: parsed.value,
      rating_count: parsed.count,
    };
  } catch (error) {
    if (error && error.name === 'AbortError') {
      console.warn(`[AI][${requestId}] IMDb rating request timed out for ${normalizedImdbId}`);
      return null;
    }
    console.warn(`[AI][${requestId}] IMDb rating fetch error:`, error?.message || error);
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

async function fetchTmdbJsonWithFailover(path, query, requestId) {
  const result = await fetchTmdbWithFailover(path, query, requestId);
  if (result.error || !result.response) return null;

  try {
    return await result.response.json();
  } catch (error) {
    console.warn(`[AI][${requestId}] Failed to parse TMDB JSON:`, error?.message || error);
    return null;
  }
}

async function buildMovieWebContext(questionText, requestId) {
  const rawMessage = normalizeAiMessageContent(questionText);
  const question = extractQuestionFromAiMessage(rawMessage);
  if (!question) return null;

  const linkedMovieTitleHints = extractLinkedMovieTitleHints(rawMessage);
  const quotedTitle = extractQuotedTitleCandidate(question);
  let searchQuery = quotedTitle || sanitizeMovieSearchQuery(question);
  const hasPronounReference = /\b(this|that|it)\b/i.test(question);

  if (!quotedTitle && linkedMovieTitleHints.length > 0 && hasPronounReference) {
    searchQuery = linkedMovieTitleHints[0];
  }

  if ((!searchQuery || isWeakMovieSearchQuery(searchQuery)) && linkedMovieTitleHints.length > 0) {
    searchQuery = linkedMovieTitleHints[0];
  }
  if (!searchQuery) return null;

  const searchJson = await fetchTmdbJsonWithFailover(
    'search/movie',
    {
      query: searchQuery,
      include_adult: 'false',
      language: 'en-US',
      page: '1',
    },
    `${requestId}:movie-search`
  );

  const searchResults = Array.isArray(searchJson?.results) ? searchJson.results : [];
  if (searchResults.length === 0) {
    const fetchedAtMs = Date.now();
    return {
      question,
      search_query: searchQuery,
      linked_movie_hints: linkedMovieTitleHints,
      movie: null,
      warning: 'No TMDB movie result found for this query.',
      fetched_at_ms: fetchedAtMs,
      fetched_at_ist: formatIstTimestamp(fetchedAtMs),
    };
  }

  const normalizedQuoted = quotedTitle.toLowerCase();
  const selectedMovie = searchResults.find((entry) => {
    if (!normalizedQuoted) return false;
    const title = String(entry?.title || '').toLowerCase();
    const originalTitle = String(entry?.original_title || '').toLowerCase();
    return title.includes(normalizedQuoted) || originalTitle.includes(normalizedQuoted);
  }) || searchResults[0];

  const movieId = Number(selectedMovie?.id);
  if (!Number.isFinite(movieId) || movieId <= 0) return null;

  const detailJson = await fetchTmdbJsonWithFailover(
    `movie/${movieId}`,
    { append_to_response: 'external_ids' },
    `${requestId}:movie-details`
  );

  const details = detailJson && typeof detailJson === 'object' ? detailJson : {};
  const imdbId = normalizeId(details?.external_ids?.imdb_id || '', 32);
  const imdbRating = imdbId ? await fetchImdbRating(imdbId, `${requestId}:imdb`) : null;
  const revenueUsd = toPositiveWholeNumber(details?.revenue);
  const budgetUsd = toPositiveWholeNumber(details?.budget);
  const revenueInr = convertUsdToInrWhole(revenueUsd);
  const budgetInr = convertUsdToInrWhole(budgetUsd);
  const voteAverage = Number(details?.vote_average);
  const voteCount = Number(details?.vote_count);
  const fetchedAtMs = Date.now();

  return {
    question,
    search_query: searchQuery,
    linked_movie_hints: linkedMovieTitleHints,
    currency: {
      display_currency: 'INR',
      crore_threshold_inr: 10000000,
      converted_from_usd_rate: AI_USD_TO_INR_RATE,
    },
    movie: {
      id: movieId,
      title: normalizeId(details?.title || selectedMovie?.title || '', 200),
      original_title: normalizeId(details?.original_title || selectedMovie?.original_title || '', 200) || null,
      release_date: normalizeId(details?.release_date || selectedMovie?.release_date || '', 32) || null,
      overview: normalizeId(details?.overview || selectedMovie?.overview || '', 1200) || null,
      box_office_worldwide_inr: revenueInr,
      box_office_worldwide_formatted: formatInrAmount(revenueInr),
      box_office_worldwide_crore: toCroreNumber(revenueInr),
      box_office_worldwide_crore_text: formatCroreAmount(revenueInr),
      budget_inr: budgetInr,
      budget_formatted: formatInrAmount(budgetInr),
      budget_crore: toCroreNumber(budgetInr),
      budget_crore_text: formatCroreAmount(budgetInr),
      tmdb_rating: Number.isFinite(voteAverage) ? voteAverage : null,
      tmdb_vote_count: Number.isFinite(voteCount) ? Math.floor(voteCount) : null,
      imdb: imdbRating || (imdbId ? { imdb_id: imdbId, imdb_url: `https://www.imdb.com/title/${imdbId}/` } : null),
    },
    sources: {
      tmdb_url: `https://www.themoviedb.org/movie/${movieId}`,
      imdb_url: imdbId ? `https://www.imdb.com/title/${imdbId}/` : null,
    },
    fetched_at_ms: fetchedAtMs,
    fetched_at_ist: formatIstTimestamp(fetchedAtMs),
  };
}

function attachMovieWebContextMessage(payload, movieWebContext) {
  if (!payload || typeof payload !== 'object' || !Array.isArray(payload.messages)) return payload;
  if (!movieWebContext || typeof movieWebContext !== 'object') return payload;

  const contextMessage = {
    role: 'system',
    content: [
      'Movie web search context for factual fields (box office, ratings, release info).',
      'Use INR for money and crore format for values >= 1 crore.',
      `Use IST (${AI_IST_TIMEZONE}) for any time reference.`,
      'Use this context when answering the user.',
      JSON.stringify(movieWebContext),
    ].join('\n'),
  };

  const messages = payload.messages.slice();
  if (messages[0] && messages[0].role === 'system') {
    return {
      ...payload,
      messages: [messages[0], contextMessage, ...messages.slice(1)],
    };
  }

  return {
    ...payload,
    messages: [contextMessage, ...messages],
  };
}

function buildDirectMovieFactsReply(questionText, movieWebContext) {
  if (!movieWebContext || typeof movieWebContext !== 'object') return '';
  const movie = movieWebContext.movie && typeof movieWebContext.movie === 'object'
    ? movieWebContext.movie
    : null;
  if (!movie) return '';

  const question = normalizeAiMessageContent(questionText || '');
  const asksDeepProfile = /\b(deep|detailed|full|complete)\s+(tmdb|movie)?\s*(profile|details?)\b/i.test(question)
    || /\b(include|show|give)\b[\s\S]{0,120}\b(cast|crew|production|genres?|runtime|plot|summary|notable|facts|similar|recommended|learn\s+more)\b/i.test(question)
    || /\b(cast|key\s+crew|production\s+companies|plot\s+summary|notable\s+facts|similar\/recommended)\b/i.test(question);

  // Do not short-circuit detailed profile requests into single-field factual replies.
  if (asksDeepProfile) return '';

  const movieTitle = normalizeId(movie.title || '', 200) || 'this movie';
  const fetchedAtIst = normalizeId(
    movieWebContext.fetched_at_ist || formatIstTimestamp(movieWebContext.fetched_at_ms || Date.now()),
    128
  );

  const asksBoxOffice = /\b(box\s*office|total\s*collection|collection|gross|revenue|worldwide|earn|earned|earnings)\b/i.test(question);
  const asksIndiaCollection = /\b(india|indian|in\s+india|india\s+only|domestic)\b/i.test(question);
  const asksBudget = /\bbudget\b/i.test(question);
  const asksRatings = /\b(imdb|rating|ratings|score|scores)\b/i.test(question);

  if (asksBoxOffice) {
    const amountInr = toPositiveWholeNumber(movie.box_office_worldwide_inr);
    const amountFormatted = normalizeId(movie.box_office_worldwide_formatted || '', 64);
    const croreText = normalizeId(movie.box_office_worldwide_crore_text || '', 64);
    const indiaAmountInr = toPositiveWholeNumber(movie.box_office_india_inr);
    const indiaAmountFormatted = normalizeId(movie.box_office_india_formatted || '', 64);
    const indiaCroreText = normalizeId(movie.box_office_india_crore_text || '', 64);

    if (amountInr) {
      const primary = croreText || amountFormatted;
      const secondary = croreText && amountFormatted ? ` (${amountFormatted})` : '';
      if (asksIndiaCollection) {
        if (indiaAmountInr) {
          const indiaPrimary = indiaCroreText || indiaAmountFormatted;
          const indiaSecondary = indiaCroreText && indiaAmountFormatted ? ` (${indiaAmountFormatted})` : '';
          return `As of ${fetchedAtIst}, the worldwide box office collection for "${movieTitle}" is ${primary}${secondary}. India-only collection is ${indiaPrimary}${indiaSecondary}.`;
        }
        return `As of ${fetchedAtIst}, the worldwide box office collection for "${movieTitle}" is ${primary}${secondary}. India-only collection data is currently unavailable from configured sources.`;
      }
      return `As of ${fetchedAtIst}, the worldwide box office collection for "${movieTitle}" is ${primary}${secondary}.`;
    }

    if (asksIndiaCollection) {
      if (indiaAmountInr) {
        const indiaPrimary = indiaCroreText || indiaAmountFormatted;
        const indiaSecondary = indiaCroreText && indiaAmountFormatted ? ` (${indiaAmountFormatted})` : '';
        return `As of ${fetchedAtIst}, worldwide box office collection data for "${movieTitle}" is currently unavailable. India-only collection is ${indiaPrimary}${indiaSecondary}.`;
      }
      return `As of ${fetchedAtIst}, worldwide and India-only box office collection data for "${movieTitle}" is currently unavailable from configured sources.`;
    }

    return `As of ${fetchedAtIst}, worldwide box office collection data for "${movieTitle}" is currently unavailable.`;
  }

  if (asksBudget) {
    const amountInr = toPositiveWholeNumber(movie.budget_inr);
    const amountFormatted = normalizeId(movie.budget_formatted || '', 64);
    const croreText = normalizeId(movie.budget_crore_text || '', 64);

    if (amountInr) {
      const primary = croreText || amountFormatted;
      const secondary = croreText && amountFormatted ? ` (${amountFormatted})` : '';
      return `As of ${fetchedAtIst}, the production budget for "${movieTitle}" is ${primary}${secondary}.`;
    }

    return `As of ${fetchedAtIst}, budget data for "${movieTitle}" is currently unavailable.`;
  }

  if (asksRatings) {
    const tmdbRating = Number(movie.tmdb_rating);
    const tmdbVotes = Number(movie.tmdb_vote_count);
    const imdb = movie.imdb && typeof movie.imdb === 'object' ? movie.imdb : null;
    const imdbRating = Number(imdb?.rating);
    const imdbVotes = Number(imdb?.rating_count);

    const parts = [];
    if (Number.isFinite(tmdbRating) && tmdbRating > 0) {
      const tmdbPart = Number.isFinite(tmdbVotes) && tmdbVotes > 0
        ? `TMDB: ${tmdbRating.toFixed(1)}/10 (${Math.floor(tmdbVotes)} votes)`
        : `TMDB: ${tmdbRating.toFixed(1)}/10`;
      parts.push(tmdbPart);
    }

    if (Number.isFinite(imdbRating) && imdbRating > 0) {
      const imdbPart = Number.isFinite(imdbVotes) && imdbVotes > 0
        ? `IMDb: ${imdbRating.toFixed(1)}/10 (${Math.floor(imdbVotes)} votes)`
        : `IMDb: ${imdbRating.toFixed(1)}/10`;
      parts.push(imdbPart);
    }

    if (parts.length > 0) {
      return `As of ${fetchedAtIst}, ratings for "${movieTitle}" are ${parts.join(' | ')}.`;
    }

    return `As of ${fetchedAtIst}, ratings data for "${movieTitle}" is currently unavailable.`;
  }

  return '';
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

  for (const [nonce, expiresAt] of aiNonceCache.entries()) {
    if (expiresAt <= now) {
      aiNonceCache.delete(nonce);
    }
  }

  // Best-effort cleanup for fallback quota store (for local/dev use only).
  if (AI_ALLOW_UNPERSISTED_LIMITS) {
    const staleAfterMs = AI_FREE_WINDOW_MS * 3;
    for (const [fingerprintHash, state] of aiQuotaFallback.entries()) {
      if (now - state.updatedAt > staleAfterMs) {
        aiQuotaFallback.delete(fingerprintHash);
      }
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

// Clean up inactive rooms
setInterval(() => {
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
  const missingAiConfig = getMissingAiConfig();
  res.json({
    activeRooms: rooms.size,
    onlineUsers: social.onlineUsers.size,
    ai: {
      enabled: missingAiConfig.length === 0,
      wrapperConfigured: !!AI_WRAPPER_URL,
      signatureConfigured: !!AI_CLIENT_SIGNATURE_SECRET,
      openAiCompat: AI_OPENAI_COMPAT_MODE,
      defaultModel: AI_DEFAULT_MODEL,
      brandName: AI_BRAND_NAME,
      missingConfig: missingAiConfig,
      freeLimit: {
        maxChats: AI_FREE_MAX_CHATS,
        windowDays: AI_FREE_WINDOW_DAYS,
      },
      upgradeDefaults: {
        maxChats: AI_UPGRADE_APPROVED_MAX_CHATS,
        windowDays: AI_UPGRADE_APPROVED_WINDOW_DAYS,
        durationDays: AI_UPGRADE_APPROVED_DURATION_DAYS,
      },
      adminApiConfigured: !!AI_ADMIN_API_KEY,
      persistentStorage: database.isConnected(),
      fallbackMode: !database.isConnected() && AI_ALLOW_UNPERSISTED_LIMITS,
      nonceCacheSize: aiNonceCache.size,
    },
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

app.get('/api/tmdb/*', async (req, res) => {
  const requestId = createTmdbRequestId();
  const startMs = Date.now();
  const rawPath = req.params[0];
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

// AI quota endpoint (signed)
app.get('/api/ai/quota', validateAiClientSignature, async (req, res) => {
  const now = Date.now();
  const fingerprint = getAiFingerprint(req);
  const policy = await getAiPolicyForRequest(req, now);
  const quota = await readAiChatQuota(fingerprint.fingerprintHash, now, {
    maxChats: policy.maxChats,
    windowMs: policy.windowMs,
  });

  if (!quota.storageAvailable) {
    return res.status(503).json({
      error: quota.error || 'AI quota storage unavailable',
    });
  }

  let latestUpgradeRequest = null;
  if (policy.googleId && database.isConnected()) {
    latestUpgradeRequest = await database.getLatestAiUpgradeRequestForUser(policy.googleId);
  }

  addAiQuotaHeaders(res, quota, policy.windowDays);
  res.set('Cache-Control', 'no-store');
  res.json({
    allowed: quota.allowed && !policy.isBanned,
    limit: quota.limit,
    used: quota.used,
    remaining: quota.remaining,
    window_start_ms: quota.windowStartMs,
    reset_at_ms: quota.resetAt,
    retry_after_ms: quota.retryAfterMs,
    fingerprint: {
      has_device_id: fingerprint.hasDeviceId,
      has_device_signature: fingerprint.hasDeviceSignature,
    },
    tier: policy.tier,
    user: {
      google_id: policy.googleId,
      authenticated: !!policy.googleId,
    },
    entitlement: policy.entitlement ? {
      id: policy.entitlement.id,
      max_chats: policy.entitlement.maxChats,
      window_days: policy.entitlement.windowDays,
      expires_at_ms: policy.entitlement.expiresAt,
    } : null,
    ban: toAiBanResponse(policy.ban),
    rejected_requests_count: policy.rejectedRequestCount || 0,
    rejection_ban_threshold: AI_REJECTION_BAN_THRESHOLD,
    additional_reason_min_words: AI_ADDITIONAL_REQUEST_MIN_WORDS,
    additional_reason_min_chars: AI_ADDITIONAL_REQUEST_MIN_CHARS,
    upgrade_request: latestUpgradeRequest ? {
      id: latestUpgradeRequest.id,
      status: latestUpgradeRequest.status,
      requested_at_ms: latestUpgradeRequest.requestedAt,
      reviewed_at_ms: latestUpgradeRequest.reviewedAt,
      review_note: latestUpgradeRequest.reviewNote,
    } : null,
  });
});

// Signed AI chat proxy with free-tier limits.
app.post('/api/ai/chat', validateAiClientSignature, async (req, res) => {
  const requestId = req.aiRequestId || createAiRequestId();
  const now = Date.now();
  const sourceIp = req.aiSourceIp || getClientIp(req);
  const upstreamUrl = resolveAiUpstreamUrl(AI_WRAPPER_URL);

  if (!upstreamUrl) {
    console.warn(`[AI][${requestId}] Rejected request because AI_WRAPPER_URL is missing`);
    return res.status(503).json({ error: 'AI endpoint is not configured' });
  }

  if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
    return res.status(400).json({ error: 'Invalid AI request body' });
  }

  const fingerprint = getAiFingerprint(req);
  const policy = await getAiPolicyForRequest(req, now);
  if (policy.isBanned) {
    console.warn(
      `[AI][${requestId}] Blocked banned user ${policy.googleId || 'unknown'} from ${sourceIp}`
    );
    return res.status(403).json({
      error: 'AI chat access is blocked after repeated rejected limit requests',
      ban: toAiBanResponse(policy.ban),
      rejected_requests_count: policy.rejectedRequestCount || 0,
      rejection_ban_threshold: AI_REJECTION_BAN_THRESHOLD,
    });
  }
  const quota = await consumeAiChatQuota(fingerprint.fingerprintHash, now, {
    maxChats: policy.maxChats,
    windowMs: policy.windowMs,
  });

  if (!quota.storageAvailable) {
    console.error(`[AI][${requestId}] Failed to consume quota: ${quota.error || 'unknown error'}`);
    return res.status(503).json({ error: quota.error || 'AI quota storage unavailable' });
  }

  addAiQuotaHeaders(res, quota, policy.windowDays);
  res.set('Cache-Control', 'no-store');

  if (!quota.allowed) {
    const retryAfterSec = Math.ceil(quota.retryAfterMs / 1000);
    res.set('Retry-After', String(retryAfterSec));
    console.warn(
      `[AI][${requestId}] Quota exhausted for fingerprint ${fingerprint.fingerprintHash.slice(0, 12)} from ${sourceIp} (tier=${policy.tier})`
    );
    return res.status(429).json({
      error: 'AI chat limit reached',
      limit: quota.limit,
      remaining: quota.remaining,
      reset_at_ms: quota.resetAt,
      retry_after_ms: quota.retryAfterMs,
      tier: policy.tier,
    });
  }

  let upstreamPayload = req.body;
  if (AI_OPENAI_COMPAT_MODE) {
    const prepared = buildOpenAiCompatiblePayload(req.body);
    if (prepared.error) {
      return res.status(400).json({ error: prepared.error });
    }
    upstreamPayload = prepared.payload;
  }

  const rawLastUserMessage = getLastUserMessageText(upstreamPayload.messages);
  const lastUserMessage = extractQuestionFromAiMessage(rawLastUserMessage);
  if (lastUserMessage && isIdentityOrModelQuestion(lastUserMessage)) {
    const lockedIdentity = `I am ${AI_BRAND_NAME}, ${AI_APP_DESCRIPTION}.`;
    return res.status(200).json(buildAiTextResponse(lockedIdentity));
  }

  if (
    AI_MOVIE_ONLY_HARDCODED
    && lastUserMessage
    && isHardNonMovieTopic(lastUserMessage)
    && !looksLikeMovieTopic(lastUserMessage)
  ) {
    const movieOnlyReply = `I am ${AI_BRAND_NAME}. I can only help with movie-related questions.`;
    return res.status(200).json(buildAiTextResponse(movieOnlyReply));
  }

  let movieWebContext = null;
  if (AI_MOVIE_WEBSEARCH_ENABLED && lastUserMessage) {
    try {
      movieWebContext = await Promise.race([
        buildMovieWebContext(rawLastUserMessage, requestId),
        new Promise((resolve) => setTimeout(() => resolve(null), AI_MOVIE_WEB_CONTEXT_TIMEOUT_MS)),
      ]);
    } catch (error) {
      console.warn(`[AI][${requestId}] Movie web context fetch failed:`, error?.message || error);
    }
  }

  const movieContextResolved = !!(movieWebContext && movieWebContext.movie);
  const needsWebFacts = /\b(box\s*office|collection|gross|revenue|budget|imdb|rating|ratings|worldwide|domestic|india|indian|earn|earned|earnings)\b/i.test(lastUserMessage || '');

  if (
    AI_MOVIE_ONLY_HARDCODED
    && lastUserMessage
    && !movieContextResolved
    && !looksLikeMovieTopic(lastUserMessage)
  ) {
    const movieOnlyReply = `I am ${AI_BRAND_NAME}. I can only help with movie-related questions.`;
    return res.status(200).json(buildAiTextResponse(movieOnlyReply));
  }

  if (needsWebFacts && lastUserMessage && !movieContextResolved) {
    const unresolvedMovieReply = `I could not resolve the movie from your query for web facts. Please provide the exact movie title.`;
    return res.status(200).json(buildAiTextResponse(unresolvedMovieReply));
  }

  if (needsWebFacts && lastUserMessage && movieContextResolved) {
    const directFactsReply = buildDirectMovieFactsReply(lastUserMessage, movieWebContext);
    if (directFactsReply) {
      return res.status(200).json(buildAiTextResponse(directFactsReply));
    }
  }

  if (AI_MOVIE_WEBSEARCH_ENABLED && movieContextResolved && AI_OPENAI_COMPAT_MODE) {
    upstreamPayload = attachMovieWebContextMessage(upstreamPayload, movieWebContext);
  }

  const upstreamHeaders = {
    Accept: 'application/json',
    'Content-Type': 'application/json',
    'X-AI-Request-Id': requestId,
    'X-AI-Fingerprint': fingerprint.fingerprintHash,
  };

  if (AI_WRAPPER_AUTH_TOKEN) {
    if (
      AI_WRAPPER_AUTH_HEADER.toLowerCase() === 'authorization'
      && !AI_WRAPPER_AUTH_TOKEN.toLowerCase().startsWith('bearer ')
    ) {
      upstreamHeaders[AI_WRAPPER_AUTH_HEADER] = `Bearer ${AI_WRAPPER_AUTH_TOKEN}`;
    } else {
      upstreamHeaders[AI_WRAPPER_AUTH_HEADER] = AI_WRAPPER_AUTH_TOKEN;
    }
  }

  const abortController = new AbortController();
  const timeout = setTimeout(() => abortController.abort(), AI_WRAPPER_TIMEOUT_MS);

  try {
    const upstreamRes = await fetch(upstreamUrl, {
      method: 'POST',
      headers: upstreamHeaders,
      body: JSON.stringify(upstreamPayload),
      signal: abortController.signal,
    });

    const payload = Buffer.from(await upstreamRes.arrayBuffer());
    const contentType = upstreamRes.headers.get('content-type');
    if (contentType) {
      res.set('Content-Type', contentType);
    }

    if (!upstreamRes.ok) {
      console.warn(
        `[AI][${requestId}] Wrapper returned status ${upstreamRes.status} for fingerprint ${fingerprint.fingerprintHash.slice(0, 12)}`
      );
    }

    return res.status(upstreamRes.status).send(payload);
  } catch (error) {
    if (error && error.name === 'AbortError') {
      console.error(`[AI][${requestId}] Wrapper request timed out after ${AI_WRAPPER_TIMEOUT_MS}ms`);
      return res.status(504).json({ error: 'AI upstream timeout' });
    }
    console.error(`[AI][${requestId}] Wrapper request failed:`, error.message || error);
    return res.status(502).json({ error: 'AI upstream request failed' });
  } finally {
    clearTimeout(timeout);
  }
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
    next();
  } catch (error) {
    console.error('[Social Auth] Error:', error);
    res.status(401).json({ error: 'Authentication failed' });
  }
};

function adminAiAuth(req, res, next) {
  if (!AI_ADMIN_API_KEY) {
    return res.status(503).json({ error: 'AI admin API is not configured' });
  }

  const providedToken = extractBearerToken(req);
  if (providedToken && secureTokenEqual(AI_ADMIN_API_KEY, providedToken)) {
    return next();
  }

  // Browser-friendly admin auth: prompt username/password via Basic challenge.
  // You can use AI_ADMIN_API_KEY in both fields.
  const basicAuth = parseRuntimeBasicAuth(req);
  const basicValid = !!(
    basicAuth
    && secureTokenEqual(AI_ADMIN_API_KEY, basicAuth.username || '')
    && secureTokenEqual(AI_ADMIN_API_KEY, basicAuth.password || '')
  );

  if (basicValid) {
    return next();
  }

  res.set('WWW-Authenticate', 'Basic realm="StreamVault AI Admin", charset="UTF-8"');
  return res.status(401).json({ error: 'Invalid admin authorization' });
}

function toAiUpgradeRequestResponse(request) {
  if (!request) return null;
  return {
    id: request.id,
    google_id: request.googleId,
    status: request.status,
    request_type: request.requestType || 'referral',
    referral_1: request.referral1,
    referral_2: request.referral2,
    request_reason: request.requestReason || null,
    note: request.note,
    entitlement_id: request.entitlementId,
    requested_at_ms: request.requestedAt,
    reviewed_at_ms: request.reviewedAt,
    reviewed_by: request.reviewedBy,
    review_note: request.reviewNote,
  };
}

function toAiEntitlementResponse(entitlement) {
  if (!entitlement) return null;
  return {
    id: entitlement.id,
    google_id: entitlement.googleId,
    max_chats: entitlement.maxChats,
    window_days: entitlement.windowDays,
    expires_at_ms: entitlement.expiresAt,
    reason: entitlement.reason,
    granted_by: entitlement.grantedBy,
    request_id: entitlement.requestId,
    revoked_at_ms: entitlement.revokedAt,
    revoked_by: entitlement.revokedBy,
    revoke_reason: entitlement.revokeReason,
    created_at_ms: entitlement.createdAt,
  };
}

function toAiBanResponse(ban) {
  if (!ban || !ban.isActive) return null;
  return {
    is_banned: true,
    google_id: ban.googleId,
    banned_at_ms: ban.bannedAt,
    banned_by: ban.bannedBy,
    reason: ban.banReason,
    updated_at_ms: ban.updatedAt,
  };
}

function emitAiUpgradeRealtimeEvent(googleId, payload = {}) {
  const normalizedGoogleId = normalizeId(googleId || '', 256);
  if (!normalizedGoogleId) return false;

  const session = social.onlineUsers.get(normalizedGoogleId);
  const ws = session?.ws;
  if (!ws || ws.readyState !== 1) return false;

  try {
    ws.send(JSON.stringify({
      type: 'ai_upgrade_update',
      google_id: normalizedGoogleId,
      ...payload,
      emitted_at_ms: Date.now(),
    }));
    return true;
  } catch (error) {
    console.warn('[AI] Failed to emit realtime upgrade event:', error?.message || error);
    return false;
  }
}

function wantsHtmlResponse(req) {
  const format = normalizeId(req.query?.format || '', 32).toLowerCase();
  if (format === 'json') return false;
  if (format === 'html') return true;

  const acceptHeader = String(req.headers.accept || '').toLowerCase();
  return acceptHeader.includes('text/html');
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatAdminDate(value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return '--';
  const date = new Date(parsed);
  return date.toLocaleString();
}

function renderUpgradeStatusTag(status) {
  const normalized = String(status || 'pending').toLowerCase();
  const safeStatus = escapeHtml(normalized);

  if (normalized === 'approved') {
    return `<span class="status status-approved">${safeStatus}</span>`;
  }
  if (normalized === 'rejected') {
    return `<span class="status status-rejected">${safeStatus}</span>`;
  }
  return `<span class="status status-pending">${safeStatus}</span>`;
}

function renderAdminUpgradeRequestsPage(options = {}) {
  const requests = Array.isArray(options.requests) ? options.requests : [];
  const bans = Array.isArray(options.bans) ? options.bans : [];
  const userStates = options.userStates && typeof options.userStates === 'object' ? options.userStates : {};
  const statusFilter = normalizeId(options.statusFilter || 'pending', 16).toLowerCase() || 'pending';
  const isBanFilter = statusFilter === 'banned' || statusFilter === 'unbanned';
  const successMessage = normalizeId(options.message || '', 500);
  const errorMessage = normalizeId(options.error || '', 500);

  const statusFilters = ['pending', 'approved', 'rejected', 'all', 'banned', 'unbanned'];
  const filterTabs = statusFilters.map((filter) => {
    const active = filter === statusFilter;
    const href = `/api/admin/ai/upgrade-requests?status=${encodeURIComponent(filter)}`;
    return `<a class="filter-tab ${active ? 'active' : ''}" href="${href}">${escapeHtml(filter)}</a>`;
  }).join('');

  const requestCards = requests.map((request) => {
    const requestId = Number(request.id) || 0;
    const statusTag = renderUpgradeStatusTag(request.status);
    const showActions = request.status === 'pending';
    const googleId = normalizeId(request.googleId || request.google_id || '', 256);
    const userState = googleId ? (userStates[googleId] || {}) : {};
    const rejectedRequestCount = Math.max(0, parsePositiveInt(userState.rejected_requests_count, 0));
    const isBannedUser = !!userState.is_banned;
    const requestType = normalizeId(request.requestType || request.request_type || 'referral', 32).toLowerCase() || 'referral';
    const isAdditionalRequest = requestType === 'additional';
    const fieldOneLabel = isAdditionalRequest ? 'Reason' : 'Referral 1';
    const fieldOneValue = isAdditionalRequest
      ? (request.requestReason || request.request_reason || '--')
      : (request.referral1 || request.referral_1 || '--');
    const fieldTwoLabel = isAdditionalRequest ? 'Context' : 'Referral 2';
    const fieldTwoValue = isAdditionalRequest
      ? 'Additional rate limit request'
      : (request.referral2 || request.referral_2 || '--');

    const approveForm = showActions
      ? `
          <form method="post" action="/api/admin/ai/upgrade-requests/${requestId}/approve?return_status=${encodeURIComponent(statusFilter)}" class="action-form">
            <label>Max Chats
              <input name="max_chats" type="number" min="1" value="${escapeHtml(AI_UPGRADE_APPROVED_MAX_CHATS)}" />
            </label>
            <label>Window Days
              <input name="window_days" type="number" min="1" value="${escapeHtml(AI_UPGRADE_APPROVED_WINDOW_DAYS)}" />
            </label>
            <label>Duration Days
              <input name="duration_days" type="number" min="1" value="${escapeHtml(AI_UPGRADE_APPROVED_DURATION_DAYS)}" />
            </label>
            <label>Review Note
              <input name="review_note" type="text" placeholder="Optional note" />
            </label>
            <button class="btn btn-approve" type="submit">Approve</button>
          </form>
        `
      : '';

    const rejectForm = showActions
      ? `
          <form method="post" action="/api/admin/ai/upgrade-requests/${requestId}/reject?return_status=${encodeURIComponent(statusFilter)}" class="action-form">
            <label>Reject Reason
              <input name="review_note" type="text" placeholder="Reason for rejection" required />
            </label>
            <button class="btn btn-reject" type="submit">Reject</button>
          </form>
        `
      : '';

    const banControls = googleId
      ? (isBannedUser
        ? `
          <form method="post" action="/api/admin/ai/users/${encodeURIComponent(googleId)}/unban?return_status=${encodeURIComponent(statusFilter)}" class="action-form action-form-user">
            <label>Unban Note
              <input name="reason" type="text" placeholder="Optional note" />
            </label>
            <button class="btn btn-unban" type="submit">Unban AI Chat</button>
          </form>
        `
        : `
          <form method="post" action="/api/admin/ai/users/${encodeURIComponent(googleId)}/ban?return_status=${encodeURIComponent(statusFilter)}" class="action-form action-form-user">
            <label>Ban Note
              <input name="reason" type="text" placeholder="Manual ban reason (optional)" />
            </label>
            <button class="btn btn-ban" type="submit">Ban AI Chat</button>
          </form>
        `
      )
      : '';

    return `
      <article class="request-card">
        <div class="request-head">
          <h3>Request #${escapeHtml(requestId)}</h3>
          ${statusTag}
        </div>
        <div class="request-grid">
          <div>
            <p class="label">User</p>
            <p class="value mono">${escapeHtml(request.googleId || request.google_id || '--')}</p>
          </div>
          <div>
            <p class="label">Type</p>
            <p class="value">${escapeHtml(requestType)}</p>
          </div>
          <div>
            <p class="label">${escapeHtml(fieldOneLabel)}</p>
            <p class="value">${escapeHtml(fieldOneValue)}</p>
          </div>
          <div>
            <p class="label">Requested</p>
            <p class="value">${escapeHtml(formatAdminDate(request.requestedAt || request.requested_at_ms))}</p>
          </div>
          <div>
            <p class="label">${escapeHtml(fieldTwoLabel)}</p>
            <p class="value">${escapeHtml(fieldTwoValue)}</p>
          </div>
        </div>
        <div class="request-meta">
          <p class="label">Note</p>
          <p class="value">${escapeHtml(request.note || '--')}</p>
          <p class="label">Review</p>
          <p class="value">${escapeHtml(request.reviewNote || request.review_note || '--')}</p>
          <p class="label">Moderation</p>
          <p class="value">${escapeHtml(isBannedUser ? 'AI chat banned' : 'Not banned')}</p>
          <p class="value">Rejected requests: ${escapeHtml(rejectedRequestCount)} (auto-ban when > ${escapeHtml(AI_REJECTION_BAN_THRESHOLD)})</p>
        </div>
        <div class="actions">
          ${approveForm}
          ${rejectForm}
          ${banControls}
        </div>
      </article>
    `;
  }).join('');

  const banCards = bans.map((ban) => {
    const googleId = normalizeId(ban.googleId || ban.google_id || '', 256);
    const userState = googleId ? (userStates[googleId] || {}) : {};
    const rejectedRequestCount = Math.max(0, parsePositiveInt(userState.rejected_requests_count, 0));
    const isBannedUser = !!(ban.isActive || Number(ban.is_active) === 1);
    const banStatusTag = isBannedUser
      ? '<span class="status status-banned">banned</span>'
      : '<span class="status status-unbanned">unbanned</span>';
    const banNote = ban.banReason || ban.ban_reason || '--';
    const unbanNote = ban.unbanReason || ban.unban_reason || '--';

    const moderationForm = googleId
      ? (isBannedUser
        ? `
          <form method="post" action="/api/admin/ai/users/${encodeURIComponent(googleId)}/unban?return_status=${encodeURIComponent(statusFilter)}" class="action-form action-form-user">
            <label>Unban Note
              <input name="reason" type="text" placeholder="Optional note" />
            </label>
            <button class="btn btn-unban" type="submit">Unban AI Chat</button>
          </form>
        `
        : `
          <form method="post" action="/api/admin/ai/users/${encodeURIComponent(googleId)}/ban?return_status=${encodeURIComponent(statusFilter)}" class="action-form action-form-user">
            <label>Ban Note
              <input name="reason" type="text" placeholder="Manual ban reason (optional)" />
            </label>
            <button class="btn btn-ban" type="submit">Ban AI Chat</button>
          </form>
        `
      )
      : '';

    return `
      <article class="request-card">
        <div class="request-head">
          <h3>User Moderation</h3>
          ${banStatusTag}
        </div>
        <div class="request-grid">
          <div>
            <p class="label">User</p>
            <p class="value mono">${escapeHtml(googleId || '--')}</p>
          </div>
          <div>
            <p class="label">Updated</p>
            <p class="value">${escapeHtml(formatAdminDate(ban.updatedAt || ban.updated_at))}</p>
          </div>
          <div>
            <p class="label">Banned At</p>
            <p class="value">${escapeHtml(formatAdminDate(ban.bannedAt || ban.banned_at))}</p>
          </div>
          <div>
            <p class="label">Unbanned At</p>
            <p class="value">${escapeHtml(formatAdminDate(ban.unbannedAt || ban.unbanned_at))}</p>
          </div>
        </div>
        <div class="request-meta">
          <p class="label">Banned By</p>
          <p class="value mono">${escapeHtml(ban.bannedBy || ban.banned_by || '--')}</p>
          <p class="label">Ban Reason</p>
          <p class="value">${escapeHtml(banNote)}</p>
          <p class="label">Unbanned By</p>
          <p class="value mono">${escapeHtml(ban.unbannedBy || ban.unbanned_by || '--')}</p>
          <p class="label">Unban Reason</p>
          <p class="value">${escapeHtml(unbanNote)}</p>
          <p class="label">Rejected Requests</p>
          <p class="value">${escapeHtml(rejectedRequestCount)} (auto-ban when > ${escapeHtml(AI_REJECTION_BAN_THRESHOLD)})</p>
        </div>
        <div class="actions">
          ${moderationForm}
        </div>
      </article>
    `;
  }).join('');

  const cards = isBanFilter ? banCards : requestCards;
  const emptyState = cards.length === 0
    ? `<div class="empty">No ${isBanFilter ? 'users' : 'requests'} found for "${escapeHtml(statusFilter)}".</div>`
    : cards;

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
  </style>
</head>
<body>
  <main class="wrap">
    <header class="head">
      <div>
        <h1 class="title">StreamVault AI Upgrade Requests</h1>
        <p class="sub">Review requests, approve/reject, and manage AI chat ban or unban from this panel.</p>
      </div>
    </header>
    <section class="bar">
      <nav class="filters">${filterTabs}</nav>
      <a class="refresh" href="/api/admin/ai/upgrade-requests?status=${encodeURIComponent(statusFilter)}">Refresh</a>
    </section>
    ${successMessage ? `<div class="message ok">${escapeHtml(successMessage)}</div>` : ''}
    ${errorMessage ? `<div class="message err">${escapeHtml(errorMessage)}</div>` : ''}
    <section class="grid">
      ${emptyState}
    </section>
  </main>
</body>
</html>`;
}

// User submits request to unlock higher AI limits.
app.post('/api/ai/upgrade-request', socialAuth, async (req, res) => {
  if (!database.isConnected()) {
    return res.status(503).json({ error: 'Upgrade request storage unavailable' });
  }

  const now = Date.now();
  const requestTypeInput = normalizeId(req.body?.request_type || req.body?.requestType || 'referral', 32).toLowerCase();
  let requestType = requestTypeInput === 'additional' ? 'additional' : 'referral';
  const referral1 = normalizeId(req.body?.referral_1 || req.body?.referral1 || '', 256);
  const referral2 = normalizeId(req.body?.referral_2 || req.body?.referral2 || '', 256);
  const requestReason = normalizeId(req.body?.request_reason || req.body?.requestReason || req.body?.reason || '', 1000);
  const note = normalizeId(req.body?.note || '', 1000);

  // Backward-compatible fallback:
  // if client sends only reason (without request_type/referrals), treat it as additional request.
  if (requestType !== 'additional' && requestReason && !referral1 && !referral2) {
    requestType = 'additional';
  }

  if (requestType === 'additional') {
    if (!requestReason) {
      return res.status(400).json({ error: 'Reason is required for additional rate limit request' });
    }
    const reasonWords = countWords(requestReason);
    const reasonChars = countDetailChars(requestReason);
    const meetsWordRule = reasonWords >= AI_ADDITIONAL_REQUEST_MIN_WORDS;
    const meetsCharRule = reasonChars >= AI_ADDITIONAL_REQUEST_MIN_CHARS;
    if (!meetsWordRule && !meetsCharRule) {
      return res.status(400).json({
        error: `Please provide a detailed reason (minimum ${AI_ADDITIONAL_REQUEST_MIN_WORDS} words or ${AI_ADDITIONAL_REQUEST_MIN_CHARS} characters)`,
        min_words: AI_ADDITIONAL_REQUEST_MIN_WORDS,
        words_provided: reasonWords,
        min_chars: AI_ADDITIONAL_REQUEST_MIN_CHARS,
        chars_provided: reasonChars,
      });
    }
  } else if (!referral1 || !referral2) {
    return res.status(400).json({ error: 'Two referrals are required' });
  }

  const created = await database.createAiUpgradeRequest(req.googleId, {
    requestType,
    referral1,
    referral2,
    requestReason,
    note,
    now,
  });

  if (!created.ok) {
    if (created.code === 'PENDING_EXISTS') {
      return res.status(409).json({
        error: created.error || 'A pending request already exists',
        request: toAiUpgradeRequestResponse(created.request),
      });
    }
    return res.status(500).json({ error: created.error || 'Failed to create upgrade request' });
  }

  return res.status(201).json({
    success: true,
    request: toAiUpgradeRequestResponse(created.request),
  });
});

// User checks their latest request and active entitlement.
app.get('/api/ai/upgrade-request', socialAuth, async (req, res) => {
  if (!database.isConnected()) {
    return res.status(503).json({ error: 'Upgrade request storage unavailable' });
  }

  const now = Date.now();
  const [request, entitlement, ban, rejectedCount] = await Promise.all([
    database.getLatestAiUpgradeRequestForUser(req.googleId),
    database.getActiveAiEntitlement(req.googleId, { now }),
    database.getAiChatBan(req.googleId),
    database.countRejectedAiUpgradeRequests(req.googleId),
  ]);

  return res.json({
    request: toAiUpgradeRequestResponse(request),
    entitlement: toAiEntitlementResponse(entitlement),
    ban: toAiBanResponse(ban),
    rejected_requests_count: Math.max(0, parsePositiveInt(rejectedCount, 0)),
    rejection_ban_threshold: AI_REJECTION_BAN_THRESHOLD,
    additional_reason_min_words: AI_ADDITIONAL_REQUEST_MIN_WORDS,
    additional_reason_min_chars: AI_ADDITIONAL_REQUEST_MIN_CHARS,
    defaults: {
      approved_max_chats: AI_UPGRADE_APPROVED_MAX_CHATS,
      approved_window_days: AI_UPGRADE_APPROVED_WINDOW_DAYS,
      approved_duration_days: AI_UPGRADE_APPROVED_DURATION_DAYS,
    },
  });
});

// Admin API for reviewing AI upgrade requests
app.get('/api/admin/ai/upgrade-requests', adminAiAuth, async (req, res) => {
  const statusFilter = normalizeId(req.query.status || 'pending', 16).toLowerCase() || 'pending';
  const wantsHtml = wantsHtmlResponse(req);

  if (!database.isConnected()) {
    if (wantsHtml) {
      const html = renderAdminUpgradeRequestsPage({
        requests: [],
        statusFilter,
        error: 'Upgrade request storage unavailable',
      });
      return res.status(503).type('html').send(html);
    }
    return res.status(503).json({ error: 'Upgrade request storage unavailable' });
  }

  const limit = parsePositiveInt(req.query.limit, 100);
  const isBanStatusFilter = statusFilter === 'banned' || statusFilter === 'unbanned';

  if (isBanStatusFilter) {
    const bans = await database.listAiChatBans({ status: statusFilter, limit });
    const banByGoogleId = new Map(
      bans
        .map((ban) => [normalizeId(ban.googleId || ban.google_id || '', 256), ban])
        .filter(([googleId]) => !!googleId)
    );
    const uniqueGoogleIds = Array.from(new Set(
      bans
        .map((ban) => normalizeId(ban.googleId || ban.google_id || '', 256))
        .filter(Boolean)
    ));

    const userStatePairs = await Promise.all(
      uniqueGoogleIds.map(async (googleId) => {
        const banRecord = banByGoogleId.get(googleId) || null;
        const rejectedCount = await database.countRejectedAiUpgradeRequests(googleId);
        return [
          googleId,
          {
            is_banned: !!(banRecord && banRecord.isActive),
            ban: toAiBanResponse(banRecord),
            rejected_requests_count: Math.max(0, parsePositiveInt(rejectedCount, 0)),
            rejection_ban_threshold: AI_REJECTION_BAN_THRESHOLD,
          },
        ];
      })
    );
    const userStates = Object.fromEntries(userStatePairs);

    if (wantsHtml) {
      const html = renderAdminUpgradeRequestsPage({
        requests: [],
        bans,
        userStates,
        statusFilter,
        message: req.query.message,
        error: req.query.error,
      });
      return res.type('html').send(html);
    }

    return res.json({
      status: statusFilter,
      count: bans.length,
      users: bans.map((ban) => {
        const googleId = normalizeId(ban.googleId || ban.google_id || '', 256);
        const userState = googleId ? (userStates[googleId] || {}) : {};
        return {
          google_id: googleId || null,
          is_banned: !!(ban.isActive || Number(ban.is_active) === 1),
          banned_at_ms: Number(ban.bannedAt || ban.banned_at || 0) || null,
          banned_by: ban.bannedBy || ban.banned_by || null,
          ban_reason: ban.banReason || ban.ban_reason || null,
          unbanned_at_ms: Number(ban.unbannedAt || ban.unbanned_at || 0) || null,
          unbanned_by: ban.unbannedBy || ban.unbanned_by || null,
          unban_reason: ban.unbanReason || ban.unban_reason || null,
          updated_at_ms: Number(ban.updatedAt || ban.updated_at || 0) || null,
          rejected_requests_count: Math.max(0, parsePositiveInt(userState.rejected_requests_count, 0)),
          rejection_ban_threshold: AI_REJECTION_BAN_THRESHOLD,
        };
      }),
      user_states: userStates,
      rejection_ban_threshold: AI_REJECTION_BAN_THRESHOLD,
    });
  }

  const requests = await database.listAiUpgradeRequests({ status: statusFilter, limit });
  const uniqueGoogleIds = Array.from(new Set(
    requests
      .map((request) => normalizeId(request.googleId || request.google_id || '', 256))
      .filter(Boolean)
  ));
  const userStatePairs = await Promise.all(
    uniqueGoogleIds.map(async (googleId) => {
      const [ban, rejectedCount] = await Promise.all([
        database.getAiChatBan(googleId),
        database.countRejectedAiUpgradeRequests(googleId),
      ]);
      return [
        googleId,
        {
          is_banned: !!(ban && ban.isActive),
          ban: toAiBanResponse(ban),
          rejected_requests_count: Math.max(0, parsePositiveInt(rejectedCount, 0)),
          rejection_ban_threshold: AI_REJECTION_BAN_THRESHOLD,
        },
      ];
    })
  );
  const userStates = Object.fromEntries(userStatePairs);

  if (wantsHtml) {
    const html = renderAdminUpgradeRequestsPage({
      requests,
      userStates,
      statusFilter,
      message: req.query.message,
      error: req.query.error,
    });
    return res.type('html').send(html);
  }

  return res.json({
    status: statusFilter || 'all',
    count: requests.length,
    requests: requests.map(toAiUpgradeRequestResponse),
    user_states: userStates,
    rejection_ban_threshold: AI_REJECTION_BAN_THRESHOLD,
  });
});

app.post('/api/admin/ai/upgrade-requests/:id/approve', adminAiAuth, async (req, res) => {
  const returnStatus = normalizeId(req.query.return_status || 'pending', 16).toLowerCase() || 'pending';
  const fromHtmlForm = req.is('application/x-www-form-urlencoded') || wantsHtmlResponse(req);
  const redirectWith = (message, isError = false, statusCode = 303) => {
    const key = isError ? 'error' : 'message';
    const location = `/api/admin/ai/upgrade-requests?status=${encodeURIComponent(returnStatus)}&${key}=${encodeURIComponent(message)}`;
    return res.redirect(statusCode, location);
  };

  if (!database.isConnected()) {
    if (fromHtmlForm) return redirectWith('Upgrade request storage unavailable', true);
    return res.status(503).json({ error: 'Upgrade request storage unavailable' });
  }

  const requestId = parsePositiveInt(req.params.id, 0);
  if (!requestId) {
    if (fromHtmlForm) return redirectWith('Invalid request id', true);
    return res.status(400).json({ error: 'Invalid request id' });
  }

  const existing = await database.getAiUpgradeRequestById(requestId);
  if (!existing) {
    if (fromHtmlForm) return redirectWith('Upgrade request not found', true);
    return res.status(404).json({ error: 'Upgrade request not found' });
  }
  if (existing.status !== 'pending') {
    if (fromHtmlForm) return redirectWith('Upgrade request is not pending', true);
    return res.status(409).json({
      error: 'Upgrade request is not pending',
      request: toAiUpgradeRequestResponse(existing),
    });
  }

  const maxChats = parsePositiveInt(req.body?.max_chats, AI_UPGRADE_APPROVED_MAX_CHATS);
  const windowDays = parsePositiveInt(req.body?.window_days, AI_UPGRADE_APPROVED_WINDOW_DAYS);
  const durationDays = parsePositiveInt(req.body?.duration_days, AI_UPGRADE_APPROVED_DURATION_DAYS);
  const now = Date.now();
  const expiresAt = now + durationDays * 24 * 60 * 60 * 1000;
  const reviewedBy = normalizeId(
    req.headers['x-admin-id'] || req.body?.reviewed_by || req.body?.admin_id || 'admin',
    256
  );
  const reviewNote = normalizeId(req.body?.review_note || '', 1000);
  const requestType = normalizeId(existing.requestType || existing.request_type || 'referral', 32).toLowerCase();
  const defaultReason = requestType === 'additional'
    ? 'approved_additional_upgrade'
    : 'approved_referral_upgrade';
  const reason = normalizeId(req.body?.reason || defaultReason, 1000);

  const entitlementResult = await database.createAiEntitlement(existing.googleId, {
    maxChats,
    windowDays,
    expiresAt,
    reason,
    grantedBy: reviewedBy,
    requestId: existing.id,
    now,
  });

  if (!entitlementResult.ok || !entitlementResult.entitlement) {
    if (fromHtmlForm) return redirectWith(entitlementResult.error || 'Failed to create entitlement', true);
    return res.status(500).json({ error: entitlementResult.error || 'Failed to create entitlement' });
  }

  const reviewResult = await database.reviewAiUpgradeRequest(existing.id, {
    status: 'approved',
    reviewedBy,
    reviewNote,
    entitlementId: entitlementResult.entitlement.id,
    now,
  });

  if (!reviewResult.ok) {
    if (fromHtmlForm) return redirectWith(reviewResult.error || 'Failed to approve upgrade request', true);
    return res.status(500).json({ error: reviewResult.error || 'Failed to approve upgrade request' });
  }

  emitAiUpgradeRealtimeEvent(existing.googleId, {
    action: 'approved',
    status: 'approved',
    request_id: existing.id,
    reviewed_at_ms: now,
    review_note: reviewNote || null,
    entitlement: toAiEntitlementResponse(entitlementResult.entitlement),
    message: 'Your AI rate limit request was approved.',
  });

  if (fromHtmlForm) {
    return redirectWith(`Request #${existing.id} approved`);
  }

  return res.json({
    success: true,
    request: toAiUpgradeRequestResponse(reviewResult.request),
    entitlement: toAiEntitlementResponse(entitlementResult.entitlement),
  });
});

app.post('/api/admin/ai/upgrade-requests/:id/reject', adminAiAuth, async (req, res) => {
  const returnStatus = normalizeId(req.query.return_status || 'pending', 16).toLowerCase() || 'pending';
  const fromHtmlForm = req.is('application/x-www-form-urlencoded') || wantsHtmlResponse(req);
  const redirectWith = (message, isError = false, statusCode = 303) => {
    const key = isError ? 'error' : 'message';
    const location = `/api/admin/ai/upgrade-requests?status=${encodeURIComponent(returnStatus)}&${key}=${encodeURIComponent(message)}`;
    return res.redirect(statusCode, location);
  };

  if (!database.isConnected()) {
    if (fromHtmlForm) return redirectWith('Upgrade request storage unavailable', true);
    return res.status(503).json({ error: 'Upgrade request storage unavailable' });
  }

  const requestId = parsePositiveInt(req.params.id, 0);
  if (!requestId) {
    if (fromHtmlForm) return redirectWith('Invalid request id', true);
    return res.status(400).json({ error: 'Invalid request id' });
  }

  const reviewedBy = normalizeId(
    req.headers['x-admin-id'] || req.body?.reviewed_by || req.body?.admin_id || 'admin',
    256
  );
  const reviewNote = normalizeId(req.body?.review_note || req.body?.reason || '', 1000);
  const reviewResult = await database.reviewAiUpgradeRequest(requestId, {
    status: 'rejected',
    reviewedBy,
    reviewNote,
    now: Date.now(),
  });

  if (!reviewResult.ok) {
    if (reviewResult.code === 'NOT_FOUND') {
      if (fromHtmlForm) return redirectWith('Upgrade request not found', true);
      return res.status(404).json({ error: reviewResult.error || 'Upgrade request not found' });
    }
    if (reviewResult.code === 'NOT_PENDING') {
      if (fromHtmlForm) return redirectWith('Upgrade request is not pending', true);
      return res.status(409).json({
        error: reviewResult.error || 'Upgrade request is not pending',
        request: toAiUpgradeRequestResponse(reviewResult.request),
      });
    }
    if (fromHtmlForm) return redirectWith(reviewResult.error || 'Failed to reject upgrade request', true);
    return res.status(500).json({ error: reviewResult.error || 'Failed to reject upgrade request' });
  }

  let rejectedRequestCount = 0;
  let autoBanned = false;
  let banResponse = null;
  const rejectedGoogleId = normalizeId(reviewResult.request?.googleId || reviewResult.request?.google_id || '', 256);
  if (rejectedGoogleId) {
    const [existingBan, rejectedCountRaw] = await Promise.all([
      database.getAiChatBan(rejectedGoogleId),
      database.countRejectedAiUpgradeRequests(rejectedGoogleId),
    ]);

    rejectedRequestCount = Math.max(0, parsePositiveInt(rejectedCountRaw, 0));
    if (rejectedRequestCount > AI_REJECTION_BAN_THRESHOLD) {
      if (existingBan && existingBan.isActive) {
        banResponse = toAiBanResponse(existingBan);
      } else {
        const banResult = await database.setAiChatBan(rejectedGoogleId, {
          now: Date.now(),
          bannedBy: reviewedBy,
          banReason: `auto_ban_after_rejections:${rejectedRequestCount}`,
        });
        if (banResult.ok && banResult.ban) {
          autoBanned = true;
          banResponse = toAiBanResponse(banResult.ban);
        }
      }
    }
  }

  emitAiUpgradeRealtimeEvent(rejectedGoogleId, {
    action: 'rejected',
    status: 'rejected',
    request_id: requestId,
    reviewed_at_ms: Date.now(),
    review_note: reviewNote || null,
    rejected_requests_count: rejectedRequestCount,
    rejection_ban_threshold: AI_REJECTION_BAN_THRESHOLD,
    auto_banned: autoBanned,
    ban: banResponse,
    message: autoBanned
      ? 'Your AI rate limit request was rejected and AI chat access is now blocked.'
      : 'Your AI rate limit request was rejected.',
  });

  if (fromHtmlForm) {
    const suffix = autoBanned ? ` and user auto-banned (rejections: ${rejectedRequestCount})` : '';
    return redirectWith(`Request #${requestId} rejected${suffix}`);
  }

  return res.json({
    success: true,
    request: toAiUpgradeRequestResponse(reviewResult.request),
    rejected_requests_count: rejectedRequestCount,
    rejection_ban_threshold: AI_REJECTION_BAN_THRESHOLD,
    auto_banned: autoBanned,
    ban: banResponse,
  });
});

app.post('/api/admin/ai/users/:googleId/ban', adminAiAuth, async (req, res) => {
  const returnStatus = normalizeId(req.query.return_status || 'pending', 16).toLowerCase() || 'pending';
  const fromHtmlForm = req.is('application/x-www-form-urlencoded') || wantsHtmlResponse(req);
  const redirectWith = (message, isError = false, statusCode = 303) => {
    const key = isError ? 'error' : 'message';
    const location = `/api/admin/ai/upgrade-requests?status=${encodeURIComponent(returnStatus)}&${key}=${encodeURIComponent(message)}`;
    return res.redirect(statusCode, location);
  };

  if (!database.isConnected()) {
    if (fromHtmlForm) return redirectWith('AI ban storage unavailable', true);
    return res.status(503).json({ error: 'AI ban storage unavailable' });
  }

  const googleId = normalizeId(req.params.googleId || '', 256);
  if (!googleId) {
    if (fromHtmlForm) return redirectWith('Invalid user id', true);
    return res.status(400).json({ error: 'Invalid user id' });
  }

  const bannedBy = normalizeId(
    req.headers['x-admin-id'] || req.body?.reviewed_by || req.body?.admin_id || 'admin',
    256
  );
  const reason = normalizeId(req.body?.reason || req.body?.review_note || 'manual_admin_ban', 1000);
  const result = await database.setAiChatBan(googleId, {
    now: Date.now(),
    bannedBy,
    banReason: reason,
  });

  if (!result.ok) {
    if (fromHtmlForm) return redirectWith(result.error || 'Failed to ban user', true);
    return res.status(500).json({ error: result.error || 'Failed to ban user' });
  }

  emitAiUpgradeRealtimeEvent(googleId, {
    action: 'banned',
    status: 'banned',
    ban: toAiBanResponse(result.ban),
    message: 'AI chat access has been blocked by admin.',
  });

  if (fromHtmlForm) {
    return redirectWith(`User ${googleId} banned from AI chat`);
  }

  return res.json({
    success: true,
    ban: toAiBanResponse(result.ban),
  });
});

app.post('/api/admin/ai/users/:googleId/unban', adminAiAuth, async (req, res) => {
  const returnStatus = normalizeId(req.query.return_status || 'pending', 16).toLowerCase() || 'pending';
  const fromHtmlForm = req.is('application/x-www-form-urlencoded') || wantsHtmlResponse(req);
  const redirectWith = (message, isError = false, statusCode = 303) => {
    const key = isError ? 'error' : 'message';
    const location = `/api/admin/ai/upgrade-requests?status=${encodeURIComponent(returnStatus)}&${key}=${encodeURIComponent(message)}`;
    return res.redirect(statusCode, location);
  };

  if (!database.isConnected()) {
    if (fromHtmlForm) return redirectWith('AI ban storage unavailable', true);
    return res.status(503).json({ error: 'AI ban storage unavailable' });
  }

  const googleId = normalizeId(req.params.googleId || '', 256);
  if (!googleId) {
    if (fromHtmlForm) return redirectWith('Invalid user id', true);
    return res.status(400).json({ error: 'Invalid user id' });
  }

  const unbannedBy = normalizeId(
    req.headers['x-admin-id'] || req.body?.reviewed_by || req.body?.admin_id || 'admin',
    256
  );
  const reason = normalizeId(req.body?.reason || req.body?.review_note || 'manual_admin_unban', 1000);
  const result = await database.clearAiChatBan(googleId, {
    now: Date.now(),
    unbannedBy,
    unbanReason: reason,
  });

  if (!result.ok) {
    if (fromHtmlForm) return redirectWith(result.error || 'Failed to unban user', true);
    return res.status(500).json({ error: result.error || 'Failed to unban user' });
  }

  emitAiUpgradeRealtimeEvent(googleId, {
    action: 'unbanned',
    status: 'unbanned',
    code: result.code || null,
    message: 'AI chat access has been restored by admin.',
  });

  if (fromHtmlForm) {
    if (result.code === 'NOT_BANNED') {
      return redirectWith(`User ${googleId} was not banned`);
    }
    return redirectWith(`User ${googleId} unbanned`);
  }

  return res.json({
    success: true,
    code: result.code || null,
    ban: toAiBanResponse(result.ban),
  });
});

app.get('/api/admin/ai/entitlements', adminAiAuth, async (req, res) => {
  if (!database.isConnected()) {
    return res.status(503).json({ error: 'Entitlement storage unavailable' });
  }

  const status = normalizeId(req.query.status || 'active', 16).toLowerCase();
  const limit = parsePositiveInt(req.query.limit, 100);
  const entitlements = await database.listAiEntitlements({
    status,
    limit,
    now: Date.now(),
  });

  return res.json({
    status: status || 'all',
    count: entitlements.length,
    entitlements: entitlements.map(toAiEntitlementResponse),
    base_policy: {
      max_chats: AI_FREE_MAX_CHATS,
      window_days: AI_FREE_WINDOW_DAYS,
    },
  });
});

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
    const { displayName, avatarUrl } = req.body;
    const profile = await social.updateProfile(req.googleId, req.accessToken, { displayName, avatarUrl });
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
    const online = social.getOnlineFriends(req.googleId);
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
    const { contentType, genre, userId } = req.query;
    const activities = await social.getFriendsActivity(req.googleId, req.accessToken, {
      contentType, genre, userId
    });
    res.json(activities);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get activity feed' });
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
    const watching = social.getFriendsCurrentlyWatching(req.googleId);
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

// Create a new Watch Together room
app.post('/api/watchtogether/rooms', (req, res) => {
  const { media_id, media_title, host_nickname } = req.body;

  if (!media_id || !media_title || !host_nickname) {
    return res.status(400).json({ error: 'media_id, media_title, and host_nickname required' });
  }

  // Generate unique room code
  let code;
  do {
    code = generateRoomCode();
  } while (rooms.has(code));

  const hostId = uuidv4();
  const room = {
    code,
    media_id,
    media_title,
    host_id: hostId,
    state: 'waiting', // waiting, playing, paused
    current_position: 0,
    is_paused: true,
    position_updated_at: Date.now(),
    sync_mode: WT_SYNC_MODE,
    participants: new Map(),
    created_at: Date.now(),
    lastActivity: Date.now(),
    syncInterval: null,
    pingInterval: null,
  };

  // Add host as first participant
  room.participants.set(hostId, {
    id: hostId,
    nickname: host_nickname,
    is_host: true,
    is_ready: false,
    joined_at: Date.now(),
    ws: null,
    rtt: 0,
    rttAvg: 0,
    lastPosition: 0,
    lastPaused: true,
    lastStateReport: Date.now(),
    disconnectTimer: null,
    disconnected_at: null,
  });

  rooms.set(code, room);
  wtDebugLog(`[WT] Room created: ${code} by ${host_nickname}`);

  res.json({
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
});

// Get room info
app.get('/api/watchtogether/rooms/:code', (req, res) => {
  const { code } = req.params;
  const room = rooms.get(code.toUpperCase());

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
app.delete('/api/watchtogether/rooms/:code', (req, res) => {
  const { code } = req.params;
  const room = rooms.get(code.toUpperCase());

  if (!room) {
    return res.status(404).json({ error: 'Room not found' });
  }

  // Close all WebSocket connections
  for (const participant of room.participants.values()) {
    if (participant.ws && participant.ws.readyState === 1) {
      participant.ws.close(1000, 'Room closed');
    }
  }

  stopRoomSyncTimers(room);
  rooms.delete(code.toUpperCase());
  wtDebugLog(`[WT] Room deleted: ${code}`);

  res.json({ success: true });
});

// Step 1: Initiate OAuth flow
app.get('/auth/google', (req, res) => {
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
  authUrl.searchParams.set('scope', SCOPES);
  authUrl.searchParams.set('access_type', 'offline');
  authUrl.searchParams.set('prompt', 'consent');
  authUrl.searchParams.set('state', state);

  wtDebugLog('Redirecting to Google with redirect_uri:', redirectUri);
  res.redirect(authUrl.toString());
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
      console.error('Token error:', tokens);
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
    // Verify token with Google
    const userInfoRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });

    if (!userInfoRes.ok) {
      ws.close(1008, 'Invalid access token');
      return;
    }

    const userInfo = await userInfoRes.json();
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

  ws.on('message', (data) => {
    try {
      const message = JSON.parse(data.toString());

      // Handle room creation first (no room code needed)
      if (message.type === 'create') {
        const { media_title, media_id, nickname, client_id } = message;

        if (!media_id || !media_title || !nickname) {
          ws.send(JSON.stringify({ type: 'error', message: 'media_id, media_title, and nickname required' }));
          return;
        }

        // Generate unique room code
        let newCode;
        do {
          newCode = generateRoomCode();
        } while (rooms.has(newCode));

        const hostId = client_id || uuidv4();
        const room = {
          code: newCode,
          media_id,
          media_title,
          host_id: hostId,
          state: 'waiting',
          current_position: 0,
          is_paused: true,
          position_updated_at: Date.now(), // Track when position was last set
          sync_mode: WT_SYNC_MODE,
          participants: new Map(),
          created_at: Date.now(),
          lastActivity: Date.now(),
          syncInterval: null, // Will hold the periodic state broadcast timer
          pingInterval: null, // Will hold the periodic ping timer
        };

        // Add host as first participant
        room.participants.set(hostId, {
          id: hostId,
          nickname: nickname,
          is_host: true,
          is_ready: false,
          joined_at: Date.now(),
          ws: ws,
          rtt: 0, // Round-trip time in ms
          rttAvg: 0, // Smoothed RTT (moving average)
          lastPosition: 0, // Last reported position
          lastPaused: true, // Last reported pause state
          lastStateReport: Date.now(),
          disconnectTimer: null,
          disconnected_at: null,
        });

        // Start periodic ping + state broadcast for this room
        startRoomSyncTimers(room);

        rooms.set(newCode, room);
        roomCode = newCode;
        currentRoom = room;
        participantId = hostId;

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

      if (!room) {
        ws.send(JSON.stringify({ type: 'error', message: 'Room not found' }));
        return;
      }

      room.lastActivity = Date.now();
      currentRoom = room;

      switch (message.type) {
        case 'join': {
          // Join room with nickname and client_id
          const { nickname, client_id, media_id } = message;
          const normalizedNickname = (nickname || '').toString().trim();

          if (!client_id || !normalizedNickname) {
            ws.send(JSON.stringify({ type: 'error', message: 'client_id and nickname are required to join' }));
            break;
          }

          // Enforce media compatibility for consistent sync
          if (media_id !== undefined && Number(media_id) !== Number(room.media_id)) {
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
          break;
        }

        case 'ready': {
          // Participant is ready to start
          const participant = room.participants.get(participantId);
          if (participant) {
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
            room.state = 'playing';
            room.is_paused = false;
            room.current_position = message.position ?? 0;
            room.position_updated_at = Date.now();

            wtDebugLog(`[WT] Playback started in room ${room.code}`);

            broadcastToRoom(room, {
              type: 'playback_started',
              position: room.current_position,
              timestamp: Date.now()
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

          const now = Date.now();
          if (command.position !== undefined && command.position !== null) {
            room.current_position = command.position;
          }
          room.position_updated_at = now;

          if (command.action === 'play') {
            room.state = 'playing';
            room.is_paused = false;
          }
          if (command.action === 'pause') {
            room.state = 'paused';
            room.is_paused = true;
          }

          // Broadcast to ALL participants (including sender with a flag)
          // Each client uses ignoringOnTheFly to suppress echo
          for (const [id, p] of room.participants) {
            if (p.ws && p.ws.readyState === 1) {
              const msg = {
                type: 'sync',
                command,
                from: participantId,
                timestamp: now,
                is_echo: id === participantId, // Let sender know this is their own echo
              };
              p.ws.send(JSON.stringify(msg));
            }
          }
          break;
        }

        case 'state_report': {
          // Continuous state report from client (sent every ~1s)
          // This is the Syncplay-style "State" message
          const participant = room.participants.get(participantId);
          if (participant) {
            participant.lastPosition = message.position ?? participant.lastPosition;
            participant.lastPaused = message.paused !== undefined ? message.paused : participant.lastPaused;
            participant.lastStateReport = Date.now();
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
          handleParticipantLeave(room, participantId);
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

  ws.on('close', () => {
    wtDebugLog(`[WT] WebSocket closed for participant: ${participantId}`);
    if (currentRoom && participantId) {
      handleSocketClose(currentRoom, participantId, ws);
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

function handleSocketClose(room, participantId, ws) {
  const participant = room.participants.get(participantId);
  if (!participant) return;

  // If participant already reconnected with a newer socket, ignore stale close.
  if (participant.ws !== ws) {
    return;
  }

  participant.ws = null;
  participant.disconnected_at = Date.now();

  if (participant.disconnectTimer) {
    clearTimeout(participant.disconnectTimer);
  }

  participant.disconnectTimer = setTimeout(() => {
    handleParticipantLeave(room, participantId);
  }, DISCONNECT_GRACE_MS);
}

function handleParticipantLeave(room, participantId) {
  const participant = room.participants.get(participantId);
  if (!participant) return;

  if (participant.disconnectTimer) {
    clearTimeout(participant.disconnectTimer);
    participant.disconnectTimer = null;
  }

  const wasHost = participant.is_host;
  room.participants.delete(participantId);

  wtDebugLog(`[WT] ${participant.nickname} left room ${room.code}`);

  // If host left, assign new host or close room
  if (wasHost && room.participants.size > 0) {
    const newHost = room.participants.values().next().value;
    newHost.is_host = true;
    room.host_id = newHost.id;
    wtDebugLog(`[WT] New host: ${newHost.nickname}`);
  }

  // If room is empty, delete it and stop timers
  if (room.participants.size === 0) {
    stopRoomSyncTimers(room);
    rooms.delete(room.code);
    wtDebugLog(`[WT] Room ${room.code} deleted (empty)`);
    return;
  }

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

  server.listen(PORT, () => {
    console.log(`StreamVault Auth Server running on port ${PORT}`);
    console.log(`WebSocket endpoint: ws://localhost:${PORT}/ws/watchtogether/{roomCode}`);
    console.log(`Database connected: ${database.isConnected()}`);
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
    const missingAiConfig = getMissingAiConfig();
    if (missingAiConfig.length > 0) {
      console.warn(`[AI] AI proxy disabled. Missing/invalid env: ${missingAiConfig.join(', ')}`);
    } else {
      console.log(`[AI] Signed proxy enabled -> ${resolveAiUpstreamUrl(AI_WRAPPER_URL)}`);
      console.log(`[AI] OpenAI compatible mode: ${AI_OPENAI_COMPAT_MODE} (model: ${AI_DEFAULT_MODEL})`);
      console.log(`[AI] Identity brand: ${AI_BRAND_NAME}`);
      console.log(`[AI] Free tier: ${AI_FREE_MAX_CHATS} chats per ${AI_FREE_WINDOW_DAYS} day(s)`);
      console.log(`[AI] Movie-only mode (hardcoded): ${AI_MOVIE_ONLY_HARDCODED}`);
      console.log(`[AI] Movie websearch enrichment: ${AI_MOVIE_WEBSEARCH_ENABLED} (timeout ${AI_MOVIE_WEB_CONTEXT_TIMEOUT_MS}ms)`);
      console.log(`[AI] Currency output policy: INR only (USD->INR rate ${AI_USD_TO_INR_RATE})`);
      console.log(`[AI] Timezone policy: IST (${AI_IST_TIMEZONE})`);
      console.log(`[AI] Additional request minimum reason length: ${AI_ADDITIONAL_REQUEST_MIN_WORDS} words`);
      console.log(`[AI] Additional request character fallback: ${AI_ADDITIONAL_REQUEST_MIN_CHARS} chars`);
      console.log(`[AI] Auto-ban threshold: more than ${AI_REJECTION_BAN_THRESHOLD} rejected upgrade requests`);
      console.log(
        `[AI] Approved upgrade default: ${AI_UPGRADE_APPROVED_MAX_CHATS} chats per ${AI_UPGRADE_APPROVED_WINDOW_DAYS} day(s) for ${AI_UPGRADE_APPROVED_DURATION_DAYS} day(s)`
      );
      if (!AI_ADMIN_API_KEY) {
        console.warn('[AI] AI admin review API disabled until AI_ADMIN_API_KEY is configured');
      } else {
        console.log('[AI] AI admin review API enabled');
      }
      if (AI_ALLOWED_ORIGINS.size > 0) {
        console.log(`[AI] Allowed browser origins: ${Array.from(AI_ALLOWED_ORIGINS).join(', ')}`);
      }
      if (!database.isConnected()) {
        if (AI_ALLOW_UNPERSISTED_LIMITS) {
          console.warn('[AI] Using in-memory fallback limits (non-persistent). Configure Turso for persistent quota enforcement.');
        } else {
          console.warn('[AI] Persistent quota storage unavailable. AI requests will be blocked until Turso is connected.');
        }
      }
    }
  });
})();
