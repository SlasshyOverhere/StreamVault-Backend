# StreamVault Auth Server

Backend service for StreamVault desktop. It handles Google OAuth, AI proxying with signed requests and quotas, TMDB proxy failover, and social/watch-together APIs.

## About

This project is designed for native clients and trusted internal tooling. Secrets remain server-side, and feature modules can be enabled/disabled through environment variables.

## Core Features

- Google OAuth flow for desktop login and token refresh
- Signed AI endpoints with replay protection (`x-ai-timestamp`, `x-ai-nonce`, HMAC signature)
- Free-tier AI quota enforcement with Turso persistence
- Admin review panel for AI upgrade/entitlement workflow
- TMDB proxy with multi-key rotation and failure cooldowns
- Watch Together + Social APIs over HTTP and WebSocket
- Runtime metrics endpoint with Basic Auth + brute-force controls

## Tech Stack

- Node.js 18+
- Express
- WebSocket (`ws`)
- Turso/libSQL (`@libsql/client`)

## Quick Start (Local)

1. Install dependencies:
   - `npm install`
2. Create environment file:
   - `copy .env.example .env` (Windows)
   - `cp .env.example .env` (macOS/Linux)
3. Fill required values in `.env` (see Environment Variables below).
4. Start server:
   - `npm start`
5. Health check:
   - `GET http://localhost:3001/health`

## Environment Variables

### Required for server startup (recommended baseline)

- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `REDIRECT_URI`
- `RUNTIME_METRICS_PASSWORD`

### Runtime and security

- `PORT` (default fallback in code: `3001`)
- `CORS_ALLOWED_ORIGINS` (optional allowlist; empty = allow all origins)
- `RUNTIME_METRICS_USERNAME`
- `RUNTIME_RATE_WINDOW_MS`
- `RUNTIME_RATE_MAX_REQUESTS`
- `RUNTIME_AUTH_FAIL_WINDOW_MS`
- `RUNTIME_AUTH_MAX_FAILS`
- `RUNTIME_AUTH_LOCK_MS`

### AI module

- `AI_WRAPPER_URL`
- `AI_CLIENT_SIGNATURE_SECRET`
- `AI_OPENAI_COMPAT_MODE` (`0` or `1`)
- `AI_DEFAULT_MODEL`
- `AI_BRAND_NAME`
- `AI_APP_DESCRIPTION`
- `AI_WRAPPER_AUTH_HEADER` / `AI_WRAPPER_AUTH_TOKEN` (optional)
- `AI_FREE_MAX_CHATS`
- `AI_FREE_WINDOW_DAYS`
- `AI_SIGNATURE_MAX_AGE_MS`
- `AI_NONCE_TTL_MS`
- `AI_ALLOWED_ORIGINS` (browser-origin guard for AI routes)
- `AI_ADMIN_API_KEY` (required for admin endpoints)

### AI upgrade policy defaults

- `AI_UPGRADE_APPROVED_MAX_CHATS`
- `AI_UPGRADE_APPROVED_WINDOW_DAYS`
- `AI_UPGRADE_APPROVED_DURATION_DAYS`

### Persistence (strongly recommended for production)

- `TURSO_DATABASE_URL`
- `TURSO_AUTH_TOKEN`

### TMDB proxy (optional)

- `TMDB_ACCESS_TOKEN_1..5` or `TMDB_ACCESS_TOKENS`
- `TMDB_API_KEY_1..5` or `TMDB_API_KEYS`
- `TMDB_PROXY_LOGS`
- `TMDB_PROXY_DEBUG`
- `TMDB_MAX_INFLIGHT_PER_KEY`

## Endpoint Overview

| Group | Endpoint | Method | Notes |
| --- | --- | --- | --- |
| Health | `/health` | GET | Basic status |
| Health | `/health/runtime` | GET | Basic Auth protected runtime metrics |
| OAuth | `/auth/google` | GET | Start Google OAuth |
| OAuth | `/auth/callback` | GET | Handle OAuth callback |
| OAuth | `/auth/refresh` | POST | Exchange refresh token for new access token |
| TMDB | `/api/tmdb/*` | GET | Proxy + key rotation/failover |
| AI | `/api/ai/quota` | GET | Signed request required |
| AI | `/api/ai/chat` | POST | Signed + rate-limited proxy |
| AI | `/api/ai/upgrade-request` | GET/POST | User request and status |
| AI Admin | `/api/admin/ai/upgrade-requests` | GET | Review queue |
| AI Admin | `/api/admin/ai/upgrade-requests/:id/approve` | POST | Approve request |
| AI Admin | `/api/admin/ai/upgrade-requests/:id/reject` | POST | Reject request |
| AI Admin | `/api/admin/ai/entitlements` | GET | List entitlements |
| Social | `/api/social/*` | mixed | Profile, friends, activity, chat |
| WebSocket | `/ws/watchtogether/:roomCode` | WS | Watch Together sync |

## Signed AI Request Format

Required headers for `/api/ai/chat` and `/api/ai/quota`:

- `x-ai-timestamp` (unix ms)
- `x-ai-nonce` (unique request nonce)
- `x-ai-signature` (`hex(hmac_sha256(AI_CLIENT_SIGNATURE_SECRET, signature_base))`)

Signature base string:

```text
<HTTP_METHOD_UPPERCASE>
<REQUEST_PATH>
<x-ai-timestamp>
<x-ai-nonce>
<sha256_hex(JSON.stringify(request_body_or_empty_object))>
```

## Deployment (Render Example)

1. Create a new Render Web Service.
2. Connect this GitHub repository.
3. Build command: `npm install`
4. Start command: `npm start`
5. Set environment variables from `.env.example`.
6. Set `REDIRECT_URI` to your public callback URL:
   - `https://<your-service-domain>/auth/callback`

## Public Release Checklist

Before setting the repo public:

- Rotate all production secrets (OAuth, AI, DB, TMDB, admin keys)
- Verify `.env` is not tracked and `.env.example` has placeholders only
- Confirm no private URLs, IPs, or internal hostnames remain in docs/config
- Keep `RUNTIME_METRICS_PASSWORD` and `AI_ADMIN_API_KEY` set in production
- Set `CORS_ALLOWED_ORIGINS` to trusted clients (do not leave open in production)
- Enable GitHub Dependabot and secret scanning

## Security

- See `SECURITY.md` for vulnerability reporting guidelines.
- Never commit `.env` or private key/certificate files.

## Useful Scripts

- `npm start` - Run server
- `npm run dev` - Run server (same as start)
- `npm run test:watchtogether` - Watch Together sync test script
- `npm run test:wan:tauri` - WAN E2E helper script for Tauri integration
