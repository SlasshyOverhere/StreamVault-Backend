# StreamVault Auth Server

OAuth proxy server for StreamVault desktop app. This server handles Google OAuth flow securely, keeping client credentials on the server side.

## Deployment on Render

1. Create a new **Web Service** on [Render](https://render.com)
2. Connect your GitHub repo
3. Configure:
   - **Build Command:** `npm install`
   - **Start Command:** `npm start`
4. Add environment variables:
   - `GOOGLE_CLIENT_ID` - Your Google OAuth client ID
   - `GOOGLE_CLIENT_SECRET` - Your Google OAuth client secret
   - `REDIRECT_URI` - `https://your-app-name.onrender.com/auth/callback`
   - `TMDB_ACCESS_TOKEN_1..5` - TMDB read access tokens (optional but required for TMDB proxy)
   - `AI_WRAPPER_URL` - Your internal AI wrapper endpoint
   - `AI_CLIENT_SIGNATURE_SECRET` - HMAC secret used by signed AI requests
   - `AI_FREE_MAX_CHATS` / `AI_FREE_WINDOW_DAYS` - free-tier quota (defaults: 10 chats / 7 days)
   - `AI_ADMIN_API_KEY` - bearer key for admin review API
   - `AI_UPGRADE_APPROVED_MAX_CHATS` / `AI_UPGRADE_APPROVED_WINDOW_DAYS` / `AI_UPGRADE_APPROVED_DURATION_DAYS` - default approved upgrade policy
   - `TURSO_DATABASE_URL` + `TURSO_AUTH_TOKEN` - required for persistent quota enforcement

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Service info |
| `/health` | GET | Basic health (`status`, `timestamp`, `configured`) |
| `/health/runtime` | GET | Runtime metrics (`activeRooms`, `onlineUsers`, TMDB pool stats), protected by password auth + anti-bruteforce guards |
| `/api/tmdb/*` | GET | TMDB proxy with automatic key rotation/failover |
| `/api/ai/quota` | GET | Signed endpoint to read remaining free AI chats |
| `/api/ai/chat` | POST | Signed + rate-limited AI proxy endpoint to your wrapper |
| `/api/ai/upgrade-request` | GET | User (Bearer token) reads latest upgrade request + active entitlement |
| `/api/ai/upgrade-request` | POST | User (Bearer token) submits referral-based upgrade request |
| `/api/admin/ai/upgrade-requests` | GET | Admin list of upgrade requests (`status` filter) |
| `/api/admin/ai/upgrade-requests/:id/approve` | POST | Admin approves request and grants entitlement |
| `/api/admin/ai/upgrade-requests/:id/reject` | POST | Admin rejects request |
| `/api/admin/ai/entitlements` | GET | Admin list of active/inactive entitlements |
| `/auth/google` | GET | Initiates OAuth flow |
| `/auth/callback` | GET | Handles Google callback |
| `/auth/refresh` | POST | Refreshes access token |

## AI Free-Tier Limits + Endpoint Protection

### Limit policy
- Default policy is **10 free chats per 7 days** (`AI_FREE_MAX_CHATS`, `AI_FREE_WINDOW_DAYS`).
- Quota key is a hashed fingerprint derived from request IP + device ID/hardware ID headers + optional device signature + user agent.
- Persistent quota is stored in Turso (`ai_chat_limits` table).
- If Turso is unavailable and `AI_ALLOW_UNPERSISTED_LIMITS=0`, AI requests are rejected (fail-closed).
- For OpenAI-compatible providers, set `AI_WRAPPER_URL` to your base `/v1` URL and keep `AI_OPENAI_COMPAT_MODE=1`.
- Default model is controlled by `AI_DEFAULT_MODEL` (e.g. `llama-3.1-8b-instant`).
- Assistant identity is controlled server-side by `AI_BRAND_NAME` + `AI_APP_DESCRIPTION`.
  The server injects system rules so identity/model questions return branded app identity only.

### Signed request headers (required for `/api/ai/chat` and `/api/ai/quota`)
- `x-ai-timestamp`: unix time in milliseconds
- `x-ai-nonce`: unique nonce (`[a-zA-Z0-9:_-]`, 8..128 chars)
- `x-ai-signature`: `hex(hmac_sha256(AI_CLIENT_SIGNATURE_SECRET, signature_base))`
- Optional fingerprint-strength headers:
  - `x-device-id` or `x-hardware-id` or `x-installation-id`
  - `x-device-signature` or `x-client-signature`

### Signature base string
```
<HTTP_METHOD_UPPERCASE>
<REQUEST_PATH>
<x-ai-timestamp>
<x-ai-nonce>
<sha256_hex(JSON.stringify(request_body_or_empty_object))>
```

Example path values:
- `GET /api/ai/quota` -> `/api/ai/quota`
- `POST /api/ai/chat` -> `/api/ai/chat`

Requests are rejected when:
- signature is missing/invalid
- timestamp is stale (`AI_SIGNATURE_MAX_AGE_MS`)
- nonce is replayed before nonce TTL expiry (`AI_NONCE_TTL_MS`)

## Upgrade Request Flow (No Payments)

- Users submit referral proof from Tower app via `POST /api/ai/upgrade-request` (requires Google Bearer token).
- Admin panel reviews requests via `/api/admin/ai/upgrade-requests`.
- Approving creates an entitlement override for that user (e.g. `20 chats / 3 days` for `30 days`).
- AI quota/chat endpoints automatically apply active entitlement when a valid Bearer token is sent with signed AI calls.

### Admin Web UI

- Open `http://localhost:3001/api/admin/ai/upgrade-requests` in browser.
- The endpoint serves a full HTML dashboard (cards + approve/reject forms) when requested from browser.
- Auth options:
  - Bearer: `Authorization: Bearer <AI_ADMIN_API_KEY>`
  - Browser login prompt (Basic): enter `AI_ADMIN_API_KEY` as both username and password.

## Runtime Metrics Auth

Set:
- `RUNTIME_METRICS_USERNAME`
- `RUNTIME_METRICS_PASSWORD`

When opened in a browser, `/health/runtime` now returns a Basic Auth challenge, which triggers the browser login pop-up.

Example (CLI):
`curl -u "<RUNTIME_METRICS_USERNAME>:<RUNTIME_METRICS_PASSWORD>" https://your-server/health/runtime`

Anti-bruteforce protections are built in:
- Per-IP request rate limiting (`RUNTIME_RATE_WINDOW_MS`, `RUNTIME_RATE_MAX_REQUESTS`)
- Per-IP failed-login tracking with lockout (`RUNTIME_AUTH_FAIL_WINDOW_MS`, `RUNTIME_AUTH_MAX_FAILS`, `RUNTIME_AUTH_LOCK_MS`)

## Logging Controls

- `WT_LIVE_LOGS=1` enables high-volume Watch Together/Social connection logs.
- `SOCIAL_DEBUG_LOGS=1` enables Social module debug logs (profile/folder migration details).
- `TMDB_PROXY_LOGS=0` disables TMDB proxy info logs.
- `TMDB_PROXY_DEBUG=1` enables verbose TMDB request debug logs.

Recommended production defaults:
- `WT_LIVE_LOGS=0`
- `SOCIAL_DEBUG_LOGS=0`
- `TMDB_PROXY_DEBUG=0`

## Flow

1. App opens browser to `https://your-server.onrender.com/auth/google`
2. Server redirects to Google OAuth
3. User authorizes
4. Google redirects to server's `/auth/callback`
5. Server exchanges code for tokens
6. Server redirects to `streamvault://oauth/callback?tokens=...`
7. App receives tokens via deep link
