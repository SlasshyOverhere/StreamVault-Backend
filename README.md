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

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Health check |
| `/auth/google` | GET | Initiates OAuth flow |
| `/auth/callback` | GET | Handles Google callback |
| `/auth/refresh` | POST | Refreshes access token |

## Flow

1. App opens browser to `https://your-server.onrender.com/auth/google`
2. Server redirects to Google OAuth
3. User authorizes
4. Google redirects to server's `/auth/callback`
5. Server exchanges code for tokens
6. Server redirects to `streamvault://oauth/callback?tokens=...`
7. App receives tokens via deep link
