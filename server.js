const express = require('express');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

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

// Health check
app.get('/', (req, res) => {
  const redirectUri = getRedirectUri(req);
  res.json({
    status: 'ok',
    service: 'StreamVault Auth Server',
    redirect_uri: redirectUri,
    client_id_set: !!GOOGLE_CLIENT_ID,
    client_secret_set: !!GOOGLE_CLIENT_SECRET
  });
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

  console.log('Redirecting to Google with redirect_uri:', redirectUri);
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

app.listen(PORT, () => {
  console.log(`StreamVault Auth Server running on port ${PORT}`);
});
