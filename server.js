const express = require('express');
const cors = require('cors');
const http = require('http');
const { WebSocketServer } = require('ws');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const social = require('./social');
const database = require('./database');

const app = express();
app.use(cors());
app.use(express.json());

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
// Watch Together - Room Management
// ============================================

// In-memory room storage (use Redis in production for scaling)
const rooms = new Map();

// Syncplay-inspired constants
const SYNC_BROADCAST_INTERVAL = 1000; // Broadcast state updates every 1s
const PING_INTERVAL = 2000; // Ping clients every 2s for RTT measurement
const PING_MOVING_AVG_WEIGHT = 0.85; // Moving average weight for RTT smoothing

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
      console.log(`[WT] Cleaning up inactive room: ${code}`);
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
  res.json({ service: 'StreamVault Auth Server', version: '1.2.0', features: ['oauth', 'watchtogether', 'social'] });
});

// Health check endpoint for monitoring
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    configured: !!(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET),
    activeRooms: rooms.size,
    onlineUsers: social.onlineUsers.size
  });
});

// ============================================
// Social API Endpoints
// ============================================

// Auth middleware for social endpoints
const socialAuth = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid authorization header' });
  }

  const accessToken = authHeader.split(' ')[1];

  try {
    // Verify token with Google
    const userInfoRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });

    if (!userInfoRes.ok) {
      return res.status(401).json({ error: 'Invalid access token' });
    }

    const userInfo = await userInfoRes.json();
    req.googleId = userInfo.id;
    req.accessToken = accessToken;
    req.userInfo = userInfo;
    next();
  } catch (error) {
    console.error('[Social Auth] Error:', error);
    res.status(401).json({ error: 'Authentication failed' });
  }
};

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
    participants: new Map(),
    created_at: Date.now(),
    lastActivity: Date.now()
  };

  // Add host as first participant
  room.participants.set(hostId, {
    id: hostId,
    nickname: host_nickname,
    is_host: true,
    is_ready: false,
    joined_at: Date.now(),
    ws: null
  });

  rooms.set(code, room);
  console.log(`[WT] Room created: ${code} by ${host_nickname}`);

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

  res.json({
    code: room.code,
    media_id: room.media_id,
    media_title: room.media_title,
    host_id: room.host_id,
    state: room.state,
    current_position: room.current_position,
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

  rooms.delete(code.toUpperCase());
  console.log(`[WT] Room deleted: ${code}`);

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

// ============================================
// HTTP Server & WebSocket Setup
// ============================================

const server = http.createServer(app);

// WebSocket server for Watch Together
const wss = new WebSocketServer({ server, path: '/ws/watchtogether' });

// WebSocket server for Social features
const socialWss = new WebSocketServer({ server, path: '/ws/social' });

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

    console.log(`[Social WS] User connected: ${userInfo.email}`);

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

  console.log(`[WT] WebSocket connection, room code: ${roomCode || 'none (will create)'}`);

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
          pendingPings: new Map(), // pingId -> sendTimestamp
          lastPosition: 0, // Last reported position
          lastPaused: true, // Last reported pause state
          lastStateReport: Date.now(),
        });

        // Start periodic ping + state broadcast for this room
        startRoomSyncTimers(room);

        rooms.set(newCode, room);
        roomCode = newCode;
        currentRoom = room;
        participantId = hostId;

        console.log(`[WT] Room created via WebSocket: ${newCode} by ${nickname}`);

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

          // Check if this is an existing participant reconnecting
          let participant = room.participants.get(client_id);

          if (participant) {
            // Reconnecting
            participant.ws = ws;
            participantId = client_id;
          } else {
            // New participant
            participantId = client_id || uuidv4();
            participant = {
              id: participantId,
              nickname: nickname || 'Guest',
              is_host: false,
              is_ready: false,
              joined_at: Date.now(),
              media_id: media_id,
              ws,
              rtt: 0,
              rttAvg: 0,
              pendingPings: new Map(),
              lastPosition: 0,
              lastPaused: true,
              lastStateReport: Date.now(),
            };
            room.participants.set(participantId, participant);
          }

          console.log(`[WT] ${nickname} joined room ${room.code}`);

          // Send room_joined response to the joining participant
          ws.send(JSON.stringify({
            type: 'room_joined',
            room: {
              code: room.code,
              media_id: room.media_id,
              media_title: room.media_title,
              host_id: room.host_id,
              is_playing: room.state === 'playing',
              current_position: room.current_position,
              participants: Array.from(room.participants.values()).map(p => ({
                id: p.id,
                nickname: p.nickname,
                is_host: p.is_host,
                is_ready: p.is_ready
              }))
            }
          }));

          // Notify others
          broadcastToRoom(room, {
            type: 'participant_joined',
            participant: {
              id: participantId,
              nickname: participant.nickname,
              is_host: participant.is_host,
              is_ready: participant.is_ready
            }
          }, participantId);
          break;
        }

        case 'ready': {
          // Participant is ready to start
          const participant = room.participants.get(participantId);
          if (participant) {
            participant.is_ready = true;
            if (message.duration) {
              participant.duration = message.duration;
            }

            console.log(`[WT] ${participant.nickname} is ready in room ${room.code}`);

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
          if (participant && participant.is_host) {
            room.state = 'playing';
            room.is_paused = false;
            room.current_position = message.position || 0;
            room.position_updated_at = Date.now();

            console.log(`[WT] Playback started in room ${room.code}`);

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

          const now = Date.now();
          room.current_position = command.position || room.current_position;
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
            participant.lastPosition = message.position || 0;
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
          console.log(`[WT] Unknown message type: ${message.type}`);
      }
    } catch (err) {
      console.error('[WT] Message parse error:', err);
      ws.send(JSON.stringify({ type: 'error', message: 'Invalid message format' }));
    }
  });

  ws.on('close', () => {
    console.log(`[WT] WebSocket closed for participant: ${participantId}`);
    if (currentRoom && participantId) {
      handleParticipantLeave(currentRoom, participantId);
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
}

function handleParticipantLeave(room, participantId) {
  const participant = room.participants.get(participantId);
  if (!participant) return;

  const wasHost = participant.is_host;
  room.participants.delete(participantId);

  console.log(`[WT] ${participant.nickname} left room ${room.code}`);

  // If host left, assign new host or close room
  if (wasHost && room.participants.size > 0) {
    const newHost = room.participants.values().next().value;
    newHost.is_host = true;
    room.host_id = newHost.id;
    console.log(`[WT] New host: ${newHost.nickname}`);
  }

  // If room is empty, delete it and stop timers
  if (room.participants.size === 0) {
    stopRoomSyncTimers(room);
    rooms.delete(room.code);
    console.log(`[WT] Room ${room.code} deleted (empty)`);
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
  return {
    code: room.code,
    media_id: room.media_id,
    media_title: room.media_title,
    host_id: room.host_id,
    state: room.state,
    current_position: room.current_position,
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
  });
})();
