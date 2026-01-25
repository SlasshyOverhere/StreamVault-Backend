const express = require('express');
const cors = require('cors');
const http = require('http');
const { WebSocketServer } = require('ws');
const { v4: uuidv4 } = require('uuid');
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

// ============================================
// Watch Together - Room Management
// ============================================

// In-memory room storage (use Redis in production for scaling)
const rooms = new Map();

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
  res.json({ service: 'StreamVault Auth Server', version: '1.1.0' });
});

// Health check endpoint for monitoring
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    configured: !!(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET),
    activeRooms: rooms.size
  });
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

wss.on('connection', (ws, req) => {
  // Extract room code from URL: /ws/watchtogether/ROOMCODE
  const urlParts = req.url.split('/');
  const roomCode = urlParts[urlParts.length - 1]?.split('?')[0]?.toUpperCase();

  let participantId = null;
  let currentRoom = null;

  console.log(`[WT] WebSocket connection for room: ${roomCode}`);

  ws.on('message', (data) => {
    try {
      const message = JSON.parse(data.toString());
      const room = rooms.get(roomCode);

      if (!room) {
        ws.send(JSON.stringify({ type: 'error', message: 'Room not found' }));
        ws.close();
        return;
      }

      room.lastActivity = Date.now();
      currentRoom = room;

      switch (message.type) {
        case 'join': {
          // Join room with nickname and client_id
          const { nickname, client_id } = message;

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
              ws
            };
            room.participants.set(participantId, participant);
          }

          console.log(`[WT] ${nickname} joined room ${roomCode}`);

          // Send room state to the joining participant
          ws.send(JSON.stringify({
            type: 'room_state',
            room: {
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

            // Broadcast updated room state
            broadcastToRoom(room, {
              type: 'participant_changed',
              room: getRoomState(room)
            });
          }
          break;
        }

        case 'start_playback': {
          // Only host can start playback
          const participant = room.participants.get(participantId);
          if (participant && participant.is_host) {
            room.state = 'playing';
            room.current_position = message.position || 0;

            broadcastToRoom(room, {
              type: 'playback_started',
              position: room.current_position,
              timestamp: Date.now()
            });
          }
          break;
        }

        case 'sync': {
          // Sync command from a participant
          const { command } = message;
          if (!command) break;

          room.current_position = command.position || room.current_position;
          if (command.action === 'play') room.state = 'playing';
          if (command.action === 'pause') room.state = 'paused';

          // Broadcast to all other participants
          broadcastToRoom(room, {
            type: 'sync_command',
            command,
            from: participantId,
            timestamp: Date.now()
          }, participantId);
          break;
        }

        case 'heartbeat': {
          // Update last activity and optionally sync position
          if (message.position !== undefined) {
            const participant = room.participants.get(participantId);
            if (participant) {
              participant.last_position = message.position;
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

  // If room is empty, delete it
  if (room.participants.size === 0) {
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
server.listen(PORT, () => {
  console.log(`StreamVault Auth Server running on port ${PORT}`);
  console.log(`WebSocket endpoint: ws://localhost:${PORT}/ws/watchtogether/{roomCode}`);
});
