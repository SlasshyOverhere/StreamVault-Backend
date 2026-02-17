/**
 * StreamVault Social Module
 *
 * Handles social features with data stored in user's Google Drive:
 * - User profiles and privacy settings
 * - Friends management
 * - Activity feed
 * - Real-time chat (stored in Google Drive)
 * - "Currently watching" status
 */

const { v4: uuidv4 } = require('uuid');
const database = require('./database');

const SOCIAL_DEBUG_LOGS = process.env.SOCIAL_DEBUG_LOGS === '1';

function socialDebugLog(...args) {
  if (!SOCIAL_DEBUG_LOGS) return;
  console.log(...args);
}

// In-memory caches (will be synced with Google Drive)
const userProfiles = new Map();
const friendships = new Map();
const friendRequests = new Map();
const onlineUsers = new Map(); // Maps googleId -> { ws, lastSeen, currentlyWatching }
const activeChats = new Map(); // Maps chatId -> Set of participant websockets

// Google Drive folder names
const SOCIAL_FOLDER = 'StreamVault_Social';
const PROFILE_FILE = 'profile.json';
const FRIENDS_FILE = 'friends.json';
const ACTIVITY_FILE = 'activity.json';
const CHAT_FOLDER = 'chats';

/**
 * Generate username from email
 */
function generateUsernameFromEmail(email) {
  socialDebugLog('[Social] Generating username from email:', email);
  if (!email) return `user_${Date.now()}`;
  const username = email.split('@')[0]?.toLowerCase().replace(/[^a-z0-9_]/g, '_');
  socialDebugLog('[Social] Generated username:', username);
  return username || `user_${Date.now()}`;
}

/**
 * Initialize social features for a user
 */
async function initUserSocial(googleId, accessToken, userInfo) {
  socialDebugLog('[Social] initUserSocial called for:', googleId);
  socialDebugLog('[Social] userInfo:', JSON.stringify(userInfo, null, 2));

  try {
    // Check if social folder exists in Drive
    socialDebugLog('[Social] Getting or creating social folder...');
    const folderId = await getOrCreateSocialFolder(accessToken);
    socialDebugLog('[Social] Folder ID:', folderId);

    // Load or create profile
    socialDebugLog('[Social] Loading profile...');
    let profile = await loadFileFromDrive(accessToken, folderId, PROFILE_FILE);
    socialDebugLog('[Social] Existing profile:', profile ? JSON.stringify(profile, null, 2) : 'not found');

    let needsSave = false;

    if (!profile) {
      socialDebugLog('[Social] Creating new profile...');
      // Generate username from email (remove @gmail.com, @domain.com, etc.)
      const username = generateUsernameFromEmail(userInfo.email);

      profile = {
        id: googleId,
        username: username,
        displayName: userInfo.name || username,
        email: userInfo.email,
        avatarUrl: userInfo.picture || null,
        bio: '',
        favoriteGenre: '',
        location: '',
        joinedAt: Date.now(),
        createdAt: Date.now(),
        privacySettings: {
          showStatsToFriends: true,
          showActivityToFriends: true,
          showCurrentlyWatching: true,
          allowFriendRequests: true,
          showEmail: false,
          showLocation: false
        },
        stats: {
          totalWatchTime: 0,
          moviesWatched: 0,
          tvEpisodesWatched: 0,
          favoriteGenres: [],
          lastUpdated: Date.now()
        }
      };
      needsSave = true;
    } else {
      // Migration: Update email from userInfo if missing
      if (!profile.email && userInfo.email) {
        socialDebugLog('[Social] Profile missing email, adding from userInfo...');
        profile.email = userInfo.email;
        needsSave = true;
      }

      // Migration: Check if existing profile is missing username
      if (!profile.username || profile.username.trim() === '') {
        socialDebugLog('[Social] Profile missing username, generating from email...');
        const emailToUse = profile.email || userInfo.email;
        profile.username = generateUsernameFromEmail(emailToUse);
        needsSave = true;
      }

      // Migration: Update avatar from userInfo if missing
      if (!profile.avatarUrl && userInfo.picture) {
        socialDebugLog('[Social] Profile missing avatar, adding from userInfo...');
        profile.avatarUrl = userInfo.picture;
        needsSave = true;
      }

      // Ensure all new fields exist (migration for old profiles)
      if (profile.bio === undefined) {
        profile.bio = '';
        needsSave = true;
      }
      if (profile.favoriteGenre === undefined) {
        profile.favoriteGenre = '';
        needsSave = true;
      }
      if (profile.location === undefined) {
        profile.location = '';
        needsSave = true;
      }
      if (profile.joinedAt === undefined) {
        profile.joinedAt = profile.createdAt || Date.now();
        needsSave = true;
      }
    }

    socialDebugLog('[Social] Profile after migration:', JSON.stringify(profile, null, 2));
    socialDebugLog('[Social] Needs save:', needsSave);

    if (needsSave) {
      const saved = await saveFileToDrive(accessToken, folderId, PROFILE_FILE, profile);
      socialDebugLog('[Social] Profile save result:', saved);
    }

    userProfiles.set(googleId, { ...profile, folderId, accessToken });
    socialDebugLog('[Social] Profile cached, returning:', profile.displayName, 'username:', profile.username);

    // Register/update user in Turso for persistent search
    await database.upsertUser({
      googleId,
      username: profile.username,
      displayName: profile.displayName,
      email: profile.email,
      avatarUrl: profile.avatarUrl,
      allowFriendRequests: profile.privacySettings?.allowFriendRequests !== false,
      createdAt: profile.createdAt
    });

    return profile;
  } catch (error) {
    console.error('[Social] Init error:', error.message || error);
    throw error;
  }
}

/**
 * Google Drive API helpers
 */
async function getOrCreateSocialFolder(accessToken) {
  try {
    const searchUrl = `https://www.googleapis.com/drive/v3/files?q=name='${SOCIAL_FOLDER}' and mimeType='application/vnd.google-apps.folder' and trashed=false&fields=files(id,name)`;

    socialDebugLog('[Social] Searching for folder...');
    const searchRes = await fetch(searchUrl, {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });

    if (!searchRes.ok) {
      const errorText = await searchRes.text();
      console.error('[Social] Folder search failed:', searchRes.status, errorText);
      throw new Error(`Drive API error: ${searchRes.status}`);
    }

    const searchData = await searchRes.json();
    socialDebugLog('[Social] Search result:', searchData);

    if (searchData.files && searchData.files.length > 0) {
      socialDebugLog('[Social] Found existing folder:', searchData.files[0].id);
      return searchData.files[0].id;
    }

    // Create folder
    socialDebugLog('[Social] Creating new folder...');
    const createRes = await fetch('https://www.googleapis.com/drive/v3/files', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        name: SOCIAL_FOLDER,
        mimeType: 'application/vnd.google-apps.folder'
      })
    });

    if (!createRes.ok) {
      const errorText = await createRes.text();
      console.error('[Social] Folder creation failed:', createRes.status, errorText);
      throw new Error(`Drive API error: ${createRes.status}`);
    }

    const folder = await createRes.json();
    socialDebugLog('[Social] Created folder:', folder.id);
    return folder.id;
  } catch (error) {
    console.error('[Social] getOrCreateSocialFolder error:', error.message || error);
    throw error;
  }
}

async function loadFileFromDrive(accessToken, folderId, fileName) {
  try {
    const searchUrl = `https://www.googleapis.com/drive/v3/files?q=name='${fileName}' and '${folderId}' in parents and trashed=false&fields=files(id)`;
    const searchRes = await fetch(searchUrl, {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    const searchData = await searchRes.json();

    if (!searchData.files || searchData.files.length === 0) {
      return null;
    }

    const fileId = searchData.files[0].id;
    const contentRes = await fetch(`https://www.googleapis.com/drive/v3/files/${fileId}?alt=media`, {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    return await contentRes.json();
  } catch (error) {
    console.error('[Social] Load file error:', error);
    return null;
  }
}

async function saveFileToDrive(accessToken, folderId, fileName, data) {
  try {
    // Check if file exists
    const searchUrl = `https://www.googleapis.com/drive/v3/files?q=name='${fileName}' and '${folderId}' in parents and trashed=false&fields=files(id)`;
    const searchRes = await fetch(searchUrl, {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    const searchData = await searchRes.json();

    const content = JSON.stringify(data, null, 2);

    if (searchData.files && searchData.files.length > 0) {
      // Update existing file
      const fileId = searchData.files[0].id;
      await fetch(`https://www.googleapis.com/upload/drive/v3/files/${fileId}?uploadType=media`, {
        method: 'PATCH',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        },
        body: content
      });
    } else {
      // Create new file with multipart upload
      const boundary = '-------314159265358979323846';
      const metadata = {
        name: fileName,
        parents: [folderId],
        mimeType: 'application/json'
      };

      const multipartBody =
        `--${boundary}\r\n` +
        `Content-Type: application/json; charset=UTF-8\r\n\r\n` +
        `${JSON.stringify(metadata)}\r\n` +
        `--${boundary}\r\n` +
        `Content-Type: application/json\r\n\r\n` +
        `${content}\r\n` +
        `--${boundary}--`;

      await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': `multipart/related; boundary=${boundary}`
        },
        body: multipartBody
      });
    }
    return true;
  } catch (error) {
    console.error('[Social] Save file error:', error);
    return false;
  }
}

/**
 * Profile Management
 */
async function getProfile(googleId, accessToken) {
  if (userProfiles.has(googleId)) {
    const cached = userProfiles.get(googleId);
    return {
      id: cached.id,
      username: cached.username,
      displayName: cached.displayName,
      email: cached.email,
      avatarUrl: cached.avatarUrl,
      bio: cached.bio,
      favoriteGenre: cached.favoriteGenre,
      location: cached.location,
      joinedAt: cached.joinedAt,
      createdAt: cached.createdAt,
      privacySettings: cached.privacySettings,
      stats: cached.stats
    };
  }

  const folderId = await getOrCreateSocialFolder(accessToken);
  const profile = await loadFileFromDrive(accessToken, folderId, PROFILE_FILE);
  if (profile) {
    userProfiles.set(googleId, { ...profile, folderId, accessToken });
  }
  return profile;
}

async function updateProfile(googleId, accessToken, updates) {
  const cached = userProfiles.get(googleId);
  if (!cached) {
    throw new Error('Profile not initialized');
  }

  const updatedProfile = {
    ...cached,
    ...updates,
    id: googleId // Prevent ID change
  };

  await saveFileToDrive(accessToken, cached.folderId, PROFILE_FILE, updatedProfile);
  userProfiles.set(googleId, updatedProfile);
  return updatedProfile;
}

async function updatePrivacySettings(googleId, accessToken, privacySettings) {
  return updateProfile(googleId, accessToken, { privacySettings });
}

async function updateStats(googleId, accessToken, statsUpdate) {
  const cached = userProfiles.get(googleId);
  if (!cached) return null;

  const stats = {
    ...cached.stats,
    ...statsUpdate,
    lastUpdated: Date.now()
  };

  return updateProfile(googleId, accessToken, { stats });
}

/**
 * Friends Management
 */
async function getFriends(googleId, accessToken) {
  const cached = userProfiles.get(googleId);
  if (!cached) return [];

  const friendsData = await loadFileFromDrive(accessToken, cached.folderId, FRIENDS_FILE);
  return friendsData?.friends || [];
}

async function sendFriendRequest(fromId, fromName, fromAvatar, toId, toAccessToken) {
  const toProfile = userProfiles.get(toId);
  if (!toProfile) {
    throw new Error('User not found');
  }

  if (!toProfile.privacySettings?.allowFriendRequests) {
    throw new Error('User does not accept friend requests');
  }

  // Load target user's friends file
  const friendsData = await loadFileFromDrive(toAccessToken, toProfile.folderId, FRIENDS_FILE) || { friends: [], requests: [] };

  // Check if already friends or request pending
  if (friendsData.friends?.some(f => f.id === fromId)) {
    throw new Error('Already friends');
  }
  if (friendsData.requests?.some(r => r.fromId === fromId)) {
    throw new Error('Request already pending');
  }

  // Add request
  friendsData.requests = friendsData.requests || [];
  friendsData.requests.push({
    fromId,
    fromName,
    fromAvatar,
    sentAt: Date.now()
  });

  await saveFileToDrive(toAccessToken, toProfile.folderId, FRIENDS_FILE, friendsData);

  // Notify via WebSocket if online
  const targetWs = onlineUsers.get(toId)?.ws;
  if (targetWs && targetWs.readyState === 1) {
    targetWs.send(JSON.stringify({
      type: 'friend_request',
      from: { id: fromId, name: fromName, avatar: fromAvatar }
    }));
  }

  return true;
}

async function acceptFriendRequest(googleId, accessToken, fromId) {
  const cached = userProfiles.get(googleId);
  if (!cached) throw new Error('Profile not initialized');

  const friendsData = await loadFileFromDrive(accessToken, cached.folderId, FRIENDS_FILE) || { friends: [], requests: [] };

  const requestIndex = friendsData.requests?.findIndex(r => r.fromId === fromId);
  if (requestIndex === -1 || requestIndex === undefined) {
    throw new Error('Request not found');
  }

  const request = friendsData.requests[requestIndex];

  // Remove request and add friend
  friendsData.requests.splice(requestIndex, 1);
  friendsData.friends = friendsData.friends || [];
  friendsData.friends.push({
    id: fromId,
    name: request.fromName,
    avatar: request.fromAvatar,
    since: Date.now()
  });

  await saveFileToDrive(accessToken, cached.folderId, FRIENDS_FILE, friendsData);

  // Also add to sender's friends list
  const senderProfile = userProfiles.get(fromId);
  if (senderProfile) {
    const senderFriendsData = await loadFileFromDrive(senderProfile.accessToken, senderProfile.folderId, FRIENDS_FILE) || { friends: [], requests: [] };
    senderFriendsData.friends = senderFriendsData.friends || [];
    senderFriendsData.friends.push({
      id: googleId,
      name: cached.displayName,
      avatar: cached.avatarUrl,
      since: Date.now()
    });
    await saveFileToDrive(senderProfile.accessToken, senderProfile.folderId, FRIENDS_FILE, senderFriendsData);

    // Notify sender
    const senderWs = onlineUsers.get(fromId)?.ws;
    if (senderWs && senderWs.readyState === 1) {
      senderWs.send(JSON.stringify({
        type: 'friend_accepted',
        friend: { id: googleId, name: cached.displayName, avatar: cached.avatarUrl }
      }));
    }
  }

  return true;
}

async function rejectFriendRequest(googleId, accessToken, fromId) {
  const cached = userProfiles.get(googleId);
  if (!cached) throw new Error('Profile not initialized');

  const friendsData = await loadFileFromDrive(accessToken, cached.folderId, FRIENDS_FILE) || { friends: [], requests: [] };

  friendsData.requests = friendsData.requests?.filter(r => r.fromId !== fromId) || [];
  await saveFileToDrive(accessToken, cached.folderId, FRIENDS_FILE, friendsData);

  return true;
}

async function removeFriend(googleId, accessToken, friendId) {
  const cached = userProfiles.get(googleId);
  if (!cached) throw new Error('Profile not initialized');

  const friendsData = await loadFileFromDrive(accessToken, cached.folderId, FRIENDS_FILE) || { friends: [], requests: [] };
  friendsData.friends = friendsData.friends?.filter(f => f.id !== friendId) || [];
  await saveFileToDrive(accessToken, cached.folderId, FRIENDS_FILE, friendsData);

  // Also remove from friend's list
  const friendProfile = userProfiles.get(friendId);
  if (friendProfile) {
    const friendFriendsData = await loadFileFromDrive(friendProfile.accessToken, friendProfile.folderId, FRIENDS_FILE) || { friends: [], requests: [] };
    friendFriendsData.friends = friendFriendsData.friends?.filter(f => f.id !== googleId) || [];
    await saveFileToDrive(friendProfile.accessToken, friendProfile.folderId, FRIENDS_FILE, friendFriendsData);
  }

  return true;
}

async function getPendingRequests(googleId, accessToken) {
  const cached = userProfiles.get(googleId);
  if (!cached) return [];

  const friendsData = await loadFileFromDrive(accessToken, cached.folderId, FRIENDS_FILE);
  return friendsData?.requests || [];
}

/**
 * Activity Feed
 */
async function logActivity(googleId, accessToken, activity) {
  const cached = userProfiles.get(googleId);
  if (!cached) return null;

  const activityData = await loadFileFromDrive(accessToken, cached.folderId, ACTIVITY_FILE) || { activities: [] };

  const newActivity = {
    id: uuidv4(),
    ...activity,
    timestamp: Date.now()
  };

  // Keep last 100 activities
  activityData.activities.unshift(newActivity);
  if (activityData.activities.length > 100) {
    activityData.activities = activityData.activities.slice(0, 100);
  }

  await saveFileToDrive(accessToken, cached.folderId, ACTIVITY_FILE, activityData);

  // Update stats based on activity type
  if (activity.type === 'watched_movie') {
    await updateStats(googleId, accessToken, {
      moviesWatched: (cached.stats?.moviesWatched || 0) + 1,
      totalWatchTime: (cached.stats?.totalWatchTime || 0) + (activity.duration || 0)
    });
  } else if (activity.type === 'watched_episode') {
    await updateStats(googleId, accessToken, {
      tvEpisodesWatched: (cached.stats?.tvEpisodesWatched || 0) + 1,
      totalWatchTime: (cached.stats?.totalWatchTime || 0) + (activity.duration || 0)
    });
  }

  // Notify online friends only when the user allows activity sharing.
  if (cached.privacySettings?.showActivityToFriends !== false) {
    const friends = await getFriends(googleId, accessToken);
    for (const friend of friends) {
      const friendWs = onlineUsers.get(friend.id)?.ws;
      if (friendWs && friendWs.readyState === 1) {
        friendWs.send(JSON.stringify({
          type: 'friend_activity',
          activity: { ...newActivity, userId: googleId, userName: cached.displayName }
        }));
      }
    }
  }

  return newActivity;
}

async function getActivity(googleId, accessToken) {
  const cached = userProfiles.get(googleId);
  if (!cached) return [];

  const activityData = await loadFileFromDrive(accessToken, cached.folderId, ACTIVITY_FILE);
  return activityData?.activities || [];
}

async function getFriendsActivity(googleId, accessToken, filters = {}) {
  const friends = await getFriends(googleId, accessToken);

  // Load all friends' activities in parallel instead of sequentially
  const eligibleFriends = friends.filter(friend => {
    const friendProfile = userProfiles.get(friend.id);
    return friendProfile && friendProfile.privacySettings?.showActivityToFriends !== false;
  });

  const activityResults = await Promise.allSettled(
    eligibleFriends.map(async (friend) => {
      const friendProfile = userProfiles.get(friend.id);
      const friendActivity = await loadFileFromDrive(friendProfile.accessToken, friendProfile.folderId, ACTIVITY_FILE);
      if (friendActivity?.activities) {
        return friendActivity.activities.map(a => ({
          ...a,
          userId: friend.id,
          userName: friend.name,
          userAvatar: friend.avatar
        }));
      }
      return [];
    })
  );

  // Collect all successful results, skip failed ones gracefully
  const allActivities = [];
  for (const result of activityResults) {
    if (result.status === 'fulfilled' && result.value) {
      allActivities.push(...result.value);
    }
  }

  // Sort by timestamp
  allActivities.sort((a, b) => b.timestamp - a.timestamp);

  // Apply filters
  let filtered = allActivities;
  if (filters.contentType) {
    filtered = filtered.filter(a => a.contentType === filters.contentType);
  }
  if (filters.genre) {
    filtered = filtered.filter(a => a.genres?.includes(filters.genre));
  }
  if (filters.userId) {
    filtered = filtered.filter(a => a.userId === filters.userId);
  }

  return filtered.slice(0, 50);
}

/**
 * Currently Watching Status
 */
function setCurrentlyWatching(googleId, content) {
  const userSession = onlineUsers.get(googleId);
  if (userSession) {
    userSession.currentlyWatching = content ? {
      ...content,
      startedAt: Date.now()
    } : null;

    // Broadcast to friends
    broadcastToFriends(googleId, {
      type: 'currently_watching',
      userId: googleId,
      content: userSession.currentlyWatching
    });
  }
}

function getCurrentlyWatching(googleId) {
  return onlineUsers.get(googleId)?.currentlyWatching || null;
}

function getFriendsCurrentlyWatching(googleId) {
  const friends = friendships.get(googleId) || [];
  const watching = [];

  for (const friendId of friends) {
    const friendSession = onlineUsers.get(friendId);
    const friendProfile = userProfiles.get(friendId);

    if (friendSession?.currentlyWatching && friendProfile?.privacySettings?.showCurrentlyWatching !== false) {
      watching.push({
        userId: friendId,
        userName: friendProfile.displayName,
        userAvatar: friendProfile.avatarUrl,
        ...friendSession.currentlyWatching
      });
    }
  }

  return watching;
}

/**
 * Chat (stored in Google Drive)
 */
function getChatId(userId1, userId2) {
  return [userId1, userId2].sort().join('_');
}

async function getOrCreateChatFolder(accessToken, folderId) {
  const searchUrl = `https://www.googleapis.com/drive/v3/files?q=name='${CHAT_FOLDER}' and '${folderId}' in parents and mimeType='application/vnd.google-apps.folder' and trashed=false&fields=files(id)`;

  const searchRes = await fetch(searchUrl, {
    headers: { 'Authorization': `Bearer ${accessToken}` }
  });
  const searchData = await searchRes.json();

  if (searchData.files && searchData.files.length > 0) {
    return searchData.files[0].id;
  }

  const createRes = await fetch('https://www.googleapis.com/drive/v3/files', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      name: CHAT_FOLDER,
      parents: [folderId],
      mimeType: 'application/vnd.google-apps.folder'
    })
  });
  const folder = await createRes.json();
  return folder.id;
}

async function loadChatHistory(googleId, accessToken, friendId) {
  const cached = userProfiles.get(googleId);
  if (!cached) return [];

  const chatFolderId = await getOrCreateChatFolder(accessToken, cached.folderId);
  const chatId = getChatId(googleId, friendId);
  const chatData = await loadFileFromDrive(accessToken, chatFolderId, `${chatId}.json`);

  return chatData?.messages || [];
}

async function saveChatMessage(googleId, accessToken, friendId, message) {
  const cached = userProfiles.get(googleId);
  if (!cached) return null;

  const chatFolderId = await getOrCreateChatFolder(accessToken, cached.folderId);
  const chatId = getChatId(googleId, friendId);

  const chatData = await loadFileFromDrive(accessToken, chatFolderId, `${chatId}.json`) || { messages: [] };

  const newMessage = {
    id: uuidv4(),
    senderId: googleId,
    text: message.text,
    timestamp: Date.now()
  };

  chatData.messages.push(newMessage);

  // Keep last 500 messages
  if (chatData.messages.length > 500) {
    chatData.messages = chatData.messages.slice(-500);
  }

  await saveFileToDrive(accessToken, chatFolderId, `${chatId}.json`, chatData);

  // Also save to friend's Drive
  const friendProfile = userProfiles.get(friendId);
  if (friendProfile) {
    const friendChatFolderId = await getOrCreateChatFolder(friendProfile.accessToken, friendProfile.folderId);
    const friendChatData = await loadFileFromDrive(friendProfile.accessToken, friendChatFolderId, `${chatId}.json`) || { messages: [] };
    friendChatData.messages.push(newMessage);
    if (friendChatData.messages.length > 500) {
      friendChatData.messages = friendChatData.messages.slice(-500);
    }
    await saveFileToDrive(friendProfile.accessToken, friendChatFolderId, `${chatId}.json`, friendChatData);
  }

  return newMessage;
}

/**
 * WebSocket handlers for real-time features
 */
function handleSocialConnection(ws, googleId, accessToken) {
  onlineUsers.set(googleId, {
    ws,
    lastSeen: Date.now(),
    currentlyWatching: null
  });

  // Notify friends that user is online
  broadcastToFriends(googleId, {
    type: 'friend_online',
    userId: googleId
  });

  ws.on('message', async (data) => {
    try {
      const message = JSON.parse(data.toString());

      switch (message.type) {
        case 'chat_message': {
          const { friendId, text } = message;
          const savedMessage = await saveChatMessage(googleId, accessToken, friendId, { text });

          // Send to friend if online
          const friendWs = onlineUsers.get(friendId)?.ws;
          if (friendWs && friendWs.readyState === 1) {
            const profile = userProfiles.get(googleId);
            friendWs.send(JSON.stringify({
              type: 'chat_message',
              message: {
                ...savedMessage,
                senderName: profile?.displayName,
                senderAvatar: profile?.avatarUrl
              },
              fromUserId: googleId
            }));
          }

          // Confirm to sender
          ws.send(JSON.stringify({
            type: 'chat_message_sent',
            message: savedMessage,
            friendId
          }));
          break;
        }

        case 'typing': {
          const { friendId } = message;
          const friendWs = onlineUsers.get(friendId)?.ws;
          if (friendWs && friendWs.readyState === 1) {
            friendWs.send(JSON.stringify({
              type: 'typing',
              userId: googleId
            }));
          }
          break;
        }

        case 'currently_watching': {
          setCurrentlyWatching(googleId, message.content);
          break;
        }

        case 'stop_watching': {
          setCurrentlyWatching(googleId, null);
          break;
        }

        case 'heartbeat': {
          const session = onlineUsers.get(googleId);
          if (session) {
            session.lastSeen = Date.now();
          }
          ws.send(JSON.stringify({ type: 'heartbeat_ack' }));
          break;
        }
      }
    } catch (error) {
      console.error('[Social WS] Message error:', error);
    }
  });

  ws.on('close', () => {
    // Notify friends that user is offline
    broadcastToFriends(googleId, {
      type: 'friend_offline',
      userId: googleId
    });
    onlineUsers.delete(googleId);
  });
}

function broadcastToFriends(googleId, message) {
  const profile = userProfiles.get(googleId);
  if (!profile) return;

  // Get friends from cache or load
  const friends = friendships.get(googleId) || [];
  const data = JSON.stringify(message);

  for (const friendId of friends) {
    const friendSession = onlineUsers.get(friendId);
    if (friendSession?.ws && friendSession.ws.readyState === 1) {
      friendSession.ws.send(data);
    }
  }
}

/**
 * User search - uses Turso for persistent search, falls back to in-memory
 */
async function searchUsers(query, excludeId) {
  // Try Turso first (persistent across restarts)
  if (database.isConnected()) {
    const results = await database.searchUsers(query, excludeId, 20);
    if (results.length > 0) {
      return results;
    }
  }

  // Fallback to in-memory cache
  const results = [];

  for (const [id, profile] of userProfiles) {
    if (id === excludeId) continue;
    if (!profile.privacySettings?.allowFriendRequests) continue;

    const name = profile.displayName?.toLowerCase() || '';
    const email = profile.email?.toLowerCase() || '';
    const username = profile.username?.toLowerCase() || '';
    const q = query.toLowerCase();

    if (name.includes(q) || email.includes(q) || username.includes(q)) {
      results.push({
        id,
        username: profile.username,
        displayName: profile.displayName,
        avatarUrl: profile.avatarUrl
      });
    }

    if (results.length >= 20) break;
  }

  return results;
}

/**
 * Get friend's profile (respects privacy settings)
 */
async function getFriendProfile(googleId, accessToken, friendId) {
  const friends = await getFriends(googleId, accessToken);
  const isFriend = friends.some(f => f.id === friendId);

  const friendProfile = userProfiles.get(friendId);
  if (!friendProfile) return null;

  const profile = {
    id: friendId,
    displayName: friendProfile.displayName,
    avatarUrl: friendProfile.avatarUrl
  };

  if (isFriend) {
    if (friendProfile.privacySettings?.showStatsToFriends !== false) {
      profile.stats = friendProfile.stats;
    }
    if (friendProfile.privacySettings?.showCurrentlyWatching !== false) {
      profile.currentlyWatching = getCurrentlyWatching(friendId);
    }
  }

  return profile;
}

/**
 * Get online friends
 */
function getOnlineFriends(googleId) {
  const friends = friendships.get(googleId) || [];
  const online = [];

  for (const friendId of friends) {
    if (onlineUsers.has(friendId)) {
      const profile = userProfiles.get(friendId);
      online.push({
        id: friendId,
        displayName: profile?.displayName,
        avatarUrl: profile?.avatarUrl,
        currentlyWatching: onlineUsers.get(friendId)?.currentlyWatching
      });
    }
  }

  return online;
}

module.exports = {
  initUserSocial,
  getProfile,
  updateProfile,
  updatePrivacySettings,
  updateStats,
  getFriends,
  sendFriendRequest,
  acceptFriendRequest,
  rejectFriendRequest,
  removeFriend,
  getPendingRequests,
  logActivity,
  getActivity,
  getFriendsActivity,
  setCurrentlyWatching,
  getCurrentlyWatching,
  getFriendsCurrentlyWatching,
  loadChatHistory,
  saveChatMessage,
  handleSocialConnection,
  searchUsers,
  getFriendProfile,
  getOnlineFriends,
  userProfiles,
  onlineUsers
};
