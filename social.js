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

function normalizeSocialId(value) {
  if (typeof value !== 'string') return '';
  return value.trim();
}

function normalizeText(value, maxLength = 500) {
  if (typeof value !== 'string') return '';
  return value.trim().slice(0, maxLength);
}

function syncFriendshipsForUser(googleId, friends) {
  const userId = normalizeSocialId(googleId);
  if (!userId) return [];

  const friendIds = Array.isArray(friends)
    ? Array.from(new Set(
      friends
        .map((friend) => normalizeSocialId(friend?.id))
        .filter(Boolean)
    ))
    : [];

  friendships.set(userId, friendIds);
  return friendIds;
}

function addFriendshipLink(userId, friendId) {
  const normalizedUserId = normalizeSocialId(userId);
  const normalizedFriendId = normalizeSocialId(friendId);
  if (!normalizedUserId || !normalizedFriendId) return;
  const existing = friendships.get(normalizedUserId) || [];
  if (!existing.includes(normalizedFriendId)) {
    friendships.set(normalizedUserId, [...existing, normalizedFriendId]);
  }
}

function removeFriendshipLink(userId, friendId) {
  const normalizedUserId = normalizeSocialId(userId);
  const normalizedFriendId = normalizeSocialId(friendId);
  if (!normalizedUserId || !normalizedFriendId) return;
  const existing = friendships.get(normalizedUserId) || [];
  friendships.set(normalizedUserId, existing.filter((id) => id !== normalizedFriendId));
}

function touchUserSession(googleId, accessToken) {
  const userId = normalizeSocialId(googleId);
  const token = normalizeText(accessToken || '', 4096);
  if (!userId || !token) return;

  const cached = userProfiles.get(userId);
  if (!cached) return;

  cached.accessToken = token;
  cached.lastSeen = Date.now();
}

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

function createDefaultPrivacySettings(existing = {}) {
  return {
    showStatsToFriends: true,
    showActivityToFriends: true,
    showCurrentlyWatching: true,
    allowFriendRequests: true,
    showEmail: false,
    showLocation: false,
    ...(existing || {})
  };
}

function createDefaultStats(existing = {}) {
  return {
    totalWatchTime: 0,
    moviesWatched: 0,
    tvEpisodesWatched: 0,
    favoriteGenres: [],
    lastUpdated: Date.now(),
    ...(existing || {})
  };
}

function createSocialProfile(googleId, userInfo = {}, existing = {}) {
  const email = existing.email || userInfo.email || '';
  const username = existing.username || generateUsernameFromEmail(email);
  const createdAt = Number(existing.createdAt) || Date.now();

  return {
    id: googleId,
    username,
    displayName: existing.displayName || userInfo.name || username,
    email,
    avatarUrl: existing.avatarUrl || userInfo.picture || null,
    bio: existing.bio || '',
    favoriteGenre: existing.favoriteGenre || '',
    location: existing.location || '',
    joinedAt: Number(existing.joinedAt) || createdAt,
    createdAt,
    privacySettings: createDefaultPrivacySettings(existing.privacySettings),
    stats: createDefaultStats(existing.stats)
  };
}

/**
 * Initialize social features for a user
 */
async function initUserSocial(googleId, accessToken, userInfo) {
  socialDebugLog('[Social] initUserSocial called for:', googleId);
  socialDebugLog('[Social] userInfo:', JSON.stringify(userInfo, null, 2));

  try {
    // Drive is optional now. Social auth may only have identity scopes.
    socialDebugLog('[Social] Getting or creating social folder when Drive scope is available...');
    const folderId = await getOrCreateSocialFolder(accessToken);
    socialDebugLog('[Social] Folder ID:', folderId);

    // Load or create profile
    socialDebugLog('[Social] Loading profile...');
    let profile = await loadFileFromDrive(accessToken, folderId, PROFILE_FILE);
    if (!profile && database.isConnected()) {
      const storedProfile = await database.getUser(googleId);
      if (storedProfile) {
        profile = createSocialProfile(googleId, userInfo, {
          username: storedProfile.username,
          displayName: storedProfile.displayName,
          email: storedProfile.email,
          avatarUrl: storedProfile.avatarUrl,
          bio: storedProfile.bio,
          location: storedProfile.location,
          createdAt: storedProfile.createdAt,
          privacySettings: {
            allowFriendRequests: storedProfile.allowFriendRequests
          }
        });
      }
    }
    socialDebugLog('[Social] Existing profile:', profile ? JSON.stringify(profile, null, 2) : 'not found');

    let needsSave = false;

    if (!profile) {
      socialDebugLog('[Social] Creating new profile...');
      profile = createSocialProfile(googleId, userInfo);
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
      profile.privacySettings = createDefaultPrivacySettings(profile.privacySettings);
      profile.stats = createDefaultStats(profile.stats);
    }

    socialDebugLog('[Social] Profile after migration:', JSON.stringify(profile, null, 2));
    socialDebugLog('[Social] Needs save:', needsSave);

    if (needsSave && folderId) {
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
    if (!accessToken) {
      return null;
    }

    const searchUrl = `https://www.googleapis.com/drive/v3/files?q=name='${SOCIAL_FOLDER}' and mimeType='application/vnd.google-apps.folder' and trashed=false&fields=files(id,name)`;

    socialDebugLog('[Social] Searching for folder...');
    const searchRes = await fetch(searchUrl, {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });

    if (!searchRes.ok) {
      const errorText = await searchRes.text();
      if (searchRes.status === 403) {
        socialDebugLog('[Social] Folder search skipped because Drive scope is unavailable:', errorText);
        return null;
      }
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
      if (createRes.status === 403) {
        socialDebugLog('[Social] Folder creation skipped because Drive scope is unavailable:', errorText);
        return null;
      }
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
    if (!accessToken || !folderId || !fileName) {
      return null;
    }

    const searchUrl = `https://www.googleapis.com/drive/v3/files?q=name='${fileName}' and '${folderId}' in parents and trashed=false&fields=files(id)`;
    const searchRes = await fetch(searchUrl, {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    if (!searchRes.ok) {
      return null;
    }
    const searchData = await searchRes.json();

    if (!searchData.files || searchData.files.length === 0) {
      return null;
    }

    const fileId = searchData.files[0].id;
    const contentRes = await fetch(`https://www.googleapis.com/drive/v3/files/${fileId}?alt=media`, {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    if (!contentRes.ok) {
      return null;
    }
    return await contentRes.json();
  } catch (error) {
    console.error('[Social] Load file error:', error);
    return null;
  }
}

async function saveFileToDrive(accessToken, folderId, fileName, data) {
  try {
    if (!accessToken || !folderId || !fileName) {
      return false;
    }

    // Check if file exists
    const searchUrl = `https://www.googleapis.com/drive/v3/files?q=name='${fileName}' and '${folderId}' in parents and trashed=false&fields=files(id)`;
    const searchRes = await fetch(searchUrl, {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    if (!searchRes.ok) {
      return false;
    }
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
    touchUserSession(googleId, accessToken);
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
    return profile;
  }

  if (database.isConnected()) {
    const storedProfile = await database.getUser(googleId);
    if (storedProfile) {
      const hydratedProfile = createSocialProfile(googleId, {}, {
        username: storedProfile.username,
        displayName: storedProfile.displayName,
        email: storedProfile.email,
        avatarUrl: storedProfile.avatarUrl,
        bio: storedProfile.bio,
        location: storedProfile.location,
        createdAt: storedProfile.createdAt,
        privacySettings: {
          allowFriendRequests: storedProfile.allowFriendRequests
        }
      });
      userProfiles.set(googleId, { ...hydratedProfile, folderId, accessToken });
      return hydratedProfile;
    }
  }

  return null;
}

async function updateProfile(googleId, accessToken, updates) {
  const cached = userProfiles.get(googleId);
  if (!cached) {
    throw new Error('Profile not initialized');
  }

  const normalizedUpdates = {};
  if (Object.prototype.hasOwnProperty.call(updates || {}, 'displayName')) {
    normalizedUpdates.displayName = normalizeText(updates.displayName, 120) || cached.displayName;
  }
  if (Object.prototype.hasOwnProperty.call(updates || {}, 'avatarUrl')) {
    const avatarUrl = normalizeText(updates.avatarUrl, 2048);
    normalizedUpdates.avatarUrl = avatarUrl || null;
  }
  if (Object.prototype.hasOwnProperty.call(updates || {}, 'bio')) {
    normalizedUpdates.bio = normalizeText(updates.bio, 200);
  }
  if (Object.prototype.hasOwnProperty.call(updates || {}, 'favoriteGenre')) {
    normalizedUpdates.favoriteGenre = normalizeText(updates.favoriteGenre, 60);
  }
  if (Object.prototype.hasOwnProperty.call(updates || {}, 'location')) {
    normalizedUpdates.location = normalizeText(updates.location, 80);
  }
  if (Object.prototype.hasOwnProperty.call(updates || {}, 'privacySettings')) {
    normalizedUpdates.privacySettings = {
      ...(cached.privacySettings || {}),
      ...(updates.privacySettings || {})
    };
  }
  if (Object.prototype.hasOwnProperty.call(updates || {}, 'stats')) {
    normalizedUpdates.stats = {
      ...(cached.stats || {}),
      ...(updates.stats || {})
    };
  }

  const updatedProfile = {
    ...cached,
    ...normalizedUpdates,
    id: googleId // Prevent ID change
  };

  await saveFileToDrive(accessToken, cached.folderId, PROFILE_FILE, updatedProfile);
  userProfiles.set(googleId, updatedProfile);

  // Keep persistent user search metadata in sync when profile changes.
  await database.upsertUser({
    googleId,
    username: updatedProfile.username,
    displayName: updatedProfile.displayName,
    email: updatedProfile.email,
    avatarUrl: updatedProfile.avatarUrl,
    bio: updatedProfile.bio,
    location: updatedProfile.location,
    allowFriendRequests: updatedProfile.privacySettings?.allowFriendRequests !== false,
    createdAt: updatedProfile.createdAt
  });

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

  const updatedProfile = await updateProfile(googleId, accessToken, { stats });

  if (database.isConnected()) {
    await database.updateWatchStats({
      userId: googleId,
      moviesWatched: updatedProfile?.stats?.moviesWatched || 0,
      episodesWatched: updatedProfile?.stats?.tvEpisodesWatched || 0,
      totalWatchTime: updatedProfile?.stats?.totalWatchTime || 0,
      favoriteGenres: updatedProfile?.stats?.favoriteGenres || [],
      updatedAt: updatedProfile?.stats?.lastUpdated || Date.now()
    });
  }

  return updatedProfile;
}

/**
 * Friends Management
 */
async function getFriends(googleId, accessToken) {
  touchUserSession(googleId, accessToken);
  const cached = userProfiles.get(googleId);
  if (!cached) {
    friendships.set(googleId, []);
    return [];
  }

  if (database.isConnected()) {
    const tursoFriends = await database.getFriends(googleId);
    if (tursoFriends.length > 0) {
      syncFriendshipsForUser(googleId, tursoFriends);
      return tursoFriends;
    }
  }

  const friendsData = await loadFileFromDrive(accessToken, cached.folderId, FRIENDS_FILE);
  const friends = Array.isArray(friendsData?.friends) ? friendsData.friends : [];
  syncFriendshipsForUser(googleId, friends);

  if (database.isConnected() && friends.length > 0) {
    for (const friend of friends) {
      const friendId = normalizeSocialId(friend?.id);
      if (!friendId) continue;
      await database.addFriendship(googleId, friendId, Number(friend?.since) || Date.now());
    }
  }

  return friends;
}

async function sendFriendRequest(fromId, fromName, fromAvatar, toId, toAccessToken) {
  const toProfile = userProfiles.get(toId);
  if (!toProfile) {
    throw new Error('User not found');
  }

  if (!toProfile.privacySettings?.allowFriendRequests) {
    throw new Error('User does not accept friend requests');
  }

  if (database.isConnected()) {
    if (await database.isFriend(fromId, toId)) {
      throw new Error('Already friends');
    }
    const existingRequest = await database.getFriendRequestBetween(fromId, toId);
    if (existingRequest?.status === 'pending') {
      throw new Error('Request already pending');
    }
  }

  // Load target user's friends file when a Drive mirror is available.
  const friendsData = await loadFileFromDrive(toAccessToken, toProfile.folderId, FRIENDS_FILE) || { friends: [], requests: [] };

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

  if (database.isConnected()) {
    await database.createFriendRequest(fromId, toId);
  }

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
  let requestIndex = friendsData.requests?.findIndex(r => r.fromId === fromId);
  let request = requestIndex !== -1 && requestIndex !== undefined
    ? friendsData.requests[requestIndex]
    : null;

  if (!request && database.isConnected()) {
    const requestRecord = await database.getFriendRequestBetween(fromId, googleId);
    if (requestRecord?.status === 'pending') {
      const senderProfile = userProfiles.get(fromId);
      const storedSender = !senderProfile ? await database.getUser(fromId) : null;
      request = {
        fromId,
        fromName: senderProfile?.displayName || storedSender?.displayName || 'Friend',
        fromAvatar: senderProfile?.avatarUrl || storedSender?.avatarUrl || null,
        sentAt: requestRecord.createdAt
      };
    }
  }

  if (!request) {
    throw new Error('Request not found');
  }

  // Remove request and add friend
  if (requestIndex !== -1 && requestIndex !== undefined) {
    friendsData.requests.splice(requestIndex, 1);
  }
  friendsData.friends = friendsData.friends || [];
  const alreadyFriend = friendsData.friends.some((f) => f.id === fromId);
  if (!alreadyFriend) {
    friendsData.friends.push({
      id: fromId,
      name: request.fromName,
      avatar: request.fromAvatar,
      since: Date.now()
    });
  }

  await saveFileToDrive(accessToken, cached.folderId, FRIENDS_FILE, friendsData);
  syncFriendshipsForUser(googleId, friendsData.friends);
  addFriendshipLink(googleId, fromId);
  addFriendshipLink(fromId, googleId);

  if (database.isConnected()) {
    await database.addFriendship(googleId, fromId, Date.now());
    const requestRecord = await database.getFriendRequestBetween(fromId, googleId);
    if (requestRecord) {
      await database.updateFriendRequestStatus(requestRecord.id, 'accepted');
    }
  }

  // Also add to sender's friends list
  const senderProfile = userProfiles.get(fromId);
  if (senderProfile) {
    const senderFriendsData = await loadFileFromDrive(senderProfile.accessToken, senderProfile.folderId, FRIENDS_FILE) || { friends: [], requests: [] };
    senderFriendsData.friends = senderFriendsData.friends || [];
    const senderAlreadyFriend = senderFriendsData.friends.some((f) => f.id === googleId);
    if (!senderAlreadyFriend) {
      senderFriendsData.friends.push({
        id: googleId,
        name: cached.displayName,
        avatar: cached.avatarUrl,
        since: Date.now()
      });
    }
    await saveFileToDrive(senderProfile.accessToken, senderProfile.folderId, FRIENDS_FILE, senderFriendsData);
    syncFriendshipsForUser(fromId, senderFriendsData.friends);

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

  if (database.isConnected()) {
    const requestRecord = await database.getFriendRequestBetween(fromId, googleId);
    if (requestRecord) {
      await database.updateFriendRequestStatus(requestRecord.id, 'rejected');
    }
  }

  return true;
}

async function removeFriend(googleId, accessToken, friendId) {
  const cached = userProfiles.get(googleId);
  if (!cached) throw new Error('Profile not initialized');

  const friendsData = await loadFileFromDrive(accessToken, cached.folderId, FRIENDS_FILE) || { friends: [], requests: [] };
  friendsData.friends = friendsData.friends?.filter(f => f.id !== friendId) || [];
  await saveFileToDrive(accessToken, cached.folderId, FRIENDS_FILE, friendsData);
  syncFriendshipsForUser(googleId, friendsData.friends);
  removeFriendshipLink(googleId, friendId);
  removeFriendshipLink(friendId, googleId);

  if (database.isConnected()) {
    await database.removeFriendship(googleId, friendId);
  }

  // Also remove from friend's list
  const friendProfile = userProfiles.get(friendId);
  if (friendProfile) {
    const friendFriendsData = await loadFileFromDrive(friendProfile.accessToken, friendProfile.folderId, FRIENDS_FILE) || { friends: [], requests: [] };
    friendFriendsData.friends = friendFriendsData.friends?.filter(f => f.id !== googleId) || [];
    await saveFileToDrive(friendProfile.accessToken, friendProfile.folderId, FRIENDS_FILE, friendFriendsData);
    syncFriendshipsForUser(friendId, friendFriendsData.friends);
  }

  return true;
}

async function getPendingRequests(googleId, accessToken) {
  const cached = userProfiles.get(googleId);
  if (!cached) return [];

  if (database.isConnected()) {
    const pending = await database.getPendingRequests(googleId);
    if (pending.length > 0) {
      return pending;
    }
  }

  const friendsData = await loadFileFromDrive(accessToken, cached.folderId, FRIENDS_FILE);
  const requests = friendsData?.requests || [];

  if (database.isConnected() && requests.length > 0) {
    for (const request of requests) {
      const fromId = normalizeSocialId(request?.fromId);
      if (!fromId) continue;
      await database.createFriendRequest(fromId, googleId, {
        createdAt: Number(request?.sentAt) || Date.now()
      });
    }
  }

  return requests;
}

/**
 * Activity Feed
 */
async function logActivity(googleId, accessToken, activity) {
  const cached = userProfiles.get(googleId);
  if (!cached) return null;

  const newActivity = {
    id: uuidv4(),
    ...activity,
    timestamp: Date.now()
  };

  if (database.isConnected()) {
    await database.logActivity({
      ...newActivity,
      userId: googleId,
      createdAt: newActivity.timestamp
    });
  }

  const activityData = await loadFileFromDrive(accessToken, cached.folderId, ACTIVITY_FILE) || { activities: [] };
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

  if (database.isConnected()) {
    const tursoActivities = await database.getUserActivities(googleId, 100);
    if (tursoActivities.length > 0) {
      return tursoActivities;
    }
  }

  const activityData = await loadFileFromDrive(accessToken, cached.folderId, ACTIVITY_FILE);
  const activities = activityData?.activities || [];

  if (database.isConnected() && activities.length > 0) {
    for (const driveActivity of activities) {
      await database.logActivity({
        ...driveActivity,
        userId: googleId,
        createdAt: driveActivity.timestamp
      });
    }
  }

  return activities;
}

async function getFriendsActivity(googleId, accessToken, filters = {}) {
  const friends = await getFriends(googleId, accessToken);
  const eligibleFriends = friends.filter(friend => {
    const friendProfile = userProfiles.get(friend.id);
    return !friendProfile || friendProfile.privacySettings?.showActivityToFriends !== false;
  });
  const friendIds = eligibleFriends.map((friend) => friend.id);

  const page = Math.max(Number(filters.page) || 1, 1);
  const pageSize = Math.min(Math.max(Number(filters.pageSize) || 50, 1), 100);

  if (database.isConnected() && friendIds.length > 0) {
    const activities = await database.getFriendsActivity(googleId, friendIds, filters, page, pageSize);
    const totalCount = await database.getFriendsActivityCount(googleId, friendIds, filters);

    if (activities.length > 0 || totalCount === 0) {
      return {
        activities,
        page,
        pageSize,
        totalCount,
        hasMore: (page * pageSize) < totalCount
      };
    }
  }

  // Load all friends' activities in parallel instead of sequentially
  const activityResults = await Promise.allSettled(
    eligibleFriends.map(async (friend) => {
      const friendProfile = userProfiles.get(friend.id);
      if (!friendProfile) return [];
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

  const offset = (page - 1) * pageSize;
  const activities = filtered.slice(offset, offset + pageSize);

  return {
    activities,
    page,
    pageSize,
    totalCount: filtered.length,
    hasMore: offset + activities.length < filtered.length
  };
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

async function getFriendsCurrentlyWatching(googleId, accessToken) {
  const friends = await getFriends(googleId, accessToken);
  const watching = [];

  for (const friend of friends) {
    const friendId = friend.id;
    const friendSession = onlineUsers.get(friendId);
    const friendProfile = userProfiles.get(friendId);

    if (friendSession?.currentlyWatching && friendProfile?.privacySettings?.showCurrentlyWatching !== false) {
      watching.push({
        userId: friendId,
        userName: friend.name || friendProfile.displayName,
        userAvatar: friend.avatar ?? friendProfile.avatarUrl,
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
  if (!accessToken || !folderId) {
    return null;
  }

  const searchUrl = `https://www.googleapis.com/drive/v3/files?q=name='${CHAT_FOLDER}' and '${folderId}' in parents and mimeType='application/vnd.google-apps.folder' and trashed=false&fields=files(id)`;

  const searchRes = await fetch(searchUrl, {
    headers: { 'Authorization': `Bearer ${accessToken}` }
  });
  if (!searchRes.ok) {
    return null;
  }
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
  if (!createRes.ok) {
    return null;
  }
  const folder = await createRes.json();
  return folder.id;
}

async function loadChatHistory(googleId, accessToken, friendId) {
  const cached = userProfiles.get(googleId);
  if (!cached) return [];

  const normalizedFriendId = normalizeSocialId(friendId);
  if (!normalizedFriendId) return [];

  if (database.isConnected()) {
    const tursoHistory = await database.getChatHistory(googleId, normalizedFriendId, { limit: 500, order: 'asc' });
    if (tursoHistory.length > 0) {
      return tursoHistory.map((message) => ({
        id: message.id,
        senderId: message.senderId,
        text: message.text,
        timestamp: message.timestamp
      }));
    }
  }

  const chatFolderId = await getOrCreateChatFolder(accessToken, cached.folderId);
  const chatId = getChatId(googleId, normalizedFriendId);
  const chatData = await loadFileFromDrive(accessToken, chatFolderId, `${chatId}.json`);

  const driveMessages = chatData?.messages || [];

  if (database.isConnected() && driveMessages.length > 0) {
    for (const driveMessage of driveMessages) {
      await database.saveMessage({
        id: driveMessage.id,
        senderId: driveMessage.senderId,
        receiverId: driveMessage.senderId === googleId ? normalizedFriendId : googleId,
        text: driveMessage.text,
        read: true,
        createdAt: driveMessage.timestamp
      });
    }
  }

  return driveMessages;
}

async function saveChatMessage(googleId, accessToken, friendId, message) {
  touchUserSession(googleId, accessToken);
  const cached = userProfiles.get(googleId);
  if (!cached) return null;

  const normalizedFriendId = normalizeSocialId(friendId);
  if (!normalizedFriendId) {
    throw new Error('Missing friend id');
  }

  const text = normalizeText(message?.text || '', 2000);
  if (!text) {
    throw new Error('Message cannot be empty');
  }

  const friends = await getFriends(googleId, accessToken);
  const isFriend = friends.some((friend) => friend.id === normalizedFriendId);
  if (!isFriend) {
    throw new Error('Can only message friends');
  }

  const chatFolderId = await getOrCreateChatFolder(accessToken, cached.folderId);
  const chatId = getChatId(googleId, normalizedFriendId);

  const chatData = await loadFileFromDrive(accessToken, chatFolderId, `${chatId}.json`) || { messages: [] };

  const newMessage = {
    id: uuidv4(),
    senderId: googleId,
    text,
    timestamp: Date.now()
  };

  if (database.isConnected()) {
    await database.saveMessage({
      id: newMessage.id,
      senderId: googleId,
      receiverId: normalizedFriendId,
      text: newMessage.text,
      read: false,
      createdAt: newMessage.timestamp
    });

    const receiverSession = onlineUsers.get(normalizedFriendId);
    if (!receiverSession?.ws) {
      await database.queueMessageForDelivery({
        id: `queue_${newMessage.id}`,
        receiverId: normalizedFriendId,
        messageId: newMessage.id,
        createdAt: newMessage.timestamp
      });
    }
  }

  chatData.messages.push(newMessage);

  // Keep last 500 messages
  if (chatData.messages.length > 500) {
    chatData.messages = chatData.messages.slice(-500);
  }

  await saveFileToDrive(accessToken, chatFolderId, `${chatId}.json`, chatData);

  // Also save to friend's Drive when we have a valid cached session for that user.
  // Mirror failures should not fail the sender's write path.
  const friendProfile = userProfiles.get(normalizedFriendId);
  if (friendProfile?.accessToken) {
    try {
      const friendChatFolderId = await getOrCreateChatFolder(friendProfile.accessToken, friendProfile.folderId);
      const friendChatData = await loadFileFromDrive(friendProfile.accessToken, friendChatFolderId, `${chatId}.json`) || { messages: [] };
      friendChatData.messages.push(newMessage);
      if (friendChatData.messages.length > 500) {
        friendChatData.messages = friendChatData.messages.slice(-500);
      }
      await saveFileToDrive(friendProfile.accessToken, friendChatFolderId, `${chatId}.json`, friendChatData);
    } catch (error) {
      socialDebugLog('[Social] Failed to mirror chat to friend drive:', normalizedFriendId, error?.message || error);
    }
  }

  return newMessage;
}

async function markChatMessagesAsRead(googleId, friendId) {
  if (!database.isConnected()) return 0;
  return database.markMessagesAsRead(friendId, googleId);
}

async function deliverPendingMessages(googleId) {
  if (!database.isConnected()) return [];

  const pendingMessages = await database.getPendingMessages(googleId);
  if (!pendingMessages.length) return [];

  const userSession = onlineUsers.get(googleId);
  if (!userSession?.ws || userSession.ws.readyState !== 1) {
    return [];
  }

  const delivered = [];
  for (const pending of pendingMessages) {
    userSession.ws.send(JSON.stringify({
      type: 'chat_message',
      message: {
        id: pending.message.id,
        senderId: pending.message.senderId,
        text: pending.message.text,
        timestamp: pending.message.timestamp
      },
      fromUserId: pending.message.senderId
    }));
    await database.markQueuedMessageDelivered(pending.queueId);
    delivered.push(pending.message);
  }

  return delivered;
}

function emitRealtimeChatDelivery(fromId, friendId, message, options = {}) {
  const senderProfile = userProfiles.get(fromId);
  const friendWs = onlineUsers.get(friendId)?.ws;
  if (friendWs && friendWs.readyState === 1) {
    friendWs.send(JSON.stringify({
      type: 'chat_message',
      message: {
        ...message,
        senderName: senderProfile?.displayName,
        senderAvatar: senderProfile?.avatarUrl
      },
      fromUserId: fromId
    }));
  }

  const senderWs = onlineUsers.get(fromId)?.ws;
  if (senderWs && senderWs.readyState === 1 && options.emitToSender !== false) {
    senderWs.send(JSON.stringify({
      type: 'chat_message_sent',
      message,
      friendId,
      clientMessageId: options.clientMessageId || null,
    }));
  }
}

/**
 * WebSocket handlers for real-time features
 */
function handleSocialConnection(ws, googleId, accessToken) {
  const existingSession = onlineUsers.get(googleId);
  if (existingSession?.ws && existingSession.ws !== ws) {
    try {
      existingSession.ws.close(1000, 'Session replaced');
    } catch {
      // Ignore close errors for stale sockets.
    }
  }

  onlineUsers.set(googleId, {
    ws,
    lastSeen: Date.now(),
    currentlyWatching: null
  });

  // Keep friendship cache fresh so presence broadcasts can route correctly.
  getFriends(googleId, accessToken).catch((error) => {
    socialDebugLog('[Social] Failed to hydrate friendships on connect:', error?.message || error);
  });

  if (database.isConnected()) {
    database.updateLastSeen(googleId).catch((error) => {
      socialDebugLog('[Social] Failed to update last seen on connect:', error?.message || error);
    });
    deliverPendingMessages(googleId).catch((error) => {
      socialDebugLog('[Social] Failed to deliver pending messages:', error?.message || error);
    });
  }

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
          if (!friendId || typeof text !== 'string') {
            ws.send(JSON.stringify({ type: 'error', message: 'friendId and text are required' }));
            break;
          }
          const savedMessage = await saveChatMessage(googleId, accessToken, friendId, { text });
          if (!savedMessage) {
            ws.send(JSON.stringify({ type: 'error', message: 'Failed to save message' }));
            break;
          }

          emitRealtimeChatDelivery(googleId, friendId, savedMessage, {
            clientMessageId: normalizeText(message.clientMessageId || '', 128) || null,
            emitToSender: true,
          });
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
          if (database.isConnected()) {
            database.updateLastSeen(googleId).catch(() => {});
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
    const activeSession = onlineUsers.get(googleId);
    if (!activeSession || activeSession.ws !== ws) {
      return;
    }

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
  const storedProfile = !friendProfile && database.isConnected()
    ? await database.getUser(friendId)
    : null;
  if (!friendProfile && !storedProfile) return null;

  const profile = {
    id: friendId,
    displayName: friendProfile?.displayName || storedProfile?.displayName,
    avatarUrl: friendProfile?.avatarUrl || storedProfile?.avatarUrl || null
  };

  if (isFriend) {
    if (friendProfile?.privacySettings?.showStatsToFriends !== false) {
      profile.stats = friendProfile.stats;
    }
    if (friendProfile?.privacySettings?.showCurrentlyWatching !== false) {
      profile.currentlyWatching = getCurrentlyWatching(friendId);
    }
  }

  return profile;
}

/**
 * Get online friends
 */
async function getOnlineFriends(googleId, accessToken) {
  const friends = await getFriends(googleId, accessToken);
  const online = [];

  for (const friend of friends) {
    const friendId = normalizeSocialId(friend?.id);
    if (!friendId) continue;

    const friendSession = onlineUsers.get(friendId);
    if (friendSession) {
      const profile = userProfiles.get(friendId);
      online.push({
        id: friendId,
        name: friend.name || profile?.displayName || 'Friend',
        avatar: friend.avatar ?? profile?.avatarUrl ?? null,
        since: Number(friend?.since) || 0,
        isOnline: true,
        currentlyWatching: profile?.privacySettings?.showCurrentlyWatching === false
          ? null
          : friendSession.currentlyWatching || null
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
  markChatMessagesAsRead,
  deliverPendingMessages,
  emitRealtimeChatDelivery,
  handleSocialConnection,
  searchUsers,
  getFriendProfile,
  getOnlineFriends,
  touchUserSession,
  loadFileFromDrive,
  getChatId,
  userProfiles,
  onlineUsers
};
