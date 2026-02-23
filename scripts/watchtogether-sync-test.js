#!/usr/bin/env node

const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { setTimeout: delay } = require('node:timers/promises');
const WebSocket = require('ws');

const HEALTH_TIMEOUT_MS = 15000;
const MESSAGE_TIMEOUT_MS = 5000;

class WTClient {
  constructor(name, url) {
    this.name = name;
    this.url = url;
    this.ws = null;
    this.inbox = [];
    this.waiters = [];
    this.maxInbox = 500;
  }

  async connect(timeoutMs = 5000) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      return;
    }

    await new Promise((resolve, reject) => {
      const ws = new WebSocket(this.url);
      const timeout = setTimeout(() => {
        reject(new Error(`[${this.name}] connect timeout`));
      }, timeoutMs);

      ws.on('open', () => {
        clearTimeout(timeout);
        this.ws = ws;
        resolve();
      });
      ws.on('error', (err) => {
        clearTimeout(timeout);
        reject(err);
      });
      ws.on('message', (raw) => {
        this.#handleRawMessage(raw);
      });
      ws.on('close', () => {
        this.ws = null;
      });
    });
  }

  send(payload) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error(`[${this.name}] websocket is not open`);
    }
    const now = Date.now();
    this.ws.send(JSON.stringify(payload));
    return now;
  }

  async close() {
    if (!this.ws) return;
    const ws = this.ws;
    await new Promise((resolve) => {
      const timeout = setTimeout(resolve, 800);
      ws.once('close', () => {
        clearTimeout(timeout);
        resolve();
      });
      try {
        ws.close();
      } catch {
        clearTimeout(timeout);
        resolve();
      }
    });
  }

  waitFor(predicate, timeoutMs = MESSAGE_TIMEOUT_MS, label = 'message') {
    for (let i = 0; i < this.inbox.length; i += 1) {
      const msg = this.inbox[i];
      if (predicate(msg)) {
        this.inbox.splice(i, 1);
        return Promise.resolve(msg);
      }
    }

    return new Promise((resolve, reject) => {
      const waiter = {
        predicate,
        resolve: (msg) => {
          clearTimeout(waiter.timer);
          resolve(msg);
        },
        reject: (err) => {
          clearTimeout(waiter.timer);
          reject(err);
        },
        label,
        timer: null,
      };

      waiter.timer = setTimeout(() => {
        const idx = this.waiters.indexOf(waiter);
        if (idx >= 0) {
          this.waiters.splice(idx, 1);
        }
        const tail = this.inbox.slice(-6).map((m) => m.data.type).join(', ');
        reject(new Error(`[${this.name}] timeout waiting for ${label}. recent=[${tail}]`));
      }, timeoutMs);

      this.waiters.push(waiter);
    });
  }

  #handleRawMessage(raw) {
    let data;
    try {
      data = JSON.parse(raw.toString());
    } catch {
      return;
    }

    const envelope = { data, receivedAt: Date.now() };
    for (let i = 0; i < this.waiters.length; i += 1) {
      const waiter = this.waiters[i];
      let matched = false;
      try {
        matched = waiter.predicate(envelope);
      } catch {
        matched = false;
      }
      if (matched) {
        this.waiters.splice(i, 1);
        waiter.resolve(envelope);
        return;
      }
    }

    this.inbox.push(envelope);
    if (this.inbox.length > this.maxInbox) {
      this.inbox.shift();
    }
  }
}

function summarizeLatency(samples) {
  const values = [...samples].sort((a, b) => a - b);
  const sum = values.reduce((acc, v) => acc + v, 0);
  const idx95 = Math.floor((values.length - 1) * 0.95);
  return {
    count: values.length,
    min: values[0],
    avg: sum / values.length,
    p95: values[idx95],
    max: values[values.length - 1],
  };
}

async function waitForHealth(baseUrl, timeoutMs = HEALTH_TIMEOUT_MS) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(`${baseUrl}/health`);
      if (res.ok) {
        return;
      }
    } catch {
      // retry
    }
    await delay(200);
  }
  throw new Error(`health check timeout at ${baseUrl}`);
}

function spawnServer(port) {
  const child = spawn(process.execPath, ['server.js'], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      PORT: String(port),
      WT_SYNC_MODE: 'collaborative',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  child.stdout.on('data', (chunk) => {
    process.stdout.write(`[server] ${chunk}`);
  });
  child.stderr.on('data', (chunk) => {
    process.stderr.write(`[server:err] ${chunk}`);
  });

  return child;
}

async function measureSyncLatency({
  sender,
  receiver,
  senderId,
  receiverName,
  rounds,
  startPos,
}) {
  const latencies = [];
  let position = startPos;

  for (let i = 0; i < rounds; i += 1) {
    let action = 'seek';
    if (i % 3 === 1) action = 'pause';
    if (i % 3 === 2) action = 'play';

    position += 1.5;
    const sentAt = sender.send({
      type: 'sync',
      command: {
        action,
        position,
      },
    });

    const msg = await receiver.waitFor(
      (m) => (
        m.data.type === 'sync'
        && !m.data.is_echo
        && m.data.from === senderId
        && m.data.command?.action === action
        && Math.abs((m.data.command?.position ?? 0) - position) < 0.001
      ),
      2500,
      `${receiverName} sync ${action}`,
    );

    latencies.push(msg.receivedAt - sentAt);
    await delay(35);
  }

  return latencies;
}

async function measureConcurrentLatency({
  host,
  guest,
  hostId,
  guestId,
  rounds,
  startPos,
}) {
  const hostToGuest = [];
  const guestToHost = [];
  let base = startPos;

  for (let i = 0; i < rounds; i += 1) {
    base += 2.0;
    const hostPosition = base + 0.1;
    const guestPosition = base + 0.2;
    const action = i % 2 === 0 ? 'seek' : 'play';

    const hostSentAt = host.send({
      type: 'sync',
      command: { action, position: hostPosition },
    });
    const guestSentAt = guest.send({
      type: 'sync',
      command: { action, position: guestPosition },
    });

    const [guestReceived, hostReceived] = await Promise.all([
      guest.waitFor(
        (m) => (
          m.data.type === 'sync'
          && !m.data.is_echo
          && m.data.from === hostId
          && m.data.command?.action === action
          && Math.abs((m.data.command?.position ?? 0) - hostPosition) < 0.001
        ),
        2500,
        'guest concurrent sync',
      ),
      host.waitFor(
        (m) => (
          m.data.type === 'sync'
          && !m.data.is_echo
          && m.data.from === guestId
          && m.data.command?.action === action
          && Math.abs((m.data.command?.position ?? 0) - guestPosition) < 0.001
        ),
        2500,
        'host concurrent sync',
      ),
    ]);

    hostToGuest.push(guestReceived.receivedAt - hostSentAt);
    guestToHost.push(hostReceived.receivedAt - guestSentAt);
    await delay(25);
  }

  return { hostToGuest, guestToHost };
}

async function run() {
  const port = 3400 + Math.floor(Math.random() * 200);
  const baseUrl = `http://127.0.0.1:${port}`;
  const wsUrl = `ws://127.0.0.1:${port}/ws/watchtogether`;
  const server = spawnServer(port);

  const host = new WTClient('host', wsUrl);
  let guest = new WTClient('guest', wsUrl);
  const stray = new WTClient('stray', wsUrl);

  const cleanup = async () => {
    await Promise.allSettled([host.close(), guest.close(), stray.close()]);
    if (!server.killed) {
      server.kill('SIGTERM');
      await delay(200);
      if (!server.killed) {
        server.kill('SIGKILL');
      }
    }
  };

  try {
    await waitForHealth(baseUrl);
    console.log('[test] server healthy');

    await host.connect();
    const hostClientId = `host-${Date.now()}`;
    host.send({
      type: 'create',
      media_id: 424242,
      media_title: 'Sync Test Film',
      media_match_key: 'cloud:host-file-id|file:sync-test-film.mp4|title:sync test film',
      nickname: 'Host',
      client_id: hostClientId,
    });

    const roomCreated = await host.waitFor(
      (m) => m.data.type === 'room_created',
      4000,
      'room_created',
    );
    const roomCode = roomCreated.data.room.code;
    const hostId = roomCreated.data.room.host_id;
    assert.equal(roomCreated.data.room.participants.length, 1, 'room should start with one participant');

    await guest.connect();
    const guestClientId = `guest-${Date.now()}`;
    guest.send({
      type: 'join',
      room_code: roomCode,
      media_id: 424242,
      media_title: 'Sync Test Film',
      media_match_key: 'cloud:guest-different-id|file:sync-test-film.mp4|title:sync test film',
      nickname: 'Guest',
      client_id: guestClientId,
    });

    const roomJoined = await guest.waitFor(
      (m) => m.data.type === 'room_joined',
      4000,
      'room_joined',
    );
    assert.equal(roomJoined.data.room.code, roomCode, 'guest should join same room');
    assert.equal(roomJoined.data.room.participants.length, 2, 'room should contain two participants');
    const guestParticipant = roomJoined.data.room.participants.find((p) => p.nickname === 'Guest');
    assert.ok(guestParticipant, 'guest participant should exist');
    const guestId = guestParticipant.id;

    await stray.connect();
    stray.send({
      type: 'join',
      room_code: roomCode,
      media_id: 111111,
      media_title: 'Completely Different Film',
      media_match_key: 'cloud:stray-id|file:another-film.mp4|title:completely different film',
      nickname: 'WrongMedia',
      client_id: `stray-${Date.now()}`,
    });
    const mediaError = await stray.waitFor(
      (m) => m.data.type === 'error',
      3000,
      'media mismatch error',
    );
    assert.match(mediaError.data.message, /different media item/i, 'wrong media join should be rejected');

    host.send({ type: 'ready', duration: 3600 });
    guest.send({ type: 'ready', duration: 3600 });

    const readyRoom = await host.waitFor(
      (m) => (
        m.data.type === 'room_state'
        && m.data.room?.participants?.length === 2
        && m.data.room.participants.every((p) => p.is_ready === true)
      ),
      5000,
      'all ready room_state',
    );
    assert.equal(readyRoom.data.room.participants.filter((p) => p.is_ready).length, 2);

    host.send({ type: 'start_playback', position: 12.0 });
    const hostStarted = await host.waitFor((m) => m.data.type === 'playback_started', 3000, 'host playback_started');
    const guestStarted = await guest.waitFor((m) => m.data.type === 'playback_started', 3000, 'guest playback_started');
    assert.equal(hostStarted.data.position, 12.0);
    assert.equal(guestStarted.data.position, 12.0);

    // Feed state reports to keep participant telemetry current.
    let simPos = 12.0;
    for (let i = 0; i < 8; i += 1) {
      simPos += 0.25;
      host.send({ type: 'state_report', position: simPos, paused: false });
      guest.send({ type: 'state_report', position: simPos + 0.03, paused: false });
      await delay(120);
    }

    const guestStateUpdates = [];
    for (let i = 0; i < 4; i += 1) {
      const stateUpdate = await guest.waitFor((m) => m.data.type === 'state_update', 2500, 'guest state_update');
      guestStateUpdates.push(stateUpdate);
    }
    for (let i = 1; i < guestStateUpdates.length; i += 1) {
      const interval = guestStateUpdates[i].receivedAt - guestStateUpdates[i - 1].receivedAt;
      assert.ok(interval >= 250 && interval <= 1300, `state_update interval out of range: ${interval}ms`);
      assert.ok(
        guestStateUpdates[i].data.position >= guestStateUpdates[i - 1].data.position - 0.5,
        'state_update positions should not jump backwards significantly',
      );
    }

    // "resume" should be accepted as a legacy alias and canonicalized to "play".
    const resumeTarget = simPos + 2.5;
    host.send({
      type: 'sync',
      command: {
        action: 'resume',
        position: resumeTarget,
      },
    });
    const resumeSync = await guest.waitFor(
      (m) => (
        m.data.type === 'sync'
        && !m.data.is_echo
        && m.data.from === hostId
        && m.data.command?.action === 'play'
        && Math.abs((m.data.command?.position ?? 0) - resumeTarget) < 0.001
      ),
      2500,
      'resume alias canonicalization',
    );
    assert.equal(resumeSync.data.command.action, 'play', 'resume alias should be broadcast as play');

    // If a seek command carries a stale position, fresh state_report from the
    // same authority should pull the room toward the true playback position.
    const staleSeekPos = simPos + 18;
    const correctedHostPos = staleSeekPos + 36;
    host.send({
      type: 'sync',
      command: {
        action: 'seek',
        position: staleSeekPos,
      },
    });
    await guest.waitFor(
      (m) => (
        m.data.type === 'sync'
        && !m.data.is_echo
        && m.data.from === hostId
        && m.data.command?.action === 'seek'
        && Math.abs((m.data.command?.position ?? 0) - staleSeekPos) < 0.001
      ),
      2500,
      'stale host seek relay',
    );
    for (let i = 0; i < 3; i += 1) {
      host.send({ type: 'state_report', position: correctedHostPos + (i * 0.05), paused: false });
      await delay(70);
    }
    const hostCorrectionUpdate = await guest.waitFor(
      (m) => (
        m.data.type === 'state_update'
        && m.data.paused === false
        && (m.data.position ?? 0) > correctedHostPos - 0.8
      ),
      3500,
      'host correction state_update',
    );
    assert.ok(
      hostCorrectionUpdate.data.position > correctedHostPos - 0.8,
      `expected corrected host position near ${correctedHostPos}, got ${hostCorrectionUpdate.data.position}`,
    );

    // Collaborative mode: the latest non-host sync source should also be able
    // to correct authoritative room state via state_report.
    const staleGuestSeekPos = correctedHostPos + 22;
    const correctedGuestPos = staleGuestSeekPos + 33;
    guest.send({
      type: 'sync',
      command: {
        action: 'seek',
        position: staleGuestSeekPos,
      },
    });
    await host.waitFor(
      (m) => (
        m.data.type === 'sync'
        && !m.data.is_echo
        && m.data.from === guestId
        && m.data.command?.action === 'seek'
        && Math.abs((m.data.command?.position ?? 0) - staleGuestSeekPos) < 0.001
      ),
      2500,
      'stale guest seek relay',
    );
    for (let i = 0; i < 3; i += 1) {
      guest.send({ type: 'state_report', position: correctedGuestPos + (i * 0.05), paused: false });
      await delay(70);
    }
    const guestCorrectionUpdate = await host.waitFor(
      (m) => (
        m.data.type === 'state_update'
        && m.data.paused === false
        && (m.data.position ?? 0) > correctedGuestPos - 0.8
      ),
      3500,
      'guest correction state_update',
    );
    assert.ok(
      guestCorrectionUpdate.data.position > correctedGuestPos - 0.8,
      `expected corrected guest position near ${correctedGuestPos}, got ${guestCorrectionUpdate.data.position}`,
    );
    simPos = correctedGuestPos;

    const hostToGuest = await measureSyncLatency({
      sender: host,
      receiver: guest,
      senderId: hostId,
      receiverName: 'guest',
      rounds: 18,
      startPos: simPos,
    });

    const guestToHost = await measureSyncLatency({
      sender: guest,
      receiver: host,
      senderId: guestId,
      receiverName: 'host',
      rounds: 18,
      startPos: simPos + 30,
    });

    const concurrent = await measureConcurrentLatency({
      host,
      guest,
      hostId,
      guestId,
      rounds: 12,
      startPos: simPos + 60,
    });

    const hostGuestStats = summarizeLatency(hostToGuest);
    const guestHostStats = summarizeLatency(guestToHost);
    const concurrentHostGuestStats = summarizeLatency(concurrent.hostToGuest);
    const concurrentGuestHostStats = summarizeLatency(concurrent.guestToHost);

    assert.ok(hostGuestStats.p95 <= 400, `host->guest p95 too high: ${hostGuestStats.p95}ms`);
    assert.ok(guestHostStats.p95 <= 400, `guest->host p95 too high: ${guestHostStats.p95}ms`);
    assert.ok(hostGuestStats.max <= 900, `host->guest max too high: ${hostGuestStats.max}ms`);
    assert.ok(guestHostStats.max <= 900, `guest->host max too high: ${guestHostStats.max}ms`);
    assert.ok(concurrentHostGuestStats.p95 <= 450, `concurrent host->guest p95 too high: ${concurrentHostGuestStats.p95}ms`);
    assert.ok(concurrentGuestHostStats.p95 <= 450, `concurrent guest->host p95 too high: ${concurrentGuestHostStats.p95}ms`);

    console.log(`[metrics] host->guest latency ms: min=${hostGuestStats.min.toFixed(1)} avg=${hostGuestStats.avg.toFixed(1)} p95=${hostGuestStats.p95.toFixed(1)} max=${hostGuestStats.max.toFixed(1)}`);
    console.log(`[metrics] guest->host latency ms: min=${guestHostStats.min.toFixed(1)} avg=${guestHostStats.avg.toFixed(1)} p95=${guestHostStats.p95.toFixed(1)} max=${guestHostStats.max.toFixed(1)}`);
    console.log(`[metrics] concurrent host->guest latency ms: min=${concurrentHostGuestStats.min.toFixed(1)} avg=${concurrentHostGuestStats.avg.toFixed(1)} p95=${concurrentHostGuestStats.p95.toFixed(1)} max=${concurrentHostGuestStats.max.toFixed(1)}`);
    console.log(`[metrics] concurrent guest->host latency ms: min=${concurrentGuestHostStats.min.toFixed(1)} avg=${concurrentGuestHostStats.avg.toFixed(1)} p95=${concurrentGuestHostStats.p95.toFixed(1)} max=${concurrentGuestHostStats.max.toFixed(1)}`);

    // Reconnect guest quickly with the same client_id and ensure room continuity.
    await guest.close();
    await delay(500);

    const reGuest = new WTClient('guest-reconnect', wsUrl);
    await reGuest.connect();
    reGuest.send({
      type: 'join',
      room_code: roomCode,
      media_id: 424242,
      nickname: 'Guest',
      client_id: guestClientId,
    });
    const rejoined = await reGuest.waitFor((m) => m.data.type === 'room_joined', 5000, 'rejoin room_joined');
    assert.equal(rejoined.data.room.participants.length, 2, 'reconnected guest should keep room at two participants');
    guest = reGuest;

    // Validate host handoff.
    host.send({ type: 'leave' });
    const hostLeft = await guest.waitFor(
      (m) => m.data.type === 'participant_left' && m.data.participant_id === hostId,
      5000,
      'participant_left (host)',
    );
    assert.equal(hostLeft.data.room.host_id, guestId, 'guest should become host after host leaves');

    console.log('[result] PASS - watch together sync integration test completed');
  } finally {
    await cleanup();
  }
}

run().catch((err) => {
  console.error('[result] FAIL -', err.message);
  process.exitCode = 1;
});
