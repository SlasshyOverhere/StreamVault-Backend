#!/usr/bin/env node

const http = require('node:http');
const WebSocket = require('ws');

const LISTEN_HOST = process.env.PROXY_HOST || '127.0.0.1';
const LISTEN_PORT = Number(process.env.PROXY_PORT || 3899);
const TARGET_WS_URL = process.env.TARGET_WS_URL || 'ws://127.0.0.1:3001/ws/watchtogether';

const BASE_DELAY_MS = Number(process.env.WAN_BASE_DELAY_MS || 90);
const JITTER_MS = Number(process.env.WAN_JITTER_MS || 40);
const LOSS_PCT = Number(process.env.WAN_PACKET_LOSS_PCT || 0);
const DUPLICATE_PCT = Number(process.env.WAN_DUPLICATE_PCT || 0.0);

const stats = {
  c2s: { queued: 0, forwarded: 0, dropped: 0, duplicated: 0 },
  s2c: { queued: 0, forwarded: 0, dropped: 0, duplicated: 0 },
  sockets: 0,
};

function computeDelayMs() {
  const jitter = (Math.random() * 2 - 1) * JITTER_MS;
  return Math.max(0, Math.round(BASE_DELAY_MS + jitter));
}

function maybeDrop() {
  return Math.random() * 100 < LOSS_PCT;
}

function maybeDuplicate() {
  return Math.random() * 100 < DUPLICATE_PCT;
}

function safeSend(ws, data, isBinary) {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(data, { binary: isBinary });
    return true;
  }
  return false;
}

function relayWithImpairment({ from, to, direction, data, isBinary }) {
  const channel = stats[direction];
  channel.queued += 1;

  if (maybeDrop()) {
    channel.dropped += 1;
    return;
  }

  const delayMs = computeDelayMs();
  setTimeout(() => {
    if (safeSend(to, data, isBinary)) {
      channel.forwarded += 1;

      if (maybeDuplicate()) {
        const dupDelay = computeDelayMs();
        setTimeout(() => {
          if (safeSend(to, data, isBinary)) {
            channel.forwarded += 1;
            channel.duplicated += 1;
          }
        }, dupDelay);
      }
    }
  }, delayMs);
}

function json(res, code, payload) {
  res.writeHead(code, { 'content-type': 'application/json' });
  res.end(JSON.stringify(payload));
}

const server = http.createServer((req, res) => {
  if (req.url === '/health') {
    json(res, 200, {
      status: 'ok',
      target: TARGET_WS_URL,
      profile: {
        base_delay_ms: BASE_DELAY_MS,
        jitter_ms: JITTER_MS,
        packet_loss_pct: LOSS_PCT,
        duplicate_pct: DUPLICATE_PCT,
      },
      stats,
      ts: new Date().toISOString(),
    });
    return;
  }
  json(res, 404, { error: 'Not found' });
});

const wss = new WebSocket.Server({ server, perMessageDeflate: false });

wss.on('connection', (client, req) => {
  if (!req.url || !req.url.startsWith('/ws/watchtogether')) {
    client.close(1008, 'Invalid path');
    return;
  }

  stats.sockets += 1;
  const upstream = new WebSocket(TARGET_WS_URL, { perMessageDeflate: false });

  let closed = false;
  const closeBoth = () => {
    if (closed) return;
    closed = true;
    try { client.close(); } catch {}
    try { upstream.close(); } catch {}
    stats.sockets = Math.max(0, stats.sockets - 1);
  };

  upstream.on('open', () => {
    // ready
  });

  client.on('message', (data, isBinary) => {
    relayWithImpairment({
      from: client,
      to: upstream,
      direction: 'c2s',
      data,
      isBinary: !!isBinary,
    });
  });

  upstream.on('message', (data, isBinary) => {
    relayWithImpairment({
      from: upstream,
      to: client,
      direction: 's2c',
      data,
      isBinary: !!isBinary,
    });
  });

  client.on('close', closeBoth);
  upstream.on('close', closeBoth);
  client.on('error', closeBoth);
  upstream.on('error', closeBoth);
});

server.listen(LISTEN_PORT, LISTEN_HOST, () => {
  console.log(`[proxy] listening on ws://${LISTEN_HOST}:${LISTEN_PORT}/ws/watchtogether`);
  console.log(`[proxy] target=${TARGET_WS_URL}`);
  console.log(`[proxy] profile delay=${BASE_DELAY_MS}ms jitter=${JITTER_MS}ms loss=${LOSS_PCT}% dup=${DUPLICATE_PCT}%`);
});

setInterval(() => {
  console.log(
    `[proxy-stats] sockets=${stats.sockets} c2s={fwd:${stats.c2s.forwarded} drop:${stats.c2s.dropped}} s2c={fwd:${stats.s2c.forwarded} drop:${stats.s2c.dropped}}`
  );
}, 5000);
