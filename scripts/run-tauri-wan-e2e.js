#!/usr/bin/env node

const { spawn } = require('node:child_process');
const path = require('node:path');
const { setTimeout: delay } = require('node:timers/promises');

function parseArg(name, defaultValue) {
  const prefix = `--${name}=`;
  for (const arg of process.argv.slice(2)) {
    if (arg.startsWith(prefix)) {
      return arg.slice(prefix.length);
    }
  }
  return defaultValue;
}

function randPort(base, span) {
  return base + Math.floor(Math.random() * span);
}

function spawnWithLogs(command, args, options, label) {
  const child = spawn(command, args, options);
  child.stdout?.on('data', (chunk) => process.stdout.write(`[${label}] ${chunk}`));
  child.stderr?.on('data', (chunk) => process.stderr.write(`[${label}:err] ${chunk}`));
  return child;
}

async function waitForHealth(url, timeoutMs = 15000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch {
      // retry
    }
    await delay(200);
  }
  throw new Error(`health check timeout: ${url}`);
}

async function killChild(child, name) {
  if (!child || child.killed) return;
  try {
    child.kill('SIGTERM');
  } catch {}
  await delay(250);
  if (!child.killed) {
    try {
      child.kill('SIGKILL');
    } catch {}
  }
  await new Promise((resolve) => {
    const t = setTimeout(resolve, 500);
    child.once('exit', () => {
      clearTimeout(t);
      resolve();
    });
  });
  console.log(`[orchestrator] ${name} stopped`);
}

async function main() {
  const rounds = Number(parseArg('rounds', '36'));
  const concurrentRounds = Number(parseArg('concurrent-rounds', '24'));
  const delayMs = Number(parseArg('delay-ms', '120'));
  const jitterMs = Number(parseArg('jitter-ms', '50'));
  const lossPct = Number(parseArg('loss-pct', '0'));
  const duplicatePct = Number(parseArg('duplicate-pct', '0'));
  const p95LimitMs = Number(parseArg('p95-limit-ms', '900'));
  const maxLimitMs = Number(parseArg('max-limit-ms', '2200'));

  const serverPort = randPort(3600, 200);
  const proxyPort = randPort(3900, 200);

  const serverDir = path.resolve(__dirname, '..');
  const tauriDir = path.resolve(serverDir, '..', 'slasshy-desktop', 'src-tauri');
  const wsTarget = `ws://127.0.0.1:${serverPort}/ws/watchtogether`;
  const wsProxy = `ws://127.0.0.1:${proxyPort}/ws/watchtogether`;

  console.log(
    `[orchestrator] profile delay=${delayMs}ms jitter=${jitterMs}ms loss=${lossPct}% dup=${duplicatePct}% rounds=${rounds}/${concurrentRounds}`
  );
  console.log(`[orchestrator] serverDir=${serverDir}`);
  console.log(`[orchestrator] tauriDir=${tauriDir}`);

  let serverProc;
  let proxyProc;

  try {
    serverProc = spawnWithLogs(
      process.execPath,
      ['server.js'],
      {
        cwd: serverDir,
        env: {
          ...process.env,
          PORT: String(serverPort),
          WT_SYNC_MODE: 'collaborative',
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      },
      'server',
    );

    await waitForHealth(`http://127.0.0.1:${serverPort}/health`, 20000);
    console.log('[orchestrator] server healthy');

    proxyProc = spawnWithLogs(
      process.execPath,
      ['scripts/ws-wan-proxy.js'],
      {
        cwd: serverDir,
        env: {
          ...process.env,
          PROXY_HOST: '127.0.0.1',
          PROXY_PORT: String(proxyPort),
          TARGET_WS_URL: wsTarget,
          WAN_BASE_DELAY_MS: String(delayMs),
          WAN_JITTER_MS: String(jitterMs),
          WAN_PACKET_LOSS_PCT: String(lossPct),
          WAN_DUPLICATE_PCT: String(duplicatePct),
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      },
      'proxy',
    );

    await waitForHealth(`http://127.0.0.1:${proxyPort}/health`, 10000);
    console.log('[orchestrator] proxy healthy');

    const cargoArgs = [
      'run',
      '--bin',
      'wt_tauri_wan_test',
      '--',
      `--rounds=${rounds}`,
      `--concurrent-rounds=${concurrentRounds}`,
      `--p95-limit-ms=${p95LimitMs}`,
      `--max-limit-ms=${maxLimitMs}`,
    ];

    const testExitCode = await new Promise((resolve, reject) => {
      const proc = spawnWithLogs(
        'cargo',
        cargoArgs,
        {
          cwd: tauriDir,
          env: {
            ...process.env,
            STREAMVAULT_WS_URL: wsProxy,
          },
          stdio: ['ignore', 'pipe', 'pipe'],
        },
        'tauri-test',
      );

      proc.on('error', reject);
      proc.on('exit', (code) => resolve(code ?? 1));
    });

    if (testExitCode !== 0) {
      throw new Error(`Tauri WAN test failed with exit code ${testExitCode}`);
    }

    console.log('[orchestrator] PASS - WAN Tauri E2E completed');
  } finally {
    await Promise.allSettled([
      killChild(proxyProc, 'proxy'),
      killChild(serverProc, 'server'),
    ]);
  }
}

main().catch((err) => {
  console.error(`[orchestrator] FAIL - ${err.message}`);
  process.exit(1);
});
