#!/usr/bin/env node
// Open-Shepherd Level 4 HTTP/CONNECT auditing proxy for Antigravity CLI, GUI, and MCP child processes.
// Launch processes with HTTP_PROXY=http://127.0.0.1:8787 HTTPS_PROXY=http://127.0.0.1:8787.

import fs from 'fs';
import http from 'http';
import net from 'net';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';

const BLOCKED_TARGET_RE =
  /(?:169\.254\.169\.254|169\.254\.170\.2|100\.100\.100\.200|metadata\.google\.internal|fd00:ec2::254|(?:^|[./:@])(?:ngrok\.io|webhook\.site|oastify\.com|interact\.sh|burpcollaborator\.(?:me|net)|trycloudflare\.com)(?=$|[:/?#]))/i;

export function evaluateProxyTarget(targetUrlOrHost) {
  const raw = String(targetUrlOrHost || '').trim();
  if (!raw) {
    return { allowed: false, reason: 'Empty proxy target' };
  }
  if (BLOCKED_TARGET_RE.test(raw)) {
    return { allowed: false, reason: `Blocked cloud metadata or exfiltration endpoint: ${raw}` };
  }
  return { allowed: true, reason: null };
}

function logProxyEvent(logPath, method, target, decision, reason) {
  const event = {
    timestamp: new Date().toISOString(),
    source: 'proxy-guard',
    event_type: 'network_egress',
    severity: decision === 'deny' ? 'high' : 'info',
    details: { method, target, decision, reason },
  };
  try {
    fs.mkdirSync(path.dirname(logPath), { recursive: true, mode: 0o700 });
    fs.appendFileSync(logPath, JSON.stringify(event) + '\n', { encoding: 'utf8', mode: 0o600 });
  } catch {
    // Do not crash proxy on logging error.
  }
}

export function createProxyGuardServer(options = {}) {
  const logPath =
    options.logPath || process.env.OPEN_SHEPHERD_LOG || path.join(os.homedir(), '.open-shepherd', 'events.jsonl');
  const mode = (options.mode || process.env.OPEN_SHEPHERD_MODE) === 'audit' ? 'audit' : 'enforce';

  const server = http.createServer((req, res) => {
    const target = req.url || req.headers.host || '';
    const verdict = evaluateProxyTarget(target);
    const blocked = !verdict.allowed && mode === 'enforce';
    const decision = blocked ? 'deny' : !verdict.allowed ? 'audit' : 'allow';
    logProxyEvent(logPath, req.method || 'GET', target, decision, verdict.reason);

    if (blocked) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Blocked by Open Shepherd Proxy Guard', reason: verdict.reason }));
      return;
    }

    try {
      const parsed = new URL(target.startsWith('http') ? target : `http://${req.headers.host || 'localhost'}${target}`);
      const proxyReq = http.request(
        {
          hostname: parsed.hostname,
          port: parsed.port || 80,
          path: parsed.pathname + parsed.search,
          method: req.method,
          headers: req.headers,
        },
        (proxyRes) => {
          res.writeHead(proxyRes.statusCode || 502, proxyRes.headers);
          proxyRes.pipe(res);
        },
      );
      proxyReq.on('error', () => {
        if (!res.headersSent) res.writeHead(502);
        res.end();
      });
      req.pipe(proxyReq);
    } catch {
      res.writeHead(400);
      res.end();
    }
  });

  server.on('connect', (req, clientSocket, head) => {
    const target = req.url || '';
    const verdict = evaluateProxyTarget(target);
    const blocked = !verdict.allowed && mode === 'enforce';
    const decision = blocked ? 'deny' : !verdict.allowed ? 'audit' : 'allow';
    logProxyEvent(logPath, 'CONNECT', target, decision, verdict.reason);

    if (blocked) {
      clientSocket.write(
        'HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nBlocked by Open Shepherd Proxy Guard\r\n',
      );
      clientSocket.destroy();
      return;
    }

    const [host, portStr] = target.split(':');
    const upstream = net.connect(Number(portStr) || 443, host, () => {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head && head.length > 0) upstream.write(head);
      upstream.pipe(clientSocket);
      clientSocket.pipe(upstream);
    });
    upstream.on('error', () => clientSocket.destroy());
    clientSocket.on('error', () => upstream.destroy());
  });

  return server;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.OPEN_SHEPHERD_PROXY_PORT || 8787);
  const host = process.env.OPEN_SHEPHERD_PROXY_HOST || '127.0.0.1';
  createProxyGuardServer().listen(port, host);
}
