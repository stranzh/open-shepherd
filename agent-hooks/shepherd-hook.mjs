#!/usr/bin/env node
// Open-Shepherd hook for Claude Code and AI CLI agents.
// Reads hook JSON from stdin and logs security events to ~/.open-shepherd/events.jsonl.

import fs from 'fs';
import os from 'os';
import path from 'path';

const logPath = process.env.OPEN_SHEPHERD_LOG || path.join(os.homedir(), '.open-shepherd', 'events.jsonl');
const webhookUrl = process.env.OPEN_SHEPHERD_WEBHOOK;

function summarizeToolInput(toolInput) {
  if (!toolInput || typeof toolInput !== 'object') {
    return null;
  }
  const summary = {};
  for (const key of ['command', 'file_path', 'path', 'url', 'pattern']) {
    if (typeof toolInput[key] === 'string') {
      summary[key] = toolInput[key].slice(0, 500);
    }
  }
  return Object.keys(summary).length > 0 ? summary : null;
}

const MAX_STDIN_BYTES = 256 * 1024;
let raw = '';
let truncated = false;
process.stdin.setEncoding('utf8');
process.stdin.on('error', () => process.exit(0));
process.stdin.on('data', (chunk) => {
  if (truncated) return;
  if (raw.length + chunk.length > MAX_STDIN_BYTES) {
    raw += chunk.slice(0, MAX_STDIN_BYTES - raw.length);
    truncated = true;
    process.stdin.destroy();
  } else {
    raw += chunk;
  }
});
process.stdin.on('end', () => {
  let input = {};
  try {
    const parsed = raw.trim() ? JSON.parse(raw) : {};
    input = parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    input = { raw: raw.slice(0, 500) };
  }

  const event = {
    timestamp: new Date().toISOString(),
    source: 'agent-hook',
    event_type: input.hook_event_name || process.argv[2] || 'tool_use',
    severity: 'info',
    details: {
      tool_name: input.tool_name || null,
      tool_input: summarizeToolInput(input.tool_input),
      session_id: input.session_id || null,
      cwd: input.cwd || process.cwd(),
    },
  };

  try {
    fs.mkdirSync(path.dirname(logPath), { recursive: true, mode: 0o700 });
    fs.appendFileSync(logPath, JSON.stringify(event) + '\n', { encoding: 'utf8', mode: 0o600 });
  } catch {
    // Never block the agent on logging failure.
  }

  if (webhookUrl) {
    try {
      const parsedUrl = new URL(webhookUrl);
      const isLoopback = ['localhost', '127.0.0.1', '::1', '[::1]'].includes(parsedUrl.hostname);
      if (parsedUrl.protocol === 'https:' || (parsedUrl.protocol === 'http:' && isLoopback)) {
        fetch(webhookUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(event),
          redirect: 'error',
          signal: AbortSignal.timeout(2000),
        }).catch(() => {});
      }
    } catch {
      // Ignore invalid webhook URL
    }
  }
});
