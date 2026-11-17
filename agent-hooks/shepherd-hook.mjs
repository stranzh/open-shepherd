#!/usr/bin/env node
// Open-Shepherd hook for Claude Code and AI CLI agents.
// Reads hook JSON from stdin and logs security events to ~/.open-shepherd/events.jsonl.

import fs from 'fs';
import os from 'os';
import path from 'path';

const logPath = process.env.OPEN_SHEPHERD_LOG || path.join(os.homedir(), '.open-shepherd', 'events.jsonl');
const webhookUrl = process.env.OPEN_SHEPHERD_WEBHOOK;

let raw = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => (raw += chunk));
process.stdin.on('end', () => {
  let input = {};
  try {
    input = raw.trim() ? JSON.parse(raw) : {};
  } catch {
    input = { raw };
  }

  const event = {
    timestamp: new Date().toISOString(),
    source: 'agent-hook',
    event_type: input.hook_event_name || process.argv[2] || 'tool_use',
    severity: 'info',
    details: {
      tool_name: input.tool_name || null,
      session_id: input.session_id || null,
      cwd: input.cwd || process.cwd(),
    },
  };

  try {
    fs.mkdirSync(path.dirname(logPath), { recursive: true });
    fs.appendFileSync(logPath, JSON.stringify(event) + '\n', 'utf8');
  } catch {
    // Never block the agent on logging failure.
  }

  if (webhookUrl) {
    fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(event),
    }).catch(() => {});
  }
});
