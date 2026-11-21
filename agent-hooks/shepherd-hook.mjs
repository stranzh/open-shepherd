#!/usr/bin/env node
// Open-Shepherd hook for Claude Code and AI CLI agents.
// Evaluates PreToolUse policies, logs security events to ~/.open-shepherd/events.jsonl,
// and enforces block decisions unless OPEN_SHEPHERD_MODE=audit.

import fs from 'fs';
import os from 'os';
import path from 'path';

const logPath = process.env.OPEN_SHEPHERD_LOG || path.join(os.homedir(), '.open-shepherd', 'events.jsonl');
const webhookUrl = process.env.OPEN_SHEPHERD_WEBHOOK;
const policyMode = process.env.OPEN_SHEPHERD_MODE === 'audit' ? 'audit' : 'enforce';
const MAX_STDIN_BYTES = 256 * 1024;

const SENSITIVE_PATH_RE =
  /(?:^|[/\\])(?:\.env(?:\.(?!example$|sample$|template$)[^/\\]+)?$|\.ssh[/\\](?:id_rsa|id_ed25519|id_ecdsa|id_dsa)$|\.aws[/\\]credentials$|\.(?:azure|kube)[/\\]|(?:\.git-credentials|\.netrc|\.npmrc|\.pypirc|\.claude[/\\]\.credentials\.json|\.claude\.json)$|[^/\\]+\.(?:pem|key|p12|pfx|jks|keystore)$|Windows[/\\]System32[/\\]config[/\\](?:SAM|SYSTEM|SECURITY)$)/i;

const DANGEROUS_COMMAND_RE =
  /(?:\brm\s+-[a-z]*r[a-z]*f\s+(?:\/|~|\$HOME)(?=$|[\s"'`;|&/\\])|(?:curl|wget)[^\n|]*\|\s*(?:sh|bash|zsh)\b|\b(?:nc|ncat|netcat)\b[^\n]*\s-e\b|\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]*-(?:enc|encodedcommand|executionpolicy\s+bypass)\b|\b(?:Invoke-Expression|terraform\s+destroy|diskpart\.exe|Format-Volume|Clear-Disk)\b|169\.254\.169\.254)/i;

const SUSPICIOUS_URL_RE =
  /(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|ngrok\.io|webhook\.site|oastify\.com|interact\.sh|burpcollaborator\.(?:me|net)|trycloudflare\.com)/i;

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

function evaluatePolicy(input) {
  const toolInput = input.tool_input;
  if (!toolInput || typeof toolInput !== 'object') {
    return null;
  }
  const filePath = typeof toolInput.file_path === 'string' ? toolInput.file_path : typeof toolInput.path === 'string' ? toolInput.path : '';
  if (filePath && SENSITIVE_PATH_RE.test(filePath)) {
    return `Sensitive file access blocked by Open Shepherd policy: ${filePath}`;
  }
  if (typeof toolInput.command === 'string' && DANGEROUS_COMMAND_RE.test(toolInput.command)) {
    return `Dangerous shell command blocked by Open Shepherd policy`;
  }
  if (typeof toolInput.url === 'string' && SUSPICIOUS_URL_RE.test(toolInput.url)) {
    return `Suspicious or metadata URL blocked by Open Shepherd policy: ${toolInput.url}`;
  }
  return null;
}

let raw = '';
let truncated = false;
let handled = false;

function handleInput() {
  if (handled) {
    return;
  }
  handled = true;

  let input = {};
  try {
    const parsed = raw.trim() ? JSON.parse(raw) : {};
    input = parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    const hookMatch = raw.match(/"hook_event_name"\s*:\s*"([^"]+)"/);
    input = {
      hook_event_name: hookMatch ? hookMatch[1] : undefined,
      raw: raw.slice(0, 500),
    };
  }

  const eventType = input.hook_event_name || process.argv[2] || 'tool_use';
  let violation = evaluatePolicy(input);
  if (!violation && truncated) {
    if (SENSITIVE_PATH_RE.test(raw) || DANGEROUS_COMMAND_RE.test(raw) || SUSPICIOUS_URL_RE.test(raw)) {
      violation = 'Suspicious pattern detected in oversized tool input';
    }
  }
  const blocked = Boolean(violation && eventType === 'PreToolUse' && policyMode === 'enforce');

  const event = {
    timestamp: new Date().toISOString(),
    source: 'agent-hook',
    event_type: eventType,
    severity: violation ? 'high' : 'info',
    details: {
      tool_name: input.tool_name || null,
      tool_input: summarizeToolInput(input.tool_input),
      session_id: input.session_id || null,
      cwd: input.cwd || process.cwd(),
      decision: blocked ? 'deny' : violation ? 'audit' : 'allow',
      reason: violation || null,
    },
  };

  try {
    fs.mkdirSync(path.dirname(logPath), { recursive: true, mode: 0o700 });
    fs.appendFileSync(logPath, JSON.stringify(event) + '\n', { encoding: 'utf8', mode: 0o600 });
  } catch {
    // Never block the agent on logging failure.
  }

  if (webhookUrl && violation) {
    try {
      const parsedUrl = new URL(webhookUrl);
      const isLoopback = ['localhost', '127.0.0.1', '::1', '[::1]'].includes(parsedUrl.hostname);
      if (parsedUrl.protocol === 'https:' || (parsedUrl.protocol === 'http:' && isLoopback)) {
        fetch(webhookUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(event),
          redirect: 'error',
          signal: AbortSignal.timeout(500),
        }).catch(() => {});
      }
    } catch {
      // Ignore invalid webhook URL
    }
  }

  if (blocked) {
    process.stdout.write(
      JSON.stringify({
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'deny',
          permissionDecisionReason: violation,
        },
      }) + '\n',
    );
  }
}

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
process.stdin.on('end', handleInput);
process.stdin.on('close', handleInput);
