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

const TOOL_INPUT_KEYS = [
  'command',
  'CommandLine',
  'file_path',
  'path',
  'AbsolutePath',
  'TargetFile',
  'DirectoryPath',
  'SearchDirectory',
  'SearchPath',
  'url',
  'Url',
  'pattern',
  'Query',
  'Prompt',
];

const FILE_PATH_KEYS = [
  'file_path',
  'path',
  'AbsolutePath',
  'TargetFile',
  'DirectoryPath',
  'SearchDirectory',
  'SearchPath',
];

const PROMPT_INJECTION_RE = /(?:ignore\s+(?:all\s+)?previous\s+instructions|(?:curl|wget)[^\n|]*\|\s*(?:sh|bash)\b)/i;

function summarizeToolInput(toolInput) {
  if (!toolInput || typeof toolInput !== 'object') {
    return null;
  }
  const summary = {};
  for (const key of TOOL_INPUT_KEYS) {
    if (typeof toolInput[key] === 'string') {
      summary[key] = toolInput[key].slice(0, 500);
    }
  }
  if (Array.isArray(toolInput.Subagents)) {
    summary.subagents_count = toolInput.Subagents.length;
  }
  return Object.keys(summary).length > 0 ? summary : null;
}

function normalizeFsPath(p) {
  const resolved = path.resolve(p);
  return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
}

function isUnsafeSessionCwd(cwd) {
  if (!cwd || typeof cwd !== 'string') {
    return false;
  }
  const homeDir = process.env.OPEN_SHEPHERD_HOME || os.homedir();
  const normalizedCwd = normalizeFsPath(cwd);
  const unsafeDirs = [normalizeFsPath(homeDir), normalizeFsPath(path.join(homeDir, 'Downloads'))];
  return unsafeDirs.includes(normalizedCwd);
}

function evaluatePolicy(input, eventType, sessionCwd) {
  if (isUnsafeSessionCwd(sessionCwd)) {
    return 'Unsafe session working directory (home or Downloads) blocked by Open Shepherd policy; isolate in a project subdirectory or use nono.sh';
  }

  if (
    eventType === 'PreInvocation' &&
    typeof input.lastUserInput === 'string' &&
    PROMPT_INJECTION_RE.test(input.lastUserInput)
  ) {
    return 'Suspicious prompt injection or remote shell directive in PreInvocation input';
  }

  const toolName = input.tool_name || input.toolCall?.name || null;
  const toolInput = input.tool_input || input.toolCall?.args || null;
  if (!toolInput || typeof toolInput !== 'object') {
    return null;
  }

  if (
    toolName === 'define_subagent' &&
    (toolInput.enable_write_tools === true || toolInput.enable_mcp_tools === true)
  ) {
    return 'Privileged subagent definition (write/MCP tools enabled) blocked by Open Shepherd policy';
  }

  let filePath = '';
  for (const key of FILE_PATH_KEYS) {
    if (typeof toolInput[key] === 'string' && toolInput[key].length > 0) {
      filePath = toolInput[key];
      break;
    }
  }
  if (filePath && SENSITIVE_PATH_RE.test(filePath)) {
    return `Sensitive file access blocked by Open Shepherd policy: ${filePath}`;
  }

  const cmd =
    typeof toolInput.command === 'string'
      ? toolInput.command
      : typeof toolInput.CommandLine === 'string'
        ? toolInput.CommandLine
        : '';
  if (cmd && DANGEROUS_COMMAND_RE.test(cmd)) {
    return `Dangerous shell command blocked by Open Shepherd policy`;
  }

  const url =
    typeof toolInput.url === 'string' ? toolInput.url : typeof toolInput.Url === 'string' ? toolInput.Url : '';
  if (url && SUSPICIOUS_URL_RE.test(url)) {
    return `Suspicious or metadata URL blocked by Open Shepherd policy: ${url}`;
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

  const isAntigravity = Boolean(input.toolCall || input.conversationId || input.workspacePaths);
  const toolName = input.tool_name || input.toolCall?.name || null;
  const toolInput = input.tool_input || input.toolCall?.args || null;
  const eventType =
    input.hook_event_name ||
    process.argv[2] ||
    (input.toolCall ? 'PreToolUse' : input.invocationNum !== undefined ? 'PreInvocation' : 'tool_use');

  const sessionCwd = input.cwd || (Array.isArray(input.workspacePaths) && input.workspacePaths[0]) || process.cwd();
  let violation = evaluatePolicy(input, eventType, sessionCwd);
  if (!violation && truncated) {
    if (SENSITIVE_PATH_RE.test(raw) || DANGEROUS_COMMAND_RE.test(raw) || SUSPICIOUS_URL_RE.test(raw)) {
      violation = 'Suspicious pattern detected in oversized tool input';
    }
  }
  const blocked = Boolean(
    violation && (eventType === 'PreToolUse' || eventType === 'PreInvocation') && policyMode === 'enforce',
  );

  const event = {
    timestamp: new Date().toISOString(),
    source: 'agent-hook',
    event_type: eventType,
    severity: violation ? 'high' : 'info',
    details: {
      tool_name: toolName,
      tool_input: summarizeToolInput(toolInput),
      session_id: input.session_id || input.conversationId || null,
      cwd: input.cwd || (Array.isArray(input.workspacePaths) && input.workspacePaths[0]) || process.cwd(),
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

  if (isAntigravity) {
    if (eventType === 'PreToolUse') {
      process.stdout.write(
        JSON.stringify(blocked ? { decision: 'deny', reason: violation } : { decision: 'allow' }) + '\n',
      );
    } else if (eventType === 'PreInvocation') {
      process.stdout.write(
        JSON.stringify(
          violation && policyMode === 'enforce'
            ? { injectSteps: [{ errorMessage: { userMessage: violation } }], terminationBehavior: 'terminate' }
            : {},
        ) + '\n',
      );
    } else {
      process.stdout.write('{}\n');
    }
  } else if (blocked && eventType === 'PreToolUse') {
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
