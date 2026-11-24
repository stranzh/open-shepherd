/**
 * Extended AI IDE & MCP Configuration Rules
 *
 * Pure detection helpers for AI workspace auto-approve settings, API base URL
 * overrides (CVE-2026-21852), Claude Code/Cursor CLI configs, Codex TOML,
 * Zed context_servers, OpenCode configs, MCP auth verification, and stdio script pinning.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { SeverityLevel } from '../lib/events/sec-events';
import {
  WorkspaceFinding,
  WorkspaceRuleType,
  isLocalEndpointUrl,
  isPlainObject,
  safeParseJson,
  scanHooksObject,
} from './workspace-rule-types';

const OFFICIAL_OR_LOCAL_AI_HOSTS = new Set([
  'localhost',
  '127.0.0.1',
  '::1',
  'api.anthropic.com',
  'api.openai.com',
  'generativelanguage.googleapis.com',
]);

const AI_BASE_URL_ENV_KEY_RE =
  /^(?:(?:ANTHROPIC|OPENAI|GEMINI|CURSOR|COPILOT|CLAUDE|CODEX|MISTRAL|COHERE|GROQ|DEEPSEEK|BEDROCK|OLLAMA|OPENROUTER|AZURE_OPENAI)_(?:BASE_URL|API_BASE|API_URL|ENDPOINT)|OPENAI_API_BASE|ANTHROPIC_API_URL|AZURE_OPENAI_ENDPOINT)$/i;
const BARE_SERVER_BASE_URL_KEY_RE = /^(?:BASE_URL|API_BASE|ENDPOINT)$/i;
const AUTH_HEADER_KEY_RE =
  /^(?:authorization|x-api-key|api-key|x-auth-token|x-goog-api-key|proxy-authorization)$|(?:auth|bearer|token|api[-_]?key|secret)/i;

const UNPINNED_OR_SHELL_MCP_RE = /\bnpx\b.*(?:-y|--yes)/i;
const UVX_RE = /\buvx\b/i;
const SHELL_DOWNLOAD_RE = /(?:curl|wget|\|\s*(?:sh|bash))/i;
const SCRIPT_EXT_RE = /\.(?:js|mjs|cjs|ts|py|sh)$/i;
const URI_SCHEME_RE = /^[a-z][a-z0-9+.-]*:\/\//i;
const CURSOR_WILDCARD_PERMISSION_RE = /^(?:\*{1,2}|(?:shell|bash|command|exec)\(\s*(?:[^)]*\*\s*[^)]*|all)\s*\))$/i;

export interface NormalizedMcpServerSpec {
  name: string;
  fullCmd?: string;
  url?: string;
  authed?: boolean;
  envObjects?: Array<{ label: string; env: Record<string, unknown>; allowBareBaseUrl?: boolean }>;
  sourcePrefix?: string;
}

export function isUnpinnedOrShellCmd(fullCmd: string): boolean {
  return UNPINNED_OR_SHELL_MCP_RE.test(fullCmd) || UVX_RE.test(fullCmd) || SHELL_DOWNLOAD_RE.test(fullCmd);
}

export function isCustomAiBaseUrl(url: string): boolean {
  const trimmed = url.trim();
  if (!trimmed) {
    return false;
  }

  if (trimmed.startsWith('$')) {
    const defaultMatch = trimmed.match(/^\$\{[^}:]+(?::-|:=)([^}]*)\}(.*)$/);
    if (defaultMatch) {
      const candidate = (defaultMatch[1] + defaultMatch[2]).trim();
      return candidate.length > 0 ? isCustomAiBaseUrl(candidate) : false;
    }
    const schemeIdx = trimmed.search(URI_SCHEME_RE);
    if (schemeIdx !== -1) {
      return isCustomAiBaseUrl(trimmed.slice(schemeIdx));
    }
    if (/^\$(?:[A-Za-z_][A-Za-z0-9_]*|\{(?:env:)?[A-Za-z_][A-Za-z0-9_]*\})(?:\/[^\s]*)?$/.test(trimmed)) {
      return false;
    }
    return true;
  }

  let targetToParse = trimmed;
  if (!/^https?:\/\//i.test(trimmed)) {
    if (URI_SCHEME_RE.test(trimmed)) {
      return true;
    }
    targetToParse = `https://${trimmed}`;
  }

  try {
    const parsed = new URL(targetToParse);
    const bareHost = parsed.hostname
      .toLowerCase()
      .replace(/^\[|\]$/g, '')
      .replace(/\.$/, '');
    if (!bareHost) {
      return true;
    }
    return !OFFICIAL_OR_LOCAL_AI_HOSTS.has(bareHost);
  } catch {
    return true;
  }
}

function buildBaseUrlOverrideFinding(
  key: string,
  val: string,
  filePath: string,
  sourceLabel: string,
  ruleType: WorkspaceRuleType,
): WorkspaceFinding {
  return {
    ruleId: 'ai_api_base_url_override',
    ruleName: 'Custom AI API Base URL Override',
    type: ruleType,
    severity: SeverityLevel.HIGH,
    filePath,
    finding: `${key}=${val}`,
    description: `${sourceLabel} overrides "${key}" to non-official/non-local endpoint "${val}" (CVE-2026-21852)`,
    confidence: 0.95,
  };
}

export function checkBaseUrlOverridesInEnv(
  envObj: Record<string, unknown> | undefined,
  filePath: string,
  sourceLabel: string,
  ruleType: WorkspaceRuleType = WorkspaceRuleType.AGENT_RULES,
  allowBareBaseUrl = false,
): WorkspaceFinding[] {
  if (!isPlainObject(envObj)) {
    return [];
  }
  const findings: WorkspaceFinding[] = [];
  for (const [key, val] of Object.entries(envObj)) {
    const isTargetKey = AI_BASE_URL_ENV_KEY_RE.test(key) || (allowBareBaseUrl && BARE_SERVER_BASE_URL_KEY_RE.test(key));
    if (isTargetKey && typeof val === 'string' && isCustomAiBaseUrl(val)) {
      findings.push(buildBaseUrlOverrideFinding(key, val.trim(), filePath, sourceLabel, ruleType));
    }
  }
  return findings;
}

function hasAuthHeaders(val: unknown): boolean {
  if (!isPlainObject(val)) {
    return false;
  }
  return Object.entries(val).some(
    ([key, entryVal]) =>
      AUTH_HEADER_KEY_RE.test(key.trim()) &&
      entryVal !== null &&
      entryVal !== undefined &&
      String(entryVal).trim().length > 0,
  );
}

function hasValidAuthConfig(authVal: unknown): boolean {
  if (typeof authVal === 'string') {
    const norm = authVal.trim().toLowerCase();
    return norm.length > 0 && !['none', 'false', 'off', 'disabled', 'no'].includes(norm);
  }
  if (!isPlainObject(authVal)) {
    return false;
  }
  if (authVal.enabled === false) {
    return false;
  }
  if (
    typeof authVal.type === 'string' &&
    ['none', 'false', 'off', 'disabled'].includes(authVal.type.trim().toLowerCase())
  ) {
    return false;
  }
  return Object.entries(authVal).some(([key, entryVal]) => {
    if (key === 'enabled') {
      return entryVal === true;
    }
    return entryVal !== null && entryVal !== undefined && entryVal !== false && String(entryVal).trim().length > 0;
  });
}

export function hasMcpAuth(cfg: Record<string, any>): boolean {
  if (!isPlainObject(cfg)) {
    return false;
  }
  if (hasAuthHeaders(cfg.headers) || hasAuthHeaders(cfg.http_headers) || hasAuthHeaders(cfg.env_http_headers)) {
    return true;
  }
  if (hasValidAuthConfig(cfg.auth)) {
    return true;
  }
  if (typeof cfg.bearer_token_env_var === 'string' && cfg.bearer_token_env_var.trim().length > 0) {
    return true;
  }
  if (isPlainObject(cfg.env)) {
    for (const [k, v] of Object.entries(cfg.env)) {
      if (/^authorization$/i.test(k) && typeof v === 'string' && v.trim().length > 0) {
        return true;
      }
    }
  }
  if (typeof cfg.apiKey === 'string' && cfg.apiKey.trim().length > 0) {
    return true;
  }
  if (typeof cfg.token === 'string' && cfg.token.trim().length > 0) {
    return true;
  }
  return false;
}

export function evaluateMcpServerFindings(spec: NormalizedMcpServerSpec, filePath: string): WorkspaceFinding[] {
  const findings: WorkspaceFinding[] = [];
  const prefix = spec.sourcePrefix || 'MCP server';
  const fullCmd = (spec.fullCmd || '').replace(/\s+/g, ' ').trim();
  const url = spec.url?.trim() || '';

  if (fullCmd && isUnpinnedOrShellCmd(fullCmd)) {
    findings.push({
      ruleId: 'mcp_unpinned_or_shell_server',
      ruleName: 'Suspicious MCP Server Command',
      type: WorkspaceRuleType.MCP_CONFIG,
      severity: SeverityLevel.HIGH,
      filePath,
      finding: `${spec.name}: ${fullCmd.slice(0, 160)}`,
      description: `${prefix} "${spec.name}" executes unpinned package runner or shell download command`,
      confidence: 0.9,
    });
  }

  if (url && !isLocalEndpointUrl(url)) {
    const authed = Boolean(spec.authed);
    findings.push({
      ruleId: 'mcp_remote_endpoint',
      ruleName: 'Remote MCP Server Endpoint',
      type: WorkspaceRuleType.MCP_CONFIG,
      severity: authed ? SeverityLevel.MEDIUM : SeverityLevel.HIGH,
      filePath,
      finding: `${spec.name}: ${url}`,
      description: authed
        ? `${prefix} "${spec.name}" connects to non-local remote endpoint ${url}`
        : `${prefix} "${spec.name}" connects to non-local remote endpoint ${url} without authentication`,
      confidence: 0.85,
    });
  }

  for (const item of spec.envObjects ?? []) {
    findings.push(
      ...checkBaseUrlOverridesInEnv(
        item.env,
        filePath,
        item.label,
        WorkspaceRuleType.MCP_CONFIG,
        item.allowBareBaseUrl ?? true,
      ),
    );
  }

  return findings;
}

function hasDangerousAutoApproveObject(val: Record<string, unknown>): boolean {
  for (const [key, entry] of Object.entries(val)) {
    const isTruthyApprove =
      entry === true || (isPlainObject(entry) && (entry.approve === true || entry.autoApprove === true));
    if (!isTruthyApprove) {
      continue;
    }
    const trimmedKey = key.trim();
    if (
      trimmedKey.includes('*') ||
      /^(?:all|any|true|enabled|auto[-_]?approve|default|\.\*|\/\.\*\/)$/i.test(trimmedKey) ||
      /(?:shell|bash|terminal|command|exec|run|tool)/i.test(trimmedKey)
    ) {
      return true;
    }
  }
  return false;
}

export function scanAiWorkspaceSettings(json: Record<string, any>, filePath: string): WorkspaceFinding[] {
  if (!isPlainObject(json)) {
    return [];
  }
  const findings: WorkspaceFinding[] = [];

  for (const autoKey of [
    'chat.tools.autoApprove',
    'chat.tools.global.autoApprove',
    'chat.tools.terminal.autoApprove',
  ]) {
    const val = json[autoKey];
    if (val === true || (isPlainObject(val) && hasDangerousAutoApproveObject(val))) {
      findings.push({
        ruleId: 'ai_chat_tools_auto_approve',
        ruleName: 'AI Chat Tools Auto-Approve Enabled',
        type: WorkspaceRuleType.VSCODE_CONFIG,
        severity: SeverityLevel.HIGH,
        filePath,
        finding: `${autoKey}: ${JSON.stringify(val).slice(0, 120)}`,
        description: `Workspace settings enable "${autoKey}", bypassing tool execution approval (CVE-2025-53773)`,
        confidence: 0.95,
      });
      break;
    }
  }

  const chatPermDefault = json['chat.permissions.default'];
  if (typeof chatPermDefault === 'string' && /^(?:allow|bypass|auto)$/i.test(chatPermDefault.trim())) {
    findings.push({
      ruleId: 'ai_chat_permissive_default',
      ruleName: 'Permissive AI Chat Default Permission',
      type: WorkspaceRuleType.VSCODE_CONFIG,
      severity: SeverityLevel.HIGH,
      filePath,
      finding: `chat.permissions.default: ${chatPermDefault.trim()}`,
      description: `Workspace settings configure permissive chat.permissions.default "${chatPermDefault.trim()}"`,
      confidence: 0.9,
    });
  }

  if (isPlainObject(json.env)) {
    findings.push(
      ...checkBaseUrlOverridesInEnv(json.env, filePath, 'Workspace settings env', WorkspaceRuleType.VSCODE_CONFIG),
    );
  }

  for (const key of Object.keys(json)) {
    if (key.startsWith('terminal.integrated.env.') && isPlainObject(json[key])) {
      findings.push(
        ...checkBaseUrlOverridesInEnv(
          json[key] as Record<string, unknown>,
          filePath,
          key,
          WorkspaceRuleType.VSCODE_CONFIG,
        ),
      );
    }
  }

  return findings;
}

export function scanClaudeSettings(content: string, filePath: string): WorkspaceFinding[] {
  const json = safeParseJson(content);
  if (!json || Array.isArray(json)) {
    return [];
  }
  const findings: WorkspaceFinding[] = [];

  if (json.enableAllProjectMcpServers === true) {
    findings.push({
      ruleId: 'claude_enable_all_project_mcp',
      ruleName: 'Claude Code Auto-Enabled All Project MCP Servers',
      type: WorkspaceRuleType.MCP_CONFIG,
      severity: SeverityLevel.HIGH,
      filePath,
      finding: 'enableAllProjectMcpServers: true',
      description:
        'Claude Code settings enable enableAllProjectMcpServers, running workspace MCP servers without approval (CVE-2025-59536)',
      confidence: 0.95,
    });
  }

  if (isPlainObject(json.env)) {
    findings.push(
      ...checkBaseUrlOverridesInEnv(json.env, filePath, 'Claude settings env', WorkspaceRuleType.AGENT_RULES),
    );
  }

  if (isPlainObject(json.hooks)) {
    findings.push(...scanHooksObject(json.hooks, filePath));
  }

  return findings;
}

export function scanCursorCliConfig(content: string, filePath: string): WorkspaceFinding[] {
  const json = safeParseJson(content);
  if (!json || Array.isArray(json)) {
    return [];
  }
  const findings: WorkspaceFinding[] = [];

  if (json.autoApprove === true) {
    findings.push({
      ruleId: 'cursor_cli_dangerous_config',
      ruleName: 'Cursor CLI Dangerous Auto-Approve Configuration',
      type: WorkspaceRuleType.AGENT_RULES,
      severity: SeverityLevel.HIGH,
      filePath,
      finding: 'autoApprove: true',
      description:
        'Cursor CLI config enables autoApprove: true, executing tools/commands without confirmation (CVE-2026-48124)',
      confidence: 0.95,
    });
  }

  const permissions = isPlainObject(json.permissions) ? json.permissions : undefined;
  const allowList = permissions && Array.isArray(permissions.allow) ? permissions.allow : [];
  for (const entry of allowList) {
    if (typeof entry === 'string' && CURSOR_WILDCARD_PERMISSION_RE.test(entry.trim())) {
      findings.push({
        ruleId: 'cursor_cli_dangerous_config',
        ruleName: 'Cursor CLI Wildcard Command Permission',
        type: WorkspaceRuleType.AGENT_RULES,
        severity: SeverityLevel.HIGH,
        filePath,
        finding: `permissions.allow: ${entry.trim()}`,
        description: `Cursor CLI config grants wildcard execution permission "${entry.trim()}" (CVE-2026-48124)`,
        confidence: 0.95,
      });
      break;
    }
  }

  if (isPlainObject(json.env)) {
    findings.push(...checkBaseUrlOverridesInEnv(json.env, filePath, 'Cursor CLI env', WorkspaceRuleType.AGENT_RULES));
  }

  return findings;
}

function splitTomlStatements(content: string): string[] {
  const statements: string[] = [];
  let buf = '';
  let inDouble = false;
  let inSingle = false;
  let inMultiDouble = false;
  let inMultiSingle = false;
  let inComment = false;
  let escaped = false;
  let bracketDepth = 0;

  const flush = (): void => {
    const trimmed = buf.trim();
    if (trimmed.length > 0) {
      statements.push(trimmed);
    }
    buf = '';
  };

  for (let i = 0; i < content.length; i++) {
    const ch = content[i];

    if (inComment) {
      if (ch === '\n') {
        inComment = false;
        if (bracketDepth === 0) {
          flush();
        } else {
          buf += ' ';
        }
      }
      continue;
    }

    if (inMultiDouble) {
      if (escaped) {
        buf += ch;
        escaped = false;
        continue;
      }
      if (ch === '\\') {
        buf += ch;
        escaped = true;
        continue;
      }
      if (ch === '"' && content[i + 1] === '"' && content[i + 2] === '"' && content[i + 3] !== '"') {
        buf += '"""';
        i += 2;
        inMultiDouble = false;
        continue;
      }
      buf += ch;
      continue;
    }

    if (inMultiSingle) {
      if (ch === "'" && content[i + 1] === "'" && content[i + 2] === "'" && content[i + 3] !== "'") {
        buf += "'''";
        i += 2;
        inMultiSingle = false;
        continue;
      }
      buf += ch;
      continue;
    }

    if (inDouble) {
      if (ch === '\n') {
        inDouble = false;
        escaped = false;
        if (bracketDepth === 0) {
          flush();
        } else {
          buf += ' ';
        }
        continue;
      }
      buf += ch;
      if (escaped) {
        escaped = false;
      } else if (ch === '\\') {
        escaped = true;
      } else if (ch === '"') {
        inDouble = false;
      }
      continue;
    }

    if (inSingle) {
      if (ch === '\n') {
        inSingle = false;
        if (bracketDepth === 0) {
          flush();
        } else {
          buf += ' ';
        }
        continue;
      }
      buf += ch;
      if (ch === "'") {
        inSingle = false;
      }
      continue;
    }

    if (ch === '#') {
      inComment = true;
      continue;
    }
    if (ch === '"' && content[i + 1] === '"' && content[i + 2] === '"') {
      buf += '"""';
      i += 2;
      inMultiDouble = true;
      continue;
    }
    if (ch === "'" && content[i + 1] === "'" && content[i + 2] === "'") {
      buf += "'''";
      i += 2;
      inMultiSingle = true;
      continue;
    }
    if (ch === '"') {
      inDouble = true;
      buf += ch;
      continue;
    }
    if (ch === "'") {
      inSingle = true;
      buf += ch;
      continue;
    }
    if (ch === '[' || ch === '{') {
      bracketDepth++;
      buf += ch;
      continue;
    }
    if (ch === ']' || ch === '}') {
      if (bracketDepth > 0) {
        bracketDepth--;
      }
      buf += ch;
      continue;
    }
    if (ch === '\r') {
      continue;
    }
    if (ch === '\n') {
      if (bracketDepth === 0) {
        flush();
      } else {
        buf += ' ';
      }
      continue;
    }
    buf += ch;
  }

  flush();
  return statements;
}

function decodeTomlBasicString(inner: string): string {
  const withoutLineContinuations = inner.replace(/\\\r?\n[ \t]*/g, '');
  return withoutLineContinuations.replace(/\\(["\\bfnrt]|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8})/g, (_m, seq: string) => {
    if (seq.startsWith('u') || seq.startsWith('U')) {
      const cp = parseInt(seq.slice(1), 16);
      return cp <= 0x10ffff ? String.fromCodePoint(cp) : '';
    }
    switch (seq) {
      case 'b':
        return '\b';
      case 'f':
        return '\f';
      case 'n':
        return '\n';
      case 'r':
        return '\r';
      case 't':
        return '\t';
      default:
        return seq;
    }
  });
}

function unquoteTomlToken(raw: string): string {
  const trimmed = raw.trim();
  if (trimmed.startsWith('"""') && trimmed.endsWith('"""') && trimmed.length >= 6) {
    return decodeTomlBasicString(trimmed.slice(3, -3).replace(/^\r?\n/, ''));
  }
  if (trimmed.startsWith("'''") && trimmed.endsWith("'''") && trimmed.length >= 6) {
    return trimmed.slice(3, -3).replace(/^\r?\n/, '');
  }
  if (trimmed.startsWith('"') && trimmed.endsWith('"') && trimmed.length >= 2) {
    return decodeTomlBasicString(trimmed.slice(1, -1));
  }
  if (trimmed.startsWith("'") && trimmed.endsWith("'") && trimmed.length >= 2) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function scanTopLevelToml(raw: string, onChar: (ch: string, idx: number, depth: number) => boolean | void): void {
  let depth = 0;
  let inDouble = false;
  let inSingle = false;
  let inMultiDouble = false;
  let inMultiSingle = false;
  let escaped = false;

  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (inMultiDouble) {
      if (escaped) {
        escaped = false;
      } else if (ch === '\\') {
        escaped = true;
      } else if (ch === '"' && raw[i + 1] === '"' && raw[i + 2] === '"' && raw[i + 3] !== '"') {
        i += 2;
        inMultiDouble = false;
      }
      continue;
    }
    if (inMultiSingle) {
      if (ch === "'" && raw[i + 1] === "'" && raw[i + 2] === "'" && raw[i + 3] !== "'") {
        i += 2;
        inMultiSingle = false;
      }
      continue;
    }
    if (inDouble) {
      if (escaped) {
        escaped = false;
      } else if (ch === '\\') {
        escaped = true;
      } else if (ch === '"') {
        inDouble = false;
      }
      continue;
    }
    if (inSingle) {
      if (ch === "'") {
        inSingle = false;
      }
      continue;
    }

    if (ch === '"' && raw[i + 1] === '"' && raw[i + 2] === '"') {
      i += 2;
      inMultiDouble = true;
    } else if (ch === "'" && raw[i + 1] === "'" && raw[i + 2] === "'") {
      i += 2;
      inMultiSingle = true;
    } else if (ch === '"') {
      inDouble = true;
    } else if (ch === "'") {
      inSingle = true;
    } else if (ch === '[' || ch === '{') {
      depth++;
    } else if (ch === ']' || ch === '}') {
      if (depth > 0) {
        depth--;
      }
    } else if (onChar(ch, i, depth) === true) {
      return;
    }
  }
}

function splitTopLevelToml(raw: string, delimiter: string): string[] {
  const parts: string[] = [];
  let start = 0;
  scanTopLevelToml(raw, (ch, idx, depth) => {
    if (ch === delimiter && depth === 0) {
      parts.push(raw.slice(start, idx));
      start = idx + 1;
    }
  });
  parts.push(raw.slice(start));
  return parts;
}

function findFirstTopLevelEquals(line: string): number {
  let found = -1;
  scanTopLevelToml(line, (ch, idx, depth) => {
    if (ch === '=' && depth === 0) {
      found = idx;
      return true;
    }
  });
  return found;
}

function parseTomlValue(raw: string): unknown {
  const trimmed = raw.trim();
  if (!trimmed) {
    return '';
  }
  if (
    (trimmed.startsWith('"""') && trimmed.endsWith('"""') && trimmed.length >= 6) ||
    (trimmed.startsWith("'''") && trimmed.endsWith("'''") && trimmed.length >= 6) ||
    (trimmed.startsWith('"') && trimmed.endsWith('"') && trimmed.length >= 2) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'") && trimmed.length >= 2)
  ) {
    return unquoteTomlToken(trimmed);
  }
  if (trimmed === 'true') {
    return true;
  }
  if (trimmed === 'false') {
    return false;
  }
  if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
    const inner = trimmed.slice(1, -1).trim();
    if (!inner) {
      return [];
    }
    return splitTopLevelToml(inner, ',')
      .map((item) => item.trim())
      .filter((item) => item.length > 0)
      .map((item) => parseTomlValue(item));
  }
  if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
    const inner = trimmed.slice(1, -1).trim();
    const obj: Record<string, unknown> = {};
    if (!inner) {
      return obj;
    }
    for (const pair of splitTopLevelToml(inner, ',')) {
      const eqIdx = findFirstTopLevelEquals(pair);
      if (eqIdx === -1) {
        continue;
      }
      const keySegments = splitTopLevelToml(pair.slice(0, eqIdx), '.')
        .map((seg) => unquoteTomlToken(seg))
        .filter((seg) => seg.length > 0);
      const val = parseTomlValue(pair.slice(eqIdx + 1));
      if (keySegments.length === 1) {
        obj[keySegments[0]] = val;
      } else if (keySegments.length > 1) {
        let cursor = obj;
        for (let idx = 0; idx < keySegments.length - 1; idx++) {
          const seg = keySegments[idx];
          if (!isPlainObject(cursor[seg])) {
            cursor[seg] = {};
          }
          cursor = cursor[seg] as Record<string, unknown>;
        }
        cursor[keySegments[keySegments.length - 1]] = val;
      }
    }
    return obj;
  }
  return unquoteTomlToken(trimmed);
}

interface CodexTomlData {
  topLevel: Record<string, unknown>;
  env: Record<string, unknown>;
  mcpServers: Record<string, Record<string, unknown>>;
}

function assignNestedMap(target: Record<string, unknown>, pathSegments: string[], value: unknown): void {
  if (pathSegments.length === 0) {
    return;
  }
  if (pathSegments.length === 1) {
    const k = pathSegments[0];
    if (isPlainObject(value) && isPlainObject(target[k])) {
      Object.assign(target[k] as Record<string, unknown>, value);
    } else {
      target[k] = value;
    }
    return;
  }
  let cursor = target;
  for (let i = 0; i < pathSegments.length - 1; i++) {
    const seg = pathSegments[i];
    if (!isPlainObject(cursor[seg])) {
      cursor[seg] = {};
    }
    cursor = cursor[seg] as Record<string, unknown>;
  }
  const leaf = pathSegments[pathSegments.length - 1];
  if (isPlainObject(value) && isPlainObject(cursor[leaf])) {
    Object.assign(cursor[leaf] as Record<string, unknown>, value);
  } else {
    cursor[leaf] = value;
  }
}

function parseCodexToml(content: string): CodexTomlData {
  const data: CodexTomlData = { topLevel: {}, env: {}, mcpServers: {} };
  let currentSection: string[] = [];

  for (const line of splitTomlStatements(content)) {
    if (line.startsWith('[[') && line.endsWith(']]')) {
      currentSection = [];
      continue;
    }

    if (line.startsWith('[') && line.endsWith(']')) {
      const headerInner = line.slice(1, -1).trim();
      currentSection = splitTopLevelToml(headerInner, '.')
        .map((seg) => unquoteTomlToken(seg))
        .filter((seg) => seg.length > 0);
      if (currentSection[0] === 'mcp_servers' && currentSection[1]) {
        data.mcpServers[currentSection[1]] ??= {};
      }
      continue;
    }

    const eqIdx = findFirstTopLevelEquals(line);
    if (eqIdx === -1) {
      continue;
    }
    const keySegments = splitTopLevelToml(line.slice(0, eqIdx), '.')
      .map((seg) => unquoteTomlToken(seg))
      .filter((seg) => seg.length > 0);
    if (keySegments.length === 0) {
      continue;
    }
    const value = parseTomlValue(line.slice(eqIdx + 1));
    const fullPath = [...currentSection, ...keySegments];

    if (fullPath[0] === 'env') {
      if (fullPath.length === 1 && isPlainObject(value)) {
        Object.assign(data.env, value);
      } else if (fullPath.length >= 2) {
        assignNestedMap(data.env, fullPath.slice(1), value);
      }
      if (currentSection.length === 0 && keySegments.length === 1) {
        data.topLevel[keySegments[0]] = value;
      }
      continue;
    }

    if (fullPath[0] === 'mcp_servers' && fullPath[1]) {
      const srv = (data.mcpServers[fullPath[1]] ??= {});
      if (fullPath.length === 2) {
        if (isPlainObject(value)) {
          for (const [k, v] of Object.entries(value)) {
            assignNestedMap(srv, [k], v);
          }
        }
      } else {
        assignNestedMap(srv, fullPath.slice(2), value);
      }
      continue;
    }

    if (currentSection.length === 0 && keySegments.length === 1) {
      data.topLevel[keySegments[0]] = value;
    }
  }

  return data;
}

export function scanCodexTomlMcp(content: string, filePath: string): WorkspaceFinding[] {
  const parsed = parseCodexToml(content);
  const findings: WorkspaceFinding[] = [];

  if (typeof parsed.topLevel.openai_base_url === 'string' && isCustomAiBaseUrl(parsed.topLevel.openai_base_url)) {
    findings.push(
      buildBaseUrlOverrideFinding(
        'openai_base_url',
        parsed.topLevel.openai_base_url.trim(),
        filePath,
        'Codex config',
        WorkspaceRuleType.AGENT_RULES,
      ),
    );
  }

  findings.push(...checkBaseUrlOverridesInEnv(parsed.env, filePath, 'Codex config env', WorkspaceRuleType.AGENT_RULES));

  for (const [name, srv] of Object.entries(parsed.mcpServers)) {
    const command = typeof srv.command === 'string' ? srv.command : '';
    const args = Array.isArray(srv.args) ? srv.args.map(String).join(' ') : '';
    const fullCmd = `${command} ${args}`.trim();
    const url = typeof srv.url === 'string' ? srv.url.trim() : '';

    findings.push(
      ...evaluateMcpServerFindings(
        {
          name,
          fullCmd,
          url,
          authed: hasMcpAuth(srv),
          envObjects: isPlainObject(srv.env) ? [{ label: `Codex MCP server "${name}" env`, env: srv.env }] : [],
          sourcePrefix: 'Codex MCP server',
        },
        filePath,
      ),
    );
  }

  return findings;
}

export function scanZedSettings(content: string, filePath: string): WorkspaceFinding[] {
  const json = safeParseJson(content);
  if (!json || !isPlainObject(json.context_servers)) {
    return [];
  }
  const findings: WorkspaceFinding[] = [];

  for (const [name, rawSrv] of Object.entries(json.context_servers)) {
    if (!isPlainObject(rawSrv)) {
      continue;
    }
    const settingsObj = isPlainObject(rawSrv.settings) ? rawSrv.settings : undefined;
    const cmdObj = isPlainObject(rawSrv.command) ? rawSrv.command : undefined;

    let commandStr = '';
    let argsList: unknown[] = [];
    if (typeof rawSrv.command === 'string') {
      commandStr = rawSrv.command;
      argsList = Array.isArray(rawSrv.args) ? rawSrv.args : [];
    } else if (cmdObj) {
      commandStr =
        typeof cmdObj.path === 'string' ? cmdObj.path : typeof cmdObj.command === 'string' ? cmdObj.command : '';
      argsList = Array.isArray(cmdObj.args) ? cmdObj.args : Array.isArray(rawSrv.args) ? rawSrv.args : [];
    } else if (settingsObj && typeof settingsObj.command === 'string') {
      commandStr = settingsObj.command;
      argsList = Array.isArray(settingsObj.args) ? settingsObj.args : [];
    }

    const fullCmd = [commandStr, ...argsList.map(String)].filter(Boolean).join(' ').trim();
    const url =
      typeof rawSrv.url === 'string'
        ? rawSrv.url.trim()
        : typeof rawSrv.serverUrl === 'string'
          ? rawSrv.serverUrl.trim()
          : settingsObj && typeof settingsObj.url === 'string'
            ? settingsObj.url.trim()
            : settingsObj && typeof settingsObj.serverUrl === 'string'
              ? settingsObj.serverUrl.trim()
              : '';

    const checkedEnvs = new Set<Record<string, unknown>>();
    const envObjects: Array<{ label: string; env: Record<string, unknown>; allowBareBaseUrl?: boolean }> = [];
    for (const [candidateEnv, allowBare] of [
      [rawSrv.env, true],
      [cmdObj?.env, true],
      [settingsObj?.env, true],
      [settingsObj, false],
    ] as Array<[unknown, boolean]>) {
      if (isPlainObject(candidateEnv) && !checkedEnvs.has(candidateEnv)) {
        checkedEnvs.add(candidateEnv);
        envObjects.push({ label: `Zed context_server "${name}"`, env: candidateEnv, allowBareBaseUrl: allowBare });
      }
    }

    findings.push(
      ...evaluateMcpServerFindings(
        {
          name,
          fullCmd,
          url,
          authed: hasMcpAuth(rawSrv) || (settingsObj ? hasMcpAuth(settingsObj) : false),
          envObjects,
          sourcePrefix: 'Zed context_server',
        },
        filePath,
      ),
    );
  }

  return findings;
}

export function scanOpenCodeConfig(content: string, filePath: string): WorkspaceFinding[] {
  const json = safeParseJson(content);
  if (!json || Array.isArray(json)) {
    return [];
  }
  const findings: WorkspaceFinding[] = [];

  if (isPlainObject(json.mcp)) {
    for (const [name, rawSrv] of Object.entries(json.mcp)) {
      if (!isPlainObject(rawSrv)) {
        continue;
      }
      let fullCmd = '';
      if (Array.isArray(rawSrv.command)) {
        fullCmd = rawSrv.command.map(String).join(' ').trim();
      } else if (typeof rawSrv.command === 'string') {
        const extraArgs = Array.isArray(rawSrv.args) ? rawSrv.args.map(String).join(' ') : '';
        fullCmd = `${rawSrv.command} ${extraArgs}`.trim();
      }

      const url = typeof rawSrv.url === 'string' ? rawSrv.url.trim() : '';
      const envObjects: Array<{ label: string; env: Record<string, unknown>; allowBareBaseUrl?: boolean }> = [];
      for (const envCandidate of [rawSrv.environment, rawSrv.env]) {
        if (isPlainObject(envCandidate)) {
          envObjects.push({ label: `OpenCode MCP server "${name}"`, env: envCandidate, allowBareBaseUrl: true });
        }
      }

      findings.push(
        ...evaluateMcpServerFindings(
          { name, fullCmd, url, authed: hasMcpAuth(rawSrv), envObjects, sourcePrefix: 'OpenCode MCP server' },
          filePath,
        ),
      );
    }
  }

  if (isPlainObject(json.provider)) {
    for (const [providerName, providerCfg] of Object.entries(json.provider)) {
      if (!isPlainObject(providerCfg)) {
        continue;
      }
      const options = isPlainObject(providerCfg.options) ? providerCfg.options : undefined;
      for (const [optKey, optObj] of [
        ['baseURL', options?.baseURL],
        ['baseUrl', options?.baseUrl],
        ['apiBase', options?.apiBase],
        ['endpoint', options?.endpoint],
        ['baseURL', providerCfg.baseURL],
      ] as Array<[string, unknown]>) {
        if (typeof optObj === 'string' && isCustomAiBaseUrl(optObj)) {
          findings.push(
            buildBaseUrlOverrideFinding(
              `provider.${providerName}.${optKey}`,
              optObj.trim(),
              filePath,
              `OpenCode provider "${providerName}"`,
              WorkspaceRuleType.AGENT_RULES,
            ),
          );
          break;
        }
      }
    }
  }

  return findings;
}

function isContainedInBase(basePath: string, targetPath: string): boolean {
  const rel = path.relative(basePath, targetPath);
  return rel !== '' && rel !== '..' && !rel.startsWith('../') && !rel.startsWith('..\\') && !path.isAbsolute(rel);
}

function resolveSafeScriptPath(scriptPath: string, baseDir?: string): string | null {
  if (!scriptPath || typeof scriptPath !== 'string') {
    return null;
  }
  const trimmed = scriptPath.trim();
  if (!trimmed || trimmed.startsWith('-') || URI_SCHEME_RE.test(trimmed)) {
    return null;
  }
  if (!baseDir) {
    return path.resolve(trimmed);
  }

  const resolvedBase = path.resolve(baseDir);
  const resolvedTarget = path.isAbsolute(trimmed) ? path.resolve(trimmed) : path.resolve(resolvedBase, trimmed);
  if (!isContainedInBase(resolvedBase, resolvedTarget)) {
    return null;
  }

  try {
    if (fs.existsSync(resolvedBase) && fs.existsSync(resolvedTarget)) {
      const realBase = fs.realpathSync(resolvedBase);
      const realTarget = fs.realpathSync(resolvedTarget);
      if (!isContainedInBase(realBase, realTarget)) {
        return null;
      }
    }
  } catch {
    return null;
  }

  return resolvedTarget;
}

export function computeMcpStdioScriptSha256(scriptPath: string, baseDir?: string): string | null {
  try {
    const resolved = resolveSafeScriptPath(scriptPath, baseDir);
    if (!resolved) {
      return null;
    }
    const stat = fs.statSync(resolved);
    if (!stat.isFile()) {
      return null;
    }
    const content = fs.readFileSync(resolved);
    return crypto.createHash('sha256').update(content).digest('hex');
  } catch {
    return null;
  }
}

function splitWhitespaceArgs(raw: string): string[] {
  const parts: string[] = [];
  let current = '';
  let quote: '"' | "'" | null = null;

  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (quote) {
      if (ch === quote) {
        quote = null;
      } else {
        current += ch;
      }
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (/\s/.test(ch)) {
      if (current.length > 0) {
        parts.push(current);
        current = '';
      }
      continue;
    }
    current += ch;
  }
  if (current.length > 0) {
    parts.push(current);
  }
  return parts;
}

function literalFileExists(candidate: string, baseDir?: string): boolean {
  try {
    const resolved = resolveSafeScriptPath(candidate, baseDir);
    return Boolean(resolved && fs.existsSync(resolved) && fs.statSync(resolved).isFile());
  } catch {
    return false;
  }
}

export class McpStdioPinTracker {
  private readonly baselines = new Map<string, string>();

  extractScriptPaths(command: string, args: unknown[] = [], baseDir?: string): string[] {
    const rawTokens = [command, ...args.map((a) => (typeof a === 'string' ? a : ''))];
    const scripts: string[] = [];
    const seen = new Set<string>();

    const tryAddToken = (tok: string): boolean => {
      const trimmed = tok.trim();
      if (!trimmed || trimmed.startsWith('-') || URI_SCHEME_RE.test(trimmed)) {
        return false;
      }
      if (SCRIPT_EXT_RE.test(trimmed)) {
        if (!seen.has(trimmed)) {
          seen.add(trimmed);
          scripts.push(trimmed);
        }
        return true;
      }
      return false;
    };

    for (const rawToken of rawTokens) {
      const trimmed = rawToken.trim();
      if (!trimmed) {
        continue;
      }
      if (/\s/.test(trimmed) && !literalFileExists(trimmed, baseDir)) {
        for (const subToken of splitWhitespaceArgs(trimmed)) {
          tryAddToken(subToken);
        }
      } else {
        tryAddToken(trimmed);
      }
    }

    return scripts;
  }

  checkServer(
    serverName: string,
    command: string,
    args: unknown[] | undefined,
    filePath: string,
    baseDir?: string,
  ): WorkspaceFinding[] {
    const findings: WorkspaceFinding[] = [];
    const configDir = filePath ? path.dirname(path.resolve(filePath)) : undefined;
    const scriptPaths = this.extractScriptPaths(command, args ?? [], baseDir ?? configDir);

    for (const scriptPath of scriptPaths) {
      const effectiveBaseDir = baseDir ?? (path.isAbsolute(scriptPath) ? undefined : configDir);
      const resolved = resolveSafeScriptPath(scriptPath, effectiveBaseDir);
      if (!resolved) {
        continue;
      }
      const sha256 = computeMcpStdioScriptSha256(scriptPath, effectiveBaseDir);
      if (!sha256) {
        continue;
      }
      const key = `${path.resolve(filePath)}|${serverName}|${resolved}`;
      const existing = this.baselines.get(key);
      if (!existing) {
        this.baselines.set(key, sha256);
      } else if (existing !== sha256) {
        findings.push({
          ruleId: 'mcp_stdio_script_drift',
          ruleName: 'MCP Stdio Script Integrity Drift',
          type: WorkspaceRuleType.MCP_CONFIG,
          severity: SeverityLevel.HIGH,
          filePath,
          finding: `${serverName}: ${scriptPath}`,
          description: `Local MCP stdio script "${scriptPath}" for server "${serverName}" changed SHA-256 on disk (${existing.slice(0, 12)} -> ${sha256.slice(0, 12)})`,
          confidence: 0.95,
        });
      }
    }

    return findings;
  }

  checkMcpConfig(content: string, filePath: string, baseDir?: string): WorkspaceFinding[] {
    const json = safeParseJson(content);
    if (!json || Array.isArray(json)) {
      return [];
    }
    const findings: WorkspaceFinding[] = [];
    const serverMaps = [json.mcpServers, json.servers, json.mcp, json.context_servers];

    for (const mapObj of serverMaps) {
      if (!isPlainObject(mapObj)) {
        continue;
      }
      for (const [name, rawCfg] of Object.entries(mapObj)) {
        if (!isPlainObject(rawCfg)) {
          continue;
        }
        let command = '';
        let args: unknown[] = [];
        if (Array.isArray(rawCfg.command) && rawCfg.command.length > 0) {
          command = typeof rawCfg.command[0] === 'string' ? rawCfg.command[0] : '';
          args = rawCfg.command.slice(1);
        } else if (typeof rawCfg.command === 'string') {
          command = rawCfg.command;
          args = Array.isArray(rawCfg.args) ? rawCfg.args : [];
        } else if (isPlainObject(rawCfg.command)) {
          command =
            typeof rawCfg.command.path === 'string'
              ? rawCfg.command.path
              : typeof rawCfg.command.command === 'string'
                ? rawCfg.command.command
                : '';
          args = Array.isArray(rawCfg.command.args)
            ? rawCfg.command.args
            : Array.isArray(rawCfg.args)
              ? rawCfg.args
              : [];
        } else if (isPlainObject(rawCfg.settings)) {
          if (Array.isArray(rawCfg.settings.command) && rawCfg.settings.command.length > 0) {
            command = typeof rawCfg.settings.command[0] === 'string' ? rawCfg.settings.command[0] : '';
            args = rawCfg.settings.command.slice(1);
          } else if (typeof rawCfg.settings.command === 'string') {
            command = rawCfg.settings.command;
            args = Array.isArray(rawCfg.settings.args) ? rawCfg.settings.args : [];
          }
        }
        if (command || args.length > 0) {
          findings.push(...this.checkServer(name, command, args, filePath, baseDir));
        }
      }
    }

    return findings;
  }

  checkTomlMcpServers(content: string, filePath: string, baseDir?: string): WorkspaceFinding[] {
    const parsed = parseCodexToml(content);
    const findings: WorkspaceFinding[] = [];
    for (const [name, srv] of Object.entries(parsed.mcpServers)) {
      const command = typeof srv.command === 'string' ? srv.command : '';
      const args = Array.isArray(srv.args) ? srv.args : [];
      if (command || args.length > 0) {
        findings.push(...this.checkServer(name, command, args, filePath, baseDir));
      }
    }
    return findings;
  }

  getBaseline(key: string): string | undefined {
    return this.baselines.get(key);
  }

  clear(): void {
    this.baselines.clear();
  }
}
