/**
 * Shared leaf types and primitives for workspace and AI configuration rules.
 *
 * Kept free of external rule-module imports so detection helpers form a clean DAG.
 */

import { SeverityLevel } from '../lib/events/sec-events';
import { TASK_RULES } from './task-rules';

export enum WorkspaceRuleType {
  MCP_CONFIG = 'MCP_CONFIG',
  AGENT_RULES = 'AGENT_RULES',
  VSCODE_CONFIG = 'VSCODE_CONFIG',
  GIT_CONFIG = 'GIT_CONFIG',
  DEVCONTAINER = 'DEVCONTAINER',
  PACKAGE_MANIFEST = 'PACKAGE_MANIFEST',
}

export interface WorkspaceFinding {
  ruleId: string;
  ruleName: string;
  type: WorkspaceRuleType;
  severity: SeverityLevel;
  filePath: string;
  finding: string;
  description: string;
  confidence: number;
}

export const HIDDEN_HTML_COMMENT_RE = /<!--([\s\S]{1,4000}?)-->/g;

const LOCAL_ENDPOINT_HOSTS = new Set(['localhost', '127.0.0.1', '::1']);
const SUSPICIOUS_HOOK_CMD_RE = /(?:curl|wget|\|\s*(?:sh|bash)|nc\s+-e|base64\s+-d|powershell.*-enc)/i;

export function isPlainObject(val: unknown): val is Record<string, unknown> {
  return Boolean(val && typeof val === 'object' && !Array.isArray(val));
}

export function stripJsonComments(raw: string): string {
  let out = '';
  let inString = false;
  let escaped = false;

  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (inString) {
      out += ch;
      if (escaped) {
        escaped = false;
      } else if (ch === '\\') {
        escaped = true;
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }

    if (ch === '"') {
      inString = true;
      out += ch;
    } else if (ch === '/' && raw[i + 1] === '/') {
      while (i < raw.length && raw[i] !== '\n') {
        i++;
      }
      if (i < raw.length) {
        out += '\n';
      }
    } else if (ch === '/' && raw[i + 1] === '*') {
      i += 2;
      while (i < raw.length && !(raw[i] === '*' && raw[i + 1] === '/')) {
        i++;
      }
      i++;
    } else {
      out += ch;
    }
  }

  let cleaned = '';
  inString = false;
  escaped = false;
  for (let i = 0; i < out.length; i++) {
    const ch = out[i];
    if (inString) {
      cleaned += ch;
      if (escaped) {
        escaped = false;
      } else if (ch === '\\') {
        escaped = true;
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }
    if (ch === '"') {
      inString = true;
      cleaned += ch;
    } else if (ch === ',') {
      let j = i + 1;
      while (j < out.length && /\s/.test(out[j])) {
        j++;
      }
      if (out[j] !== '}' && out[j] !== ']') {
        cleaned += ch;
      }
    } else {
      cleaned += ch;
    }
  }
  return cleaned;
}

export function safeParseJson(raw: string): Record<string, any> | null {
  try {
    const parsed = JSON.parse(stripJsonComments(raw));
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch {
    return null;
  }
}

export function isLocalEndpointUrl(url: string): boolean {
  const trimmed = url.trim();
  if (!trimmed) {
    return false;
  }
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return false;
    }
    if (parsed.username !== '' || parsed.password !== '') {
      return false;
    }
    const bareHost = parsed.hostname
      .toLowerCase()
      .replace(/^\[|\]$/g, '')
      .replace(/\.$/, '');
    return LOCAL_ENDPOINT_HOSTS.has(bareHost);
  } catch {
    return false;
  }
}

export function scanHooksObject(root: unknown, filePath: string): WorkspaceFinding[] {
  const findings: WorkspaceFinding[] = [];
  const commands: string[] = [];

  const collectCommands = (node: unknown, depth = 0): void => {
    if (!node || typeof node !== 'object' || depth > 8) {
      return;
    }
    if (Array.isArray(node)) {
      for (const item of node) {
        collectCommands(item, depth + 1);
      }
      return;
    }
    const obj = node as Record<string, unknown>;
    if (typeof obj.command === 'string' && obj.command.trim().length > 0) {
      commands.push(obj.command.trim());
    }
    for (const val of Object.values(obj)) {
      if (val && typeof val === 'object') {
        collectCommands(val, depth + 1);
      }
    }
  };

  collectCommands(root);

  for (const cmd of commands) {
    const matchedTaskRule = TASK_RULES.find((rule) => rule.commandPattern.test(cmd));
    if (matchedTaskRule || SUSPICIOUS_HOOK_CMD_RE.test(cmd)) {
      findings.push({
        ruleId: 'agent_hook_suspicious_command',
        ruleName: 'Suspicious Agent Lifecycle Hook Command',
        type: WorkspaceRuleType.AGENT_RULES,
        severity: SeverityLevel.HIGH,
        filePath,
        finding: cmd.slice(0, 160),
        description: matchedTaskRule
          ? `Agent lifecycle hook command matches "${matchedTaskRule.name}"`
          : 'Agent lifecycle hook executes suspicious network or shell command',
        confidence: 0.95,
      });
    } else {
      findings.push({
        ruleId: 'agent_hook_command_defined',
        ruleName: 'Agent Lifecycle Hook Command Defined',
        type: WorkspaceRuleType.AGENT_RULES,
        severity: SeverityLevel.MEDIUM,
        filePath,
        finding: cmd.slice(0, 160),
        description: 'Workspace or agent lifecycle hooks config defines an automatic shell hook command',
        confidence: 0.85,
      });
    }
  }

  return findings;
}
