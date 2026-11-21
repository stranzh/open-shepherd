/**
 * Workspace & AI IDE Configuration Rules
 *
 * Pure detection helpers for pre-execution scanning of workspace configs,
 * MCP server manifests, AI agent instruction files, git hooks, and devcontainers.
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

const DANGEROUS_VSCODE_SETTING_KEYS = [
  'terminal.integrated.env.linux',
  'terminal.integrated.env.osx',
  'terminal.integrated.env.windows',
  'git.path',
  'eslint.runtime',
  'typescript.tsdk',
  'php.validate.executablePath',
  'python.defaultInterpreterPath',
  'http.proxy',
];

const BIDI_OR_HIDDEN_UNICODE_RE = /[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/;
const UNICODE_TAG_CHAR_RE = /[\u{E0000}-\u{E007F}]/u;
const HIDDEN_HTML_COMMENT_RE = /<!--([\s\S]{1,4000}?)-->/g;
const PROMPT_INJECTION_CMD_RE = new RegExp(
  [
    'ignore\\s+(?:all\\s+)?previous\\s+instructions',
    'exfiltrate',
    'curl\\s+',
    'wget\\s+',
    'nc\\s+-e',
    '\\|\\s*(?:sh|bash)\\b',
    '~/.ssh',
    '~/.aws',
    '\\.env\\b',
    'base64\\s+-d',
  ].join('|'),
  'i',
);

function stripJsonComments(raw: string): string {
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

  // Strip trailing commas outside strings
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

function safeParseJson(raw: string): Record<string, any> | null {
  try {
    const parsed = JSON.parse(stripJsonComments(raw));
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch {
    return null;
  }
}

function extractTaskToken(val: unknown): string {
  if (typeof val === 'string') {
    return val;
  }
  if (val && typeof val === 'object' && typeof (val as Record<string, unknown>)['value'] === 'string') {
    return (val as Record<string, unknown>)['value'] as string;
  }
  return '';
}

function extractTaskCommandText(task: Record<string, any>): string {
  const blocks = [task, task.osx, task.linux, task.windows].filter((b) => b && typeof b === 'object');
  const parts: string[] = [];
  for (const blk of blocks) {
    const cmd = extractTaskToken(blk.command);
    if (cmd) {
      parts.push(cmd);
    }
    if (Array.isArray(blk.args)) {
      for (const arg of blk.args) {
        const token = extractTaskToken(arg);
        if (token) {
          parts.push(token);
        }
      }
    }
  }
  return parts.join(' ');
}

export function scanVscodeSettings(content: string, filePath: string): WorkspaceFinding[] {
  const json = safeParseJson(content);
  if (!json) {
    return [];
  }
  const findings: WorkspaceFinding[] = [];
  for (const key of Object.keys(json)) {
    if (DANGEROUS_VSCODE_SETTING_KEYS.includes(key)) {
      findings.push({
        ruleId: 'dangerous_vscode_setting',
        ruleName: 'Dangerous Workspace Setting Override',
        type: WorkspaceRuleType.VSCODE_CONFIG,
        severity: SeverityLevel.HIGH,
        filePath,
        finding: key,
        description: `Workspace settings override security-sensitive setting "${key}"`,
        confidence: 0.9,
      });
    }
  }
  return findings;
}

export function scanVscodeTasksJson(content: string, filePath: string): WorkspaceFinding[] {
  const json = safeParseJson(content);
  if (!json || !Array.isArray(json.tasks)) {
    return [];
  }
  const findings: WorkspaceFinding[] = [];
  for (const task of json.tasks) {
    if (!task || typeof task !== 'object') {
      continue;
    }
    const label = String(task.label || task.taskName || 'unnamed');
    if (task.runOptions?.runOn === 'folderOpen') {
      findings.push({
        ruleId: 'task_run_on_folder_open',
        ruleName: 'Auto-Run Task on Folder Open',
        type: WorkspaceRuleType.VSCODE_CONFIG,
        severity: SeverityLevel.HIGH,
        filePath,
        finding: `folderOpen task: ${label}`,
        description: `Task "${label}" is configured with runOn: "folderOpen" for automatic execution`,
        confidence: 0.95,
      });
    }
    const cmdText = extractTaskCommandText(task);
    for (const rule of TASK_RULES) {
      if (cmdText && rule.commandPattern.test(cmdText)) {
        findings.push({
          ruleId: `workspace_task_${rule.id}`,
          ruleName: `Workspace Task: ${rule.name}`,
          type: WorkspaceRuleType.VSCODE_CONFIG,
          severity: rule.severity,
          filePath,
          finding: cmdText.slice(0, 200),
          description: `Suspicious command in tasks.json ("${label}"): ${rule.description}`,
          confidence: rule.confidence,
        });
        break;
      }
    }
  }
  return findings;
}

export function scanVscodeLaunchJson(content: string, filePath: string): WorkspaceFinding[] {
  const json = safeParseJson(content);
  if (!json || !Array.isArray(json.configurations)) {
    return [];
  }
  const findings: WorkspaceFinding[] = [];
  for (const cfg of json.configurations) {
    if (!cfg || typeof cfg !== 'object') {
      continue;
    }
    const rawParts = [cfg.program, cfg.runtimeExecutable, ...(Array.isArray(cfg.args) ? cfg.args : [])];
    const cmdText = rawParts.filter((x) => typeof x === 'string').join(' ');
    for (const rule of TASK_RULES) {
      if (cmdText && rule.commandPattern.test(cmdText)) {
        findings.push({
          ruleId: `launch_${rule.id}`,
          ruleName: `Launch Config: ${rule.name}`,
          type: WorkspaceRuleType.VSCODE_CONFIG,
          severity: rule.severity,
          filePath,
          finding: cmdText.slice(0, 200),
          description: `Suspicious command in launch.json ("${String(cfg.name || 'unnamed')}")`,
          confidence: rule.confidence,
        });
        break;
      }
    }
  }
  return findings;
}

export function scanGitConfig(content: string, filePath: string): WorkspaceFinding[] {
  const findings: WorkspaceFinding[] = [];
  const dangerousKeys = [
    { key: 'fsmonitor', re: /^\s*fsmonitor\s*=\s*(.+)$/im },
    { key: 'sshCommand', re: /^\s*sshCommand\s*=\s*(.+)$/im },
    { key: 'hooksPath', re: /^\s*hooksPath\s*=\s*(.+)$/im },
    { key: 'credential.helper', re: /^\s*helper\s*=\s*(.+)$/im },
  ];
  for (const item of dangerousKeys) {
    const m = content.match(item.re);
    if (m) {
      findings.push({
        ruleId: `git_config_${item.key.replace(/\./g, '_')}`,
        ruleName: 'Dangerous Git Config Hook/Command',
        type: WorkspaceRuleType.GIT_CONFIG,
        severity: SeverityLevel.HIGH,
        filePath,
        finding: `${item.key} = ${m[1].trim()}`,
        description: `Repository .git/config defines code-executing "${item.key}" setting`,
        confidence: 0.95,
      });
    }
  }
  return findings;
}

export function scanDevcontainerJson(content: string, filePath: string): WorkspaceFinding[] {
  const json = safeParseJson(content);
  if (!json) {
    return [];
  }
  const findings: WorkspaceFinding[] = [];
  for (const hook of ['initializeCommand', 'onCreateCommand', 'postCreateCommand', 'postStartCommand']) {
    if (json[hook]) {
      const cmdStr = typeof json[hook] === 'string' ? json[hook] : JSON.stringify(json[hook]);
      if (/(?:curl|wget|bash|sh\s+-c|powershell|nc\b|base64)/i.test(cmdStr)) {
        findings.push({
          ruleId: `devcontainer_${hook}`,
          ruleName: 'Suspicious Devcontainer Lifecycle Command',
          type: WorkspaceRuleType.DEVCONTAINER,
          severity: SeverityLevel.HIGH,
          filePath,
          finding: `${hook}: ${cmdStr.slice(0, 160)}`,
          description: `Devcontainer ${hook} executes a shell/network command`,
          confidence: 0.85,
        });
      }
    }
  }
  const runArgs = Array.isArray(json.runArgs) ? json.runArgs.join(' ') : '';
  const mounts = Array.isArray(json.mounts) ? json.mounts.join(' ') : '';
  if (/--privileged\b/i.test(runArgs) || /(?:docker\.sock|\.ssh|\.aws|\.kube)/i.test(mounts + ' ' + runArgs)) {
    findings.push({
      ruleId: 'devcontainer_privileged_mount',
      ruleName: 'Privileged Devcontainer or Sensitive Host Mount',
      type: WorkspaceRuleType.DEVCONTAINER,
      severity: SeverityLevel.HIGH,
      filePath,
      finding: (runArgs || mounts).slice(0, 160),
      description: 'Devcontainer requests --privileged or mounts sensitive host paths/docker.sock',
      confidence: 0.95,
    });
  }
  return findings;
}

export function scanPackageManifest(content: string, filePath: string): WorkspaceFinding[] {
  const json = safeParseJson(content);
  if (!json || !json.scripts || typeof json.scripts !== 'object') {
    return [];
  }
  const findings: WorkspaceFinding[] = [];
  for (const hook of ['preinstall', 'install', 'postinstall', 'prepare']) {
    const script = json.scripts[hook];
    if (typeof script === 'string' && /(?:curl|wget|\|\s*(?:sh|bash)|node\s+-e|eval\s*\(|base64)/i.test(script)) {
      findings.push({
        ruleId: `npm_lifecycle_${hook}`,
        ruleName: 'Suspicious NPM Lifecycle Script',
        type: WorkspaceRuleType.PACKAGE_MANIFEST,
        severity: SeverityLevel.HIGH,
        filePath,
        finding: `${hook}: ${script.slice(0, 160)}`,
        description: `package.json defines suspicious "${hook}" lifecycle script`,
        confidence: 0.9,
      });
    }
  }
  return findings;
}

export function scanPackageManagerConfig(content: string, filePath: string): WorkspaceFinding[] {
  const findings: WorkspaceFinding[] = [];
  const customRegistry = content.match(/^\s*(?:registry|index-url|extra-index-url)\s*=\s*(https?:\/\/\S+)/im);
  if (customRegistry) {
    const url = customRegistry[1];
    if (!/(?:registry\.npmjs\.org|pypi\.org|files\.pythonhosted\.org)/i.test(url)) {
      findings.push({
        ruleId: 'custom_package_registry',
        ruleName: 'Custom Package Registry Override',
        type: WorkspaceRuleType.PACKAGE_MANIFEST,
        severity: SeverityLevel.MEDIUM,
        filePath,
        finding: url,
        description: `Package manager config overrides default registry to ${url}`,
        confidence: 0.85,
      });
    }
  }
  if (/(?:_authToken|_auth|password)\s*=\s*\S+/i.test(content)) {
    findings.push({
      ruleId: 'embedded_registry_token',
      ruleName: 'Embedded Package Registry Credential',
      type: WorkspaceRuleType.PACKAGE_MANIFEST,
      severity: SeverityLevel.HIGH,
      filePath,
      finding: 'registry auth token',
      description: 'Package manager config contains embedded registry authentication credentials',
      confidence: 0.9,
    });
  }
  return findings;
}

export function scanMcpConfig(content: string, filePath: string): WorkspaceFinding[] {
  const json = safeParseJson(content);
  if (!json) {
    return [];
  }
  const findings: WorkspaceFinding[] = [];
  const servers = (json.mcpServers || json.servers || {}) as Record<string, any>;
  if (!servers || typeof servers !== 'object') {
    return [];
  }

  for (const [name, cfg] of Object.entries(servers)) {
    if (!cfg || typeof cfg !== 'object') {
      continue;
    }
    const command = typeof cfg.command === 'string' ? cfg.command : '';
    const args = Array.isArray(cfg.args) ? cfg.args.map(String).join(' ') : '';
    const fullCmd = `${command} ${args}`.trim();
    const url = typeof cfg.url === 'string' ? cfg.url : '';

    if (
      /\bnpx\b.*(?:-y|--yes)/i.test(fullCmd) ||
      /\buvx\b/i.test(fullCmd) ||
      /(?:curl|wget|\|\s*(?:sh|bash))/i.test(fullCmd)
    ) {
      findings.push({
        ruleId: 'mcp_unpinned_or_shell_server',
        ruleName: 'Suspicious MCP Server Command',
        type: WorkspaceRuleType.MCP_CONFIG,
        severity: SeverityLevel.HIGH,
        filePath,
        finding: `${name}: ${fullCmd.slice(0, 160)}`,
        description: `MCP server "${name}" executes unpinned package runner or shell download command`,
        confidence: 0.9,
      });
    }

    if (url && !/^https?:\/\/(?:localhost|127\.0\.0\.1|\[::1\])(?:[:/]|$)/i.test(url)) {
      findings.push({
        ruleId: 'mcp_remote_endpoint',
        ruleName: 'Remote MCP Server Endpoint',
        type: WorkspaceRuleType.MCP_CONFIG,
        severity: SeverityLevel.MEDIUM,
        filePath,
        finding: `${name}: ${url}`,
        description: `MCP server "${name}" connects to non-local remote endpoint ${url}`,
        confidence: 0.85,
      });
    }

    if (typeof cfg.description === 'string' && PROMPT_INJECTION_CMD_RE.test(cfg.description)) {
      findings.push({
        ruleId: 'mcp_prompt_injection',
        ruleName: 'MCP Tool/Server Description Prompt Injection',
        type: WorkspaceRuleType.MCP_CONFIG,
        severity: SeverityLevel.HIGH,
        filePath,
        finding: `${name}: ${cfg.description.slice(0, 140)}`,
        description: `MCP server "${name}" description contains suspicious imperative/exfiltration text`,
        confidence: 0.9,
      });
    }
  }
  return findings;
}

export function scanAgentRulesFile(content: string, filePath: string): WorkspaceFinding[] {
  const findings: WorkspaceFinding[] = [];

  if (BIDI_OR_HIDDEN_UNICODE_RE.test(content) || UNICODE_TAG_CHAR_RE.test(content)) {
    findings.push({
      ruleId: 'agent_rules_hidden_unicode',
      ruleName: 'Agent Rules Hidden/Bidi Unicode Poisoning',
      type: WorkspaceRuleType.AGENT_RULES,
      severity: SeverityLevel.HIGH,
      filePath,
      finding: 'Hidden or bidirectional Unicode characters detected',
      description: 'AI agent instruction file contains zero-width, bidi override, or Unicode tag characters',
      confidence: 0.95,
    });
  }

  let match: RegExpExecArray | null;
  HIDDEN_HTML_COMMENT_RE.lastIndex = 0;
  while ((match = HIDDEN_HTML_COMMENT_RE.exec(content)) !== null) {
    if (PROMPT_INJECTION_CMD_RE.test(match[1])) {
      findings.push({
        ruleId: 'agent_rules_hidden_comment_injection',
        ruleName: 'Agent Rules Hidden Comment Instruction Injection',
        type: WorkspaceRuleType.AGENT_RULES,
        severity: SeverityLevel.HIGH,
        filePath,
        finding: match[1].trim().slice(0, 140),
        description: 'Hidden HTML comment in AI agent rules file contains command or exfiltration instructions',
        confidence: 0.95,
      });
      break;
    }
  }

  const maliciousDirectiveRe = new RegExp(
    [
      'curl\\s+[^|\\n]+\\|\\s*(?:sh|bash)',
      'wget\\s+[^|\\n]+\\|\\s*(?:sh|bash)',
      'exfiltrate\\s+.*(?:\\.env|\\.ssh|\\.aws)',
    ].join('|'),
    'i',
  );
  if (maliciousDirectiveRe.test(content)) {
    findings.push({
      ruleId: 'agent_rules_malicious_directive',
      ruleName: 'Agent Rules Malicious Execution Directive',
      type: WorkspaceRuleType.AGENT_RULES,
      severity: SeverityLevel.HIGH,
      filePath,
      finding: 'Malicious shell or credential exfiltration instruction',
      description: 'AI agent instruction file directs agent to run piped remote shell or exfiltrate secrets',
      confidence: 0.9,
    });
  }

  return findings;
}
