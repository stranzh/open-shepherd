/**
 * Workspace & AI IDE Configuration Rules
 *
 * Pure detection helpers for pre-execution scanning of workspace configs,
 * MCP server manifests, AI agent instruction files, git hooks, and devcontainers.
 */

import { SeverityLevel } from '../lib/events/sec-events';
import { evaluateMcpServerFindings, hasMcpAuth, scanAiWorkspaceSettings } from './ai-mcp-extra-rules';
import { TASK_RULES } from './task-rules';
import {
  HIDDEN_HTML_COMMENT_RE,
  WorkspaceFinding,
  WorkspaceRuleType,
  isPlainObject,
  safeParseJson,
  scanHooksObject,
} from './workspace-rule-types';

export { WorkspaceFinding, WorkspaceRuleType, safeParseJson } from './workspace-rule-types';

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
  findings.push(...scanAiWorkspaceSettings(json, filePath));
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

const SAFE_BUILTIN_CREDENTIAL_HELPER_RE =
  /^(?:store|cache(?:\s+--timeout=\d+)?|osxkeychain|manager(?:-core)?|wincred|libsecret)$/i;

export function scanGitConfig(content: string, filePath: string): WorkspaceFinding[] {
  const findings: WorkspaceFinding[] = [];
  const dangerousKeys = [
    { key: 'fsmonitor', re: /^\s*fsmonitor\s*=\s*(.+)$/gim },
    { key: 'sshCommand', re: /^\s*sshCommand\s*=\s*(.+)$/gim },
    { key: 'hooksPath', re: /^\s*hooksPath\s*=\s*(.+)$/gim },
    { key: 'credential.helper', re: /^\s*helper\s*=\s*(.+)$/gim },
  ];
  for (const item of dangerousKeys) {
    for (const m of content.matchAll(item.re)) {
      const value = m[1].trim();
      if (item.key === 'credential.helper' && SAFE_BUILTIN_CREDENTIAL_HELPER_RE.test(value)) {
        continue;
      }
      findings.push({
        ruleId: `git_config_${item.key.replace(/\./g, '_')}`,
        ruleName: 'Dangerous Git Config Hook/Command',
        type: WorkspaceRuleType.GIT_CONFIG,
        severity: SeverityLevel.HIGH,
        filePath,
        finding: `${item.key} = ${value}`,
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
    const url = typeof cfg.url === 'string' ? cfg.url : typeof cfg.serverUrl === 'string' ? cfg.serverUrl : '';

    findings.push(
      ...evaluateMcpServerFindings(
        {
          name,
          fullCmd,
          url,
          authed: hasMcpAuth(cfg),
          envObjects: isPlainObject(cfg.env) ? [{ label: `MCP server "${name}" env`, env: cfg.env }] : [],
          sourcePrefix: 'MCP server',
        },
        filePath,
      ),
    );

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

export function scanHooksConfig(content: string, filePath: string): WorkspaceFinding[] {
  const json = safeParseJson(content);
  if (!json) {
    return [];
  }
  return scanHooksObject(json, filePath);
}

export function scanAntigravityCliSettings(content: string, filePath: string): WorkspaceFinding[] {
  const json = safeParseJson(content);
  if (!json) {
    return [];
  }
  const findings: WorkspaceFinding[] = [];

  if (json.toolPermission === 'always-proceed') {
    findings.push({
      ruleId: 'antigravity_always_proceed',
      ruleName: 'Antigravity Unattended Tool Execution Enabled',
      type: WorkspaceRuleType.AGENT_RULES,
      severity: SeverityLevel.HIGH,
      filePath,
      finding: 'toolPermission: always-proceed',
      description:
        'Antigravity CLI settings enable toolPermission "always-proceed", bypassing interactive tool approval',
      confidence: 0.95,
    });
  }

  const permissions = json.permissions as Record<string, unknown> | undefined;
  const allowList = permissions && Array.isArray(permissions.allow) ? permissions.allow : [];
  for (const entry of allowList) {
    if (typeof entry === 'string' && /^command\(\s*\*?\s*\)$/i.test(entry.trim())) {
      findings.push({
        ruleId: 'antigravity_wildcard_command_allow',
        ruleName: 'Antigravity Wildcard Command Permission',
        type: WorkspaceRuleType.AGENT_RULES,
        severity: SeverityLevel.HIGH,
        filePath,
        finding: 'permissions.allow: command(*)',
        description: 'Antigravity settings grant unrestricted shell command execution',
        confidence: 0.95,
      });
      break;
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
  HIDDEN_HTML_COMMENT_RE.lastIndex = 0;
  const visibleContent = content.replace(HIDDEN_HTML_COMMENT_RE, '');
  if (maliciousDirectiveRe.test(visibleContent)) {
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
