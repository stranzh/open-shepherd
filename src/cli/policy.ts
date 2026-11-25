import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { SeverityLevel } from '../lib/events/sec-events';
import {
  isPlainObject,
  stripJsonComments,
  WorkspaceFinding,
  WorkspaceRuleType,
} from '../detection/workspace-rule-types';

export interface AuditEnterprisePoliciesOptions {
  linuxPolicyPath?: string;
  macosPolicyPath?: string;
  winPolicies?: Record<string, unknown>;
}

export interface AuditEnterprisePoliciesResult {
  findings: WorkspaceFinding[];
  policies: Record<string, unknown>;
}

export interface AnalyzePolicyImpactOptions {
  homeDir?: string;
  extensionDirs?: string[];
}

export interface AnalyzePolicyImpactResult {
  allowed: string[];
  blocked: string[];
  mcpBlocked: string[];
}

export interface GitOpsPolicyBundle {
  vscodePolicy: Record<string, unknown>;
  admxPolicy: Record<string, unknown>;
}

export interface PolicyCommandIO {
  stdout: (s: string) => void;
  stderr: (s: string) => void;
  homeDir?: string;
}

const DEFAULT_LINUX_POLICY_PATH = '/etc/vscode/policy.json';
const DEFAULT_MACOS_POLICY_PATH = '/Library/Managed Preferences/com.microsoft.VSCode.json';

const DEFAULT_EXTENSION_REL_DIRS = [
  path.join('.vscode', 'extensions'),
  path.join('.cursor', 'extensions'),
  path.join('.vscode-oss', 'extensions'),
  path.join('.windsurf', 'extensions'),
  path.join('.kiro', 'extensions'),
];

const MCP_EXTENSION_HINT_RE = /(?:mcp|model-context-protocol|cline|roo-code|continue|copilot|cursor)/i;

function readJsonPolicyFile(filePath: string): Record<string, unknown> | undefined {
  if (!fs.existsSync(filePath)) {
    return undefined;
  }
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    const parsed: unknown = JSON.parse(stripJsonComments(raw));
    return isPlainObject(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function readListLines(filePath: string): string[] {
  const raw = fs.readFileSync(filePath, 'utf8');
  return raw
    .split(/\r?\n/)
    .map((line) => line.replace(/#.*$/, '').trim())
    .filter((line) => line.length > 0);
}

function addFinding(
  findings: WorkspaceFinding[],
  ruleId: string,
  ruleName: string,
  severity: SeverityLevel,
  filePath: string,
  finding: string,
  description: string,
): void {
  findings.push({
    ruleId,
    ruleName,
    type: WorkspaceRuleType.VSCODE_CONFIG,
    severity,
    filePath,
    finding,
    description,
    confidence: 0.9,
  });
}

function auditPolicyObject(policies: Record<string, unknown>, sourceLabel: string, findings: WorkspaceFinding[]): void {
  const allowedExt = policies.AllowedExtensions;
  if (allowedExt === undefined || allowedExt === '*') {
    addFinding(
      findings,
      'POLICY-ALLOWED-EXTENSIONS',
      'Enterprise AllowedExtensions Policy',
      SeverityLevel.HIGH,
      sourceLabel,
      'AllowedExtensions is missing or wildcard (*)',
      'Restrict AllowedExtensions to an explicit publisher/extension allowlist rather than permitting all extensions.',
    );
  } else if (isPlainObject(allowedExt) && allowedExt['*'] === true) {
    addFinding(
      findings,
      'POLICY-ALLOWED-EXTENSIONS',
      'Enterprise AllowedExtensions Policy',
      SeverityLevel.HIGH,
      sourceLabel,
      'AllowedExtensions explicitly allows wildcard (*)',
      'Remove the "*" : true entry from AllowedExtensions so unapproved extensions cannot be installed.',
    );
  }

  const chatMcp = policies.ChatMCP;
  if (chatMcp === undefined || chatMcp === true || chatMcp === 'all') {
    addFinding(
      findings,
      'POLICY-CHAT-MCP',
      'Enterprise ChatMCP Policy',
      SeverityLevel.HIGH,
      sourceLabel,
      'ChatMCP is missing or unrestricted',
      'Set ChatMCP to "disabled" or restrict MCP servers via ChatAllowManagedMcpServersOnly.',
    );
  }

  if (policies.ChatAllowManagedMcpServersOnly !== true) {
    addFinding(
      findings,
      'POLICY-MANAGED-MCP-ONLY',
      'Enterprise Managed MCP Servers Only',
      SeverityLevel.HIGH,
      sourceLabel,
      'ChatAllowManagedMcpServersOnly is not enabled',
      'Set ChatAllowManagedMcpServersOnly to true to prevent user-defined or workspace-defined MCP servers.',
    );
  }

  if (policies.ChatAllowManagedHooksOnly !== true) {
    addFinding(
      findings,
      'POLICY-MANAGED-HOOKS-ONLY',
      'Enterprise Managed Hooks Only',
      SeverityLevel.MEDIUM,
      sourceLabel,
      'ChatAllowManagedHooksOnly is not enabled',
      'Set ChatAllowManagedHooksOnly to true so only administrator-managed agent hooks can execute.',
    );
  }

  const telemetry = policies.TelemetryLevel;
  if (telemetry === undefined || telemetry === 'all') {
    addFinding(
      findings,
      'POLICY-TELEMETRY-LEVEL',
      'Enterprise TelemetryLevel Policy',
      SeverityLevel.MEDIUM,
      sourceLabel,
      'TelemetryLevel is missing or set to "all"',
      'Set TelemetryLevel to "off" or "error" to minimize telemetry exposure.',
    );
  }

  const remoteTunnel = policies.RemoteTunnelAccess;
  if (remoteTunnel === undefined || remoteTunnel === true || remoteTunnel === 'enabled') {
    addFinding(
      findings,
      'POLICY-REMOTE-TUNNEL',
      'Enterprise RemoteTunnelAccess Policy',
      SeverityLevel.HIGH,
      sourceLabel,
      'RemoteTunnelAccess is missing or enabled',
      'Disable RemoteTunnelAccess (false) to prevent unauthorized inbound remote tunnel connections.',
    );
  }
}

export function auditEnterprisePolicies(options: AuditEnterprisePoliciesOptions = {}): AuditEnterprisePoliciesResult {
  const linuxPath = options.linuxPolicyPath ?? DEFAULT_LINUX_POLICY_PATH;
  const macosPath = options.macosPolicyPath ?? DEFAULT_MACOS_POLICY_PATH;

  const mergedPolicies: Record<string, unknown> = {};
  const sources: string[] = [];

  const linuxPolicies = readJsonPolicyFile(linuxPath);
  if (linuxPolicies) {
    Object.assign(mergedPolicies, linuxPolicies);
    sources.push(linuxPath);
  }

  const macosPolicies = readJsonPolicyFile(macosPath);
  if (macosPolicies) {
    Object.assign(mergedPolicies, macosPolicies);
    sources.push(macosPath);
  }

  if (options.winPolicies && isPlainObject(options.winPolicies)) {
    Object.assign(mergedPolicies, options.winPolicies);
    sources.push('winPolicies');
  }

  const findings: WorkspaceFinding[] = [];
  const sourceLabel = sources.length > 0 ? sources.join(', ') : linuxPath;
  auditPolicyObject(mergedPolicies, sourceLabel, findings);

  return { findings, policies: mergedPolicies };
}

function normalizeExtensionId(dirName: string): string | undefined {
  if (dirName.startsWith('.')) {
    return undefined;
  }
  const match = /^([a-z0-9-]+)\.([a-z0-9-]+?)(?:-\d+\.\d+\.\d+.*)?$/i.exec(dirName);
  if (match) {
    return `${match[1].toLowerCase()}.${match[2].toLowerCase()}`;
  }
  return undefined;
}

export function analyzePolicyImpact(
  allowlistPath: string,
  options: AnalyzePolicyImpactOptions = {},
): AnalyzePolicyImpactResult {
  if (!fs.existsSync(allowlistPath)) {
    throw new Error(`Allowlist file not found: ${allowlistPath}`);
  }

  const entries = readListLines(allowlistPath).map((e) => e.toLowerCase());
  const allowedPublishers = new Set<string>();
  const allowedExtensions = new Set<string>();

  for (const entry of entries) {
    if (entry.includes('.')) {
      allowedExtensions.add(entry);
    } else {
      allowedPublishers.add(entry);
    }
  }

  const homeDir = options.homeDir ?? os.homedir();
  const extensionDirs = options.extensionDirs ?? DEFAULT_EXTENSION_REL_DIRS.map((rel) => path.join(homeDir, rel));

  const seen = new Set<string>();
  const allowed: string[] = [];
  const blocked: string[] = [];
  const mcpBlocked: string[] = [];

  for (const dir of extensionDirs) {
    if (!fs.existsSync(dir)) {
      continue;
    }
    let dirents: fs.Dirent[];
    try {
      dirents = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const dirent of dirents) {
      if (!dirent.isDirectory()) {
        continue;
      }
      const extId = normalizeExtensionId(dirent.name);
      if (!extId || seen.has(extId)) {
        continue;
      }
      seen.add(extId);

      const publisher = extId.split('.')[0];
      if (allowedExtensions.has(extId) || allowedPublishers.has(publisher)) {
        allowed.push(extId);
      } else {
        blocked.push(extId);
        if (MCP_EXTENSION_HINT_RE.test(extId)) {
          mcpBlocked.push(extId);
        }
      }
    }
  }

  allowed.sort();
  blocked.sort();
  mcpBlocked.sort();

  return { allowed, blocked, mcpBlocked };
}

export function generatePolicyFromGitOps(inputDir: string): GitOpsPolicyBundle {
  if (!fs.existsSync(inputDir)) {
    throw new Error(`GitOps policy directory not found: ${inputDir}`);
  }

  const publishersPath = path.join(inputDir, 'allowed_publishers.txt');
  const allowedPath = path.join(inputDir, 'allowed_extensions.txt');
  const disallowedPath = path.join(inputDir, 'disallowed_extensions.txt');

  const publishers = fs.existsSync(publishersPath) ? readListLines(publishersPath) : [];
  const allowedExts = fs.existsSync(allowedPath) ? readListLines(allowedPath) : [];
  const disallowedExts = fs.existsSync(disallowedPath) ? readListLines(disallowedPath) : [];

  const allowedExtensionsMap: Record<string, boolean> = { '*': false };
  for (const pub of publishers) {
    allowedExtensionsMap[pub] = true;
  }
  for (const ext of allowedExts) {
    allowedExtensionsMap[ext] = true;
  }
  for (const ext of disallowedExts) {
    allowedExtensionsMap[ext] = false;
  }

  const vscodePolicy: Record<string, unknown> = {
    AllowedExtensions: allowedExtensionsMap,
    ChatMCP: true,
    ChatAllowManagedMcpServersOnly: true,
    ChatAllowManagedHooksOnly: true,
    RemoteTunnelAccess: false,
    TelemetryLevel: 'off',
  };

  const admxPolicy: Record<string, unknown> = {
    AllowedExtensions: JSON.stringify(allowedExtensionsMap),
    ChatMCP: 1,
    ChatAllowManagedMcpServersOnly: 1,
    ChatAllowManagedHooksOnly: 1,
    RemoteTunnelAccess: 0,
    TelemetryLevel: 'off',
  };

  return { vscodePolicy, admxPolicy };
}

function printHelp(stdout: (s: string) => void): void {
  stdout(
    [
      'Usage: open-shepherd policy <subcommand> [options]',
      '',
      'Subcommands:',
      '  audit                         Audit enterprise VS Code/IDE policies',
      '  impact --allowlist <file>     Analyze extension allowlist impact',
      '  generate <dir>                Generate VS Code & ADMX policies from GitOps lists',
      '  --help, -h                    Show this help message',
      '',
    ].join('\n'),
  );
}

export async function runPolicyCommand(args: string[], io: PolicyCommandIO): Promise<number> {
  if (args.length === 0 || args[0] === '--help' || args[0] === '-h') {
    printHelp(io.stdout);
    return 0;
  }

  const subcommand = args[0];

  if (subcommand === 'audit') {
    const result = auditEnterprisePolicies();
    io.stdout(JSON.stringify(result, null, 2) + '\n');
    const hasHigh = result.findings.some((f) => f.severity === SeverityLevel.HIGH);
    return hasHigh ? 1 : 0;
  }

  if (subcommand === 'impact') {
    const allowlistIdx = args.indexOf('--allowlist');
    const allowlistPath = allowlistIdx !== -1 ? args[allowlistIdx + 1] : undefined;
    if (!allowlistPath) {
      io.stderr('Error: impact requires --allowlist <file>\n');
      return 2;
    }
    try {
      const result = analyzePolicyImpact(allowlistPath, { homeDir: io.homeDir });
      io.stdout(JSON.stringify(result, null, 2) + '\n');
      return 0;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      io.stderr(`Error: ${message}\n`);
      return 2;
    }
  }

  if (subcommand === 'generate') {
    const inputDir = args[1];
    if (!inputDir) {
      io.stderr('Error: generate requires <dir>\n');
      return 2;
    }
    try {
      const bundle = generatePolicyFromGitOps(inputDir);
      io.stdout(JSON.stringify(bundle, null, 2) + '\n');
      return 0;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      io.stderr(`Error: ${message}\n`);
      return 2;
    }
  }

  io.stderr(`Unknown policy subcommand: ${subcommand}\n`);
  return 2;
}
