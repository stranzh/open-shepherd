/**
 * Process Rules - Rule definitions for process execution analysis
 */

import { SeverityLevel } from '../lib/events/sec-events';
import { Target } from '../lib/events/ext-events';
import { EXTRA_PROCESS_RULES } from './process-rules-extra';

export enum ProcessRuleType {
  COMMAND = 'COMMAND',
  SCRIPT = 'SCRIPT',
}

export interface ProcessRule {
  id: string;
  name: string;
  description: string;
  type: ProcessRuleType;
  target: Target;
  severity: SeverityLevel;
  /** Pattern matched against the command string. Optional when optionsMatcher covers the full signal. */
  commandPattern?: RegExp;
  flagPattern?: RegExp;
  /** Matched against exec/spawn options object. When present alongside commandPattern, both must match. */
  optionsMatcher?: (options: Record<string, unknown>) => boolean;
  confidence: number;
}

/**
 * Process rules for command execution analysis
 */
export const PROCESS_RULES: ProcessRule[] = [
  // PowerShell Execution Rules
  {
    id: 'powershell_execution',
    name: 'PowerShell Execution',
    description: 'Detected suspicious PowerShell execution',
    type: ProcessRuleType.SCRIPT,
    target: Target.PROCESS,
    severity: SeverityLevel.HIGH,
    commandPattern: /\b(powershell|pwsh)(\.exe)?\b/i,
    flagPattern:
      /-(?:c(?:ommand)?|enc(?:odedcommand)?|exec(?:utionpolicy)?(?:\s+bypass)?|noprofile|w(?:indowstyle)?(?:\s+hidden)?|noninteractive)/i,
    confidence: 1,
  },

  // Command Injection Rules
  {
    id: 'command_injection',
    name: 'Command Injection',
    description: 'Detected command injection attempt',
    type: ProcessRuleType.COMMAND,
    target: Target.PROCESS,
    severity: SeverityLevel.HIGH,
    commandPattern: /(?:\|\s*(sh|bash|zsh|cmd)\b|\b(curl|wget)\b)/i,
    confidence: 1,
  },

  // Windows Script Host execution — cscript/wscript/mshta are not used by legitimate VS Code extensions
  {
    id: 'windows_script_host',
    name: 'Windows Script Host Execution',
    description:
      'Detected execution via cscript, wscript, or mshta — Windows scripting hosts that legitimate VS Code extensions do not invoke',
    type: ProcessRuleType.COMMAND,
    target: Target.PROCESS,
    severity: SeverityLevel.HIGH,
    commandPattern: /\b(?:cscript|wscript|mshta)(\.exe)?\b/i,
    confidence: 0.95,
  },

  // Detached silent process — payload delivery pattern
  {
    id: 'detached_silent_process',
    name: 'Detached Silent Process',
    description:
      'Process spawned detached with stdio ignored — common pattern for delivering and running a payload independently of the extension host',
    type: ProcessRuleType.COMMAND,
    target: Target.PROCESS,
    severity: SeverityLevel.HIGH,
    optionsMatcher: (opts) => opts['detached'] === true && opts['stdio'] === 'ignore',
    confidence: 0.9,
  },

  // Destructive filesystem, disk, and infrastructure commands
  {
    id: 'destructive_fs_or_disk_command',
    name: 'Destructive Filesystem or Disk Command',
    description: 'Detected destructive filesystem, disk partitioning, or infrastructure destroy command',
    type: ProcessRuleType.COMMAND,
    target: Target.PROCESS,
    severity: SeverityLevel.HIGH,
    commandPattern:
      /(?:\brm\s+-[a-z]*r[a-z]*f|\b(?:diskpart|bcdedit)(?:\.exe)?\b|\bterraform\s+destroy\b|\b(?:Format-Volume|Clear-Disk|Initialize-Disk|Remove-Partition)\b)/i,
    confidence: 0.95,
  },

  // Network transfer, scanning, and remote access tools
  {
    id: 'network_transfer_or_scan_command',
    name: 'Network Transfer or Scanning Command',
    description: 'Detected network transfer, tunneling, remote shell, or port scanning command',
    type: ProcessRuleType.COMMAND,
    target: Target.PROCESS,
    severity: SeverityLevel.HIGH,
    commandPattern:
      /\b(?:nc|ncat|netcat|nmap|socat|ssh|scp|sftp|rsync)(?:\.exe)?\b|\b(?:Invoke-WebRequest|iwr|Start-BitsTransfer|Invoke-Expression)\b/i,
    confidence: 0.9,
  },

  // Windows system administration, firewall, Defender, and persistence commands
  {
    id: 'windows_admin_or_persistence_command',
    name: 'Windows Admin or Persistence Command',
    description: 'Detected Windows registry, service, scheduled task, firewall, or Defender modification command',
    type: ProcessRuleType.COMMAND,
    target: Target.PROCESS,
    severity: SeverityLevel.HIGH,
    commandPattern:
      /\b(?:reg|schtasks|sc|icacls|takeown|net|netsh|wmic|rundll32|regsvr32)\.exe\b|\b(?:Set-ExecutionPolicy|(?:New|Set|Remove)-Service|(?:Register|Unregister)-ScheduledTask|(?:Set|Add|Remove)-MpPreference|(?:New|Set|Remove|Disable)-NetFirewallRule|(?:New|Remove)-LocalUser|(?:Add|Remove)-LocalGroupMember|(?:Restart|Stop)-Computer)\b/i,
    confidence: 0.9,
  },

  // Environment variable injection (LD_PRELOAD, DYLD_INSERT_LIBRARIES, NODE_OPTIONS)
  {
    id: 'env_injection_preload',
    name: 'Process Environment Injection',
    description: 'Detected dynamic linker preload or Node.js runtime option injection in child process environment',
    type: ProcessRuleType.COMMAND,
    target: Target.PROCESS,
    severity: SeverityLevel.HIGH,
    optionsMatcher: (opts) => {
      const env = opts['env'];
      if (!env || typeof env !== 'object' || env === process.env) {
        return false;
      }
      const envObj = env as Record<string, unknown>;
      for (const preloadKey of ['LD_PRELOAD', 'DYLD_INSERT_LIBRARIES']) {
        const val = envObj[preloadKey];
        if (typeof val === 'string' && val && val !== process.env[preloadKey]) {
          return true;
        }
      }
      const nodeOpts = envObj['NODE_OPTIONS'];
      return (
        typeof nodeOpts === 'string' &&
        nodeOpts !== process.env['NODE_OPTIONS'] &&
        /(?:--require|--import|-r\b)/i.test(nodeOpts)
      );
    },
    confidence: 0.95,
  },

  // Explicit forwarding of sensitive credential env vars to untrusted child process
  {
    id: 'env_secret_leak',
    name: 'Sensitive Environment Variable Forwarding',
    description: 'Detected explicit sensitive API/cloud credential variable passed to child process environment',
    type: ProcessRuleType.COMMAND,
    target: Target.PROCESS,
    severity: SeverityLevel.MEDIUM,
    optionsMatcher: (opts) => {
      const env = opts['env'];
      if (!env || typeof env !== 'object' || env === process.env) {
        return false;
      }
      const envObj = env as Record<string, unknown>;
      const sensitiveKeys = [
        'AWS_SECRET_ACCESS_KEY',
        'AWS_SESSION_TOKEN',
        'GITHUB_TOKEN',
        'GH_TOKEN',
        'OPENAI_API_KEY',
        'ANTHROPIC_API_KEY',
        'NPM_TOKEN',
      ];
      return sensitiveKeys.some(
        (key) => typeof envObj[key] === 'string' && envObj[key] !== process.env[key] && Boolean(envObj[key]),
      );
    },
    confidence: 0.85,
  },
  ...EXTRA_PROCESS_RULES,
];

export function getRuleById(id: string): ProcessRule | undefined {
  return PROCESS_RULES.find((rule) => rule.id === id);
}

export function getRulesByType(type: ProcessRuleType): ProcessRule[] {
  return PROCESS_RULES.filter((rule) => rule.type === type);
}

export function getRulesBySeverity(severity: SeverityLevel): ProcessRule[] {
  return PROCESS_RULES.filter((rule) => rule.severity === severity);
}

export function getAllRules(): ProcessRule[] {
  return [...PROCESS_RULES];
}
