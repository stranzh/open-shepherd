#!/usr/bin/env node
/**
 * Open Shepherd Headless CLI
 *
 * Scans local workspaces, user global AI/IDE configs, and remote GitHub repositories
 * for pre-execution supply-chain and prompt-injection risks without VS Code dependencies.
 */

import * as fs from 'fs';
import * as path from 'path';
import { WorkspaceFinding } from '../detection/workspace-rule-types';
import { SeverityLevel } from '../lib/events/sec-events';
import { parseSyslogEndpoint, sendSyslogPayload } from '../lib/services/syslog-transport';
import { ConsoleLogger } from './console-logger';
import { CliExportFormat, formatWorkspaceFindings } from './formatters';
import { HeadlessWorkspaceScanner } from './headless-scanner';
import { collectIdeInventory, formatInventoryOcsf } from './inventory';
import { runPolicyCommand } from './policy';
import { scanRemoteGithubRepo } from './scan-repo';

export interface CliIo {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  fetchFn?: typeof fetch;
  homeDir?: string;
  cwd?: string;
}

const VALID_FORMATS = new Set<CliExportFormat>(['jsonl', 'sarif', 'ocsf', 'cef']);

const USAGE_TEXT = [
  'Usage:',
  '  open-shepherd scan [dir] [--global] [--inventory] [--format <jsonl|sarif|ocsf|cef>] [--syslog <udp|tcp|tls://host:port>]',
  '  open-shepherd scan-repo <github-url|owner/repo> [--ref <branch-or-sha>] [--token <token>] [--format <jsonl|sarif|ocsf|cef>] [--syslog <udp|tcp|tls://host:port>]',
  '  open-shepherd policy <audit|impact|generate> [options]',
  '',
  'Options:',
  '  --global                 Scan user global AI/IDE configs (in addition to [dir] if provided)',
  '  --inventory              Emit OCSF Inventory Info (class_uid 5001) for installed IDEs and extensions',
  '  --format <fmt>           Output format: jsonl (default), sarif, ocsf, cef',
  '  --syslog <endpoint>      Forward formatted lines to udp://, tcp://, or tls:// host:port',
  '  --ref <branch-or-sha>    Git branch, tag, or commit SHA for scan-repo',
  '  --token <token>          GitHub API token (falls back to GITHUB_TOKEN / GH_TOKEN)',
  '  -h, --help               Show this help message',
  '',
  'Exit codes:',
  '  0  No HIGH severity findings',
  '  1  One or more HIGH severity findings detected',
  '  2  Invalid arguments, configuration error, or scan failure',
].join('\n');

function parseExportFormat(raw: string): CliExportFormat | null {
  if (VALID_FORMATS.has(raw as CliExportFormat)) {
    return raw as CliExportFormat;
  }
  return null;
}

interface ParsedScanArgs {
  help?: boolean;
  includeGlobal: boolean;
  inventory: boolean;
  format: CliExportFormat;
  syslogEndpoint?: string;
  dirArg?: string;
}

function parseScanArgs(args: string[]): ParsedScanArgs {
  let includeGlobal = false;
  let inventory = false;
  let format: CliExportFormat = 'jsonl';
  let syslogEndpoint: string | undefined;
  let dirArg: string | undefined;
  let endOfFlags = false;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (!endOfFlags && (arg === '--help' || arg === '-h')) {
      return { help: true, includeGlobal, inventory, format, syslogEndpoint, dirArg };
    }
    if (!endOfFlags && arg === '--') {
      endOfFlags = true;
      continue;
    }
    if (!endOfFlags && arg === '--global') {
      includeGlobal = true;
      continue;
    }
    if (!endOfFlags && arg === '--inventory') {
      inventory = true;
      continue;
    }
    if (!endOfFlags && arg === '--syslog') {
      const next = args[++i];
      if (!next || next.startsWith('-')) {
        throw new Error('Missing value for --syslog');
      }
      syslogEndpoint = next;
      continue;
    }
    if (!endOfFlags && arg.startsWith('--syslog=')) {
      const rawSyslog = arg.slice('--syslog='.length);
      if (!rawSyslog) {
        throw new Error('Missing value for --syslog');
      }
      syslogEndpoint = rawSyslog;
      continue;
    }
    if (!endOfFlags && arg === '--format') {
      const next = args[++i];
      if (!next || next.startsWith('-')) {
        throw new Error('Missing value for --format (expected jsonl, sarif, ocsf, or cef)');
      }
      const parsedFmt = parseExportFormat(next);
      if (!parsedFmt) {
        throw new Error(`Invalid format "${next}". Expected one of: jsonl, sarif, ocsf, cef`);
      }
      format = parsedFmt;
      continue;
    }
    if (!endOfFlags && arg.startsWith('--format=')) {
      const rawFmt = arg.slice('--format='.length);
      const parsedFmt = parseExportFormat(rawFmt);
      if (!parsedFmt) {
        throw new Error(`Invalid format "${rawFmt}". Expected one of: jsonl, sarif, ocsf, cef`);
      }
      format = parsedFmt;
      continue;
    }
    if (!endOfFlags && arg === '--syslog') {
      const next = args[++i];
      if (!next || next.startsWith('-')) {
        throw new Error('Missing value for --syslog');
      }
      syslogEndpoint = next;
      continue;
    }
    if (!endOfFlags && arg.startsWith('--syslog=')) {
      const rawSyslog = arg.slice('--syslog='.length);
      if (!rawSyslog) {
        throw new Error('Missing value for --syslog');
      }
      syslogEndpoint = rawSyslog;
      continue;
    }
    if (!endOfFlags && arg.startsWith('-')) {
      throw new Error(`Unknown option "${arg}" for command "scan"`);
    }
    if (dirArg !== undefined) {
      throw new Error(`Unexpected extra positional argument "${arg}" for command "scan"`);
    }
    dirArg = arg;
  }

  return { includeGlobal, inventory, format, syslogEndpoint, dirArg };
}

interface ParsedScanRepoArgs {
  help?: boolean;
  repoArg?: string;
  ref?: string;
  token?: string;
  format: CliExportFormat;
  syslogEndpoint?: string;
}

function parseScanRepoArgs(args: string[]): ParsedScanRepoArgs {
  let repoArg: string | undefined;
  let ref: string | undefined;
  let token: string | undefined;
  let format: CliExportFormat = 'jsonl';
  let syslogEndpoint: string | undefined;
  let endOfFlags = false;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (!endOfFlags && (arg === '--help' || arg === '-h')) {
      return { help: true, repoArg, ref, token, format, syslogEndpoint };
    }
    if (!endOfFlags && arg === '--') {
      endOfFlags = true;
      continue;
    }
    if (!endOfFlags && arg === '--ref') {
      const next = args[++i];
      if (!next || next.startsWith('-')) {
        throw new Error('Missing value for --ref');
      }
      ref = next;
      continue;
    }
    if (!endOfFlags && arg.startsWith('--ref=')) {
      const rawRef = arg.slice('--ref='.length);
      if (!rawRef) {
        throw new Error('Missing value for --ref');
      }
      ref = rawRef;
      continue;
    }
    if (!endOfFlags && arg === '--token') {
      const next = args[++i];
      if (!next || next.startsWith('-')) {
        throw new Error('Missing value for --token');
      }
      token = next;
      continue;
    }
    if (!endOfFlags && arg.startsWith('--token=')) {
      const rawToken = arg.slice('--token='.length);
      if (!rawToken) {
        throw new Error('Missing value for --token');
      }
      token = rawToken;
      continue;
    }
    if (!endOfFlags && arg === '--format') {
      const next = args[++i];
      if (!next || next.startsWith('-')) {
        throw new Error('Missing value for --format (expected jsonl, sarif, ocsf, or cef)');
      }
      const parsedFmt = parseExportFormat(next);
      if (!parsedFmt) {
        throw new Error(`Invalid format "${next}". Expected one of: jsonl, sarif, ocsf, cef`);
      }
      format = parsedFmt;
      continue;
    }
    if (!endOfFlags && arg.startsWith('--format=')) {
      const rawFmt = arg.slice('--format='.length);
      const parsedFmt = parseExportFormat(rawFmt);
      if (!parsedFmt) {
        throw new Error(`Invalid format "${rawFmt}". Expected one of: jsonl, sarif, ocsf, cef`);
      }
      format = parsedFmt;
      continue;
    }
    if (!endOfFlags && arg === '--syslog') {
      const next = args[++i];
      if (!next || next.startsWith('-')) {
        throw new Error('Missing value for --syslog');
      }
      syslogEndpoint = next;
      continue;
    }
    if (!endOfFlags && arg.startsWith('--syslog=')) {
      const rawSyslog = arg.slice('--syslog='.length);
      if (!rawSyslog) {
        throw new Error('Missing value for --syslog');
      }
      syslogEndpoint = rawSyslog;
      continue;
    }
    if (!endOfFlags && arg.startsWith('-')) {
      throw new Error(`Unknown option "${arg}" for command "scan-repo"`);
    }
    if (repoArg !== undefined) {
      throw new Error(`Unexpected extra positional argument "${arg}" for command "scan-repo"`);
    }
    repoArg = arg;
  }

  return { repoArg, ref, token, format, syslogEndpoint };
}

export async function runCli(argv: string[], io?: Partial<CliIo>): Promise<number> {
  const resolvedIo: CliIo = {
    stdout: io?.stdout ?? ((text: string) => process.stdout.write(text.endsWith('\n') ? text : `${text}\n`)),
    stderr: io?.stderr ?? ((text: string) => process.stderr.write(text.endsWith('\n') ? text : `${text}\n`)),
    fetchFn: io?.fetchFn,
    homeDir: io?.homeDir,
    cwd: io?.cwd,
  };

  if (argv.length === 0) {
    resolvedIo.stderr(`Missing command. Expected "scan" or "scan-repo".\n\n${USAGE_TEXT}`);
    return 2;
  }

  const [command, ...rest] = argv;
  if (command === '--help' || command === '-h' || command === 'help') {
    resolvedIo.stdout(USAGE_TEXT);
    return 0;
  }

  const logger = new ConsoleLogger((line: string) => resolvedIo.stderr(line));
  const scanner = new HeadlessWorkspaceScanner(logger);
  let findings: WorkspaceFinding[] = [];
  let format: CliExportFormat = 'jsonl';
  let syslogEndpoint: string | undefined;
  let targetLabel = '';

  if (command === 'policy') {
    return runPolicyCommand(rest, {
      stdout: resolvedIo.stdout,
      stderr: resolvedIo.stderr,
      homeDir: resolvedIo.homeDir,
    });
  }

  if (command === 'scan') {
    let parsed: ParsedScanArgs;
    try {
      parsed = parseScanArgs(rest);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      resolvedIo.stderr(`${msg}\n\n${USAGE_TEXT}`);
      return 2;
    }

    if (parsed.help) {
      resolvedIo.stdout(USAGE_TEXT);
      return 0;
    }

    if (parsed.inventory) {
      const inv = collectIdeInventory(resolvedIo.homeDir);
      const invOutput = formatInventoryOcsf(inv);
      if (invOutput.trim().length > 0) {
        resolvedIo.stdout(invOutput);
        if (parsed.syslogEndpoint) {
          try {
            parseSyslogEndpoint(parsed.syslogEndpoint);
            await sendSyslogPayload(parsed.syslogEndpoint, invOutput.split('\n'));
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            resolvedIo.stderr(`syslog delivery failed: ${msg}`);
            return 2;
          }
        }
      }
      return 0;
    }

    format = parsed.format;
    syslogEndpoint = parsed.syslogEndpoint;

    if (parsed.dirArg !== undefined || !parsed.includeGlobal) {
      const baseCwd = resolvedIo.cwd ?? process.cwd();
      const targetPath = parsed.dirArg !== undefined ? path.resolve(baseCwd, parsed.dirArg) : baseCwd;
      targetLabel = targetPath;

      let stat: fs.Stats;
      try {
        stat = fs.statSync(targetPath);
      } catch {
        resolvedIo.stderr(`Target path does not exist: ${targetPath}`);
        return 2;
      }

      if (stat.isDirectory()) {
        findings.push(...scanner.scanDirectory(targetPath));
      } else if (stat.isFile()) {
        findings.push(...scanner.scanSingleFile(targetPath, path.dirname(targetPath)));
      } else {
        resolvedIo.stderr(`Target path is neither a file nor a directory: ${targetPath}`);
        return 2;
      }
    }

    if (parsed.includeGlobal) {
      if (!targetLabel) {
        targetLabel = resolvedIo.homeDir ?? 'global';
      }
      findings.push(...scanner.scanGlobalConfigs(resolvedIo.homeDir));
    }
  } else if (command === 'scan-repo') {
    let parsed: ParsedScanRepoArgs;
    try {
      parsed = parseScanRepoArgs(rest);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      resolvedIo.stderr(`${msg}\n\n${USAGE_TEXT}`);
      return 2;
    }

    if (parsed.help) {
      resolvedIo.stdout(USAGE_TEXT);
      return 0;
    }

    if (!parsed.repoArg) {
      resolvedIo.stderr(`Missing GitHub repository URL or owner/repo slug for "scan-repo".\n\n${USAGE_TEXT}`);
      return 2;
    }

    format = parsed.format;
    syslogEndpoint = parsed.syslogEndpoint;
    targetLabel = parsed.repoArg;

    try {
      findings = await scanRemoteGithubRepo(parsed.repoArg, {
        ref: parsed.ref,
        token: parsed.token,
        fetchFn: resolvedIo.fetchFn,
        scanner,
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      resolvedIo.stderr(`scan-repo failed: ${msg}`);
      return 2;
    }
  } else {
    resolvedIo.stderr(`Unknown command "${command}". Expected "scan" or "scan-repo".\n\n${USAGE_TEXT}`);
    return 2;
  }

  if (syslogEndpoint) {
    try {
      parseSyslogEndpoint(syslogEndpoint);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      resolvedIo.stderr(`syslog configuration error: ${msg}`);
      return 2;
    }
  }

  const formatted = formatWorkspaceFindings(findings, format, { target: targetLabel });
  if (formatted.trim().length > 0) {
    resolvedIo.stdout(formatted);
    if (syslogEndpoint) {
      try {
        const lines = format === 'sarif' ? [formatted] : formatted.split('\n');
        await sendSyslogPayload(syslogEndpoint, lines);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        resolvedIo.stderr(`syslog delivery failed: ${msg}`);
        return 2;
      }
    }
  }

  return findings.some((f) => f.severity === SeverityLevel.HIGH) ? 1 : 0;
}

if (typeof require !== 'undefined' && require.main === module) {
  runCli(process.argv.slice(2))
    .then((code) => {
      process.exit(code);
    })
    .catch((err: unknown) => {
      const message = err instanceof Error ? err.message : String(err);
      process.stderr.write(`open-shepherd error: ${message}\n`);
      process.exit(2);
    });
}
