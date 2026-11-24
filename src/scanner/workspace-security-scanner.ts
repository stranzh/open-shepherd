/**
 * Workspace & AI IDE Configuration Security Scanner
 *
 * Scans workspace folders and user AI configs (MCP servers, agent rules,
 * VS Code tasks/launch/settings, git hooks/config, devcontainers, package manifests)
 * before execution.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as vscode from 'vscode';
import {
  McpStdioPinTracker,
  scanClaudeSettings,
  scanCodexTomlMcp,
  scanCursorCliConfig,
  scanOpenCodeConfig,
  scanZedSettings,
} from '../detection/ai-mcp-extra-rules';
import { IDE_AND_AGENT_REGISTRY, detectShadowAiInPaths } from '../detection/ide-registry';
import {
  WorkspaceFinding,
  WorkspaceRuleType,
  scanAgentRulesFile,
  scanAntigravityCliSettings,
  scanDevcontainerJson,
  scanGitConfig,
  scanHooksConfig,
  scanMcpConfig,
  scanPackageManagerConfig,
  scanPackageManifest,
  scanVscodeLaunchJson,
  scanVscodeSettings,
  scanVscodeTasksJson,
} from '../detection/workspace-rules';
import { WorkspaceInfo } from '../lib/events/ext-events';
import { SecurityEvent, SeverityLevel } from '../lib/events/sec-events';
import { TaskEvent } from '../lib/events/task-events';
import { Logger } from '../lib/logger';
import { IDEStatusService } from '../lib/services/ide-status-service';
import { TrustedWorkspaceService } from '../lib/services/trusted-workspace-service';

const MAX_CONFIG_BYTES = 512 * 1024;

function readTextSafe(filePath: string): string | null {
  try {
    const stat = fs.statSync(filePath);
    if (!stat.isFile() || stat.size > MAX_CONFIG_BYTES) {
      return null;
    }
    return fs.readFileSync(filePath, 'utf8');
  } catch {
    return null;
  }
}

function endsWithPath(normPath: string, suffix: string): boolean {
  const lower = suffix.toLowerCase();
  return normPath === lower || normPath.endsWith(`/${lower}`);
}

function collectExistingRegistryPaths(baseDir: string, relPaths: string[]): string[] {
  const found: string[] = [];
  for (const rawRel of relPaths) {
    const rel = rawRel.startsWith('~/') ? rawRel.slice(2) : rawRel;
    const candidate = path.join(baseDir, rel);
    try {
      if (fs.existsSync(candidate)) {
        found.push(candidate);
      }
    } catch {
      // ignore inaccessible registry paths
    }
  }
  return found;
}

const CONFIG_SCANNERS: Array<{
  relPath?: string;
  match: (normPath: string) => boolean;
  scan: (content: string, filePath: string) => WorkspaceFinding[];
}> = [
  {
    relPath: '.vscode/settings.json',
    match: (p) => endsWithPath(p, '.vscode/settings.json'),
    scan: scanVscodeSettings,
  },
  { relPath: '.vscode/tasks.json', match: (p) => endsWithPath(p, '.vscode/tasks.json'), scan: scanVscodeTasksJson },
  { relPath: '.vscode/launch.json', match: (p) => endsWithPath(p, '.vscode/launch.json'), scan: scanVscodeLaunchJson },
  { relPath: '.git/config', match: (p) => endsWithPath(p, '.git/config'), scan: scanGitConfig },
  {
    relPath: '.devcontainer/devcontainer.json',
    match: (p) => endsWithPath(p, 'devcontainer.json'),
    scan: scanDevcontainerJson,
  },
  { relPath: 'package.json', match: (p) => endsWithPath(p, 'package.json'), scan: scanPackageManifest },
  { relPath: '.npmrc', match: (p) => endsWithPath(p, '.npmrc'), scan: scanPackageManagerConfig },
  { relPath: 'pip.conf', match: (p) => endsWithPath(p, 'pip.conf'), scan: scanPackageManagerConfig },
  { relPath: '.vscode/mcp.json', match: (p) => endsWithPath(p, '.vscode/mcp.json'), scan: scanMcpConfig },
  { relPath: '.cursor/mcp.json', match: (p) => endsWithPath(p, '.cursor/mcp.json'), scan: scanMcpConfig },
  { relPath: '.kiro/settings/mcp.json', match: (p) => endsWithPath(p, '.kiro/settings/mcp.json'), scan: scanMcpConfig },
  { relPath: '.agents/mcp_config.json', match: (p) => endsWithPath(p, '.agents/mcp_config.json'), scan: scanMcpConfig },
  {
    relPath: '.antigravity-plugin/mcp_config.json',
    match: (p) => endsWithPath(p, '.antigravity-plugin/mcp_config.json'),
    scan: scanMcpConfig,
  },
  { relPath: 'mcp_config.json', match: (p) => endsWithPath(p, 'mcp_config.json'), scan: scanMcpConfig },
  {
    relPath: '.mcp.json',
    match: (p) => endsWithPath(p, '.mcp.json') || endsWithPath(p, 'mcp.json') || endsWithPath(p, 'mcp-config.json'),
    scan: scanMcpConfig,
  },
  {
    match: (p) => endsWithPath(p, '.claude.json') || endsWithPath(p, 'claude_desktop_config.json'),
    scan: scanMcpConfig,
  },
  {
    relPath: '.claude/settings.json',
    match: (p) => endsWithPath(p, '.claude/settings.json'),
    scan: scanClaudeSettings,
  },
  {
    relPath: '.claude/settings.local.json',
    match: (p) => endsWithPath(p, '.claude/settings.local.json'),
    scan: scanClaudeSettings,
  },
  { relPath: '.cursor/cli.json', match: (p) => endsWithPath(p, '.cursor/cli.json'), scan: scanCursorCliConfig },
  { relPath: '.codex/config.toml', match: (p) => endsWithPath(p, '.codex/config.toml'), scan: scanCodexTomlMcp },
  {
    relPath: '.zed/settings.json',
    match: (p) => endsWithPath(p, '.zed/settings.json') || endsWithPath(p, 'zed/settings.json'),
    scan: scanZedSettings,
  },
  { relPath: 'opencode.json', match: (p) => endsWithPath(p, 'opencode.json'), scan: scanOpenCodeConfig },
  {
    relPath: '.opencode/config.json',
    match: (p) => endsWithPath(p, '.opencode/config.json'),
    scan: scanOpenCodeConfig,
  },
  {
    relPath: '.agents/hooks.json',
    match: (p) => endsWithPath(p, '.agents/hooks.json') || endsWithPath(p, 'hooks.json'),
    scan: scanHooksConfig,
  },
  { relPath: '.cursorrules', match: (p) => endsWithPath(p, '.cursorrules'), scan: scanAgentRulesFile },
  { match: (p) => p.includes('/.cursor/rules/'), scan: scanAgentRulesFile },
  { relPath: 'CLAUDE.md', match: (p) => endsWithPath(p, 'claude.md'), scan: scanAgentRulesFile },
  { relPath: 'AGENTS.md', match: (p) => endsWithPath(p, 'agents.md'), scan: scanAgentRulesFile },
  { relPath: 'AGENTS.override.md', match: (p) => endsWithPath(p, 'agents.override.md'), scan: scanAgentRulesFile },
  { relPath: 'GEMINI.md', match: (p) => endsWithPath(p, 'gemini.md'), scan: scanAgentRulesFile },
  {
    match: (p) =>
      p.includes('/.agents/rules/') ||
      p.includes('/.agents/agents/') ||
      p.includes('/.agents/skills/') ||
      p.includes('/.agent/skills/') ||
      endsWithPath(p, 'skill.md'),
    scan: scanAgentRulesFile,
  },
  {
    relPath: '.github/copilot-instructions.md',
    match: (p) => endsWithPath(p, 'copilot-instructions.md'),
    scan: scanAgentRulesFile,
  },
  { relPath: '.windsurfrules', match: (p) => endsWithPath(p, '.windsurfrules'), scan: scanAgentRulesFile },
  { relPath: '.clinerules', match: (p) => endsWithPath(p, '.clinerules'), scan: scanAgentRulesFile },
  { match: (p) => endsWithPath(p, 'antigravity-cli/settings.json'), scan: scanAntigravityCliSettings },
];

export class WorkspaceSecurityScanner {
  private static _instance: WorkspaceSecurityScanner;
  private readonly mcpPinTracker = new McpStdioPinTracker();

  private constructor() {}

  static getInstance(): WorkspaceSecurityScanner {
    if (!WorkspaceSecurityScanner._instance) {
      WorkspaceSecurityScanner._instance = new WorkspaceSecurityScanner();
    }
    return WorkspaceSecurityScanner._instance;
  }

  activate(context: vscode.ExtensionContext): void {
    this.scanAllWorkspaces(true).catch((err) => {
      Logger.warn(`WorkspaceSecurityScanner: initial scan failed: ${(err as Error).message}`);
    });

    context.subscriptions.push(
      vscode.workspace.onDidChangeWorkspaceFolders(() => {
        this.scanAllWorkspaces(false).catch((err) => {
          Logger.warn(`WorkspaceSecurityScanner: folder change scan failed: ${(err as Error).message}`);
        });
      }),
      vscode.workspace.onDidSaveTextDocument((doc) => {
        const fsPath = doc.uri.fsPath;
        if (this.isWatchedConfigPath(fsPath)) {
          const folder = vscode.workspace.getWorkspaceFolder(doc.uri);
          const findings = this.scanSingleFile(fsPath, folder?.uri.fsPath);
          if (findings.length > 0) {
            const wsName = folder?.name || 'Workspace';
            const wsPath = folder?.uri.fsPath || path.dirname(fsPath);
            this.reportFindings(findings, wsName, wsPath).catch(() => {});
          }
        }
      }),
    );
  }

  private isWatchedConfigPath(filePath: string): boolean {
    const norm = filePath.replace(/\\/g, '/').toLowerCase();
    return CONFIG_SCANNERS.some((entry) => entry.match(norm));
  }

  scanSingleFile(filePath: string, baseDir?: string): WorkspaceFinding[] {
    const content = readTextSafe(filePath);
    if (content === null) {
      return [];
    }
    const norm = filePath.replace(/\\/g, '/').toLowerCase();
    const entry = CONFIG_SCANNERS.find((item) => item.match(norm));
    if (!entry) {
      return [];
    }
    const findings = entry.scan(content, filePath);
    if (entry.scan === scanMcpConfig || entry.scan === scanZedSettings || entry.scan === scanOpenCodeConfig) {
      findings.push(...this.mcpPinTracker.checkMcpConfig(content, filePath, baseDir));
    } else if (entry.scan === scanCodexTomlMcp) {
      findings.push(...this.mcpPinTracker.checkTomlMcpServers(content, filePath, baseDir));
    }
    return findings;
  }

  scanDirectory(rootDir: string): WorkspaceFinding[] {
    const findings: WorkspaceFinding[] = [];
    for (const entry of CONFIG_SCANNERS) {
      if (entry.relPath) {
        findings.push(...this.scanSingleFile(path.join(rootDir, entry.relPath), rootDir));
      }
    }

    const existingWorkspacePaths = collectExistingRegistryPaths(
      rootDir,
      IDE_AND_AGENT_REGISTRY.flatMap((ideEntry) => ideEntry.workspacePaths),
    );
    findings.push(...detectShadowAiInPaths(existingWorkspacePaths, undefined, rootDir));

    // Scan .cursor/rules/*, .agents/rules/*, .agents/agents/*
    for (const relDir of [
      path.join('.cursor', 'rules'),
      path.join('.agents', 'rules'),
      path.join('.agents', 'agents'),
    ]) {
      const dirPath = path.join(rootDir, relDir);
      try {
        if (fs.existsSync(dirPath)) {
          for (const entry of fs.readdirSync(dirPath)) {
            const full = path.join(dirPath, entry);
            const content = readTextSafe(full);
            if (content !== null) {
              findings.push(...scanAgentRulesFile(content, full));
            }
          }
        }
      } catch {
        // ignore unreadable rule directories
      }
    }

    // Scan one-level <skill>/SKILL.md inside .agents/skills and .agent/skills
    for (const relSkillsDir of [path.join('.agents', 'skills'), path.join('.agent', 'skills')]) {
      const skillsDir = path.join(rootDir, relSkillsDir);
      try {
        if (fs.existsSync(skillsDir)) {
          for (const skillEntry of fs.readdirSync(skillsDir)) {
            const skillMd = path.join(skillsDir, skillEntry, 'SKILL.md');
            const content = readTextSafe(skillMd);
            if (content !== null) {
              findings.push(...scanAgentRulesFile(content, skillMd));
            }
          }
        }
      } catch {
        // ignore unreadable skills directories
      }
    }

    // Scan .git/hooks/* (non-sample executable scripts)
    const gitHooksDir = path.join(rootDir, '.git', 'hooks');
    try {
      if (fs.existsSync(gitHooksDir)) {
        for (const entry of fs.readdirSync(gitHooksDir)) {
          if (entry.endsWith('.sample')) {
            continue;
          }
          const full = path.join(gitHooksDir, entry);
          const content = readTextSafe(full);
          if (content !== null && content.trim().length > 0) {
            findings.push({
              ruleId: 'git_hook_script',
              ruleName: 'Active Git Hook Script',
              type: WorkspaceRuleType.GIT_CONFIG,
              severity: SeverityLevel.MEDIUM,
              filePath: full,
              finding: `.git/hooks/${entry}`,
              description: `Repository contains active git hook script "${entry}" that runs on git actions`,
              confidence: 0.85,
            });
          }
        }
      }
    } catch {
      // ignore unreadable .git/hooks
    }

    return findings;
  }

  async scanAllWorkspaces(includeGlobalMcp = true): Promise<WorkspaceFinding[]> {
    const allFindings: WorkspaceFinding[] = [];
    const folders = vscode.workspace.workspaceFolders ?? [];

    for (const folder of folders) {
      const folderPath = folder.uri.fsPath;
      if (TrustedWorkspaceService.getInstance().isTrusted(folderPath)) {
        continue;
      }
      const findings = this.scanDirectory(folderPath);
      allFindings.push(...findings);
      if (findings.length > 0) {
        await this.reportFindings(findings, folder.name, folderPath);
      }
    }

    if (includeGlobalMcp) {
      const home = os.homedir();
      for (const globalMcp of [
        path.join(home, '.cursor', 'mcp.json'),
        path.join(home, '.claude.json'),
        path.join(home, '.claude', 'settings.json'),
        path.join(home, '.claude', 'settings.local.json'),
        path.join(home, '.config', 'Claude', 'claude_desktop_config.json'),
        path.join(home, '.codeium', 'windsurf', 'mcp_config.json'),
        path.join(home, '.config', 'devin', 'mcp.json'),
        path.join(home, '.kiro', 'settings', 'mcp.json'),
        path.join(home, '.codex', 'config.toml'),
        path.join(home, '.config', 'opencode', 'opencode.json'),
        path.join(home, '.copilot', 'mcp-config.json'),
        path.join(home, '.config', 'zed', 'settings.json'),
        path.join(home, '.gemini', 'config', 'mcp_config.json'),
        path.join(home, '.gemini', 'config', 'hooks.json'),
        path.join(home, '.gemini', 'GEMINI.md'),
        path.join(home, '.gemini', 'antigravity-cli', 'settings.json'),
      ]) {
        const mcpFindings = this.scanSingleFile(globalMcp);
        if (mcpFindings.length > 0) {
          allFindings.push(...mcpFindings);
          await this.reportFindings(mcpFindings, 'User Global MCP', path.dirname(globalMcp));
        }
      }

      const existingHomePaths = collectExistingRegistryPaths(
        home,
        IDE_AND_AGENT_REGISTRY.flatMap((ideEntry) => ideEntry.homePaths),
      );
      const shadowFindings = detectShadowAiInPaths(existingHomePaths, undefined, home);
      if (shadowFindings.length > 0) {
        allFindings.push(...shadowFindings);
        await this.reportFindings(shadowFindings, 'User Global MCP', home);
      }

      for (const globalSkillsDir of [
        path.join(home, '.gemini', 'config', 'skills'),
        path.join(home, '.gemini', 'skills'),
        path.join(home, '.gemini', 'antigravity-cli', 'skills'),
      ]) {
        try {
          if (fs.existsSync(globalSkillsDir)) {
            for (const skillEntry of fs.readdirSync(globalSkillsDir)) {
              const skillMd = path.join(globalSkillsDir, skillEntry, 'SKILL.md');
              const content = readTextSafe(skillMd);
              if (content !== null) {
                const skillFindings = scanAgentRulesFile(content, skillMd);
                if (skillFindings.length > 0) {
                  allFindings.push(...skillFindings);
                  await this.reportFindings(skillFindings, 'User Global MCP', path.dirname(skillMd));
                }
              }
            }
          }
        } catch {
          // ignore unreadable global skills directories
        }
      }

      for (const globalPluginsDir of [
        path.join(home, '.gemini', 'config', 'plugins'),
        path.join(home, '.gemini', 'antigravity-cli', 'plugins'),
      ]) {
        try {
          if (fs.existsSync(globalPluginsDir)) {
            for (const pluginEntry of fs.readdirSync(globalPluginsDir)) {
              for (const cfgName of ['hooks.json', 'mcp_config.json']) {
                const cfgPath = path.join(globalPluginsDir, pluginEntry, cfgName);
                const pluginFindings = this.scanSingleFile(cfgPath);
                if (pluginFindings.length > 0) {
                  allFindings.push(...pluginFindings);
                  await this.reportFindings(pluginFindings, 'User Global MCP', path.dirname(cfgPath));
                }
              }
            }
          }
        } catch {
          // ignore unreadable global plugins directories
        }
      }

      const transcriptFindings = this.scanAntigravityTranscripts(home);
      if (transcriptFindings.length > 0) {
        allFindings.push(...transcriptFindings);
        await this.reportFindings(transcriptFindings, 'User Global MCP', path.join(home, '.gemini'));
      }
    }

    return allFindings;
  }

  scanAntigravityTranscripts(homeDir = os.homedir()): WorkspaceFinding[] {
    const findings: WorkspaceFinding[] = [];
    const candidates: Array<{ filePath: string; mtimeMs: number }> = [];

    for (const surf of ['antigravity', 'antigravity-cli', 'antigravity-ide']) {
      const brainDir = path.join(homeDir, '.gemini', surf, 'brain');
      try {
        if (!fs.existsSync(brainDir)) {
          continue;
        }
        for (const convId of fs.readdirSync(brainDir)) {
          const transcriptPath = path.join(brainDir, convId, '.system_generated', 'logs', 'transcript.jsonl');
          try {
            const stat = fs.statSync(transcriptPath);
            if (stat.isFile()) {
              candidates.push({ filePath: transcriptPath, mtimeMs: stat.mtimeMs });
            }
          } catch {
            // ignore missing transcript.jsonl
          }
        }
      } catch {
        // ignore unreadable brain directory
      }
    }

    candidates.sort((a, b) => b.mtimeMs - a.mtimeMs);
    const dangerRe = /(?:\brm\s+-[a-z]*r[a-z]*f\s+\/|(?:curl|wget)[^\n|]*\|\s*(?:sh|bash)\b|169\.254\.169\.254)/i;

    for (const item of candidates.slice(0, 5)) {
      const content = readTextSafe(item.filePath);
      if (content === null) {
        continue;
      }
      for (const line of content.split(/\r?\n/)) {
        if (line.includes('--dangerously-skip-permissions') || dangerRe.test(line)) {
          findings.push({
            ruleId: 'antigravity_transcript_unhooked_violation',
            ruleName: 'Suspicious Activity in Antigravity Transcript',
            type: WorkspaceRuleType.AGENT_RULES,
            severity: SeverityLevel.HIGH,
            filePath: item.filePath,
            finding: 'Dangerous command or permission bypass in transcript.jsonl',
            description:
              'Antigravity conversation transcript recorded a dangerous command or --dangerously-skip-permissions execution',
            confidence: 0.9,
          });
          break;
        }
      }
    }

    return findings;
  }

  private async reportFindings(findings: WorkspaceFinding[], wsName: string, wsPath: string): Promise<void> {
    for (const f of findings) {
      const wsInfo = new WorkspaceInfo(wsName, wsPath, false);
      const taskEvent = new TaskEvent(
        `Workspace Scan: ${path.basename(f.filePath)}`,
        f.type,
        'WorkspaceSecurityScanner',
        f.finding,
        [],
        wsInfo,
        wsPath,
      );
      const secEvent = new SecurityEvent(taskEvent, wsInfo, f.severity, f.type, [
        {
          finding: `${f.filePath}: ${f.finding}`,
          rule: f.ruleName,
          description: f.description,
          confidence: f.confidence,
          severity: f.severity,
        },
      ]);
      await IDEStatusService.emitSecurityEvent(secEvent).catch((err) => {
        Logger.warn(`WorkspaceSecurityScanner: failed to emit event: ${(err as Error).message}`);
      });
    }

    const highCount = findings.filter((f) => f.severity === SeverityLevel.HIGH).length;
    if (highCount > 0) {
      vscode.window.showWarningMessage(`IDE Shepherd detected ${highCount} high-risk issue(s) in ${wsName}.`);
    }
  }
}
