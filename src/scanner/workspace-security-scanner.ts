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

const CONFIG_SCANNERS: Array<{
  relPath?: string;
  match: (normPath: string) => boolean;
  scan: (content: string, filePath: string) => WorkspaceFinding[];
}> = [
  { relPath: '.vscode/settings.json', match: (p) => p.endsWith('/.vscode/settings.json'), scan: scanVscodeSettings },
  { relPath: '.vscode/tasks.json', match: (p) => p.endsWith('/.vscode/tasks.json'), scan: scanVscodeTasksJson },
  { relPath: '.vscode/launch.json', match: (p) => p.endsWith('/.vscode/launch.json'), scan: scanVscodeLaunchJson },
  { relPath: '.git/config', match: (p) => p.endsWith('/.git/config'), scan: scanGitConfig },
  {
    relPath: '.devcontainer/devcontainer.json',
    match: (p) => p.endsWith('/devcontainer.json'),
    scan: scanDevcontainerJson,
  },
  { relPath: 'package.json', match: (p) => p.endsWith('/package.json'), scan: scanPackageManifest },
  { relPath: '.npmrc', match: (p) => p.endsWith('/.npmrc') || p.endsWith('/pip.conf'), scan: scanPackageManagerConfig },
  { relPath: 'pip.conf', match: () => false, scan: scanPackageManagerConfig },
  { relPath: '.vscode/mcp.json', match: (p) => p.endsWith('/.vscode/mcp.json'), scan: scanMcpConfig },
  {
    relPath: '.mcp.json',
    match: (p) => p.endsWith('/.mcp.json') || p.endsWith('/mcp.json') || p.endsWith('/mcp_config.json'),
    scan: scanMcpConfig,
  },
  { relPath: '.agents/mcp_config.json', match: () => false, scan: scanMcpConfig },
  { relPath: 'mcp_config.json', match: () => false, scan: scanMcpConfig },
  { relPath: '.antigravity-plugin/mcp_config.json', match: () => false, scan: scanMcpConfig },
  { relPath: '.cursor/mcp.json', match: (p) => p.endsWith('/.cursor/mcp.json'), scan: scanMcpConfig },
  { match: (p) => p.endsWith('/.claude.json') || p.endsWith('/claude_desktop_config.json'), scan: scanMcpConfig },
  {
    relPath: '.agents/hooks.json',
    match: (p) => p.endsWith('/.agents/hooks.json') || p.endsWith('/hooks.json'),
    scan: scanHooksConfig,
  },
  { relPath: '.cursorrules', match: (p) => p.endsWith('/.cursorrules'), scan: scanAgentRulesFile },
  { match: (p) => p.includes('/.cursor/rules/'), scan: scanAgentRulesFile },
  { relPath: 'CLAUDE.md', match: (p) => p.endsWith('/claude.md'), scan: scanAgentRulesFile },
  { relPath: 'AGENTS.md', match: (p) => p.endsWith('/agents.md'), scan: scanAgentRulesFile },
  { relPath: 'GEMINI.md', match: (p) => p.endsWith('/gemini.md'), scan: scanAgentRulesFile },
  {
    match: (p) =>
      p.includes('/.agents/rules/') ||
      p.includes('/.agents/agents/') ||
      p.includes('/.agents/skills/') ||
      p.includes('/.agent/skills/') ||
      p.endsWith('/skill.md'),
    scan: scanAgentRulesFile,
  },
  {
    relPath: '.github/copilot-instructions.md',
    match: (p) => p.endsWith('/copilot-instructions.md'),
    scan: scanAgentRulesFile,
  },
  { relPath: '.windsurfrules', match: (p) => p.endsWith('/.windsurfrules'), scan: scanAgentRulesFile },
  { relPath: '.clinerules', match: (p) => p.endsWith('/.clinerules'), scan: scanAgentRulesFile },
  { match: (p) => p.endsWith('/antigravity-cli/settings.json'), scan: scanAntigravityCliSettings },
];

export class WorkspaceSecurityScanner {
  private static _instance: WorkspaceSecurityScanner;

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
          const findings = this.scanSingleFile(fsPath);
          if (findings.length > 0) {
            const folder = vscode.workspace.getWorkspaceFolder(doc.uri);
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

  scanSingleFile(filePath: string): WorkspaceFinding[] {
    const content = readTextSafe(filePath);
    if (content === null) {
      return [];
    }
    const norm = filePath.replace(/\\/g, '/').toLowerCase();
    const entry = CONFIG_SCANNERS.find((item) => item.match(norm));
    return entry ? entry.scan(content, filePath) : [];
  }

  scanDirectory(rootDir: string): WorkspaceFinding[] {
    const findings: WorkspaceFinding[] = [];
    for (const entry of CONFIG_SCANNERS) {
      if (entry.relPath) {
        findings.push(...this.scanSingleFile(path.join(rootDir, entry.relPath)));
      }
    }

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
        path.join(home, '.config', 'Claude', 'claude_desktop_config.json'),
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
    }

    return allFindings;
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
