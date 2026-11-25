/**
 * Headless Workspace & AI IDE Configuration Security Scanner
 *
 * Pure Node.js scanner operating on filesystem paths and in-memory buffers
 * with zero VS Code dependencies.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  McpStdioPinTracker,
  scanClaudeSettings,
  scanCodexTomlMcp,
  scanCursorCliConfig,
  scanOpenCodeConfig,
  scanZedSettings,
} from '../detection/ai-mcp-extra-rules';
import { scanJupyterNotebook, scanMsbuildProject, scanXcodePbxproj } from '../detection/build-notebook-rules';
import {
  checkInstalledZedVersion,
  scanEmacsDirLocals,
  scanLazyLockJson,
  scanVimConfig,
  scanZedTasksJson,
} from '../detection/editor-config-rules';
import { IDE_AND_AGENT_REGISTRY, detectShadowAiInPaths } from '../detection/ide-registry';
import { scanHuskyHook, scanPreCommitConfig } from '../detection/repo-hook-rules';
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
import { SeverityLevel } from '../lib/events/sec-events';
import { ScanReporter } from './console-logger';
import { scanDownloadsInstructionFiles } from './downloads-guard';
import { scanTunnelPersistence } from './tunnel-persistence';

const MAX_CONFIG_BYTES = 512 * 1024;

export interface ScanDirectoryOptions {
  excludeGitInternal?: boolean;
  skipRuleIds?: string[];
}

export interface ConfigScannerEntry {
  relPath?: string;
  match: (normPath: string) => boolean;
  scan: (content: string, filePath: string, isGlobal?: boolean) => WorkspaceFinding[];
  pinMcpMode?: 'json' | 'toml';
}

export function readTextSafe(filePath: string): string | null {
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

function pathExistsSafe(targetPath: string): boolean {
  try {
    return fs.existsSync(targetPath);
  } catch {
    return false;
  }
}

function endsWithPath(normPath: string, suffix: string): boolean {
  const lower = suffix.toLowerCase();
  return normPath === lower || normPath.endsWith(`/${lower}`);
}

function hasPathSegment(normPath: string, segment: string): boolean {
  const clean = segment.replace(/^\/+|\/+$/g, '').toLowerCase();
  return normPath.startsWith(`${clean}/`) || normPath.includes(`/${clean}/`);
}

export function collectExistingRegistryPaths(baseDir: string, relPaths: string[]): string[] {
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

export const CONFIG_SCANNERS: ConfigScannerEntry[] = [
  // VS Code & IDE configs
  {
    relPath: '.vscode/settings.json',
    match: (p) => endsWithPath(p, '.vscode/settings.json'),
    scan: scanVscodeSettings,
  },
  { relPath: '.vscode/tasks.json', match: (p) => endsWithPath(p, '.vscode/tasks.json'), scan: scanVscodeTasksJson },
  { relPath: '.vscode/launch.json', match: (p) => endsWithPath(p, '.vscode/launch.json'), scan: scanVscodeLaunchJson },

  // Git & Devcontainer
  { relPath: '.git/config', match: (p) => endsWithPath(p, '.git/config'), scan: scanGitConfig },
  {
    match: (p) => hasPathSegment(p, '.git/hooks') && !p.endsWith('.sample'),
    scan: (content, filePath) => {
      if (content.trim().length === 0) {
        return [];
      }
      return [
        {
          ruleId: 'git_hook_script',
          ruleName: 'Active Git Hook Script',
          type: WorkspaceRuleType.GIT_CONFIG,
          severity: SeverityLevel.MEDIUM,
          filePath,
          finding: path.basename(filePath),
          description: `Repository contains active git hook script "${path.basename(filePath)}" that runs on git actions`,
          confidence: 0.85,
        },
      ];
    },
  },
  {
    relPath: '.devcontainer/devcontainer.json',
    match: (p) => endsWithPath(p, 'devcontainer.json'),
    scan: scanDevcontainerJson,
  },

  // Package manifests & package manager configs
  { relPath: 'package.json', match: (p) => endsWithPath(p, 'package.json'), scan: scanPackageManifest },
  { relPath: '.npmrc', match: (p) => endsWithPath(p, '.npmrc'), scan: scanPackageManagerConfig },
  { relPath: 'pip.conf', match: (p) => endsWithPath(p, 'pip.conf'), scan: scanPackageManagerConfig },

  // MCP & AI IDE/CLI configurations
  {
    relPath: '.vscode/mcp.json',
    match: (p) => endsWithPath(p, '.vscode/mcp.json'),
    scan: scanMcpConfig,
    pinMcpMode: 'json',
  },
  {
    relPath: '.cursor/mcp.json',
    match: (p) => endsWithPath(p, '.cursor/mcp.json'),
    scan: scanMcpConfig,
    pinMcpMode: 'json',
  },
  {
    relPath: '.kiro/settings/mcp.json',
    match: (p) => endsWithPath(p, '.kiro/settings/mcp.json'),
    scan: scanMcpConfig,
    pinMcpMode: 'json',
  },
  {
    relPath: '.agents/mcp_config.json',
    match: (p) => endsWithPath(p, '.agents/mcp_config.json'),
    scan: scanMcpConfig,
    pinMcpMode: 'json',
  },
  {
    relPath: '.antigravity-plugin/mcp_config.json',
    match: (p) => endsWithPath(p, '.antigravity-plugin/mcp_config.json'),
    scan: scanMcpConfig,
    pinMcpMode: 'json',
  },
  {
    relPath: 'mcp_config.json',
    match: (p) => endsWithPath(p, 'mcp_config.json'),
    scan: scanMcpConfig,
    pinMcpMode: 'json',
  },
  {
    relPath: '.mcp.json',
    match: (p) => endsWithPath(p, '.mcp.json') || endsWithPath(p, 'mcp.json') || endsWithPath(p, 'mcp-config.json'),
    scan: scanMcpConfig,
    pinMcpMode: 'json',
  },
  {
    match: (p) => endsWithPath(p, '.claude.json') || endsWithPath(p, 'claude_desktop_config.json'),
    scan: scanMcpConfig,
    pinMcpMode: 'json',
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
  {
    relPath: '.codex/config.toml',
    match: (p) => endsWithPath(p, '.codex/config.toml'),
    scan: scanCodexTomlMcp,
    pinMcpMode: 'toml',
  },
  {
    relPath: '.zed/settings.json',
    match: (p) => endsWithPath(p, '.zed/settings.json') || endsWithPath(p, 'zed/settings.json'),
    scan: scanZedSettings,
    pinMcpMode: 'json',
  },
  {
    relPath: 'opencode.json',
    match: (p) => endsWithPath(p, 'opencode.json'),
    scan: scanOpenCodeConfig,
    pinMcpMode: 'json',
  },
  {
    relPath: '.opencode/config.json',
    match: (p) => endsWithPath(p, '.opencode/config.json'),
    scan: scanOpenCodeConfig,
    pinMcpMode: 'json',
  },

  // Agent hooks & instruction files
  {
    relPath: '.agents/hooks.json',
    match: (p) => endsWithPath(p, '.agents/hooks.json') || endsWithPath(p, 'hooks.json'),
    scan: scanHooksConfig,
  },
  { relPath: '.cursorrules', match: (p) => endsWithPath(p, '.cursorrules'), scan: scanAgentRulesFile },
  { match: (p) => hasPathSegment(p, '.cursor/rules'), scan: scanAgentRulesFile },
  { relPath: 'CLAUDE.md', match: (p) => endsWithPath(p, 'claude.md'), scan: scanAgentRulesFile },
  { relPath: 'AGENTS.md', match: (p) => endsWithPath(p, 'agents.md'), scan: scanAgentRulesFile },
  { relPath: 'AGENTS.override.md', match: (p) => endsWithPath(p, 'agents.override.md'), scan: scanAgentRulesFile },
  { relPath: 'GEMINI.md', match: (p) => endsWithPath(p, 'gemini.md'), scan: scanAgentRulesFile },
  {
    match: (p) =>
      hasPathSegment(p, '.agents/rules') ||
      hasPathSegment(p, '.agents/agents') ||
      hasPathSegment(p, '.agents/skills') ||
      hasPathSegment(p, '.agent/skills') ||
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

  // Stage 2: Non-Electron IDEs, notebooks, build configs, and repo hooks
  {
    relPath: '.vimrc',
    match: (p) =>
      endsWithPath(p, '.vimrc') ||
      endsWithPath(p, '.nvimrc') ||
      endsWithPath(p, '.nvim.lua') ||
      endsWithPath(p, '.exrc'),
    scan: (content, filePath, isGlobal) => scanVimConfig(content, filePath, Boolean(isGlobal)),
  },
  {
    match: (p) => endsWithPath(p, '.config/nvim/init.vim') || endsWithPath(p, '.config/nvim/init.lua'),
    scan: (content, filePath) => scanVimConfig(content, filePath, true),
  },
  { relPath: 'lazy-lock.json', match: (p) => endsWithPath(p, 'lazy-lock.json'), scan: scanLazyLockJson },
  { relPath: '.dir-locals.el', match: (p) => endsWithPath(p, '.dir-locals.el'), scan: scanEmacsDirLocals },
  { relPath: '.zed/tasks.json', match: (p) => endsWithPath(p, '.zed/tasks.json'), scan: scanZedTasksJson },
  {
    relPath: 'Directory.Build.props',
    match: (p) =>
      endsWithPath(p, 'directory.build.props') ||
      endsWithPath(p, 'directory.build.targets') ||
      p.endsWith('.csproj') ||
      p.endsWith('.vcxproj'),
    scan: scanMsbuildProject,
  },
  { match: (p) => p.endsWith('.ipynb'), scan: scanJupyterNotebook },
  { match: (p) => endsWithPath(p, 'project.pbxproj'), scan: scanXcodePbxproj },
  {
    relPath: '.pre-commit-config.yaml',
    match: (p) => endsWithPath(p, '.pre-commit-config.yaml') || endsWithPath(p, '.pre-commit-config.yml'),
    scan: scanPreCommitConfig,
  },
  { match: (p) => hasPathSegment(p, '.husky') && !hasPathSegment(p, '.husky/_'), scan: scanHuskyHook },
];

const GLOBAL_MCP_CONFIG_PATHS: string[][] = [
  ['.cursor', 'mcp.json'],
  ['.claude.json'],
  ['.claude', 'settings.json'],
  ['.claude', 'settings.local.json'],
  ['.config', 'Claude', 'claude_desktop_config.json'],
  ['.codeium', 'windsurf', 'mcp_config.json'],
  ['.config', 'devin', 'mcp.json'],
  ['.kiro', 'settings', 'mcp.json'],
  ['.codex', 'config.toml'],
  ['.config', 'opencode', 'opencode.json'],
  ['.copilot', 'mcp-config.json'],
  ['.config', 'zed', 'settings.json'],
  ['.gemini', 'config', 'mcp_config.json'],
  ['.gemini', 'config', 'hooks.json'],
  ['.gemini', 'GEMINI.md'],
  ['.gemini', 'antigravity-cli', 'settings.json'],
  ['.vimrc'],
  ['.config', 'nvim', 'init.vim'],
  ['.config', 'nvim', 'init.lua'],
];

const GLOBAL_SKILLS_DIRS: string[][] = [
  ['.gemini', 'config', 'skills'],
  ['.gemini', 'skills'],
  ['.gemini', 'antigravity-cli', 'skills'],
];

const GLOBAL_PLUGINS_DIRS: string[][] = [
  ['.gemini', 'config', 'plugins'],
  ['.gemini', 'antigravity-cli', 'plugins'],
];

export class HeadlessWorkspaceScanner {
  private readonly mcpPinTracker = new McpStdioPinTracker();

  constructor(private readonly reporter?: ScanReporter) {}

  isWatchedConfigPath(filePath: string): boolean {
    const norm = filePath.replace(/\\/g, '/').toLowerCase();
    return CONFIG_SCANNERS.some((entry) => entry.match(norm));
  }

  scanContent(content: string, filePath: string, baseDir?: string): WorkspaceFinding[] {
    const allowDiskPin = Boolean(baseDir) || (path.isAbsolute(filePath) && pathExistsSafe(filePath));
    return this.scanMatchedContent(content, filePath, baseDir, allowDiskPin);
  }

  scanSingleFile(filePath: string, baseDir?: string): WorkspaceFinding[] {
    const content = readTextSafe(filePath);
    if (content === null) {
      return [];
    }
    return this.scanMatchedContent(content, filePath, baseDir, true);
  }

  private scanGlobalFile(filePath: string): WorkspaceFinding[] {
    const content = readTextSafe(filePath);
    if (content === null) {
      return [];
    }
    return this.scanMatchedContent(content, filePath, undefined, true, true);
  }

  private scanMatchedContent(
    content: string,
    filePath: string,
    baseDir: string | undefined,
    allowDiskPin: boolean,
    isGlobal = false,
  ): WorkspaceFinding[] {
    const norm = filePath.replace(/\\/g, '/').toLowerCase();
    const entry = CONFIG_SCANNERS.find((item) => item.match(norm));
    if (!entry) {
      return [];
    }
    const findings = entry.scan(content, filePath, isGlobal);
    if (entry.pinMcpMode && allowDiskPin) {
      if (entry.pinMcpMode === 'json') {
        findings.push(...this.mcpPinTracker.checkMcpConfig(content, filePath, baseDir));
      } else if (entry.pinMcpMode === 'toml') {
        findings.push(...this.mcpPinTracker.checkTomlMcpServers(content, filePath, baseDir));
      }
    }
    return findings;
  }

  scanDirectory(rootDir: string, options?: ScanDirectoryOptions): WorkspaceFinding[] {
    const excludeGitInternal = Boolean(options?.excludeGitInternal);
    const findings: WorkspaceFinding[] = [];

    for (const entry of CONFIG_SCANNERS) {
      if (!entry.relPath) {
        continue;
      }
      if (excludeGitInternal && (entry.relPath === '.git' || entry.relPath.startsWith('.git/'))) {
        continue;
      }
      findings.push(...this.scanSingleFile(path.join(rootDir, entry.relPath), rootDir));
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
    if (!excludeGitInternal) {
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
    }

    // Bounded recursive walk for nested Stage 2 files (notebooks, MSBuild, Xcode, Vim/Emacs, Husky, pre-commit)
    const SKIP_WALK_DIRS = new Set(['.git', 'node_modules', 'out', 'dist', 'graphify-out', '.vscode-test']);
    const visited = new Set<string>(
      CONFIG_SCANNERS.filter((e) => e.relPath).map((e) => path.resolve(path.join(rootDir, e.relPath!))),
    );
    let matchedFiles = 0;
    const walkNested = (dir: string, depth: number): void => {
      if (depth > 4 || matchedFiles >= 200) {
        return;
      }
      let entries: fs.Dirent[];
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        return;
      }
      for (const entry of entries) {
        if (matchedFiles >= 200) {
          break;
        }
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          if (SKIP_WALK_DIRS.has(entry.name)) {
            continue;
          }
          if (entry.name === '_' && path.basename(dir) === '.husky') {
            continue;
          }
          walkNested(full, depth + 1);
        } else if (entry.isFile()) {
          const lower = entry.name.toLowerCase();
          const inHusky = path.basename(dir) === '.husky';
          if (
            inHusky ||
            lower.endsWith('.ipynb') ||
            lower.endsWith('.csproj') ||
            lower.endsWith('.vcxproj') ||
            lower === 'project.pbxproj' ||
            lower === 'directory.build.props' ||
            lower === 'directory.build.targets' ||
            lower === '.nvimrc' ||
            lower === '.nvim.lua' ||
            lower === '.exrc' ||
            lower === '.pre-commit-config.yml' ||
            lower === '.dir-locals.el' ||
            lower === 'lazy-lock.json'
          ) {
            const normFull = path.resolve(full);
            if (!visited.has(normFull)) {
              visited.add(normFull);
              matchedFiles++;
              findings.push(...this.scanSingleFile(full, rootDir));
            }
          }
        }
      }
    };
    walkNested(rootDir, 0);

    if (options?.skipRuleIds && options.skipRuleIds.length > 0) {
      const skipSet = new Set(options.skipRuleIds);
      return findings.filter((f) => !skipSet.has(f.ruleId));
    }

    return findings;
  }

  scanGlobalConfigs(homeDir = os.homedir()): WorkspaceFinding[] {
    const allFindings: WorkspaceFinding[] = [];

    for (const segments of GLOBAL_MCP_CONFIG_PATHS) {
      const globalMcp = path.join(homeDir, ...segments);
      const mcpFindings = this.scanGlobalFile(globalMcp);
      if (mcpFindings.length > 0) {
        allFindings.push(...mcpFindings);
        this.emitReport(mcpFindings, 'User Global MCP', path.dirname(globalMcp));
      }
    }

    const existingHomePaths = collectExistingRegistryPaths(
      homeDir,
      IDE_AND_AGENT_REGISTRY.flatMap((ideEntry) => ideEntry.homePaths),
    );
    const shadowFindings = detectShadowAiInPaths(existingHomePaths, undefined, homeDir);
    if (shadowFindings.length > 0) {
      allFindings.push(...shadowFindings);
      this.emitReport(shadowFindings, 'User Global MCP', homeDir);
    }

    for (const segments of GLOBAL_SKILLS_DIRS) {
      const globalSkillsDir = path.join(homeDir, ...segments);
      try {
        if (fs.existsSync(globalSkillsDir)) {
          for (const skillEntry of fs.readdirSync(globalSkillsDir)) {
            const skillMd = path.join(globalSkillsDir, skillEntry, 'SKILL.md');
            const content = readTextSafe(skillMd);
            if (content !== null) {
              const skillFindings = scanAgentRulesFile(content, skillMd);
              if (skillFindings.length > 0) {
                allFindings.push(...skillFindings);
                this.emitReport(skillFindings, 'User Global MCP', path.dirname(skillMd));
              }
            }
          }
        }
      } catch {
        // ignore unreadable global skills directories
      }
    }

    for (const segments of GLOBAL_PLUGINS_DIRS) {
      const globalPluginsDir = path.join(homeDir, ...segments);
      try {
        if (fs.existsSync(globalPluginsDir)) {
          for (const pluginEntry of fs.readdirSync(globalPluginsDir)) {
            for (const cfgName of ['hooks.json', 'mcp_config.json']) {
              const cfgPath = path.join(globalPluginsDir, pluginEntry, cfgName);
              const pluginFindings = this.scanSingleFile(cfgPath);
              if (pluginFindings.length > 0) {
                allFindings.push(...pluginFindings);
                this.emitReport(pluginFindings, 'User Global MCP', path.dirname(cfgPath));
              }
            }
          }
        }
      } catch {
        // ignore unreadable global plugins directories
      }
    }

    const transcriptFindings = this.scanAntigravityTranscripts(homeDir);
    if (transcriptFindings.length > 0) {
      allFindings.push(...transcriptFindings);
      this.emitReport(transcriptFindings, 'User Global MCP', path.join(homeDir, '.gemini'));
    }

    const tunnelFindings = scanTunnelPersistence(homeDir);
    if (tunnelFindings.length > 0) {
      allFindings.push(...tunnelFindings);
      this.emitReport(tunnelFindings, 'User Global MCP', homeDir);
    }

    const downloadsFindings = scanDownloadsInstructionFiles(homeDir);
    if (downloadsFindings.length > 0) {
      allFindings.push(...downloadsFindings);
      this.emitReport(downloadsFindings, 'User Global MCP', path.join(homeDir, 'Downloads'));
    }

    const zedVersionFindings = checkInstalledZedVersion(homeDir);
    if (zedVersionFindings.length > 0) {
      allFindings.push(...zedVersionFindings);
      this.emitReport(zedVersionFindings, 'User Global MCP', homeDir);
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

  private emitReport(findings: WorkspaceFinding[], scopeName: string, scopePath: string): void {
    if (findings.length === 0 || !this.reporter?.reportFindings) {
      return;
    }
    try {
      const result = this.reporter.reportFindings(findings, scopeName, scopePath);
      if (result && typeof (result as Promise<void>).catch === 'function') {
        (result as Promise<void>).catch((err: unknown) => {
          const msg = err instanceof Error ? err.message : String(err);
          this.reporter?.warn(`HeadlessWorkspaceScanner: failed to report findings: ${msg}`);
        });
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.reporter?.warn(`HeadlessWorkspaceScanner: failed to report findings: ${msg}`);
    }
  }
}
