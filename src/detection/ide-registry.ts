/**
 * AI IDE & Agent Registry and Shadow AI Detection
 *
 * Maintains workspace and user-home footprint definitions for AI IDEs, forks,
 * and coding agents, and flags unapproved or high-risk shadow AI environments.
 */

import * as path from 'path';
import { SeverityLevel } from '../lib/events/sec-events';
import { WorkspaceFinding, WorkspaceRuleType } from './workspace-rule-types';

export interface IdeAgentEntry {
  id: string;
  name: string;
  workspacePaths: string[];
  homePaths: string[];
  notes?: string;
}

export const IDE_AND_AGENT_REGISTRY: IdeAgentEntry[] = [
  {
    id: 'vscode',
    name: 'Visual Studio Code',
    workspacePaths: [
      '.vscode',
      '.vscode/settings.json',
      '.vscode/tasks.json',
      '.vscode/launch.json',
      '.vscode/mcp.json',
    ],
    homePaths: ['~/.vscode', '~/.config/Code/User/settings.json'],
  },
  {
    id: 'vscodium',
    name: 'VSCodium',
    workspacePaths: [],
    homePaths: ['~/.vscode-oss', '~/.config/VSCodium', '~/.config/VSCodium/User/settings.json'],
  },
  {
    id: 'cursor',
    name: 'Cursor',
    workspacePaths: ['.cursor', '.cursor/mcp.json', '.cursor/cli.json', '.cursor/rules', '.cursorrules'],
    homePaths: ['~/.cursor', '~/.cursor/mcp.json'],
  },
  {
    id: 'windsurf',
    name: 'Windsurf',
    workspacePaths: ['.windsurfrules', '.windsurf'],
    homePaths: ['~/.codeium/windsurf', '~/.codeium/windsurf/mcp_config.json'],
  },
  {
    id: 'antigravity',
    name: 'Antigravity',
    workspacePaths: [
      '.agents',
      '.agent',
      '.agents/mcp_config.json',
      '.agents/hooks.json',
      '.antigravity-plugin/mcp_config.json',
    ],
    homePaths: [
      '~/.gemini/antigravity',
      '~/.gemini/antigravity-cli',
      '~/.gemini/antigravity-ide',
      '~/.gemini/config/mcp_config.json',
    ],
  },
  {
    id: 'claude-code',
    name: 'Claude Code',
    workspacePaths: ['.claude', '.claude/settings.json', '.claude/settings.local.json', '.mcp.json', 'CLAUDE.md'],
    homePaths: [
      '~/.claude',
      '~/.claude.json',
      '~/.claude/settings.json',
      '~/.claude/settings.local.json',
      '~/.config/Claude/claude_desktop_config.json',
    ],
  },
  {
    id: 'codex',
    name: 'OpenAI Codex CLI',
    workspacePaths: ['.codex', '.codex/config.toml'],
    homePaths: ['~/.codex', '~/.codex/config.toml', '~/.codex/auth.json'],
  },
  {
    id: 'opencode',
    name: 'OpenCode',
    workspacePaths: ['opencode.json', '.opencode', '.opencode/config.json'],
    homePaths: ['~/.config/opencode', '~/.config/opencode/opencode.json'],
  },
  {
    id: 'copilot-cli',
    name: 'GitHub Copilot CLI',
    workspacePaths: [],
    homePaths: ['~/.copilot', '~/.copilot/mcp-config.json', '~/.copilot/hosts.json'],
  },
  {
    id: 'zed',
    name: 'Zed',
    workspacePaths: ['.zed', '.zed/settings.json', '.zed/tasks.json'],
    homePaths: ['~/.config/zed', '~/.config/zed/settings.json'],
  },
  {
    id: 'devin',
    name: 'Devin',
    workspacePaths: [],
    homePaths: ['~/.config/devin', '~/.config/devin/mcp.json', '~/.config/devin/skills'],
  },
  {
    id: 'kiro',
    name: 'Kiro',
    workspacePaths: ['.kiro', '.kiro/settings/mcp.json', '.kiro/steering'],
    homePaths: ['~/.kiro', '~/.kiro/settings/mcp.json'],
  },
  {
    id: 'trae',
    name: 'Trae',
    workspacePaths: ['.trae', '.trae/rules'],
    homePaths: ['~/.trae'],
    notes: 'ByteDance AI IDE with non-disableable telemetry risk',
  },
  { id: 'qoder', name: 'Qoder', workspacePaths: ['.qoder'], homePaths: ['~/.qoder'] },
];

export const DEFAULT_APPROVED_FORKS: string[] = [
  'vscode',
  'vscodium',
  'cursor',
  'windsurf',
  'antigravity',
  'zed',
  'claude-code',
  'codex',
  'opencode',
  'copilot-cli',
];

export function getApprovedForks(override?: string[]): string[] {
  if (override !== undefined) {
    return override.map((s) => s.trim().toLowerCase()).filter((s) => s.length > 0);
  }
  const envRaw = process.env.OPEN_SHEPHERD_ALLOWED_FORKS;
  if (envRaw !== undefined) {
    return envRaw
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter((s) => s.length > 0);
  }
  return [...DEFAULT_APPROVED_FORKS];
}

function normalizePosixPath(rawPath: string): string {
  return rawPath.replace(/\\/g, '/').replace(/\/+$/, '');
}

function toRootRelative(rawPath: string, baseDir?: string): string | null {
  const norm = normalizePosixPath(rawPath);
  if (!norm) {
    return null;
  }
  if (baseDir) {
    const resolvedBase = path.resolve(baseDir);
    const resolvedTarget = path.isAbsolute(rawPath) ? path.resolve(rawPath) : path.resolve(resolvedBase, rawPath);
    const rel = path.relative(resolvedBase, resolvedTarget).replace(/\\/g, '/');
    if (!rel || rel === '..' || rel.startsWith('../') || path.isAbsolute(rel)) {
      return null;
    }
    return rel;
  }
  return norm;
}

function matchesPattern(candidatePath: string, rawPattern: string, hasBaseDir: boolean): boolean {
  const lowerPath = candidatePath.toLowerCase();
  const cleanPattern = rawPattern.replace(/^~\//, '').replace(/^\.\//, '').replace(/\/+$/, '').toLowerCase();
  if (!cleanPattern) {
    return false;
  }
  if (hasBaseDir) {
    return lowerPath === cleanPattern || lowerPath.startsWith(`${cleanPattern}/`);
  }
  if (lowerPath.startsWith('~/')) {
    const fromHome = lowerPath.slice(2);
    return fromHome === cleanPattern || fromHome.startsWith(`${cleanPattern}/`);
  }
  if (!lowerPath.startsWith('/') && !/^[a-z]:\//i.test(lowerPath)) {
    return lowerPath === cleanPattern || lowerPath.startsWith(`${cleanPattern}/`);
  }
  if (lowerPath.endsWith(`/${cleanPattern}`)) {
    return true;
  }
  const marker = `/${cleanPattern}/`;
  const idx = lowerPath.lastIndexOf(marker);
  if (idx !== -1) {
    const after = lowerPath.slice(idx + marker.length);
    return after.length > 0 && !after.includes('/');
  }
  return false;
}

export function detectShadowAiInPaths(
  existingPaths: string[],
  allowedForks?: string[],
  baseDir?: string,
): WorkspaceFinding[] {
  const approved = new Set(getApprovedForks(allowedForks));
  const findings: WorkspaceFinding[] = [];
  const hasBaseDir = Boolean(baseDir);

  const normalizedInputs = existingPaths
    .map((raw) => ({ raw, matchTarget: toRootRelative(raw, baseDir) }))
    .filter((item): item is { raw: string; matchTarget: string } => Boolean(item.matchTarget));

  for (const entry of IDE_AND_AGENT_REGISTRY) {
    if (approved.has(entry.id)) {
      continue;
    }
    const allPatterns = [...entry.workspacePaths, ...entry.homePaths];
    const matched = normalizedInputs.find((item) =>
      allPatterns.some((pattern) => matchesPattern(item.matchTarget, pattern, hasBaseDir)),
    );
    if (!matched) {
      continue;
    }

    const isTrae = entry.id === 'trae';
    findings.push({
      ruleId: 'shadow_ai_ide_detected',
      ruleName: isTrae
        ? 'Shadow AI IDE Detected (Trae High-Risk Telemetry)'
        : 'Unapproved Shadow AI IDE / Agent Detected',
      type: WorkspaceRuleType.AGENT_RULES,
      severity: isTrae ? SeverityLevel.HIGH : SeverityLevel.MEDIUM,
      filePath: matched.raw,
      finding: `${entry.id}: ${matched.raw}`,
      description: isTrae
        ? `Detected unapproved Trae IDE/agent path (${matched.raw}); ByteDance Trae carries non-disableable telemetry risk`
        : `Detected unapproved AI IDE/agent "${entry.name}" (${entry.id}) at ${matched.raw}`,
      confidence: 0.9,
    });
  }

  return findings;
}
