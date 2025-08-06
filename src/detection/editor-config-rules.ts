/**
 * Editor Configuration Security Rules (Roadmap 2.1, 2.2, 2.6)
 *
 * Scanners for Vim/Neovim config & lazy-lock.json, Emacs .dir-locals.el,
 * and Zed tasks.json & version checks.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { SeverityLevel } from '../lib/events/sec-events';
import { TASK_RULES } from './task-rules';
import { isPlainObject, stripJsonComments, WorkspaceFinding, WorkspaceRuleType } from './workspace-rule-types';

const VIM_EXRC_SET_RE = /^\s*:?(?:set|se)\s+.*\bexrc!?/i;
const VIM_EXRC_LUA_RE = /\bvim\.(?:o|opt)\.exrc\s*=\s*true\b/;
const VIM_NOEXRC_RE = /^\s*:?(?:set|se)\s+.*\bnoexrc\b(?!.*\bexrc\b)/i;

const VIM_LOCAL_EXEC_RE =
  /(?:^|\s):!|\bsystem\s*\(|\bjobstart\s*\(|\bio\.popen\s*\(|\bos\.execute\s*\(|\bvim\.fn\.system\b|\bvim\.system\b|\bautocmd\b|\bnvim_create_autocmd\b/i;

const HEX_40_RE = /^[0-9a-f]{40}$/i;

const EMACS_EXEC_RE = /\(\s*eval\b|\bshell-command\b|\bstart-process\b|\bcall-process\b/i;
const EMACS_COMPILE_CMD_RE = /\(\s*compile-command\s*\.\s*"([^"]+)"/gi;
const EMACS_SUSPICIOUS_CMD_RE =
  /(?:\b(?:curl|wget)\b|\|\s*(?:sh|bash)\b|\bnc\s+-e\b|\bbase64\s+-d\b|powershell.*-enc|\brm\s+-rf\b|;\s*(?:sh|bash)\b)/i;

function isVimCommentLine(line: string, isLua: boolean): boolean {
  const trimmed = line.trim();
  if (!trimmed) {
    return true;
  }
  return isLua ? trimmed.startsWith('--') : trimmed.startsWith('"');
}

/**
 * Scan Vim/Neovim configuration files for unsafe `exrc` or local rc execution.
 */
export function scanVimConfig(content: string, filePath: string, isGlobal = false): WorkspaceFinding[] {
  const findings: WorkspaceFinding[] = [];
  const effectiveIsGlobal = isGlobal;
  const isLua = /\.lua$/i.test(filePath);

  if (effectiveIsGlobal) {
    const lines = content.split(/\r?\n/);
    for (const line of lines) {
      if (isVimCommentLine(line, isLua)) {
        continue;
      }
      if (VIM_NOEXRC_RE.test(line)) {
        continue;
      }
      if (VIM_EXRC_SET_RE.test(line) || VIM_EXRC_LUA_RE.test(line)) {
        findings.push({
          ruleId: 'vim_exrc_enabled',
          ruleName: 'Vim/Neovim: exrc Enabled in Global Config',
          type: WorkspaceRuleType.AGENT_RULES,
          severity: SeverityLevel.HIGH,
          filePath,
          finding: line.trim(),
          description:
            'Global Vim/Neovim config enables exrc, allowing repository-local .exrc/.nvim.lua files to execute automatically.',
          confidence: 0.95,
        });
        break;
      }
    }
    return findings;
  }

  const trimmedContent = content.trim();
  if (!trimmedContent) {
    return findings;
  }

  const lines = content.split(/\r?\n/);
  for (const line of lines) {
    if (isVimCommentLine(line, isLua)) {
      continue;
    }
    if (VIM_LOCAL_EXEC_RE.test(line)) {
      findings.push({
        ruleId: 'vim_local_rc_execution',
        ruleName: 'Vim/Neovim: Command Execution in Repo-Local Config',
        type: WorkspaceRuleType.AGENT_RULES,
        severity: SeverityLevel.HIGH,
        filePath,
        finding: line.trim(),
        description: 'Repository-local Vim/Neovim config contains shell or autocmd execution primitives.',
        confidence: 0.9,
      });
      return findings;
    }
  }

  findings.push({
    ruleId: 'vim_local_rc_present',
    ruleName: 'Vim/Neovim: Repo-Local Config Present',
    type: WorkspaceRuleType.AGENT_RULES,
    severity: SeverityLevel.MEDIUM,
    filePath,
    finding: filePath,
    description: 'Repository contains a local Vim/Neovim config file that may execute if exrc is enabled.',
    confidence: 0.85,
  });

  return findings;
}

/**
 * Scan Neovim `lazy-lock.json` for plugins without a pinned 40-char hex commit SHA.
 */
export function scanLazyLockJson(content: string, filePath: string): WorkspaceFinding[] {
  const findings: WorkspaceFinding[] = [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return findings;
  }

  if (!isPlainObject(parsed)) {
    return findings;
  }

  for (const [plugin, meta] of Object.entries(parsed)) {
    if (!isPlainObject(meta)) {
      continue;
    }
    const commit = typeof meta.commit === 'string' ? meta.commit.trim() : '';
    if (!HEX_40_RE.test(commit)) {
      findings.push({
        ruleId: 'nvim_lazy_lock_unpinned',
        ruleName: 'Neovim: Unpinned Plugin in lazy-lock.json',
        type: WorkspaceRuleType.PACKAGE_MANIFEST,
        severity: SeverityLevel.MEDIUM,
        filePath,
        finding: plugin,
        description: `Plugin "${plugin}" in lazy-lock.json is missing a pinned 40-character hex commit SHA.`,
        confidence: 0.95,
      });
    }
  }

  return findings;
}

/**
 * Scan Emacs `.dir-locals.el` for dangerous eval forms or shell/process execution.
 */
export function scanEmacsDirLocals(content: string, filePath: string): WorkspaceFinding[] {
  const findings: WorkspaceFinding[] = [];
  const trimmed = content.trim();
  if (!trimmed) {
    return findings;
  }

  const nonCommentContent = content
    .split(/\r?\n/)
    .filter((line) => !line.trim().startsWith(';'))
    .join('\n');

  const execMatch = EMACS_EXEC_RE.exec(nonCommentContent);
  if (execMatch) {
    findings.push({
      ruleId: 'emacs_dir_locals_exec',
      ruleName: 'Emacs: Dangerous Execution in .dir-locals.el',
      type: WorkspaceRuleType.AGENT_RULES,
      severity: SeverityLevel.HIGH,
      filePath,
      finding: execMatch[0],
      description:
        'Emacs .dir-locals.el contains eval or process-execution forms that can run arbitrary commands when opening files.',
      confidence: 0.9,
    });
    return findings;
  }

  for (const compileMatch of nonCommentContent.matchAll(EMACS_COMPILE_CMD_RE)) {
    if (EMACS_SUSPICIOUS_CMD_RE.test(compileMatch[1])) {
      findings.push({
        ruleId: 'emacs_dir_locals_exec',
        ruleName: 'Emacs: Suspicious compile-command in .dir-locals.el',
        type: WorkspaceRuleType.AGENT_RULES,
        severity: SeverityLevel.HIGH,
        filePath,
        finding: compileMatch[1],
        description: 'Emacs .dir-locals.el sets compile-command to a suspicious shell command.',
        confidence: 0.85,
      });
    }
  }

  return findings;
}

/**
 * Scan Zed `.zed/tasks.json` against `TASK_RULES`.
 */
export function scanZedTasksJson(content: string, filePath: string): WorkspaceFinding[] {
  const findings: WorkspaceFinding[] = [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(stripJsonComments(content));
  } catch {
    return findings;
  }

  if (!Array.isArray(parsed)) {
    return findings;
  }

  for (const entry of parsed) {
    if (!isPlainObject(entry)) {
      continue;
    }
    const command = typeof entry.command === 'string' ? entry.command : '';
    const args = Array.isArray(entry.args)
      ? entry.args.filter((a): a is string => typeof a === 'string').join(' ')
      : '';
    const fullCommand = `${command} ${args}`.trim();
    if (!fullCommand) {
      continue;
    }

    const label = typeof entry.label === 'string' && entry.label ? entry.label : fullCommand;

    for (const rule of TASK_RULES) {
      if (rule.commandPattern.test(fullCommand)) {
        findings.push({
          ruleId: `zed_task_${rule.id}`,
          ruleName: `Zed ${rule.name}`,
          type: WorkspaceRuleType.VSCODE_CONFIG,
          severity: rule.severity,
          filePath,
          finding: `${label}: ${fullCommand}`,
          description: rule.description,
          confidence: rule.confidence,
        });
      }
    }
  }

  return findings;
}

/**
 * Return true if the Zed editor version is vulnerable (< 0.165.4).
 */
export function isVulnerableZedVersion(version: string): boolean {
  const match = /^\s*v?(\d+)\.(\d+)\.(\d+)/.exec(version);
  if (!match) {
    return false;
  }
  const major = Number(match[1]);
  const minor = Number(match[2]);
  const patch = Number(match[3]);

  if (major !== 0) {
    return false;
  }
  if (minor !== 165) {
    return minor < 165;
  }
  return patch < 4;
}

/**
 * Check installed Zed version against pre-IDEsaster (< 0.165.4) baseline.
 */
export function checkInstalledZedVersion(
  homeDir = os.homedir(),
  options?: { versionString?: string; plistPaths?: string[] },
): WorkspaceFinding[] {
  let version = options?.versionString?.trim() || process.env.OPEN_SHEPHERD_ZED_VERSION?.trim() || '';
  let sourcePath = 'zed-version';

  if (!version) {
    const plistCandidates = options?.plistPaths ?? [
      path.join(homeDir, 'Applications', 'Zed.app', 'Contents', 'Info.plist'),
      '/Applications/Zed.app/Contents/Info.plist',
    ];
    for (const plistPath of plistCandidates) {
      try {
        if (fs.existsSync(plistPath)) {
          const plist = fs.readFileSync(plistPath, 'utf8');
          const m = /<key>CFBundleShortVersionString<\/key>\s*<string>([^<]+)<\/string>/i.exec(plist);
          if (m && m[1].trim()) {
            version = m[1].trim();
            sourcePath = plistPath;
            break;
          }
        }
      } catch {
        // ignore unreadable plist
      }
    }
  }

  if (!version) {
    const versionTxt = path.join(homeDir, '.config', 'zed', 'version.txt');
    try {
      if (fs.existsSync(versionTxt)) {
        version = fs.readFileSync(versionTxt, 'utf8').trim();
        sourcePath = versionTxt;
      }
    } catch {
      // ignore unreadable version.txt
    }
  }

  if (!version || !isVulnerableZedVersion(version)) {
    return [];
  }

  return [
    {
      ruleId: 'zed_vulnerable_idesaster_version',
      ruleName: 'Zed: Vulnerable Pre-IDEsaster Version (< 0.165.4)',
      type: WorkspaceRuleType.VSCODE_CONFIG,
      severity: SeverityLevel.HIGH,
      filePath: sourcePath,
      finding: `Zed ${version}`,
      description: `Installed Zed version ${version} is below 0.165.4 and vulnerable to IDEsaster prompt/command execution.`,
      confidence: 0.95,
    },
  ];
}
