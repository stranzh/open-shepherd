/**
 * Repository hook and pre-commit configuration detection rules (Roadmap 2.7).
 */

import { SeverityLevel } from '../lib/events/sec-events';
import { TASK_RULES } from './task-rules';
import { WorkspaceFinding, WorkspaceRuleType } from './workspace-rule-types';

const HUSKY_SUSPICIOUS_RE = /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sh|bash)\b|\bbase64\s+-d\b|\bnc\s+-e\b/i;
const PRE_COMMIT_LOCAL_SUSPICIOUS_RE = /(?:\b(?:curl|wget)\b|\bbase64\s+-d\b|\b(?:sh|bash)\s+-c\b)/i;
const MUTABLE_REVS = new Set(['head', 'main', 'master', 'develop', 'latest']);
const UNTRUSTED_REPO_URL_RE =
  /^(?:http:\/\/|https?:\/\/(?:\d{1,3}\.){3}\d{1,3}(?:[:/]|$)|https?:\/\/\[[0-9a-fA-F:]+\])/i;

function stripYamlScalar(raw: string): string {
  const trimmed = raw.trim();
  if ((trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
    return trimmed.slice(1, -1).trim();
  }
  return trimmed.replace(/\s+#.*$/, '').trim();
}

/**
 * Scan a Husky hook script (e.g. `.husky/pre-commit`) for suspicious commands.
 */
export function scanHuskyHook(content: string, filePath: string): WorkspaceFinding[] {
  const findings: WorkspaceFinding[] = [];
  const lines = content.split(/\r?\n/);

  for (let idx = 0; idx < lines.length; idx++) {
    const trimmed = lines[idx].trim();
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }

    const matchedTaskRule = TASK_RULES.find((rule) => rule.commandPattern.test(trimmed));
    const matchedHookPattern = HUSKY_SUSPICIOUS_RE.test(trimmed);

    if (matchedTaskRule || matchedHookPattern) {
      findings.push({
        ruleId: 'husky_suspicious_hook',
        ruleName: 'Git Hook: Suspicious Husky Hook Command',
        type: WorkspaceRuleType.GIT_CONFIG,
        severity: SeverityLevel.HIGH,
        filePath,
        finding: `Line ${idx + 1}: ${trimmed}`,
        description: matchedTaskRule
          ? `Husky hook contains suspicious command matching ${matchedTaskRule.id}.`
          : 'Husky hook contains suspicious remote execution or obfuscated command.',
        confidence: 0.9,
      });
    }
  }

  return findings;
}

/**
 * Scan `.pre-commit-config.yaml` / `.pre-commit-config.yml` for suspicious local entries,
 * mutable external revisions, or untrusted repository URLs.
 */
interface PreCommitRepoBlock {
  repo?: string;
  rev?: string;
  entries: string[];
}

export function scanPreCommitConfig(content: string, filePath: string): WorkspaceFinding[] {
  const findings: WorkspaceFinding[] = [];
  const lines = content.split(/\r?\n/);

  const blocks: PreCommitRepoBlock[] = [];
  let currentBlock: PreCommitRepoBlock | null = null;
  let inReposSection = false;
  let repoItemIndent = -1;
  let inBlockScalar = false;
  let blockScalarIndent = -1;
  let blockScalarLines: string[] = [];

  const flushBlockScalar = (): void => {
    if (inBlockScalar && currentBlock && blockScalarLines.length > 0) {
      currentBlock.entries.push(blockScalarLines.join('\n').trim());
    }
    inBlockScalar = false;
    blockScalarIndent = -1;
    blockScalarLines = [];
  };

  for (let idx = 0; idx < lines.length; idx++) {
    const rawLine = lines[idx];
    const trimmed = rawLine.trim();
    const indent = rawLine.search(/\S/);

    if (inBlockScalar) {
      if (!trimmed) {
        blockScalarLines.push('');
        continue;
      }
      if (indent > blockScalarIndent) {
        blockScalarLines.push(trimmed);
        continue;
      }
      flushBlockScalar();
    }

    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }

    if (/^repos\s*:/.test(trimmed)) {
      inReposSection = true;
      continue;
    }

    if (!inReposSection) {
      continue;
    }

    const isListDash = trimmed.startsWith('- ');
    if (isListDash && (repoItemIndent === -1 || indent <= repoItemIndent)) {
      const afterDash = trimmed.slice(2).trim();
      if (/^(?:repo|rev)\s*:/.test(afterDash)) {
        repoItemIndent = indent;
        currentBlock = { entries: [] };
        blocks.push(currentBlock);
      }
    }

    if (!currentBlock) {
      continue;
    }

    const repoMatch = trimmed.match(/^-?\s*repo\s*:\s*(.+)$/);
    if (repoMatch) {
      currentBlock.repo = stripYamlScalar(repoMatch[1]);
      continue;
    }

    const revMatch = trimmed.match(/^-?\s*rev\s*:\s*(.+)$/);
    if (revMatch) {
      currentBlock.rev = stripYamlScalar(revMatch[1]);
      continue;
    }

    const entryMatch = trimmed.match(/^-?\s*entry\s*:\s*(.*)$/);
    if (entryMatch) {
      const rawVal = entryMatch[1].trim();
      if (rawVal === '|' || rawVal === '>' || rawVal === '|-' || rawVal === '>-') {
        inBlockScalar = true;
        blockScalarIndent = indent;
        blockScalarLines = [];
      } else if (rawVal) {
        currentBlock.entries.push(stripYamlScalar(rawVal));
      }
    }
  }
  flushBlockScalar();

  for (const block of blocks) {
    const repo = block.repo;
    if (repo && repo !== 'local' && repo !== 'meta') {
      if (UNTRUSTED_REPO_URL_RE.test(repo)) {
        findings.push({
          ruleId: 'pre_commit_untrusted_repo_url',
          ruleName: 'Pre-commit: Untrusted Repository URL',
          type: WorkspaceRuleType.GIT_CONFIG,
          severity: SeverityLevel.HIGH,
          filePath,
          finding: `repo: ${repo}`,
          description: 'Pre-commit external repository uses unencrypted HTTP or a raw IP host.',
          confidence: 0.95,
        });
      }
      if (block.rev && MUTABLE_REVS.has(block.rev.toLowerCase())) {
        findings.push({
          ruleId: 'pre_commit_unpinned_rev',
          ruleName: 'Pre-commit: Unpinned Mutable Revision',
          type: WorkspaceRuleType.GIT_CONFIG,
          severity: SeverityLevel.MEDIUM,
          filePath,
          finding: `repo: ${repo} @ rev: ${block.rev}`,
          description:
            'External pre-commit repository uses a mutable branch/HEAD revision instead of a pinned tag or commit SHA.',
          confidence: 0.9,
        });
      }
    }

    for (const entry of block.entries) {
      const matchedTaskRule = TASK_RULES.find((rule) => rule.commandPattern.test(entry));
      if (matchedTaskRule || PRE_COMMIT_LOCAL_SUSPICIOUS_RE.test(entry)) {
        findings.push({
          ruleId: 'pre_commit_suspicious_local_entry',
          ruleName: 'Pre-commit: Suspicious Local Hook Entry',
          type: WorkspaceRuleType.GIT_CONFIG,
          severity: SeverityLevel.HIGH,
          filePath,
          finding: `entry: ${entry}`,
          description: 'Pre-commit hook entry executes a suspicious or remote command.',
          confidence: 0.9,
        });
      }
    }
  }

  return findings;
}
