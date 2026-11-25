import { SeverityLevel } from '../lib/events/sec-events';
import { WorkspaceFinding, WorkspaceRuleType, isPlainObject } from './workspace-rule-types';

const JUPYTER_BANG_NETWORK_RE = /(?:^|\n)\s*!(?:curl|wget)\b/i;
const JUPYTER_SHELL_MAGIC_RE = /(?:^|\n)\s*%%(?:bash|sh)\b/i;
const JUPYTER_SHELL_PAYLOAD_RE = /\b(?:curl|wget|base64\s+-d|nc\s)/i;
const JUPYTER_HIDDEN_EXEC_RE = /\b(?:os\.system|subprocess|__import__)\b|\b(?:eval|exec)\s*\(/;
const JUPYTER_DESERIALIZE_RE = /\b(?:pickle|cPickle|_pickle|joblib|dill|cloudpickle)\.loads?\s*\(/;

const XCODE_SHELL_SCRIPT_RE = /shellScript\s*=\s*"((?:[^"\\]|\\.)*)"/g;
const XCODE_SUSPICIOUS_SCRIPT_RE = /(?:\b(?:curl|wget)\b|\|\s*(?:sh|bash)\b|\bbase64\s+-[dD]\b|\bnc\s+-e\b)/i;

const MSBUILD_EXEC_TASK_RE = /<Exec\b[^>]*\bCommand\s*=\s*(?:"([^"]*)"|'([^']*)')/gi;
const MSBUILD_PREBUILD_CMD_RE =
  /<(?:Pre|Post)BuildEvent\b[^>]*>(?:(?!(?:Pre|Post)BuildEvent)[\s\S])*?<Command>([\s\S]*?)<\/Command>|<(?:Pre|Post)BuildEvent\b[^>]*>([^<]+)<\/(?:Pre|Post)BuildEvent>/gi;
const MSBUILD_SUSPICIOUS_CMD_RE =
  /(?:powershell\b[^"'\n]*(?:-enc|-encodedcommand|\bbypass\b)|\b(?:curl|wget|iwr|Invoke-WebRequest|mshta|rundll32)\b)/i;
const MSBUILD_INLINE_TASK_RE =
  /<UsingTask\b[^>]*\bTaskFactory\s*=\s*(?:"(?:CodeTaskFactory|RoslynCodeTaskFactory)"|'(?:CodeTaskFactory|RoslynCodeTaskFactory)')/gi;

function joinCellSource(source: unknown): string {
  if (typeof source === 'string') {
    return source;
  }
  if (Array.isArray(source)) {
    return source.filter((line): line is string => typeof line === 'string').join('');
  }
  return '';
}

function isHiddenJupyterCell(metadata: unknown): boolean {
  if (!isPlainObject(metadata)) {
    return false;
  }
  if (metadata.collapsed === true) {
    return true;
  }
  if (isPlainObject(metadata.jupyter) && metadata.jupyter.source_hidden === true) {
    return true;
  }
  return false;
}

export function scanJupyterNotebook(content: string, filePath: string): WorkspaceFinding[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return [];
  }

  if (!isPlainObject(parsed) || !Array.isArray(parsed.cells)) {
    return [];
  }

  const findings: WorkspaceFinding[] = [];
  for (let i = 0; i < parsed.cells.length; i++) {
    const cell = parsed.cells[i];
    if (!isPlainObject(cell) || cell.cell_type !== 'code') {
      continue;
    }

    const source = joinCellSource(cell.source);
    if (!source) {
      continue;
    }

    const hasShellMagic =
      JUPYTER_BANG_NETWORK_RE.test(source) ||
      (JUPYTER_SHELL_MAGIC_RE.test(source) && JUPYTER_SHELL_PAYLOAD_RE.test(source));
    if (hasShellMagic) {
      findings.push({
        ruleId: 'jupyter_shell_magic_exec',
        ruleName: 'Jupyter: Suspicious Shell Magic Execution',
        type: WorkspaceRuleType.PACKAGE_MANIFEST,
        severity: SeverityLevel.HIGH,
        filePath,
        finding: `Cell ${i}: suspicious shell magic command`,
        description: 'Jupyter notebook cell executes network or encoded shell commands via ! or %%bash/%%sh magic',
        confidence: 0.9,
      });
    }

    if (isHiddenJupyterCell(cell.metadata) && JUPYTER_HIDDEN_EXEC_RE.test(source)) {
      findings.push({
        ruleId: 'jupyter_hidden_cell_exec',
        ruleName: 'Jupyter: Hidden Cell Code Execution',
        type: WorkspaceRuleType.PACKAGE_MANIFEST,
        severity: SeverityLevel.HIGH,
        filePath,
        finding: `Cell ${i}: hidden cell contains dynamic or OS execution`,
        description:
          'Hidden or collapsed Jupyter notebook cell contains os.system, subprocess, eval, exec, or __import__',
        confidence: 0.9,
      });
    }

    if (JUPYTER_DESERIALIZE_RE.test(source)) {
      findings.push({
        ruleId: 'jupyter_unsafe_deserialization',
        ruleName: 'Jupyter: Unsafe Deserialization',
        type: WorkspaceRuleType.PACKAGE_MANIFEST,
        severity: SeverityLevel.MEDIUM,
        filePath,
        finding: `Cell ${i}: unsafe deserialization call`,
        description: 'Jupyter notebook cell deserializes untrusted data with pickle, joblib, dill, or cloudpickle',
        confidence: 0.85,
      });
    }
  }

  return findings;
}

export function scanXcodePbxproj(content: string, filePath: string): WorkspaceFinding[] {
  if (!content.includes('PBXShellScriptBuildPhase')) {
    return [];
  }

  const findings: WorkspaceFinding[] = [];
  XCODE_SHELL_SCRIPT_RE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = XCODE_SHELL_SCRIPT_RE.exec(content)) !== null) {
    const unescaped = match[1].replace(/\\n/g, '\n').replace(/\\"/g, '"');
    if (XCODE_SUSPICIOUS_SCRIPT_RE.test(unescaped)) {
      findings.push({
        ruleId: 'xcode_build_phase_suspicious_script',
        ruleName: 'Xcode: Suspicious Build Phase Shell Script',
        type: WorkspaceRuleType.PACKAGE_MANIFEST,
        severity: SeverityLevel.HIGH,
        filePath,
        finding: unescaped.slice(0, 120),
        description:
          'Xcode PBXShellScriptBuildPhase contains suspicious download, pipe-to-shell, or reverse-shell command',
        confidence: 0.9,
      });
    }
  }

  return findings;
}

export function scanMsbuildProject(content: string, filePath: string): WorkspaceFinding[] {
  const findings: WorkspaceFinding[] = [];

  MSBUILD_EXEC_TASK_RE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = MSBUILD_EXEC_TASK_RE.exec(content)) !== null) {
    const command = match[1] ?? match[2] ?? '';
    if (MSBUILD_SUSPICIOUS_CMD_RE.test(command)) {
      findings.push({
        ruleId: 'msbuild_suspicious_exec_task',
        ruleName: 'MSBuild: Suspicious Exec Task',
        type: WorkspaceRuleType.PACKAGE_MANIFEST,
        severity: SeverityLevel.HIGH,
        filePath,
        finding: command.slice(0, 120),
        description: 'MSBuild Exec task runs suspicious PowerShell, download, or living-off-the-land binary',
        confidence: 0.9,
      });
    }
  }

  MSBUILD_PREBUILD_CMD_RE.lastIndex = 0;
  while ((match = MSBUILD_PREBUILD_CMD_RE.exec(content)) !== null) {
    const command = match[1] ?? match[2] ?? '';
    if (MSBUILD_SUSPICIOUS_CMD_RE.test(command)) {
      findings.push({
        ruleId: 'msbuild_suspicious_exec_task',
        ruleName: 'MSBuild: Suspicious PreBuildEvent Command',
        type: WorkspaceRuleType.PACKAGE_MANIFEST,
        severity: SeverityLevel.HIGH,
        filePath,
        finding: command.trim().slice(0, 120),
        description: 'MSBuild PreBuildEvent runs suspicious PowerShell, download, or living-off-the-land binary',
        confidence: 0.9,
      });
    }
  }

  MSBUILD_INLINE_TASK_RE.lastIndex = 0;
  while ((match = MSBUILD_INLINE_TASK_RE.exec(content)) !== null) {
    findings.push({
      ruleId: 'msbuild_inline_code_task',
      ruleName: 'MSBuild: Inline Code Task',
      type: WorkspaceRuleType.PACKAGE_MANIFEST,
      severity: SeverityLevel.HIGH,
      filePath,
      finding: match[0].slice(0, 120),
      description: 'MSBuild UsingTask uses CodeTaskFactory or RoslynCodeTaskFactory to compile and execute inline code',
      confidence: 0.9,
    });
  }

  return findings;
}
