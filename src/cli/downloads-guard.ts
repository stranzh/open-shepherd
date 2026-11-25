import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { WorkspaceFinding, WorkspaceRuleType } from '../detection/workspace-rule-types';
import { SeverityLevel } from '../lib/events/sec-events';

const DOWNLOADS_INSTRUCTION_FILES = [
  'AGENTS.md',
  'AGENTS.override.md',
  'CLAUDE.md',
  'GEMINI.md',
  '.cursorrules',
  '.windsurfrules',
  '.mcp.json',
  'mcp.json',
];

/**
 * Scans ~/Downloads for AI agent instruction or MCP config files that could
 * hijack agent sessions launched from the Downloads directory.
 */
export function scanDownloadsInstructionFiles(homeDir: string = os.homedir()): WorkspaceFinding[] {
  const downloadsDir = path.join(homeDir, 'Downloads');
  if (!fs.existsSync(downloadsDir)) {
    return [];
  }

  const findings: WorkspaceFinding[] = [];
  for (const fileName of DOWNLOADS_INSTRUCTION_FILES) {
    const filePath = path.join(downloadsDir, fileName);
    if (!fs.existsSync(filePath)) {
      continue;
    }

    findings.push({
      ruleId: 'downloads_dir_agent_instructions',
      ruleName: 'Agent Instructions in Downloads Directory',
      type: WorkspaceRuleType.AGENT_RULES,
      severity: SeverityLevel.HIGH,
      filePath,
      finding: `Agent instruction/config file '${fileName}' found in Downloads directory`,
      description:
        'AI agent instruction or MCP configuration files in ~/Downloads can be automatically loaded if an agent is launched there, enabling prompt injection or tool hijacking. Remove the file or isolate sessions in a project subdirectory.',
      confidence: 0.95,
    });
  }

  return findings;
}
