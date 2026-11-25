import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { SeverityLevel } from '../lib/events/sec-events';
import { WorkspaceFinding, WorkspaceRuleType } from '../detection/workspace-rule-types';

const WIN_RUN_TUNNEL_RE =
  /\b(?:code(?:-insiders)?|codium|cursor|windsurf|(?:code|cursor)-tunnel)(?:\.exe)?\b[^\n]*\btunnel\b/i;
const IDE_TUNNEL_NAME_RE = /(?:code|cursor|codium|windsurf|visualstudio).*tunnel/i;
const IDE_TUNNEL_CONTENT_RE =
  /\b(?:code(?:-insiders)?|codium|cursor|windsurf|(?:code|cursor)-tunnel)(?:\.exe)?\b[^\n]*\btunnel\b|devtunnels\.ms|tunnels\.api\.visualstudio\.com/i;

function isIdeTunnelFile(filePath: string): boolean {
  if (IDE_TUNNEL_NAME_RE.test(path.basename(filePath))) {
    return true;
  }
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    return IDE_TUNNEL_CONTENT_RE.test(content);
  } catch {
    return false;
  }
}

function makeTunnelFinding(filePath: string, finding: string, description: string): WorkspaceFinding {
  return {
    ruleId: 'ide_tunnel_persistence_detected',
    ruleName: 'IDE Tunnel Persistence Detected',
    type: WorkspaceRuleType.AGENT_RULES,
    severity: SeverityLevel.HIGH,
    filePath,
    finding,
    description,
    confidence: 0.95,
  };
}

function findMatchingFiles(dirPath: string, matcher: (name: string) => boolean): string[] {
  if (!fs.existsSync(dirPath)) {
    return [];
  }
  try {
    const entries = fs.readdirSync(dirPath, { withFileTypes: true });
    return entries
      .filter((entry) => entry.isFile() && matcher(entry.name))
      .map((entry) => path.join(dirPath, entry.name));
  } catch {
    return [];
  }
}

/**
 * Scan user home directory and optional Windows Run registry entries for persistent IDE remote tunnel artifacts.
 */
export function scanTunnelPersistence(
  homeDir = os.homedir(),
  options?: { winRunEntries?: Record<string, string> },
): WorkspaceFinding[] {
  const findings: WorkspaceFinding[] = [];

  const systemdDir = path.join(homeDir, '.config', 'systemd', 'user');
  for (const filePath of findMatchingFiles(
    systemdDir,
    (name) => name.toLowerCase().includes('tunnel') && name.toLowerCase().endsWith('.service'),
  )) {
    if (!isIdeTunnelFile(filePath)) {
      continue;
    }
    findings.push(
      makeTunnelFinding(
        filePath,
        `Systemd user tunnel service: ${path.basename(filePath)}`,
        'Persistent systemd user service for an IDE remote tunnel was detected.',
      ),
    );
  }

  const launchAgentsDir = path.join(homeDir, 'Library', 'LaunchAgents');
  for (const filePath of findMatchingFiles(
    launchAgentsDir,
    (name) => name.toLowerCase().includes('tunnel') && name.toLowerCase().endsWith('.plist'),
  )) {
    if (!isIdeTunnelFile(filePath)) {
      continue;
    }
    findings.push(
      makeTunnelFinding(
        filePath,
        `macOS LaunchAgent tunnel plist: ${path.basename(filePath)}`,
        'Persistent macOS LaunchAgent plist for an IDE remote tunnel was detected.',
      ),
    );
  }

  const fixedArtifacts: Array<{ relPath: string; label: string }> = [
    { relPath: path.join('.vscode-cli', 'code_tunnel.json'), label: 'VS Code CLI tunnel state file' },
    { relPath: path.join('.vscode-cli', 'tunnel-service.log'), label: 'VS Code CLI tunnel service log' },
    { relPath: path.join('.cursor-cli', 'code_tunnel.json'), label: 'Cursor CLI tunnel state file' },
    { relPath: path.join('.cursor-cli', 'tunnel-service.log'), label: 'Cursor CLI tunnel service log' },
  ];

  for (const artifact of fixedArtifacts) {
    const fullPath = path.join(homeDir, artifact.relPath);
    if (fs.existsSync(fullPath)) {
      findings.push(
        makeTunnelFinding(
          fullPath,
          `${artifact.label}: ${artifact.relPath}`,
          'IDE remote tunnel CLI state or service log artifact was detected.',
        ),
      );
    }
  }

  if (options?.winRunEntries) {
    for (const [entryName, command] of Object.entries(options.winRunEntries)) {
      if (WIN_RUN_TUNNEL_RE.test(command)) {
        findings.push(
          makeTunnelFinding(
            `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\${entryName}`,
            `Windows Run entry "${entryName}": ${command}`,
            'Persistent Windows Run registry entry for an IDE remote tunnel was detected.',
          ),
        );
      }
    }
  }

  return findings;
}
