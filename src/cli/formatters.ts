/**
 * Headless output formatters for workspace security findings (JSONL, SARIF, OCSF, CEF).
 *
 * Intentionally free of VS Code dependencies so CLI tooling runs in plain Node.js.
 */

import { randomUUID } from 'crypto';
import * as path from 'path';
import { WorkspaceFinding } from '../detection/workspace-rule-types';
import { SeverityLevel } from '../lib/events/sec-events';

export type CliExportFormat = 'jsonl' | 'sarif' | 'ocsf' | 'cef';

const DEFAULT_CLI_VERSION = '1.0.0';
const SARIF_SCHEMA = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json';

function sarifLevel(severity: SeverityLevel): 'error' | 'warning' | 'note' {
  switch (severity) {
    case SeverityLevel.HIGH:
      return 'error';
    case SeverityLevel.MEDIUM:
      return 'warning';
    default:
      return 'note';
  }
}

function ocsfSeverityId(severity: SeverityLevel): number {
  switch (severity) {
    case SeverityLevel.HIGH:
      return 4;
    case SeverityLevel.MEDIUM:
      return 3;
    case SeverityLevel.LOW:
      return 2;
    default:
      return 1;
  }
}

function cefSeverity(severity: SeverityLevel): number {
  switch (severity) {
    case SeverityLevel.HIGH:
      return 8;
    case SeverityLevel.MEDIUM:
      return 5;
    default:
      return 3;
  }
}

function escapeCefHeader(val: string): string {
  return val
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|')
    .replace(/[\r\n]+/g, ' ');
}

function escapeCefExtension(val: string): string {
  return val
    .replace(/\\/g, '\\\\')
    .replace(/=/g, '\\=')
    .replace(/[\r\n]+/g, ' ');
}

function normalizeDriveLetter(posixPath: string): string {
  return posixPath.replace(/^([a-zA-Z]):/, (_, drive: string) => `${drive.toLowerCase()}:`);
}

function isContainedRelativePath(rel: string): boolean {
  return Boolean(
    rel && rel !== '..' && !rel.startsWith('../') && !path.posix.isAbsolute(rel) && !/^[a-zA-Z]:\//.test(rel),
  );
}

function normalizeArtifactUri(filePath: string, target?: string): string {
  const posixFile = filePath.replace(/\\/g, '/');
  if (target) {
    const posixTarget = target.replace(/\\/g, '/');
    const isWinAbsFile = /^[a-zA-Z]:\//.test(posixFile);
    const isWinAbsTarget = /^[a-zA-Z]:\//.test(posixTarget);

    if (isWinAbsFile && isWinAbsTarget) {
      const normTarget = path.posix.normalize(normalizeDriveLetter(posixTarget)).replace(/\/+$/, '');
      const normFile = path.posix.normalize(normalizeDriveLetter(posixFile));
      const rel = path.posix.relative(normTarget, normFile);
      if (isContainedRelativePath(rel)) {
        return rel.replace(/^\.\//, '');
      }
    } else if (path.isAbsolute(filePath)) {
      const resolvedTarget = path.resolve(target);
      const resolvedFile = path.resolve(filePath);
      const rel = path.relative(resolvedTarget, resolvedFile).replace(/\\/g, '/');
      if (isContainedRelativePath(rel)) {
        return rel.replace(/^\.\//, '');
      }
    }
  }
  return posixFile.replace(/^\.\//, '');
}

export function formatWorkspaceFindings(
  findings: WorkspaceFinding[],
  format: CliExportFormat,
  metadata?: { version?: string; target?: string },
): string {
  const version = metadata?.version || DEFAULT_CLI_VERSION;

  switch (format) {
    case 'jsonl':
      return findings
        .map((f) =>
          JSON.stringify({
            ruleId: f.ruleId,
            ruleName: f.ruleName,
            type: f.type,
            severity: f.severity,
            filePath: f.filePath,
            finding: f.finding,
            description: f.description,
            confidence: f.confidence,
          }),
        )
        .join('\n');

    case 'sarif': {
      const rulesMap = new Map<string, { id: string; name: string; shortDescription: { text: string } }>();
      const results = findings.map((f) => {
        if (!rulesMap.has(f.ruleId)) {
          rulesMap.set(f.ruleId, { id: f.ruleId, name: f.ruleName, shortDescription: { text: f.description } });
        }
        return {
          ruleId: f.ruleId,
          level: sarifLevel(f.severity),
          message: { text: `${f.description} (${f.finding})` },
          locations: [
            { physicalLocation: { artifactLocation: { uri: normalizeArtifactUri(f.filePath, metadata?.target) } } },
          ],
        };
      });

      const sarifDoc = {
        $schema: SARIF_SCHEMA,
        version: '2.1.0',
        runs: [{ tool: { driver: { name: 'Open Shepherd', version, rules: Array.from(rulesMap.values()) } }, results }],
      };
      return JSON.stringify(sarifDoc, null, 2);
    }

    case 'ocsf':
      return findings
        .map((f) =>
          JSON.stringify({
            activity_id: 1,
            category_uid: 2,
            class_uid: 2004,
            type_uid: 200401,
            severity_id: ocsfSeverityId(f.severity),
            status_id: 1,
            time: Date.now(),
            metadata: { version: '1.6.0', product: { name: 'Open Shepherd', vendor_name: 'Open Shepherd' } },
            finding_info: { uid: randomUUID(), title: `Security Detection: ${f.ruleName}`, desc: f.description },
            resources: { uid: f.filePath, role_id: 3 },
            observables: [{ name: f.ruleName, type_id: 45, value: f.finding }],
            isAlert: true,
          }),
        )
        .join('\n');

    case 'cef':
      return findings
        .map((f) =>
          [
            'CEF:0',
            'OpenShepherd',
            'OpenShepherd-CLI',
            escapeCefHeader(version),
            escapeCefHeader(f.ruleId),
            escapeCefHeader(f.ruleName),
            String(cefSeverity(f.severity)),
            `filePath=${escapeCefExtension(f.filePath)} msg=${escapeCefExtension(f.description)} cs1=${escapeCefExtension(f.finding)} cs1Label=Finding cat=${escapeCefExtension(f.type)}`,
          ].join('|'),
        )
        .join('\n');
  }
}
