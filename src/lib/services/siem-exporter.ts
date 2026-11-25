/**
 * SIEM Exporter - Exports recorded SecurityEvents to JSONL, CEF, OCSF, or SARIF 2.1.0.
 */

import { SecurityEvent, SeverityLevel } from '../events/sec-events';
import { buildDetectionFinding } from './datadog/ocsf-builder';

export type ExportFormat = 'jsonl' | 'cef' | 'ocsf' | 'sarif';

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

function escapeCef(val: string): string {
  const escaped = val.replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
  return escaped.replace(/=/g, '\\=').replace(/[\r\n]+/g, ' ');
}

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

export function exportSecurityEvents(events: SecurityEvent[], format: ExportFormat): string {
  switch (format) {
    case 'jsonl': {
      const lines = events.map((ev) => {
        const ioc = ev.getPrimaryIoC();
        return JSON.stringify({
          id: ev.secEventId,
          timestamp: new Date(ev.timestamp).toISOString(),
          severity: ev.severity,
          type: ev.securityEventType,
          target: ev.originalEvent.eventType,
          actor: ev.callerExtension?.id || ev.extension?.id || ev.workspace?.path || 'unknown',
          rule: ioc.rule,
          finding: ioc.finding,
          description: ioc.description,
        });
      });
      return lines.join('\n');
    }

    case 'cef': {
      const lines = events.map((ev) => {
        const ioc = ev.getPrimaryIoC();
        const actor = ev.callerExtension?.id || ev.extension?.id || ev.workspace?.path || 'unknown';
        return [
          'CEF:0',
          'OpenShepherd',
          'IDE-Shepherd',
          '3.2.0',
          escapeCef(String(ev.securityEventType)),
          escapeCef(ioc.rule),
          String(cefSeverity(ev.severity)),
          `src=${escapeCef(actor)} msg=${escapeCef(ioc.description)} cs1=${escapeCef(ioc.finding)} cs1Label=Finding`,
        ].join('|');
      });
      return lines.join('\n');
    }

    case 'ocsf':
      return events.map((ev) => JSON.stringify(buildDetectionFinding(ev))).join('\n');

    case 'sarif': {
      const rulesMap = new Map<string, { id: string; name: string; shortDescription: { text: string } }>();
      const results = events.map((ev) => {
        const ioc = ev.getPrimaryIoC();
        const ruleId = ioc.rule.toLowerCase().replace(/[^a-z0-9]+/g, '-');
        if (!rulesMap.has(ruleId)) {
          rulesMap.set(ruleId, { id: ruleId, name: ioc.rule, shortDescription: { text: ioc.description } });
        }
        const uri = ev.workspace?.path || ev.extension?.id || 'ide://runtime';
        return {
          ruleId,
          level: sarifLevel(ev.severity),
          message: { text: `${ioc.description} (${ioc.finding})` },
          locations: [{ physicalLocation: { artifactLocation: { uri } } }],
        };
      });

      const rules = Array.from(rulesMap.values());
      const driver = { name: 'Open Shepherd', version: '3.2.0', rules };
      const sarifDoc = {
        $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        version: '2.1.0',
        runs: [{ tool: { driver }, results }],
      };
      return JSON.stringify(sarifDoc, null, 2);
    }
  }
}
