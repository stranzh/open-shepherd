import { SeverityLevel } from '../lib/events/sec-events';
import { Target } from '../lib/events/ext-events';
import type { ProcessRule, ProcessRuleType } from './process-rules';

/**
 * Additional process rules for IDE remote tunnel LOLRMM execution.
 */
export const EXTRA_PROCESS_RULES: ProcessRule[] = [
  {
    id: 'ide_remote_tunnel_execution',
    name: 'IDE Remote Tunnel Execution',
    description: 'Detected IDE CLI remote tunnel service installation or execution (LOLRMM)',
    type: 'COMMAND' as ProcessRuleType,
    target: Target.PROCESS,
    severity: SeverityLevel.HIGH,
    commandPattern:
      /\b(?:code(?:-insiders)?|codium|cursor|windsurf|(?:code|cursor)-tunnel)(?:\.exe)?\b[^\n]*\btunnel\b[^\n]*(?:\bservice\s+install\b|\binternal-run\b|--accept-server-license-terms\b)/i,
    confidence: 0.95,
  },
];
