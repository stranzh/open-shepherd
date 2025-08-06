import { SeverityLevel } from '../lib/events/sec-events';
import { Target } from '../lib/events/ext-events';
import type { NetworkRule, NetworkRuleType } from './network-rules';

/**
 * Additional network rules for IDE remote tunnel endpoints.
 */
export const EXTRA_NETWORK_RULES: NetworkRule[] = [
  {
    id: 'ide_devtunnel_endpoint',
    name: 'IDE DevTunnel Endpoint',
    description: 'Detected connection to Microsoft Dev Tunnels / VS Code Remote Tunnel infrastructure',
    type: 'URL' as NetworkRuleType,
    target: Target.NETWORK,
    severity: SeverityLevel.HIGH,
    pattern: /(?:^|\/\/|[.])(?:tunnels\.api\.visualstudio\.com|devtunnels\.ms)(?:[:/?#]|$)/i,
    confidence: 0.95,
  },
];
