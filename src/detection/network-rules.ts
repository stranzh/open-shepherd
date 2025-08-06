/**
 * Network Rules - Rule definitions for network traffic analysis
 */

import { SeverityLevel } from '../lib/events/sec-events';
import { Target } from '../lib/events/ext-events';
import { EXTRA_NETWORK_RULES } from './network-rules-extra';

export enum NetworkRuleType {
  URL = 'URL',
  IP = 'IP',
  DNS = 'DNS',
}

export interface NetworkRule {
  id: string;
  name: string;
  description: string;
  type: NetworkRuleType;
  target: Target;
  severity: SeverityLevel;
  pattern: RegExp;
  confidence: number;
}

/**
 * Network rules for traffic analysis
 */
export const NETWORK_RULES: NetworkRule[] = [
  // Cloud Metadata & SSRF Rules
  {
    id: 'cloud_metadata_ssrf',
    name: 'Cloud Metadata SSRF',
    description: 'Request to cloud instance metadata service endpoint',
    type: NetworkRuleType.URL,
    target: Target.NETWORK,
    severity: SeverityLevel.HIGH,
    pattern:
      /(?:^|\/\/(?:[^/@]+@)?)(?:\[::ffff:)?(?:169\.254\.169\.254|169\.254\.170\.2|100\.100\.100\.200|metadata\.google\.internal|metadata\.goog|\[?fd00:ec2::254\]?)\]?\.?(?:[:/?#]|$)/i,
    confidence: 1,
  },

  // Suspicious Domain Rules
  {
    id: 'suspicious_domains',
    name: 'Suspicious Domains',
    description: 'Request to known suspicious domain',
    type: NetworkRuleType.URL,
    target: Target.NETWORK,
    severity: SeverityLevel.HIGH,
    pattern:
      /(bit\.ly|workers\.dev|appdomain\.cloud|ngrok\.io|termbin\.com|localhost\.run|webhook\.(site|cool)|oastify\.com|burpcollaborator\.(me|net)|trycloudflare\.com|oast\.(pro|live|site|online|fun|me)|ply\.gg|pipedream\.net|dnslog\.cn|webhook-test\.com|typedwebhook\.tools|beeceptor\.com|ngrok-free\.(app|dev)|interact\.sh)/,
    confidence: 1,
  },

  // Exfiltration Domain Rules
  {
    id: 'exfiltration_domains',
    name: 'Exfiltration Domains',
    description: 'Request to potential data exfiltration service',
    type: NetworkRuleType.URL,
    target: Target.NETWORK,
    severity: SeverityLevel.HIGH,
    pattern:
      /(discord\.com|transfer\.sh|filetransfer\.io|sendspace\.com|backblazeb2\.com|paste\.ee|pastebin\.com|hastebin\.com|ghostbin\.site|api\.telegram\.org|rentry\.co)/,
    confidence: 1,
  },

  // Malware Download Domain Rules
  {
    id: 'malware_download_domains',
    name: 'Malware Download Domains',
    description: 'Request to known malware distribution domain',
    type: NetworkRuleType.URL,
    target: Target.NETWORK,
    severity: SeverityLevel.HIGH,
    pattern: /(files\.catbox\.moe|notif\.su|solidity\.bot|git-service\.com|m-kosche\.com)/,
    confidence: 1,
  },

  // Intelligence Domain Rules
  {
    id: 'intel_domains',
    name: 'Intel Domains',
    description: 'Request to IP intelligence service',
    type: NetworkRuleType.URL,
    target: Target.NETWORK,
    severity: SeverityLevel.MEDIUM,
    pattern: /.{0,50}(ipinfo\.io|checkip\.dyndns\.org|ip\.me|jsonip\.com|ipify\.org|ifconfig\.me)/,
    confidence: 1,
  },

  // External IP Rules
  {
    id: 'external_ip',
    name: 'Unknown External IP',
    description: 'Request to external IP address',
    type: NetworkRuleType.IP,
    target: Target.NETWORK,
    severity: SeverityLevel.MEDIUM,
    pattern: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
    confidence: 1,
  },
  ...EXTRA_NETWORK_RULES,
];

// Helper patterns for IP filtering
// Excludes:
// - Local IPv4: 127.x.x.x, 10.x.x.x, 192.168.x.x, 172.16-31.x.x, 169.254.x.x (link-local; metadata IP 169.254.169.254 is caught above)
// - Public DNS used in tests: 1.1.1.1 (Cloudflare), 8.8.8.8 (Google)
// - Localhost
export const EXCLUDED_IP_PATTERN =
  /(127\.|10\.)\d{1,3}\.\d{1,3}\.\d{1,3}|(192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|169\.254\.)\d{1,3}\.\d{1,3}|1\.1\.1\.1|8\.8\.8\.8/;

// Wildcard IP (0.0.0.0) and localhost
export const WILDCARD_IP_PATTERN = /0\.0\.0\.0/;
export const LOCALHOST_PATTERN = /localhost/i;

function shannonEntropy(input: string): number {
  if (!input.length) {
    return 0;
  }
  const freq = new Map<string, number>();
  for (const ch of input) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / input.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function isSuspiciousDnsQuery(hostname: string): string | null {
  if (!hostname || typeof hostname !== 'string') {
    return null;
  }
  const clean = hostname.trim().toLowerCase().replace(/\.$/, '');
  const labels = clean.split('.').filter(Boolean);
  if (labels.length < 2) {
    return null;
  }
  const maxLabelLen = Math.max(...labels.map((l) => l.length));
  if (maxLabelLen >= 50) {
    return `Excessively long DNS label (${maxLabelLen} chars) in ${clean}`;
  }
  if (labels.length >= 6 && clean.length >= 64) {
    const sub = labels.slice(0, -2).join('');
    if (shannonEntropy(sub) >= 3.6) {
      return `High-entropy multi-label DNS query (${labels.length} labels) in ${clean}`;
    }
  }
  return null;
}

export function getRuleById(id: string): NetworkRule | undefined {
  return NETWORK_RULES.find((rule) => rule.id === id);
}

export function getRulesByType(type: NetworkRuleType): NetworkRule[] {
  return NETWORK_RULES.filter((rule) => rule.type === type);
}

export function getRulesBySeverity(severity: SeverityLevel): NetworkRule[] {
  return NETWORK_RULES.filter((rule) => rule.severity === severity);
}

export function getAllRules(): NetworkRule[] {
  return [...NETWORK_RULES];
}
