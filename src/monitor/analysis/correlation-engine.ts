/**
 * Cross-Domain Behavioral Kill-Chain Correlation Engine
 *
 * Correlates sensitive local reads (credential files, clipboard, env secrets)
 * with subsequent outbound network requests or subprocess spawns from the same extension.
 */

import { CONFIG } from '../../lib/config';

export type SensitiveAccessKind = 'fs_sensitive_read' | 'clipboard_read' | 'env_secret_access';

interface AccessRecord {
  kind: SensitiveAccessKind;
  detail: string;
  timestamp: number;
}

interface TokenStoreReadRecord {
  storeFamily: string;
  filePath: string;
  timestamp: number;
}

export interface CorrelationMatch {
  rule: string;
  description: string;
  sourceAccess: AccessRecord;
}

const LOOPBACK_URL_RE = /^https?:\/\/(?:localhost|127\.0\.0\.1|\[::1\])(?:[:/]|$)/i;
const SHELL_OR_EXFIL_CMD_RE = /\b(?:sh|bash|zsh|cmd|powershell|pwsh|python|python3|node|curl|wget|nc|ssh|scp)\b/i;

export class CorrelationEngine {
  private static _instance: CorrelationEngine;
  private _recentAccesses: Map<string, AccessRecord[]> = new Map();
  private _tokenStoreReads: Map<string, TokenStoreReadRecord[]> = new Map();
  private _windowMs = CONFIG.POLICY.CORRELATION_WINDOW_MS;

  private constructor() {}

  static getInstance(): CorrelationEngine {
    if (!CorrelationEngine._instance) {
      CorrelationEngine._instance = new CorrelationEngine();
    }
    return CorrelationEngine._instance;
  }

  setWindowMs(windowMs: number): void {
    this._windowMs = windowMs;
  }

  clear(): void {
    this._recentAccesses.clear();
    this._tokenStoreReads.clear();
  }

  recordSensitiveAccess(extensionId: string, kind: SensitiveAccessKind, detail: string, now = Date.now()): void {
    if (!extensionId || extensionId === 'unknown' || extensionId === 'caller:unknown') {
      return;
    }
    const entries = this.prune(extensionId, now);
    entries.push({ kind, detail, timestamp: now });
    if (entries.length > 50) {
      entries.shift();
    }
    this._recentAccesses.set(extensionId, entries);
  }

  correlateOutboundAction(
    extensionId: string,
    outboundKind: 'network' | 'process',
    target: string,
    now = Date.now(),
  ): CorrelationMatch | null {
    if (!extensionId || extensionId === 'unknown' || extensionId === 'caller:unknown') {
      return null;
    }
    if (outboundKind === 'network' && LOOPBACK_URL_RE.test(target)) {
      return null;
    }
    if (outboundKind === 'process' && !SHELL_OR_EXFIL_CMD_RE.test(target)) {
      return null;
    }

    const entries = this.prune(extensionId, now);
    if (entries.length === 0) {
      return null;
    }

    const latest = entries[entries.length - 1];
    return {
      rule: 'Kill-Chain Exfiltration Correlation',
      description: `Extension accessed sensitive source (${latest.kind}: ${latest.detail}) before ${outboundKind} action (${target})`,
      sourceAccess: latest,
    };
  }

  recordIdeTokenStoreRead(
    extensionId: string,
    storeFamily: string,
    filePath: string,
    now = Date.now(),
  ): CorrelationMatch | null {
    if (!extensionId || extensionId === 'unknown' || extensionId === 'caller:unknown') {
      return null;
    }
    const cutoff = now - this._windowMs;
    const entries = (this._tokenStoreReads.get(extensionId) ?? []).filter((e) => e.timestamp >= cutoff);
    entries.push({ storeFamily, filePath, timestamp: now });
    if (entries.length > 50) {
      entries.shift();
    }
    this._tokenStoreReads.set(extensionId, entries);

    const families = Array.from(new Set(entries.map((e) => e.storeFamily)));
    if (families.length < 2) {
      return null;
    }

    return {
      rule: 'H207 Multi-Store AI/IDE Session Theft',
      description: `Extension accessed multiple AI/IDE token stores within ${Math.round(this._windowMs / 1000)}s: ${families.join(', ')}`,
      sourceAccess: { kind: 'fs_sensitive_read', detail: filePath, timestamp: now },
    };
  }

  private prune(extensionId: string, now: number): AccessRecord[] {
    const cutoff = now - this._windowMs;
    const current = (this._recentAccesses.get(extensionId) ?? []).filter((e) => e.timestamp >= cutoff);
    if (current.length === 0) {
      this._recentAccesses.delete(extensionId);
    } else {
      this._recentAccesses.set(extensionId, current);
    }
    return current;
  }
}
