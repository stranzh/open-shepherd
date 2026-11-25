/**
 * Revocation Service - Checks installed extensions against revoked extension feeds
 * (VS Marketplace RemovedPackages.md and Open VSX revoked feed) with a 24h cache.
 */

import * as vscode from 'vscode';
import { ExtensionInfo } from '../events/ext-events';
import { ExecEvent } from '../events/process-events';
import { IntegrityRuleType, SecurityEvent, SeverityLevel } from '../events/sec-events';
import { ExtensionsRepository } from '../extensions';
import { Logger } from '../logger';
import { ExtensionChangeListener } from './extension-lifecycle-service';
import { IDEStatusService } from './ide-status-service';

export interface RevocationServiceOptions {
  fetchFn?: typeof fetch;
  nowFn?: () => number;
}

interface RevocationCache {
  fetchedAt: number;
  revokedIds: string[];
}

export class RevocationService implements ExtensionChangeListener {
  private static _instance: RevocationService;
  private static readonly STORAGE_KEY = 'ide-shepherd.revocationCache';
  private static readonly CACHE_TTL_MS = 24 * 60 * 60 * 1000;
  private static readonly VSMARKETPLACE_REMOVED_URL =
    'https://raw.githubusercontent.com/microsoft/vsmarketplace/main/RemovedPackages.md';
  private static readonly OPENVSX_REVOKED_URL = 'https://open-vsx.org/api/-/revoked';

  private _context: vscode.ExtensionContext | null = null;
  private _cache: RevocationCache | null = null;
  private _fetchFn: typeof fetch;
  private _nowFn: () => number;

  constructor(options?: RevocationServiceOptions) {
    this._fetchFn = options?.fetchFn ?? globalThis.fetch;
    this._nowFn = options?.nowFn ?? (() => Date.now());
  }

  static getInstance(): RevocationService {
    if (!RevocationService._instance) {
      RevocationService._instance = new RevocationService();
    }
    return RevocationService._instance;
  }

  async initialize(context: vscode.ExtensionContext): Promise<void> {
    this._context = context;
    const saved = context.globalState.get<RevocationCache>(RevocationService.STORAGE_KEY);
    if (saved && typeof saved === 'object' && Array.isArray(saved.revokedIds)) {
      this._cache = saved;
    }

    await this.checkExtensions();
    Logger.info('RevocationService: Initialized');
  }

  async onExtensionChange(): Promise<void> {
    await this.checkExtensions();
  }

  async checkExtensions(): Promise<void> {
    const revokedIds = await this.getRevokedIds();
    if (revokedIds.size === 0) {
      return;
    }

    const extensions = ExtensionsRepository.getInstance().getUserExtensions();
    for (const ext of extensions) {
      if (revokedIds.has(ext.displayName.toLowerCase())) {
        Logger.warn(`RevocationService: Installed extension ${ext.id} is on the marketplace revocation list.`);

        const extInfo = new ExtensionInfo(ext.id, ext.isActive, this._nowFn());
        const ev = new ExecEvent('extension-revocation-check', [ext.extensionPath], undefined, __filename, extInfo);
        const secEvent = new SecurityEvent(ev, extInfo, SeverityLevel.HIGH, IntegrityRuleType.INTEGRITY_DRIFT, [
          {
            finding: `${ext.displayName} (${ext.id})`,
            rule: 'Revoked Marketplace Extension Installed',
            description: `Installed extension ${ext.displayName} appears on the marketplace revocation list`,
            confidence: 0.99,
            severity: SeverityLevel.HIGH,
          },
        ]);
        await IDEStatusService.emitSecurityEvent(secEvent).catch(() => {});
      }
    }
  }

  private async getRevokedIds(): Promise<Set<string>> {
    if (this._cache && this._nowFn() - this._cache.fetchedAt < RevocationService.CACHE_TTL_MS) {
      return new Set(this._cache.revokedIds);
    }

    const ids = new Set<string>();
    const [vsResult, ovsxResult] = await Promise.allSettled([
      this.fetchVsMarketplaceRevoked(),
      this.fetchOpenVsxRevoked(),
    ]);
    let anySucceeded = false;
    if (vsResult.status === 'fulfilled' && vsResult.value !== null) {
      anySucceeded = true;
      for (const id of vsResult.value) {
        ids.add(id);
      }
    }
    if (ovsxResult.status === 'fulfilled' && ovsxResult.value !== null) {
      anySucceeded = true;
      for (const id of ovsxResult.value) {
        ids.add(id);
      }
    }

    if (anySucceeded) {
      this._cache = { fetchedAt: this._nowFn(), revokedIds: Array.from(ids) };
      if (this._context) {
        await this._context.globalState.update(RevocationService.STORAGE_KEY, this._cache);
      }
    }

    return ids;
  }

  private async fetchVsMarketplaceRevoked(): Promise<string[]> {
    if (!this._fetchFn) {
      return [];
    }
    try {
      const response = await this._fetchFn(RevocationService.VSMARKETPLACE_REMOVED_URL, { method: 'GET' });
      if (!response.ok) {
        return [];
      }
      const text = await response.text();
      const matches = text.match(/\b[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b/g);
      return matches ? matches.map((id) => id.toLowerCase()) : [];
    } catch {
      return [];
    }
  }

  private async fetchOpenVsxRevoked(): Promise<string[]> {
    if (!this._fetchFn) {
      return [];
    }
    try {
      const response = await this._fetchFn(RevocationService.OPENVSX_REVOKED_URL, { method: 'GET' });
      if (!response.ok) {
        return [];
      }
      const data = (await response.json()) as unknown;
      const results: string[] = [];
      const entries = Array.isArray(data)
        ? data
        : Array.isArray((data as { extensions?: unknown[] })?.extensions)
          ? (data as { extensions: unknown[] }).extensions
          : [];

      for (const entry of entries) {
        if (typeof entry === 'string' && entry.includes('.')) {
          results.push(entry.toLowerCase());
        } else if (entry && typeof entry === 'object') {
          const obj = entry as { id?: string; namespace?: string; name?: string };
          if (typeof obj.id === 'string' && obj.id.includes('.')) {
            results.push(obj.id.toLowerCase());
          } else if (typeof obj.namespace === 'string' && typeof obj.name === 'string') {
            results.push(`${obj.namespace}.${obj.name}`.toLowerCase());
          }
        }
      }
      return results;
    } catch {
      return [];
    }
  }
}
