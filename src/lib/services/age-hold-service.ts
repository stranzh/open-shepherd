/**
 * Age-Hold Service - Monitors newly published/updated extensions within a 48-hour
 * age-hold window and emits advisory warnings without disabling or uninstalling.
 */

import * as vscode from 'vscode';
import { ExtensionInfo } from '../events/ext-events';
import { ExecEvent } from '../events/process-events';
import { IntegrityRuleType, SecurityEvent, SeverityLevel } from '../events/sec-events';
import { Extension, ExtensionsRepository } from '../extensions';
import { Logger } from '../logger';
import { emitEvent } from '../transport';
import { ExtensionChangeListener } from './extension-lifecycle-service';
import { IDEStatusService } from './ide-status-service';

export interface AgeHoldServiceOptions {
  fetchFn?: typeof fetch;
  nowFn?: () => number;
}

export class AgeHoldService implements ExtensionChangeListener {
  private static _instance: AgeHoldService;
  private static readonly STORAGE_KEY = 'ide-shepherd.ageHoldCache';
  private static readonly AGE_HOLD_MS = 48 * 60 * 60 * 1000;
  private static readonly MARKETPLACE_QUERY_URL =
    'https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery';

  private _context: vscode.ExtensionContext | null = null;
  private _cache: Record<string, number> = {};
  private _alertedKeys = new Set<string>();
  private _fetchFn: typeof fetch;
  private _nowFn: () => number;

  constructor(options?: AgeHoldServiceOptions) {
    this._fetchFn = options?.fetchFn ?? globalThis.fetch;
    this._nowFn = options?.nowFn ?? (() => Date.now());
  }

  static getInstance(): AgeHoldService {
    if (!AgeHoldService._instance) {
      AgeHoldService._instance = new AgeHoldService();
    }
    return AgeHoldService._instance;
  }

  async initialize(context: vscode.ExtensionContext): Promise<void> {
    this._context = context;
    const saved = context.globalState.get<Record<string, number>>(AgeHoldService.STORAGE_KEY);
    if (saved && typeof saved === 'object') {
      this._cache = { ...saved };
    }

    const autoUpdate = vscode.workspace.getConfiguration('extensions').get('autoUpdate');
    if (autoUpdate === true || autoUpdate === 'onlyEnabledExtensions') {
      Logger.warn(
        'AgeHoldService: extensions.autoUpdate is enabled; automatic updates may bypass 48-hour age-hold review.',
      );
    }

    await this.checkExtensions();
    Logger.info('AgeHoldService: Initialized');
  }

  async onExtensionChange(): Promise<void> {
    await this.checkExtensions();
  }

  async checkExtensions(): Promise<void> {
    const extensions = ExtensionsRepository.getInstance().getUserExtensions();
    let dirty = false;

    for (const ext of extensions) {
      const version = ext.packageJSON?.version ?? 'unknown';
      const cacheKey = `${ext.id}@${version}`;
      let lastUpdatedMs = this._cache[cacheKey];
      if (typeof lastUpdatedMs !== 'number' || Number.isNaN(lastUpdatedMs)) {
        const fetched = await this.fetchLastUpdatedMs(ext);
        if (fetched === null) {
          continue;
        }
        lastUpdatedMs = fetched;
        this._cache[cacheKey] = lastUpdatedMs;
        dirty = true;
      }

      const ageMs = this._nowFn() - lastUpdatedMs;
      if (ageMs < AgeHoldService.AGE_HOLD_MS && !this._alertedKeys.has(cacheKey)) {
        this._alertedKeys.add(cacheKey);
        Logger.warn(
          `AgeHoldService: Extension ${ext.id} was updated within the 48-hour age-hold window (ageMs=${ageMs}).`,
        );

        const extInfo = new ExtensionInfo(ext.id, ext.isActive, this._nowFn());
        const ev = new ExecEvent('extension-age-hold-check', [ext.extensionPath], undefined, __filename, extInfo);
        const secEvent = new SecurityEvent(ev, extInfo, SeverityLevel.MEDIUM, IntegrityRuleType.INTEGRITY_DRIFT, [
          {
            finding: `${ext.id} (age ${Math.max(0, Math.round(ageMs / (60 * 60 * 1000)))}h < 48h)`,
            rule: 'Extension Age-Hold Violation',
            description: `Extension ${ext.id} was published or updated less than 48 hours ago`,
            confidence: 0.9,
            severity: SeverityLevel.MEDIUM,
          },
        ]);
        await IDEStatusService.emitSecurityEvent(secEvent).catch(() => {});

        emitEvent({
          source: 'vscode',
          event_type: 'extension_age_hold_violation',
          severity: 'warn',
          details: { extensionId: ext.id, displayName: ext.displayName, lastUpdatedMs, ageMs },
        });
      }
    }

    if (dirty && this._context) {
      await this._context.globalState.update(AgeHoldService.STORAGE_KEY, this._cache);
    }
  }

  private async fetchLastUpdatedMs(ext: Extension): Promise<number | null> {
    if (!this._fetchFn) {
      return null;
    }

    const [publisher, name] = this.extractPublisherAndName(ext);
    if (!publisher || !name) {
      return null;
    }

    const version = ext.packageJSON?.version;
    const marketplaceMs = await this.queryMarketplace(`${publisher}.${name}`, version);
    if (marketplaceMs !== null) {
      return marketplaceMs;
    }

    if (version) {
      return this.queryOpenVsx(publisher, name, version);
    }

    return null;
  }

  private extractPublisherAndName(ext: Extension): [string | undefined, string | undefined] {
    if (ext.displayName && ext.displayName.includes('.')) {
      const dotIdx = ext.displayName.indexOf('.');
      return [ext.displayName.slice(0, dotIdx), ext.displayName.slice(dotIdx + 1)];
    }
    return [ext.packageJSON?.publisher, ext.packageJSON?.name];
  }

  private async queryMarketplace(extensionId: string, version?: string): Promise<number | null> {
    try {
      const response = await this._fetchFn(AgeHoldService.MARKETPLACE_QUERY_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json;api-version=3.0-preview.1' },
        body: JSON.stringify({ filters: [{ criteria: [{ filterType: 7, value: extensionId }] }], flags: 0x1 | 0x2 }),
      });
      if (!response.ok) {
        return null;
      }
      const data = (await response.json()) as {
        results?: Array<{
          extensions?: Array<{ lastUpdated?: string; versions?: Array<{ version?: string; lastUpdated?: string }> }>;
        }>;
      };
      const extEntry = data?.results?.[0]?.extensions?.[0];
      const matchedVer = version ? extEntry?.versions?.find((v) => v.version === version) : undefined;
      const rawDate = matchedVer?.lastUpdated ?? extEntry?.versions?.[0]?.lastUpdated ?? extEntry?.lastUpdated;
      if (!rawDate) {
        return null;
      }
      const parsed = Date.parse(rawDate);
      return Number.isNaN(parsed) ? null : parsed;
    } catch {
      return null;
    }
  }

  private async queryOpenVsx(publisher: string, name: string, version: string): Promise<number | null> {
    try {
      const url = `https://open-vsx.org/api/${encodeURIComponent(publisher)}/${encodeURIComponent(name)}/${encodeURIComponent(version)}`;
      const response = await this._fetchFn(url, { method: 'GET' });
      if (!response.ok) {
        return null;
      }
      const data = (await response.json()) as { timestamp?: string; lastUpdated?: string };
      const rawDate = data?.lastUpdated ?? data?.timestamp;
      if (!rawDate) {
        return null;
      }
      const parsed = Date.parse(rawDate);
      return Number.isNaN(parsed) ? null : parsed;
    } catch {
      return null;
    }
  }
}
