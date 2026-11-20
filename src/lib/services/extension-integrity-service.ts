/**
 * Extension Integrity Service - Computes SHA-256 digests of installed extensions'
 * manifest and entrypoint files to detect silent tampering or integrity drift.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import { ExtensionInfo } from '../events/ext-events';
import { IntegrityRuleType, SecurityEvent, SeverityLevel } from '../events/sec-events';
import { ExecEvent } from '../events/process-events';
import { Extension, ExtensionsRepository } from '../extensions';
import { Logger } from '../logger';
import { IDEStatusService } from './ide-status-service';

interface IntegrityRecord {
  sha256: string;
  recordedAt: number;
}

export class ExtensionIntegrityService {
  private static _instance: ExtensionIntegrityService;
  private static readonly STORAGE_KEY = 'ide-shepherd.extensionIntegrity';
  private _context: vscode.ExtensionContext | null = null;
  private _baselines: Record<string, IntegrityRecord> = {};
  private _driftedIds: Set<string> = new Set();

  private constructor() {}

  static getInstance(): ExtensionIntegrityService {
    if (!ExtensionIntegrityService._instance) {
      ExtensionIntegrityService._instance = new ExtensionIntegrityService();
    }
    return ExtensionIntegrityService._instance;
  }

  async initialize(context: vscode.ExtensionContext): Promise<void> {
    this._context = context;
    const saved = context.globalState.get<Record<string, IntegrityRecord>>(ExtensionIntegrityService.STORAGE_KEY);
    if (saved && typeof saved === 'object') {
      this._baselines = { ...saved };
    }
    await this.verifyAllExtensions();
    Logger.info('ExtensionIntegrityService: Initialized');
  }

  computeExtensionDigest(extension: Pick<Extension, 'extensionPath' | 'packageJSON'>): string | null {
    try {
      if (!extension.extensionPath || !fs.existsSync(extension.extensionPath)) {
        return null;
      }
      const hash = crypto.createHash('sha256');
      const pkgPath = path.join(extension.extensionPath, 'package.json');
      if (fs.existsSync(pkgPath)) {
        hash.update(fs.readFileSync(pkgPath));
      }
      const pkgMeta = extension.packageJSON as Record<string, unknown> | undefined;
      const mainRel = pkgMeta?.['main'];
      if (typeof mainRel === 'string' && mainRel.length > 0) {
        const rootDir = path.resolve(extension.extensionPath);
        const mainAbs = path.resolve(rootDir, mainRel);
        const rel = path.relative(rootDir, mainAbs);
        if (rel && !rel.startsWith('..') && !path.isAbsolute(rel) && fs.existsSync(mainAbs)) {
          hash.update(fs.readFileSync(mainAbs));
        }
      }
      return hash.digest('hex');
    } catch {
      return null;
    }
  }

  hasIntegrityDrift(extensionId: string): boolean {
    return this._driftedIds.has(extensionId);
  }

  getBaselineDigest(extensionId: string): string | undefined {
    return this._baselines[extensionId]?.sha256;
  }

  async verifyAllExtensions(): Promise<string[]> {
    const drifted: string[] = [];
    const pendingEvents: SecurityEvent[] = [];
    const extensions = ExtensionsRepository.getInstance().getUserExtensions();
    let dirty = false;

    for (const ext of extensions) {
      const digest = this.computeExtensionDigest(ext);
      if (!digest) {
        continue;
      }

      const existing = this._baselines[ext.id];
      if (!existing) {
        this._baselines[ext.id] = { sha256: digest, recordedAt: Date.now() };
        dirty = true;
      } else if (existing.sha256 !== digest) {
        this._driftedIds.add(ext.id);
        drifted.push(ext.id);
        Logger.warn(`ExtensionIntegrityService: Integrity drift detected for ${ext.id}`);

        const extInfo = new ExtensionInfo(ext.id, ext.isActive, Date.now());
        const ev = new ExecEvent('extension-integrity-check', [ext.extensionPath], undefined, __filename, extInfo);
        const secEvent = new SecurityEvent(ev, extInfo, SeverityLevel.HIGH, IntegrityRuleType.INTEGRITY_DRIFT, [
          {
            finding: `${ext.id} (${digest.slice(0, 12)} != ${existing.sha256.slice(0, 12)})`,
            rule: 'Extension Integrity Drift',
            description: `On-disk files for ${ext.id} changed without a version change`,
            confidence: 0.95,
            severity: SeverityLevel.HIGH,
          },
        ]);
        pendingEvents.push(secEvent);
      }
    }

    await Promise.all(pendingEvents.map((ev) => IDEStatusService.emitSecurityEvent(ev).catch(() => {})));

    if (dirty && this._context) {
      await this._context.globalState.update(ExtensionIntegrityService.STORAGE_KEY, this._baselines);
    }
    return drifted;
  }
}
