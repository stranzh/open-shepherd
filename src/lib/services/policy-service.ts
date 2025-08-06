/**
 * Policy Service - Evaluates enforcement mode (strict | balanced | audit-only)
 */

import * as vscode from 'vscode';
import { CONFIG } from '../config';
import { SeverityLevel } from '../events/sec-events';

export type PolicyMode = 'strict' | 'balanced' | 'audit-only';

export class PolicyService {
  private static _instance: PolicyService;
  private _overrideMode: PolicyMode | null = null;

  private constructor() {}

  static getInstance(): PolicyService {
    if (!PolicyService._instance) {
      PolicyService._instance = new PolicyService();
    }
    return PolicyService._instance;
  }

  getMode(): PolicyMode {
    if (this._overrideMode) {
      return this._overrideMode;
    }
    try {
      const configured = vscode.workspace?.getConfiguration?.('ide-shepherd')?.get<string>('policyMode');
      if (configured === 'strict' || configured === 'balanced' || configured === 'audit-only') {
        return configured;
      }
    } catch {
      // Fallback when vscode configuration is unavailable in unit tests
    }
    return CONFIG.POLICY.DEFAULT_MODE;
  }

  setModeOverride(mode: PolicyMode | null): void {
    this._overrideMode = mode;
  }

  shouldBlock(severity: SeverityLevel, defaultBlock = true): boolean {
    const mode = this.getMode();
    if (mode === 'audit-only') {
      return false;
    }
    if (mode === 'strict') {
      return true;
    }
    return defaultBlock;
  }
}
