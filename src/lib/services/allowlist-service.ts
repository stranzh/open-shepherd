/**
 * Allow List Service - Manages extension allow lists for IDE Shepherd
 *
 * Two types of allow lists:
 * 1. Built-in/First-party extensions (automatically populated, read-only via API)
 * 2. User allow list including trusted publishers and extensions (manually managed by users)
 */

import * as vscode from 'vscode';
import { Logger } from '../logger';
import { ExtensionsRepository } from '../extensions';
import { CONFIG } from '../config';
import { ExtensionIntegrityService } from './extension-integrity-service';

export interface AllowListEntryMetadata {
  expiresAt?: number;
  integrityHash?: string;
}

interface AllowListState {
  userExtensions: string[]; // extension IDs manually allowed by user
  trustedPublishers: string[]; // all trusted publishers (initialized with defaults, can be modified by user)
  entryMetadata?: Record<string, AllowListEntryMetadata>;
}

export class AllowListService {
  private static _instance: AllowListService;
  private _context: vscode.ExtensionContext | null = null; // ensures persistence of allow list across sessions
  private _userAllowList: Set<string> = new Set();
  private _sessionAllowList: Set<string> = new Set();
  private _entryMetadata: Map<string, AllowListEntryMetadata> = new Map();
  private _builtInAllowList: Set<string> = new Set();
  private _trustedPublisherAllowList: Set<string> = new Set(); // Extension IDs from trusted publishers
  private _trustedPublishers: Set<string> = new Set();

  private _extensionsRepo: ExtensionsRepository;

  private static readonly STORAGE_KEY = 'ide-shepherd.allowlist';

  private constructor() {
    this._extensionsRepo = ExtensionsRepository.getInstance();
    this.initializeBuiltInAllowList();
  }

  static getInstance(): AllowListService {
    if (!AllowListService._instance) {
      AllowListService._instance = new AllowListService();
    }
    return AllowListService._instance;
  }

  async initialize(context: vscode.ExtensionContext): Promise<void> {
    this._context = context;
    await this.loadState();
    Logger.info('AllowListService: Initialized');
  }

  /**
   * Initialize built-in allow list with first-party extensions
   */
  private initializeBuiltInAllowList(): void {
    // Initialize trusted publishers with defaults if not already loaded from state
    if (this._trustedPublishers.size === 0) {
      CONFIG.ALLOWLIST.DEFAULT_TRUSTED_PUBLISHERS.forEach((publisher) => {
        this._trustedPublishers.add(publisher);
      });
    }

    this.rebuildAllowLists();

    Logger.debug(
      `AllowListService: Built-in allow list contains ${this._builtInAllowList.size} extensions, ` +
        `Trusted publisher allow list contains ${this._trustedPublisherAllowList.size} extensions`,
    );
  }

  /**
   * Rebuild the allow lists based on current trusted publishers
   */
  private rebuildAllowLists(): void {
    this._builtInAllowList.clear();
    this._trustedPublisherAllowList.clear();

    const builtInExtensions = this._extensionsRepo.getBuiltInExtensions();
    builtInExtensions.forEach((ext) => {
      this._builtInAllowList.add(ext.id);
    });

    // Add extensions from all trusted publishers
    this._trustedPublishers.forEach((publisher) => {
      const publisherExtensions = this._extensionsRepo.getExtensionsByPublisher(publisher);
      publisherExtensions.forEach((ext) => {
        if (!this._builtInAllowList.has(ext.id)) {
          this._trustedPublisherAllowList.add(ext.id);
        }
      });
    });
  }

  isAllowed(extensionId: string): boolean {
    if (ExtensionIntegrityService.getInstance().hasIntegrityDrift(extensionId)) {
      Logger.warn(`AllowListService: Denying allowlist trust due to integrity drift for ${extensionId}`);
      return false;
    }

    const meta = this._entryMetadata.get(extensionId);
    if (meta?.expiresAt && Date.now() > meta.expiresAt) {
      this._userAllowList.delete(extensionId);
      this._entryMetadata.delete(extensionId);
      this.saveState().catch(() => {});
    }

    if (meta?.integrityHash) {
      const currentDigest = ExtensionIntegrityService.getInstance().getBaselineDigest(extensionId);
      if (currentDigest && currentDigest !== meta.integrityHash) {
        return false;
      }
    }

    return (
      this._builtInAllowList.has(extensionId) ||
      this._trustedPublisherAllowList.has(extensionId) ||
      this._userAllowList.has(extensionId) ||
      this._sessionAllowList.has(extensionId)
    );
  }

  allowOnceForSession(extensionId: string): void {
    if (!extensionId) {
      return;
    }
    this._sessionAllowList.add(extensionId);
    Logger.info(`AllowListService: Temporarily allowed ${extensionId} for current session`);
  }

  async addToUserAllowList(extensionId: string, options?: { ttlMs?: number; integrityHash?: string }): Promise<void> {
    if (this.isAllowed(extensionId) && !options?.ttlMs && !options?.integrityHash) {
      Logger.debug(`AllowListService: Extension ${extensionId} is already allowed`);
      return;
    }

    this._userAllowList.add(extensionId);
    const meta: AllowListEntryMetadata = {};
    if (options?.ttlMs && options.ttlMs > 0) {
      meta.expiresAt = Date.now() + options.ttlMs;
    }
    const digest = options?.integrityHash || ExtensionIntegrityService.getInstance().getBaselineDigest(extensionId);
    if (digest) {
      meta.integrityHash = digest;
    }
    if (meta.expiresAt || meta.integrityHash) {
      this._entryMetadata.set(extensionId, meta);
    }

    await this.saveState();
    Logger.info(`AllowListService: Added ${extensionId} to user allow list`);
  }

  async removeFromUserAllowList(extensionId: string): Promise<void> {
    if (!this._userAllowList.has(extensionId) && !this._sessionAllowList.has(extensionId)) {
      Logger.debug(`AllowListService: Extension ${extensionId} not in user allow list`);
      return;
    }

    this._userAllowList.delete(extensionId);
    this._sessionAllowList.delete(extensionId);
    this._entryMetadata.delete(extensionId);
    await this.saveState();
    Logger.info(`AllowListService: Removed ${extensionId} from user allow list`);
  }

  getUserAllowList(): string[] {
    return Array.from(this._userAllowList);
  }

  getBuiltInAllowList(): string[] {
    return Array.from(this._builtInAllowList);
  }

  getTrustedPublisherAllowList(): string[] {
    return Array.from(this._trustedPublisherAllowList);
  }

  getTrustedPublishers(): string[] {
    return Array.from(this._trustedPublishers).sort();
  }

  async addTrustedPublisher(publisher: string): Promise<void> {
    if (this._trustedPublishers.has(publisher)) {
      Logger.debug(`AllowListService: Publisher ${publisher} is already trusted`);
      return;
    }

    this._trustedPublishers.add(publisher);
    await this.saveState();
    this.rebuildAllowLists();
    Logger.info(`AllowListService: Added ${publisher} to trusted publishers`);
  }

  async removeTrustedPublisher(publisher: string): Promise<void> {
    if (!this._trustedPublishers.has(publisher)) {
      Logger.debug(`AllowListService: Publisher ${publisher} is not in trusted list`);
      return;
    }

    this._trustedPublishers.delete(publisher);
    await this.saveState();
    this.rebuildAllowLists();
    Logger.info(`AllowListService: Removed ${publisher} from trusted publishers`);
  }

  isTrustedPublisher(publisher: string): boolean {
    return this._trustedPublishers.has(publisher);
  }

  getStatistics(): { builtInCount: number; trustedPublisherCount: number; userCount: number; totalCount: number } {
    return {
      builtInCount: this._builtInAllowList.size,
      trustedPublisherCount: this._trustedPublisherAllowList.size,
      userCount: this._userAllowList.size,
      totalCount: this._builtInAllowList.size + this._trustedPublisherAllowList.size + this._userAllowList.size,
    };
  }

  /**
   * Load saved state from VS Code storage
   */
  private async loadState(): Promise<void> {
    if (!this._context) {
      Logger.warn('AllowListService: Cannot load state - context not initialized');
      return;
    }

    try {
      const savedState = this._context.globalState.get<AllowListState>(AllowListService.STORAGE_KEY);

      if (savedState?.userExtensions) {
        this._userAllowList = new Set(savedState.userExtensions);
        Logger.info(`AllowListService: Loaded ${this._userAllowList.size} user-allowed extensions`);
      } else {
        Logger.info('AllowListService: No saved state found, starting fresh');
      }

      this._entryMetadata.clear();
      if (savedState?.entryMetadata) {
        for (const [id, meta] of Object.entries(savedState.entryMetadata)) {
          if (!meta.expiresAt || meta.expiresAt > Date.now()) {
            this._entryMetadata.set(id, meta);
          } else {
            this._userAllowList.delete(id);
          }
        }
      }

      if (savedState?.trustedPublishers) {
        this._trustedPublishers = new Set(savedState.trustedPublishers);
        Logger.info(`AllowListService: Loaded ${this._trustedPublishers.size} trusted publishers`);
      }

      // Rebuild after loading so _trustedPublisherAllowList reflects persisted publishers,
      // not just the defaults that were available at construction time.
      this.rebuildAllowLists();
    } catch (error) {
      Logger.error('AllowListService: Failed to load state', error as Error);
    }
  }

  private async saveState(): Promise<void> {
    if (!this._context) {
      Logger.warn('AllowListService: Cannot save state - context not initialized');
      return;
    }

    try {
      const state: AllowListState = {
        userExtensions: Array.from(this._userAllowList),
        trustedPublishers: Array.from(this._trustedPublishers),
      };
      if (this._entryMetadata.size > 0) {
        state.entryMetadata = Object.fromEntries(this._entryMetadata.entries());
      }

      await this._context.globalState.update(AllowListService.STORAGE_KEY, state);
      Logger.debug('AllowListService: State saved successfully');
    } catch (error) {
      Logger.error('AllowListService: Failed to save state', error as Error);
    }
  }

  /**
   * Clear all user allow list entries (for testing or reset purposes)
   */
  async clearUserAllowList(): Promise<void> {
    this._userAllowList.clear();
    this._sessionAllowList.clear();
    this._entryMetadata.clear();
    await this.saveState();
    Logger.info('AllowListService: User allow list cleared');
  }
}
