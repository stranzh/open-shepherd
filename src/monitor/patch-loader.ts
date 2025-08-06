/**
 * High level layer to loop through all the modules names and apply the patch
 * will report the status of the patch for each module
 * will receive config params and pass them to the hooks
 */

import { Logger } from '../lib/logger';
import { CONFIG } from '../lib/config';
import { patchHttpExports } from './instrumentations/http-client-instrument';
import { patchGlobalFetch } from './instrumentations/fetch-instrument';
import { patchNetExports, patchTlsExports, patchDnsExports } from './instrumentations/socket-dns-instrument';
import { patchChildProcess } from './instrumentations/child-process-instrument';
import { patchFs } from './instrumentations/fs-instrument';
import { patchWorkerThreads, patchVmExports } from './instrumentations/worker-vm-instrument';
import { patchVscodeTasks } from './instrumentations/vscode-tasks-instrument';
import { patchVscodeApis } from './instrumentations/vscode-api-instrument';
import { Protocol } from '../lib/events/network-events';

const { Module } = require('module');

const PATCHER_SYMBOL = Symbol.for('__ideSecPatcher__');

export class ModuleLoaderPatcher {
  private originalLoad!: typeof Module._load;
  private patched = false;

  private getHookedModuleGroups(): string[][] {
    return [
      CONFIG.MODULES.HTTP_MODULES,
      CONFIG.MODULES.NET_MODULES,
      CONFIG.MODULES.TLS_MODULES,
      CONFIG.MODULES.DNS_MODULES,
      CONFIG.MODULES.CHILD_PROCESS_MODULES,
      CONFIG.MODULES.FS_MODULES,
      CONFIG.MODULES.WORKER_MODULES,
      CONFIG.MODULES.VM_MODULES,
      CONFIG.MODULES.VSCODE_MODULES,
    ];
  }

  // Patch modules that are already in the require cache before the RITM hook
  // is installed. Without this, any module loaded before IDE Shepherd activated
  // (child_process, fs, http are loaded early by the VS Code host) remains
  // unpatched — all existing references to those exports stay unmonitored.
  private patchCachedModules(): void {
    const allModuleNames = this.getHookedModuleGroups().flat();

    for (const moduleName of allModuleNames) {
      try {
        const exports = require(moduleName);
        this.patchExports(exports, moduleName);
      } catch {
        // module unavailable on this Node version (e.g. node:fs/promises < 14.18) — skip
      }
    }
  }

  patch(): void {
    if (this.patched) {
      return;
    }

    try {
      // Patch global fetch (Undici) before module loader hooks
      patchGlobalFetch();

      // Eagerly patch modules that are already loaded — must run before the
      // RITM hook so that pre-existing exports references are covered.
      this.patchCachedModules();

      // patch Module._load for future requires
      const self = this;
      this.originalLoad = (Module as any)._load;

      (Module as any)._load = function patchedLoad(request: any, parent: any, isMain: any) {
        const exports = self.originalLoad.apply(this, arguments);
        const toHook = self.getHookedModuleGroups().flat();

        if (toHook.includes(request)) {
          self.patchExports(exports, request);
        }
        return exports;
      };

      this.patched = true;
    } catch (error) {
      Logger.error('ModuleLoaderPatcher: Failed to complete patch process', error as Error);
      throw error;
    }
  }

  private patchExports(exp: any, spec: string): void {
    if (!exp || exp.__patched__) {
      return;
    }

    try {
      if (CONFIG.MODULES.HTTP_MODULES.includes(spec)) {
        const protocol: Protocol = spec.includes('https') ? 'https' : 'http';
        patchHttpExports(exp, protocol);
      }

      if (CONFIG.MODULES.NET_MODULES.includes(spec)) {
        patchNetExports(exp);
      }

      if (CONFIG.MODULES.TLS_MODULES.includes(spec)) {
        patchTlsExports(exp);
      }

      if (CONFIG.MODULES.DNS_MODULES.includes(spec)) {
        patchDnsExports(exp);
      }

      if (CONFIG.MODULES.CHILD_PROCESS_MODULES.includes(spec)) {
        patchChildProcess(exp);
      }

      if (CONFIG.MODULES.FS_MODULES.includes(spec)) {
        patchFs(exp);
      }

      if (CONFIG.MODULES.WORKER_MODULES.includes(spec)) {
        patchWorkerThreads(exp);
      }

      if (CONFIG.MODULES.VM_MODULES.includes(spec)) {
        patchVmExports(exp);
      }

      if (CONFIG.MODULES.VSCODE_MODULES.includes(spec)) {
        patchVscodeTasks(exp);
        patchVscodeApis(exp);
      }
    } catch (error) {
      Logger.error(`ModuleLoaderPatcher: Failed to patch exports for ${spec}`, error as Error);
      throw error;
    }
  }
}

// expose singleton on globalThis
if (!(global as any)[PATCHER_SYMBOL]) {
  (global as any)[PATCHER_SYMBOL] = new ModuleLoaderPatcher();
}
export const moduleLoaderPatcher: ModuleLoaderPatcher = (global as any)[PATCHER_SYMBOL];
