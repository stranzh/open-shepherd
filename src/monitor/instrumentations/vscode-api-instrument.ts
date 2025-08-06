/**
 * VS Code API Instrumentation - Monitors vscode.workspace.fs, vscode.env.openExternal,
 * and vscode.env.clipboard.readText calls that bypass Node fs/http/child_process hooks.
 */

import * as vscode from 'vscode';
import { FsRuleType } from '../../detection/fs-rules';
import { NetworkRuleType } from '../../detection/network-rules';
import { ExtensionInfo } from '../../lib/events/ext-events';
import { FsEvent } from '../../lib/events/fs-events';
import { NetworkEvent } from '../../lib/events/network-events';
import { SecurityEvent, SeverityLevel } from '../../lib/events/sec-events';
import { Logger } from '../../lib/logger';
import { AllowListService } from '../../lib/services/allowlist-service';
import { ExtensionServices } from '../../lib/services/ext-service';
import { IDEStatusService } from '../../lib/services/ide-status-service';
import { BlockedOperationType, NotificationService } from '../../lib/services/notification-service';
import { PolicyService } from '../../lib/services/policy-service';
import { CorrelationEngine } from '../analysis/correlation-engine';
import { FsAnalyzer } from '../analysis/fs-analyzer';
import { NetworkAnalyzer } from '../analysis/network-analyzer';

const DANGEROUS_URI_SCHEME_RE = /^(?:file|ms-msdt|search-ms|javascript|vbscript|data):/i;

export function patchVscodeApis(
  vscodeMod: typeof vscode,
  fsAnalyzer = new FsAnalyzer(),
  networkAnalyzer = new NetworkAnalyzer(),
): void {
  const vs = vscodeMod as any;
  if (!vs || vs.__apisPatched__) {
    return;
  }

  // 1. vscode.workspace.fs readFile / writeFile
  try {
    const wsFs = vs.workspace?.fs;
    if (wsFs && !wsFs.__fsPatched__) {
      if (typeof wsFs.readFile === 'function') {
        const origReadFile = wsFs.readFile.bind(wsFs);
        wsFs.readFile = async function patchedWorkspaceFsReadFile(uri: vscode.Uri): Promise<Uint8Array> {
          const fsPath = uri?.fsPath || uri?.toString?.() || '';
          if (fsPath) {
            const callContext = ExtensionServices.getCallContext();
            const extensionInfo = new ExtensionInfo(callContext.extension, true, Date.now());
            const analysis = fsAnalyzer.analyze(new FsEvent(fsPath, 'read', __filename, extensionInfo));
            if (analysis && !analysis.verdict.allowed && analysis.securityEvent) {
              Logger.warn(`VscodeApiInstrument: blocked workspace.fs.readFile(${fsPath})`);
              const op = BlockedOperationType.FS_READ;
              NotificationService.showSecurityBlockingInfo(fsPath, analysis.securityEvent, op);
              throw vscodeMod.FileSystemError.NoPermissions(uri);
            }
          }
          return origReadFile(uri);
        };
      }

      if (typeof wsFs.writeFile === 'function') {
        const origWriteFile = wsFs.writeFile.bind(wsFs);
        wsFs.writeFile = async function patchedWriteFile(uri: vscode.Uri, content: Uint8Array): Promise<void> {
          const fsPath = uri?.fsPath || uri?.toString?.() || '';
          if (fsPath) {
            const callContext = ExtensionServices.getCallContext();
            const extensionInfo = new ExtensionInfo(callContext.extension, true, Date.now());
            const preview = content ? Buffer.from(content.slice(0, 64 * 1024)).toString('utf8') : undefined;
            const fsEv = new FsEvent(fsPath, 'write', __filename, extensionInfo, undefined, preview);
            const analysis = fsAnalyzer.analyze(fsEv);
            if (analysis && !analysis.verdict.allowed && analysis.securityEvent) {
              Logger.warn(`VscodeApiInstrument: blocked workspace.fs.writeFile(${fsPath})`);
              const op = BlockedOperationType.FS_WRITE;
              NotificationService.showSecurityBlockingInfo(fsPath, analysis.securityEvent, op);
              throw vscodeMod.FileSystemError.NoPermissions(uri);
            }
          }
          return origWriteFile(uri, content);
        };
      }

      Object.defineProperty(wsFs, '__fsPatched__', { value: true, configurable: false });
    }
  } catch (error) {
    Logger.warn(`VscodeApiInstrument: Unable to patch workspace.fs: ${(error as Error).message}`);
  }

  // 2. vscode.env.openExternal
  try {
    const envObj = vs.env;
    if (envObj && typeof envObj.openExternal === 'function' && !envObj.__envPatched__) {
      const origOpenExternal = envObj.openExternal.bind(envObj);
      envObj.openExternal = async function patchedOpenExternal(target: vscode.Uri): Promise<boolean> {
        const uriStr = target?.toString?.() || String(target || '');
        const callContext = ExtensionServices.getCallContext();
        const extensionInfo = new ExtensionInfo(callContext.extension, true, Date.now());

        if (!AllowListService.getInstance().isAllowed(extensionInfo.id)) {
          if (DANGEROUS_URI_SCHEME_RE.test(uriStr)) {
            const ev = new NetworkEvent('https', uriStr, 'request:pre', __filename, extensionInfo, 'OPEN_EXTERNAL');
            const secEvent = new SecurityEvent(ev, extensionInfo, SeverityLevel.HIGH, NetworkRuleType.URL, [
              {
                finding: uriStr,
                rule: 'Dangerous External URI Scheme',
                description: `Extension attempted to open dangerous external URI scheme: ${uriStr}`,
                confidence: 0.95,
                severity: SeverityLevel.HIGH,
              },
            ]);
            IDEStatusService.emitSecurityEvent(secEvent).catch((err) => {
              Logger.error(`VscodeApiInstrument: Failed to emit openExternal event: ${err.message}`);
            });
            if (PolicyService.getInstance().shouldBlock(SeverityLevel.HIGH, true)) {
              NotificationService.showSecurityBlockingInfo(uriStr, secEvent, BlockedOperationType.EXTERNAL_URI);
              return false;
            }
          } else {
            const netEv = new NetworkEvent('https', uriStr, 'request:pre', __filename, extensionInfo, 'OPEN_EXTERNAL');
            const analysis = networkAnalyzer.analyze(netEv);
            if (analysis && !analysis.verdict.allowed && analysis.securityEvent) {
              const op = BlockedOperationType.EXTERNAL_URI;
              NotificationService.showSecurityBlockingInfo(uriStr, analysis.securityEvent, op);
              return false;
            }
          }
        }
        return origOpenExternal(target);
      };

      // 3. vscode.env.clipboard.readText
      if (envObj.clipboard && typeof envObj.clipboard.readText === 'function') {
        const origReadText = envObj.clipboard.readText.bind(envObj.clipboard);
        envObj.clipboard.readText = async function patchedClipboardReadText(): Promise<string> {
          const callContext = ExtensionServices.getCallContext();
          const extensionInfo = new ExtensionInfo(callContext.extension, true, Date.now());
          if (!AllowListService.getInstance().isAllowed(extensionInfo.id)) {
            const corr = CorrelationEngine.getInstance();
            corr.recordSensitiveAccess(extensionInfo.id, 'clipboard_read', 'vscode.env.clipboard.readText');
            if (PolicyService.getInstance().getMode() === 'strict') {
              const ev = new FsEvent('clipboard://readText', 'read', __filename, extensionInfo);
              const secEvent = new SecurityEvent(ev, extensionInfo, SeverityLevel.MEDIUM, FsRuleType.READ, [
                {
                  finding: 'vscode.env.clipboard.readText()',
                  rule: 'Untrusted Clipboard Read',
                  description: 'Non-allowlisted extension attempted to read system clipboard in strict mode',
                  confidence: 0.85,
                  severity: SeverityLevel.MEDIUM,
                },
              ]);
              IDEStatusService.emitSecurityEvent(secEvent).catch((err) => {
                Logger.error(`VscodeApiInstrument: Failed to emit clipboard event: ${err.message}`);
              });
              NotificationService.showSecurityBlockingInfo('clipboard', secEvent, BlockedOperationType.CLIPBOARD);
              return '';
            }
          }
          return origReadText();
        };
      }

      Object.defineProperty(envObj, '__envPatched__', { value: true, configurable: false });
    }
  } catch (error) {
    Logger.warn(`VscodeApiInstrument: Unable to patch vscode.env: ${(error as Error).message}`);
  }

  try {
    Object.defineProperty(vs, '__apisPatched__', { value: true, configurable: false });
  } catch {
    // Non-extensible mock or VS Code namespace object
  }
  Logger.info('VscodeApiInstrument: vscode workspace.fs/env instrumentation applied');
}
