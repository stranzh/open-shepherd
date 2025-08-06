/**
 * Workspace & AI IDE Configuration Security Scanner
 *
 * Scans workspace folders and user AI configs (MCP servers, agent rules,
 * VS Code tasks/launch/settings, git hooks/config, devcontainers, package manifests)
 * before execution.
 */

import * as path from 'path';
import * as vscode from 'vscode';
import { ScanReporter } from '../cli/console-logger';
import { HeadlessWorkspaceScanner, ScanDirectoryOptions } from '../cli/headless-scanner';
import { WorkspaceFinding } from '../detection/workspace-rules';
import { WorkspaceInfo } from '../lib/events/ext-events';
import { SecurityEvent, SeverityLevel } from '../lib/events/sec-events';
import { TaskEvent } from '../lib/events/task-events';
import { Logger } from '../lib/logger';
import { IDEStatusService } from '../lib/services/ide-status-service';
import { TrustedWorkspaceService } from '../lib/services/trusted-workspace-service';

export class WorkspaceSecurityScanner {
  private static _instance: WorkspaceSecurityScanner;
  private readonly pendingReports = new Set<Promise<void>>();
  private readonly headless: HeadlessWorkspaceScanner;

  private constructor() {
    const reporter: ScanReporter = {
      info: (message: string) => Logger.info(message),
      warn: (message: string) => Logger.warn(message),
      error: (message: string, error?: Error) => Logger.error(message, error),
      reportFindings: (findings: WorkspaceFinding[], scopeName: string, scopePath: string) => {
        const promise = this.reportFindings(findings, scopeName, scopePath).finally(() => {
          this.pendingReports.delete(promise);
        });
        this.pendingReports.add(promise);
        return promise;
      },
    };
    this.headless = new HeadlessWorkspaceScanner(reporter);
  }

  static getInstance(): WorkspaceSecurityScanner {
    if (!WorkspaceSecurityScanner._instance) {
      WorkspaceSecurityScanner._instance = new WorkspaceSecurityScanner();
    }
    return WorkspaceSecurityScanner._instance;
  }

  activate(context: vscode.ExtensionContext): void {
    this.scanAllWorkspaces(true).catch((err) => {
      Logger.warn(`WorkspaceSecurityScanner: initial scan failed: ${(err as Error).message}`);
    });

    context.subscriptions.push(
      vscode.workspace.onDidChangeWorkspaceFolders(() => {
        this.scanAllWorkspaces(false).catch((err) => {
          Logger.warn(`WorkspaceSecurityScanner: folder change scan failed: ${(err as Error).message}`);
        });
      }),
      vscode.workspace.onDidSaveTextDocument((doc) => {
        const fsPath = doc.uri.fsPath;
        if (this.isWatchedConfigPath(fsPath)) {
          const folder = vscode.workspace.getWorkspaceFolder(doc.uri);
          const findings = this.scanSingleFile(fsPath, folder?.uri.fsPath);
          if (findings.length > 0) {
            const wsName = folder?.name || 'Workspace';
            const wsPath = folder?.uri.fsPath || path.dirname(fsPath);
            this.reportFindings(findings, wsName, wsPath).catch(() => {});
          }
        }
      }),
    );
  }

  isWatchedConfigPath(filePath: string): boolean {
    return this.headless.isWatchedConfigPath(filePath);
  }

  scanSingleFile(filePath: string, baseDir?: string): WorkspaceFinding[] {
    return this.headless.scanSingleFile(filePath, baseDir);
  }

  scanDirectory(rootDir: string, options?: ScanDirectoryOptions): WorkspaceFinding[] {
    return this.headless.scanDirectory(rootDir, options);
  }

  scanGlobalConfigs(homeDir?: string): WorkspaceFinding[] {
    return this.headless.scanGlobalConfigs(homeDir);
  }

  async scanAllWorkspaces(includeGlobalMcp = true): Promise<WorkspaceFinding[]> {
    const allFindings: WorkspaceFinding[] = [];
    const folders = vscode.workspace.workspaceFolders ?? [];

    for (const folder of folders) {
      const folderPath = folder.uri.fsPath;
      if (TrustedWorkspaceService.getInstance().isTrusted(folderPath)) {
        continue;
      }
      const findings = this.scanDirectory(folderPath);
      allFindings.push(...findings);
      if (findings.length > 0) {
        await this.reportFindings(findings, folder.name, folderPath);
      }
    }

    if (includeGlobalMcp) {
      allFindings.push(...this.scanGlobalConfigs());
      if (this.pendingReports.size > 0) {
        await Promise.all(Array.from(this.pendingReports));
      }
    }

    return allFindings;
  }

  scanAntigravityTranscripts(homeDir?: string): WorkspaceFinding[] {
    return this.headless.scanAntigravityTranscripts(homeDir);
  }

  private async reportFindings(findings: WorkspaceFinding[], wsName: string, wsPath: string): Promise<void> {
    for (const f of findings) {
      const wsInfo = new WorkspaceInfo(wsName, wsPath, false);
      const taskEvent = new TaskEvent(
        `Workspace Scan: ${path.basename(f.filePath)}`,
        f.type,
        'WorkspaceSecurityScanner',
        f.finding,
        [],
        wsInfo,
        wsPath,
      );
      const secEvent = new SecurityEvent(taskEvent, wsInfo, f.severity, f.type, [
        {
          finding: `${f.filePath}: ${f.finding}`,
          rule: f.ruleName,
          description: f.description,
          confidence: f.confidence,
          severity: f.severity,
        },
      ]);
      await IDEStatusService.emitSecurityEvent(secEvent).catch((err) => {
        Logger.warn(`WorkspaceSecurityScanner: failed to emit event: ${(err as Error).message}`);
      });
    }

    const highCount = findings.filter((f) => f.severity === SeverityLevel.HIGH).length;
    if (highCount > 0) {
      vscode.window.showWarningMessage(`IDE Shepherd detected ${highCount} high-risk issue(s) in ${wsName}.`);
    }
  }
}
