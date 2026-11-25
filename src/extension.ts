/**
 * Main VS Code extension entry point
 * Activates the IDE Shepherd security monitoring system
 */

import * as fs from 'fs';
import * as vscode from 'vscode';
import { Logger } from './lib/logger';
import { moduleLoaderPatcher } from './monitor/index';
import { IDEStatusService } from './lib/services/ide-status-service';
import { SidebarService } from './lib/services/sidebar-service';
import { AllowListService } from './lib/services/allowlist-service';
import { TrustedWorkspaceService } from './lib/services/trusted-workspace-service';
import { ExtensionIntegrityService } from './lib/services/extension-integrity-service';
import { ExportFormat, exportSecurityEvents } from './lib/services/siem-exporter';
import { DatadogTelemetryService } from './lib/services/datadog/datadog-service';
import { ExtensionChangeService } from './lib/services/extension-lifecycle-service';
import { AgeHoldService } from './lib/services/age-hold-service';
import { RevocationService } from './lib/services/revocation-service';
import { TaskScanner } from './monitor/analysis/task-analyzer';
import { WorkspaceSecurityScanner } from './scanner/workspace-security-scanner';
import { WelcomeService } from './lib/services/welcome-service';

export function activate(context: vscode.ExtensionContext) {
  try {
    Logger.init(context);
    Logger.info('IDE Shepherd Extension: Logger initialized');

    // Patch the module loader first — before any other service init — to minimise
    // the window in which another extension's module-level require() runs unhooked.
    Logger.info('IDE Shepherd Extension: Activating module loader patcher...');
    moduleLoaderPatcher.patch();
    Logger.info('IDE Shepherd Extension: Module loader patcher activated successfully');

    // Initialize Extension Integrity Service
    const integrityService = ExtensionIntegrityService.getInstance();
    integrityService.initialize(context).then(() => {
      Logger.info('IDE Shepherd Extension: Extension Integrity Service initialized');
    });

    const ageHoldService = AgeHoldService.getInstance();
    ExtensionChangeService.getInstance().registerListener(ageHoldService);
    ageHoldService.initialize(context).catch((err) => {
      Logger.warn(`IDE Shepherd Extension: AgeHoldService initialization failed: ${(err as Error).message}`);
    });

    const revocationService = RevocationService.getInstance();
    ExtensionChangeService.getInstance().registerListener(revocationService);
    revocationService.initialize(context).catch((err) => {
      Logger.warn(`IDE Shepherd Extension: RevocationService initialization failed: ${(err as Error).message}`);
    });

    // Initialize Allow List Service
    const allowListService = AllowListService.getInstance();
    allowListService.initialize(context).then(() => {
      Logger.info('IDE Shepherd Extension: Allow List Service initialized');
    });

    // Initialize Trusted Workspace Service
    const trustedWorkspaceService = TrustedWorkspaceService.getInstance();
    trustedWorkspaceService.initialize(context).then(() => {
      Logger.info('IDE Shepherd Extension: Trusted Workspace Service initialized');
    });

    // Initialize Datadog Telemetry Service only when explicitly enabled
    const ddEnabled = vscode.workspace.getConfiguration('ide-shepherd.datadog').get<boolean>('isEnabled', false);
    if (ddEnabled) {
      const datadogService = DatadogTelemetryService.getInstance();
      datadogService.initialize(context).then(() => {
        Logger.info('IDE Shepherd Extension: Datadog Telemetry Service initialized');
        const extensionChangeService = ExtensionChangeService.getInstance();
        const ocsfTracker = datadogService.getOCSFTracker();

        if (ocsfTracker) {
          extensionChangeService.registerListener(ocsfTracker);
        } else {
          Logger.error('OCSF tracker is undefined! Cannot register.');
        }
      });
    }

    const sidebarService = SidebarService.getInstance();
    sidebarService.initialize();

    // Activate the Task Scanner with Termination
    Logger.info('IDE Shepherd Extension: Activating Task Scanner ...');
    const taskScanner = new TaskScanner();
    taskScanner.activate(context);
    Logger.info('IDE Shepherd Extension: Task Scanner activated successfully');

    // Activate Pre-Execution Workspace & AI Config Scanner
    const workspaceScanner = WorkspaceSecurityScanner.getInstance();
    workspaceScanner.activate(context);
    Logger.info('IDE Shepherd Extension: Workspace Security Scanner activated');

    const statusCommand = vscode.commands.registerCommand('ide-shepherd.showStatus', () => {
      IDEStatusService.showStatus();
    });

    const refreshStatusCommand = vscode.commands.registerCommand('ide-shepherd.refreshStatus', () => {
      IDEStatusService.showStatus();
    });

    const scanExtensionsCommand = vscode.commands.registerCommand('ide-shepherd.scanExtensions', () => {
      sidebarService.triggerExtensionAnalysis();
    });

    const scanWorkspaceCommand = vscode.commands.registerCommand('ide-shepherd.scanWorkspace', async () => {
      const findings = await workspaceScanner.scanAllWorkspaces();
      vscode.window.showInformationMessage(`IDE Shepherd workspace scan complete: ${findings.length} issue(s) found.`);
    });

    const exportEventsCommand = vscode.commands.registerCommand('ide-shepherd.exportEvents', async () => {
      const pickOpts = { placeHolder: 'Select SIEM / Security export format' };
      const format = await vscode.window.showQuickPick(['jsonl', 'cef', 'ocsf', 'sarif'], pickOpts);
      if (!format) {
        return;
      }
      const status = await IDEStatusService.getStatus();
      const content = exportSecurityEvents(status.lastSecurityEvents, format as ExportFormat);
      const extMap: Record<string, string> = { jsonl: 'jsonl', cef: 'cef', ocsf: 'jsonl', sarif: 'sarif' };
      const filterExt = extMap[format] || 'txt';
      const saveOpts = { filters: { 'Security Export': [filterExt] }, saveLabel: 'Export Security Events' };
      const uri = await vscode.window.showSaveDialog(saveOpts);
      if (uri) {
        fs.writeFileSync(uri.fsPath, content, 'utf8');
        const exportedCount = status.lastSecurityEvents.length;
        const hasMore = status.totalSecurityEvents > exportedCount;
        const capNote = hasMore ? ` (latest ${exportedCount} of ${status.totalSecurityEvents})` : '';
        vscode.window.showInformationMessage(`Exported ${exportedCount} event(s)${capNote} to ${uri.fsPath}`);
      }
    });

    const removeFromAllowListCommand = vscode.commands.registerCommand(
      'ide-shepherd.removeFromAllowList',
      (extensionId: string) => sidebarService.removeFromAllowList(extensionId),
    );

    const addToAllowListCommand = vscode.commands.registerCommand('ide-shepherd.addToAllowList', () =>
      sidebarService.addToAllowList(),
    );

    const clearAllowListCommand = vscode.commands.registerCommand('ide-shepherd.clearAllowList', () =>
      sidebarService.clearAllowList(),
    );

    const addTrustedPublisherCommand = vscode.commands.registerCommand('ide-shepherd.addTrustedPublisher', () =>
      sidebarService.addTrustedPublisher(),
    );

    const removeTrustedPublisherCommand = vscode.commands.registerCommand(
      'ide-shepherd.removeTrustedPublisher',
      (publisher: string) => sidebarService.removeTrustedPublisher(publisher),
    );

    const removeTrustedWorkspaceCommand = vscode.commands.registerCommand(
      'ide-shepherd.removeTrustedWorkspace',
      (workspacePath: string) => sidebarService.removeTrustedWorkspace(workspacePath),
    );

    // Settings commands
    const refreshSettingsCommand = vscode.commands.registerCommand('ide-shepherd.settings.refresh', () =>
      sidebarService.refreshSettingsView(),
    );

    const toggleDatadogTelemetryCommand = vscode.commands.registerCommand(
      'ide-shepherd.settings.toggleDatadogTelemetry',
      () => sidebarService.toggleDatadogTelemetry(),
    );

    const clearTaskTimelineCommand = vscode.commands.registerCommand('ide-shepherd.clearTaskTimeline', () => {
      sidebarService.clearTaskTimeline();
      vscode.window.showInformationMessage('Task timeline cleared');
    });

    context.subscriptions.push(
      statusCommand,
      refreshStatusCommand,
      scanExtensionsCommand,
      scanWorkspaceCommand,
      exportEventsCommand,
      removeFromAllowListCommand,
      addToAllowListCommand,
      clearAllowListCommand,
      addTrustedPublisherCommand,
      removeTrustedPublisherCommand,
      removeTrustedWorkspaceCommand,
      refreshSettingsCommand,
      toggleDatadogTelemetryCommand,
      clearTaskTimelineCommand,
    );

    setTimeout(() => {
      IDEStatusService.showStatus();
    }, 1000);

    IDEStatusService.startAutoRefresh();

    WelcomeService.handleActivation(context);
    Logger.info('IDE Shepherd Extension: Welcome service initialized');

    Logger.info('IDE Shepherd Extension: Activation completed successfully');
  } catch (error) {
    Logger.error('IDE Shepherd Extension: Failed to activate', error as Error);
    throw error;
  }
}

export function deactivate() {
  IDEStatusService.stopAutoRefresh();
  DatadogTelemetryService.getInstance().dispose();
}
