/**
 * Minimal VS Code API shim loaded via mocha `--require` for headless unit testing
 * outside the VS Code Electron host.
 */

const Module = require('module');
const originalLoad = Module._load;

function createDisposable() {
  return { dispose: () => {} };
}

class MockEventEmitter {
  private listeners: Array<(e: any) => void> = [];
  event = (listener: (e: any) => void) => {
    this.listeners.push(listener);
    return createDisposable();
  };
  fire(data?: any) {
    for (const l of this.listeners) {
      l(data);
    }
  }
  dispose() {
    this.listeners = [];
  }
}

class MockShellExecution {
  commandLine?: string;
  command?: string | { value: string };
  args?: Array<string | { value: string }>;
  options?: Record<string, unknown>;
  constructor(commandOrLine: string | { value: string }, args?: Array<string | { value: string }>, options?: any) {
    if (args !== undefined) {
      this.command = commandOrLine;
      this.args = args;
      this.options = options;
    } else if (typeof commandOrLine === 'string') {
      this.commandLine = commandOrLine;
    } else {
      this.command = commandOrLine;
    }
  }
}

class MockProcessExecution {
  process: string;
  args: string[];
  options?: Record<string, unknown>;
  constructor(processName: string, args: string[] = [], options?: any) {
    this.process = processName;
    this.args = args;
    this.options = options;
  }
}

class MockCustomExecution {
  callback: unknown;
  constructor(callback: unknown) {
    this.callback = callback;
  }
}

const mockVscode = {
  version: '1.99.3',
  EventEmitter: MockEventEmitter,
  ShellExecution: MockShellExecution,
  ProcessExecution: MockProcessExecution,
  CustomExecution: MockCustomExecution,
  TaskScope: { Global: 1, Workspace: 2 },
  ExtensionKind: { UI: 1, Workspace: 2 },
  ExtensionMode: { Production: 1, Development: 2, Test: 3 },
  StatusBarAlignment: { Left: 1, Right: 2 },
  TreeItemCollapsibleState: { None: 0, Collapsed: 1, Expanded: 2 },
  TreeItem: class {
    label: string;
    collapsibleState: number;
    constructor(label: string, collapsibleState = 0) {
      this.label = label;
      this.collapsibleState = collapsibleState;
    }
  },
  ThemeIcon: class {
    id: string;
    constructor(id: string) {
      this.id = id;
    }
  },
  ThemeColor: class {
    id: string;
    constructor(id: string) {
      this.id = id;
    }
  },
  Uri: {
    file: (fsPath: string) => ({ scheme: 'file', fsPath, path: fsPath, toString: () => `file://${fsPath}` }),
    parse: (raw: string) => ({ scheme: 'https', fsPath: raw, path: raw, toString: () => raw }),
    joinPath: (base: { fsPath: string }, ...parts: string[]) => {
      const joined = [base.fsPath, ...parts].join('/');
      return { scheme: 'file', fsPath: joined, path: joined, toString: () => `file://${joined}` };
    },
  },
  FileSystemError: { NoPermissions: (uri?: unknown) => new Error(`NoPermissions: ${String(uri || '')}`) },
  workspace: {
    name: 'mock-workspace',
    workspaceFolders: undefined as any,
    getConfiguration: () => ({
      get: (_k: string, def?: unknown) => def,
      update: async () => {},
      has: () => false,
      inspect: () => undefined,
    }),
    onDidChangeConfiguration: () => createDisposable(),
    onDidChangeWorkspaceFolders: () => createDisposable(),
    onDidSaveTextDocument: () => createDisposable(),
    getWorkspaceFolder: () => undefined,
    fs: { readFile: async () => Buffer.alloc(0), writeFile: async () => {} },
  },
  window: {
    createOutputChannel: () => ({ appendLine: () => {}, append: () => {}, show: () => {}, dispose: () => {} }),
    createStatusBarItem: () => ({ show: () => {}, hide: () => {}, dispose: () => {} }),
    showInformationMessage: async () => undefined,
    showWarningMessage: async () => undefined,
    showErrorMessage: async () => undefined,
    showQuickPick: async () => undefined,
    showSaveDialog: async () => undefined,
    showInputBox: async () => undefined,
    registerTreeDataProvider: () => createDisposable(),
    createWebviewPanel: () => ({ webview: { html: '' }, onDidDispose: () => createDisposable(), dispose: () => {} }),
  },
  extensions: { all: [] as any[], onDidChange: () => createDisposable(), getExtension: () => undefined },
  tasks: {
    taskExecutions: [] as any[],
    onDidStartTask: () => createDisposable(),
    onDidEndTask: () => createDisposable(),
    onDidStartTaskProcess: () => createDisposable(),
    onDidEndTaskProcess: () => createDisposable(),
    executeTask: async (t: any) => ({ task: t, terminate: () => {} }),
  },
  commands: { registerCommand: () => createDisposable(), executeCommand: async () => undefined },
  env: {
    appName: 'Visual Studio Code',
    openExternal: async () => true,
    clipboard: { readText: async () => '', writeText: async () => {} },
  },
};

Module._load = function patchedTestLoad(request: string, parent: unknown, isMain: boolean) {
  if (request === 'vscode') {
    return mockVscode;
  }
  return originalLoad.call(this, request, parent, isMain);
};

const chaiLib = require('chai');
const sinonChai = require('sinon-chai');
chaiLib.use(sinonChai);

const { ExtensionsRepository } = require('../lib/extensions');
ExtensionsRepository.getInstance();
