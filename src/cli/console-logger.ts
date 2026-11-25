/**
 * Console logger and reporter interface for headless CLI scanning.
 */

import { WorkspaceFinding } from '../detection/workspace-rule-types';

export interface ScanReporter {
  info(message: string): void;
  warn(message: string): void;
  error(message: string, error?: Error): void;
  reportFindings?(findings: WorkspaceFinding[], scopeName: string, scopePath: string): Promise<void> | void;
}

export class ConsoleLogger implements ScanReporter {
  private readonly writeFn: (line: string) => void;

  constructor(writeFn?: (line: string) => void) {
    this.writeFn = writeFn ?? ((line: string) => process.stderr.write(line + '\n'));
  }

  info(message: string): void {
    this.writeFn(`[INFO] ${message}`);
  }

  warn(message: string): void {
    this.writeFn(`[WARN] ${message}`);
  }

  error(message: string, error?: Error): void {
    this.writeFn(`[ERROR] ${message}`);
    if (error) {
      this.writeFn(`[ERROR] ${error.stack || error.message}`);
    }
  }
}
