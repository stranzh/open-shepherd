import * as path from 'path';
import { SecurityEvent } from '../../lib/events/sec-events';
import { Logger } from '../../lib/logger';
import { IDEStatusService } from '../../lib/services/ide-status-service';
import { AnalysisResult } from './analyzer';
import { FsEvent } from '../../lib/events/fs-events';
import { FS_RULES, FsRule } from '../../detection/fs-rules';

export class FsAnalyzer {
  analyze(ev: FsEvent): AnalysisResult | undefined {
    const startTime = Date.now();

    try {
      let result = new AnalysisResult();

      // Canonicalize and normalize path to forward slashes for cross-platform matching
      let decodedPath = ev.path;
      try {
        decodedPath = decodeURIComponent(ev.path);
      } catch {
        // ignore malformed URI sequences
      }
      const normalizedPath = path.resolve(decodedPath).replace(/\\/g, '/');

      for (const rule of FS_RULES) {
        const checkResult = this.checkRule(ev, normalizedPath, rule);
        if (checkResult.securityEvent) {
          result = checkResult;
          break; // stop on first security event found
        }
      }

      if (!ev.extension) {
        Logger.error('FsAnalyzer: Filesystem event missing extension info');
        return new AnalysisResult();
      }

      result = result.checkAgainstAllowList(ev.extension.id, ev.path, 'FsAnalyzer');

      const endTime = Date.now();
      IDEStatusService.updatePerformanceMetrics(endTime - startTime).catch((error) => {
        Logger.error(`FsAnalyzer: Failed to record processing time: ${error.message}`);
      });

      return result;
    } catch (error) {
      Logger.error('FsAnalyzer: Error during analysis', error as Error);
      return new AnalysisResult();
    }
  }

  private checkRule(ev: FsEvent, normalizedPath: string, rule: FsRule): AnalysisResult {
    // Check that the operation matches what this rule monitors
    if (!rule.operations.includes(ev.operation)) {
      return new AnalysisResult();
    }

    if (!rule.pathPattern.test(normalizedPath)) {
      return new AnalysisResult();
    }

    // Content gate: if the rule specifies a payload pattern, the write data must
    // also match. No match (or no content captured) means the rule does not fire.
    if (rule.contentPattern !== undefined) {
      if (!ev.content || !rule.contentPattern.test(ev.content)) {
        return new AnalysisResult();
      }
    }

    if (!ev.extension) {
      return new AnalysisResult();
    }

    return new AnalysisResult(
      { allowed: false },
      new SecurityEvent(ev, ev.extension, rule.severity, rule.type, [
        {
          finding: ev.path,
          rule: rule.name,
          description: `${rule.description}: ${ev.path}`,
          confidence: rule.confidence,
          severity: rule.severity,
        },
      ]),
    );
  }
}
