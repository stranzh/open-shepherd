import { CorrelationRuleType, SecurityEvent, SeverityLevel } from '../../lib/events/sec-events';
import { Logger } from '../../lib/logger';
import { IDEStatusService } from '../../lib/services/ide-status-service';
import { AnalysisResult } from './analyzer';
import { CorrelationEngine } from './correlation-engine';
import { FsEvent } from '../../lib/events/fs-events';
import { FS_RULES, FsRule, FsRuleType } from '../../detection/fs-rules';
import { classifyIdeTokenStorePath } from '../../detection/fs-rules-extra';

export class FsAnalyzer {
  analyze(ev: FsEvent): AnalysisResult | undefined {
    const startTime = Date.now();

    try {
      let result = new AnalysisResult();

      // Normalize path to forward slashes for cross-platform matching
      const normalizedPath = ev.path.replace(/\\/g, '/');

      let matchedRuleType: FsRuleType | null = null;
      for (const rule of FS_RULES) {
        const checkResult = this.checkRule(ev, normalizedPath, rule);
        if (checkResult.securityEvent) {
          result = checkResult;
          matchedRuleType = rule.type;
          break; // stop on first security event found
        }
      }

      if (!ev.extension) {
        Logger.error('FsAnalyzer: Filesystem event missing extension info');
        return new AnalysisResult();
      }

      result = result.checkAgainstAllowList(ev.extension.id, ev.path, 'FsAnalyzer');

      if (result.securityEvent && matchedRuleType === FsRuleType.READ) {
        CorrelationEngine.getInstance().recordSensitiveAccess(ev.extension.id, 'fs_sensitive_read', ev.path);
        const storeFamily = classifyIdeTokenStorePath(normalizedPath);
        if (storeFamily) {
          const match = CorrelationEngine.getInstance().recordIdeTokenStoreRead(ev.extension.id, storeFamily, ev.path);
          if (match) {
            result = new AnalysisResult(
              { allowed: false },
              new SecurityEvent(ev, ev.extension, SeverityLevel.HIGH, CorrelationRuleType.KILL_CHAIN, [
                {
                  finding: ev.path,
                  rule: match.rule,
                  description: match.description,
                  confidence: 0.99,
                  severity: SeverityLevel.HIGH,
                },
                ...result.securityEvent.iocs,
              ]),
            );
          }
        }
      }

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
