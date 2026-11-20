/**
 * Worker Threads & VM Instrumentation - Detects unmonitored worker_threads.Worker
 * spawns (especially eval: true workers) and obfuscated vm.* code execution.
 */

import { SOURCE_RULES } from '../../detection/source-rules';
import { ProcessRuleType } from '../../detection/process-rules';
import { ExtensionInfo } from '../../lib/events/ext-events';
import { ExecEvent } from '../../lib/events/process-events';
import { SecurityEvent, SeverityLevel } from '../../lib/events/sec-events';
import { Logger } from '../../lib/logger';
import { AllowListService } from '../../lib/services/allowlist-service';
import { ExtensionServices } from '../../lib/services/ext-service';
import { IDEStatusService } from '../../lib/services/ide-status-service';
import { BlockedOperationType, NotificationService } from '../../lib/services/notification-service';
import { PolicyService } from '../../lib/services/policy-service';

function evaluateDynamicCode(code: string, apiName: string): { blocked: boolean; message?: string } {
  const callContext = ExtensionServices.getCallContext();
  const extensionInfo = new ExtensionInfo(callContext.extension, true, Date.now());
  if (AllowListService.getInstance().isAllowed(extensionInfo.id)) {
    return { blocked: false };
  }

  for (const rule of SOURCE_RULES) {
    if (rule.severity === SeverityLevel.HIGH && rule.detect(code)) {
      const ev = new ExecEvent(apiName, [Logger.truncate(code, 160)], undefined, __filename, extensionInfo);
      const secEvent = new SecurityEvent(ev, extensionInfo, SeverityLevel.HIGH, ProcessRuleType.SCRIPT, [
        {
          finding: `${apiName}: ${Logger.truncate(code, 120)}`,
          rule: `VM Dynamic Execution (${rule.name})`,
          description: rule.description,
          confidence: 0.9,
          severity: SeverityLevel.HIGH,
        },
      ]);
      IDEStatusService.emitSecurityEvent(secEvent).catch((err) => {
        Logger.error(`VmInstrument: Failed to emit security event: ${err.message}`);
      });
      if (PolicyService.getInstance().shouldBlock(SeverityLevel.HIGH, true)) {
        NotificationService.showSecurityBlockingInfo(apiName, secEvent, BlockedOperationType.VM);
        return { blocked: true, message: `VM code execution blocked by security policy (${rule.name})` };
      }
      break;
    }
  }

  return { blocked: false };
}

export function patchWorkerThreads(workerMod: any): void {
  if (!workerMod || workerMod.__workerPatched__ || typeof workerMod.Worker !== 'function') {
    return;
  }

  const OrigWorker = workerMod.Worker;
  workerMod.Worker = new Proxy(OrigWorker, {
    construct(target, args, newTarget) {
      const [filenameOrCode, options] = args;
      const callContext = ExtensionServices.getCallContext();
      const extensionInfo = new ExtensionInfo(callContext.extension, true, Date.now());

      if (!AllowListService.getInstance().isAllowed(extensionInfo.id)) {
        const isEval = Boolean(options && typeof options === 'object' && options.eval === true);
        const policyMode = PolicyService.getInstance().getMode();
        if (isEval || policyMode === 'strict') {
          const targetDesc = isEval
            ? `eval Worker(${Logger.truncate(String(filenameOrCode), 120)})`
            : String(filenameOrCode);
          const ev = new ExecEvent('worker_threads.Worker', [targetDesc], options, __filename, extensionInfo);
          const secEvent = new SecurityEvent(ev, extensionInfo, SeverityLevel.HIGH, ProcessRuleType.SCRIPT, [
            {
              finding: targetDesc,
              rule: isEval ? 'Inline Eval Worker Thread' : 'Untrusted Worker Thread Spawn',
              description: isEval
                ? 'Extension spawned an inline eval worker_threads.Worker bypassing module hooks'
                : 'Extension spawned a worker thread in strict policy mode',
              confidence: 0.9,
              severity: SeverityLevel.HIGH,
            },
          ]);
          IDEStatusService.emitSecurityEvent(secEvent).catch((err) => {
            Logger.error(`WorkerInstrument: Failed to emit security event: ${err.message}`);
          });
          if (PolicyService.getInstance().shouldBlock(SeverityLevel.HIGH, true)) {
            Logger.warn(`WorkerInstrument: blocked Worker(): ${targetDesc}`);
            NotificationService.showSecurityBlockingInfo(targetDesc, secEvent, BlockedOperationType.WORKER);
            throw new Error('Worker execution blocked by security policy');
          }
        }
      }

      return Reflect.construct(target, args, newTarget);
    },
  });

  Object.defineProperty(workerMod, '__workerPatched__', { value: true, configurable: false });
  Logger.info('WorkerInstrument: worker_threads.Worker patched');
}

export function patchVmExports(vmMod: any): void {
  if (!vmMod || vmMod.__vmPatched__) {
    return;
  }

  for (const fnName of ['runInNewContext', 'runInContext', 'runInThisContext', 'compileFunction']) {
    if (typeof vmMod[fnName] !== 'function') {
      continue;
    }
    const orig = vmMod[fnName].bind(vmMod);
    vmMod[fnName] = function patchedVmRun(code: string, ...rest: any[]): any {
      if (typeof code === 'string') {
        const res = evaluateDynamicCode(code, `vm.${fnName}`);
        if (res.blocked) {
          Logger.warn(`VmInstrument: blocked ${fnName}()`);
          throw new Error(res.message);
        }
      }
      return orig(code, ...rest);
    };
  }

  if (typeof vmMod.Script === 'function') {
    const OrigScript = vmMod.Script;
    vmMod.Script = new Proxy(OrigScript, {
      construct(target, args, newTarget) {
        const [code] = args;
        if (typeof code === 'string') {
          const res = evaluateDynamicCode(code, 'vm.Script');
          if (res.blocked) {
            Logger.warn('VmInstrument: blocked new vm.Script()');
            throw new Error(res.message);
          }
        }
        return Reflect.construct(target, args, newTarget);
      },
    });
  }

  Object.defineProperty(vmMod, '__vmPatched__', { value: true, configurable: false });
  Logger.info('VmInstrument: vm module patched');
}
