/**
 * Fetch Instrumentation - Patches globalThis.fetch to monitor and block
 * suspicious outbound HTTP/HTTPS requests made via the Fetch / Undici API.
 */

import { ExtensionInfo } from '../../lib/events/ext-events';
import { NetworkEvent, Protocol } from '../../lib/events/network-events';
import { Logger } from '../../lib/logger';
import { ExtensionServices } from '../../lib/services/ext-service';
import { IDEStatusService } from '../../lib/services/ide-status-service';
import { BlockedOperationType, NotificationService } from '../../lib/services/notification-service';
import { NetworkAnalyzer } from '../analysis/network-analyzer';

type FetchInput = string | URL | { url?: string; method?: string };

function extractFetchTarget(input: FetchInput, init?: RequestInit): { url: string; method: string } {
  let url = '';
  let method = init?.method || 'GET';
  if (typeof input === 'string') {
    url = input;
  } else if (input instanceof URL) {
    url = input.toString();
  } else if (input && typeof input === 'object' && 'url' in input) {
    url = String(input.url || '');
    if (!init?.method && typeof input.method === 'string') {
      method = input.method;
    }
  }
  return { url, method: method.toUpperCase() };
}

export function patchGlobalFetch(analyzer = new NetworkAnalyzer()): void {
  const g = globalThis as any;
  if (typeof g.fetch !== 'function' || g.fetch.__fetchPatched__) {
    return;
  }

  const origFetch = g.fetch.bind(globalThis);

  const patchedFetch = async function patchedFetch(input: FetchInput, init?: RequestInit): Promise<Response> {
    const { url, method } = extractFetchTarget(input, init);
    if (url) {
      const callContext = ExtensionServices.getCallContext();
      const extensionInfo = new ExtensionInfo(callContext.extension, true, Date.now());

      IDEStatusService.updatePatchedExtension(extensionInfo).catch((error) => {
        Logger.warn(`FetchInstrument: Failed to update extension status for ${extensionInfo.id}: ${error.message}`);
      });

      const protocol: Protocol = url.startsWith('http://') ? 'http' : 'https';
      const ev = new NetworkEvent(protocol, url, 'request:pre', __filename, extensionInfo, method);
      const analysis = analyzer.analyze(ev);

      if (analysis && !analysis.verdict.allowed && analysis.securityEvent) {
        Logger.warn(`FetchInstrument: blocked fetch(${method} ${Logger.truncate(url, 120)})`);
        NotificationService.showSecurityBlockingInfo(url, analysis.securityEvent, BlockedOperationType.FETCH);
        throw new TypeError(`Network request blocked by security policy: ${url}`);
      }
    }

    return origFetch(input, init);
  };

  Object.defineProperty(patchedFetch, '__fetchPatched__', { value: true, configurable: false });
  g.fetch = patchedFetch;
  Logger.info('FetchInstrument: globalThis.fetch patched');
}
