/**
 * Socket & DNS Instrumentation - Hooks net, tls, and dns modules to detect
 * raw TCP/TLS bypasses, SSRF connections, and DNS tunneling/exfiltration.
 */

import { EventEmitter } from 'events';
import { ExtensionInfo } from '../../lib/events/ext-events';
import { NetworkEvent, Protocol } from '../../lib/events/network-events';
import { NetworkRuleType, isSuspiciousDnsQuery } from '../../detection/network-rules';
import { SecurityEvent, SeverityLevel } from '../../lib/events/sec-events';
import { Logger } from '../../lib/logger';
import { AllowListService } from '../../lib/services/allowlist-service';
import { ExtensionServices } from '../../lib/services/ext-service';
import { IDEStatusService } from '../../lib/services/ide-status-service';
import { BlockedOperationType, NotificationService } from '../../lib/services/notification-service';
import { PolicyService } from '../../lib/services/policy-service';
import { NetworkAnalyzer } from '../analysis/network-analyzer';

function createBlockedSocket(message: string): any {
  const sock = new EventEmitter() as any;
  sock.destroyed = true;
  sock.writable = false;
  sock.readable = false;
  sock.write = () => false;
  sock.end = () => sock;
  sock.destroy = () => sock;
  sock.unref = () => sock;
  sock.ref = () => sock;
  sock.setTimeout = () => sock;
  process.nextTick(() => {
    if (sock.listenerCount('error') > 0) {
      sock.emit('error', new Error(message));
    }
  });
  return sock;
}

function extractHostPort(args: any[]): { host: string; port?: number } {
  const first = args[0];
  if (typeof first === 'number') {
    const second = args[1];
    if (typeof second === 'string') {
      return { host: second, port: first };
    }
    if (second && typeof second === 'object') {
      return { host: String(second.host || second.hostname || second.path || 'localhost'), port: first };
    }
    return { host: 'localhost', port: first };
  }
  if (typeof first === 'string') {
    if (/^\d+$/.test(first) && typeof args[1] === 'string') {
      return { host: args[1], port: Number(first) };
    }
    return { host: first };
  }
  if (first && typeof first === 'object') {
    return { host: String(first.host || first.hostname || first.path || 'localhost'), port: first.port };
  }
  return { host: 'localhost' };
}

function evaluateSocketConnect(
  args: any[],
  protocol: Protocol,
  label: string,
  methodName: string,
  analyzer: NetworkAnalyzer,
): string | null {
  const { host, port } = extractHostPort(args);
  const url = `${protocol}://${host}${port ? `:${port}` : ''}`;
  const callContext = ExtensionServices.getCallContext();
  const extensionInfo = new ExtensionInfo(callContext.extension, true, Date.now());

  const ev = new NetworkEvent(protocol, url, 'request:pre', __filename, extensionInfo, 'CONNECT');
  const analysis = analyzer.analyze(ev);
  if (analysis && !analysis.verdict.allowed && analysis.securityEvent) {
    Logger.warn(`${label}: blocked ${methodName}() to ${Logger.truncate(url, 120)}`);
    NotificationService.showSecurityBlockingInfo(url, analysis.securityEvent, BlockedOperationType.SOCKET);
    return `Socket connection blocked by security policy: ${url}`;
  }
  return null;
}

function patchSocketModule(mod: any, protocol: Protocol, label: string, analyzer: NetworkAnalyzer): void {
  if (!mod || mod.__socketPatched__) {
    return;
  }

  let inTopLevelConnect = false;

  for (const methodName of ['connect', 'createConnection']) {
    if (typeof mod[methodName] !== 'function') {
      continue;
    }
    const orig = mod[methodName].bind(mod);
    mod[methodName] = function patchedConnect(...args: any[]): any {
      const blockedMsg = evaluateSocketConnect(args, protocol, label, methodName, analyzer);
      if (blockedMsg) {
        return createBlockedSocket(blockedMsg);
      }
      inTopLevelConnect = true;
      try {
        return orig(...args);
      } finally {
        inTopLevelConnect = false;
      }
    };
  }

  const sockProto = mod.Socket?.prototype;
  if (sockProto && typeof sockProto.connect === 'function' && !sockProto.__socketConnectPatched__) {
    const origProtoConnect = sockProto.connect;
    sockProto.connect = function patchedProtoConnect(this: any, ...args: any[]): any {
      if (!inTopLevelConnect) {
        const blockedMsg = evaluateSocketConnect(args, protocol, label, 'Socket.connect', analyzer);
        if (blockedMsg) {
          process.nextTick(() => {
            if (typeof this.listenerCount === 'function' && this.listenerCount('error') > 0) {
              this.emit('error', new Error(blockedMsg));
            }
          });
          return this;
        }
      }
      return origProtoConnect.apply(this, args);
    };
    Object.defineProperty(sockProto, '__socketConnectPatched__', { value: true, configurable: false });
  }

  Object.defineProperty(mod, '__socketPatched__', { value: true, configurable: false });
  Logger.info(`${label}: socket instrumentation applied`);
}

export function patchNetExports(netMod: any, analyzer = new NetworkAnalyzer()): void {
  patchSocketModule(netMod, 'http', 'NetInstrument', analyzer);
}

export function patchTlsExports(tlsMod: any, analyzer = new NetworkAnalyzer()): void {
  patchSocketModule(tlsMod, 'https', 'TlsInstrument', analyzer);
}

function checkDnsQuery(hostname: string, analyzer: NetworkAnalyzer): { blocked: boolean; reason?: string } {
  const callContext = ExtensionServices.getCallContext();
  const extensionInfo = new ExtensionInfo(callContext.extension, true, Date.now());
  const url = `https://${hostname}`;

  const analysis = analyzer.analyze(new NetworkEvent('https', url, 'request:pre', __filename, extensionInfo, 'DNS'));
  if (analysis && !analysis.verdict.allowed && analysis.securityEvent) {
    NotificationService.showSecurityBlockingInfo(hostname, analysis.securityEvent, BlockedOperationType.DNS);
    return { blocked: true, reason: `DNS lookup blocked by security policy: ${hostname}` };
  }

  const tunnelReason = isSuspiciousDnsQuery(hostname);
  if (tunnelReason && !AllowListService.getInstance().isAllowed(extensionInfo.id)) {
    const ev = new NetworkEvent('https', url, 'request:pre', __filename, extensionInfo, 'DNS');
    const secEvent = new SecurityEvent(ev, extensionInfo, SeverityLevel.HIGH, NetworkRuleType.DNS, [
      {
        finding: hostname,
        rule: 'Suspicious DNS Tunneling Query',
        description: tunnelReason,
        confidence: 0.9,
        severity: SeverityLevel.HIGH,
      },
    ]);
    IDEStatusService.emitSecurityEvent(secEvent).catch((err) => {
      Logger.error(`DnsInstrument: Failed to emit security event: ${err.message}`);
    });
    if (PolicyService.getInstance().shouldBlock(SeverityLevel.HIGH, true)) {
      NotificationService.showSecurityBlockingInfo(hostname, secEvent, BlockedOperationType.DNS);
      return { blocked: true, reason: `DNS tunneling query blocked by security policy: ${hostname}` };
    }
  }

  return { blocked: false };
}

export function patchDnsExports(dnsMod: any, analyzer = new NetworkAnalyzer()): void {
  if (!dnsMod || dnsMod.__dnsPatched__) {
    return;
  }

  for (const fnName of ['lookup', 'resolve', 'resolve4', 'resolve6', 'resolveTxt']) {
    if (typeof dnsMod[fnName] !== 'function') {
      continue;
    }
    const orig = dnsMod[fnName].bind(dnsMod);
    dnsMod[fnName] = function patchedDnsFn(hostname: string, ...rest: any[]): any {
      if (typeof hostname === 'string') {
        const res = checkDnsQuery(hostname, analyzer);
        if (res.blocked) {
          Logger.warn(`DnsInstrument: blocked ${fnName}(${Logger.truncate(hostname, 120)})`);
          const cb = rest[rest.length - 1];
          if (typeof cb === 'function') {
            process.nextTick(() => cb(new Error(res.reason)));
          }
          return;
        }
      }
      return orig(hostname, ...rest);
    };
  }

  if (dnsMod.promises && !dnsMod.promises.__dnsPatched__) {
    for (const fnName of ['lookup', 'resolve', 'resolve4', 'resolve6', 'resolveTxt']) {
      if (typeof dnsMod.promises[fnName] !== 'function') {
        continue;
      }
      const orig = dnsMod.promises[fnName].bind(dnsMod.promises);
      dnsMod.promises[fnName] = async function patchedDnsPromise(hostname: string, ...rest: any[]): Promise<any> {
        if (typeof hostname === 'string') {
          const res = checkDnsQuery(hostname, analyzer);
          if (res.blocked) {
            Logger.warn(`DnsInstrument: blocked promises.${fnName}(${Logger.truncate(hostname, 120)})`);
            throw new Error(res.reason);
          }
        }
        return orig(hostname, ...rest);
      };
    }
    Object.defineProperty(dnsMod.promises, '__dnsPatched__', { value: true, configurable: false });
  }

  Object.defineProperty(dnsMod, '__dnsPatched__', { value: true, configurable: false });
  Logger.info('DnsInstrument: dns module patched');
}
