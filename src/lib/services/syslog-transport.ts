import * as dgram from 'dgram';
import * as net from 'net';
import * as os from 'os';
import * as tls from 'tls';

export type SyslogProtocol = 'udp' | 'tcp' | 'tls';

export interface SyslogEndpoint {
  protocol: SyslogProtocol;
  host: string;
  port: number;
}

export interface Rfc5424Options {
  facility?: number;
  severity?: number;
  appName?: string;
  hostname?: string;
  timestamp?: string;
}

export interface SendSyslogOptions {
  timeoutMs?: number;
  appName?: string;
  facility?: number;
  severity?: number;
}

const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_FACILITY = 16; // local0
const DEFAULT_SEVERITY = 6; // informational

export function parseSyslogEndpoint(endpoint: string): SyslogEndpoint {
  if (typeof endpoint !== 'string' || endpoint.trim().length === 0) {
    throw new Error('Syslog endpoint must be a non-empty string');
  }

  const trimmed = endpoint.trim();
  const match = /^(udp|tcp|tls):\/\/(\[[^\]]+\]|[^/:]+):(\d+)$/i.exec(trimmed);
  if (!match) {
    throw new Error(`Invalid syslog endpoint: ${endpoint}`);
  }

  const protocol = match[1].toLowerCase() as SyslogProtocol;
  const rawHost = match[2].trim();
  const host = rawHost.startsWith('[') && rawHost.endsWith(']') ? rawHost.slice(1, -1) : rawHost;
  const port = Number.parseInt(match[3], 10);

  if (!host) {
    throw new Error(`Invalid syslog host in endpoint: ${endpoint}`);
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`Invalid syslog port in endpoint: ${endpoint}`);
  }

  return { protocol, host, port };
}

export function formatRfc5424Message(payload: string, options?: Rfc5424Options): string {
  const facility = options?.facility ?? DEFAULT_FACILITY;
  const severity = options?.severity ?? DEFAULT_SEVERITY;
  const pri = Math.max(0, Math.floor(facility) * 8 + Math.floor(severity));
  const timestamp = options?.timestamp ?? new Date().toISOString();
  const hostname = (options?.hostname ?? os.hostname()) || '-';
  const appName = options?.appName ?? 'open-shepherd';

  return `<${pri}>1 ${timestamp} ${hostname} ${appName} - - - ${payload}`;
}

export async function sendSyslogPayload(endpoint: string, lines: string[], options?: SendSyslogOptions): Promise<void> {
  const parsed = parseSyslogEndpoint(endpoint);
  const nonEmptyLines = lines.filter((line) => line.trim().length > 0);
  if (nonEmptyLines.length === 0) {
    return;
  }

  const timeoutMs = options?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const messages = nonEmptyLines.map((line) =>
    formatRfc5424Message(line, { appName: options?.appName, facility: options?.facility, severity: options?.severity }),
  );

  if (parsed.protocol === 'udp') {
    await sendUdpMessages(parsed.host, parsed.port, messages, timeoutMs);
    return;
  }

  await sendStreamMessages(parsed.protocol, parsed.host, parsed.port, messages, timeoutMs);
}

function sendUdpMessages(host: string, port: number, messages: string[], timeoutMs: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket(net.isIPv6(host) ? 'udp6' : 'udp4');
    let settled = false;

    const cleanup = () => {
      clearTimeout(timer);
      try {
        socket.close();
      } catch {
        // Ignore close errors if already closed.
      }
    };

    const fail = (err: Error) => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      reject(err);
    };

    const timer = setTimeout(() => {
      fail(new Error(`Syslog UDP send timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    socket.once('error', (err) => {
      fail(err);
    });

    let index = 0;
    const sendNext = () => {
      if (settled) {
        return;
      }
      if (index >= messages.length) {
        settled = true;
        cleanup();
        resolve();
        return;
      }

      const buf = Buffer.from(messages[index], 'utf8');
      index += 1;
      socket.send(buf, port, host, (err) => {
        if (err) {
          fail(err);
          return;
        }
        sendNext();
      });
    };

    sendNext();
  });
}

function sendStreamMessages(
  protocol: 'tcp' | 'tls',
  host: string,
  port: number,
  messages: string[],
  timeoutMs: number,
): Promise<void> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const socket: net.Socket = protocol === 'tls' ? tls.connect({ host, port }) : net.createConnection({ host, port });

    const cleanup = () => {
      clearTimeout(timer);
      socket.removeAllListeners();
      if (!socket.destroyed) {
        socket.destroy();
      }
    };

    const fail = (err: Error) => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      reject(err);
    };

    const timer = setTimeout(() => {
      fail(new Error(`Syslog ${protocol.toUpperCase()} send timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    socket.once('error', (err) => {
      fail(err);
    });

    const connectEvent = protocol === 'tls' ? 'secureConnect' : 'connect';
    socket.once(connectEvent, () => {
      if (settled) {
        return;
      }
      const payload = messages.map((msg) => `${msg}\n`).join('');
      socket.end(payload, 'utf8', () => {
        if (settled) {
          return;
        }
        settled = true;
        cleanup();
        resolve();
      });
    });
  });
}
