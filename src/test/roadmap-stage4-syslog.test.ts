import { expect } from 'chai';
import * as dgram from 'dgram';
import * as net from 'net';
import { formatRfc5424Message, parseSyslogEndpoint, sendSyslogPayload } from '../lib/services/syslog-transport';

suite('Roadmap Stage 4C - Syslog Transport', () => {
  test('parseSyslogEndpoint parses udp, tcp, and tls endpoints', () => {
    expect(parseSyslogEndpoint('udp://127.0.0.1:514')).to.deep.equal({ protocol: 'udp', host: '127.0.0.1', port: 514 });
    expect(parseSyslogEndpoint('tcp://logs.example.com:1514')).to.deep.equal({
      protocol: 'tcp',
      host: 'logs.example.com',
      port: 1514,
    });
    expect(parseSyslogEndpoint('TLS://siem.internal:6514')).to.deep.equal({
      protocol: 'tls',
      host: 'siem.internal',
      port: 6514,
    });
  });

  test('parseSyslogEndpoint throws on invalid protocol, host, or port', () => {
    expect(() => parseSyslogEndpoint('')).to.throw();
    expect(() => parseSyslogEndpoint('http://127.0.0.1:514')).to.throw();
    expect(() => parseSyslogEndpoint('udp://:514')).to.throw();
    expect(() => parseSyslogEndpoint('tcp://127.0.0.1')).to.throw();
    expect(() => parseSyslogEndpoint('tcp://127.0.0.1:0')).to.throw();
    expect(() => parseSyslogEndpoint('tls://127.0.0.1:70000')).to.throw();
  });

  test('formatRfc5424Message formats <PRI>1 TIMESTAMP HOSTNAME APP-NAME - - - PAYLOAD', () => {
    const formatted = formatRfc5424Message('agent completed', {
      facility: 16,
      severity: 6,
      timestamp: '2026-01-01T00:00:00.000Z',
      hostname: 'shepherd-host',
      appName: 'open-shepherd',
    });

    expect(formatted).to.equal('<134>1 2026-01-01T00:00:00.000Z shepherd-host open-shepherd - - - agent completed');
  });

  test('sendSyslogPayload skips socket creation when all lines are empty', async () => {
    await sendSyslogPayload('udp://127.0.0.1:65534', ['', '   ']);
  });

  test('sendSyslogPayload delivers non-empty lines over UDP loopback', async () => {
    const received: string[] = [];
    const server = dgram.createSocket('udp4');

    await new Promise<void>((resolve) => {
      server.on('message', (msg) => {
        received.push(msg.toString('utf8'));
      });
      server.bind(0, '127.0.0.1', () => resolve());
    });

    try {
      const address = server.address();
      if (typeof address === 'string') {
        throw new Error('Unexpected string address for UDP socket');
      }

      await sendSyslogPayload(`udp://127.0.0.1:${address.port}`, ['line one', '', 'line two'], {
        appName: 'shepherd-test',
        facility: 1,
        severity: 5,
      });

      await new Promise<void>((resolve) => setTimeout(resolve, 50));

      expect(received).to.have.lengthOf(2);
      expect(received[0]).to.include('<13>1 ');
      expect(received[0]).to.include(' shepherd-test - - - line one');
      expect(received[1]).to.include(' shepherd-test - - - line two');
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  test('sendSyslogPayload delivers non-empty lines over TCP loopback', async () => {
    const chunks: string[] = [];
    const server = net.createServer((socket) => {
      socket.on('data', (data) => {
        chunks.push(data.toString('utf8'));
      });
    });

    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => resolve());
    });

    try {
      const address = server.address();
      if (!address || typeof address === 'string') {
        throw new Error('Unexpected address for TCP server');
      }

      await sendSyslogPayload(`tcp://127.0.0.1:${address.port}`, ['tcp event 1', 'tcp event 2'], {
        appName: 'shepherd-tcp',
        facility: 16,
        severity: 6,
      });

      await new Promise<void>((resolve) => setTimeout(resolve, 50));

      const combined = chunks.join('');
      const lines = combined.trim().split('\n');
      expect(lines).to.have.lengthOf(2);
      expect(lines[0]).to.include('<134>1 ');
      expect(lines[0]).to.include(' shepherd-tcp - - - tcp event 1');
      expect(lines[1]).to.include(' shepherd-tcp - - - tcp event 2');
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
