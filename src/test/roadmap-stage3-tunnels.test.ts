import { expect } from 'chai';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { EXTRA_PROCESS_RULES } from '../detection/process-rules-extra';
import { EXTRA_NETWORK_RULES } from '../detection/network-rules-extra';
import { scanTunnelPersistence } from '../cli/tunnel-persistence';
import { SeverityLevel } from '../lib/events/sec-events';
import { WorkspaceRuleType } from '../detection/workspace-rule-types';

suite('Roadmap Stage 3A - IDE Remote Tunnels', () => {
  test('EXTRA_PROCESS_RULES detects IDE remote tunnel LOLRMM execution', () => {
    const rule = EXTRA_PROCESS_RULES.find((r) => r.id === 'ide_remote_tunnel_execution');
    expect(rule).to.exist;
    expect(rule!.severity).to.equal(SeverityLevel.HIGH);
    expect(rule!.confidence).to.equal(0.95);

    const positives = [
      'code tunnel service install --accept-server-license-terms',
      'cursor.exe tunnel internal-run',
      'code-insiders tunnel --accept-server-license-terms',
      'windsurf tunnel service install',
      'code-tunnel.exe tunnel internal-run',
    ];
    for (const cmd of positives) {
      expect(rule!.commandPattern!.test(cmd), `expected match for: ${cmd}`).to.equal(true);
    }

    const negatives = ['code --version', 'cursor /tmp/project', 'ssh -L 8080:localhost:8080 user@host'];
    for (const cmd of negatives) {
      expect(rule!.commandPattern!.test(cmd), `expected no match for: ${cmd}`).to.equal(false);
    }
  });

  test('EXTRA_NETWORK_RULES detects Microsoft DevTunnel endpoints', () => {
    const rule = EXTRA_NETWORK_RULES.find((r) => r.id === 'ide_devtunnel_endpoint');
    expect(rule).to.exist;
    expect(rule!.severity).to.equal(SeverityLevel.HIGH);
    expect(rule!.confidence).to.equal(0.95);

    const positives = [
      'https://global.rel.tunnels.api.visualstudio.com/api/v1/tunnels',
      'https://abc123.use.devtunnels.ms:443/',
      'tunnels.api.visualstudio.com',
      'devtunnels.ms',
    ];
    for (const url of positives) {
      expect(rule!.pattern.test(url), `expected match for: ${url}`).to.equal(true);
    }

    const negatives = ['https://example.com/devtunnels', 'https://github.com/microsoft/vscode'];
    for (const url of negatives) {
      expect(rule!.pattern.test(url), `expected no match for: ${url}`).to.equal(false);
    }
  });

  test('scanTunnelPersistence detects systemd, LaunchAgents, CLI artifacts, and Windows Run entries', () => {
    const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'shepherd-tunnel-'));
    try {
      const systemdDir = path.join(tmpHome, '.config', 'systemd', 'user');
      fs.mkdirSync(systemdDir, { recursive: true });
      fs.writeFileSync(path.join(systemdDir, 'code-tunnel.service'), '[Service]\nExecStart=/usr/bin/code tunnel\n');

      const launchDir = path.join(tmpHome, 'Library', 'LaunchAgents');
      fs.mkdirSync(launchDir, { recursive: true });
      fs.writeFileSync(path.join(launchDir, 'com.visualstudio.code.tunnel.plist'), '<plist/>');

      const vscodeCliDir = path.join(tmpHome, '.vscode-cli');
      fs.mkdirSync(vscodeCliDir, { recursive: true });
      fs.writeFileSync(path.join(vscodeCliDir, 'code_tunnel.json'), '{}');
      fs.writeFileSync(path.join(vscodeCliDir, 'tunnel-service.log'), 'started');

      const cursorCliDir = path.join(tmpHome, '.cursor-cli');
      fs.mkdirSync(cursorCliDir, { recursive: true });
      fs.writeFileSync(path.join(cursorCliDir, 'code_tunnel.json'), '{}');

      const findings = scanTunnelPersistence(tmpHome, {
        winRunEntries: {
          CodeTunnel: 'C:\\Users\\dev\\code-tunnel.exe service internal-run',
          BenignApp: 'C:\\Program Files\\App\\app.exe',
        },
      });

      expect(findings).to.have.lengthOf(6);
      for (const finding of findings) {
        expect(finding.ruleId).to.equal('ide_tunnel_persistence_detected');
        expect(finding.type).to.equal(WorkspaceRuleType.AGENT_RULES);
        expect(finding.severity).to.equal(SeverityLevel.HIGH);
      }
    } finally {
      fs.rmSync(tmpHome, { recursive: true, force: true });
    }
  });

  test('ignores unrelated non-IDE tunnel services such as ssh-tunnel.service', () => {
    const homeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'os-tunnel-nonide-'));
    try {
      const systemdDir = path.join(homeDir, '.config', 'systemd', 'user');
      fs.mkdirSync(systemdDir, { recursive: true });
      fs.writeFileSync(
        path.join(systemdDir, 'ssh-tunnel.service'),
        '[Service]\nExecStart=/usr/bin/ssh -N -L 8080:localhost:80 host\n',
      );
      expect(scanTunnelPersistence(homeDir)).to.have.lengthOf(0);
    } finally {
      fs.rmSync(homeDir, { recursive: true, force: true });
    }
  });
});
