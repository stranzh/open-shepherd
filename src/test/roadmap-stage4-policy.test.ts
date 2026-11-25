import { expect } from 'chai';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  analyzePolicyImpact,
  auditEnterprisePolicies,
  generatePolicyFromGitOps,
  runPolicyCommand,
} from '../cli/policy';

suite('Stage 4A: Enterprise Policy CLI & GitOps', () => {
  let tmpDir: string;

  setup(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'open-shepherd-policy-'));
  });

  teardown(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('auditEnterprisePolicies flags missing or permissive settings', () => {
    const linuxPath = path.join(tmpDir, 'linux-policy.json');
    fs.writeFileSync(
      linuxPath,
      JSON.stringify({
        AllowedExtensions: '*',
        ChatMCP: true,
        ChatAllowManagedMcpServersOnly: false,
        ChatAllowManagedHooksOnly: false,
        TelemetryLevel: 'all',
        RemoteTunnelAccess: true,
      }),
    );

    const result = auditEnterprisePolicies({
      linuxPolicyPath: linuxPath,
      macosPolicyPath: path.join(tmpDir, 'nonexistent-macos.json'),
    });

    expect(result.findings.length).to.equal(6);
    const ruleIds = result.findings.map((f) => f.ruleId);
    expect(ruleIds).to.include('POLICY-ALLOWED-EXTENSIONS');
    expect(ruleIds).to.include('POLICY-CHAT-MCP');
    expect(ruleIds).to.include('POLICY-MANAGED-MCP-ONLY');
    expect(ruleIds).to.include('POLICY-MANAGED-HOOKS-ONLY');
    expect(ruleIds).to.include('POLICY-TELEMETRY-LEVEL');
    expect(ruleIds).to.include('POLICY-REMOTE-TUNNEL');
  });

  test('auditEnterprisePolicies passes cleanly when hardened', () => {
    const result = auditEnterprisePolicies({
      linuxPolicyPath: path.join(tmpDir, 'missing.json'),
      macosPolicyPath: path.join(tmpDir, 'missing-mac.json'),
      winPolicies: {
        AllowedExtensions: { '*': false, 'ms-vscode': true },
        ChatMCP: 'disabled',
        ChatAllowManagedMcpServersOnly: true,
        ChatAllowManagedHooksOnly: true,
        TelemetryLevel: 'off',
        RemoteTunnelAccess: false,
      },
    });

    expect(result.findings).to.have.lengthOf(0);
  });

  test('analyzePolicyImpact diffs installed extensions against allowlist', () => {
    const allowlistPath = path.join(tmpDir, 'allowlist.txt');
    fs.writeFileSync(allowlistPath, '# comment\nms-vscode\nesbenp.prettier-vscode\n');

    const vscodeExtDir = path.join(tmpDir, '.vscode', 'extensions');
    fs.mkdirSync(path.join(vscodeExtDir, 'ms-vscode.cpptools-1.0.0'), { recursive: true });
    fs.mkdirSync(path.join(vscodeExtDir, 'esbenp.prettier-vscode-10.0.0'), { recursive: true });
    fs.mkdirSync(path.join(vscodeExtDir, 'evil.mcp-server-0.1.0'), { recursive: true });

    const impact = analyzePolicyImpact(allowlistPath, { homeDir: tmpDir });

    expect(impact.allowed).to.deep.equal(['esbenp.prettier-vscode', 'ms-vscode.cpptools']);
    expect(impact.blocked).to.deep.equal(['evil.mcp-server']);
    expect(impact.mcpBlocked).to.deep.equal(['evil.mcp-server']);
  });

  test('generatePolicyFromGitOps builds vscodePolicy and admxPolicy', () => {
    const gitopsDir = path.join(tmpDir, 'gitops');
    fs.mkdirSync(gitopsDir, { recursive: true });
    fs.writeFileSync(path.join(gitopsDir, 'allowed_publishers.txt'), '# pubs\nms-vscode\n');
    fs.writeFileSync(path.join(gitopsDir, 'allowed_extensions.txt'), 'esbenp.prettier-vscode\n');
    fs.writeFileSync(path.join(gitopsDir, 'disallowed_extensions.txt'), 'ms-vscode.remote-explorer\n');

    const bundle = generatePolicyFromGitOps(gitopsDir);

    expect(bundle.vscodePolicy.AllowedExtensions).to.deep.equal({
      '*': false,
      'ms-vscode': true,
      'esbenp.prettier-vscode': true,
      'ms-vscode.remote-explorer': false,
    });
    expect(bundle.vscodePolicy.ChatAllowManagedMcpServersOnly).to.equal(true);
    expect(bundle.admxPolicy.ChatAllowManagedMcpServersOnly).to.equal(1);
    expect(bundle.admxPolicy.RemoteTunnelAccess).to.equal(0);
  });

  test('runPolicyCommand handles --help, generate, impact, and invalid args', async () => {
    const stdoutChunks: string[] = [];
    const stderrChunks: string[] = [];
    const io = {
      stdout: (s: string) => stdoutChunks.push(s),
      stderr: (s: string) => stderrChunks.push(s),
      homeDir: tmpDir,
    };

    const helpCode = await runPolicyCommand(['--help'], io);
    expect(helpCode).to.equal(0);
    expect(stdoutChunks.join('')).to.include('Usage: open-shepherd policy');

    const badCode = await runPolicyCommand(['impact'], io);
    expect(badCode).to.equal(2);
    expect(stderrChunks.join('')).to.include('--allowlist');

    const gitopsDir = path.join(tmpDir, 'gitops-cli');
    fs.mkdirSync(gitopsDir, { recursive: true });
    fs.writeFileSync(path.join(gitopsDir, 'allowed_publishers.txt'), 'ms-vscode\n');

    stdoutChunks.length = 0;
    const genCode = await runPolicyCommand(['generate', gitopsDir], io);
    expect(genCode).to.equal(0);
    const parsed = JSON.parse(stdoutChunks.join('')) as { vscodePolicy: Record<string, unknown> };
    expect(parsed.vscodePolicy).to.have.property('AllowedExtensions');
  });
});
