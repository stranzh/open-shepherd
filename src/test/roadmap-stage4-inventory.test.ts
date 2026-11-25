import { expect } from 'chai';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { scanDownloadsInstructionFiles } from '../cli/downloads-guard';
import { collectIdeInventory, formatInventoryOcsf } from '../cli/inventory';
import { WorkspaceRuleType } from '../detection/workspace-rule-types';
import { SeverityLevel } from '../lib/events/sec-events';

suite('Stage 4B: Agent Guardrails & Host Inventory', () => {
  let tmpHome: string;

  setup(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'shepherd-stage4b-'));
  });

  teardown(() => {
    fs.rmSync(tmpHome, { recursive: true, force: true });
  });

  suite('shepherd-hook.mjs cwd guardrail', () => {
    const hookPath = path.resolve(__dirname, '../../agent-hooks/shepherd-hook.mjs');

    function runHook(cwd: string, mode: 'enforce' | 'audit' = 'enforce') {
      const logFile = path.join(tmpHome, 'events.jsonl');
      const payload = JSON.stringify({
        hook_event_name: 'PreToolUse',
        tool_name: 'Bash',
        tool_input: { command: 'ls -la' },
        cwd,
      });

      const res = spawnSync(process.execPath, [hookPath], {
        input: payload,
        encoding: 'utf8',
        env: { ...process.env, OPEN_SHEPHERD_HOME: tmpHome, OPEN_SHEPHERD_LOG: logFile, OPEN_SHEPHERD_MODE: mode },
      });

      return { res, logFile };
    }

    test('blocks PreToolUse when cwd equals OPEN_SHEPHERD_HOME in enforce mode', () => {
      const { res } = runHook(tmpHome, 'enforce');
      expect(res.status).to.equal(0);
      const out = JSON.parse(res.stdout.trim());
      expect(out.hookSpecificOutput.permissionDecision).to.equal('deny');
      expect(out.hookSpecificOutput.permissionDecisionReason).to.include('nono.sh');
    });

    test('blocks PreToolUse when cwd equals ~/Downloads in enforce mode', () => {
      const downloadsDir = path.join(tmpHome, 'Downloads');
      fs.mkdirSync(downloadsDir, { recursive: true });
      const { res } = runHook(downloadsDir, 'enforce');
      expect(res.status).to.equal(0);
      const out = JSON.parse(res.stdout.trim());
      expect(out.hookSpecificOutput.permissionDecision).to.equal('deny');
      expect(out.hookSpecificOutput.permissionDecisionReason).to.include('nono.sh');
    });

    test('logs audit decision without blocking in audit mode', () => {
      const { res, logFile } = runHook(tmpHome, 'audit');
      expect(res.status).to.equal(0);
      expect(res.stdout.trim()).to.equal('');
      const logged = JSON.parse(fs.readFileSync(logFile, 'utf8').trim());
      expect(logged.details.decision).to.equal('audit');
      expect(logged.details.reason).to.include('nono.sh');
    });

    test('allows PreToolUse when cwd is a project subdirectory', () => {
      const projectDir = path.join(tmpHome, 'projects', 'my-app');
      fs.mkdirSync(projectDir, { recursive: true });
      const { res, logFile } = runHook(projectDir, 'enforce');
      expect(res.status).to.equal(0);
      expect(res.stdout.trim()).to.equal('');
      const logged = JSON.parse(fs.readFileSync(logFile, 'utf8').trim());
      expect(logged.details.decision).to.equal('allow');
    });
  });

  suite('scanDownloadsInstructionFiles', () => {
    test('detects agent instruction and MCP files in ~/Downloads', () => {
      const downloadsDir = path.join(tmpHome, 'Downloads');
      fs.mkdirSync(downloadsDir, { recursive: true });
      fs.writeFileSync(path.join(downloadsDir, 'CLAUDE.md'), '# malicious instructions', 'utf8');
      fs.writeFileSync(path.join(downloadsDir, '.mcp.json'), '{}', 'utf8');
      fs.writeFileSync(path.join(downloadsDir, 'notes.txt'), 'harmless', 'utf8');

      const findings = scanDownloadsInstructionFiles(tmpHome);
      expect(findings).to.have.lengthOf(2);
      for (const f of findings) {
        expect(f.ruleId).to.equal('downloads_dir_agent_instructions');
        expect(f.type).to.equal(WorkspaceRuleType.AGENT_RULES);
        expect(f.severity).to.equal(SeverityLevel.HIGH);
      }
    });

    test('returns empty array when ~/Downloads does not exist', () => {
      expect(scanDownloadsInstructionFiles(tmpHome)).to.deep.equal([]);
    });
  });

  suite('collectIdeInventory & formatInventoryOcsf', () => {
    test('enumerates installed IDEs and extensions and formats OCSF 5001 JSONL', () => {
      const vscodeExtDir = path.join(tmpHome, '.vscode', 'extensions', 'pub.sample-ext-1.0.0');
      fs.mkdirSync(vscodeExtDir, { recursive: true });
      fs.writeFileSync(
        path.join(vscodeExtDir, 'package.json'),
        JSON.stringify({ name: 'sample-ext', publisher: 'pub', version: '1.0.0' }),
        'utf8',
      );

      const cursorDir = path.join(tmpHome, '.cursor');
      fs.mkdirSync(cursorDir, { recursive: true });

      const inventory = collectIdeInventory(tmpHome);
      const ideIds = inventory.ides.map((i) => i.id);
      expect(ideIds).to.include('vscode');
      expect(ideIds).to.include('cursor');

      expect(inventory.extensions).to.have.lengthOf(1);
      expect(inventory.extensions[0].id).to.equal('pub.sample-ext');
      expect(inventory.extensions[0].version).to.equal('1.0.0');

      const ocsf = formatInventoryOcsf(inventory);
      const lines = ocsf.split('\n').filter(Boolean);
      expect(lines.length).to.be.at.least(3);
      for (const line of lines) {
        const parsed = JSON.parse(line);
        expect(parsed.class_uid).to.equal(5001);
        expect(parsed.category_uid).to.equal(5);
        expect(parsed.activity_id).to.equal(2);
      }
    });
  });
});
