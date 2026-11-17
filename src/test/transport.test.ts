import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { emitEvent } from '../lib/transport';

suite('Transport Tests', () => {
  test('emitEvent writes valid JSONL line to custom logPath', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'open-shepherd-test-'));
    const logPath = path.join(tmpDir, 'events.jsonl');

    try {
      emitEvent(
        { source: 'vscode', event_type: 'READ', severity: 'high', details: { rule: 'SSH Private Key Read' } },
        { logPath },
      );

      const line = fs.readFileSync(logPath, 'utf8').trim();
      const parsed = JSON.parse(line);
      assert.strictEqual(parsed.source, 'vscode');
      assert.strictEqual(parsed.event_type, 'READ');
      assert.strictEqual(parsed.severity, 'high');
      assert.strictEqual(parsed.details.rule, 'SSH Private Key Read');
      assert.ok(parsed.timestamp);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
