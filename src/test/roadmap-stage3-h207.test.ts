import { expect } from 'chai';
import { CorrelationEngine } from '../monitor/analysis/correlation-engine';

suite('Roadmap Stage 3B — H207 Multi-Store AI/IDE Session Theft', () => {
  setup(() => {
    CorrelationEngine.getInstance().clear();
    CorrelationEngine.getInstance().setWindowMs(60_000);
  });

  teardown(() => {
    CorrelationEngine.getInstance().clear();
  });

  test('1 store read does not trigger H207', () => {
    const engine = CorrelationEngine.getInstance();
    const match = engine.recordIdeTokenStoreRead(
      'ext.a',
      'vscode_state',
      '/home/user/.config/Code/User/globalStorage/state.vscdb',
      1000,
    );
    expect(match).to.be.null;
  });

  test('same store read twice within 60s does not trigger H207', () => {
    const engine = CorrelationEngine.getInstance();
    expect(
      engine.recordIdeTokenStoreRead(
        'ext.a',
        'vscode_state',
        '/home/user/.config/Code/User/globalStorage/state.vscdb',
        1000,
      ),
    ).to.be.null;
    expect(
      engine.recordIdeTokenStoreRead(
        'ext.a',
        'vscode_state',
        '/home/user/.config/Code/User/globalStorage/state.vscdb.backup',
        5000,
      ),
    ).to.be.null;
  });

  test('2 distinct stores within 60s triggers H207', () => {
    const engine = CorrelationEngine.getInstance();
    expect(
      engine.recordIdeTokenStoreRead(
        'ext.a',
        'vscode_state',
        '/home/user/.config/Code/User/globalStorage/state.vscdb',
        1000,
      ),
    ).to.be.null;

    const match = engine.recordIdeTokenStoreRead('ext.a', 'codex', '/home/user/.codex/auth.json', 30_000);
    expect(match).to.not.be.null;
    expect(match!.rule).to.equal('H207 Multi-Store AI/IDE Session Theft');
    expect(match!.sourceAccess.kind).to.equal('fs_sensitive_read');
    expect(match!.sourceAccess.detail).to.equal('/home/user/.codex/auth.json');
  });

  test('2 distinct stores >60s apart does not trigger H207', () => {
    const engine = CorrelationEngine.getInstance();
    expect(
      engine.recordIdeTokenStoreRead(
        'ext.a',
        'vscode_state',
        '/home/user/.config/Code/User/globalStorage/state.vscdb',
        1000,
      ),
    ).to.be.null;

    const match = engine.recordIdeTokenStoreRead('ext.a', 'codex', '/home/user/.codex/auth.json', 62_000);
    expect(match).to.be.null;
  });

  test('different extensions are isolated', () => {
    const engine = CorrelationEngine.getInstance();
    expect(
      engine.recordIdeTokenStoreRead(
        'ext.a',
        'vscode_state',
        '/home/user/.config/Code/User/globalStorage/state.vscdb',
        1000,
      ),
    ).to.be.null;
    expect(engine.recordIdeTokenStoreRead('ext.b', 'codex', '/home/user/.codex/auth.json', 2000)).to.be.null;
  });
});
