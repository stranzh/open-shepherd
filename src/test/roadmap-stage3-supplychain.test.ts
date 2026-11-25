import { expect } from 'chai';
import * as sinon from 'sinon';
import * as vscode from 'vscode';
import { IntegrityRuleType, SecurityEvent, SeverityLevel } from '../lib/events/sec-events';
import { Extension, ExtensionsRepository } from '../lib/extensions';
import { Logger } from '../lib/logger';
import { AgeHoldService } from '../lib/services/age-hold-service';
import { IDEStatusService } from '../lib/services/ide-status-service';
import { RevocationService } from '../lib/services/revocation-service';

function makeMockContext(initialState: Record<string, unknown> = {}): vscode.ExtensionContext {
  const store = new Map<string, unknown>(Object.entries(initialState));
  return {
    globalState: {
      get: <T>(key: string) => store.get(key) as T | undefined,
      update: async (key: string, value: unknown) => {
        store.set(key, value);
      },
      keys: () => Array.from(store.keys()),
      setKeysForSync: () => {},
    },
    subscriptions: [],
  } as unknown as vscode.ExtensionContext;
}

function makeExtension(displayName: string, version = '1.0.0'): Extension {
  const [publisher, name] = displayName.split('.');
  return {
    id: `${displayName}-${version}`,
    displayName,
    isActive: true,
    isBuiltIn: false,
    extensionPath: `/tmp/ext/${displayName}`,
    packageJSON: { publisher, name, version },
  };
}

suite('Roadmap Stage 3C - Supply Chain Services (Age-Hold & Revocation)', () => {
  let sandbox: sinon.SinonSandbox;

  setup(() => {
    sandbox = sinon.createSandbox();
  });

  teardown(() => {
    sandbox.restore();
  });

  suite('AgeHoldService', () => {
    test('emits MEDIUM SecurityEvent and warns when extension was updated within 48h', async () => {
      const now = 1_700_000_000_000;
      const twoHoursAgoIso = new Date(now - 2 * 60 * 60 * 1000).toISOString();

      const fakeExt = makeExtension('evil.newpkg', '1.2.3');
      sandbox
        .stub(ExtensionsRepository, 'getInstance')
        .returns({ getUserExtensions: () => [fakeExt] } as unknown as ExtensionsRepository);

      const warnStub = sandbox.stub(Logger, 'warn');
      sandbox.stub(Logger, 'info');
      const emitSecStub = sandbox.stub(IDEStatusService, 'emitSecurityEvent').resolves();
      sandbox
        .stub(vscode.workspace, 'getConfiguration')
        .returns({
          get: (key: string) => (key === 'autoUpdate' ? true : undefined),
        } as unknown as vscode.WorkspaceConfiguration);

      const fetchStub = sinon
        .stub()
        .resolves({
          ok: true,
          json: async () => ({ results: [{ extensions: [{ versions: [{ lastUpdated: twoHoursAgoIso }] }] }] }),
        } as unknown as Response);

      const service = new AgeHoldService({ fetchFn: fetchStub as unknown as typeof fetch, nowFn: () => now });

      const ctx = makeMockContext();
      await service.initialize(ctx);

      expect(fetchStub.calledOnce).to.equal(true);
      expect(warnStub.calledWithMatch(sinon.match(/extensions\.autoUpdate is enabled/))).to.equal(true);
      expect(warnStub.calledWithMatch(sinon.match(/48-hour age-hold window/))).to.equal(true);
      expect(emitSecStub.calledOnce).to.equal(true);

      const secEvent = emitSecStub.firstCall.args[0] as SecurityEvent;
      expect(secEvent.severity).to.equal(SeverityLevel.MEDIUM);
      expect(secEvent.securityEventType).to.equal(IntegrityRuleType.INTEGRITY_DRIFT);
    });

    test('does not emit SecurityEvent when extension is older than 48h and uses globalState cache', async () => {
      const now = 1_700_000_000_000;
      const tenDaysAgoMs = now - 10 * 24 * 60 * 60 * 1000;

      const fakeExt = makeExtension('trusted.oldpkg', '2.0.0');
      sandbox
        .stub(ExtensionsRepository, 'getInstance')
        .returns({ getUserExtensions: () => [fakeExt] } as unknown as ExtensionsRepository);

      sandbox.stub(Logger, 'warn');
      sandbox.stub(Logger, 'info');
      const emitSecStub = sandbox.stub(IDEStatusService, 'emitSecurityEvent').resolves();
      sandbox
        .stub(vscode.workspace, 'getConfiguration')
        .returns({ get: () => false } as unknown as vscode.WorkspaceConfiguration);

      const fetchStub = sinon.stub();
      const service = new AgeHoldService({ fetchFn: fetchStub as unknown as typeof fetch, nowFn: () => now });

      const ctx = makeMockContext({ 'ide-shepherd.ageHoldCache': { [fakeExt.id]: tenDaysAgoMs } });
      await service.initialize(ctx);

      expect(fetchStub.called).to.equal(false);
      expect(emitSecStub.called).to.equal(false);
    });
  });

  suite('RevocationService', () => {
    test('emits HIGH SecurityEvent when installed extension matches VS Marketplace or Open VSX revoked feed', async () => {
      const now = 1_700_000_000_000;
      const fakeExt = makeExtension('malicious.stealer', '0.1.0');

      sandbox
        .stub(ExtensionsRepository, 'getInstance')
        .returns({ getUserExtensions: () => [fakeExt] } as unknown as ExtensionsRepository);

      const warnStub = sandbox.stub(Logger, 'warn');
      sandbox.stub(Logger, 'info');
      const emitSecStub = sandbox.stub(IDEStatusService, 'emitSecurityEvent').resolves();

      const fetchStub = sinon.stub().callsFake(async (url: string) => {
        if (url.includes('RemovedPackages.md')) {
          return { ok: true, text: async () => '| `malicious.stealer` | Malware |\n' } as unknown as Response;
        }
        return { ok: true, json: async () => [] } as unknown as Response;
      });

      const service = new RevocationService({ fetchFn: fetchStub as unknown as typeof fetch, nowFn: () => now });

      const ctx = makeMockContext();
      await service.initialize(ctx);

      expect(fetchStub.calledTwice).to.equal(true);
      expect(warnStub.calledWithMatch(sinon.match(/revocation list/))).to.equal(true);
      expect(emitSecStub.calledOnce).to.equal(true);

      const secEvent = emitSecStub.firstCall.args[0] as SecurityEvent;
      expect(secEvent.severity).to.equal(SeverityLevel.HIGH);
      expect(secEvent.iocs[0].rule).to.equal('Revoked Marketplace Extension Installed');
    });

    test('uses 24h cached revocation list without re-fetching', async () => {
      const now = 1_700_000_000_000;
      const fakeExt = makeExtension('ovsx.revokedpkg', '1.0.0');

      sandbox
        .stub(ExtensionsRepository, 'getInstance')
        .returns({ getUserExtensions: () => [fakeExt] } as unknown as ExtensionsRepository);

      sandbox.stub(Logger, 'warn');
      sandbox.stub(Logger, 'info');
      const emitSecStub = sandbox.stub(IDEStatusService, 'emitSecurityEvent').resolves();

      const fetchStub = sinon.stub();
      const service = new RevocationService({ fetchFn: fetchStub as unknown as typeof fetch, nowFn: () => now });

      const ctx = makeMockContext({
        'ide-shepherd.revocationCache': { fetchedAt: now - 60 * 60 * 1000, revokedIds: ['ovsx.revokedpkg'] },
      });
      await service.initialize(ctx);

      expect(fetchStub.called).to.equal(false);
      expect(emitSecStub.calledOnce).to.equal(true);
    });
  });
});
