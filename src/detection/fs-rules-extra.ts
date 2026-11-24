/**
 * Extra File System Rules - IDE & AI coding-assistant credential/token stores.
 *
 * Kept separate from fs-rules.ts to minimize merge conflicts with upstream.
 */

import { Target } from '../lib/events/ext-events';
import { SeverityLevel } from '../lib/events/sec-events';
import type { FsRule, FsRuleType } from './fs-rules';

const VSCDB_SUBPATTERN = 'globalStorage[/\\\\]state\\.vscdb(?:\\.backup)?$';
const GLOBAL_STORAGE_JSON_SUBPATTERN = 'globalStorage[/\\\\]storage\\.json$';
const CODEX_AUTH_SUBPATTERN = '\\.codex[/\\\\]auth\\.json$';
const KIRO_AUTH_SUBPATTERN = 'kiro-auth-token\\.json$';
const GEMINI_MASTER_KEY_SUBPATTERN = '\\.gemini-cli-workspace-master-key$';
const COPILOT_HOSTS_SUBPATTERN =
  '(?:\\.copilot|(?:\\.config|AppData[/\\\\]Local)[/\\\\]github-copilot)[/\\\\](?:hosts|apps)\\.json$';
const CODEIUM_CONFIG_SUBPATTERN = '\\.codeium[/\\\\]config\\.json$';
const CLAUDE_CREDENTIALS_SUBPATTERN = '(?:\\.claude[/\\\\]\\.credentials\\.json|\\.claude\\.json)$';

const PATH_PREFIX = '(?:^|[/\\\\])';

const IDE_STATE_VSCDB_PATTERN = new RegExp(`${PATH_PREFIX}${VSCDB_SUBPATTERN}`, 'i');
const IDE_GLOBAL_STORAGE_JSON_PATTERN = new RegExp(`${PATH_PREFIX}${GLOBAL_STORAGE_JSON_SUBPATTERN}`, 'i');
const AI_IDE_TOKEN_STORE_PATTERN = new RegExp(
  `${PATH_PREFIX}(?:${[
    CODEX_AUTH_SUBPATTERN,
    KIRO_AUTH_SUBPATTERN,
    GEMINI_MASTER_KEY_SUBPATTERN,
    COPILOT_HOSTS_SUBPATTERN,
    CODEIUM_CONFIG_SUBPATTERN,
  ].join('|')})`,
  'i',
);

interface FsRulePairSpec {
  idPrefix: string;
  namePrefix: string;
  readDescription: string;
  writeDescription: string;
  pathPattern: RegExp;
}

function createReadWriteRulePair(spec: FsRulePairSpec): FsRule[] {
  return [
    {
      id: `${spec.idPrefix}_read`,
      name: `${spec.namePrefix} Read`,
      description: spec.readDescription,
      type: 'READ' as FsRuleType,
      target: Target.FILESYSTEM,
      severity: SeverityLevel.HIGH,
      pathPattern: spec.pathPattern,
      operations: ['read'],
      confidence: 0.95,
    },
    {
      id: `${spec.idPrefix}_write`,
      name: `${spec.namePrefix} Write`,
      description: spec.writeDescription,
      type: 'WRITE' as FsRuleType,
      target: Target.FILESYSTEM,
      severity: SeverityLevel.HIGH,
      pathPattern: spec.pathPattern,
      operations: ['write', 'append'],
      confidence: 0.95,
    },
  ];
}

export const EXTRA_FS_RULES: FsRule[] = [
  ...createReadWriteRulePair({
    idPrefix: 'ide_state_vscdb',
    namePrefix: 'IDE State Database',
    readDescription: 'Detected read access to IDE globalStorage state.vscdb database',
    writeDescription: 'Detected write access to IDE globalStorage state.vscdb database',
    pathPattern: IDE_STATE_VSCDB_PATTERN,
  }),
  ...createReadWriteRulePair({
    idPrefix: 'ide_global_storage_json',
    namePrefix: 'IDE Global Storage JSON',
    readDescription: 'Detected read access to IDE globalStorage storage.json file',
    writeDescription: 'Detected write access to IDE globalStorage storage.json file',
    pathPattern: IDE_GLOBAL_STORAGE_JSON_PATTERN,
  }),
  ...createReadWriteRulePair({
    idPrefix: 'ai_ide_token_store',
    namePrefix: 'AI IDE Token Store',
    readDescription: 'Detected read access to AI coding assistant or IDE token store',
    writeDescription: 'Detected write access to AI coding assistant or IDE token store',
    pathPattern: AI_IDE_TOKEN_STORE_PATTERN,
  }),
];

const IDE_TOKEN_STORE_CLASSIFIERS: ReadonlyArray<readonly [RegExp, string]> = (
  [
    [VSCDB_SUBPATTERN, 'vscode-state-vscdb'],
    [GLOBAL_STORAGE_JSON_SUBPATTERN, 'vscode-global-storage'],
    [CODEX_AUTH_SUBPATTERN, 'codex-auth'],
    [KIRO_AUTH_SUBPATTERN, 'kiro-auth'],
    [GEMINI_MASTER_KEY_SUBPATTERN, 'gemini-master-key'],
    [COPILOT_HOSTS_SUBPATTERN, 'copilot-hosts'],
    [CODEIUM_CONFIG_SUBPATTERN, 'codeium-config'],
    [CLAUDE_CREDENTIALS_SUBPATTERN, 'claude-credentials'],
  ] as const
).map(([subpattern, storeId]) => [new RegExp(`(?:^|/)${subpattern.replace(/\[\/\\\\\]/g, '/')}`, 'i'), storeId]);

/**
 * Classifies a file path into a canonical IDE or AI coding-assistant token store family.
 */
export function classifyIdeTokenStorePath(filePath: string): string | null {
  const normalized = filePath.replace(/\\/g, '/');
  for (const [pattern, storeId] of IDE_TOKEN_STORE_CLASSIFIERS) {
    if (pattern.test(normalized)) {
      return storeId;
    }
  }
  return null;
}
