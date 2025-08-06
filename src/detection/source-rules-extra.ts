/**
 * Extra Source Rules - Additional TTP-based file-content detection rules.
 *
 * Kept separate from source-rules.ts to minimize merge conflicts with upstream.
 */

import { SeverityLevel } from '../lib/events/sec-events';
import type { SourceRule } from './source-rules';

const VARIATION_SELECTOR_RE = /[\uFE00-\uFE0F\u{E0100}-\u{E01EF}]/u;
// Note: `\bFunction\s*\(` also matches `new Function(...)`.
const DYNAMIC_EXEC_RE = /\b(?:eval|Function)\s*\(|vm\.runIn(?:New|This)?Context\s*\(/;

export const EXTRA_SOURCE_RULES: SourceRule[] = [
  {
    id: 'glassworm_invisible_unicode_eval',
    name: 'GlassWorm Invisible Unicode Eval',
    description:
      'File embeds Unicode variation selectors (U+FE00-FE0F or U+E0100-E01EF) alongside dynamic code execution (eval/Function/vm) — GlassWorm steganographic payload execution TTP',
    severity: SeverityLevel.HIGH,
    detect: (content) => {
      return VARIATION_SELECTOR_RE.test(content) && DYNAMIC_EXEC_RE.test(content);
    },
  },
];
