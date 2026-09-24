/**
 * In-source suppression pragmas: `# stellar-toml-lint-disable*`.
 *
 * `smol-toml` discards comments when it parses, so pragmas are recovered by
 * scanning the raw source line by line. Everything is resolved into a
 * per-line map in one pass — blocks are walked here — and the linter only has
 * to ask "is this rule suppressed on this line?" for each diagnostic.
 */

/** Rules suppressed on one line. `'*'` means every rule. */
export type LineSuppression = '*' | Set<string>;

/** 1-based line number → the rules suppressed on it. */
export type SuppressionMap = Map<number, LineSuppression>;

/**
 * A pragma comment, recognised anywhere a `#` introduces one. The directive
 * names are ordered longest-first so `disable-line` is not read as `disable`.
 */
const PRAGMA = /#\s*stellar-toml-lint-(disable-next-line|disable-line|disable|enable)\b(.*)/;

/** Parses a comma-separated rule list; empty or `*` means "every rule". */
function parseRuleList(raw: string): '*' | Set<string> {
  const parts = raw
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part.length > 0);
  if (parts.length === 0 || parts.includes('*')) return '*';
  return new Set(parts);
}

/**
 * Scans `source` for suppression pragmas and resolves them to per-line rule
 * sets:
 *
 * - `stellar-toml-lint-disable-line` suppresses its own line,
 * - `stellar-toml-lint-disable-next-line` the one after it,
 * - `stellar-toml-lint-disable` … `stellar-toml-lint-enable` a block, from the
 *   `disable` line up to (but not including) the `enable` line, or EOF when no
 *   `enable` follows,
 * - a bare rule list (or `*`) suppresses every rule on the covered lines.
 *
 * A specific `enable` only lifts rules from specific blocks; ending a
 * wildcard block needs a bare (or `*`) `enable`.
 */
export function parseSuppressions(source: string): SuppressionMap {
  const map: SuppressionMap = new Map();
  const blocks: ('*' | Set<string>)[] = [];

  const add = (line: number, rules: '*' | Set<string>): void => {
    if (rules === '*') {
      map.set(line, '*');
      return;
    }
    const existing = map.get(line);
    if (existing === '*') return;
    if (existing === undefined) {
      map.set(line, new Set(rules));
      return;
    }
    for (const rule of rules) existing.add(rule);
  };

  const lines = source.split(/\r?\n/);
  for (const [index, text] of lines.entries()) {
    const line = index + 1;
    const match = PRAGMA.exec(text);

    if (match) {
      const kind = match[1];
      const rules = parseRuleList(match[2] ?? '');

      if (kind === 'disable-line') {
        add(line, rules);
      } else if (kind === 'disable-next-line') {
        add(line + 1, rules);
      } else if (kind === 'disable') {
        blocks.push(rules);
      } else if (kind === 'enable') {
        if (rules === '*') {
          blocks.length = 0;
        } else {
          for (let i = blocks.length - 1; i >= 0; i--) {
            const block = blocks[i];
            if (block === undefined || block === '*') continue;
            for (const rule of rules) block.delete(rule);
            if (block.size === 0) blocks.splice(i, 1);
          }
        }
      }
    }

    // Active blocks cover their own `disable` line (so a trailing `disable`
    // comment works), but not the `enable` line: re-enabling takes effect
    // from the pragma itself onward.
    if (blocks.length > 0) {
      if (blocks.some((block) => block === '*')) {
        add(line, '*');
      } else {
        const union = new Set<string>();
        for (const block of blocks) {
          if (block !== '*') for (const rule of block) union.add(rule);
        }
        add(line, union);
      }
    }
  }

  return map;
}

/** True when `rule` on `line` is covered by a suppression pragma. */
export function isSuppressed(map: SuppressionMap, line: number | undefined, rule: string): boolean {
  if (line === undefined) return false;
  const entry = map.get(line);
  if (entry === undefined) return false;
  return entry === '*' || entry.has(rule);
}
