import { describe, expect, it } from 'vitest';

import { allRules } from '../../src/rules/index.js';
import {
  createRuleExplorerEntries,
  createRuleExplorerState,
  exploreRulesToText,
  formatOverrides,
  fuzzyMatch,
  matchingRuleEntries,
  overridePreview,
  reduceRuleExplorer,
  renderRuleExplorer,
  runRuleExplorer,
  runRuleExplorerCli,
  selectedRuleEntry,
  supportsRuleExplorer,
  type RuleExplorerState,
  type RuleExplorerStreams,
} from '../../src/ui/rule-explorer.js';

function press(keys: string, state: RuleExplorerState): RuleExplorerState {
  const sequence = keys.startsWith('\x1b') ? [keys] : [...keys];
  return sequence.reduce((acc, key) => reduceRuleExplorer(acc, key), state);
}

const state = (): RuleExplorerState => createRuleExplorerState(allRules);

describe('fuzzyMatch', () => {
  it('matches a query as an ordered subsequence and reports the indices', () => {
    const match = fuzzyMatch('cmi', 'currencies/missing-issuer');

    expect(match).toBeDefined();
    expect(match?.indices).toHaveLength(3);
    // Indices are strictly increasing and land on c, m, i.
    const text = 'currencies/missing-issuer';
    expect(match?.indices.map((index) => text[index])).toEqual(['c', 'm', 'i']);
  });

  it('is case-insensitive', () => {
    expect(fuzzyMatch('CMI', 'currencies/missing-issuer')).toEqual(
      fuzzyMatch('cmi', 'currencies/missing-issuer'),
    );
  });

  it('returns undefined when the query is not a subsequence', () => {
    expect(fuzzyMatch('xyz', 'currencies/missing-issuer')).toBeUndefined();
    // Right letters, wrong order.
    expect(fuzzyMatch('mci', 'currencies/missing-issuer')).toBeUndefined();
  });

  it('scores a prefix above a scattered match', () => {
    const prefix = fuzzyMatch('gen', 'general/version');
    const scattered = fuzzyMatch('gen', 'changes-merge-nodes');

    expect(prefix).toBeDefined();
    expect(scattered).toBeDefined();
    expect(prefix?.score).toBeGreaterThan(scattered?.score ?? 0);
  });
});

describe('fuzzy matching against every registered rule', () => {
  it('matches each rule id against itself completely', () => {
    for (const rule of allRules) {
      const match = fuzzyMatch(rule.id, rule.id);
      expect(match, rule.id).toBeDefined();
      expect(match?.indices, rule.id).toHaveLength(rule.id.length);
    }
  });

  it('finds a rule by a category keyword', () => {
    const results = matchingRuleEntries(press('currencies', state()));

    expect(results.length).toBeGreaterThan(0);
    expect(results.some((entry) => entry.rule.category === 'currencies')).toBe(true);
  });

  it('ranks an exact rule id first', () => {
    const target = allRules.find((rule) => rule.id === 'validators/public-key');
    if (target === undefined) throw new Error('fixture rule missing');

    const results = matchingRuleEntries(press(target.id, state()));

    expect(results[0]?.rule.id).toBe(target.id);
  });

  it('keeps the registry order when the query is empty', () => {
    const results = matchingRuleEntries(state());

    expect(results.map((entry) => entry.rule.id)).toEqual(allRules.map((rule) => rule.id));
  });
});

describe('rule explorer state and keystrokes', () => {
  it('starts on the first rule with no overrides', () => {
    const initial = state();

    expect(selectedRuleEntry(initial)?.rule.id).toBe(allRules[0]?.id);
    expect(formatOverrides(initial)).toBe('');
  });

  it('moves with j/k and the arrow sequences, and stops at the ends', () => {
    expect(selectedRuleEntry(press('j', state()))?.rule.id).toBe(allRules[1]?.id);
    expect(selectedRuleEntry(press('\x1b[B', state()))?.rule.id).toBe(allRules[1]?.id);
    expect(press('kkk', state()).cursor).toBe(0);
  });

  it('edits the query while searching and leaves it on Enter', () => {
    const typing = press('/missing', state());

    expect(typing.searching).toBe(true);
    expect(typing.query).toBe('missing');
    expect(press('\x7f', typing).query).toBe('missin');

    const done = press('\r', typing);
    expect(done.searching).toBe(false);
    expect(done.query).toBe('missing');
  });

  it('cycles a rule through off, warn, and error with space', () => {
    const first = allRules[0];
    if (first === undefined) throw new Error('no rules registered');

    const off = press(' ', state());
    expect(overridePreview(off, first.id)).toBe('off');
    expect(formatOverrides(off)).toBe(`--off ${first.id}`);

    const warn = press(' ', off);
    expect(formatOverrides(warn)).toBe(`--warn ${first.id}`);

    const error = press(' ', warn);
    expect(formatOverrides(error)).toBe(`--error ${first.id}`);

    const reset = press(' ', error);
    expect(overridePreview(reset, first.id)).toBe('default');
    expect(formatOverrides(reset)).toBe('');
  });

  it('formats every previewed override in registry order and clears them on c', () => {
    const withTwo = press('/currencies\r', state());
    const offFirst = press(' ', withTwo);
    const offSecond = press('j ', offFirst);

    const flags = formatOverrides(offSecond);
    expect(flags.match(/--off/g)).toHaveLength(2);
    const c = press('c', offSecond);
    expect(formatOverrides(c)).toBe('');
  });

  it('quits on q or Ctrl-C', () => {
    expect(reduceRuleExplorer(state(), 'q').quit).toBe(true);
    expect(reduceRuleExplorer(state(), '\x03').quit).toBe(true);
  });
});

describe('rule explorer rendering', () => {
  it('draws the list, the spec link, and the key hints', () => {
    const initial = state();
    const frame = renderRuleExplorer(initial, { width: 100, height: 24 });

    expect(frame).toContain(allRules[0]?.id ?? '');
    expect(frame).toContain('j/k');
    expect(frame).toContain('space override');
    expect(frame).toContain(`${allRules.length} of ${allRules.length} rules`);
  });

  it('shows the selected rule description and spec URL', () => {
    const frame = renderRuleExplorer(state(), { width: 120, height: 24 });
    const selected = selectedRuleEntry(state());

    expect(frame).toContain(selected?.rule.description ?? '');
    expect(frame).toContain('github.com/stellar/stellar-protocol');
  });

  it('adds no escape codes unless colour was asked for', () => {
    expect(renderRuleExplorer(state(), { color: false })).not.toContain('\x1b[');
    expect(renderRuleExplorer(state(), { color: true })).toContain('\x1b[');
  });
});

describe('rule explorer entry points', () => {
  it('links each category to its SEP-1 section', () => {
    const entries = createRuleExplorerEntries(allRules);
    const currencies = entries.find((entry) => entry.rule.category === 'currencies');

    expect(currencies?.specUrl).toContain('#currency-documentation');
  });

  it('only claims to support a real terminal', () => {
    expect(supportsRuleExplorer({ isTTY: true })).toBe(true);
    expect(supportsRuleExplorer({ isTTY: false })).toBe(false);
    expect(supportsRuleExplorer({})).toBe(false);
  });

  it('prints the plain catalogue when stdout is not a terminal', async () => {
    let out = '';
    const streams = {
      stdin: {} as RuleExplorerStreams['stdin'],
      stdout: {
        isTTY: false,
        write: (chunk: string) => {
          out += chunk;
          return true;
        },
      } as unknown as RuleExplorerStreams['stdout'],
    };

    const code = await runRuleExplorerCli(allRules, streams);

    expect(code).toBe(0);
    expect(out).toContain(`${allRules.length} rules`);
    expect(out).toContain(allRules[0]?.id ?? '');
    expect(out).toBe(exploreRulesToText(allRules));
  });

  it('runs the TTY loop, follows keystrokes, and prints the flags on quit', async () => {
    const writes: string[] = [];
    const { EventEmitter } = await import('node:events');
    const input = new EventEmitter() as unknown as RuleExplorerStreams['stdin'];
    Object.assign(input, {
      isRaw: false,
      setRawMode: (mode: boolean) => {
        (input as { isRaw: boolean }).isRaw = mode;
      },
      resume: () => {},
      pause: () => {},
      setEncoding: () => {},
    });
    const stdout = {
      isTTY: true,
      columns: 100,
      rows: 24,
      write: (chunk: string) => {
        writes.push(chunk);
        return true;
      },
    } as unknown as RuleExplorerStreams['stdout'];

    const pending = runRuleExplorer(allRules, { stdin: input, stdout }, { color: false });
    await new Promise((resolve) => setTimeout(resolve, 0));
    input.emit('data', ' '); // override the first rule to --off
    input.emit('data', 'q');

    const { state: final, overrides } = await pending;
    expect(final.quit).toBe(true);
    expect(overrides).toBe(`--off ${allRules[0]?.id}`);
    expect(writes.join('')).toContain('space override');
  });
});
