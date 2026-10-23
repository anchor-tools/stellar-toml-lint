/**
 * Interactive rule explorer for `--explore-rules`.
 *
 * With over seventy lint and security rules, discovering the exact id to pass
 * to `--off`, `--warn`, or `--error` is the slow part of adopting the linter.
 * This module is a fuzzy-searchable list of every registered rule: type to
 * narrow by id, category, or keyword; select one to read its full description
 * and the section of SEP-1 it comes from; press space to cycle a severity
 * override and watch the `--off`/`--warn`/`--error` flags build up, ready to
 * paste into a shell script.
 *
 * Following the split used by `dashboard.ts`, the logic is pure —
 * {@link fuzzyMatch} scores a query against a string, {@link reduceRuleExplorer}
 * is a reducer over keystrokes, and {@link renderRuleExplorer} turns state into
 * a frame — so the fuzzy matcher and the flag formatter are tested as functions
 * rather than by driving a terminal. Only {@link runRuleExplorer} touches a TTY,
 * and {@link runRuleExplorerCli} falls back to a plain listing when stdout is a
 * pipe or a file.
 */

import type { Rule, RuleCategory } from '../types.js';
import { specUrl } from '../spec.js';

/** A pending severity a user is previewing for one rule. */
export type OverridePreview = 'default' | 'off' | 'warn' | 'error';

const OVERRIDE_CYCLE: OverridePreview[] = ['default', 'off', 'warn', 'error'];

/** The `--list-rules` severity spelling for a preview; `default` has no flag. */
const FLAG_FOR: Record<'off' | 'warn' | 'error', string> = {
  off: '--off',
  warn: '--warn',
  error: '--error',
};

/**
 * SEP-1 anchor each rule category links to. Categories the spec does not name
 * under its own heading (network probes, policy, monitoring) point at General
 * Information, which is where their fields are documented.
 */
const CATEGORY_ANCHOR: Record<RuleCategory, string> = {
  file: 'general-information',
  general: 'general-information',
  documentation: 'organization-documentation',
  principals: 'point-of-contact-documentation',
  currencies: 'currency-documentation',
  validators: 'validator-information',
  network: 'general-information',
  fees: 'general-information',
  sep24: 'general-information',
  policy: 'general-information',
  sep12: 'general-information',
  monitor: 'general-information',
  codemod: 'general-information',
  style: 'general-information',
};

export interface RuleExplorerEntry {
  rule: Rule;
  /** SEP-1 section that documents the rule's subject. */
  specUrl: string;
  /** Lowercased id + category + description, for keyword search. */
  haystack: string;
}

export interface RuleExplorerState {
  entries: RuleExplorerEntry[];
  /** Current fuzzy-search query. */
  query: string;
  /** True while keystrokes edit the query rather than the list. */
  searching: boolean;
  /** Index into the *visible* list. */
  cursor: number;
  /** Previewed overrides, keyed by rule id. Absent means "default". */
  overrides: Map<string, OverridePreview>;
  quit: boolean;
  /** Last action's outcome, shown above the key hints. */
  status?: string;
}

export interface RuleExplorerStreams {
  stdin: NodeJS.ReadStream & { setRawMode?: (mode: boolean) => void };
  stdout: NodeJS.WriteStream;
}

export interface RuleExplorerRenderOptions {
  width?: number;
  height?: number;
  color?: boolean;
}

// ─── Fuzzy matching ───────────────────────────────────────────────────────────

export interface FuzzyMatch {
  score: number;
  /** Indices in `text` the query characters matched, for highlighting. */
  indices: number[];
}

const WORD_BOUNDARY = /[^a-z0-9]/;

/**
 * Scores `query` against `text` as a case-insensitive subsequence match.
 *
 * Every query character must appear in order, so `cmi` matches
 * `currencies/missing-issuer`. Consecutive runs and matches at a word boundary
 * score higher than scattered ones, which puts an id beginning with the query
 * above one that merely contains the letters. Returns `undefined` when not every
 * character matches, so a caller can filter with one call.
 */
export function fuzzyMatch(query: string, text: string): FuzzyMatch | undefined {
  const needle = query.trim().toLowerCase().replace(/\s+/g, '');
  if (needle === '') return { score: 0, indices: [] };

  const haystack = text.toLowerCase();
  const indices: number[] = [];
  let score = 0;
  let cursor = 0;
  let previousIndex = -2;

  for (const char of needle) {
    const found = haystack.indexOf(char, cursor);
    if (found < 0) return undefined;

    if (found === previousIndex + 1) score += 3;
    if (found === 0 || WORD_BOUNDARY.test(haystack[found - 1] ?? '')) score += 2;
    score += 1;

    indices.push(found);
    cursor = found + 1;
    previousIndex = found;
  }

  // Prefer shorter texts, and an exact prefix over a late match.
  score += Math.max(0, 12 - haystack.length / 2);
  if (haystack.startsWith(needle)) score += 8;
  return { score, indices };
}

// ─── State ────────────────────────────────────────────────────────────────────

/** Builds explorer entries from the registered rule list, in report order. */
export function createRuleExplorerEntries(rules: readonly Rule[]): RuleExplorerEntry[] {
  return rules.map((rule) => ({
    rule,
    specUrl: specUrl(CATEGORY_ANCHOR[rule.category]),
    haystack: `${rule.id} ${rule.category} ${rule.description}`.toLowerCase(),
  }));
}

export function createRuleExplorerState(rules: readonly Rule[]): RuleExplorerState {
  return {
    entries: createRuleExplorerEntries(rules),
    query: '',
    searching: false,
    cursor: 0,
    overrides: new Map(),
    quit: false,
  };
}

/**
 * Entries matching the current query, best score first. An empty query keeps the
 * registry's own order. The id is matched first so an exact id prefix always
 * outranks a keyword that happens to match the description.
 */
export function matchingRuleEntries(state: RuleExplorerState): RuleExplorerEntry[] {
  const query = state.query.trim();
  if (query === '') return state.entries;

  const scored: { entry: RuleExplorerEntry; score: number }[] = [];
  for (const entry of state.entries) {
    const byId = fuzzyMatch(query, entry.rule.id);
    const byHaystack = fuzzyMatch(query, entry.haystack);
    if (byId === undefined && byHaystack === undefined) continue;
    const score = (byId?.score ?? 0) * 2 + (byHaystack?.score ?? 0);
    scored.push({ entry, score });
  }

  return scored.sort((a, b) => b.score - a.score).map(({ entry }) => entry);
}

export function selectedRuleEntry(state: RuleExplorerState): RuleExplorerEntry | undefined {
  return matchingRuleEntries(state)[state.cursor];
}

export function overridePreview(state: RuleExplorerState, ruleId: string): OverridePreview {
  return state.overrides.get(ruleId) ?? 'default';
}

/**
 * Formats the previewed overrides as CLI flags, in registry order. Rules left at
 * their default are omitted, so the output is exactly what a user would add to
 * their command line.
 */
export function formatOverrides(state: RuleExplorerState): string {
  const parts: string[] = [];
  for (const entry of state.entries) {
    const preview = state.overrides.get(entry.rule.id);
    if (preview === undefined || preview === 'default') continue;
    parts.push(`${FLAG_FOR[preview]} ${entry.rule.id}`);
  }
  return parts.join(' ');
}

function cycleOverride(preview: OverridePreview): OverridePreview {
  const index = OVERRIDE_CYCLE.indexOf(preview);
  return OVERRIDE_CYCLE[(index + 1) % OVERRIDE_CYCLE.length] ?? 'default';
}

function clampCursor(cursor: number, length: number): number {
  if (length === 0) return 0;
  return Math.min(Math.max(cursor, 0), length - 1);
}

// ─── Reducer ──────────────────────────────────────────────────────────────────

/**
 * Applies one keystroke. Works for both a bare key (`j`, `q`, space) and the
 * escape sequences terminals send for arrows, so navigation does not depend on
 * the user's terminal.
 */
export function reduceRuleExplorer(state: RuleExplorerState, key: string): RuleExplorerState {
  if (state.quit) return state;

  if (state.searching) {
    if (key === '\r' || key === '\x1b') return { ...state, searching: false };
    if (key === '\x7f' || key === '\b') {
      return { ...state, query: state.query.slice(0, -1), cursor: 0 };
    }
    if (key >= ' ' && key !== '\x7f') {
      return { ...state, query: state.query + key, cursor: 0 };
    }
    return state;
  }

  switch (key) {
    case 'q':
    case '\x03':
      return { ...state, quit: true };
    case '/':
      return { ...state, searching: true, status: undefined };
    case 'j':
    case '\x1b[B':
      return { ...state, cursor: clampCursor(state.cursor + 1, matchingRuleEntries(state).length) };
    case 'k':
    case '\x1b[A':
      return { ...state, cursor: clampCursor(state.cursor - 1, matchingRuleEntries(state).length) };
    case ' ':
    case '\r': {
      const entry = selectedRuleEntry(state);
      if (entry === undefined) return { ...state, status: 'Nothing selected to override.' };
      const next = cycleOverride(overridePreview(state, entry.rule.id));
      const overrides = new Map(state.overrides);
      if (next === 'default') overrides.delete(entry.rule.id);
      else overrides.set(entry.rule.id, next);
      return {
        ...state,
        overrides,
        status: `${entry.rule.id} → ${next === 'default' ? 'default' : FLAG_FOR[next]}`,
      };
    }
    case 'c': {
      if (state.overrides.size === 0) return { ...state, status: 'No overrides to clear.' };
      return { ...state, overrides: new Map(), status: 'Cleared all overrides.' };
    }
    case '\x1b':
      return state.query === '' ? state : { ...state, query: '', cursor: 0 };
    default:
      return state;
  }
}

// ─── Rendering ────────────────────────────────────────────────────────────────

const ANSI = {
  error: '\x1b[31m',
  warning: '\x1b[33m',
  info: '\x1b[36m',
  dim: '\x1b[2m',
  reset: '\x1b[0m',
};

function paint(code: string, text: string, color: boolean): string {
  return color ? `${code}${text}${ANSI.reset}` : text;
}

function truncate(text: string, width: number): string {
  if (text.length <= width) return text;
  if (width <= 1) return text.slice(0, width);
  return `${text.slice(0, width - 1)}…`;
}

function severityColor(severity: Rule['severity']): string {
  return ANSI[severity] ?? ANSI.info;
}

/**
 * Draws one frame: the search bar, the visible rules with their pending
 * override, the details of the highlighted rule, and the key hints.
 */
export function renderRuleExplorer(
  state: RuleExplorerState,
  options: RuleExplorerRenderOptions = {},
): string {
  const width = Math.max(40, options.width ?? 90);
  const height = Math.max(8, options.height ?? 20);
  const color = options.color ?? false;
  const inner = width - 2;

  const visible = matchingRuleEntries(state);
  const selected = visible[state.cursor];
  const lines: string[] = [];
  const row = (text: string): void => {
    lines.push(`│${truncate(text, inner).padEnd(inner)}│`);
  };

  lines.push(`┌${'─'.repeat(inner)}┐`);
  const searchLabel = state.searching ? 'search: ' : 'filter: ';
  row(` ${searchLabel}${state.query}${state.searching ? '▏' : ''}`);
  lines.push(`├${'─'.repeat(inner)}┤`);

  const headerRows = 4; // search + separator + column header + selected details
  const detailRows = selected === undefined ? 0 : 2;
  const listHeight = Math.max(1, height - headerRows - detailRows - 2);

  row(paint(ANSI.dim, ` ${visible.length} of ${state.entries.length} rules`, color));

  for (let index = 0; index < listHeight; index++) {
    const entry = visible[index];
    if (entry === undefined) {
      row('');
      continue;
    }
    const marker = index === state.cursor ? '▸' : ' ';
    const preview = overridePreview(state, entry.rule.id);
    const flag = preview === 'default' ? '' : ` ${FLAG_FOR[preview]}`;
    const label = `${entry.rule.id}${flag}`;
    const padded = `${label}`.padEnd(Math.max(0, inner - 12));
    const text = ` ${marker} ${truncate(padded, inner - 12)} ${entry.rule.severity}`;
    row(index === state.cursor ? paint(severityColor(entry.rule.severity), text, color) : text);
  }

  lines.push(`├${'─'.repeat(inner)}┤`);

  if (selected !== undefined) {
    row(` ${paint(ANSI.dim, selected.rule.description, color)}`);
    row(` ${paint(ANSI.dim, selected.specUrl, color)}`);
  }

  if (state.status !== undefined) {
    row(` ${state.status}`);
  }

  const overrides = formatOverrides(state);
  if (overrides !== '') {
    row(` ${paint(ANSI.dim, `flags: ${overrides}`, color)}`);
  }

  const keys = 'j/k ↑↓ move · / search · space override · c clear · q quit';
  row(` ${paint(ANSI.dim, keys, color)}`);
  lines.push(`└${'─'.repeat(inner)}┘`);

  return lines.join('\n');
}

/** A plain, non-interactive listing used when stdout is not a terminal. */
export function exploreRulesToText(rules: readonly Rule[]): string {
  const entries = createRuleExplorerEntries(rules);
  const width = Math.max(...entries.map((entry) => entry.rule.id.length));
  const lines = entries.map(
    (entry) =>
      `  ${entry.rule.id.padEnd(width)}  ${entry.rule.severity.padEnd(7)}  ${entry.specUrl}\n    ${entry.rule.description}`,
  );
  return `${rules.length} rules — run in a terminal for fuzzy search and override preview\n\n${lines.join('\n')}\n`;
}

// ─── TTY loop and CLI entry ────────────────────────────────────────────────────

/** True when a full-screen explorer makes sense. */
export function supportsRuleExplorer(stdout: { isTTY?: boolean }): boolean {
  return stdout.isTTY === true;
}

/**
 * Runs the explorer until the user quits, resolving with the final overrides
 * string and the frames drawn. Never throws and never exits the process: the
 * caller owns the exit code.
 */
export async function runRuleExplorer(
  entries: readonly Rule[],
  streams: RuleExplorerStreams,
  options: RuleExplorerRenderOptions = {},
): Promise<{ state: RuleExplorerState; lines: string[]; overrides: string }> {
  const { stdin, stdout } = streams;
  const width = options.width ?? stdout.columns ?? 90;
  const height = options.height ?? stdout.rows ?? 20;
  let state = createRuleExplorerState(entries);
  const frames: string[] = [];

  const draw = (): void => {
    const frame = renderRuleExplorer(state, { width, height, color: options.color ?? false });
    frames.push(frame);
    stdout.write('\x1b[2J\x1b[H');
    stdout.write(`${frame}\n`);
  };

  return await new Promise((resolve) => {
    const wasRaw = stdin.isRaw === true;
    stdin.setRawMode?.(true);
    stdin.resume();
    stdin.setEncoding('utf8');

    const finish = (): void => {
      stdin.setRawMode?.(wasRaw);
      stdin.pause();
      stdin.removeListener('data', onData);
      stdout.write('\x1b[2J\x1b[H');
      resolve({ state, lines: frames, overrides: formatOverrides(state) });
    };

    const onData = (chunk: string): void => {
      for (const key of chunk) {
        state = reduceRuleExplorer(state, key);
        if (state.quit) {
          draw();
          finish();
          return;
        }
      }
      draw();
    };

    stdin.on('data', onData);
    draw();
  });
}

/**
 * `--explore-rules` entry point. In a terminal it opens the interactive view
 * and prints the collected flags on exit; otherwise it prints the plain listing
 * so a pipe or a CI log still gets the rule catalogue.
 */
export async function runRuleExplorerCli(
  rules: readonly Rule[],
  streams: RuleExplorerStreams,
  options: RuleExplorerRenderOptions = {},
): Promise<number> {
  if (!supportsRuleExplorer(streams.stdout)) {
    streams.stdout.write(exploreRulesToText(rules));
    return 0;
  }

  const { overrides } = await runRuleExplorer(rules, streams, options);
  if (overrides !== '') {
    streams.stdout.write(`\n${overrides}\n`);
  } else {
    streams.stdout.write('\nNo overrides selected.\n');
  }
  return 0;
}
