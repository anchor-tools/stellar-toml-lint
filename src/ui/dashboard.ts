/**
 * Interactive terminal dashboard for `--interactive`.
 *
 * Split into three parts on purpose:
 *
 * - {@link reduceDashboard} is a pure reducer over keystrokes, so navigation,
 *   filtering and search are tested as logic rather than by driving a terminal;
 * - {@link renderDashboard} turns a state into the frame it prints, so the
 *   layout is a string comparison;
 * - {@link runDashboard} is the only part that touches a TTY, and it is skipped
 *   entirely when stdout is not one — a dashboard that sprays ANSI codes into a
 *   CI log or a redirected file would be a regression, not a feature.
 *
 * No dependencies: the whole view is a few box-drawing characters and `padEnd`.
 * A linter that anchors run in CI benefits from a dependency tree you can audit
 * by eye, which is the reasoning already recorded for the hand-rolled arg
 * parsing in `cli.ts`.
 */

import type { Diagnostic, LintResult, Severity } from '../types.js';

export type SeverityFilter = 'all' | 'error' | 'warning';

export interface DashboardEntry {
  file: string;
  diagnostic: Diagnostic;
}

export interface DashboardState {
  entries: DashboardEntry[];
  /** Index into the *visible* list, not into `entries`. */
  cursor: number;
  filter: SeverityFilter;
  /** Rule-name search, matched case-insensitively against the rule id. */
  search: string;
  /** True while keystrokes go into the search bar rather than the list. */
  searching: boolean;
  /** Details panel for the highlighted finding. */
  expanded: boolean;
  /** Last action's outcome, shown above the key hints. */
  status?: string;
  quit: boolean;
}

export interface DashboardContext {
  /**
   * Attempts a fix for the highlighted finding and returns what to tell the
   * user. Absent means no fix engine is wired up, which is the current state —
   * #9 tracks the mechanical fixes this would call into.
   */
  autofix?: (entry: DashboardEntry) => string | undefined;
}

/** What the run's findings look like as a flat list the dashboard can walk. */
export function createDashboardState(
  run: { name: string; result: LintResult }[],
  /** Lets `--quiet` open the dashboard already filtered to errors. */
  filter: SeverityFilter = 'all',
): DashboardState {
  const entries: DashboardEntry[] = [];

  for (const { name, result } of run) {
    for (const diagnostic of result.diagnostics) {
      entries.push({ file: name, diagnostic });
    }
  }

  return {
    entries,
    cursor: 0,
    filter,
    search: '',
    searching: false,
    expanded: false,
    quit: false,
  };
}

/** Findings matching the current filter and search, in report order. */
export function matchingEntries(state: DashboardState): DashboardEntry[] {
  const needle = state.search.trim().toLowerCase();

  return state.entries.filter(({ diagnostic }) => {
    if (state.filter === 'error' && diagnostic.severity !== 'error') return false;
    if (state.filter === 'warning' && diagnostic.severity !== 'warning') return false;
    if (needle.length > 0 && !diagnostic.rule.toLowerCase().includes(needle)) return false;
    return true;
  });
}

export function selectedEntry(state: DashboardState): DashboardEntry | undefined {
  return matchingEntries(state)[state.cursor];
}

function countsBySeverity(entries: DashboardEntry[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { error: 0, warning: 0, info: 0 };
  for (const { diagnostic } of entries) counts[diagnostic.severity] += 1;
  return counts;
}

function clampCursor(cursor: number, length: number): number {
  if (length === 0) return 0;
  return Math.min(Math.max(cursor, 0), length - 1);
}

const FILTER_CYCLE: SeverityFilter[] = ['all', 'error', 'warning'];

function cycleFilter(filter: SeverityFilter): SeverityFilter {
  const next = FILTER_CYCLE[(FILTER_CYCLE.indexOf(filter) + 1) % FILTER_CYCLE.length];
  return next ?? 'all';
}

/**
 * Applies one keystroke. `key` is the raw sequence a terminal reports, so both
 * `j` and the down arrow work: arrows arrive as escape sequences.
 */
export function reduceDashboard(
  state: DashboardState,
  key: string,
  context: DashboardContext = {},
): DashboardState {
  const move = (delta: number): DashboardState => ({
    ...state,
    cursor: clampCursor(state.cursor + delta, matchingEntries(state).length),
  });

  // While the search bar is open, printable keys belong to it. Navigation and
  // the way out still work, because a search that traps you is worse than none.
  if (state.searching) {
    switch (key) {
      case '\r':
      case '\n':
      case '\x1b':
        return { ...state, searching: false };
      case '\x7f':
      case '\b':
        return { ...state, search: state.search.slice(0, -1), cursor: 0 };
      case 'j':
      case '\x1b[B':
        return move(1);
      case 'k':
      case '\x1b[A':
        return move(-1);
      default:
        if (key.length === 1 && key >= ' ') {
          return { ...state, search: state.search + key, cursor: 0 };
        }
        return state;
    }
  }

  switch (key) {
    case 'q':
    case '\x03':
      return { ...state, quit: true };
    case 'j':
    case '\x1b[B':
      return move(1);
    case 'k':
    case '\x1b[A':
      return move(-1);
    case '\r':
    case '\n':
      return { ...state, expanded: !state.expanded };
    case 's':
    case '\t':
      return { ...state, filter: cycleFilter(state.filter), cursor: 0, status: undefined };
    case '/':
      return { ...state, searching: true };
    case 'f': {
      const entry = selectedEntry(state);
      if (!entry) return { ...state, status: 'Nothing selected to fix.' };
      const outcome = context.autofix?.(entry);
      return {
        ...state,
        status:
          outcome ?? `No autofix for ${entry.diagnostic.rule} yet — #9 tracks the mechanical ones.`,
      };
    }
    default:
      return state;
  }
}

// ── rendering ───────────────────────────────────────────────────────────────

export interface RenderOptions {
  /** Initial severity filter; `--quiet` passes `'error'`. */
  filter?: SeverityFilter;
  width?: number;
  /** Total rows the frame may occupy, including its borders. */
  height?: number;
  color?: boolean;
  title?: string;
  autofix?: boolean;
}

const MIN_WIDTH = 48;
const DEFAULT_WIDTH = 80;
const DEFAULT_HEIGHT = 24;
/** Rows the frame spends on borders, the header and the key hints. */
const CHROME_ROWS = 8;

const GLYPH: Record<Severity, string> = { error: '✗', warning: '⚠', info: '·' };
const ANSI: Record<Severity, string> = { error: '\x1b[31m', warning: '\x1b[33m', info: '\x1b[36m' };
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';

function truncate(text: string, width: number): string {
  if (width <= 0) return '';
  return text.length <= width ? text : `${text.slice(0, Math.max(0, width - 1))}…`;
}

/** Wraps on spaces where possible; long tokens are cut rather than overflowed. */
function wrap(text: string, width: number): string[] {
  if (width <= 0) return [];
  const lines: string[] = [];
  let current = '';

  for (const word of text.split(/\s+/)) {
    if (current.length === 0) current = word;
    else if (current.length + 1 + word.length <= width) current += ` ${word}`;
    else {
      lines.push(current);
      current = word;
    }
  }
  if (current.length > 0) lines.push(current);

  return lines.flatMap((line) =>
    line.length <= width ? [line] : [line.slice(0, width), ...wrap(line.slice(width), width)],
  );
}

function severityText(severity: Severity, color: boolean): string {
  const glyph = `${GLYPH[severity]} ${severity}`;
  return color ? `${ANSI[severity]}${glyph}${RESET}` : glyph;
}

/**
 * Renders the whole frame. Returns a single string with `\n` separators and no
 * cursor or clear codes — {@link runDashboard} adds those, and tests compare
 * this text directly.
 */
export function renderDashboard(state: DashboardState, options: RenderOptions = {}): string {
  const width = Math.max(options.width ?? DEFAULT_WIDTH, MIN_WIDTH);
  const height = Math.max(options.height ?? DEFAULT_HEIGHT, CHROME_ROWS + 3);
  const color = options.color ?? false;
  const paint = (code: string, text: string): string => (color ? `${code}${text}${RESET}` : text);

  const visible = matchingEntries(state);
  const counts = countsBySeverity(state.entries);
  const inner = width - 2;
  const lines: string[] = [];

  const title = options.title ?? 'stellar-toml-lint';
  const searchLabel = state.search.length > 0 ? `/${state.search}` : '';
  const filterLabel = state.filter === 'all' ? 'all' : `${state.filter}s only`;
  const header = truncate(
    `${title}  ${counts.error} errors · ${counts.warning} warnings · ${counts.info} info`,
    inner,
  );
  lines.push(`┌${paint(BOLD, header.padEnd(inner))}┐`);

  const sub = truncate(
    `${visible.length} of ${state.entries.length} shown   filter: ${filterLabel}${
      searchLabel.length > 0 ? `   search: ${searchLabel}` : ''
    }`,
    inner,
  );
  lines.push(`│${paint(DIM, sub.padEnd(inner))}│`);
  lines.push(`├${'─'.repeat(inner)}┤`);

  const listWidth = state.expanded ? Math.max(24, Math.floor(inner * 0.55)) : inner;
  const panelWidth = Math.max(8, inner - listWidth - 1);
  const bodyRows = Math.max(1, height - CHROME_ROWS);

  /**
   * One body row. With the details pane open the row is split in two, and both
   * halves are padded to their exact width so every line of the frame is the
   * same length — a frame that shifts by a character is unusable in practice.
   */
  const bodyRow = (left: string, right = ''): string =>
    state.expanded
      ? `│${truncate(left, listWidth).padEnd(listWidth)}│${truncate(right, panelWidth).padEnd(panelWidth)}│`
      : `│${truncate(left, inner).padEnd(inner)}│`;

  // Left rows stay plain and exactly `listWidth` wide; colour is applied to the
  // finished row further down. Padding or truncating a string that already
  // contains escape codes counts them as visible width and shortens the line —
  // which is how the first version of this produced 71-character rows inside an
  // 80-character frame.
  const left: { text: string; label?: string; severity?: Severity }[] = [];
  if (visible.length === 0) {
    left.push({ text: '  No findings match this filter.' });
  } else {
    // One row is held back for the "… N more" line when the list does not fit,
    // otherwise the hint that tells you to narrow the view would itself be cut.
    const capacity = visible.length > bodyRows ? Math.max(1, bodyRows - 1) : bodyRows;

    for (let index = 0; index < Math.min(visible.length, capacity); index++) {
      const entry = visible[index];
      if (!entry) continue;
      const cursor = index === state.cursor ? '▸' : ' ';
      const location = entry.diagnostic.position ? `line ${entry.diagnostic.position.line}` : '—';
      const rule = truncate(entry.diagnostic.rule, Math.max(1, listWidth - 14));
      const label = severityText(entry.diagnostic.severity, false);

      left.push({
        text: truncate(`${cursor} ${label} ${rule} ${location}`, listWidth).padEnd(listWidth),
        label,
        severity: entry.diagnostic.severity,
      });
    }

    if (visible.length > bodyRows) {
      left.push({ text: `  … ${visible.length - bodyRows} more (filter or search to narrow)` });
    }
  }

  const right: string[] = [];
  if (state.expanded) {
    const entry = selectedEntry(state);

    if (!entry) {
      right.push(' Nothing selected.');
    } else {
      const { diagnostic } = entry;
      const heading = `${entry.file}${diagnostic.position ? `:${diagnostic.position.line}` : ''}`;
      right.push(` ${heading}`);

      const blocks = [
        diagnostic.message,
        diagnostic.suggestion === undefined ? undefined : `→ ${diagnostic.suggestion}`,
        diagnostic.helpUri,
      ];
      for (const block of blocks) {
        if (block === undefined) continue;
        for (const line of wrap(block, panelWidth - 2)) right.push(` ${line}`);
        if (right.length >= bodyRows) break;
      }
    }
  }

  for (let index = 0; index < Math.min(Math.max(left.length, right.length, 1), bodyRows); index++) {
    const row = left[index];
    const fitted = bodyRow(row?.text ?? '', right[index] ?? '');

    lines.push(
      color && row?.label !== undefined && row.severity !== undefined
        ? fitted.replace(row.label, `${ANSI[row.severity]}${row.label}${RESET}`)
        : fitted,
    );
  }

  lines.push(`├${'─'.repeat(inner)}┤`);

  if (state.status) {
    lines.push(`│${truncate(` ${state.status}`, inner).padEnd(inner)}│`);
  }

  const keys = [
    'j/k ↑↓ move',
    'Enter details',
    's filter',
    '/ search',
    options.autofix === false ? '' : 'f fix',
    'q quit',
  ]
    .filter(Boolean)
    .join(' · ');
  lines.push(`│${paint(DIM, truncate(` ${keys}`, inner).padEnd(inner))}│`);
  lines.push(`└${'─'.repeat(inner)}┘`);

  return lines.join('\n');
}

// ── the TTY loop ────────────────────────────────────────────────────────────

export interface DashboardStreams {
  stdin: NodeJS.ReadStream & { setRawMode?: (mode: boolean) => void };
  stdout: NodeJS.WriteStream;
}

/**
 * True when a full-screen view makes sense. A dashboard written into a pipe or
 * a file would corrupt the output it is meant to replace, so the caller falls
 * back to the text reporter instead.
 */
export function supportsDashboard(stdout: { isTTY?: boolean }): boolean {
  return stdout.isTTY === true;
}

/**
 * Runs the dashboard until the user quits. Resolves without throwing with the
 * final state's exit signal: the caller decides the process exit code, which
 * keeps the verdict tied to the diagnostics.
 */
export async function runDashboard(
  run: { name: string; result: LintResult }[],
  streams: DashboardStreams,
  context: DashboardContext & RenderOptions = {},
): Promise<{ state: DashboardState; lines: string[] }> {
  const { stdin, stdout } = streams;
  const width = context.width ?? stdout.columns ?? DEFAULT_WIDTH;
  const height = context.height ?? stdout.rows ?? DEFAULT_HEIGHT;
  let state = createDashboardState(run, context.filter ?? 'all');
  const frames: string[] = [];

  const draw = (): void => {
    const frame = renderDashboard(state, {
      width,
      height,
      color: context.color ?? false,
      autofix: context.autofix !== undefined,
    });
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
      resolve({ state, lines: frames });
    };

    const onData = (chunk: string): void => {
      for (const key of chunk) {
        state = reduceDashboard(state, key, context);
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
