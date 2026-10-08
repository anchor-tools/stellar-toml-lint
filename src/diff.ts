/**
 * Semantic comparison of two stellar.toml versions.
 *
 * A file can be perfectly valid against SEP-1 and still break every wallet that
 * already trusts its assets: dropping an issuer, flipping a status to dead,
 * or rotating SIGNING_KEY all parse cleanly. --diff exists to surface those
 * moves before a PR merges, with severities chosen for that audience rather
 * than for the linter.
 *
 * Severity contract:
 * - BREAKING: something an existing integration would stop working over.
 *   The CLI exits 1 when any of these are present.
 * - WARNING: a material change that is not automatically fatal.
 * - INFO: purely additive, or cosmetic.
 */
import { parse } from 'smol-toml';
import { HTTPS_ENDPOINT_FIELDS, ISSUANCE_FIELDS } from './spec.js';

export type DiffSeverity = 'BREAKING' | 'WARNING' | 'INFO';

/** One semantic difference between the base and target documents. */
export interface TomlDifference {
  /** Dotted path into the document, e.g. CURRENCIES[USDX].issuer. */
  path: string;
  message: string;
  severity: DiffSeverity;
  breaking: boolean;
}

const SEVERITY_RANK: Record<DiffSeverity, number> = { BREAKING: 0, WARNING: 1, INFO: 2 };

/** Fields whose change invalidates existing sessions or network identity. */
const CRITICAL_GLOBAL_FIELDS = ['SIGNING_KEY', 'NETWORK_PASSPHRASE'] as const;

const ENDPOINT_FIELDS = new Set<string>(HTTPS_ENDPOINT_FIELDS);

/**
 * Compares two stellar.toml sources and returns every semantic difference.
 *
 * Both documents must parse; a syntax error throws so the caller can map it to
 * exit code 2 rather than pretending the files are equal or unrelated.
 */
export function compareToml(baseSource: string, targetSource: string): TomlDifference[] {
  const base = parse(baseSource) as Record<string, unknown>;
  const target = parse(targetSource) as Record<string, unknown>;
  const differences: TomlDifference[] = [];

  compareCurrencies(base, target, differences);
  compareValidators(base, target, differences);
  compareGlobals(base, target, differences);
  compareFlatTable(base, target, 'DOCUMENTATION', differences);
  comparePrincipals(base, target, differences);

  return differences.sort((a, b) => {
    const bySeverity = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
    if (bySeverity !== 0) return bySeverity;
    return a.path.localeCompare(b.path);
  });
}

/** True when any difference is marked breaking. */
export function hasBreakingChanges(differences: TomlDifference[]): boolean {
  return differences.some((d) => d.breaking);
}

/** Counts differences per severity, always returning all three keys. */
export function countDifferences(differences: TomlDifference[]): Record<DiffSeverity, number> {
  const counts: Record<DiffSeverity, number> = { BREAKING: 0, WARNING: 0, INFO: 0 };
  for (const d of differences) counts[d.severity]++;
  return counts;
}

export interface FormatDiffOptions {
  color?: boolean;
}

/** Renders a human-readable summary of compareToml output. */
export function formatDiff(
  differences: TomlDifference[],
  files: { base: string; target: string },
  options: FormatDiffOptions = {},
): string {
  const color = options.color === true;

  if (differences.length === 0) {
    return `No differences between ${files.base} and ${files.target}\n`;
  }

  const paint = (severity: DiffSeverity, text: string): string => {
    if (!color) return text;
    const open = severity === 'BREAKING' ? 31 : severity === 'WARNING' ? 33 : 36;
    return `[${open}m${text}[39m`;
  };

  const lines: string[] = [`Diff: ${files.base} -> ${files.target}`, ''];
  for (const d of differences) {
    lines.push(`${paint(d.severity, d.severity.padEnd(8))} ${d.path}  ${d.message}`);
  }

  const counts = countDifferences(differences);
  lines.push('');
  lines.push(
    `${counts.BREAKING} breaking, ${counts.WARNING} warning${counts.WARNING === 1 ? '' : 's'}, ${counts.INFO} info${counts.INFO === 1 ? '' : 's'}`,
  );
  return `${lines.join('\n')}\n`;
}

// ---------------------------------------------------------------------------
// Document helpers
// ---------------------------------------------------------------------------

type Table = Record<string, unknown>;

function isTable(value: unknown): value is Table {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function asTables(value: unknown): Table[] {
  if (!Array.isArray(value)) return [];
  return value.filter(isTable);
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((item, i) => deepEqual(item, b[i]));
  }
  if (isTable(a) && isTable(b)) {
    const aKeys = Object.keys(a);
    const bKeys = Object.keys(b);
    if (aKeys.length !== bKeys.length) return false;
    return aKeys.every((key) => key in b && deepEqual(a[key], b[key]));
  }
  return false;
}

function display(value: unknown): string {
  if (value === undefined) return '(absent)';
  if (typeof value === 'string') return JSON.stringify(value);
  try {
    return JSON.stringify(value) ?? String(value);
  } catch {
    return String(value);
  }
}

function push(
  differences: TomlDifference[],
  path: string,
  message: string,
  severity: DiffSeverity,
): void {
  differences.push({ path, message, severity, breaking: severity === 'BREAKING' });
}

// ---------------------------------------------------------------------------
// CURRENCIES
// ---------------------------------------------------------------------------

/**
 * Stable identity for a currency across versions.
 *
 * code (or code_template for contract-only assets) is what wallets and
 * trustlines key on: an issuer edit must read as a mutation of the same
 * asset, not as remove-plus-add. Duplicate codes (already a lint error) fall
 * back to occurrence order so pairing stays deterministic.
 */
function currencyKeys(entries: Table[]): Map<string, Table> {
  const keyed = new Map<string, Table>();
  const seen = new Map<string, number>();

  entries.forEach((entry, index) => {
    const raw = typeof entry.code === 'string' && entry.code !== '' ? entry.code : undefined;
    const template =
      typeof entry.code_template === 'string' && entry.code_template !== ''
        ? entry.code_template
        : undefined;
    const stem = raw ?? (template !== undefined ? 'template:' + template : undefined);

    let key: string;
    if (stem === undefined) {
      key = 'index:' + index;
    } else {
      const n = seen.get(stem) ?? 0;
      seen.set(stem, n + 1);
      key = n === 0 ? stem : stem + '#' + n;
    }
    keyed.set(key, entry);
  });

  return keyed;
}

function isLive(status: unknown): boolean {
  return status === 'live';
}

function compareCurrencies(base: Table, target: Table, differences: TomlDifference[]): void {
  const baseMap = currencyKeys(asTables(base.CURRENCIES));
  const targetMap = currencyKeys(asTables(target.CURRENCIES));

  for (const key of baseMap.keys()) {
    if (!targetMap.has(key)) {
      push(differences, 'CURRENCIES[' + key + ']', 'currency ' + key + ' was removed', 'BREAKING');
    }
  }

  for (const key of targetMap.keys()) {
    if (!baseMap.has(key)) {
      push(differences, 'CURRENCIES[' + key + ']', 'currency ' + key + ' was added', 'INFO');
    }
  }

  for (const [key, before] of baseMap) {
    const after = targetMap.get(key);
    if (!after) continue;
    compareCurrencyEntry(key, before, after, differences);
  }
}

function compareCurrencyEntry(
  key: string,
  before: Table,
  after: Table,
  differences: TomlDifference[],
): void {
  const path = (field: string): string => 'CURRENCIES[' + key + '].' + field;

  for (const field of ['issuer', 'contract']) {
    const from = before[field];
    const to = after[field];
    if (deepEqual(from, to)) continue;
    if (from !== undefined && to === undefined) {
      push(differences, path(field), field + ' was removed: ' + display(from), 'BREAKING');
    } else if (from === undefined && to !== undefined) {
      push(differences, path(field), field + ' was added (was absent)', 'WARNING');
    } else {
      push(
        differences,
        path(field),
        field + ' changed from ' + display(from) + ' to ' + display(to),
        'BREAKING',
      );
    }
  }

  for (const field of ISSUANCE_FIELDS) {
    if (!deepEqual(before[field], after[field])) {
      push(
        differences,
        path(field),
        'issuance rule ' +
          field +
          ' changed from ' +
          display(before[field]) +
          ' to ' +
          display(after[field]),
        'BREAKING',
      );
    }
  }

  const statusBefore = before.status;
  const statusAfter = after.status;
  if (!deepEqual(statusBefore, statusAfter)) {
    if (isLive(statusBefore) && !isLive(statusAfter)) {
      push(
        differences,
        path('status'),
        'status changed from live to ' +
          display(statusAfter) +
          ' - existing holders may be affected',
        'BREAKING',
      );
    } else {
      push(
        differences,
        path('status'),
        'status changed from ' + display(statusBefore) + ' to ' + display(statusAfter),
        'WARNING',
      );
    }
  }

  const fields = new Set([...Object.keys(before), ...Object.keys(after)]);
  const handled = new Set<string>([...ISSUANCE_FIELDS, 'issuer', 'contract', 'status']);
  for (const field of fields) {
    if (handled.has(field)) continue;
    if (deepEqual(before[field], after[field])) continue;
    push(
      differences,
      path(field),
      'changed from ' + display(before[field]) + ' to ' + display(after[field]),
      'WARNING',
    );
  }
}

// ---------------------------------------------------------------------------
// VALIDATORS
// ---------------------------------------------------------------------------

function validatorKeys(entries: Table[]): Map<string, Table> {
  const keyed = new Map<string, Table>();
  const seen = new Map<string, number>();

  entries.forEach((entry, index) => {
    const alias = typeof entry.ALIAS === 'string' && entry.ALIAS !== '' ? entry.ALIAS : undefined;
    const stem = alias ?? 'index:' + index;
    const n = seen.get(stem) ?? 0;
    seen.set(stem, n + 1);
    keyed.set(n === 0 ? stem : stem + '#' + n, entry);
  });

  return keyed;
}

function compareValidators(base: Table, target: Table, differences: TomlDifference[]): void {
  const baseMap = validatorKeys(asTables(base.VALIDATORS));
  const targetMap = validatorKeys(asTables(target.VALIDATORS));

  for (const key of baseMap.keys()) {
    if (!targetMap.has(key)) {
      push(differences, 'VALIDATORS[' + key + ']', 'validator ' + key + ' was removed', 'BREAKING');
    }
  }

  for (const key of targetMap.keys()) {
    if (!baseMap.has(key)) {
      push(differences, 'VALIDATORS[' + key + ']', 'validator ' + key + ' was added', 'INFO');
    }
  }

  for (const [key, before] of baseMap) {
    const after = targetMap.get(key);
    if (!after) continue;

    if (!deepEqual(before.PUBLIC_KEY, after.PUBLIC_KEY)) {
      push(
        differences,
        'VALIDATORS[' + key + '].PUBLIC_KEY',
        'PUBLIC_KEY changed from ' +
          display(before.PUBLIC_KEY) +
          ' to ' +
          display(after.PUBLIC_KEY),
        'BREAKING',
      );
    }

    const fields = new Set([...Object.keys(before), ...Object.keys(after)]);
    for (const field of fields) {
      if (field === 'PUBLIC_KEY') continue;
      if (deepEqual(before[field], after[field])) continue;
      push(
        differences,
        'VALIDATORS[' + key + '].' + field,
        'changed from ' + display(before[field]) + ' to ' + display(after[field]),
        'WARNING',
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Globals, documentation, principals
// ---------------------------------------------------------------------------

function compareGlobals(base: Table, target: Table, differences: TomlDifference[]): void {
  const critical = new Set<string>(CRITICAL_GLOBAL_FIELDS);
  const fields = new Set([...Object.keys(base), ...Object.keys(target)]);

  for (const field of fields) {
    if (critical.has(field)) {
      if (deepEqual(base[field], target[field])) continue;
      push(
        differences,
        field,
        'changed from ' + display(base[field]) + ' to ' + display(target[field]),
        'BREAKING',
      );
      continue;
    }

    if (ENDPOINT_FIELDS.has(field)) {
      const from = base[field];
      const to = target[field];
      if (deepEqual(from, to)) continue;
      if (from !== undefined && to === undefined) {
        push(differences, field, 'endpoint was removed: ' + display(from), 'BREAKING');
      } else if (from === undefined && to !== undefined) {
        push(differences, field, 'endpoint was added: ' + display(to), 'INFO');
      } else {
        push(
          differences,
          field,
          'endpoint changed from ' + display(from) + ' to ' + display(to),
          'WARNING',
        );
      }
      continue;
    }

    if (field === 'CURRENCIES' || field === 'VALIDATORS') continue;
    if (field === 'DOCUMENTATION' || field === 'PRINCIPALS') continue;
    if (field in target && !(field in base)) {
      push(differences, field, 'added: ' + display(target[field]), 'INFO');
    } else if (!(field in target) && field in base) {
      push(differences, field, 'removed: ' + display(base[field]), 'WARNING');
    } else if (!deepEqual(base[field], target[field])) {
      push(
        differences,
        field,
        'changed from ' + display(base[field]) + ' to ' + display(target[field]),
        'WARNING',
      );
    }
  }
}

function compareFlatTable(
  base: Table,
  target: Table,
  name: 'DOCUMENTATION',
  differences: TomlDifference[],
): void {
  const before = isTable(base[name]) ? base[name] : undefined;
  const after = isTable(target[name]) ? target[name] : undefined;
  const fields = new Set([...Object.keys(before ?? {}), ...Object.keys(after ?? {})]);

  for (const field of fields) {
    const from = before?.[field];
    const to = after?.[field];
    const path = name + '.' + field;
    if (deepEqual(from, to)) continue;
    if (from !== undefined && to === undefined) {
      push(differences, path, 'removed: ' + display(from), 'WARNING');
    } else if (from === undefined && to !== undefined) {
      push(differences, path, 'added: ' + display(to), 'INFO');
    } else {
      push(differences, path, 'changed from ' + display(from) + ' to ' + display(to), 'WARNING');
    }
  }
}

function comparePrincipals(base: Table, target: Table, differences: TomlDifference[]): void {
  const keyBy = (entries: Table[]): Map<string, Table> => {
    const keyed = new Map<string, Table>();
    const seen = new Map<string, number>();
    entries.forEach((entry, index) => {
      const stem =
        typeof entry.email === 'string' && entry.email !== '' ? entry.email : 'index:' + index;
      const n = seen.get(stem) ?? 0;
      seen.set(stem, n + 1);
      keyed.set(n === 0 ? stem : stem + '#' + n, entry);
    });
    return keyed;
  };

  const before = keyBy(asTables(base.PRINCIPALS));
  const after = keyBy(asTables(target.PRINCIPALS));

  for (const key of before.keys()) {
    if (!after.has(key)) {
      push(differences, 'PRINCIPALS[' + key + ']', 'principal ' + key + ' was removed', 'WARNING');
    }
  }
  for (const key of after.keys()) {
    if (!before.has(key)) {
      push(differences, 'PRINCIPALS[' + key + ']', 'principal ' + key + ' was added', 'INFO');
    }
  }

  for (const [key, from] of before) {
    const to = after.get(key);
    if (!to) continue;
    const fields = new Set([...Object.keys(from), ...Object.keys(to)]);
    for (const field of fields) {
      if (deepEqual(from[field], to[field])) continue;
      push(
        differences,
        'PRINCIPALS[' + key + '].' + field,
        'changed from ' + display(from[field]) + ' to ' + display(to[field]),
        'WARNING',
      );
    }
  }
}
