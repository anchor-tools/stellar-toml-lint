/**
 * Semantic diff between two `stellar.toml` documents.
 *
 * Run as `stellar-toml-lint diff <source> <target>`, where each side is a file,
 * an `http(s)` URL, or `-` for stdin — the live production document against the
 * candidate an anchor is about to deploy.
 *
 * A text diff answers "which lines moved", which is the wrong question here: the
 * canonical sort reorders keys, an editor reindents a table, and forty changed
 * lines turn out to mean nothing. This compares the *parsed* documents, so layout
 * produces an empty diff and every change it does report is one a client would
 * read differently. Array entries pair on their SEP-1 identity key — `code` for
 * currencies, `PUBLIC_KEY` for validators — rather than their position, so a
 * currency is still the same currency when the entries around it move.
 */

import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import process from 'node:process';
import { parse } from 'smol-toml';
import { makeColors } from '../reporters.js';
import { ACCOUNT_ID_FIELDS, DEPRECATED_FIELDS, HTTPS_ENDPOINT_FIELDS } from '../spec.js';
import { CANONICAL_ARRAY_ORDER } from './canonicalSortCodemod.js';

export type DiffKind = 'added' | 'removed' | 'modified';

/** What a changed path *is*, which is what decides whether it breaks anyone. */
export type DiffCategory =
  | 'network'
  | 'signing-key'
  | 'endpoint'
  | 'documentation'
  | 'currency'
  | 'validator'
  | 'principal'
  | 'general';

export interface SemanticChange {
  /** Dotted path with array keys, e.g. `CURRENCIES[USD].issuer`. */
  path: string;
  kind: DiffKind;
  /** SEP-1 section the path lives in; `''` is the document root. */
  section: string;
  category: DiffCategory;
  breaking: boolean;
  /** Set when `breaking`: what a client already holds that stops working. */
  reason?: string;
  /** The leaf value, or the whole entry for an array-table add or removal. */
  before?: unknown;
  after?: unknown;
}

export interface SemanticDiffSide {
  /** Exactly what the caller passed: a path, a URL, or `-`. */
  input: string;
  parsed: boolean;
  /** Why the side could not be diffed, when `parsed` is false. */
  error?: string;
  /** Top-level fields, so an empty document reads as empty and not as equal. */
  fields: number;
}

export interface SemanticDiff {
  source: SemanticDiffSide;
  target: SemanticDiffSide;
  /** In document order: source keys first, then whatever only the target has. */
  changes: SemanticChange[];
  added: number;
  removed: number;
  modified: number;
  breaking: number;
}

export interface SemanticTomlDifferOptions {
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

export interface DiffLabels {
  source?: string;
  target?: string;
}

/** How long a side is given over the network before the run gives up. */
const DEFAULT_TIMEOUT_MS = 10_000;

/** Collection members shown before the rest collapse into a count. */
const MAX_LIST_ITEMS = 3;

const SIGNING_KEY_FIELDS = new Set<string>(ACCOUNT_ID_FIELDS);
const ENDPOINT_FIELDS = new Set<string>(HTTPS_ENDPOINT_FIELDS);

/** Root fields whose value clients already hold, so a new one invalidates it. */
const CRITICAL_ROOT_FIELDS: Readonly<Record<string, string>> = {
  NETWORK_PASSPHRASE:
    'asset and account IDs are only meaningful on the network named here, so every client that resolved the old value is now on the wrong network',
  SIGNING_KEY:
    'SEP-10 and SEP-45 responses are verified against this key, so clients holding the previous one start rejecting the anchor',
  URI_REQUEST_SIGNING_KEY: 'clients verify signed asset URI requests against this key',
};

/**
 * Which SEP a root endpoint field announces, transcribed from the SEP-1 field
 * tables. Deleting the field deletes the support, which is why this is the one
 * catalog a *removal* consults.
 */
const SEP_BY_ENDPOINT_FIELD: Readonly<Record<string, string>> = {
  FEDERATION_SERVER: 'SEP-2 federation',
  AUTH_SERVER: 'SEP-3 compliance',
  TRANSFER_SERVER: 'SEP-6 deposits and withdrawals',
  TRANSFER_SERVER_SEP0024: 'SEP-24 interactive transfers',
  KYC_SERVER: 'SEP-12 customer data',
  WEB_AUTH_ENDPOINT: 'SEP-10 authentication',
  WEB_AUTH_FOR_CONTRACTS_ENDPOINT: 'SEP-45 smart contract authentication',
  DIRECT_PAYMENT_SERVER: 'SEP-31 remittances',
  ANCHOR_QUOTE_SERVER: 'SEP-38 quotes',
};

/**
 * Entry fields that carry an identity wallets or peers have already stored,
 * keyed by the section they live in.
 */
const CRITICAL_ENTRY_FIELDS: Readonly<Record<string, Record<string, string>>> = {
  CURRENCIES: {
    issuer: 'the issuer account is part of the asset, so this code now names a different asset',
    contract: 'the smart contract is the asset, so wallets are pointed at a different token',
  },
  VALIDATORS: {
    HOST: 'other operators write this host into their stellar-core quorum config',
    ALIAS: 'the alias is the name operators use to reference this validator in quorum slices',
  },
};

/** Array sections where losing an entry takes something away from a client. */
const BREAKING_REMOVAL_SECTIONS: Readonly<Record<string, string>> = {
  CURRENCIES: 'the asset is no longer advertised, so wallets and exchanges stop offering it',
  VALIDATORS: 'operators following this validator lose the contact information for it',
};

const SECTION_CATEGORY: Readonly<Record<string, DiffCategory>> = {
  DOCUMENTATION: 'documentation',
  PRINCIPALS: 'principal',
  CURRENCIES: 'currency',
  VALIDATORS: 'validator',
};

/** A parsed side plus the document, which stays out of the report. */
interface ParseResult extends SemanticDiffSide {
  document?: Record<string, unknown>;
}

/** How an array's entries are paired, and what dropping one costs a client. */
interface ArrayMatch {
  identity?: string;
  removal?: string;
}

const NO_MATCH: ArrayMatch = {};

export class SemanticTomlDiffer {
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;

  constructor(options: SemanticTomlDifferOptions = {}) {
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  /** Diff two documents that are already in memory. */
  diff(sourceText: string, targetText: string, labels: DiffLabels = {}): SemanticDiff {
    const source = parseSide(labels.source ?? 'source', sourceText);
    const target = parseSide(labels.target ?? 'target', targetText);
    const changes =
      source.document !== undefined && target.document !== undefined
        ? this.diffRecords(source.document, target.document, '', '')
        : [];

    return {
      source: withoutDocument(source),
      target: withoutDocument(target),
      changes,
      added: changes.filter((change) => change.kind === 'added').length,
      removed: changes.filter((change) => change.kind === 'removed').length,
      modified: changes.filter((change) => change.kind === 'modified').length,
      breaking: changes.filter((change) => change.breaking).length,
    };
  }

  /**
   * Load both sides and diff them.
   *
   * Each input is an `http(s)` URL, a path, or `-` for stdin — but only one of
   * them may be `-`, since there is a single stream to read.
   */
  async diffInputs(sourceInput: string, targetInput: string): Promise<SemanticDiff> {
    const [sourceText, targetText] = await Promise.all([
      this.load(sourceInput),
      this.load(targetInput),
    ]);
    return this.diff(sourceText, targetText, { source: sourceInput, target: targetInput });
  }

  /** Resolve one input reference to the text it points at. */
  async load(input: string): Promise<string> {
    if (/^https?:\/\//i.test(input)) {
      const response = await this.fetchImpl(input, { signal: AbortSignal.timeout(this.timeoutMs) });
      if (!response.ok) throw new Error(`Could not fetch ${input}: HTTP ${response.status}`);
      return response.text();
    }
    if (input === '-') return readStdin();
    return readFile(resolve(input), 'utf8');
  }

  private diffRecords(
    before: Record<string, unknown>,
    after: Record<string, unknown>,
    basePath: string,
    section: string,
  ): SemanticChange[] {
    const changes: SemanticChange[] = [];
    for (const key of unionKeys(before, after)) {
      const path = join(basePath, key);
      // `Object.hasOwn` rather than `in`: `smol-toml` hands back prototypes-less
      // tables, which have no inherited members to trip over and no
      // `hasOwnProperty` method to call.
      const hasBefore = Object.hasOwn(before, key);
      const hasAfter = Object.hasOwn(after, key);
      // Only the document root introduces a section: `WEB_AUTH_ENDPOINT` is a
      // root field of its own, while the fields under it belong to DOCUMENTATION.
      const childSection = section === '' ? key : section;

      if (!hasBefore || !hasAfter) {
        changes.push(
          ...this.diffOneSided(
            path,
            section,
            childSection,
            hasBefore ? before[key] : undefined,
            hasAfter ? after[key] : undefined,
          ),
        );
      } else {
        changes.push(...this.diffValues(before[key], after[key], path, section, childSection));
      }
    }
    return changes;
  }

  /**
   * A key only one of the documents has.
   *
   * An array table is still reported entry by entry when the whole section
   * disappeared: an anchor that drops its last `[[CURRENCIES]]` has delisted an
   * asset exactly as surely as one that dropped one of five, and the path should
   * say which asset either way.
   */
  private diffOneSided(
    path: string,
    section: string,
    childSection: string,
    before: unknown,
    after: unknown,
  ): SemanticChange[] {
    const present = before === undefined ? after : before;
    if (Array.isArray(present) && present.length > 0 && present.every(isRecord)) {
      return this.diffArrays(
        Array.isArray(before) ? before : [],
        Array.isArray(after) ? after : [],
        path,
        childSection,
        this.matchFor(section, childSection),
      );
    }
    const kind: DiffKind = before === undefined ? 'added' : 'removed';
    return [this.change(path, section, kind, before, after)];
  }

  /**
   * `section` is where a change to this value belongs; `childSection` is where a
   * change to what the value *contains* belongs. They differ only at the root,
   * where a table names the SEP-1 section its fields live in.
   */
  private diffValues(
    before: unknown,
    after: unknown,
    path: string,
    section: string,
    childSection: string,
  ): SemanticChange[] {
    if (isRecord(before) && isRecord(after)) {
      return this.diffRecords(before, after, path, childSection);
    }
    if (Array.isArray(before) && Array.isArray(after)) {
      return this.diffArrays(
        before,
        after,
        path,
        childSection,
        this.matchFor(section, childSection),
      );
    }
    if (sameValue(before, after)) return [];
    return [this.change(path, section, 'modified', before, after)];
  }

  /**
   * How the entries of an array are identified and what losing one means. Only a
   * top-level table has either: `[[CURRENCIES]]` is keyed by `code`, while a
   * nested `collateral_addresses` is a list of strings with nothing to match on.
   */
  private matchFor(section: string, childSection: string): ArrayMatch {
    if (section !== '') return NO_MATCH;
    return {
      identity: CANONICAL_ARRAY_ORDER[childSection],
      removal: BREAKING_REMOVAL_SECTIONS[childSection],
    };
  }

  /**
   * Compare array entries by identity rather than position.
   *
   * Sections SEP-1 gives an identity key to (`code`, `PUBLIC_KEY`) match on it, so
   * reordering `[[CURRENCIES]]` is not a diff. Everything else — `[[PRINCIPALS]]`
   * and nested arrays like `collateral_addresses` — is compared position by
   * position, which means a mid-list removal reads as a run of modifications
   * ending in one removal. That is the same trade a line diff makes, and it is
   * the honest one when the entries carry nothing to match on.
   */
  private diffArrays(
    before: unknown[],
    after: unknown[],
    path: string,
    section: string,
    match: ArrayMatch,
  ): SemanticChange[] {
    const beforeKeys = entryKeys(before, match.identity);
    const afterKeys = entryKeys(after, match.identity);
    const afterIndex = new Map<string, number>();
    afterKeys.forEach((key, index) => afterIndex.set(key, index));
    const beforeIndex = new Map<string, number>();
    beforeKeys.forEach((key, index) => beforeIndex.set(key, index));

    const changes: SemanticChange[] = [];
    beforeKeys.forEach((key, index) => {
      const entryPath = `${path}[${key}]`;
      const matched = afterIndex.get(key);
      if (matched === undefined) {
        changes.push(this.entryChange(entryPath, section, 'removed', before[index], match));
      } else {
        changes.push(
          ...this.diffValues(before[index], after[matched], entryPath, section, section),
        );
      }
    });
    afterKeys.forEach((key, index) => {
      if (beforeIndex.has(key)) return;
      changes.push(this.entryChange(`${path}[${key}]`, section, 'added', after[index], match));
    });
    return changes;
  }

  /** A whole array-table entry appearing or disappearing. */
  private entryChange(
    path: string,
    section: string,
    kind: 'added' | 'removed',
    value: unknown,
    match: ArrayMatch,
  ): SemanticChange {
    return this.build(
      path,
      section,
      kind,
      kind === 'removed' ? value : undefined,
      kind === 'added' ? value : undefined,
      kind === 'removed' ? match.removal : undefined,
    );
  }

  private change(
    path: string,
    section: string,
    kind: DiffKind,
    before: unknown,
    after: unknown,
  ): SemanticChange {
    return this.build(path, section, kind, before, after, this.reasonFor(section, path, kind));
  }

  private build(
    path: string,
    section: string,
    kind: DiffKind,
    before: unknown,
    after: unknown,
    reason: string | undefined,
  ): SemanticChange {
    const field = fieldOf(path);
    const change: SemanticChange = {
      path,
      kind,
      section,
      category: categoryOf(section, field),
      breaking: reason !== undefined,
    };
    if (reason !== undefined) change.reason = reason;
    if (kind !== 'removed') change.after = after;
    if (kind !== 'added') change.before = before;
    return change;
  }

  /** Why this change breaks a client that read the source document. */
  private reasonFor(section: string, path: string, kind: DiffKind): string | undefined {
    // Publishing something new cannot break a client that has not seen it.
    if (kind === 'added') return undefined;
    const field = fieldOf(path);

    if (section === '') {
      const critical = CRITICAL_ROOT_FIELDS[field];
      if (critical !== undefined) return critical;
      if (kind === 'removed' && !isDeprecated(field)) {
        const sep = SEP_BY_ENDPOINT_FIELD[field];
        if (sep !== undefined) return `${field} is how clients discover ${sep}; it is now gone`;
      }
      return undefined;
    }

    return CRITICAL_ENTRY_FIELDS[section]?.[field];
  }
}

/** {@link SemanticTomlDiffer.diff} without constructing one. */
export function diffSemanticToml(
  sourceText: string,
  targetText: string,
  labels: DiffLabels = {},
): SemanticDiff {
  return new SemanticTomlDiffer().diff(sourceText, targetText, labels);
}

/**
 * Terminal markdown for a diff report.
 *
 * Markdown headings and bullets so the same text drops into a pull-request
 * comment, with the `+` and `-` markers coloured the way `git diff` colours them.
 * A report whose side did not parse says so instead of claiming there is nothing
 * to review.
 */
export function renderSemanticDiff(report: SemanticDiff, color = false): string {
  const c = makeColors(color);
  const lines: string[] = ['# stellar.toml semantic diff', ''];

  for (const side of [report.source, report.target]) {
    const detail = side.parsed
      ? c.grey(`(${count(side.fields, 'field')})`)
      : c.red('did not parse');
    lines.push(
      `- **${side === report.source ? 'source' : 'target'}:** \`${side.input}\` ${detail}`,
    );
  }
  lines.push('');

  for (const side of [report.source, report.target]) {
    if (side.error !== undefined) lines.push(c.red(`! ${side.input}: ${side.error}`));
  }
  if (!report.source.parsed || !report.target.parsed) return `${lines.join('\n')}\n`;

  lines.push(summaryLine(report, c));
  lines.push('');

  if (report.changes.length === 0) {
    lines.push(
      'No semantic changes. The documents describe the same configuration, whatever order, ' +
        'indentation and comments they happen to use.',
    );
    return `${lines.join('\n')}\n`;
  }

  lines.push('## Changes', '');
  for (const change of report.changes) lines.push(...renderChange(change, c));
  return `${lines.join('\n')}\n`;
}

/** Machine-readable changelog: the report, verbatim, as pretty-printed JSON. */
export function renderSemanticDiffJson(report: SemanticDiff): string {
  return `${JSON.stringify(report, null, 2)}\n`;
}

type Colors = ReturnType<typeof makeColors>;

function summaryLine(report: SemanticDiff, c: Colors): string {
  const parts = [
    c.green(`${report.added} added`),
    c.red(`${report.removed} removed`),
    c.yellow(`${report.modified} modified`),
  ];
  const alert = `${report.breaking} ${plural(report.breaking, 'breaking change')}`;
  parts.push(report.breaking > 0 ? c.bold(c.red(`BREAKING: ${alert}`)) : c.grey('0 breaking'));
  return parts.join(' · ');
}

function renderChange(change: SemanticChange, c: Colors): string[] {
  const sign =
    change.kind === 'added' ? c.green('+') : change.kind === 'removed' ? c.red('-') : c.yellow('~');
  const tag = change.breaking ? ` ${c.bold(c.red('BREAKING'))}` : '';
  const lines = [`${sign} \`${change.path}\`${tag}`];

  if (change.kind === 'modified') {
    lines.push(`  ${c.red(`- ${formatValue(change.before)}`)}`);
    lines.push(`  ${c.green(`+ ${formatValue(change.after)}`)}`);
  } else {
    const value = change.kind === 'added' ? change.after : change.before;
    lines.push(`  ${sign} ${formatValue(value)}`);
  }
  if (change.reason !== undefined) lines.push(`  ${c.red('!')} ${change.reason}`);
  return lines;
}

/**
 * One-line rendering of a value.
 *
 * Whole entries are added and removed as units, so their contents have to fit on
 * a line: the first few members show, the rest collapse into a count, and the
 * JSON report stays the complete record.
 */
export function formatValue(value: unknown): string {
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (value instanceof Date) return value.toISOString();
  if (Array.isArray(value)) {
    const shown = value.slice(0, MAX_LIST_ITEMS).map(formatValue);
    if (shown.length < value.length) shown.push(`… ${value.length - shown.length} more`);
    return `[${shown.join(', ')}]`;
  }
  if (isRecord(value)) {
    const entries = Object.entries(value);
    const shown = entries
      .slice(0, MAX_LIST_ITEMS)
      .map(([key, item]) => `${key}=${formatLeaf(item)}`);
    if (shown.length < entries.length) shown.push(`… ${entries.length - shown.length} more`);
    return `{${shown.join(', ')}}`;
  }
  return String(value);
}

/** Nested collections get no room in a one-line summary. */
function formatLeaf(value: unknown): string {
  if (Array.isArray(value)) return `[${value.length} values]`;
  if (isRecord(value)) return `{${Object.keys(value).length} fields}`;
  return formatValue(value);
}

function parseSide(input: string, text: string): ParseResult {
  try {
    const document = parse(text) as Record<string, unknown>;
    return { input, parsed: true, fields: Object.keys(document).length, document };
  } catch (error) {
    return { input, parsed: false, fields: 0, error: `Invalid TOML: ${firstLine(error)}` };
  }
}

/** The report is a changelog; the parsed document it was derived from is not. */
function withoutDocument(side: ParseResult): SemanticDiffSide {
  const report: SemanticDiffSide = {
    input: side.input,
    parsed: side.parsed,
    fields: side.fields,
  };
  if (side.error !== undefined) report.error = side.error;
  return report;
}

/**
 * Keys of both tables, source order first.
 */
function unionKeys(before: Record<string, unknown>, after: Record<string, unknown>): string[] {
  const seen = new Set<string>();
  const keys: string[] = [];
  for (const key of [...Object.keys(before), ...Object.keys(after)]) {
    if (seen.has(key)) continue;
    seen.add(key);
    keys.push(key);
  }
  return keys;
}

function entryKeys(entries: unknown[], identity: string | undefined): string[] {
  const counts = new Map<string, number>();
  return entries.map((entry, index) => {
    const raw = identity === undefined || !isRecord(entry) ? undefined : entry[identity];
    const base =
      typeof raw === 'string' && raw.length > 0
        ? raw
        : typeof raw === 'number'
          ? String(raw)
          : `#${index + 1}`;
    const seen = (counts.get(base) ?? 0) + 1;
    counts.set(base, seen);
    return seen === 1 ? base : `${base}#${seen}`;
  });
}

function sameValue(before: unknown, after: unknown): boolean {
  if (before === after) return true;
  return canonicalText(before) === canonicalText(after);
}

/**
 * JSON text with table keys in sorted order.
 *
 * Sorting is the point: two nested tables that agree field by field but were
 * written in a different order are the same value, and a diff that says otherwise
 * is the noise this module exists to remove.
 */
function canonicalText(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalText).join(',')}]`;
  if (value instanceof Date) return value.toISOString();
  if (isRecord(value)) {
    const entries = Object.keys(value)
      .sort()
      .map((key) => `${key}:${canonicalText(value[key])}`);
    return `{${entries.join(',')}}`;
  }
  return JSON.stringify(value) ?? String(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function categoryOf(section: string, field: string): DiffCategory {
  if (section !== '') return SECTION_CATEGORY[section] ?? 'general';
  if (field === 'NETWORK_PASSPHRASE') return 'network';
  if (SIGNING_KEY_FIELDS.has(field)) return 'signing-key';
  if (ENDPOINT_FIELDS.has(field)) return 'endpoint';
  return SECTION_CATEGORY[field] ?? 'general';
}

function isDeprecated(field: string): boolean {
  return Object.hasOwn(DEPRECATED_FIELDS, field);
}

function fieldOf(path: string): string {
  const dot = path.lastIndexOf('.');
  return dot === -1 ? path : path.slice(dot + 1);
}

function join(base: string, key: string): string {
  return base === '' ? key : `${base}.${key}`;
}

function firstLine(error: unknown): string {
  const text = error instanceof Error ? error.message : String(error);
  return text.split('\n')[0]?.trim() || 'could not parse the file';
}

function count(n: number, word: string): string {
  return `${n} ${plural(n, word)}`;
}

function plural(n: number, word: string): string {
  return n === 1 ? word : `${word}s`;
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString('utf8');
}
