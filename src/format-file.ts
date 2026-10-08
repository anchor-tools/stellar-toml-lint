/**
 * A canonicalising editor for `stellar.toml`.
 *
 * `smol-toml` (like most parsers) throws away everything that is not part of
 * the document — comments, blank lines, quoting style, the order keys were
 * written in. Reserialising would therefore "format" a file into something its
 * author no longer recognises, so this module rewrites the *source* instead:
 * it scans the text into blocks, reorders them against SEP-1, normalises the
 * whitespace and quoting around each value, and leaves every comment where the
 * author put it (comments travel with the construct that follows them).
 *
 * Three invariants hold for every input:
 *
 * 1. **Round-trip** — the output re-parses to exactly the same document as the
 *    input. This is checked before the caller ever sees a result; if it does
 *    not hold, the formatter refuses and reports an error rather than hand back
 *    a file it has silently changed.
 * 2. **Idempotence** — formatting an already-formatted file is a no-op.
 * 3. **Invalid input is not touched** — a parse failure means no output at all,
 *    so a half-written or corrupt file can never be rewritten by a hook.
 *
 * Deliberate limits: line breaks inside multi-line values (arrays, `"""` blocks)
 * are preserved rather than reflowed, because reflowing risks editing the
 * contents of a string. Whitespace changes are therefore confined to the
 * structure around values.
 */
import { parse } from 'smol-toml';
import type { Diagnostic, Position } from './types.js';
import {
  CURRENCY_FIELDS,
  DOCUMENTATION_FIELDS,
  GLOBAL_FIELDS,
  PRINCIPAL_FIELDS,
  TABLE_ORDER,
  VALIDATOR_FIELDS,
} from './spec.js';

/**
 * Converts a `smol-toml` parse failure into a positioned diagnostic.
 *
 * Deliberately local: `lint()` reads documents with the CST parser now, while
 * the formatter still parses with `smol-toml` to prove its rewrite round-trips,
 * so it needs the error shape `smol-toml` actually throws.
 */
function parseDiagnostic(error: unknown, source: string): Diagnostic {
  const position = positionOf(error) ?? (source.length > 0 ? { line: 1, column: 1 } : undefined);

  return {
    rule: 'file/parse',
    severity: 'error',
    category: 'file',
    message: `Invalid TOML: ${cleanParseMessage(error)}`,
    position,
    helpUri: 'https://toml.io/en/v1.0.0',
    suggestion: 'Fix the syntax error — no other checks can run until the file parses.',
  };
}

/**
 * `smol-toml` throws a plain `Error` in some builds, but still attaches `line`
 * and `column`. Read them defensively rather than losing the position.
 */
function positionOf(error: unknown): Position | undefined {
  if (typeof error === 'object' && error !== null) {
    const candidate = error as { line?: unknown; column?: unknown };
    if (typeof candidate.line === 'number' && typeof candidate.column === 'number') {
      return { line: candidate.line, column: candidate.column };
    }
  }
  return undefined;
}

/** Strips the code frame that `smol-toml` appends to its message. */
function cleanParseMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return (
    message
      .split('\n')[0]
      ?.replace(/^Invalid TOML document:\s*/i, '')
      .trim() || 'could not parse the file'
  );
}

/** Result of a format attempt. On failure `output` is deliberately absent. */
export type FormatResult =
  | { ok: true; output: string; changed: boolean }
  | { ok: false; error: string; line?: number; column?: number };

/** Mutable state carried across the lines of a multi-line value. */
interface Walker {
  /** Bracket depth outside strings; arrays and inline tables nest. */
  depth: number;
  /** Set while inside `"""` or `'''`, which swallow everything until they close. */
  multiline: 'basic' | 'literal' | null;
}

interface Scan {
  /** Index of the `=` that separates key from value, or -1. */
  eq: number;
  /** Index of a trailing `#` comment outside any string or bracket, or -1. */
  comment: number;
}

interface HeaderItem {
  line: string;
  leading: string[];
}

interface KvItem {
  /** Normalised key text, used for ordering. */
  key: string;
  lines: string[];
  leading: string[];
  /** A blank line separated this item's comments from what came before. */
  spaced: boolean;
  /** Original position, so equal-rank items keep their order. */
  order: number;
}

interface Block {
  /** Dotted table path; `''` for the implicit root table. */
  name: string;
  header?: HeaderItem;
  kvs: KvItem[];
}

const BOM = '﻿';

/**
 * Rewrites `source` in canonical SEP-1 layout.
 *
 * Returns `{ ok: false }` for input that cannot be parsed (or that the
 * formatter cannot round-trip exactly); callers should then leave the file
 * alone and surface {@link FormatResult.error}.
 */
export function formatToml(source: string): FormatResult {
  const hasBom = source.startsWith(BOM);
  const body = hasBom ? source.slice(1) : source;

  let before: unknown;
  try {
    before = parse(body);
  } catch (error) {
    const diagnostic = parseDiagnostic(error, body);
    return {
      ok: false,
      error: `${diagnostic.message}. The file was left untouched.`,
      line: diagnostic.position?.line,
      column: diagnostic.position?.column,
    };
  }

  const scanned = scanDocument(body);
  if (!scanned.ok) return { ok: false, error: `${scanned.error}. The file was left untouched.` };

  let output = render(orderBlocks(scanned.blocks), scanned.trailer, scanned.eol);
  if (hasBom) output = BOM + output;

  if (output === source) return { ok: true, output, changed: false };

  // Belt and braces: never hand back a file whose meaning we cannot prove is
  // unchanged. This is what makes reordering safe on documents we have never
  // seen.
  let after: unknown;
  try {
    after = parse(hasBom ? output.slice(1) : output);
  } catch (error) {
    const reason = error instanceof Error ? error.message.split('\n')[0] : String(error);
    return {
      ok: false,
      error: `Formatting would emit invalid TOML (${reason}). The file was left untouched.`,
    };
  }

  if (!deepEqual(before, after)) {
    return {
      ok: false,
      error: 'Formatting would change the parsed document. The file was left untouched.',
    };
  }

  return { ok: true, output, changed: true };
}

type ScanResult =
  { ok: true; blocks: Block[]; trailer: string[]; eol: string } | { ok: false; error: string };

/** Splits the source into blocks of a header plus the key/value items under it. */
function scanDocument(source: string): ScanResult {
  const lines = source.split('\n');
  const root: Block = { name: '', kvs: [] };
  const blocks: Block[] = [root];
  let current = root;
  let pending: string[] = [];
  let order = 0;

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i] ?? '';
    const trimmed = raw.trim();

    // Comments and blank lines are not constructs of their own: they are held
    // until the next construct appears and then become its leading lines, which
    // is what makes them survive a reordering.
    if (trimmed === '' || trimmed.startsWith('#')) {
      pending.push(raw);
      continue;
    }

    const leading = pending;
    const spaced = pending.some((line) => line.trim() === '');
    pending = [];

    const first = scanLine(raw, { depth: 0, multiline: null });

    if (first.eq < 0) {
      if (!trimmed.startsWith('[')) {
        return { ok: false, error: `Unsupported content at line ${i + 1}` };
      }
      current = {
        name: headerName(trimmed),
        header: { line: normaliseHeader(trimmed) + endOfLine(raw), leading },
        kvs: [],
      };
      blocks.push(current);
      continue;
    }

    const consumed = consumeKv(lines, i);
    if ('error' in consumed) return { ok: false, error: consumed.error };

    current.kvs.push({
      key: consumed.key,
      lines: consumed.lines,
      leading,
      spaced,
      order: order++,
    });
    i = consumed.end;
  }

  // Blank lines the formatter synthesises have to use the file's own line
  // ending, or a CRLF file would come back with holes in it.
  const eol = (lines[0] ?? '').endsWith('\r') ? '\r' : '';
  return { ok: true, blocks, trailer: pending, eol };
}

/**
 * Drops trailing spaces and tabs but keeps a carriage return, so a CRLF file
 * stays CRLF instead of acquiring a mixture of the two conventions.
 */
function rstripWs(text: string): string {
  return text.replace(/[ \t]+(\r?)$/, '$1');
}

/** The line terminator of a single source line, if it had one. */
function endOfLine(raw: string): string {
  return raw.endsWith('\r') ? '\r' : '';
}

/** `[ DOCUMENTATION ]` and `[[ CURRENCIES ]]` both become their tight form. */
function normaliseHeader(trimmed: string): string {
  const array = trimmed.startsWith('[[');
  const inner = array ? trimmed.slice(2, -2) : trimmed.slice(1, -1);
  return array ? `[[${inner.trim()}]]` : `[${inner.trim()}]`;
}

/** The table path a header declares, with quotes left exactly as written. */
function headerName(trimmed: string): string {
  return trimmed.startsWith('[[') ? trimmed.slice(2, -2).trim() : trimmed.slice(1, -1).trim();
}

interface Consumed {
  key: string;
  lines: string[];
  end: number;
}

interface ConsumeFailure {
  error: string;
}

/**
 * Consumes one key/value construct, which may span lines when the value is an
 * array or a multi-line string. Returns the normalised lines for it.
 */
function consumeKv(lines: string[], start: number): Consumed | ConsumeFailure {
  const walker: Walker = { depth: 0, multiline: null };
  const raw = lines[start] ?? '';
  const scan = scanLine(raw, walker);
  if (scan.eq < 0) return { error: `Unsupported content at line ${start + 1}` };

  const output: string[] = [normaliseFirstLine(raw, scan, walker.multiline !== null)];
  let end = start;

  while (walker.depth !== 0 || walker.multiline !== null) {
    end++;
    const line = lines[end];
    if (line === undefined) {
      return { error: `Unterminated value starting at line ${start + 1}` };
    }
    const insideBefore = walker.multiline !== null;
    scanLine(line, walker);
    const insideAfter = walker.multiline !== null;
    // A line that touches a multi-line string is byte-preserved: indentation
    // and trailing spaces there belong to the string, not to the layout.
    output.push(insideBefore || insideAfter ? line : normaliseContinuation(line));
  }

  return { key: normaliseKey(raw.slice(0, scan.eq)), lines: output, end };
}

/**
 * Rebuilds the first line of a key/value as `key = value`, splitting off a
 * trailing comment. When the value opened a multi-line string the tail is left
 * alone, because whitespace there is part of the string.
 */
function normaliseFirstLine(raw: string, scan: Scan, multilineOpen: boolean): string {
  const tail = raw.slice(scan.eq + 1, scan.comment >= 0 ? scan.comment : undefined);
  const head = tail.replace(/^\s+/, '');
  const trimmed = multilineOpen ? head : rstripWs(head);
  const value = normalizeQuotes(trimmed);
  const comment = scan.comment >= 0 ? ` ${rstripWs(raw.slice(scan.comment))}` : '';
  return `${normaliseKey(raw.slice(0, scan.eq))} = ${value}${comment}`;
}

/** A continuation line of a value: trim the layout, keep the value's shape. */
function normaliseContinuation(line: string): string {
  return normalizeQuotes(rstripWs(line));
}

/** Strips a key of stray spacing and of quotes a bare key does not need. */
function normaliseKey(raw: string): string {
  const normalised = normalizeQuotes(raw.trim());
  const quoted = /^"([^"\\]*)"$/.exec(normalised);
  if (quoted) {
    const content = quoted[1] ?? '';
    if (content.length > 0 && /^[A-Za-z0-9_-]+$/.test(content)) return content;
  }
  return normalised;
}

/**
 * Rewrites single-quoted strings as basic strings and leaves everything else
 * alone. Only one direction is ever taken: a literal string becomes basic, a
 * basic string is never turned back into a literal. Normalising both ways would
 * oscillate and break idempotence.
 */
function normalizeQuotes(text: string): string {
  let out = '';
  let i = 0;

  while (i < text.length) {
    const ch = text[i];

    if (ch === '#') return out + text.slice(i);
    // A multi-line opener swallows the rest of the line; leave it verbatim.
    if (text.startsWith('"""', i) || text.startsWith("'''", i)) return out + text.slice(i);

    if (ch === '"') {
      const end = scanBasic(text, i + 1);
      out += text.slice(i, end);
      i = end;
      continue;
    }

    if (ch === "'") {
      const end = scanLiteral(text, i + 1);
      out += basicString(text.slice(i + 1, end - 1));
      i = end;
      continue;
    }

    out += ch ?? '';
    i++;
  }

  return out;
}

/** Escapes literal-string content so it means the same thing between `"`. */
function basicString(content: string): string {
  return `"${content.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

/** Index just past the closing quote of a basic string starting at `from`. */
function scanBasic(text: string, from: number): number {
  let i = from;
  while (i < text.length) {
    const ch = text[i];
    if (ch === '\\') {
      i += 2;
      continue;
    }
    if (ch === '"') return i + 1;
    i++;
  }
  return text.length;
}

/** Index just past the closing quote of a literal string starting at `from`. */
function scanLiteral(text: string, from: number): number {
  const close = text.indexOf("'", from);
  return close === -1 ? text.length : close + 1;
}

/**
 * Walks one line, updating the multi-line state, and reports the two offsets
 * that matter: the key/value separator and any trailing comment. The walker is
 * string-aware, so an `=` or `#` inside a value never counts.
 */
function scanLine(line: string, walker: Walker): Scan {
  let eq = -1;
  let comment = -1;
  let i = 0;

  while (i < line.length) {
    if (walker.multiline !== null) {
      if (walker.multiline === 'basic') {
        if (line[i] === '\\') {
          i += 2;
          continue;
        }
        if (line.startsWith('"""', i)) {
          walker.multiline = null;
          i += 3;
          continue;
        }
      } else if (line.startsWith("'''", i)) {
        walker.multiline = null;
        i += 3;
        continue;
      }
      i++;
      continue;
    }

    const ch = line[i];

    if (ch === '#') {
      if (walker.depth === 0) comment = i;
      break;
    }
    if (ch === '=') {
      if (walker.depth === 0 && eq < 0) eq = i;
      i++;
      continue;
    }
    if (ch === '"') {
      if (line.startsWith('"""', i)) {
        walker.multiline = 'basic';
        i += 3;
        continue;
      }
      i = scanBasic(line, i + 1);
      continue;
    }
    if (ch === "'") {
      if (line.startsWith("'''", i)) {
        walker.multiline = 'literal';
        i += 3;
        continue;
      }
      i = scanLiteral(line, i + 1);
      continue;
    }
    if (ch === '[' || ch === '{') {
      walker.depth++;
      i++;
      continue;
    }
    if (ch === ']' || ch === '}') {
      walker.depth = Math.max(0, walker.depth - 1);
      i++;
      continue;
    }
    i++;
  }

  return { eq, comment };
}

/** Orders blocks by SEP-1 section rank, keeping everything else in place. */
function orderBlocks(blocks: Block[]): Block[] {
  return blocks
    .map((block, index) => ({ block, index }))
    .sort((a, b) => sectionRank(a.block.name) - sectionRank(b.block.name) || a.index - b.index)
    .map(({ block }) => block);
}

/**
 * SEP-1 tables first, in spec order; anything else last. Sections sharing a
 * first path segment share a rank, so a nested table never moves past its
 * parent and relative order inside a branch is untouched.
 */
function sectionRank(name: string): number {
  if (name === '') return -1;
  const head = name.split('.')[0] ?? name;
  const order = TABLE_ORDER as readonly string[];
  const index = order.indexOf(head);
  return index === -1 ? TABLE_ORDER.length : index;
}

/** Field order for the table a block belongs to, when SEP-1 defines one. */
function fieldTable(sectionName: string): readonly string[] {
  const head = sectionName.split('.')[0] ?? sectionName;
  switch (head) {
    case 'DOCUMENTATION':
      return DOCUMENTATION_FIELDS;
    case 'PRINCIPALS':
      return PRINCIPAL_FIELDS;
    case 'CURRENCIES':
      return CURRENCY_FIELDS;
    case 'VALIDATORS':
      return VALIDATOR_FIELDS;
    default:
      // The root table has a spec order of its own; unknown tables have none,
      // so their keys simply keep the order they were written in.
      return sectionName === '' ? GLOBAL_FIELDS : [];
  }
}

/** Sorts a block's key/values into spec order. Equal ranks keep written order. */
function orderKvs(block: Block): KvItem[] {
  const table = fieldTable(block.name) as readonly string[];
  return [...block.kvs]
    .map((item) => ({ item, rank: fieldRank(table, item.key) }))
    .sort((a, b) => a.rank - b.rank || a.item.order - b.item.order)
    .map(({ item }) => item);
}

function fieldRank(table: readonly string[], key: string): number {
  const head = firstSegment(key);
  const index = table.indexOf(head);
  return index === -1 ? Number.POSITIVE_INFINITY : index;
}

/** The leading field name of a (possibly dotted, possibly quoted) key. */
function firstSegment(key: string): string {
  const whole = /^"([^"\\]*)"$/.exec(key.trim());
  if (whole) return whole[1] ?? key;
  const dot = key.indexOf('.');
  const head = (dot === -1 ? key : key.slice(0, dot)).trim();
  const quoted = /^"([^"\\]*)"$/.exec(head);
  return quoted ? (quoted[1] ?? head) : head;
}

function render(blocks: Block[], trailer: string[], eol: string): string {
  const out: string[] = [];

  for (const block of blocks) {
    const kvs = orderKvs(block);

    if (block.header) {
      // Sections are separated by exactly one blank line, whether or not the
      // author wrote one — that rule is what makes the output stable.
      if (out.length > 0) out.push(eol);
      pushLeading(out, block.header.leading);
      out.push(block.header.line);
    }

    for (const kv of kvs) {
      if (kv.spaced && out.length > 0) out.push(eol);
      pushLeading(out, kv.leading);
      out.push(...kv.lines);
    }
  }

  for (const line of trailer) out.push(rstripWs(line));
  return out.join('\n');
}

function pushLeading(out: string[], leading: string[]): void {
  for (const line of leading) {
    const text = rstripWs(line);
    if (text.trim() !== '') out.push(text);
  }
}

/**
 * Structural equality for parsed TOML, ignoring key order (reordering is the
 * whole point of the formatter) and comparing dates by instant.
 */
function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (a === null || b === null) return false;

  if (a instanceof Date || b instanceof Date) {
    if (!(a instanceof Date) || !(b instanceof Date)) return false;
    const left = a.getTime();
    const right = b.getTime();
    return left === right || (Number.isNaN(left) && Number.isNaN(right));
  }

  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return a.every((value, index) => deepEqual(value, b[index]));
  }

  if (typeof a === 'object' && typeof b === 'object') {
    const left = a as Record<string, unknown>;
    const right = b as Record<string, unknown>;
    const keys = Object.keys(left);
    if (keys.length !== Object.keys(right).length) return false;
    return keys.every(
      (key) => Object.prototype.hasOwnProperty.call(right, key) && deepEqual(left[key], right[key]),
    );
  }

  return false;
}
