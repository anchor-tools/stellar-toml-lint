/**
 * Canonical table-key and table-array reordering.
 *
 * The problem this solves is diff noise: an anchor that adds one currency to a
 * `stellar.toml` whose keys are written in an arbitrary order produces a diff a
 * reviewer cannot read. Reordering keys is only safe if the file's own
 * formatting survives it, so this codemod never re-renders a statement. It moves
 * whole entries inside the lossless CST the linter already parses, which keeps
 * `printCst` byte-exact for everything that is not a move.
 *
 * Two properties the tests pin down:
 *
 * - **Comments travel with the key they annotate.** A comment is attached to the
 *   entry below it when no blank line separates them; a blank line makes a
 *   comment floating, and floating whitespace stays at its *position* instead of
 *   following the entry. That is what makes the output stable rather than
 *   drifting a line on every run.
 * - **Idempotency.** Sorting an already-canonical file returns the input
 *   unchanged and reports `changed: false`, so `--sort-keys` is safe in a
 *   pre-commit hook and CI can assert on the diff it prints.
 */
import { parseCst, printCst } from './parser.js';
import type { CstDocument, CstKeyValueEntry, CstTableEntry, CstTrivia } from './parser.js';
import {
  KNOWN_CURRENCY_FIELDS,
  KNOWN_DOCUMENTATION_FIELDS,
  KNOWN_PRINCIPAL_FIELDS,
  KNOWN_VALIDATOR_FIELDS,
} from '../spec.js';

/**
 * SEP-1 field order for the four tables anchors maintain, taken from the
 * catalogs in `src/spec.ts` rather than a second copy of the same list: those
 * Sets are written in the order the SEP documents each field, and they are what
 * `--json-schema` publishes for editor autocompletion. Ordering a file the same
 * way means a reviewer reads `code` and `issuer` before `desc`, and two anchors'
 * files line up field for field in a diff.
 *
 * Matching is case-insensitive, so a validator block written with `public_key`
 * sorts the same as the canonical `PUBLIC_KEY`. Tables with no catalog — every
 * custom section — keep the author's order.
 */
export const CANONICAL_KEY_ORDER: Readonly<Record<string, readonly string[]>> = {
  DOCUMENTATION: [...KNOWN_DOCUMENTATION_FIELDS],
  PRINCIPALS: [...KNOWN_PRINCIPAL_FIELDS],
  CURRENCIES: [...KNOWN_CURRENCY_FIELDS],
  VALIDATORS: [...KNOWN_VALIDATOR_FIELDS],
};

/**
 * Array tables with an identity key: currencies sort by asset code, validators
 * by signing key. Tables absent here keep the order the author listed them in.
 */
export const CANONICAL_ARRAY_ORDER: Readonly<Record<string, string>> = {
  CURRENCIES: 'code',
  VALIDATORS: 'PUBLIC_KEY',
};

export interface CanonicalSortResult {
  /** The reordered source, or the original when nothing could be sorted. */
  output: string;
  /** False when the source has parse errors, which is why nothing moved. */
  parsed: boolean;
  changed: boolean;
  /** Dotted table paths whose key order changed. */
  tablesSorted: string[];
  /** Array table paths whose entry order changed. */
  arraysSorted: string[];
  /** Why something was left alone, e.g. an array missing its identity key. */
  warnings: string[];
}

/** One `key = value` statement, its position, and how its leading splits. */
interface KvBlock {
  entry: CstKeyValueEntry;
  /** Index in `document.entries`, which is where it is written back to. */
  index: number;
  /** Whitespace-only leading trivia that stays at the position. */
  separator: CstTrivia[];
  /** Leading trivia that belongs to the entry: its attached comments. */
  attached: CstTrivia[];
  name: string;
}

/** A `[table]` / `[[array]]` header plus the key-value lines written under it. */
interface Section {
  path: string;
  /** Index of the header entry, or -1 for the preamble before any table. */
  headerIndex: number;
  /** The header entry itself, or undefined for the preamble. */
  header: CstTableEntry | undefined;
  blocks: KvBlock[];
  /** Half-open entry range owned by this section, header included. */
  start: number;
  end: number;
}

/**
 * Splits a leading-trivia run into the whitespace that stays put and the
 * comments that belong to the entry below.
 *
 * The cut is the last blank line: a `newline` trivia at index 0 of the run or
 * following another `newline`. Everything after it is attached, but only when
 * it holds a comment — an all-whitespace run has nothing to attach.
 */
function splitLeading(leading: CstTrivia[]): { separator: CstTrivia[]; attached: CstTrivia[] } {
  let cut = -1;
  for (let i = 0; i < leading.length; i++) {
    if (leading[i]?.kind !== 'newline') continue;
    const previous = i === 0 ? 'newline' : leading[i - 1]?.kind;
    if (previous === 'newline') cut = i + 1;
  }
  const attached = cut === -1 ? leading : leading.slice(cut);
  const separator = cut === -1 ? [] : leading.slice(0, cut);
  if (!attached.some((trivia) => trivia.kind === 'comment')) {
    return { separator: leading, attached: [] };
  }
  return { separator, attached };
}

/** The last segment of a dotted key, which is the field a canon compares on. */
function fieldName(path: string): string {
  const dot = path.lastIndexOf('.');
  return dot === -1 ? path : path.slice(dot + 1);
}

/** Canonical order for the table a key lives in, looked up by table name. */
function orderFor(path: string): readonly string[] | undefined {
  const segments = path.split('.').filter((segment) => segment !== '');
  const name = segments.at(-1) ?? path;
  return CANONICAL_KEY_ORDER[name] ?? CANONICAL_KEY_ORDER[path];
}

/**
 * Stable sort by canonical rank. Keys outside the canonical list keep their
 * relative order and land at the end: nothing is invented about a field we have
 * not seen, which is what "preserve custom user keys" means in practice.
 */
function rankBlocks(blocks: KvBlock[], order: readonly string[]): KvBlock[] {
  const rank = new Map<string, number>();
  order.forEach((field, index) => {
    const key = field.toLowerCase();
    if (!rank.has(key)) rank.set(key, index);
  });
  const unknown = order.length;
  return blocks
    .map((block, position) => {
      const known = rank.get(fieldName(block.name).toLowerCase());
      return { block, position, score: known === undefined ? unknown + position : known };
    })
    .sort((left, right) => left.score - right.score || left.position - right.position)
    .map((ranked) => ranked.block);
}

/**
 * Writes blocks back into the positions they came from. Each position keeps its
 * own separator and the entry that moved there brings its comments along, so the
 * blank-line rhythm of the file survives the move.
 */
function reattach(
  document: CstDocument,
  positions: number[],
  separators: CstTrivia[][],
  blocks: KvBlock[],
): boolean {
  const moved = positions.some(
    (position, index) => document.entries[position] !== blocks[index]?.entry,
  );
  if (!moved) return false;
  positions.forEach((position, index) => {
    const block = blocks[index] as KvBlock;
    block.entry.leading = [...(separators[index] ?? []), ...block.attached];
    document.entries[position] = block.entry;
  });
  return true;
}

function sectionsOf(document: CstDocument): Section[] {
  const sections: Section[] = [];
  let current: Section = {
    path: '',
    headerIndex: -1,
    header: undefined,
    blocks: [],
    start: 0,
    end: 0,
  };
  document.entries.forEach((entry, index) => {
    if (entry.kind === 'table' || entry.kind === 'array-table') {
      const header = entry as CstTableEntry;
      if (header.errors.length > 0) return;
      if (current.blocks.length > 0 || current.headerIndex !== -1) sections.push(current);
      current = {
        path: header.key?.path ?? '',
        headerIndex: index,
        header,
        blocks: [],
        start: index,
        end: index + 1,
      };
      return;
    }
    const keyValue = entry as CstKeyValueEntry;
    current.end = index + 1;
    if (keyValue.key === null || keyValue.errors.length > 0) return;
    const { separator, attached } = splitLeading(keyValue.leading);
    current.blocks.push({
      entry: keyValue,
      index,
      separator,
      attached,
      name: keyValue.key?.path ?? '',
    });
  });
  if (current.blocks.length > 0 || current.headerIndex !== -1) sections.push(current);
  return sections;
}

/** The value of `field` as written in a section, for array comparison. */
function valueOf(section: Section, field: string): string | undefined {
  for (const block of section.blocks) {
    if (fieldName(block.name).toLowerCase() !== field.toLowerCase()) continue;
    const value = block.entry.value;
    if (value !== null && value !== undefined && 'value' in value) {
      return String((value as { value: unknown }).value);
    }
    return undefined;
  }
  return undefined;
}

/**
 * Contiguous runs of two or more `[[NAME]]` sections sharing a name. Non-
 * contiguous repeats are not a candidate: re-opening an array table after
 * another table is already invalid TOML, and sorting across an unrelated table
 * would move data the author deliberately separated.
 */
function arrayRuns(sections: Section[]): Section[][] {
  const runs: Section[][] = [];
  let open: Section[] = [];
  for (const section of sections) {
    const previous = open.at(-1);
    const continues =
      previous !== undefined &&
      previous.path === section.path &&
      previous.end === section.start &&
      section.headerIndex !== -1 &&
      previous.headerIndex !== -1;
    if (continues) {
      open.push(section);
      continue;
    }
    if (open.length > 1) runs.push(open);
    open = section.headerIndex === -1 ? [] : [section];
  }
  if (open.length > 1) runs.push(open);
  return runs;
}

/**
 * Moves whole sections, header and key-value lines together.
 *
 * A section's header carries the blank line and the floating comment that came
 * before it, so those have to stay at the *position* rather than travel with the
 * section, exactly as `reattach` does for keys. Without that the first block of
 * a run would inherit the file's leading blank line and the separator between
 * two blocks would vanish.
 */
function moveSections(document: CstDocument, run: Section[], order: Section[]): void {
  const from = (run[0] as Section).start;
  const to = (run.at(-1) as Section).end;
  const laid: typeof document.entries = [];
  for (const section of order) {
    for (let index = section.start; index < section.end; index++) {
      const entry = document.entries[index];
      if (entry !== undefined) laid.push(entry);
    }
  }
  // A section whose header parsed but whose body held a recovered entry can own
  // fewer slots than the run spans; moving it would drop text, so leave it.
  if (laid.length !== to - from) return;

  const separators = run.map((section) => splitLeading(section.header?.leading ?? []).separator);
  laid.forEach((entry, offset) => {
    document.entries[from + offset] = entry;
  });
  order.forEach((section, position) => {
    const header = section.header;
    if (header === undefined) return;
    const { attached } = splitLeading(header.leading);
    header.leading = [...(separators[position] ?? []), ...attached];
  });
}

/**
 * Reorders keys inside standard tables and sorts `[[CURRENCIES]]` /
 * `[[VALIDATORS]]` entries, leaving every byte it does not have to move alone.
 *
 * A file that does not parse is returned untouched: a half-sorted
 * `stellar.toml` is worse than an unsorted one, and linting is where the reason
 * belongs.
 */
export function sortCanonical(source: string): CanonicalSortResult {
  const document = parseCst(source);
  if (document.errors.length > 0) {
    return {
      output: source,
      parsed: false,
      changed: false,
      tablesSorted: [],
      arraysSorted: [],
      warnings: ['file does not parse; nothing was reordered'],
    };
  }

  const tablesSorted: string[] = [];
  const arraysSorted: string[] = [];
  const warnings: string[] = [];

  // Keys first, then entries: the key pass only permutes within a section, so
  // every section keeps the entry range it had at parse time and the array pass
  // below can still move sections by those ranges.
  for (const section of sectionsOf(document)) {
    const order = orderFor(section.path);
    if (section.blocks.length < 2 || order === undefined) continue;
    const sorted = rankBlocks(section.blocks, order);
    const positions = section.blocks.map((block) => block.index);
    const separators = section.blocks.map((block) => block.separator);
    if (reattach(document, positions, separators, sorted)) {
      tablesSorted.push(section.path === '' ? '<root>' : section.path);
    }
  }

  for (const run of arrayRuns(sectionsOf(document))) {
    const name = (run[0] as Section).path;
    const field = CANONICAL_ARRAY_ORDER[name];
    if (field === undefined) continue;
    const keyed = run.map((section) => ({ section, value: valueOf(section, field) }));
    if (keyed.some((entry) => entry.value === undefined)) {
      warnings.push(`${name}: an entry has no \`${field}\`, left in place`);
      continue;
    }
    const ordered = [...keyed].sort((left, right) => {
      const a = String(left.value).toUpperCase();
      const b = String(right.value).toUpperCase();
      if (a < b) return -1;
      if (a > b) return 1;
      return keyed.indexOf(left) - keyed.indexOf(right);
    });
    if (ordered.every((entry, index) => entry.section === run[index])) continue;
    moveSections(
      document,
      run,
      ordered.map((entry) => entry.section),
    );
    arraysSorted.push(name);
  }

  const output = printCst(document);
  return {
    output,
    parsed: true,
    changed: output !== source,
    tablesSorted: [...new Set(tablesSorted)],
    arraysSorted: [...new Set(arraysSorted)],
    warnings,
  };
}
