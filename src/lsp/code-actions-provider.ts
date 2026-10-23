/**
 * LSP `textDocument/codeAction` provider — interactive quick fixes (#42) and
 * the auto-fix / refactor surface editors expect from a modern lightbulb
 * menu (#332).
 *
 * Four families of actions come out of {@link codeActionsFor}:
 *
 *   - `quickfix` — every diagnostic that carries a {@link Fix} gets an
 *     executable `WorkspaceEdit` replacing only the offending value (strip a
 *     trailing slash, normalize a near-miss passphrase, reduce a social URL
 *     to a bare handle, format a phone number as E.164, upgrade `http://` to
 *     `https://`, trim stray whitespace, uppercase a public key, …). The
 *     title whitelist has a generic fallback, so a mechanically safe rule
 *     never needs a provider change to become fixable.
 *   - `quickfix` (insertion) — a missing recommended `[DOCUMENTATION]` field
 *     such as `ORG_NAME` is added as a new `KEY = ""` line right under the
 *     table header; the value is the only thing a human can supply.
 *   - `refactor.rewrite` — "Derive SAC contract ID" hashes the `code` and
 *     `issuer` of the `[[CURRENCIES]]` entry under the cursor against the
 *     document's `NETWORK_PASSPHRASE` (via `Asset.contractId`) and inserts
 *     the resulting `contract = "C…"`.
 *   - `source.fixAll` — "Fix all auto-fixable problems in file" merges every
 *     value rewrite in the document into one `WorkspaceEdit`, mirroring what
 *     `--fix` would write, so editors offer the same answer as the CLI.
 *
 * Unfixable findings (parse errors, missing required tables, …) produce no
 * action rather than an empty edit.
 */
import { Asset } from '@stellar/stellar-base';
import { computeFixEdits } from '../fix.js';
import { PUBLIC_NETWORK_PASSPHRASE } from '../spec.js';
import type { Diagnostic } from '../types.js';

/** 0-based LSP position. */
export interface LspPosition {
  line: number;
  character: number;
}

/** 0-based LSP range (end exclusive). */
export interface LspRange {
  start: LspPosition;
  end: LspPosition;
}

export interface LspTextEdit {
  range: LspRange;
  newText: string;
}

export interface LspWorkspaceEdit {
  changes: Record<string, LspTextEdit[]>;
}

export interface LspDiagnostic {
  range: LspRange;
  severity?: number;
  code?: string;
  source?: string;
  message: string;
}

export type LspCodeActionKind = 'quickfix' | 'refactor.rewrite' | 'source.fixAll';

export interface LspCodeAction {
  title: string;
  kind: LspCodeActionKind;
  diagnostics?: LspDiagnostic[];
  isPreferred?: boolean;
  edit?: LspWorkspaceEdit;
}

/** The `codeActionKinds` this provider serves, advertised at initialize. */
export const CODE_ACTION_KINDS: readonly LspCodeActionKind[] = [
  'quickfix',
  'refactor.rewrite',
  'source.fixAll',
];

/**
 * Builds the code actions for a `textDocument/codeAction` request.
 *
 * @param source     Document text the actions apply to.
 * @param uri        Document URI editors key `WorkspaceEdit.changes` by.
 * @param diagnostics Lint diagnostics currently published for the document.
 * @param range      Requested range (0-based, end exclusive).
 * @param only       Optional `context.only` filter; kinds are matched with
 *                   LSP's prefix semantics (`refactor` admits
 *                   `refactor.rewrite`).
 */
export function codeActionsFor(
  source: string,
  uri: string,
  diagnostics: Diagnostic[],
  range: LspRange,
  only?: readonly string[],
): LspCodeAction[] {
  const actions: LspCodeAction[] = [];

  for (const diagnostic of diagnostics) {
    if (diagnostic.rule === 'documentation/recommended-fields') {
      const insert = missingFieldAction(source, uri, diagnostic);
      if (insert && kindAllowed(insert.kind, only) && coversDiagnostic(range, diagnostic)) {
        actions.push(insert);
      }
      continue;
    }

    if (!diagnostic.fix || !diagnostic.path || !diagnostic.position) continue;
    if (!kindAllowed('quickfix', only) || !coversDiagnostic(range, diagnostic)) continue;

    const edit = valueTextEdit(source, diagnostic);
    if (!edit) continue;

    actions.push({
      title: titleFor(diagnostic),
      kind: 'quickfix',
      diagnostics: [toLspDiagnostic(diagnostic)],
      isPreferred: true,
      edit: { changes: { [uri]: [edit] } },
    });
  }

  if (kindAllowed('refactor.rewrite', only)) {
    const refactor = sacDerivationAction(source, uri, range);
    if (refactor) actions.push(refactor);
  }

  if (kindAllowed('source.fixAll', only)) {
    const fixAll = fixAllAction(source, uri, diagnostics);
    if (fixAll) actions.push(fixAll);
  }

  return actions;
}

/** Maps a package diagnostic onto the LSP shape editors understand. */
export function toLspDiagnostic(d: Diagnostic): LspDiagnostic {
  const start = {
    line: (d.position?.line ?? 1) - 1,
    character: (d.position?.column ?? 1) - 1,
  };
  return {
    range: {
      start,
      end: { line: start.line, character: start.character + (d.position ? 1 : 0) },
    },
    severity: d.severity === 'error' ? 1 : d.severity === 'warning' ? 2 : 3,
    code: d.rule,
    source: 'stellar-toml-lint',
    message: d.suggestion ? `${d.message}. ${d.suggestion}` : d.message,
  };
}

/** 0-based LSP position for a source offset. */
export function offsetToPosition(source: string, offset: number): LspPosition {
  let line = 0;
  let character = 0;
  const limit = Math.min(offset, source.length);
  for (let i = 0; i < limit; i++) {
    if (source.charCodeAt(i) === 10) {
      line++;
      character = 0;
    } else {
      character++;
    }
  }
  return { line, character };
}

/** "Fix all auto-fixable problems in file" — one edit per value rewrite. */
function fixAllAction(
  source: string,
  uri: string,
  diagnostics: Diagnostic[],
): LspCodeAction | undefined {
  const edits = computeFixEdits(source, diagnostics).map((edit) => ({
    range: { start: offsetToPosition(source, edit.start), end: offsetToPosition(source, edit.end) },
    newText: edit.text,
  }));
  if (edits.length === 0) return undefined;
  return {
    title: 'Fix all auto-fixable problems in file',
    kind: 'source.fixAll',
    edit: { changes: { [uri]: edits } },
  };
}

/**
 * "Add missing DOCUMENTATION.ORG_NAME" (and its recommended siblings): a
 * zero-width insertion of `KEY = ""` on the line after the `[DOCUMENTATION]`
 * header. Only fires when the header is exactly that table — an inline
 * `DOCUMENTATION = {}` or a malformed file gets no action, because guessing
 * where a key belongs is worse than doing nothing.
 */
function missingFieldAction(source: string, uri: string, d: Diagnostic): LspCodeAction | undefined {
  const path = d.path;
  if (!path || !path.startsWith('DOCUMENTATION.')) return undefined;
  const field = path.slice('DOCUMENTATION.'.length);
  if (!/^[A-Z][A-Z0-9_]*$/.test(field)) return undefined;
  const line = d.position?.line;
  if (line === undefined) return undefined;

  const starts = lineStartOffsets(source);
  const lineStart = starts[line - 1];
  if (lineStart === undefined) return undefined;
  const lineEnd = starts[line] !== undefined ? starts[line]! - 1 : source.length;
  if (!/^\s*\[\s*DOCUMENTATION\s*\]\s*(#.*)?$/.test(source.slice(lineStart, lineEnd))) {
    return undefined;
  }

  return {
    title: `Fix: Add missing ${path}`,
    kind: 'quickfix',
    diagnostics: [toLspDiagnostic(d)],
    edit: {
      changes: {
        [uri]: [{ range: zeroWidth(source, lineEnd), newText: `\n${field} = ""` }],
      },
    },
  };
}

/**
 * "Derive SAC contract ID" for the `[[CURRENCIES]]` entry under the cursor:
 * the Stellar Asset Contract address is the strkey of the asset hashed with
 * the network passphrase, so `code` + `issuer` determine it exactly. Offered
 * as a `refactor.rewrite` rather than a quick fix because swapping `issuer`
 * for `contract` is a semantic choice, not a repair.
 */
function sacDerivationAction(
  source: string,
  uri: string,
  range: LspRange,
): LspCodeAction | undefined {
  const lines = source.split('\n');
  const block = currencyBlocks(lines).find(
    (candidate) => range.start.line >= candidate.startLine && range.start.line <= candidate.endLine,
  );
  if (!block || !block.code || !block.issuer || block.contract !== undefined) return undefined;

  let contractId: string;
  try {
    contractId = new Asset(block.code, block.issuer).contractId(networkPassphraseOf(source));
  } catch {
    return undefined; // Malformed code/issuer — the linter already complains.
  }

  const starts = lineStartOffsets(source);
  const anchorLine = block.issuerLine ?? block.headerLine;
  const anchorStart = starts[anchorLine];
  if (anchorStart === undefined) return undefined;
  const nextStart = starts[anchorLine + 1];
  const anchorEnd = nextStart !== undefined ? nextStart - 1 : source.length;

  return {
    title: `Refactor: Derive SAC contract ID for CURRENCIES[${block.index}]`,
    kind: 'refactor.rewrite',
    edit: {
      changes: {
        [uri]: [{ range: zeroWidth(source, anchorEnd), newText: `\ncontract = "${contractId}"` }],
      },
    },
  };
}

/** One `[[CURRENCIES]]` array-of-tables entry, scanned from raw lines. */
interface CurrencyBlock {
  /** 0-based position among the `[[CURRENCIES]]` tables in the file. */
  index: number;
  /** 0-based lines, both inclusive. */
  startLine: number;
  endLine: number;
  headerLine: number;
  /** Line holding the `issuer = …` assignment, when present. */
  issuerLine?: number;
  code?: string;
  issuer?: string;
  /** Present (even if empty) when the entry already declares a contract. */
  contract?: string;
}

function currencyBlocks(lines: string[]): CurrencyBlock[] {
  const blocks: CurrencyBlock[] = [];
  let current: CurrencyBlock | undefined;
  let index = 0;

  const close = (endLine: number): void => {
    if (current) {
      current.endLine = endLine;
      current = undefined;
    }
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? '';
    if (/^\s*\[\[CURRENCIES\]\]/.test(line)) {
      close(i - 1);
      current = { index: index++, startLine: i, endLine: lines.length - 1, headerLine: i };
      blocks.push(current);
      continue;
    }
    if (/^\s*\[/.test(line)) {
      close(i - 1);
      continue;
    }
    if (!current) continue;

    const assignment = /^[ \t]*(code|issuer|contract)[ \t]*=[ \t]*(?:"([^"]*)"|'([^']*)')/.exec(
      line,
    );
    if (!assignment) continue;
    const key = assignment[1];
    const value = assignment[2] ?? assignment[3] ?? '';
    if (key === 'code') current.code = value;
    else if (key === 'issuer') {
      current.issuer = value;
      current.issuerLine = i;
    } else current.contract = value;
  }
  close(lines.length - 1);
  return blocks;
}

/** The root `NETWORK_PASSPHRASE`, defaulting to Public as SEP-1 does. */
function networkPassphraseOf(source: string): string {
  let preamble = source;
  const firstTable = source.search(/^\s*\[/m);
  if (firstTable >= 0) preamble = source.slice(0, firstTable);
  const match = /^[ \t]*NETWORK_PASSPHRASE[ \t]*=[ \t]*"((?:[^"\\]|\\.)*)"/m.exec(preamble);
  return match?.[1] ?? PUBLIC_NETWORK_PASSPHRASE;
}

/** The single value-replacement edit for a fix-bearing diagnostic. */
function valueTextEdit(source: string, diagnostic: Diagnostic): LspTextEdit | undefined {
  const edit = computeFixEdits(source, [diagnostic])[0];
  if (!edit) return undefined;
  return {
    range: { start: offsetToPosition(source, edit.start), end: offsetToPosition(source, edit.end) },
    newText: edit.text,
  };
}

function titleFor(d: Diagnostic): string {
  const path = d.path ?? '';
  switch (d.rule) {
    case 'general/trailing-slash-in-endpoint':
      return `Fix: Strip trailing slash from ${path}`;
    case 'network/passphrase':
      return 'Fix: Normalize NETWORK_PASSPHRASE to the known passphrase';
    case 'documentation/social-handles':
    case 'principals/social-handles':
    case 'general/invalid-twitter-handle':
      return `Fix: Use bare handle for ${path}`;
    case 'documentation/phone-e164':
      return `Fix: Format ${path} as E.164`;
    case 'general/insecure-http-url':
      return `Fix: Use https:// for ${path}`;
    case 'general/untrimmed-string-value':
      return `Fix: Trim whitespace from ${path}`;
    case 'general/lowercase-public-key':
      return `Fix: Uppercase ${path}`;
    default:
      return `Fix: Set ${path} to ${JSON.stringify(d.fix?.value ?? '')}`;
  }
}

/** True when `kind` survives the request's `context.only` filter. */
function kindAllowed(kind: LspCodeActionKind, only?: readonly string[]): boolean {
  if (!only || only.length === 0) return true;
  return only.some((entry) => kind === entry || kind.startsWith(`${entry}.`));
}

/** True when the requested range touches the diagnostic's 1-character range. */
function coversDiagnostic(range: LspRange, diagnostic: Diagnostic): boolean {
  const start = {
    line: diagnostic.position!.line - 1,
    character: diagnostic.position!.column - 1,
  };
  const end = { line: start.line, character: start.character + 1 };
  return rangeCovers(range, start, end);
}

function zeroWidth(
  source: string,
  offset: number,
): { start: LspRange['start']; end: LspRange['end'] } {
  const position = offsetToPosition(source, offset);
  return { start: position, end: position };
}

function rangeCovers(range: LspRange, start: LspPosition, end: LspPosition): boolean {
  return (
    positionInRange(start, range) ||
    positionInRange(end, range) ||
    spansOverlap(range, {
      start,
      end,
    })
  );
}

function positionInRange(position: LspPosition, range: LspRange): boolean {
  if (position.line < range.start.line || position.line > range.end.line) return false;
  if (position.line === range.start.line && position.character < range.start.character)
    return false;
  if (position.line === range.end.line && position.character > range.end.character) return false;
  return true;
}

function spansOverlap(a: LspRange, b: LspRange): boolean {
  return compare(a.start, b.end) <= 0 && compare(b.start, a.end) <= 0;
}

function compare(a: LspPosition, b: LspPosition): number {
  if (a.line !== b.line) return a.line - b.line;
  return a.character - b.character;
}

function lineStartOffsets(source: string): number[] {
  const starts = [0];
  for (let i = 0; i < source.length; i++) {
    if (source[i] === '\n') starts.push(i + 1);
  }
  return starts;
}
