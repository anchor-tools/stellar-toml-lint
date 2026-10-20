/**
 * `textDocument/semanticTokens/full` — semantic classification of SEP-1 tokens.
 *
 * A TextMate grammar can only pattern-match `"G[A-Z0-9]{55}"`; it cannot tell a
 * well-formed Ed25519 account ID from a mistyped one, a `C...` Soroban contract
 * address from an account ID, an anchor endpoint URL from an arbitrary string,
 * or a deprecated key from a current one. This provider reads the parsed shape
 * of the file — the table each key sits in, the field the value belongs to — and
 * classifies every token by what it *means*, so editors can colour an invalid
 * issuer differently from a valid one long before the linter publishes a
 * diagnostic.
 *
 * The output is the LSP wire form: a flat, delta-encoded stream of 5-tuples
 * `[deltaLine, deltaStartChar, length, tokenType, tokenModifiers]` per LSP
 * 3.17. Keeping the encoder pure (see {@link encodeSemanticTokens}) means the
 * offset arithmetic that editors depend on is tested directly rather than
 * through a language-server handshake.
 *
 * Deliberately dependency-free, like the rest of `src/lsp/`: the server ships
 * with no `vscode-languageserver` runtime and the legend is a plain data table.
 */

import { isAccountId, isContractId, isUrl } from '../predicates.js';
import {
  DEPRECATED_FIELDS,
  HTTPS_ENDPOINT_FIELDS,
  KNOWN_CURRENCY_FIELDS,
  KNOWN_DOCUMENTATION_FIELDS,
  KNOWN_GLOBAL_FIELDS,
  KNOWN_PRINCIPAL_FIELDS,
  KNOWN_VALIDATOR_FIELDS,
} from '../spec.js';

/** Semantic token types this server understands, in legend order. */
export const SEMANTIC_TOKEN_TYPES = [
  'stellarAddress',
  'contractId',
  'endpointUrl',
  'currencyCode',
  'deprecatedKey',
  'key',
] as const;

export type SemanticTokenType = (typeof SEMANTIC_TOKEN_TYPES)[number];

/**
 * Token modifiers. `invalid` marks a value that cannot be what its field
 * requires (a malformed key or address); `deprecated` marks a key SEP-1 no
 * longer recommends. Both are surfaced as warning squiggles by the editor.
 */
export const SEMANTIC_TOKEN_MODIFIERS = ['invalid', 'deprecated'] as const;

export type SemanticTokenModifier = (typeof SEMANTIC_TOKEN_MODIFIERS)[number];

/** The `legend` advertised in the server's `semanticTokensProvider` capability. */
export const SEMANTIC_TOKEN_LEGEND: {
  tokenTypes: SemanticTokenType[];
  tokenModifiers: SemanticTokenModifier[];
} = {
  tokenTypes: [...SEMANTIC_TOKEN_TYPES],
  tokenModifiers: [...SEMANTIC_TOKEN_MODIFIERS],
};

const TYPE_INDEX = new Map<string, number>(SEMANTIC_TOKEN_TYPES.map((t, i) => [t, i]));

/** Bit for each modifier, in legend order: `invalid` = 1, `deprecated` = 2. */
const MODIFIER_BIT = new Map<string, number>(SEMANTIC_TOKEN_MODIFIERS.map((m, i) => [m, 1 << i]));

/** Zero-based, as LSP reports positions, with a resolved `type` index. */
export interface SemanticToken {
  line: number;
  startChar: number;
  length: number;
  type: number;
  modifiers: number;
}

// ─── Field → semantic value kind ──────────────────────────────────────────────

type ValueKind = 'address' | 'contract' | 'url' | 'currency';

/** Fields whose value must be a `G...` Stellar account ID. */
const ADDRESS_FIELDS = new Set<string>([
  'SIGNING_KEY',
  'URI_REQUEST_SIGNING_KEY',
  'ACCOUNTS',
  'PUBLIC_KEY',
  'issuer',
  'collateral_addresses',
]);

/** Fields whose value must be a `C...` Soroban contract ID. */
const CONTRACT_FIELDS = new Set<string>(['WEB_AUTH_CONTRACT_ID', 'contract']);

/** Fields holding an absolute endpoint or resource URL. */
const URL_FIELDS = new Set<string>([
  ...HTTPS_ENDPOINT_FIELDS,
  'HORIZON_URL',
  'ORG_URL',
  'ORG_LOGO',
  'image',
  'toml',
  'approval_server',
  'attestation_of_reserve',
  'HISTORY',
  'CONFIG_URL',
]);

/** Fields holding a SEP-1 asset/currency code. */
const CURRENCY_FIELDS = new Set<string>(['code', 'code_template', 'anchor_asset']);

function valueKindFor(key: string): ValueKind | undefined {
  if (ADDRESS_FIELDS.has(key)) return 'address';
  if (CONTRACT_FIELDS.has(key)) return 'contract';
  if (URL_FIELDS.has(key)) return 'url';
  if (CURRENCY_FIELDS.has(key)) return 'currency';
  return undefined;
}

// ─── Key classification ───────────────────────────────────────────────────────

function modifierMask(...modifiers: SemanticTokenModifier[]): number {
  let mask = 0;
  for (const modifier of modifiers) mask |= MODIFIER_BIT.get(modifier) ?? 0;
  return mask;
}

const INVALID = modifierMask('invalid');
const DEPRECATED = modifierMask('deprecated');

/**
 * Whether `key` is defined by SEP-1 inside `table`. An empty table is the
 * document root. Unknown tables are treated as permissive so a vendor extension
 * is never painted as an error.
 */
function isKnownKey(table: string, key: string): boolean {
  switch (table) {
    case '':
      return KNOWN_GLOBAL_FIELDS.has(key);
    case 'DOCUMENTATION':
      return KNOWN_DOCUMENTATION_FIELDS.has(key);
    case 'PRINCIPALS':
      return KNOWN_PRINCIPAL_FIELDS.has(key);
    case 'CURRENCIES':
      return KNOWN_CURRENCY_FIELDS.has(key);
    case 'VALIDATORS':
      return KNOWN_VALIDATOR_FIELDS.has(key);
    default:
      return true;
  }
}

interface Classified {
  type: number;
  modifiers: number;
}

function classifyKey(table: string, key: string): Classified {
  if (Object.prototype.hasOwnProperty.call(DEPRECATED_FIELDS, key)) {
    return { type: TYPE_INDEX.get('deprecatedKey') ?? 4, modifiers: DEPRECATED };
  }
  const type = TYPE_INDEX.get('key') ?? 5;
  return { type, modifiers: isKnownKey(table, key) ? 0 : INVALID };
}

function classifyValue(kind: ValueKind, value: string): Classified {
  switch (kind) {
    case 'address': {
      const type = TYPE_INDEX.get('stellarAddress') ?? 0;
      return { type, modifiers: isAccountId(value) ? 0 : INVALID };
    }
    case 'contract': {
      const type = TYPE_INDEX.get('contractId') ?? 1;
      return { type, modifiers: isContractId(value) ? 0 : INVALID };
    }
    case 'url': {
      const type = TYPE_INDEX.get('endpointUrl') ?? 2;
      return { type, modifiers: isUrl(value) ? 0 : INVALID };
    }
    case 'currency': {
      const type = TYPE_INDEX.get('currencyCode') ?? 3;
      return { type, modifiers: /^[A-Za-z0-9]{1,12}$/.test(value) ? 0 : INVALID };
    }
  }
}

// ─── Source scanning ──────────────────────────────────────────────────────────

const TABLE_HEADER = /^\s*\[\[?\s*([^\]]+?)\s*\]?\]\s*(?:#.*)?$/;
const KEY_VALUE =
  /^(\s*)(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'|([A-Za-z0-9_.-]+))(\s*)=\s*(.*)$/;
const QUOTED = /"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'/g;

function bracketDelta(text: string): number {
  let depth = 0;
  for (const char of text) {
    if (char === '[') depth += 1;
    else if (char === ']') depth -= 1;
  }
  return depth;
}

function scanQuotedValues(
  text: string,
  kind: ValueKind,
  line: number,
  offset: number,
  out: SemanticToken[],
): void {
  QUOTED.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = QUOTED.exec(text)) !== null) {
    const rawLength = match[0].length - 2;
    if (rawLength <= 0) continue;
    const value = match[1] ?? match[2] ?? '';
    const classified = classifyValue(kind, value);
    out.push({
      line,
      startChar: offset + match.index + 1,
      length: rawLength,
      type: classified.type,
      modifiers: classified.modifiers,
    });
  }
}

/**
 * Walks `source` line by line and classifies every token whose meaning is
 * knowable: keys against the SEP-1 field tables, and string values against the
 * type their field requires. Multi-line arrays keep the key of the line that
 * opened them, so a `collateral_addresses = [` list attributes every address to
 * that field.
 */
export function collectSemanticTokens(source: string): SemanticToken[] {
  const tokens: SemanticToken[] = [];
  const lines = source.split(/\r?\n/);
  let table = '';
  let pendingKind: ValueKind | undefined;
  let arrayDepth = 0;

  for (let index = 0; index < lines.length; index++) {
    const line = lines[index] ?? '';

    if (pendingKind !== undefined) {
      scanQuotedValues(line, pendingKind, index, 0, tokens);
      arrayDepth += bracketDelta(line);
      if (arrayDepth <= 0) {
        pendingKind = undefined;
        arrayDepth = 0;
      }
      continue;
    }

    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('#')) continue;

    const header = TABLE_HEADER.exec(line);
    if (header?.[1] !== undefined) {
      table = header[1].trim();
      continue;
    }

    const kv = KEY_VALUE.exec(line);
    if (kv === null) continue;

    const indent = kv[1] ?? '';
    const quotedKey = kv[2] !== undefined || kv[3] !== undefined;
    const key = kv[2] ?? kv[3] ?? kv[4] ?? '';
    if (key === '') continue;

    const keyStart = indent.length + (quotedKey ? 1 : 0);
    const classifiedKey = classifyKey(table, key);
    tokens.push({
      line: index,
      startChar: keyStart,
      length: key.length,
      type: classifiedKey.type,
      modifiers: classifiedKey.modifiers,
    });

    const rawValue = kv[6] ?? '';
    const kind = valueKindFor(key);
    if (kind === undefined) continue;

    const valueOffset = line.length - rawValue.length;
    scanQuotedValues(rawValue, kind, index, valueOffset, tokens);

    const delta = bracketDelta(rawValue);
    if (delta > 0) {
      pendingKind = kind;
      arrayDepth = delta;
    }
  }

  return tokens;
}

// ─── Delta encoding ───────────────────────────────────────────────────────────

/**
 * Encodes tokens into the LSP 5-tuple delta stream.
 *
 * Tokens are sorted by position, overlapping/duplicate spans are dropped, and
 * each entry stores the line delta, the character delta (absolute when the line
 * changed), the length, the type index, and the modifier bitmask — exactly what
 * `textDocument/semanticTokens/full` returns in its `data` field.
 */
export function encodeSemanticTokens(tokens: SemanticToken[]): number[] {
  const sorted = [...tokens]
    .filter((token) => token.length > 0)
    .sort((a, b) => (a.line === b.line ? a.startChar - b.startChar : a.line - b.line));

  const data: number[] = [];
  let previousLine = 0;
  let previousStart = 0;
  let lastEnd = -1;
  let lastLine = -1;

  for (const token of sorted) {
    // Batch the decode back: a token that starts inside the previous one on the
    // same line would corrupt the delta stream, so it is skipped rather than
    // emitted as a broken range.
    if (token.line === lastLine && token.startChar < lastEnd) continue;

    const deltaLine = token.line - previousLine;
    const deltaStart = deltaLine === 0 ? token.startChar - previousStart : token.startChar;
    data.push(deltaLine, deltaStart, token.length, token.type, token.modifiers);

    previousLine = token.line;
    previousStart = token.startChar;
    lastLine = token.line;
    lastEnd = token.startChar + token.length;
  }

  return data;
}

/** Convenience wrapper: classify and encode `source` in one call. */
export function computeSemanticTokens(source: string): number[] {
  return encodeSemanticTokens(collectSemanticTokens(source));
}
