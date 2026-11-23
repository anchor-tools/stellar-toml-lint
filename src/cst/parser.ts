/**
 * Concrete Syntax Tree (CST) parser for TOML 1.0.
 *
 * Where `smol-toml` returns a plain JavaScript object, this parser returns a
 * tree that also remembers every byte it consumed — whitespace, comments,
 * quoting style, and exact offsets. Serializing an unmodified tree reproduces
 * the source exactly, which is what the formatter (#11), the suppression
 * comments (#25), and the AST-guided autofixer (#9) need.
 *
 * The tree is deliberately tolerant: syntax errors are collected in
 * {@link CstDocument.errors} and the parser resynchronizes at the next line
 * rather than throwing. Callers that want the old short-circuit behaviour can
 * look at `document.errors[0]` (see {@link ./visitor.ts}).
 */
import { Lexer, SourcePositions, isTrivia } from './lexer.js';
import type { LexContext, SourcePosition, StringStyle, Token, TriviaKind } from './lexer.js';

/** A piece of trivia with the exact span it occupies. */
export interface CstTrivia {
  kind: TriviaKind;
  /** Raw text, including the leading `#` for comments. */
  text: string;
  start: number;
  end: number;
  /** 1-based line where the trivia starts. */
  line: number;
  /** 1-based column where the trivia starts. */
  column: number;
}

/** A `#` comment, surfaced separately from the trivia that carries it. */
export interface CstComment {
  kind: 'comment';
  /** Raw text, including the leading `#`. */
  text: string;
  start: number;
  end: number;
  line: number;
  column: number;
}

/** A punctuation token, kept as text so printing never consults the source. */
export interface CstTokenSpan {
  start: number;
  end: number;
  text: string;
}

/** One dot-separated segment of a key. */
export interface CstKeySegment {
  kind: 'key-segment';
  /** Exact spelling, including quotes for quoted keys. */
  text: string;
  /** Decoded name: quotes removed and basic-string escapes resolved. */
  name: string;
  /** True when the segment was written with quotes. */
  quoted: boolean;
  /** Present for quoted keys, so the original quote style survives a rewrite. */
  style?: StringStyle;
  start: number;
  end: number;
  /** Trivia between the preceding `.` and this segment (empty for the first). */
  leading: CstTrivia[];
  /** Trivia between this segment and the following `.` (empty for the last). */
  trailing: CstTrivia[];
}

/** A dotted key: `DOCUMENTATION.ORG_NAME` or `a . "b c"`. */
export interface CstKey {
  kind: 'key';
  segments: CstKeySegment[];
  /** Decoded dotted path, e.g. `DOCUMENTATION.ORG_NAME`. */
  path: string;
  start: number;
  end: number;
}

export interface CstStringValue {
  kind: 'string';
  style: StringStyle;
  /** Raw source spelling, including the delimiters. */
  raw: string;
  /** Decoded content. */
  value: string;
  start: number;
  end: number;
}

export interface CstNumberValue {
  kind: 'integer' | 'float';
  raw: string;
  value: number;
  start: number;
  end: number;
}

export interface CstBooleanValue {
  kind: 'boolean';
  raw: string;
  value: boolean;
  start: number;
  end: number;
}

export interface CstDateTimeValue {
  kind: 'datetime';
  raw: string;
  /** `Date` where the value is representable, otherwise the raw text. */
  value: Date | string;
  start: number;
  end: number;
}

/** One element of an array, with the trivia and comma that surround it. */
export interface CstArrayItem {
  leading: CstTrivia[];
  value: CstValue;
  trailing: CstTrivia[];
  comma: CstTokenSpan | null;
}

export interface CstArrayValue {
  kind: 'array';
  open: CstTokenSpan;
  items: CstArrayItem[];
  /** Trivia between the last element (or `[`) and the closing `]`. */
  closeLeading: CstTrivia[];
  close: CstTokenSpan | null;
  start: number;
  end: number;
}

/** One `key = value` inside an inline table. */
export interface CstInlineEntry {
  leading: CstTrivia[];
  key: CstKey | null;
  keyTrailing: CstTrivia[];
  equals: CstTokenSpan | null;
  valueLeading: CstTrivia[];
  value: CstValue | null;
  trailing: CstTrivia[];
  comma: CstTokenSpan | null;
  /** Raw text the parser could not interpret, kept so the tree is lossless. */
  recovery?: string;
}

export interface CstInlineTableValue {
  kind: 'inline-table';
  open: CstTokenSpan;
  entries: CstInlineEntry[];
  closeLeading: CstTrivia[];
  close: CstTokenSpan | null;
  start: number;
  end: number;
}

/** A value the parser could not classify; `raw` keeps the source lossless. */
export interface CstInvalidValue {
  kind: 'invalid';
  raw: string;
  start: number;
  end: number;
}

export type CstValue =
  | CstStringValue
  | CstNumberValue
  | CstBooleanValue
  | CstDateTimeValue
  | CstArrayValue
  | CstInlineTableValue
  | CstInvalidValue;

/** A syntax error, located at a precise line and column. */
export interface CstError {
  message: string;
  start: number;
  end: number;
  /** 1-based line of the offending token. */
  line: number;
  /** 1-based column of the offending token. */
  column: number;
}

interface CstEntryBase {
  /** Trivia after the preceding entry's line, up to this entry's first token. */
  leading: CstTrivia[];
  /** Same-line trivia from the entry's end through the first newline. */
  trailing: CstTrivia[];
  /** Comments found in {@link leading}, in source order. */
  leadingComments: CstComment[];
  /** The single comment on the entry's own line, if there is one. */
  trailingComment?: CstComment;
  /** Offset of the first token of the entry. */
  start: number;
  /** Offset just past the last token of the entry (excluding `trailing`). */
  end: number;
  /** Raw text the parser skipped while recovering, kept for losslessness. */
  recovery?: string;
  /** Errors produced while parsing this entry. */
  errors: CstError[];
}

export interface CstKeyValueEntry extends CstEntryBase {
  kind: 'key-value';
  key: CstKey | null;
  keyTrailing: CstTrivia[];
  equals: CstTokenSpan | null;
  valueLeading: CstTrivia[];
  value: CstValue | null;
}

export interface CstTableEntry extends CstEntryBase {
  kind: 'table' | 'array-table';
  /** `[` or `[[`. */
  open: CstTokenSpan;
  keyLeading: CstTrivia[];
  key: CstKey | null;
  keyTrailing: CstTrivia[];
  /** `]` or `]]`. */
  close: CstTokenSpan | null;
}

export type CstEntry = CstKeyValueEntry | CstTableEntry;

/** The root of a parsed document. */
export interface CstDocument {
  kind: 'document';
  /** The exact source the tree was built from. */
  source: string;
  /** True when the source began with a UTF-8 byte order mark. */
  bom: boolean;
  entries: CstEntry[];
  /** Trivia after the final entry. */
  trailing: CstTrivia[];
  /** Every syntax error the parser recovered from, in source order. */
  errors: CstError[];
  start: number;
  end: number;
}

/** The first error in a document, or `undefined` for a clean parse. */
export function firstError(document: CstDocument): CstError | undefined {
  return document.errors[0];
}

/**
 * Parses `source` into a lossless CST.
 *
 * Never throws: a malformed document still yields a tree, with the problems
 * listed in {@link CstDocument.errors}.
 */
export function parseCst(source: string): CstDocument {
  return new Parser(source).parse();
}

/** Thrown by {@link parseOrThrow} when a document has syntax errors. */
export class CstParseError extends Error {
  readonly line: number;
  readonly column: number;

  constructor(error: CstError) {
    super(error.message);
    this.name = 'CstParseError';
    this.line = error.line;
    this.column = error.column;
  }
}

/** Parses `source`, throwing {@link CstParseError} on the first error. */
export function parseOrThrow(source: string): CstDocument {
  const document = parseCst(source);
  const error = firstError(document);
  if (error !== undefined) throw new CstParseError(error);
  return document;
}

/** Splits trivia at the first newline: the head ends a statement's line. */
function splitAtFirstNewline(trivia: CstTrivia[]): { first: CstTrivia[]; rest: CstTrivia[] } {
  const first: CstTrivia[] = [];
  const rest: CstTrivia[] = [];
  let seenNewline = false;
  for (const piece of trivia) {
    if (seenNewline) rest.push(piece);
    else first.push(piece);
    if (piece.kind === 'newline') seenNewline = true;
  }
  return { first, rest };
}

/** Extracts the comments from a trivia run, preserving order. */
function commentsOf(trivia: CstTrivia[]): CstComment[] {
  const comments: CstComment[] = [];
  for (const piece of trivia) {
    if (piece.kind !== 'comment') continue;
    comments.push({
      kind: 'comment',
      text: piece.text,
      start: piece.start,
      end: piece.end,
      line: piece.line,
      column: piece.column,
    });
  }
  return comments;
}

/** Removes the delimiters that surround a string token's content. */
function stripStringDelimiters(raw: string, style: StringStyle): string {
  const width = (style === 'basic' || style === 'literal' ? 1 : 3) as number;
  return raw.slice(width, Math.max(width, raw.length - width));
}

/** Resolves the escape sequences of a basic string into its content. */
function decodeBasicString(content: string): string {
  let out = '';
  for (let i = 0; i < content.length; i++) {
    const char = content[i] ?? '';
    if (char !== '\\') {
      out += char;
      continue;
    }

    const next = content[i + 1];
    if (next === undefined) {
      out += '\\';
      break;
    }

    switch (next) {
      case 'b':
        out += '\b';
        i++;
        break;
      case 't':
        out += '\t';
        i++;
        break;
      case 'n':
        out += '\n';
        i++;
        break;
      case 'f':
        out += '\f';
        i++;
        break;
      case 'r':
        out += '\r';
        i++;
        break;
      case '"':
        out += '"';
        i++;
        break;
      case '\\':
        out += '\\';
        i++;
        break;
      case 'u':
      case 'U': {
        const width = next === 'u' ? 4 : 8;
        const hex = content.slice(i + 2, i + 2 + width);
        const code = Number.parseInt(hex, 16);
        out += Number.isNaN(code) ? '' : String.fromCodePoint(code);
        i += 1 + width;
        break;
      }
      default: {
        // A backslash at the end of a line swallows the whitespace that
        // follows it, which is how a multi-line basic string joins lines.
        if (next === ' ' || next === '\t' || next === '\n' || next === '\r') {
          let cursor = i + 1;
          while (cursor < content.length) {
            const c = content[cursor];
            if (c !== ' ' && c !== '\t' && c !== '\n' && c !== '\r') break;
            cursor++;
          }
          i = cursor - 1;
        } else {
          out += next;
          i++;
        }
      }
    }
  }
  return out;
}

/** Decodes a key token into its name and whether it was quoted. */
function decodeKeySegment(token: Token): { name: string; quoted: boolean; style?: StringStyle } {
  if (token.kind === 'key') return { name: token.text, quoted: false };

  const style = token.style ?? 'basic';
  const content = stripStringDelimiters(token.text, style);
  const name =
    style === 'literal' || style === 'multiline-literal' ? content : decodeBasicString(content);
  return { name, quoted: true, style };
}

/** Parses a primitive value token into a number. */
function parseNumberValue(raw: string, kind: 'integer' | 'float'): number {
  const cleaned = raw.replace(/_/g, '');
  if (kind === 'float') {
    const lower = cleaned.toLowerCase();
    if (lower === 'inf' || lower === '+inf') return Number.POSITIVE_INFINITY;
    if (lower === '-inf') return Number.NEGATIVE_INFINITY;
    if (lower === 'nan' || lower === '+nan' || lower === '-nan') return Number.NaN;
    return Number(cleaned);
  }

  const sign = cleaned.startsWith('-') ? -1 : 1;
  const body = cleaned.replace(/^[+-]/, '');
  if (body.startsWith('0x')) return sign * Number.parseInt(body.slice(2), 16);
  if (body.startsWith('0o')) return sign * Number.parseInt(body.slice(2), 8);
  if (body.startsWith('0b')) return sign * Number.parseInt(body.slice(2), 2);
  return Number(cleaned);
}

/** Converts a datetime token into a `Date`, or keeps the raw text. */
function parseDateTimeValue(raw: string): Date | string {
  const normalized = raw.replace(' ', 'T').replace(/z$/, 'Z');
  const date = new Date(normalized);
  return Number.isNaN(date.getTime()) ? raw : date;
}

class Parser {
  private readonly source: string;
  private readonly lexer: Lexer;
  private readonly positions: SourcePositions;
  private readonly errors: CstError[] = [];
  private buffered: Token | undefined;

  constructor(source: string) {
    this.source = source;
    const bom = source.charCodeAt(0) === 0xfeff;
    this.lexer = new Lexer(source, bom ? 1 : 0);
    this.positions = new SourcePositions(source);
  }

  parse(): CstDocument {
    const bom = this.source.charCodeAt(0) === 0xfeff;
    let leading = this.readTrivia('key');
    const entries: CstEntry[] = [];

    for (;;) {
      const token = this.peek('key');
      if (token.kind === 'eof') break;
      const parsed = this.parseStatement(leading);
      entries.push(parsed.entry);
      leading = parsed.nextLeading;
    }

    return {
      kind: 'document',
      source: this.source,
      bom,
      entries,
      trailing: leading,
      errors: this.errors,
      start: 0,
      end: this.source.length,
    };
  }

  // ── token plumbing ────────────────────────────────────────────────────────

  private nextToken(context: LexContext): Token {
    const buffered = this.buffered;
    if (buffered !== undefined) {
      this.buffered = undefined;
      return buffered;
    }
    return this.lexer.next(context);
  }

  private peek(context: LexContext): Token {
    if (this.buffered === undefined) this.buffered = this.lexer.next(context);
    return this.buffered;
  }

  /** Consumes trivia, leaving the first non-trivia token buffered. */
  private readTrivia(context: LexContext): CstTrivia[] {
    const trivia: CstTrivia[] = [];
    for (;;) {
      const token = this.nextToken(context);
      if (!isTrivia(token.kind)) {
        this.buffered = token;
        return trivia;
      }
      trivia.push(this.toTrivia(token));
    }
  }

  private toTrivia(token: Token): CstTrivia {
    const position = this.positions.at(token.start);
    return {
      kind: token.kind as TriviaKind,
      text: token.text,
      start: token.start,
      end: token.end,
      line: position.line,
      column: position.column,
    };
  }

  private error(message: string, token: { start: number; end: number }): void {
    const position: SourcePosition = this.positions.at(token.start);
    this.errors.push({
      message,
      start: token.start,
      end: token.end,
      line: position.line,
      column: position.column,
    });
  }

  private span(token: Token): CstTokenSpan {
    return { start: token.start, end: token.end, text: token.text };
  }

  /**
   * Consumes the rest of the line, returning its raw text.
   *
   * Recovery keeps the skipped bytes on the entry so the tree still round-trips
   * even though a malformed statement could not be interpreted.
   */
  private recoverToLineEnd(): string {
    let text = '';
    const buffered = this.buffered;
    if (buffered !== undefined) {
      text += buffered.text;
      this.buffered = undefined;
    }
    for (;;) {
      const token = this.lexer.next('key');
      text += token.text;
      if (token.kind === 'eof' || token.kind === 'newline') break;
    }
    return text;
  }

  private startOffset(): number {
    return this.buffered !== undefined ? this.buffered.start : this.lexer.offset;
  }

  // ── statements ────────────────────────────────────────────────────────────

  private parseStatement(leading: CstTrivia[]): { entry: CstEntry; nextLeading: CstTrivia[] } {
    const token = this.peek('key');
    const entry =
      token.kind === 'bracket-open'
        ? this.parseTableEntry(leading)
        : this.parseKeyValueEntry(leading);

    const after = this.readTrivia('key');
    const { first, rest } = splitAtFirstNewline(after);
    entry.trailing = first;
    const trailingComment = commentsOf(first)[0];
    if (trailingComment !== undefined) entry.trailingComment = trailingComment;
    return { entry, nextLeading: rest };
  }

  private parseKeyValueEntry(leading: CstTrivia[]): CstKeyValueEntry {
    const errorsBefore = this.errors.length;
    const start = this.startOffset();
    const { key, trailing } = this.parseKey();

    const entry: CstKeyValueEntry = {
      kind: 'key-value',
      leading,
      trailing: [],
      leadingComments: commentsOf(leading),
      start: key !== null ? key.start : start,
      end: key !== null ? key.end : start,
      key,
      keyTrailing: trailing,
      equals: null,
      valueLeading: [],
      value: null,
      errors: [],
    };

    if (key === null) {
      entry.recovery = this.recoverToLineEnd();
      entry.errors = this.errors.slice(errorsBefore);
      return entry;
    }

    const equals = this.peek('key');
    if (equals.kind !== 'equal') {
      this.error('expected "=" after the key', equals);
      entry.recovery = this.recoverToLineEnd();
      entry.errors = this.errors.slice(errorsBefore);
      return entry;
    }

    this.nextToken('key');
    entry.equals = this.span(equals);
    entry.valueLeading = this.readTrivia('value');
    entry.value = this.parseValue();
    entry.end = entry.value.end;
    entry.errors = this.errors.slice(errorsBefore);
    return entry;
  }

  private parseTableEntry(leading: CstTrivia[]): CstTableEntry {
    const errorsBefore = this.errors.length;
    const first = this.nextToken('key');
    let open = this.span(first);
    let kind: 'table' | 'array-table' = 'table';

    if (this.source[first.end] === '[') {
      const second = this.nextToken('key');
      kind = 'array-table';
      open = {
        start: first.start,
        end: second.end,
        text: this.source.slice(first.start, second.end),
      };
    }

    const keyLeading = this.readTrivia('key');
    const { key, trailing } = this.parseKey();

    const entry: CstTableEntry = {
      kind,
      leading,
      trailing: [],
      leadingComments: commentsOf(leading),
      start: first.start,
      end: key !== null ? key.end : first.end,
      open,
      keyLeading,
      key,
      keyTrailing: trailing,
      close: null,
      errors: [],
    };

    if (key === null) {
      entry.recovery = this.recoverToLineEnd();
      entry.errors = this.errors.slice(errorsBefore);
      return entry;
    }

    const closing = this.peek('key');
    if (closing.kind !== 'bracket-close') {
      this.error('expected "]" to close the table header', closing);
      entry.recovery = this.recoverToLineEnd();
      entry.errors = this.errors.slice(errorsBefore);
      return entry;
    }

    this.nextToken('key');
    let close = this.span(closing);
    if (kind === 'array-table' && this.source[closing.end] === ']') {
      const second = this.nextToken('key');
      close = {
        start: closing.start,
        end: second.end,
        text: this.source.slice(closing.start, second.end),
      };
    }
    entry.close = close;
    entry.end = close.end;
    entry.errors = this.errors.slice(errorsBefore);
    return entry;
  }

  /** Parses a dotted key, leaving the token after it buffered. */
  private parseKey(): { key: CstKey | null; trailing: CstTrivia[] } {
    const segments: CstKeySegment[] = [];
    let leading: CstTrivia[] = [];

    for (;;) {
      const token = this.peek('key');
      if (token.kind !== 'key' && token.kind !== 'string') {
        if (segments.length === 0) {
          this.error('expected a key', token);
          return { key: null, trailing: [] };
        }
        return { key: this.finishKey(segments), trailing: leading };
      }

      this.nextToken('key');
      const decoded = decodeKeySegment(token);
      const segment: CstKeySegment = {
        kind: 'key-segment',
        text: token.text,
        name: decoded.name,
        quoted: decoded.quoted,
        start: token.start,
        end: token.end,
        leading,
        trailing: [],
      };
      if (decoded.style !== undefined) segment.style = decoded.style;
      segments.push(segment);

      const after = this.readTrivia('key');
      const next = this.peek('key');
      if (next.kind !== 'dot') {
        const key = this.finishKey(segments);
        return { key, trailing: after };
      }

      this.nextToken('key');
      segment.trailing = after;
      leading = this.readTrivia('key');
    }
  }

  private finishKey(segments: CstKeySegment[]): CstKey {
    const first = segments[0];
    const last = segments[segments.length - 1];
    const start = first !== undefined ? first.start : 0;
    const end = last !== undefined ? last.end : start;
    return {
      kind: 'key',
      segments,
      path: segments.map((segment) => segment.name).join('.'),
      start,
      end,
    };
  }

  // ── values ────────────────────────────────────────────────────────────────

  private parseValue(): CstValue {
    const token = this.peek('value');

    switch (token.kind) {
      case 'string': {
        this.nextToken('value');
        const style = token.style ?? 'basic';
        let content = stripStringDelimiters(token.text, style);
        // A newline immediately after a multi-line delimiter is not content;
        // TOML trims it so `"""\nline"""` is just `line`.
        if (style === 'multiline-basic' || style === 'multiline-literal') {
          if (content.startsWith('\r\n')) content = content.slice(2);
          else if (content.startsWith('\n')) content = content.slice(1);
        }
        const value =
          style === 'literal' || style === 'multiline-literal'
            ? content
            : decodeBasicString(content);
        return {
          kind: 'string',
          style,
          raw: token.text,
          value,
          start: token.start,
          end: token.end,
        };
      }
      case 'integer':
      case 'float': {
        this.nextToken('value');
        return {
          kind: token.kind,
          raw: token.text,
          value: parseNumberValue(token.text, token.kind),
          start: token.start,
          end: token.end,
        };
      }
      case 'boolean': {
        this.nextToken('value');
        return {
          kind: 'boolean',
          raw: token.text,
          value: token.text === 'true',
          start: token.start,
          end: token.end,
        };
      }
      case 'datetime': {
        this.nextToken('value');
        return {
          kind: 'datetime',
          raw: token.text,
          value: parseDateTimeValue(token.text),
          start: token.start,
          end: token.end,
        };
      }
      case 'bracket-open':
        return this.parseArray();
      case 'brace-open':
        return this.parseInlineTable();
      default: {
        this.error(`unexpected ${describeToken(token)} where a value was expected`, token);
        if (token.kind !== 'eof') this.nextToken('value');
        return { kind: 'invalid', raw: token.text, start: token.start, end: token.end };
      }
    }
  }

  private parseArray(): CstArrayValue {
    const openToken = this.nextToken('value');
    const open = this.span(openToken);
    const items: CstArrayItem[] = [];
    let leading = this.readTrivia('value');
    let closeLeading = leading;
    let close: CstTokenSpan | null = null;

    for (;;) {
      const token = this.peek('value');
      if (token.kind === 'eof') {
        this.error('unterminated array', token);
        break;
      }
      if (token.kind === 'bracket-close') {
        const closeToken = this.nextToken('value');
        close = this.span(closeToken);
        closeLeading = leading;
        break;
      }

      const value = this.parseValue();
      const after = this.readTrivia('value');
      const next = this.peek('value');

      if (next.kind === 'comma') {
        const commaToken = this.nextToken('value');
        items.push({ leading, value, trailing: after, comma: this.span(commaToken) });
        leading = this.readTrivia('value');
        continue;
      }

      items.push({ leading, value, trailing: [], comma: null });

      if (next.kind === 'bracket-close' || next.kind === 'eof') {
        // Hand the trivia to the loop so the closing bracket claims it
        // exactly once.
        leading = after;
        continue;
      }

      // A missing comma is reported but does not abort: the next value simply
      // becomes another element, which keeps the tree lossless.
      this.error('expected "," or "]" between array elements', next);
      leading = after;
    }

    const lastItem = items[items.length - 1];
    return {
      kind: 'array',
      open,
      items,
      closeLeading,
      close,
      start: open.start,
      end: close?.end ?? lastItem?.value.end ?? open.end,
    };
  }

  private parseInlineTable(): CstInlineTableValue {
    const openToken = this.nextToken('value');
    const open = this.span(openToken);
    const entries: CstInlineEntry[] = [];
    let leading = this.readTrivia('key');
    let closeLeading = leading;
    let close: CstTokenSpan | null = null;

    for (;;) {
      const token = this.peek('key');
      if (token.kind === 'eof') {
        this.error('unterminated inline table', token);
        break;
      }
      if (token.kind === 'brace-close') {
        const closeToken = this.nextToken('key');
        close = this.span(closeToken);
        closeLeading = leading;
        break;
      }

      const { key, trailing: keyTrailing } = this.parseKey();
      const entry: CstInlineEntry = {
        leading,
        key,
        keyTrailing,
        equals: null,
        valueLeading: [],
        value: null,
        trailing: [],
        comma: null,
      };

      if (key === null) {
        entry.recovery = this.recoverToLineEnd();
        entries.push(entry);
        break;
      }

      const equals = this.peek('key');
      if (equals.kind === 'equal') {
        this.nextToken('key');
        entry.equals = this.span(equals);
        entry.valueLeading = this.readTrivia('value');
        entry.value = this.parseValue();
      } else {
        this.error('expected "=" after the key', equals);
      }

      const after = this.readTrivia('key');
      const next = this.peek('key');
      if (next.kind === 'comma') {
        const commaToken = this.nextToken('key');
        entry.trailing = after;
        entry.comma = this.span(commaToken);
        entries.push(entry);
        leading = this.readTrivia('key');
        continue;
      }

      if (next.kind === 'brace-close') {
        entries.push(entry);
        leading = after;
        continue;
      }

      if (next.kind === 'eof') {
        closeLeading = after;
        entries.push(entry);
        break;
      }

      this.error('expected "," or "}" between inline table entries', next);
      entries.push(entry);
      leading = after;
    }

    const lastEntry = entries[entries.length - 1];
    const fallback = lastEntry?.value?.end ?? lastEntry?.key?.end ?? open.end;
    return {
      kind: 'inline-table',
      open,
      entries,
      closeLeading,
      close,
      start: open.start,
      end: close?.end ?? fallback,
    };
  }
}

/** A human-readable name for a token, used in error messages. */
function describeToken(token: Token): string {
  if (token.kind === 'eof') return 'end of file';
  if (token.kind === 'invalid') return `invalid value ${JSON.stringify(token.text)}`;
  return JSON.stringify(token.text);
}

// ── printing ────────────────────────────────────────────────────────────────

function printTrivia(trivia: CstTrivia[]): string {
  let out = '';
  for (const piece of trivia) out += piece.text;
  return out;
}

function printKey(key: CstKey | null): string {
  if (key === null) return '';
  let out = '';
  for (const [index, segment] of key.segments.entries()) {
    out += printTrivia(segment.leading);
    out += segment.text;
    if (index < key.segments.length - 1) {
      out += printTrivia(segment.trailing);
      out += '.';
    }
  }
  return out;
}

function printValue(value: CstValue | null): string {
  if (value === null) return '';
  switch (value.kind) {
    case 'string':
    case 'integer':
    case 'float':
    case 'boolean':
    case 'datetime':
      return value.raw;
    case 'invalid':
      return value.raw;
    case 'array': {
      let out = value.open.text;
      for (const item of value.items) {
        out += printTrivia(item.leading);
        out += printValue(item.value);
        out += printTrivia(item.trailing);
        if (item.comma !== null) out += item.comma.text;
      }
      out += printTrivia(value.closeLeading);
      if (value.close !== null) out += value.close.text;
      return out;
    }
    case 'inline-table': {
      let out = value.open.text;
      for (const entry of value.entries) {
        out += printTrivia(entry.leading);
        out += printKey(entry.key);
        out += printTrivia(entry.keyTrailing);
        if (entry.equals !== null) out += entry.equals.text;
        out += printTrivia(entry.valueLeading);
        out += printValue(entry.value);
        out += printTrivia(entry.trailing);
        if (entry.comma !== null) out += entry.comma.text;
        out += entry.recovery ?? '';
      }
      out += printTrivia(value.closeLeading);
      if (value.close !== null) out += value.close.text;
      return out;
    }
  }
}

/** Prints one entry without its surrounding trivia. */
function printEntry(entry: CstEntry): string {
  let out = '';
  if (entry.kind === 'key-value') {
    out += printKey(entry.key);
    out += printTrivia(entry.keyTrailing);
    if (entry.equals !== null) out += entry.equals.text;
    out += printTrivia(entry.valueLeading);
    out += printValue(entry.value);
  } else {
    out += entry.open.text;
    out += printTrivia(entry.keyLeading);
    out += printKey(entry.key);
    out += printTrivia(entry.keyTrailing);
    if (entry.close !== null) out += entry.close.text;
  }
  return out + (entry.recovery ?? '');
}

/**
 * Walks the tree and returns the source it represents.
 *
 * For a tree that was not modified after parsing this is byte-for-byte equal
 * to the original input — the property the canonical formatter depends on.
 */
export function printCst(document: CstDocument): string {
  let out = document.bom ? '\ufeff' : '';
  for (const entry of document.entries) {
    out += printTrivia(entry.leading);
    out += printEntry(entry);
    out += printTrivia(entry.trailing);
  }
  out += printTrivia(document.trailing);
  return out;
}

/** Alias for {@link printCst}, named for the round-trip property. */
export function serialize(document: CstDocument): string {
  return printCst(document);
}
