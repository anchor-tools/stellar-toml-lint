/**
 * Lossless TOML 1.0 lexer.
 *
 * Unlike a conventional parser front-end, this lexer never discards trivia.
 * Whitespace, newlines, and comments are first-class tokens with exact source
 * spans, which is what lets {@link ./parser.ts} build a Concrete Syntax Tree
 * that round-trips byte-for-byte.
 *
 * The lexer is deliberately context-aware in one place only: a quoted string
 * means the same thing whether it is a key or a value, but a bare word does
 * not (`true` is a value, `true` could not be a key that continues into an
 * `=`). Callers pass a {@link LexContext} so a bare word is classified as a
 * key or as a primitive value.
 */

/** Kinds of trivia a document may contain between meaningful tokens. */
export type TriviaKind = 'whitespace' | 'newline' | 'comment';

/** Every kind of token the lexer can yield. */
export type TokenKind =
  | TriviaKind
  | 'equal'
  | 'dot'
  | 'comma'
  | 'bracket-open'
  | 'bracket-close'
  | 'brace-open'
  | 'brace-close'
  | 'key'
  | 'string'
  | 'integer'
  | 'float'
  | 'boolean'
  | 'datetime'
  | 'invalid'
  | 'eof';

/** How a string was written. Preserved so the printer never rewrites it. */
export type StringStyle = 'basic' | 'literal' | 'multiline-basic' | 'multiline-literal';

/** The two contexts a bare word can appear in. */
export type LexContext = 'key' | 'value';

/** One lexical unit, with the half-open source span it occupies. */
export interface Token {
  kind: TokenKind;
  /** Offset of the first character of the token. */
  start: number;
  /** Offset just past the last character of the token. */
  end: number;
  /** Raw source text of the token; `''` for `eof`. */
  text: string;
  /** Only set for `string` tokens. */
  style?: StringStyle;
}

/** A 1-based line/column pair, matching what diagnostics expect. */
export interface SourcePosition {
  line: number;
  column: number;
}

/**
 * Converts offsets to line/column pairs without re-scanning the document.
 *
 * The line-start table is built once and binary-searched per lookup, so a
 * document with thousands of tokens stays linear rather than quadratic.
 */
export class SourcePositions {
  private readonly starts: number[];

  constructor(source: string) {
    const starts = [0];
    for (let i = 0; i < source.length; i++) {
      if (source.charCodeAt(i) === 0x0a) starts.push(i + 1);
    }
    this.starts = starts;
  }

  /** 1-based line and column of `offset`. */
  at(offset: number): SourcePosition {
    const starts = this.starts;
    let low = 0;
    let high = starts.length - 1;
    let best = 0;
    while (low <= high) {
      const mid = (low + high) >> 1;
      const start = starts[mid] ?? 0;
      if (start <= offset) {
        best = mid;
        low = mid + 1;
      } else {
        high = mid - 1;
      }
    }
    return { line: best + 1, column: offset - (starts[best] ?? 0) + 1 };
  }
}

/** Characters that may appear in a bare key. */
const BARE_KEY = /[A-Za-z0-9_-]/;

/** Characters that terminate an unquoted primitive value. */
const VALUE_TERMINATOR = /[\s,={}[\]#]/;

const DECIMAL_INTEGER = /^[+-]?(0|[1-9](_?[0-9])*)$/;
const HEX_INTEGER = /^0x[0-9A-Fa-f](_?[0-9A-Fa-f])*$/;
const OCTAL_INTEGER = /^0o[0-7](_?[0-7])*$/;
const BINARY_INTEGER = /^0b[01](_?[01])*$/;
const FLOAT = /^[+-]?(0|[1-9](_?[0-9])*)(\.[0-9](_?[0-9])*)?([eE][+-]?[0-9](_?[0-9])*)?$/;
const SPECIAL_FLOAT = /^[+-]?(inf|nan)$/;
const LOCAL_DATE = /^\d{4}-\d{2}-\d{2}$/;
const LOCAL_TIME = /^\d{2}:\d{2}:\d{2}(\.\d+)?$/;
const OFFSET_DATE_TIME = /^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/;

/**
 * A cursor over the source that produces one {@link Token} at a time.
 *
 * `next` never throws and always advances, so a malformed document cannot put
 * the lexer into an infinite loop. Characters that cannot begin a valid token
 * are emitted as single-character `invalid` tokens for the parser to report.
 */
export class Lexer {
  readonly source: string;

  private pos: number;

  constructor(source: string, start = 0) {
    this.source = source;
    this.pos = start;
  }

  /** Offset the next call to {@link next} will start from. */
  get offset(): number {
    return this.pos;
  }

  /**
   * Reads the next token.
   *
   * `context` only changes how a bare word is classified; trivia and
   * punctuation are identical in both contexts.
   */
  next(context: LexContext = 'key'): Token {
    if (this.pos >= this.source.length) {
      return this.token('eof', this.pos, this.pos);
    }

    const start = this.pos;
    const code = this.source.charCodeAt(start);

    if (code === 0x20 || code === 0x09) return this.readWhitespace(start);
    if (code === 0x0a || code === 0x0d) return this.readNewline(start);
    if (code === 0x23) return this.readComment(start);

    const char = this.source[start] as string;
    if (char === '=') return this.single('equal', start);
    if (char === '.') return this.single('dot', start);
    if (char === ',') return this.single('comma', start);
    if (char === '[') return this.single('bracket-open', start);
    if (char === ']') return this.single('bracket-close', start);
    if (char === '{') return this.single('brace-open', start);
    if (char === '}') return this.single('brace-close', start);

    if (char === '"' || char === "'") return this.readString(start);

    if (context === 'value') return this.readValue(start);

    if (BARE_KEY.test(char)) return this.readBareKey(start);

    // A character that cannot start any token: hand it to the parser so the
    // error points at the exact byte instead of aborting the lexer.
    this.pos = start + 1;
    return this.token('invalid', start, this.pos);
  }

  /** Builds a token over `[start, end)` and advances the cursor. */
  private token(kind: TokenKind, start: number, end: number, style?: StringStyle): Token {
    this.pos = end;
    const token: Token = { kind, start, end, text: this.source.slice(start, end) };
    if (style !== undefined) token.style = style;
    return token;
  }

  /** A one-character punctuation token. */
  private single(kind: TokenKind, start: number): Token {
    return this.token(kind, start, start + 1);
  }

  private readWhitespace(start: number): Token {
    let end = start;
    while (end < this.source.length) {
      const code = this.source.charCodeAt(end);
      if (code !== 0x20 && code !== 0x09) break;
      end++;
    }
    return this.token('whitespace', start, end);
  }

  /** Consumes `\n`, `\r\n`, or a lone `\r` as a single newline token. */
  private readNewline(start: number): Token {
    let end = start + 1;
    if (this.source.charCodeAt(start) === 0x0d && this.source.charCodeAt(end) === 0x0a) end++;
    return this.token('newline', start, end);
  }

  /** Consumes `#` up to (but not including) the line ending. */
  private readComment(start: number): Token {
    let end = start;
    while (end < this.source.length) {
      const code = this.source.charCodeAt(end);
      if (code === 0x0a || code === 0x0d) break;
      end++;
    }
    return this.token('comment', start, end);
  }

  private readBareKey(start: number): Token {
    let end = start;
    while (end < this.source.length && BARE_KEY.test(this.source[end] as string)) end++;
    return this.token('key', start, end);
  }

  /**
   * Reads a quoted string in either context.
   *
   * An unterminated string becomes an `invalid` token rather than an exception
   * so the parser can report it with a precise position and recover on the
   * next line.
   */
  private readString(start: number): Token {
    const quote = this.source[start] as string;
    const triple = this.source.startsWith(quote.repeat(3), start);

    if (triple) {
      const delimiter = quote.repeat(3);
      let end = start + 3;
      for (;;) {
        const close = this.source.indexOf(delimiter, end);
        if (close < 0) return this.token('invalid', start, this.source.length);

        // A basic string may escape a quote, which must not close it.
        let backslashes = 0;
        for (let i = close - 1; i > start + 2 && this.source[i] === '\\'; i--) backslashes++;
        if (quote === '"' && backslashes % 2 === 1) {
          end = close + 1;
          continue;
        }

        // Up to two extra quotes are content: the delimiter is the *last*
        // three of any run, so `"""a""""` closes after the fourth quote.
        let run = 3;
        while (this.source[close + run] === quote) run++;
        const closeEnd = close + run;
        return this.token(
          'string',
          start,
          closeEnd,
          quote === '"' ? 'multiline-basic' : 'multiline-literal',
        );
      }
    }

    let end = start + 1;
    while (end < this.source.length) {
      const code = this.source.charCodeAt(end);
      if (code === 0x0a || code === 0x0d) return this.token('invalid', start, end);
      const char = this.source[end] as string;
      if (quote === '"' && char === '\\') {
        end += 2;
        continue;
      }
      if (char === quote) {
        return this.token('string', start, end + 1, quote === '"' ? 'basic' : 'literal');
      }
      end++;
    }
    return this.token('invalid', start, this.source.length);
  }

  /**
   * Reads a primitive value: a boolean, a number, a date/time, or garbage.
   *
   * Everything up to the next delimiter is consumed as one token and then
   * classified, which keeps `1979-05-27T07:32:00Z` and `-1.5e-3` in one piece
   * without a hand-written state machine per value type.
   */
  private readValue(start: number): Token {
    let end = start;
    while (end < this.source.length && !VALUE_TERMINATOR.test(this.source[end] as string)) end++;

    let text = this.source.slice(start, end);

    // TOML permits a space instead of `T` between a date and its time. The
    // whitespace is otherwise a delimiter, so stitch the two halves back
    // together here where the shape is still visible.
    if (LOCAL_DATE.test(text)) {
      const rest = this.source.slice(end);
      const joined = /^[ \t]+\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})?/.exec(rest);
      if (joined !== null) {
        end += joined[0].length;
        text = this.source.slice(start, end);
      }
    }

    const kind = classifyValue(text);
    return this.token(kind, start, end);
  }
}

/** Maps a raw primitive value to its token kind. */
function classifyValue(text: string): TokenKind {
  if (text === 'true' || text === 'false') return 'boolean';
  if (OFFSET_DATE_TIME.test(text) || LOCAL_DATE.test(text) || LOCAL_TIME.test(text)) {
    return 'datetime';
  }
  if (SPECIAL_FLOAT.test(text)) return 'float';
  if (
    DECIMAL_INTEGER.test(text) ||
    HEX_INTEGER.test(text) ||
    OCTAL_INTEGER.test(text) ||
    BINARY_INTEGER.test(text)
  ) {
    return 'integer';
  }
  if (FLOAT.test(text)) return 'float';
  return 'invalid';
}

/** True when `kind` is one of the trivia kinds. */
export function isTrivia(kind: TokenKind): kind is TriviaKind {
  return kind === 'whitespace' || kind === 'newline' || kind === 'comment';
}

/**
 * Tokenizes a whole document in one sweep.
 *
 * This is a convenience for callers that want a flat token stream (tests,
 * syntax highlighting, diffs). The parser does not use it — it drives
 * {@link Lexer} directly because only the parser knows what it expects next.
 * The stream is lossless by construction: concatenating every token's `text`
 * reproduces the source.
 */
export function tokenize(source: string): Token[] {
  const lexer = new Lexer(source);
  const tokens: Token[] = [];
  // Open `[` arrays and `{` inline tables, innermost last. A `[` at the start
  // of a statement is a table header instead, which is why position matters.
  const stack: Array<'array' | 'inline'> = [];
  let inHeader = false;
  let atStatementStart = true;
  let context: LexContext = 'key';

  for (;;) {
    const token = lexer.next(context);
    tokens.push(token);
    if (token.kind === 'eof') break;

    if (isTrivia(token.kind)) {
      if (token.kind === 'newline' && stack.length === 0 && !inHeader) {
        atStatementStart = true;
        context = 'key';
      }
      continue;
    }

    const statementStart = atStatementStart;
    atStatementStart = false;
    const top = stack[stack.length - 1];

    switch (token.kind) {
      case 'equal':
        context = 'value';
        break;
      case 'bracket-open':
        if (statementStart && stack.length === 0) {
          inHeader = true;
        } else {
          stack.push('array');
          context = 'value';
        }
        break;
      case 'bracket-close':
        if (inHeader) {
          // The second `]` of `]]` closes the array-of-tables header.
          if (lexer.source[token.end] !== ']') inHeader = false;
        } else if (top === 'array') {
          stack.pop();
          context = 'key';
        }
        break;
      case 'brace-open':
        stack.push('inline');
        context = 'key';
        break;
      case 'brace-close':
        if (top === 'inline') stack.pop();
        context = 'key';
        break;
      case 'comma':
        context = top === 'inline' ? 'key' : 'value';
        break;
      case 'dot':
        context = 'key';
        break;
      case 'string':
        if (context === 'value') context = 'key';
        break;
      case 'integer':
      case 'float':
      case 'boolean':
      case 'datetime':
      case 'invalid':
        context = 'key';
        break;
      default:
        break;
    }
  }

  return tokens;
}
