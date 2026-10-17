/**
 * Static ReDoS (catastrophic regular-expression backtracking) detector
 * (issue #380).
 *
 * The enterprise policy engine lets an organisation bring its own matchers, and
 * a matcher is a regular expression someone typed. JavaScript's regex engine is
 * a backtracking one, so a pattern with nested or adjacent quantifiers over
 * overlapping character sets does not merely run slowly on hostile input — it
 * runs for longer than the universe has existed. `/(a+)+$/` against 30 `a`s
 * followed by a `b` explores 2^30 ways to split the input before concluding
 * there is no match. The linter is single-threaded and runs inside other
 * people's CI, so one such pattern in one policy file is an availability bug
 * for every pipeline that loads it.
 *
 * The fix has to be *static*. Timing a regex on sample input proves nothing:
 * the adversarial string that triggers the blow-up is exactly the one the
 * author did not think of. So this module parses the pattern into an AST and
 * looks for the two structures that make backtracking superlinear:
 *
 * - **Exponential, O(2^n)** — a quantifier whose body can itself match the same
 *   text in more than one way: `(a+)+`, `(a*)*`, `(a|a)*`, `(\s|\s\s)+`. Each
 *   extra input character doubles the number of ways the engine can partition
 *   it, and every one of them is tried before the match is refused.
 * - **Polynomial, O(n^2)** — two quantifiers in sequence over overlapping
 *   character sets: `\s*\s*$`, `.*.*=`, `[a-z]+[a-z0-9]+!`. The engine has to
 *   try every split point between them, which is quadratic rather than
 *   explosive, but on a 100 KB string quadratic is already a hang.
 *
 * Both detections require knowing whether two character sets *overlap*, since
 * `a+b+` is perfectly safe while `a+a+` is not. {@link charSetOf} computes a
 * conservative approximation of the set a node can match, and the analysis only
 * reports when it can show an overlap — the detector would rather miss an
 * exotic pattern than tell an operator their working regex is dangerous.
 *
 * A finding is only *reachable* if the engine can be made to backtrack into it,
 * which needs the overall match to be able to fail. A pattern that always
 * succeeds never backtracks. That is why an unanchored `/(a+)+/` is still
 * reported: a policy matcher is applied to arbitrary document values, and
 * `/(a+)+/.test('aaaa…b')` is the failing case. Anchoring changes nothing about
 * the risk, so anchors are not treated as mitigation.
 *
 * Wiring: the policy engine screens every `regex` matcher through
 * {@link analyzeRegex} before it compiles one (see `src/policy/engine.ts`), and
 * the rule test harness screens every regex literal in the built-in rules (see
 * `test/rules/redos.test.ts`), so a vulnerable pattern cannot reach a user's
 * pipeline from either direction.
 */
import type { CustomRegexMatcher, Diagnostic, Rule, Severity } from '../types.js';

/** Diagnostic id emitted for a pattern that can be made to backtrack. */
export const REDOS_RULE_ID = 'security/redos-vulnerable-regex';

/** Diagnostic id emitted when a pattern is not a valid regular expression. */
export const REDOS_INVALID_RULE_ID = 'security/invalid-regex';

/** Worst-case time complexity a finding implies. */
export type RedosComplexity = 'polynomial' | 'exponential';

/** Which structure the detector recognised. */
export type RedosKind =
  | 'nested-quantifier'
  | 'quantified-overlapping-alternation'
  | 'adjacent-quantifiers'
  | 'quantified-overlapping-sequence';

/** One structure in one pattern that an attacker can drive into backtracking. */
export interface RedosFinding {
  kind: RedosKind;
  complexity: RedosComplexity;
  /** The offending fragment of the pattern, as written. */
  fragment: string;
  /** 0-based index of `fragment` within the pattern source. */
  index: number;
  /** Why this fragment backtracks, in one sentence. */
  detail: string;
  /** A string shape that triggers the blow-up, for a regression test. */
  witness: string;
}

/** What {@link analyzeRegex} concluded about one pattern. */
export interface RedosReport {
  /** The pattern as given, without delimiters. */
  pattern: string;
  /** `true` when no finding was produced and the pattern parsed. */
  safe: boolean;
  /** Set when the pattern is not a valid regular expression. */
  parseError?: string;
  /** Findings, worst complexity first. */
  findings: RedosFinding[];
  /** The worst complexity found, or `'linear'` when there is none. */
  worstComplexity: RedosComplexity | 'linear';
}

/* ------------------------------------------------------------------ *
 * AST
 * ------------------------------------------------------------------ */

/** A span in the pattern source, so a finding can point at what it means. */
interface Span {
  start: number;
  end: number;
}

type RegexNode =
  | Alternation
  | Sequence
  | Quantified
  | Group
  | CharClass
  | Literal
  | AnyChar
  | Anchor
  | Backreference
  | Lookaround;

interface Alternation extends Span {
  type: 'alternation';
  options: RegexNode[];
}
interface Sequence extends Span {
  type: 'sequence';
  items: RegexNode[];
}
interface Quantified extends Span {
  type: 'quantified';
  body: RegexNode;
  min: number;
  /** `Infinity` for `*`, `+`, and `{n,}`. */
  max: number;
  greedy: boolean;
}
interface Group extends Span {
  type: 'group';
  body: RegexNode;
  capturing: boolean;
}
interface CharClass extends Span {
  type: 'class';
  negated: boolean;
  items: ClassItem[];
}
interface Literal extends Span {
  type: 'literal';
  value: string;
}
interface AnyChar extends Span {
  type: 'any';
}
interface Anchor extends Span {
  type: 'anchor';
  kind: '^' | '$' | '\\b' | '\\B';
}
interface Backreference extends Span {
  type: 'backreference';
}
interface Lookaround extends Span {
  type: 'lookaround';
  body: RegexNode;
  negated: boolean;
  behind: boolean;
}

/** One entry inside `[...]`: a single code point, a range, or a shorthand. */
type ClassItem =
  | { kind: 'char'; code: number }
  | { kind: 'range'; from: number; to: number }
  | { kind: 'shorthand'; name: 'd' | 'D' | 'w' | 'W' | 's' | 'S' };

/* ------------------------------------------------------------------ *
 * Parser
 * ------------------------------------------------------------------ */

class ParseError extends Error {}

/**
 * A small recursive-descent parser for the ECMAScript regex grammar.
 *
 * It covers the constructs a policy matcher or a lint rule actually uses:
 * alternation, grouping (capturing, non-capturing, and named), quantifiers in
 * all four spellings with lazy variants, character classes with ranges and
 * shorthands, escapes, anchors, backreferences, and lookaround. Unicode
 * property escapes (`\p{...}`) parse as an opaque shorthand whose character set
 * is treated as "unknown", which makes the analysis conservative rather than
 * wrong.
 *
 * Hand-written rather than pulled in as a dependency: this tool runs in other
 * people's pipelines, so the dependency list is a deliberate decision (see
 * `test/package.test.ts`), and the grammar subset here is ~250 lines.
 */
class RegexParser {
  private pos = 0;

  constructor(private readonly source: string) {}

  parse(): RegexNode {
    const node = this.parseAlternation();
    if (this.pos < this.source.length) {
      throw new ParseError(`unexpected "${this.source[this.pos]}" at index ${this.pos}`);
    }
    return node;
  }

  private parseAlternation(): RegexNode {
    const start = this.pos;
    const options: RegexNode[] = [this.parseSequence()];
    while (this.peek() === '|') {
      this.pos++;
      options.push(this.parseSequence());
    }
    if (options.length === 1) return options[0] as RegexNode;
    return { type: 'alternation', options, start, end: this.pos };
  }

  private parseSequence(): RegexNode {
    const start = this.pos;
    const items: RegexNode[] = [];
    while (this.pos < this.source.length) {
      const ch = this.peek();
      if (ch === '|' || ch === ')') break;
      items.push(this.parseQuantified());
    }
    if (items.length === 1) return items[0] as RegexNode;
    return { type: 'sequence', items, start, end: this.pos };
  }

  private parseQuantified(): RegexNode {
    const atom = this.parseAtom();
    let node = atom;

    // `a**` is a syntax error in JS, but `(a*)*` is not; loop so `a*?` and
    // `a{1,2}?` both attach correctly.
    for (;;) {
      const quantifier = this.tryParseQuantifier();
      if (quantifier === undefined) return node;
      const greedy = this.peek() !== '?';
      if (!greedy) this.pos++;
      node = {
        type: 'quantified',
        body: node,
        min: quantifier.min,
        max: quantifier.max,
        greedy,
        start: node.start,
        end: this.pos,
      };
    }
  }

  private tryParseQuantifier(): { min: number; max: number } | undefined {
    const ch = this.peek();
    if (ch === '*') {
      this.pos++;
      return { min: 0, max: Infinity };
    }
    if (ch === '+') {
      this.pos++;
      return { min: 1, max: Infinity };
    }
    if (ch === '?') {
      this.pos++;
      return { min: 0, max: 1 };
    }
    if (ch !== '{') return undefined;

    // `{` is only a quantifier when it is well-formed; otherwise it is a
    // literal brace, which is what the engine does too.
    const close = this.source.indexOf('}', this.pos);
    if (close === -1) return undefined;
    const body = this.source.slice(this.pos + 1, close);
    const match = /^(\d+)(,(\d*)?)?$/.exec(body);
    if (match === null) return undefined;
    this.pos = close + 1;
    const min = Number(match[1]);
    if (match[2] === undefined) return { min, max: min };
    return { min, max: match[3] === undefined || match[3] === '' ? Infinity : Number(match[3]) };
  }

  private parseAtom(): RegexNode {
    const start = this.pos;
    const ch = this.peek();
    if (ch === undefined) throw new ParseError('unexpected end of pattern');

    if (ch === '(') return this.parseGroup();
    if (ch === '[') return this.parseClass();
    if (ch === '.') {
      this.pos++;
      return { type: 'any', start, end: this.pos };
    }
    if (ch === '^' || ch === '$') {
      this.pos++;
      return { type: 'anchor', kind: ch, start, end: this.pos };
    }
    if (ch === '\\') return this.parseEscape();
    if (ch === '*' || ch === '+' || ch === '?') {
      throw new ParseError(`nothing to repeat at index ${this.pos}`);
    }

    this.pos++;
    return { type: 'literal', value: ch, start, end: this.pos };
  }

  private parseGroup(): RegexNode {
    const start = this.pos;
    this.pos++; // consume '('

    let capturing = true;
    let lookaround: { negated: boolean; behind: boolean } | undefined;

    if (this.peek() === '?') {
      const next = this.source[this.pos + 1];
      if (next === ':') {
        capturing = false;
        this.pos += 2;
      } else if (next === '=' || next === '!') {
        lookaround = { negated: next === '!', behind: false };
        this.pos += 2;
      } else if (next === '<') {
        const after = this.source[this.pos + 2];
        if (after === '=' || after === '!') {
          lookaround = { negated: after === '!', behind: true };
          this.pos += 3;
        } else {
          // Named capture group `(?<name>…)`.
          const close = this.source.indexOf('>', this.pos);
          if (close === -1) throw new ParseError('unterminated group name');
          this.pos = close + 1;
        }
      } else {
        throw new ParseError(`unsupported group modifier at index ${this.pos}`);
      }
    }

    const body = this.parseAlternation();
    if (this.peek() !== ')') throw new ParseError(`unterminated group at index ${start}`);
    this.pos++;

    if (lookaround !== undefined) {
      return { type: 'lookaround', body, ...lookaround, start, end: this.pos };
    }
    return { type: 'group', body, capturing, start, end: this.pos };
  }

  private parseClass(): RegexNode {
    const start = this.pos;
    this.pos++; // consume '['
    const negated = this.peek() === '^';
    if (negated) this.pos++;

    const items: ClassItem[] = [];
    let first = true;
    for (;;) {
      const ch = this.peek();
      if (ch === undefined) throw new ParseError(`unterminated character class at index ${start}`);
      // A `]` in first position is a literal, matching engine behaviour.
      if (ch === ']' && !first) break;
      first = false;

      const low = this.parseClassAtom();
      if (
        low.kind === 'char' &&
        this.peek() === '-' &&
        this.source[this.pos + 1] !== ']' &&
        this.pos + 1 < this.source.length
      ) {
        this.pos++; // consume '-'
        const high = this.parseClassAtom();
        if (high.kind === 'char') {
          items.push({ kind: 'range', from: low.code, to: high.code });
          continue;
        }
        items.push(low, { kind: 'char', code: 0x2d }, high);
        continue;
      }
      items.push(low);
    }
    this.pos++; // consume ']'
    return { type: 'class', negated, items, start, end: this.pos };
  }

  private parseClassAtom(): ClassItem {
    const ch = this.source[this.pos];
    if (ch === undefined) throw new ParseError('unterminated character class');
    if (ch !== '\\') {
      this.pos++;
      return { kind: 'char', code: ch.codePointAt(0) ?? 0 };
    }

    this.pos++; // consume '\'
    const escape = this.source[this.pos];
    if (escape === undefined) throw new ParseError('trailing backslash');
    this.pos++;

    if (escape === 'd' || escape === 'D' || escape === 'w' || escape === 'W') {
      return { kind: 'shorthand', name: escape };
    }
    if (escape === 's' || escape === 'S') return { kind: 'shorthand', name: escape };
    return { kind: 'char', code: this.decodeEscape(escape) };
  }

  private parseEscape(): RegexNode {
    const start = this.pos;
    this.pos++; // consume '\'
    const escape = this.source[this.pos];
    if (escape === undefined) throw new ParseError('trailing backslash');
    this.pos++;

    if (escape === 'b' || escape === 'B') {
      return { type: 'anchor', kind: escape === 'b' ? '\\b' : '\\B', start, end: this.pos };
    }
    if (/[1-9]/.test(escape)) {
      while (/[0-9]/.test(this.peek() ?? '')) this.pos++;
      return { type: 'backreference', start, end: this.pos };
    }
    if (escape === 'k') {
      const close = this.source.indexOf('>', this.pos);
      if (close !== -1) this.pos = close + 1;
      return { type: 'backreference', start, end: this.pos };
    }
    if ('dDwWsS'.includes(escape)) {
      const name = escape as 'd' | 'D' | 'w' | 'W' | 's' | 'S';
      return {
        type: 'class',
        negated: false,
        items: [{ kind: 'shorthand', name }],
        start,
        end: this.pos,
      };
    }
    if (escape === 'p' || escape === 'P') {
      // `\p{Letter}` — parsed, but its set is unknown, so the analysis stays
      // conservative around it rather than guessing at Unicode categories.
      if (this.peek() === '{') {
        const close = this.source.indexOf('}', this.pos);
        if (close === -1) throw new ParseError('unterminated unicode property escape');
        this.pos = close + 1;
      }
      return { type: 'any', start, end: this.pos };
    }

    return {
      type: 'literal',
      value: String.fromCodePoint(this.decodeEscape(escape)),
      start,
      end: this.pos,
    };
  }

  /** The code point an escape denotes, consuming any hex/unicode digits. */
  private decodeEscape(escape: string): number {
    const simple: Record<string, number> = {
      n: 0x0a,
      r: 0x0d,
      t: 0x09,
      f: 0x0c,
      v: 0x0b,
      '0': 0x00,
    };
    const known = simple[escape];
    if (known !== undefined) return known;

    if (escape === 'x') {
      const hex = this.source.slice(this.pos, this.pos + 2);
      if (/^[0-9a-fA-F]{2}$/.test(hex)) {
        this.pos += 2;
        return parseInt(hex, 16);
      }
      return 0x78;
    }
    if (escape === 'u') {
      if (this.peek() === '{') {
        const close = this.source.indexOf('}', this.pos);
        if (close !== -1) {
          const hex = this.source.slice(this.pos + 1, close);
          if (/^[0-9a-fA-F]+$/.test(hex)) {
            this.pos = close + 1;
            return parseInt(hex, 16);
          }
        }
        return 0x75;
      }
      const hex = this.source.slice(this.pos, this.pos + 4);
      if (/^[0-9a-fA-F]{4}$/.test(hex)) {
        this.pos += 4;
        return parseInt(hex, 16);
      }
      return 0x75;
    }
    if (escape === 'c') {
      const letter = this.peek();
      if (letter !== undefined && /[a-zA-Z]/.test(letter)) {
        this.pos++;
        return letter.toUpperCase().charCodeAt(0) - 64;
      }
      return 0x63;
    }

    return escape.codePointAt(0) ?? 0;
  }

  private peek(): string | undefined {
    return this.source[this.pos];
  }
}

/* ------------------------------------------------------------------ *
 * Character-set approximation
 * ------------------------------------------------------------------ */

/**
 * The set of characters a node can match, as a predicate over a sample of
 * code points, plus a flag for "could be anything".
 *
 * Exact set algebra over Unicode is neither necessary nor affordable here. What
 * the analysis needs is a sound answer to "can these two nodes match the same
 * character?", and sampling the printable ASCII range plus a handful of
 * representative non-ASCII code points answers it for every pattern a
 * `stellar.toml` policy or lint rule contains. A set marked `unknown` is
 * treated as overlapping nothing, which can only cause a missed finding, never
 * a false one.
 */
export interface CharSet {
  /** `true` when the node's set could not be determined. */
  unknown: boolean;
  /** `true` when the node matches no characters at all (e.g. an anchor). */
  empty: boolean;
  /** Membership test over the sampled alphabet. */
  has(code: number): boolean;
}

const EMPTY_SET: CharSet = { unknown: false, empty: true, has: () => false };
const UNKNOWN_SET: CharSet = { unknown: true, empty: false, has: () => false };

/**
 * Code points the overlap test samples.
 *
 * Printable ASCII covers everything a TOML key, URL, or Stellar account id can
 * contain; the tail adds a newline, a tab, a Latin-1 letter, a CJK ideograph,
 * and an astral code point so a `.`-vs-`\w` comparison is not decided purely on
 * ASCII.
 */
const SAMPLE_CODES: readonly number[] = [
  ...Array.from({ length: 95 }, (_, i) => 0x20 + i),
  0x09,
  0x0a,
  0x0d,
  0xe9,
  0x4e2d,
  0x1f600,
];

/** Membership for the `\d`/`\w`/`\s` family and their negations. */
function shorthandHas(name: string, code: number): boolean {
  const ch = String.fromCodePoint(code);
  switch (name) {
    case 'd':
      return /[0-9]/.test(ch);
    case 'D':
      return !/[0-9]/.test(ch);
    case 'w':
      return /[A-Za-z0-9_]/.test(ch);
    case 'W':
      return !/[A-Za-z0-9_]/.test(ch);
    case 's':
      return /\s/.test(ch);
    case 'S':
      return !/\s/.test(ch);
    default:
      return false;
  }
}

/** The character set one node matches. Exported for the regression suite. */
export function charSetOf(node: RegexNode): CharSet {
  switch (node.type) {
    case 'literal': {
      const code = node.value.codePointAt(0);
      if (code === undefined) return EMPTY_SET;
      return { unknown: false, empty: false, has: (c) => c === code };
    }
    case 'any':
      // `.` excludes line terminators without the `s` flag; treating it as
      // "everything but newlines" is right for both flag settings here,
      // because a pattern that only overlaps on `\n` is not a realistic ReDoS.
      return { unknown: false, empty: false, has: (c) => c !== 0x0a && c !== 0x0d };
    case 'class': {
      const matches = (code: number): boolean => {
        const inside = node.items.some((item) => {
          if (item.kind === 'char') return item.code === code;
          if (item.kind === 'range') return code >= item.from && code <= item.to;
          return shorthandHas(item.name, code);
        });
        return node.negated ? !inside : inside;
      };
      return { unknown: false, empty: false, has: matches };
    }
    case 'group':
      return charSetOf(node.body);
    case 'quantified':
      return charSetOf(node.body);
    case 'alternation': {
      const sets = node.options.map(charSetOf);
      if (sets.some((set) => set.unknown)) return UNKNOWN_SET;
      return {
        unknown: false,
        empty: sets.every((set) => set.empty),
        has: (code) => sets.some((set) => set.has(code)),
      };
    }
    case 'sequence': {
      // The set a sequence can *start* with is what matters for overlap; skip
      // leading zero-width and optional parts to find it.
      for (const item of node.items) {
        const set = charSetOf(item);
        if (set.empty) continue;
        if (!isOptional(item)) return set;
        const rest = charSetOf({
          type: 'sequence',
          items: node.items.slice(node.items.indexOf(item) + 1),
          start: node.start,
          end: node.end,
        });
        if (rest.unknown) return UNKNOWN_SET;
        return {
          unknown: false,
          empty: set.empty && rest.empty,
          has: (code) => set.has(code) || rest.has(code),
        };
      }
      return EMPTY_SET;
    }
    case 'anchor':
      return EMPTY_SET;
    case 'lookaround':
      // Zero-width: consumes nothing, so it contributes no characters to the
      // surrounding sequence.
      return EMPTY_SET;
    case 'backreference':
      return UNKNOWN_SET;
  }
}

/** `true` when two nodes can match the same character. */
function overlaps(a: CharSet, b: CharSet): boolean {
  if (a.unknown || b.unknown || a.empty || b.empty) return false;
  return SAMPLE_CODES.some((code) => a.has(code) && b.has(code));
}

/** `true` when the node can match the empty string. */
function isOptional(node: RegexNode): boolean {
  switch (node.type) {
    case 'quantified':
      return node.min === 0 || isOptional(node.body);
    case 'group':
      return isOptional(node.body);
    case 'alternation':
      return node.options.some(isOptional);
    case 'sequence':
      return node.items.every(isOptional);
    case 'anchor':
    case 'lookaround':
      return true;
    default:
      return false;
  }
}

/** `true` when the node can consume at least one character. */
function canConsume(node: RegexNode): boolean {
  switch (node.type) {
    case 'anchor':
    case 'lookaround':
      return false;
    case 'quantified':
      return node.max > 0 && canConsume(node.body);
    case 'group':
      return canConsume(node.body);
    case 'alternation':
      return node.options.some(canConsume);
    case 'sequence':
      return node.items.some(canConsume);
    default:
      return true;
  }
}

/**
 * `true` when the quantifier has no upper bound.
 *
 * Only an unbounded repetition makes the *outer* complexity grow with the
 * input: `(a+){2,5}` does bounded extra work, `(a+)+` does not.
 */
function isUnbounded(node: Quantified): boolean {
  return node.max === Infinity;
}

/**
 * `true` when the repeat count varies, so the body's extent is not fixed.
 *
 * This is what makes a quantifier *ambiguous* as the body of another: `a{3}`
 * matches exactly three characters and offers the engine no choice, while
 * `a*`, `a+`, and `a{2,5}` all do.
 */
function isVariable(node: Quantified): boolean {
  return node.max > node.min;
}

/**
 * `true` when the quantifier can apply its body more than once.
 *
 * A bounded outer count still multiplies an ambiguous body's choices —
 * `(.*a){10}` is O(n^10), which hangs on a 100 KB value just as surely as an
 * exponential pattern does — so bounded repetitions above one are reported
 * too, classified as polynomial rather than exponential.
 */
function repeatsMoreThanOnce(node: Quantified): boolean {
  return node.max > 1;
}

/* ------------------------------------------------------------------ *
 * Analysis
 * ------------------------------------------------------------------ */

/**
 * `true` when a node can match the same text in more than one way — the
 * property that turns an enclosing repetition superlinear.
 *
 * Note what is deliberately *not* ambiguous: a lone variable quantifier.
 * Greedy matching of `a*` over `aaa` is deterministic — it takes all three.
 * `a*` only offers the engine a choice once something else competes for those
 * characters, which is why ambiguity is a property of a quantifier's
 * surroundings rather than of the quantifier itself. Treating every `X?` or
 * `X+` as ambiguous is the obvious implementation and it is wrong: it condemns
 * `(_?[0-9])*`, where each iteration's extent is forced by the input, along
 * with `(\w+\s?)*`, where it is not.
 */
function isAmbiguous(node: RegexNode): boolean {
  switch (node.type) {
    case 'group':
    case 'quantified':
      return isAmbiguous(node.body);
    case 'alternation':
      return hasOverlappingBranches(node) || node.options.some(isAmbiguous);
    case 'sequence':
      return isSequenceAmbiguous(node);
    default:
      return false;
  }
}

/** `true` when two branches of an alternation can match the same first character. */
function hasOverlappingBranches(node: Alternation): boolean {
  const sets = node.options.map(charSetOf);
  for (let i = 0; i < sets.length; i++) {
    for (let j = i + 1; j < sets.length; j++) {
      if (overlaps(sets[i] as CharSet, sets[j] as CharSet)) return true;
    }
  }
  return false;
}

/**
 * `true` when a sequence offers the engine a choice about how to consume text.
 *
 * Three ways it can, the third being the one that matters for a repeated body:
 *
 *  - something inside it is ambiguous in its own right (`(a+)+` nested within),
 *  - two of its unbounded quantifiers compete for the same characters (`x+x+`),
 *  - one of its unbounded quantifiers matches characters that could equally
 *    start the *next* iteration of the enclosing repetition. That is the
 *    difference between `(\w+\s?)*` — where `\w+` can hand a `\w` back, so
 *    `aa` can be one iteration or two — and `(\.[a-z]+)*`, where every
 *    iteration must begin with a literal `.` that `[a-z]+` cannot match, so the
 *    partition is forced and the match is linear.
 */
function isSequenceAmbiguous(node: Sequence): boolean {
  if (node.items.some(isAmbiguous)) return true;
  if (hasAdjacentOverlap(node.items)) return true;

  const first = charSetOf(node);
  return node.items.some(
    (item) =>
      item.type === 'quantified' &&
      isUnbounded(item) &&
      canConsume(item.body) &&
      overlaps(charSetOf(item.body), first),
  );
}

/** `true` when two of the sequence's unbounded quantifiers overlap. */
function hasAdjacentOverlap(items: RegexNode[]): boolean {
  const quantified = items.filter(
    (item): item is Quantified => item.type === 'quantified' && isUnbounded(item),
  );
  for (let i = 0; i < quantified.length; i++) {
    for (let j = i + 1; j < quantified.length; j++) {
      const left = quantified[i] as Quantified;
      const right = quantified[j] as Quantified;
      if (overlaps(charSetOf(left.body), charSetOf(right.body))) return true;
    }
  }
  return false;
}

/**
 * `true` when this node's failure can fail the whole match.
 *
 * A mandatory atom can; a fully optional one (`[a-z]*`) cannot. Anchors and
 * lookarounds consume nothing but can still refuse, which is exactly why `$`
 * is what makes `\s*\s*$` exploitable while `\s*\s*` on its own matches the
 * empty string at offset 0 and never backtracks.
 */
function canFail(node: RegexNode): boolean {
  if (node.type === 'anchor' || node.type === 'lookaround') return true;
  return !isOptional(node);
}

/** `true` when any item after `index` can fail the match. */
function canFailAfter(items: RegexNode[], index: number): boolean {
  for (let i = index + 1; i < items.length; i++) {
    if (canFail(items[i] as RegexNode)) return true;
  }
  return false;
}

/** A short string that drives the engine into the reported backtracking. */
function witnessFor(node: RegexNode, repeats: number): string {
  const set = charSetOf(node);
  if (set.unknown || set.empty) return 'a'.repeat(repeats);
  const code = SAMPLE_CODES.find((candidate) => set.has(candidate) && candidate >= 0x21);
  const unit = code === undefined ? 'a' : String.fromCodePoint(code);
  // Follow the repeated unit with something the set rejects, so the overall
  // match fails and the engine has to exhaust every partition.
  const sentinel = SAMPLE_CODES.find((candidate) => !set.has(candidate) && candidate >= 0x21);
  return unit.repeat(repeats) + (sentinel === undefined ? '' : String.fromCodePoint(sentinel));
}

/**
 * Walks the AST, collecting findings.
 *
 * `failableAfter` says whether anything following this node can refuse to
 * match. It matters because backtracking only happens when the engine is
 * forced to reconsider: a pattern ending in `\d+[^\s]+` has two overlapping
 * quantifiers and is perfectly safe, because the greedy first pass always
 * succeeds and there is nothing after them to fail. Append a `$` and the same
 * pair becomes quadratic.
 *
 * The flag gates the *polynomial* findings only. Exponential structures are
 * reported wherever they appear, continuation or not: `(a+)+` is one edit away
 * from `(a+)+$`, the rewrite that removes it is always available and always an
 * improvement, and the cost of being wrong about reachability there is a hung
 * pipeline rather than a slow one.
 */
function collect(
  node: RegexNode,
  source: string,
  findings: RedosFinding[],
  failableAfter: boolean,
): void {
  if (node.type === 'quantified' && repeatsMoreThanOnce(node)) {
    const body = unwrap(node.body);
    // An unbounded outer repetition compounds the body's ambiguity without
    // limit; a bounded one raises the polynomial degree instead.
    const complexity: RedosComplexity = isUnbounded(node) ? 'exponential' : 'polynomial';

    if (body.type === 'quantified' && isVariable(body) && canConsume(body.body)) {
      findings.push({
        kind: 'nested-quantifier',
        complexity,
        fragment: source.slice(node.start, node.end),
        index: node.start,
        detail:
          'a variable-length quantifier directly inside another lets the engine split the same ' +
          'input exponentially many ways before refusing a match',
        witness: witnessFor(body.body, 30),
      });
    } else if (body.type === 'alternation') {
      if (hasOverlappingBranches(body)) {
        findings.push({
          kind: 'quantified-overlapping-alternation',
          complexity,
          fragment: source.slice(node.start, node.end),
          index: node.start,
          detail:
            'the repeated alternation has branches that match the same characters, so every ' +
            'input character doubles the number of permutations the engine tries',
          witness: witnessFor(body, 30),
        });
      }
    } else if (body.type === 'sequence' && isAmbiguous(body)) {
      findings.push({
        kind: 'quantified-overlapping-sequence',
        complexity,
        fragment: source.slice(node.start, node.end),
        index: node.start,
        detail:
          'the repeated group can match the same text in more than one way, so the outer ' +
          'repetition multiplies those ambiguities together',
        witness: witnessFor(body, 30),
      });
    }
  }

  if (node.type === 'sequence') {
    const items = node.items;
    for (let i = 0; i < items.length; i++) {
      const left = items[i];
      if (left?.type !== 'quantified' || !isUnbounded(left)) continue;
      for (let j = i + 1; j < items.length; j++) {
        const right = items[j];
        if (right === undefined) continue;
        if (right.type !== 'quantified' || !isUnbounded(right)) {
          // A mandatory atom between the two quantifiers pins the split point,
          // so `a+b a+` is not quadratic. A zero-width or optional one does
          // not, so keep scanning past it.
          if (!isOptional(right)) break;
          continue;
        }
        if (!overlaps(charSetOf(left.body), charSetOf(right.body))) continue;
        // Quadratic only if the engine can be forced to reconsider the split.
        if (!canFailAfter(items, j) && !failableAfter) break;
        findings.push({
          kind: 'adjacent-quantifiers',
          complexity: 'polynomial',
          fragment: source.slice(left.start, right.end),
          index: left.start,
          detail:
            'two unbounded quantifiers in sequence match the same characters, so the engine ' +
            'tries every split point between them — quadratic in the input length',
          witness: witnessFor(left.body, 2_000),
        });
        break;
      }
    }
  }

  if (node.type === 'sequence') {
    // Each item inherits whatever can fail after the sequence, plus whatever
    // can fail after it *within* the sequence.
    node.items.forEach((child, index) =>
      collect(child, source, findings, canFailAfter(node.items, index) || failableAfter),
    );
    return;
  }

  for (const child of childrenOf(node)) collect(child, source, findings, failableAfter);
}

/** Looks through non-capturing wrappers to the construct that matters. */
function unwrap(node: RegexNode): RegexNode {
  let current = node;
  while (current.type === 'group') current = current.body;
  if (current.type === 'sequence' && current.items.length === 1) {
    return unwrap(current.items[0] as RegexNode);
  }
  return current;
}

function childrenOf(node: RegexNode): RegexNode[] {
  switch (node.type) {
    case 'alternation':
      return node.options;
    case 'sequence':
      return node.items;
    case 'quantified':
    case 'group':
    case 'lookaround':
      return [node.body];
    default:
      return [];
  }
}

/**
 * Statically analyses one pattern for catastrophic backtracking.
 *
 * `pattern` is the regex source without delimiters — what `RegExp.prototype
 * .source` returns. Flags are accepted so a caller can pass what it has, but
 * they do not change the verdict: no flag makes a backtracking structure safe.
 *
 * Never throws. An unparseable pattern comes back with `safe: false` and a
 * `parseError`, because a matcher the detector cannot read is a matcher nobody
 * has audited.
 */
export function analyzeRegex(pattern: string, flags = ''): RedosReport {
  // The engine is the authority on whether a pattern compiles; the parser
  // below is the authority on its shape. Compiling first — which never runs the
  // pattern, so it cannot backtrack — catches what this parser's permissive
  // subset would wave through, and catches an invalid flag string such as a
  // policy's `regexFlags: "q"`.
  const compileError = whyItWillNotCompile(pattern, flags);
  if (compileError !== undefined) {
    return {
      pattern,
      safe: false,
      parseError: compileError,
      findings: [],
      worstComplexity: 'linear',
    };
  }

  let ast: RegexNode;
  try {
    ast = new RegexParser(pattern).parse();
  } catch (error) {
    return {
      pattern,
      safe: false,
      parseError: error instanceof Error ? error.message : String(error),
      findings: [],
      worstComplexity: 'linear',
    };
  }

  const findings: RedosFinding[] = [];
  // Nothing follows the pattern as a whole, so a trailing quantifier pair has
  // no continuation that could fail. An unanchored pattern is still analysed:
  // `.test()` retries at every offset, and a structure that backtracks does so
  // anchored or not.
  collect(ast, pattern, findings, false);

  // Exponential first: it is the finding that must be fixed, and a pattern
  // usually trips several detections at once.
  const ranked = [...findings].sort((a, b) =>
    a.complexity === b.complexity ? a.index - b.index : a.complexity === 'exponential' ? -1 : 1,
  );
  const deduped = ranked.filter(
    (finding, index) =>
      ranked.findIndex((other) => other.index === finding.index && other.kind === finding.kind) ===
      index,
  );

  return {
    pattern,
    safe: deduped.length === 0,
    findings: deduped,
    worstComplexity:
      deduped.length === 0
        ? 'linear'
        : (deduped[0] as RedosFinding).complexity === 'exponential'
          ? 'exponential'
          : 'polynomial',
  };
}

/** The engine's own complaint about a pattern, or `undefined` if it compiles. */
function whyItWillNotCompile(pattern: string, flags: string): string | undefined {
  try {
    new RegExp(pattern, flags);
    return undefined;
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
}

/** `true` when the pattern parses and no finding was produced. */
export function isRegexSafe(pattern: string, flags = ''): boolean {
  return analyzeRegex(pattern, flags).safe;
}

/* ------------------------------------------------------------------ *
 * Diagnostics
 * ------------------------------------------------------------------ */

/**
 * Where a regex came from, so a diagnostic can point back at it.
 *
 * An alias for the type `LintOptions.customRegexes` carries, named for how it
 * reads at the audit call site.
 */
export type RegexSource = CustomRegexMatcher;

/** One sentence naming the complexity class, for a diagnostic message. */
function complexityLabel(complexity: RedosComplexity): string {
  return complexity === 'exponential'
    ? 'exponential (O(2^n)) worst-case backtracking'
    : 'polynomial (O(n^2)) worst-case backtracking';
}

/**
 * Turns a regex source into the diagnostics it deserves.
 *
 * Emits {@link REDOS_RULE_ID} at `error` for anything that backtracks — a
 * matcher that can hang the linter is not a style preference — and
 * {@link REDOS_INVALID_RULE_ID} for a pattern that will not compile.
 */
export function auditRegexSources(
  sources: readonly RegexSource[],
  severity: Severity = 'error',
): Diagnostic[] {
  const diagnostics: Diagnostic[] = [];

  for (const source of sources) {
    const report = analyzeRegex(source.pattern, source.flags ?? '');
    const where = source.origin === undefined ? '' : ` in ${source.origin}`;

    if (report.parseError !== undefined) {
      diagnostics.push({
        rule: REDOS_INVALID_RULE_ID,
        severity,
        category: 'policy',
        message: `Regular expression /${source.pattern}/${where} is not valid: ${report.parseError}`,
        ...(source.path === undefined ? {} : { path: source.path }),
        ...(source.position === undefined ? {} : { position: source.position }),
        suggestion: 'Correct the pattern, or remove the matcher that declares it',
      });
      continue;
    }

    for (const finding of report.findings) {
      diagnostics.push({
        rule: REDOS_RULE_ID,
        severity,
        category: 'policy',
        message:
          `Regular expression /${source.pattern}/${where} is vulnerable to ` +
          `${complexityLabel(finding.complexity)}: \`${finding.fragment}\` — ${finding.detail}`,
        ...(source.path === undefined ? {} : { path: source.path }),
        ...(source.position === undefined ? {} : { position: source.position }),
        suggestion: suggestionFor(finding),
      });
    }
  }

  return diagnostics;
}

/** The concrete rewrite that removes the ambiguity, per finding shape. */
function suggestionFor(finding: RedosFinding): string {
  switch (finding.kind) {
    case 'nested-quantifier':
      return (
        `Collapse the nested quantifiers in \`${finding.fragment}\` into a single one ` +
        '(e.g. `(a+)+` becomes `a+`), or make the inner one possessive by anchoring the group'
      );
    case 'quantified-overlapping-alternation':
      return (
        `Make the branches of \`${finding.fragment}\` mutually exclusive so only one can match ` +
        'each character (e.g. `(a|ab)+` becomes `(ab?)+`)'
      );
    case 'quantified-overlapping-sequence':
      return (
        `Rewrite \`${finding.fragment}\` so the repeated group matches each input exactly one ` +
        'way, or bound the repetition with `{0,n}`'
      );
    case 'adjacent-quantifiers':
      return (
        `Merge the adjacent quantifiers in \`${finding.fragment}\` into one (e.g. \`\\s*\\s*\` ` +
        'becomes `\\s*`), or separate them with a character neither can match'
      );
  }
}

/* ------------------------------------------------------------------ *
 * Lint rule
 * ------------------------------------------------------------------ */

/**
 * Screens the run's custom regex matchers before anything uses them.
 *
 * Registered in `allRules` so a finding travels through the same reporters,
 * `--off`/`--warn` overrides, and exit-code machinery as every other rule,
 * rather than needing a bespoke output path. Both rules read the same option
 * and filter by id, so `--off security/invalid-regex` can silence an
 * unparseable pattern without also silencing a dangerous one.
 */
export const redosDetectorRules: Rule[] = [
  {
    id: REDOS_RULE_ID,
    category: 'policy',
    severity: 'error',
    description: 'Custom regex matchers must not be vulnerable to catastrophic backtracking',
    run(ctx) {
      reportConfigured(ctx, REDOS_RULE_ID);
    },
  },
  {
    id: REDOS_INVALID_RULE_ID,
    category: 'policy',
    severity: 'error',
    description: 'Custom regex matchers must be valid regular expressions',
    run(ctx) {
      reportConfigured(ctx, REDOS_INVALID_RULE_ID);
    },
  },
];

/** Reports whichever of the two findings `ruleId` names, if any were produced. */
function reportConfigured(ctx: Parameters<Rule['run']>[0], ruleId: string): void {
  const configured = ctx.options.customRegexes;
  if (configured === undefined || configured.length === 0) return;

  for (const diagnostic of auditRegexSources(configured)) {
    if (diagnostic.rule !== ruleId) continue;
    ctx.report(diagnostic);
  }
}

/* ------------------------------------------------------------------ *
 * Rule test harness
 * ------------------------------------------------------------------ */

/** A regex literal found in a source file, with where it was written. */
export interface RegexLiteral {
  pattern: string;
  flags: string;
  /** 1-based line the literal starts on. */
  line: number;
}

/**
 * Extracts regex literals from TypeScript source.
 *
 * Used by the rule test harness to hold the *built-in* rules to the same
 * standard as a user's policy: every URL, key, and account-id matcher in
 * `src/` is screened on every CI run, so a rule added next year cannot
 * introduce a quadratic matcher unnoticed.
 *
 * A regex literal and a division operator are genuinely ambiguous without a
 * full parse, so this scanner resolves the ambiguity the way JavaScript's own
 * lexer does — a `/` begins a literal only where an expression may start — and
 * skips strings, template literals, and comments. Anything it cannot classify
 * confidently is skipped rather than guessed at, since a false literal would
 * fail the build on code that does not exist.
 */
export function extractRegexLiterals(source: string): RegexLiteral[] {
  const literals: RegexLiteral[] = [];
  let line = 1;
  // Tracks whether a `/` here would start a regex (true) or be division.
  let regexAllowed = true;

  for (let i = 0; i < source.length; i++) {
    const ch = source[i] as string;

    if (ch === '\n') {
      line++;
      continue;
    }

    // Comments.
    if (ch === '/' && source[i + 1] === '/') {
      while (i < source.length && source[i] !== '\n') i++;
      i--;
      continue;
    }
    if (ch === '/' && source[i + 1] === '*') {
      i += 2;
      while (i < source.length && !(source[i] === '*' && source[i + 1] === '/')) {
        if (source[i] === '\n') line++;
        i++;
      }
      i++;
      continue;
    }

    // String and template literals.
    if (ch === '"' || ch === "'" || ch === '`') {
      const quote = ch;
      i++;
      while (i < source.length && source[i] !== quote) {
        if (source[i] === '\\') i++;
        else if (source[i] === '\n') line++;
        i++;
      }
      regexAllowed = false;
      continue;
    }

    if (ch === '/' && regexAllowed) {
      const literal = readRegexLiteral(source, i);
      if (literal !== undefined) {
        literals.push({ pattern: literal.pattern, flags: literal.flags, line });
        i = literal.end - 1;
        regexAllowed = false;
        continue;
      }
    }

    if (/\s/.test(ch)) continue;
    // After a value, `/` is division; after an operator or punctuator it can
    // start a literal. `)` is treated as ending a value, which misses
    // `if (x) /re/.test(y)` — vanishingly rare, and missing a literal is the
    // safe direction.
    regexAllowed = /[=(,:[!&|?{};+\-*%<>~^]/.test(ch) || isKeywordBoundary(source, i);
  }

  return literals;
}

/** `true` when the identifier ending at `i` is a keyword a regex may follow. */
function isKeywordBoundary(source: string, i: number): boolean {
  const KEYWORDS = ['return', 'typeof', 'case', 'in', 'of', 'new', 'delete', 'void', 'instanceof'];
  for (const keyword of KEYWORDS) {
    const start = i - keyword.length + 1;
    if (start < 0) continue;
    if (source.slice(start, i + 1) !== keyword) continue;
    const before = start === 0 ? ' ' : (source[start - 1] as string);
    if (!/[A-Za-z0-9_$]/.test(before)) return true;
  }
  return false;
}

/** Reads a regex literal starting at `start`, or `undefined` if it is not one. */
function readRegexLiteral(
  source: string,
  start: number,
): { pattern: string; flags: string; end: number } | undefined {
  let i = start + 1;
  let inClass = false;
  let body = '';

  while (i < source.length) {
    const ch = source[i] as string;
    if (ch === '\n') return undefined; // literals cannot span lines
    if (ch === '\\') {
      body += ch + (source[i + 1] ?? '');
      i += 2;
      continue;
    }
    if (ch === '[') inClass = true;
    else if (ch === ']') inClass = false;
    else if (ch === '/' && !inClass) {
      let flags = '';
      let j = i + 1;
      while (j < source.length && /[dgimsuvy]/.test(source[j] as string)) {
        flags += source[j];
        j++;
      }
      // An empty pattern is the `//` comment case, already handled above.
      if (body === '') return undefined;
      return { pattern: body, flags, end: j };
    }
    body += ch;
    i++;
  }
  return undefined;
}

/**
 * Screens every regex literal in a source file and reports the vulnerable ones.
 *
 * The shape a test wants: a file path in, a list of human-readable complaints
 * out, empty when the file is clean.
 */
export function auditSourceRegexes(
  source: string,
  label = 'source',
): Array<{ line: number; pattern: string; finding: RedosFinding }> {
  const problems: Array<{ line: number; pattern: string; finding: RedosFinding }> = [];

  for (const literal of extractRegexLiterals(source)) {
    const report = analyzeRegex(literal.pattern, literal.flags);
    // A literal the scanner misread would not compile; skip it rather than
    // failing a build over the scanner's own ambiguity.
    if (report.parseError !== undefined) continue;
    for (const finding of report.findings) {
      problems.push({
        line: literal.line,
        pattern: `${label}:${literal.line} /${literal.pattern}/`,
        finding,
      });
    }
  }

  return problems;
}
