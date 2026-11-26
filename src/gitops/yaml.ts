/**
 * A small, dependency-free YAML reader for Kubernetes manifests.
 *
 * Kubernetes manifests only use a narrow slice of YAML: block mappings and
 * sequences, quoted and plain scalars, flow collections, and the occasional
 * literal block. Implementing that slice here keeps the package free of a
 * native parser and keeps the dependency list auditable, which matters for a
 * tool that runs inside other people's CI.
 *
 * The parser is deliberately forgiving. It records errors instead of throwing,
 * so a single malformed document does not hide findings in the rest of a
 * multi-document file. Callers decide whether to report those errors and
 * whether to keep auditing the partial value.
 */

export interface YamlParseError {
  message: string;
  line: number;
  column: number;
}

export interface YamlDocument {
  value: unknown;
  /** 1-based line where the document starts. */
  line: number;
}

export interface YamlParseResult {
  documents: YamlDocument[];
  errors: YamlParseError[];
}

interface SourceLine {
  raw: string;
  number: number;
  indent: number;
  content: string;
}

export function parseYamlDocuments(source: string): YamlParseResult {
  const normalized = source.charCodeAt(0) === 0xfeff ? source.slice(1) : source;
  const lines = toLines(normalized);
  const documents: YamlDocument[] = [];
  const errors: YamlParseError[] = [];
  let current: SourceLine[] = [];
  let startLine = 1;

  const flush = (): void => {
    if (!current.some(isContentLine)) {
      current = [];
      return;
    }
    const parser = new BlockParser(current, errors);
    const value = parser.parse();
    documents.push({ value, line: startLine });
    current = [];
  };

  for (const line of lines) {
    const trimmed = line.content.trimEnd();

    if (line.indent === 0 && /^---(?:\s|$)/.test(trimmed)) {
      flush();
      startLine = line.number;
      const rest = trimmed.slice(3).trim();
      if (rest !== '' && !rest.startsWith('#')) {
        current.push({ raw: rest, number: line.number, indent: 0, content: rest });
      }
      continue;
    }

    if (line.indent === 0 && /^\.\.\.(?:\s|$)/.test(trimmed)) {
      flush();
      startLine = line.number + 1;
      continue;
    }

    // YAML directives do not carry data for Kubernetes manifests.
    if (line.indent === 0 && trimmed.startsWith('%')) continue;

    current.push(line);
  }

  flush();
  return { documents, errors };
}

function toLines(source: string): SourceLine[] {
  return source.split(/\r\n|\n|\r/).map((raw, index) => {
    // Tabs are illegal indentation in YAML. Expanding them is friendlier than
    // rejecting an otherwise readable manifest.
    const expanded = raw.replace(/\t/g, '  ');
    const indent = expanded.length - expanded.trimStart().length;
    return {
      raw: expanded,
      number: index + 1,
      indent,
      content: expanded.slice(indent),
    };
  });
}

function isContentLine(line: SourceLine): boolean {
  const trimmed = line.content.trim();
  return trimmed !== '' && !trimmed.startsWith('#');
}

class BlockParser {
  private pos = 0;
  private readonly anchors = new Map<string, unknown>();

  constructor(
    private readonly lines: SourceLine[],
    private readonly errors: YamlParseError[],
  ) {}

  parse(): unknown {
    this.skipIgnorable();
    if (this.pos >= this.lines.length) return null;

    const value = this.parseBlock(0);
    this.skipIgnorable();

    while (this.pos < this.lines.length) {
      const line = this.lines[this.pos];
      if (!line) break;
      this.error('Unexpected content after the document value', line);
      this.pos++;
      this.skipIgnorable();
    }

    return value;
  }

  private skipIgnorable(): void {
    while (this.pos < this.lines.length) {
      const line = this.lines[this.pos];
      if (!line || !isContentLine(line)) {
        this.pos++;
        continue;
      }
      break;
    }
  }

  private peek(): SourceLine | undefined {
    this.skipIgnorable();
    return this.lines[this.pos];
  }

  private parseBlock(minIndent: number): unknown {
    const first = this.peek();
    if (!first || first.indent < minIndent) return null;

    return this.isSequenceItem(first.content)
      ? this.parseSequence(first.indent)
      : this.parseMapping(first.indent);
  }

  private isSequenceItem(content: string): boolean {
    return content === '-' || content.startsWith('- ') || content.startsWith('-\t');
  }

  private parseSequence(indent: number): unknown[] {
    const result: unknown[] = [];

    while (true) {
      const line = this.peek();
      if (!line || line.indent < indent) break;

      if (line.indent > indent) {
        this.error('Unexpected indentation in sequence', line);
        break;
      }
      if (!this.isSequenceItem(line.content)) break;

      const rest = line.content.slice(1);
      const value = rest.replace(/^[ \t]+/, '');
      this.pos++;

      if (value === '' || value.startsWith('#')) {
        const next = this.peek();
        result.push(next && next.indent > indent ? this.parseBlock(indent + 1) : null);
        continue;
      }

      if (isBlockScalarIndicator(value)) {
        result.push(this.parseBlockScalar(indent, value));
        continue;
      }

      if (findMappingColon(value) >= 0) {
        result.push(this.parseSequenceMapping(indent, value, line));
        continue;
      }

      result.push(this.parseInline(value, line));
    }

    return result;
  }

  /**
   * Parses the compact form `- key: value` plus any sibling keys indented to
   * align with that first key.
   */
  private parseSequenceMapping(
    sequenceIndent: number,
    firstValue: string,
    line: SourceLine,
  ): Record<string, unknown> {
    const offset = line.content.indexOf(firstValue);
    const itemIndent = sequenceIndent + (offset >= 0 ? offset : 2);
    const colon = findMappingColon(firstValue);
    const result: Record<string, unknown> = {};

    if (colon < 0) return result;

    const key = parseKey(firstValue.slice(0, colon));
    const rawValue = stripComment(firstValue.slice(colon + 1)).trim();
    result[key] = this.parseMappingValue(rawValue, itemIndent, line);
    this.parseMappingInto(result, itemIndent);
    return result;
  }

  private parseMapping(indent: number): Record<string, unknown> {
    const result: Record<string, unknown> = {};
    this.parseMappingInto(result, indent);
    return result;
  }

  private parseMappingInto(result: Record<string, unknown>, indent: number): void {
    while (true) {
      const line = this.peek();
      if (!line || line.indent < indent) break;

      if (line.indent > indent) {
        this.error('Unexpected indentation in mapping', line);
        break;
      }
      if (this.isSequenceItem(line.content)) break;

      const colon = findMappingColon(line.content);
      if (colon < 0) {
        this.error('Expected a "key: value" mapping entry', line);
        this.pos++;
        continue;
      }

      const key = parseKey(line.content.slice(0, colon));
      const rawValue = stripComment(line.content.slice(colon + 1)).trim();
      this.pos++;

      if (Object.prototype.hasOwnProperty.call(result, key)) {
        this.error(`Duplicate mapping key "${key}"`, line);
      }
      result[key] = this.parseMappingValue(rawValue, indent, line);
    }
  }

  private parseMappingValue(rawValue: string, indent: number, line: SourceLine): unknown {
    if (rawValue === '') {
      const next = this.peek();
      return next && next.indent > indent ? this.parseBlock(indent + 1) : null;
    }
    if (isBlockScalarIndicator(rawValue)) {
      return this.parseBlockScalar(indent, rawValue);
    }
    return this.parseInline(rawValue, line);
  }

  private parseInline(rawValue: string, line: SourceLine): unknown {
    const value = stripComment(rawValue).trim();
    if (value === '') return null;

    const first = value[0];
    if (first === '[') {
      return new FlowParser(value, line, (message, column) =>
        this.error(message, line, column),
      ).parseSequence();
    }
    if (first === '{') {
      return new FlowParser(value, line, (message, column) =>
        this.error(message, line, column),
      ).parseMapping();
    }
    if (first === '"' || first === "'") {
      const quoted = parseQuoted(value, 0);
      if (!quoted) {
        this.error('Unterminated quoted string', line);
        return value;
      }
      return quoted.value;
    }

    if (first === '&') {
      const space = value.indexOf(' ');
      if (space > 0) {
        const name = value.slice(1, space);
        const parsed = this.parseInline(value.slice(space + 1), line);
        this.anchors.set(name, parsed);
        return parsed;
      }
      return null;
    }

    if (first === '*') {
      const name = value.slice(1).trim();
      return this.anchors.has(name) ? cloneValue(this.anchors.get(name)) : value;
    }

    // Tags such as !!str or !<tag:yaml.org,2002:str> only change the scalar
    // type. For manifest auditing the underlying text is what matters.
    if (first === '!') {
      const space = value.indexOf(' ');
      return space > 0 ? this.parseInline(value.slice(space + 1), line) : null;
    }

    return parsePlainScalar(value);
  }

  private parseBlockScalar(parentIndent: number, rawIndicator: string): string {
    const indicator = stripComment(rawIndicator).trim();
    const folded = indicator.startsWith('>');
    const chomp = indicator.includes('-') ? 'strip' : indicator.includes('+') ? 'keep' : 'clip';
    const digit = /\d/.exec(indicator);
    let contentIndent = digit ? parentIndent + Number(digit[0]) : undefined;

    const collected: { text: string; blank: boolean }[] = [];

    while (this.pos < this.lines.length) {
      const current = this.lines[this.pos];
      if (!current) break;

      if (current.content.trim() === '') {
        collected.push({ text: '', blank: true });
        this.pos++;
        continue;
      }

      if (current.indent <= parentIndent) break;
      if (contentIndent === undefined) contentIndent = current.indent;
      if (current.indent < contentIndent) break;

      collected.push({ text: current.raw.slice(contentIndent), blank: false });
      this.pos++;
    }

    let result: string;
    if (folded) {
      const parts: string[] = [];
      for (const [index, item] of collected.entries()) {
        if (item.blank) {
          parts.push('\n');
          continue;
        }
        const previous = collected[index - 1];
        parts.push(previous && !previous.blank ? ` ${item.text}` : item.text);
      }
      result = parts.join('');
    } else {
      result = collected.map((item) => item.text).join('\n');
    }

    if (chomp === 'strip') return result.replace(/\n+$/, '');
    if (chomp === 'clip') {
      return result.length > 0 ? `${result.replace(/\n+$/, '')}\n` : '';
    }
    return result;
  }

  private error(message: string, line: SourceLine, column?: number): void {
    this.errors.push({
      message,
      line: line.number,
      column: column ?? line.indent + 1,
    });
  }
}

class FlowParser {
  private index = 0;

  constructor(
    private readonly source: string,
    private readonly line: SourceLine,
    private readonly fail: (message: string, column: number) => void,
  ) {}

  parseSequence(): unknown[] {
    this.index = 1;
    const result: unknown[] = [];
    this.skipSpaces();

    if (this.source[this.index] === ']') {
      this.index++;
      return result;
    }

    while (this.index < this.source.length) {
      result.push(this.parseValue());
      this.skipSpaces();

      const char = this.source[this.index];
      if (char === ',') {
        this.index++;
        this.skipSpaces();
        if (this.source[this.index] === ']') {
          this.index++;
          break;
        }
        continue;
      }
      if (char === ']') {
        this.index++;
        break;
      }

      this.fail('Expected "," or "]" in flow sequence', this.index + 1);
      break;
    }

    return result;
  }

  parseMapping(): Record<string, unknown> {
    this.index = 1;
    const result: Record<string, unknown> = {};
    this.skipSpaces();

    if (this.source[this.index] === '}') {
      this.index++;
      return result;
    }

    while (this.index < this.source.length) {
      this.skipSpaces();
      const key = this.parseKey();
      this.skipSpaces();

      if (this.source[this.index] !== ':') {
        this.fail('Expected ":" in flow mapping', this.index + 1);
        break;
      }
      this.index++;

      result[key] = this.parseValue();
      this.skipSpaces();

      const char = this.source[this.index];
      if (char === ',') {
        this.index++;
        this.skipSpaces();
        if (this.source[this.index] === '}') {
          this.index++;
          break;
        }
        continue;
      }
      if (char === '}') {
        this.index++;
        break;
      }

      this.fail('Expected "," or "}" in flow mapping', this.index + 1);
      break;
    }

    return result;
  }

  private parseKey(): string {
    const first = this.source[this.index];
    if (first === '"' || first === "'") {
      const quoted = parseQuoted(this.source, this.index);
      if (quoted) {
        this.index = quoted.next;
        return String(quoted.value);
      }
      this.fail('Unterminated quoted key', this.index + 1);
      this.index = this.source.length;
      return '';
    }

    const start = this.index;
    while (this.index < this.source.length) {
      const char = this.source[this.index];
      if (char === ':' || char === ',' || char === '}') break;
      this.index++;
    }
    return this.source.slice(start, this.index).trim();
  }

  private parseValue(): unknown {
    this.skipSpaces();
    const first = this.source[this.index];

    if (first === '[') return this.parseSequence();
    if (first === '{') return this.parseMapping();

    if (first === '"' || first === "'") {
      const quoted = parseQuoted(this.source, this.index);
      if (!quoted) {
        this.fail('Unterminated quoted string', this.index + 1);
        this.index = this.source.length;
        return null;
      }
      this.index = quoted.next;
      return quoted.value;
    }

    const start = this.index;
    while (this.index < this.source.length) {
      const char = this.source[this.index];
      if (char === ',' || char === ']' || char === '}') break;
      this.index++;
    }
    return parsePlainScalar(this.source.slice(start, this.index).trim());
  }

  private skipSpaces(): void {
    while (this.index < this.source.length && /\s/.test(this.source[this.index] ?? '')) {
      this.index++;
    }
  }
}

function isBlockScalarIndicator(value: string): boolean {
  return /^[|>](?:[+-]?\d*|\d*[+-]?)$/.test(stripComment(value).trim());
}

function findMappingColon(value: string): number {
  let single = false;
  let double = false;
  let escaped = false;
  let depth = 0;

  for (let index = 0; index < value.length; index++) {
    const char = value[index];

    if (double) {
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === '"') double = false;
      continue;
    }
    if (single) {
      if (char === "'") {
        if (value[index + 1] === "'") index++;
        else single = false;
      }
      continue;
    }

    if (char === '"') {
      double = true;
      continue;
    }
    if (char === "'") {
      single = true;
      continue;
    }
    if (char === '[' || char === '{') {
      depth++;
      continue;
    }
    if (char === ']' || char === '}') {
      if (depth > 0) depth--;
      continue;
    }

    if (char === ':' && depth === 0) {
      const next = value[index + 1];
      if (next === undefined || next === ' ' || next === '\t' || next === '#') return index;
    }
  }

  return -1;
}

function stripComment(value: string): string {
  let single = false;
  let double = false;
  let escaped = false;

  for (let index = 0; index < value.length; index++) {
    const char = value[index];

    if (double) {
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === '"') double = false;
      continue;
    }
    if (single) {
      if (char === "'") {
        if (value[index + 1] === "'") index++;
        else single = false;
      }
      continue;
    }

    if (char === '"') {
      double = true;
      continue;
    }
    if (char === "'") {
      single = true;
      continue;
    }

    if (char === '#' && (index === 0 || /\s/.test(value[index - 1] ?? ''))) {
      return value.slice(0, index);
    }
  }

  return value;
}

function parseKey(value: string): string {
  const trimmed = value.trim();
  const first = trimmed[0];
  if (first === '"' || first === "'") {
    const quoted = parseQuoted(trimmed, 0);
    if (quoted) return String(quoted.value);
  }
  return trimmed;
}

function parseQuoted(source: string, start: number): { value: unknown; next: number } | undefined {
  const quote = source[start];
  if (quote !== '"' && quote !== "'") return undefined;

  let result = '';
  let index = start + 1;

  while (index < source.length) {
    const char = source[index];

    if (quote === "'") {
      if (char === "'") {
        if (source[index + 1] === "'") {
          result += "'";
          index += 2;
          continue;
        }
        return { value: result, next: index + 1 };
      }
      result += char;
      index++;
      continue;
    }

    if (char === '"') return { value: result, next: index + 1 };

    if (char === '\\') {
      const escaped = source[index + 1];
      if (escaped === undefined) return undefined;
      switch (escaped) {
        case 'n':
          result += '\n';
          break;
        case 'r':
          result += '\r';
          break;
        case 't':
          result += '\t';
          break;
        case 'b':
          result += '\b';
          break;
        case 'f':
          result += '\f';
          break;
        case '"':
        case '\\':
        case '/':
          result += escaped;
          break;
        case 'u': {
          const hex = source.slice(index + 2, index + 6);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) return undefined;
          result += String.fromCharCode(Number.parseInt(hex, 16));
          index += 4;
          break;
        }
        case 'x': {
          const hex = source.slice(index + 2, index + 4);
          if (!/^[0-9a-fA-F]{2}$/.test(hex)) return undefined;
          result += String.fromCharCode(Number.parseInt(hex, 16));
          index += 2;
          break;
        }
        default:
          result += escaped;
      }
      index += 2;
      continue;
    }

    result += char;
    index++;
  }

  return undefined;
}

function parsePlainScalar(value: string): unknown {
  if (value === '' || value === '~') return null;

  const lower = value.toLowerCase();
  if (lower === 'null') return null;
  if (lower === 'true') return true;
  if (lower === 'false') return false;

  if (/^[-+]?(?:0|[1-9]\d*)$/.test(value)) {
    const number = Number(value);
    if (Number.isSafeInteger(number)) return number;
  }

  if (
    /^[-+]?(?:\d+\.\d+|\d+\.|\.\d+)(?:[eE][-+]?\d+)?$/.test(value) ||
    /^[-+]?\d+[eE][-+]?\d+$/.test(value)
  ) {
    const number = Number(value);
    if (Number.isFinite(number)) return number;
  }

  return value;
}

function cloneValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(cloneValue);
  if (typeof value === 'object' && value !== null) {
    const result: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value)) result[key] = cloneValue(entry);
    return result;
  }
  return value;
}
