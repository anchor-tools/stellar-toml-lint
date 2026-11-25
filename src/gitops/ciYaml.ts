/**
 * A small, deterministic YAML emitter for generated GitHub Actions workflows.
 *
 * The runtime package has no YAML dependency, and workflows only need a narrow
 * subset: mappings, sequences, strings, numbers, booleans and literal block
 * scalars for multi-line `run:` scripts. Emitting that subset by hand keeps the
 * output byte-for-byte stable across releases, so a regenerated workflow shows
 * up in review as a minimal diff.
 */

export type YamlValue =
  | string
  | number
  | boolean
  | null
  | readonly YamlValue[]
  | { readonly [key: string]: YamlValue | undefined };

/** A string that the emitter must always quote. */
const NEEDS_QUOTES =
  /^$|^[\s]|[\s]$|^[-?:,[\]{}#&*!|>'"%@`~]|: | #|^(?:true|false|yes|no|on|off|null|y|n)$|^[-+]?(?:\d|\.\d)|^0x/i;

function hasControlCharacter(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

/** Plain keys must be simple identifiers; anything else is quoted. */
const PLAIN_KEY = /^[A-Za-z_][A-Za-z0-9_.-]*$/;

function quote(value: string): string {
  // JSON string syntax is a strict subset of YAML double-quoted scalars.
  return JSON.stringify(value);
}

function scalar(value: string | number | boolean | null): string {
  if (value === null) return 'null';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error(`Cannot emit non-finite number ${value}`);
    return String(value);
  }
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  // `${{ ... }}` expressions start with `$`, which YAML reads as plain text,
  // so they only get quoted when another rule below applies.
  return NEEDS_QUOTES.test(value) || hasControlCharacter(value) ? quote(value) : value;
}

function key(name: string): string {
  // GitHub's parser reads the top-level `on` key as a string; every workflow
  // in the docs writes it bare, so match that instead of quoting it.
  if (name === 'on') return name;
  return PLAIN_KEY.test(name) && !NEEDS_QUOTES.test(name) ? name : quote(name);
}

function isMapping(value: YamlValue): value is { readonly [key: string]: YamlValue | undefined } {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Callers only pass sequences and mappings. */
function isEmptyCollection(value: YamlValue): boolean {
  if (Array.isArray(value)) return value.length === 0;
  return Object.values(value as Record<string, unknown>).every((v) => v === undefined);
}

function blockScalar(value: string, indent: string): string[] {
  // `|` keeps interior newlines and adds exactly one trailing newline.
  const body = value.replace(/\n+$/, '');
  const lines = body.split('\n').map((line) => (line === '' ? '' : `${indent}${line}`));
  // Leading whitespace on the first line needs an explicit indentation
  // indicator, or the parser would infer the wrong block indentation.
  return [/^[ \t]/.test(body) ? '|2' : '|', ...lines];
}

function emit(value: YamlValue, depth: number): string[] {
  const indent = '  '.repeat(depth);
  if (Array.isArray(value)) {
    const out: string[] = [];
    for (const item of value as readonly YamlValue[]) {
      if (isMapping(item) && !isEmptyCollection(item)) {
        const [first, ...rest] = emit(item, depth + 1);
        out.push(`${indent}- ${(first as string).trimStart()}`, ...rest);
      } else if (Array.isArray(item) && !isEmptyCollection(item)) {
        out.push(`${indent}-`, ...emit(item, depth + 1));
      } else {
        out.push(`${indent}- ${inline(item)}`);
      }
    }
    return out;
  }
  if (isMapping(value)) {
    const out: string[] = [];
    for (const [name, child] of Object.entries(value)) {
      if (child === undefined) continue;
      if ((Array.isArray(child) || isMapping(child)) && !isEmptyCollection(child)) {
        out.push(`${indent}${key(name)}:`, ...emit(child, depth + 1));
      } else if (typeof child === 'string' && child.includes('\n')) {
        const [head, ...body] = blockScalar(child, '  '.repeat(depth + 1));
        out.push(`${indent}${key(name)}: ${head}`, ...body);
      } else {
        out.push(`${indent}${key(name)}: ${inline(child)}`);
      }
    }
    return out;
  }
  return [`${indent}${inline(value)}`];
}

/** A value that fits on its key's line: a scalar or an empty collection. */
function inline(value: YamlValue): string {
  if (Array.isArray(value)) return '[]';
  if (isMapping(value)) return '{}';
  // A multi-line string inside a sequence is emitted as a quoted scalar.
  if (typeof value === 'string' && value.includes('\n')) return quote(value);
  return scalar(value as string | number | boolean | null);
}

/** Serialises `value` as a YAML document ending in a newline. */
export function toYaml(value: YamlValue): string {
  return `${emit(value, 0).join('\n')}\n`;
}
