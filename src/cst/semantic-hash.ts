/**
 * Deterministic structural hashing for `stellar.toml` (issue #309).
 *
 * A reviewer looking at a diff of a stellar.toml cannot always tell whether a
 * pull request changed what the file *says* or only how it is laid out: a
 * re-indented table, a reordered key, a comment edit, or a single-quoted string
 * that became a basic string all show up as churn. This module reduces a file
 * to the data it declares and hashes that, so two files that mean the same
 * thing hash the same and any semantic change — however small — does not.
 *
 * The pipeline is: parse with the same TOML parser `lint` uses (which already
 * discards whitespace, comments, quoting style and key order of appearance),
 * serialise the result as canonical JSON with object keys sorted by code
 * point, and take the SHA-256 of those UTF-8 bytes.
 *
 * Canonical JSON alone would merge TOML values that are distinct types, so
 * the serialiser keeps them apart:
 *
 * - integers are parsed as bigints and printed as plain JSON integers, while
 *   floats always carry a fraction or exponent (`1` vs `1.0`);
 * - non-finite floats, which JSON cannot spell, and date/time values, which a
 *   string could otherwise impersonate, are wrapped in a one-key tagged object
 *   (`{"$float":"nan"}`, `{"$datetime":"1979-05-27T07:32:00Z"}`).
 *
 * The output is meant to be compared in CI: record the hash of the approved
 * file and fail the deployment when `current_hash !== approved_hash`.
 */
import { sha256 } from '@noble/hashes/sha2';
import { bytesToHex } from '@noble/hashes/utils';
import { parse, TomlDate, TomlError } from 'smol-toml';

/** The outcome of hashing one source. */
export type SemanticHashResult =
  | {
      ok: true;
      /** Lower-case hex SHA-256 of {@link SemanticHashResult.canonical}. */
      hash: string;
      /** The canonical JSON the hash was computed over. */
      canonical: string;
    }
  | {
      ok: false;
      error: string;
      line?: number;
      column?: number;
    };

/**
 * Serialises a parsed TOML value as canonical JSON.
 *
 * Exported so callers can inspect exactly what a hash covers; the format is
 * part of the hash's contract and must not change without changing every
 * hash.
 */
export function canonicalize(value: unknown): string {
  if (value === null || value === undefined) {
    // TOML has no null; reaching here means a caller passed non-TOML data.
    return 'null';
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'bigint') return value.toString();
  if (typeof value === 'number') return canonicalFloat(value);
  if (value instanceof TomlDate) return tagged('$datetime', value.toISOString());
  if (value instanceof Date) return tagged('$datetime', value.toISOString());
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (typeof value === 'object') {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort(compareCodePoints);
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalize(record[key])}`).join(',')}}`;
  }
  throw new TypeError(`Cannot canonicalize a value of type ${typeof value}`);
}

/**
 * A TOML float, always spelled so it cannot be mistaken for an integer.
 * `-0` keeps its sign: TOML distinguishes `-0.0` from `0.0`.
 */
function canonicalFloat(value: number): string {
  if (Number.isNaN(value)) return tagged('$float', 'nan');
  if (value === Infinity) return tagged('$float', '+inf');
  if (value === -Infinity) return tagged('$float', '-inf');
  if (Object.is(value, -0)) return '-0.0';
  const text = String(value);
  return /[.eE]/.test(text) ? text : `${text}.0`;
}

function tagged(tag: string, value: string): string {
  return `{${JSON.stringify(tag)}:${JSON.stringify(value)}}`;
}

/**
 * Orders keys by Unicode code point rather than by UTF-16 unit, so a key
 * outside the BMP sorts the same way in every implementation that follows the
 * canonical JSON convention.
 */
function compareCodePoints(a: string, b: string): number {
  const left = [...a];
  const right = [...b];
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index++) {
    const difference = (left[index]?.codePointAt(0) ?? 0) - (right[index]?.codePointAt(0) ?? 0);
    if (difference !== 0) return difference;
  }
  return left.length - right.length;
}

/** The SHA-256 of a canonical JSON string, as lower-case hex. */
export function hashCanonical(canonical: string): string {
  return bytesToHex(sha256(new TextEncoder().encode(canonical)));
}

/**
 * Parses `source` and returns the hash of its semantic content. Invalid TOML
 * is reported rather than hashed: a file that does not parse has no semantic
 * content to approve.
 */
export function semanticHash(source: string): SemanticHashResult {
  let data: unknown;
  try {
    data = parse(source, { integersAsBigInt: true });
  } catch (error) {
    if (error instanceof TomlError) {
      return { ok: false, error: error.message, line: error.line, column: error.column };
    }
    return { ok: false, error: error instanceof Error ? error.message : String(error) };
  }
  const canonical = canonicalize(data);
  return { ok: true, hash: hashCanonical(canonical), canonical };
}

/** True when two sources declare the same data, however they are formatted. */
export function semanticallyEqual(left: string, right: string): boolean {
  const a = semanticHash(left);
  const b = semanticHash(right);
  return a.ok && b.ok && a.hash === b.hash;
}
