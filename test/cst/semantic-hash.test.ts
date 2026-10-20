import { describe, expect, it } from 'vitest';
import {
  canonicalize,
  hashCanonical,
  semanticHash,
  semanticallyEqual,
} from '../../src/cst/semantic-hash.js';

const COMPACT = `VERSION="2.0.0"
NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"
ACCOUNTS=["GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7"]
[DOCUMENTATION]
ORG_NAME="Example Anchor"
ORG_URL="https://example.com"
[[CURRENCIES]]
code="USDC"
issuer="GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7"
display_decimals=2
`;

// Same data: reordered keys and tables, different quoting, comments, blank
// lines, and inline-table / dotted-key spellings.
const REFORMATTED = `# Stellar info file for example.com
NETWORK_PASSPHRASE = 'Public Global Stellar Network ; September 2015'

VERSION    =    "2.0.0"   # bumped on every release


ACCOUNTS = [
  # the distribution account
  "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7",
]

[[CURRENCIES]]
display_decimals = 2
issuer = "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7"
code = 'USDC'

[DOCUMENTATION]
ORG_URL = "https://example.com"
  ORG_NAME = "Example Anchor"
`;

describe('semanticHash', () => {
  it('produces identical hashes for identical data with different whitespace and comments', () => {
    const left = semanticHash(COMPACT);
    const right = semanticHash(REFORMATTED);
    expect(left.ok && right.ok).toBe(true);
    if (!left.ok || !right.ok) return;
    expect(left.hash).toMatch(/^[0-9a-f]{64}$/);
    expect(right.hash).toBe(left.hash);
    expect(right.canonical).toBe(left.canonical);
    expect(semanticallyEqual(COMPACT, REFORMATTED)).toBe(true);
  });

  it('changes when a single value changes', () => {
    const changed = REFORMATTED.replace('display_decimals = 2', 'display_decimals = 7');
    expect(semanticallyEqual(COMPACT, changed)).toBe(false);
  });

  it('keeps integers, floats, strings, and dates apart', () => {
    const integer = semanticHash('a = 1');
    const float = semanticHash('a = 1.0');
    const text = semanticHash('a = "1"');
    expect(new Set([integer, float, text].map((r) => (r.ok ? r.hash : r.error))).size).toBe(3);

    const date = semanticHash('a = 1979-05-27T07:32:00Z');
    const dateString = semanticHash('a = "1979-05-27T07:32:00.000Z"');
    expect(date.ok && dateString.ok && date.hash !== dateString.hash).toBe(true);
  });

  it('treats equivalent TOML spellings of the same table as equal', () => {
    expect(semanticallyEqual('[a]\nb = 1\nc = 2', 'a = { c = 2, b = 1 }')).toBe(true);
    expect(semanticallyEqual('a.b = 1', '[a]\nb = 1')).toBe(true);
    expect(semanticallyEqual('n = 0x10', 'n = 16')).toBe(true);
  });

  it('serialises canonical JSON with sorted keys and tagged non-JSON values', () => {
    expect(canonicalize({ b: 1n, a: [1.5, 2.0, 'x'], c: true })).toBe(
      '{"a":[1.5,2.0,"x"],"b":1,"c":true}',
    );
    expect(canonicalize({ x: Number.NaN, y: -Infinity, z: -0 })).toBe(
      '{"x":{"$float":"nan"},"y":{"$float":"-inf"},"z":-0.0}',
    );
  });

  it('is deterministic and matches a SHA-256 of the canonical form', () => {
    const first = semanticHash(COMPACT);
    const second = semanticHash(COMPACT);
    expect(first).toEqual(second);
    if (first.ok) expect(hashCanonical(first.canonical)).toBe(first.hash);
  });

  it('reports invalid TOML with a position instead of hashing it', () => {
    const result = semanticHash('VERSION = \n[broken');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.line).toBeGreaterThan(0);
  });
});
