import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  decodeShareLink,
  deflateCompress,
  encodeShareLink,
  fromBase64Url,
  inflateDecompress,
  MAX_SHARE_URL_LENGTH,
  SHARE_STATE_KEY,
  shareLinkNotice,
  sha256Digest,
  toBase64Url,
  toMarkdownLink,
  type ShareState,
} from '../../src/browser/share-state.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string): string => readFileSync(join(here, '..', 'fixtures', name), 'utf8');

const VALID_TOML = fixture('valid.toml');
const SMALL_TOML = fixture('warnings-only.toml');

/** Payload characters only, so a size claim can be made about the encoding. */
function payloadChars(link: { hash: string }): number {
  return link.hash.length - `#${SHARE_STATE_KEY}=sd.`.length - 8 - 1;
}

/** An identity codec, for the tests that want the wire format without DEFLATE. */
const stored = {
  compress: async (bytes: Uint8Array) => ({ bytes, deflated: false }),
  decompress: async (bytes: Uint8Array) => bytes,
};

/** Overrides big enough that dropping them is what buys the room. */
const manyRules: ShareState['rules'] = Object.fromEntries(
  Array.from({ length: 60 }, (_, index) => [`validators/quorum-set-${index}`, 'warning' as const]),
);

describe('base64url (#372)', () => {
  it('round-trips every tail length and both byte extremes', () => {
    for (let length = 0; length < 10; length++) {
      const bytes = new Uint8Array(length);
      for (let i = 0; i < length; i++) bytes[i] = (i * 61 + 200) % 256;
      expect(fromBase64Url(toBase64Url(bytes))).toEqual(bytes);
    }
  });

  it('emits only URL-safe characters and no padding', () => {
    const bytes = new Uint8Array(Array.from({ length: 256 }, (_, i) => i));
    const encoded = toBase64Url(bytes);
    expect(encoded).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(encoded).not.toContain('=');
    expect(encoded).not.toContain('+');
    expect(encoded).not.toContain('/');
    expect(fromBase64Url(encoded)).toEqual(bytes);
  });

  it('maps the alphabet edges the way base64url does', () => {
    expect(toBase64Url(new Uint8Array([0, 0, 0]))).toBe('AAAA');
    // 255 is six set bits, so every group lands on index 63 — the last
    // character of this alphabet, where standard base64 puts a `/`.
    expect(toBase64Url(new Uint8Array([255, 255, 255]))).toBe('____');
    expect(toBase64Url(new Uint8Array([255]))).toBe('_w');
    expect(toBase64Url(new Uint8Array())).toBe('');
  });

  it('rejects a string that is not base64url', () => {
    expect(fromBase64Url('a')).toBeUndefined();
    expect(fromBase64Url('a+b')).toBeUndefined();
    expect(fromBase64Url('héllo')).toBeUndefined();
  });
});

describe('round-trip compression (#372)', () => {
  it('returns the state it was given, through real DEFLATE', async () => {
    const state: ShareState = {
      source: SMALL_TOML,
      rules: { 'general/version': 'off', 'security/tls-cert-expiring-soon': 'error' },
      strict: true,
    };
    const link = await encodeShareLink(state);

    expect(link.compressed).toBe(true);
    expect(link.hash.startsWith(`#${SHARE_STATE_KEY}=sd.`)).toBe(true);
    expect(await decodeShareLink(link.hash)).toEqual({ status: 'ok', state, verified: true });
  });

  it('compresses a full anchor file into fewer characters than the file holds', async () => {
    const link = await encodeShareLink({ source: VALID_TOML });
    // DEFLATE reaches about half the source and base64url adds a third back,
    // so the link still lands well under the raw text it replaced.
    expect(link.chars).toBeLessThan(VALID_TOML.length);
    expect(payloadChars(link)).toBeLessThan(VALID_TOML.length);
  });

  it('survives the characters a stellar.toml actually holds', async () => {
    const state: ShareState = {
      source: 'SIGNING_KEY = "GABCDEFGHIJKLMNOPQRSTUVWXYZ234567890ABCDEFGH"\n# ünïcode — 日本語\n',
    };
    const decoded = await decodeShareLink((await encodeShareLink(state)).hash);
    expect(decoded.status === 'ok' && decoded.state.source).toBe(state.source);
  });

  it('carries a stored payload when the caller has no compression to offer', async () => {
    const link = await encodeShareLink({ source: SMALL_TOML, strict: true }, stored);
    expect(link.compressed).toBe(false);
    expect(link.hash.startsWith(`#${SHARE_STATE_KEY}=sp.`)).toBe(true);

    const decoded = await decodeShareLink(link.hash, stored);
    expect(decoded.status).toBe('ok');
    expect(decoded.status === 'ok' && decoded.state.strict).toBe(true);
    expect(decoded.status === 'ok' && decoded.state.source).toBe(SMALL_TOML);
  });

  it('pairs the deflate tag with the deflate decoder', async () => {
    const link = await encodeShareLink({ source: VALID_TOML });
    const bytes = fromBase64Url(link.hash.split('.')[2] as string) as Uint8Array;
    const inflated = await inflateDecompress(bytes, true);
    expect((JSON.parse(new TextDecoder().decode(inflated)) as { source: string }).source).toBe(
      VALID_TOML,
    );
  });

  it('leaves a stored payload alone when inflating', async () => {
    const bytes = new Uint8Array([1, 2, 3]);
    expect(await inflateDecompress(bytes, false)).toBe(bytes);
  });
});

describe('url budget (#372)', () => {
  it('keeps a standard config under 2000 characters', async () => {
    const link = await encodeShareLink({
      source: SMALL_TOML,
      rules: { 'validators/duplicate-host': 'off' },
    });
    expect(link.fits).toBe(true);
    expect(link.degraded).toBe('none');
    expect(link.chars).toBeLessThan(MAX_SHARE_URL_LENGTH);
  });

  it('reports a file it cannot fit instead of truncating it', async () => {
    const link = await encodeShareLink({ source: VALID_TOML });
    expect(link.fits).toBe(false);
    expect(link.degraded).toBe('over-budget');
    expect(link.url.length).toBe(link.chars);
    // The whole text is still in there: the caller decides what to do about it.
    const decoded = await decodeShareLink(link.hash);
    expect(decoded.status === 'ok' && decoded.state.source).toBe(VALID_TOML);
  });

  it('drops the flags before it reaches for the domain', async () => {
    const withFlags = await encodeShareLink({ source: VALID_TOML, rules: manyRules });
    const withoutFlags = await encodeShareLink({ source: VALID_TOML });
    expect(withFlags.chars).toBeGreaterThan(withoutFlags.chars);

    const link = await encodeShareLink(
      { source: VALID_TOML, rules: manyRules, domain: 'anchor.example.com' },
      { maxLength: withoutFlags.chars },
    );
    expect(link.degraded).toBe('flags-dropped');
    expect(link.mode).toBe('source');
    expect(link.fits).toBe(true);
  });

  it('carries the domain with its flags when the text cannot stay inline', async () => {
    const link = await encodeShareLink(
      { source: VALID_TOML, domain: 'anchor.example.com', rules: { 'general/version': 'off' } },
      { maxLength: 200 },
    );
    expect(link.mode).toBe('domain');
    expect(link.degraded).toBe('domain-only');
    expect(link.fits).toBe(true);

    const decoded = await decodeShareLink(link.hash);
    expect(decoded.status).toBe('ok');
    expect(decoded.status === 'ok' && decoded.state.domain).toBe('anchor.example.com');
    expect(decoded.status === 'ok' && decoded.state.rules).toEqual({ 'general/version': 'off' });
    expect(decoded.status === 'ok' && decoded.state.source).toBeUndefined();
  });

  it('encodes a domain session in under 120 characters', async () => {
    const link = await encodeShareLink({ domain: 'anchor.example.com' });
    expect(link.mode).toBe('domain');
    expect(link.hash.startsWith(`#${SHARE_STATE_KEY}=ud.`)).toBe(true);
    expect(link.chars).toBeLessThan(120);
  });

  it('charges the page url against the budget, not just the payload', async () => {
    const page = `https://${'a'.repeat(300)}.example.com/playground`;
    const link = await encodeShareLink({ source: 'VERSION = "2.7.0"\n' }, { pageUrl: page });
    expect(link.url.startsWith(page)).toBe(true);
    expect(link.chars).toBe(page.length + link.hash.length);
    // The payload is a few dozen characters; the page it hangs off is what
    // pushes this over a tight budget.
    expect(link.fits).toBe(true);
    expect(
      (await encodeShareLink({ source: 'VERSION = "2.7.0"\n' }, { pageUrl: page, maxLength: 380 }))
        .fits,
    ).toBe(false);
    expect(
      (await encodeShareLink({ source: 'VERSION = "2.7.0"\n' }, { pageUrl: page, maxLength: 500 }))
        .fits,
    ).toBe(true);
  });
});

describe('tamper evidence (#372)', () => {
  it('rejects a payload whose checksum no longer matches', async () => {
    // Stored rather than deflated: one changed character then changes one
    // changed byte, instead of collapsing a compression stream.
    const link = await encodeShareLink({ source: 'VERSION = "2.7.0"\n' }, stored);
    const [head, checksum, payload] = link.hash
      .slice(1)
      .slice(SHARE_STATE_KEY.length + 1)
      .split('.');
    // The first character is always fully significant; a trailing one can carry
    // spare bits whose loss would leave the bytes, and the checksum, intact.
    const swapped = (payload![0] === 'A' ? 'B' : 'A') + payload!.slice(1);

    const decoded = await decodeShareLink(
      `#${SHARE_STATE_KEY}=${head}.${checksum}.${swapped}`,
      stored,
    );
    expect(decoded.status).toBe('invalid');
    expect(decoded.status === 'invalid' && decoded.reason).toContain('checksum mismatch');
  });

  it('accepts an unsigned link but says it was not verified', async () => {
    const unsigned = { ...stored, digest: async () => undefined };
    const link = await encodeShareLink({ source: 'VERSION = "2.7.0"\n' }, unsigned);
    expect(link.checksum).toBeUndefined();
    expect(link.hash).toContain('.0.');

    const decoded = await decodeShareLink(link.hash, unsigned);
    expect(decoded.status).toBe('ok');
    expect(decoded.status === 'ok' && decoded.verified).toBe(false);
  });

  it('digests to eight hex characters', async () => {
    expect(await sha256Digest(new Uint8Array([0]))).toMatch(/^[0-9a-f]{8}$/);
    const again = await sha256Digest(new Uint8Array([0]));
    expect(await sha256Digest(new Uint8Array([1]))).not.toBe(again);
  });

  it('reports a corrupt fragment rather than throwing', async () => {
    const cases: [string, 'absent' | 'invalid'][] = [
      ['', 'absent'],
      ['no-state-here', 'absent'],
      ['#state=', 'absent'],
      ['#state=sd.abc', 'invalid'],
      ['#state=xx.00000000.AAAA', 'invalid'],
      ['#state=sd.00000000.!!!!', 'invalid'],
      ['#state=sd.00000000.A', 'invalid'],
      ['#state=sd.00000000.AAAA', 'invalid'],
    ];
    for (const [fragment, status] of cases) {
      expect(await decodeShareLink(fragment), fragment).toMatchObject({ status });
    }
  });

  it('reads a real corrupt link as a corrupt link, with a reason worth reading', async () => {
    const link = await encodeShareLink({ source: 'VERSION = "2.7.0"\n' });
    const payload = link.hash.split('.')[2]!;
    const decoded = await decodeShareLink(
      `#${SHARE_STATE_KEY}=sd.00000000.${'A'.repeat(payload.length)}`,
    );
    expect(decoded.status).toBe('invalid');
    const reason = decoded.status === 'invalid' ? decoded.reason : '';
    // V8's `DecompressionStream` rejects with an empty message on Node 22/24
    // and with "unknown compression method" on Node 20, so the promise here is
    // that the sentence is complete, not which engine's words appear in it —
    // the playground notice interpolates this straight after a colon.
    expect(reason).toMatch(/^could not inflate: \S/);
    expect(reason.endsWith(': ')).toBe(false);
  });

  it('reads the state out of a full url, beside other hash parameters', async () => {
    const link = await encodeShareLink({ source: 'VERSION = "2.7.0"\n' });
    const url = link.url.replace('#', '#tab=diagnostics&');
    expect(await decodeShareLink(url)).toMatchObject({ status: 'ok' });
  });
});

describe('share text for a forum reply', () => {
  it('produces a markdown link with a readable label', async () => {
    const link = await encodeShareLink({ source: SMALL_TOML });
    expect(toMarkdownLink(link)).toMatch(
      /^\[Open this stellar\.toml in the playground\]\(https:\/\//,
    );
    expect(toMarkdownLink(link)).toContain(link.url);
    expect(toMarkdownLink(link, 'acme is broken')).toBe(`[acme is broken](${link.url})`);
  });

  it('stays silent only when the link is whole', async () => {
    expect(shareLinkNotice(await encodeShareLink({ source: SMALL_TOML }))).toBe('');
    expect(shareLinkNotice(await encodeShareLink({ source: VALID_TOML }))).toContain(
      'over the 2000-character budget',
    );
    const domainOnly = await encodeShareLink(
      { source: VALID_TOML, domain: 'anchor.example.com' },
      { maxLength: 200 },
    );
    expect(shareLinkNotice(domainOnly)).toContain('re-fetches the file on load');
  });

  it('says which flags had to be dropped to fit', async () => {
    const withoutFlags = await encodeShareLink({ source: VALID_TOML });
    const dropped = await encodeShareLink(
      { source: VALID_TOML, rules: manyRules, strict: true },
      { maxLength: withoutFlags.chars },
    );
    expect(dropped.degraded).toBe('flags-dropped');
    expect(shareLinkNotice(dropped)).toContain('rule overrides');
  });

  it('warns when a non-secure context could not sign the link', async () => {
    const link = await encodeShareLink(
      { source: 'VERSION = "2.7.0"\n' },
      { digest: async () => undefined },
    );
    expect(shareLinkNotice(link)).toContain('no crypto.subtle');
  });
});

describe('the compressor reports what it actually did', () => {
  it('inflates what it deflates, and says so', async () => {
    const bytes = new TextEncoder().encode(SMALL_TOML.repeat(3));
    const result = await deflateCompress(bytes);
    expect(result.deflated).toBe(true);
    expect(result.bytes.byteLength).toBeLessThan(bytes.byteLength);
    expect(await inflateDecompress(result.bytes, true)).toEqual(bytes);
  });
});
