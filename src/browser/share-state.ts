/**
 * Playground URL state encoder and share-link generator (issue #372).
 *
 * Debugging a `stellar.toml` in a forum thread means pasting the file, losing
 * its indentation, and re-typing which rules were switched off. The state one
 * playground session holds — the text, the domain it came from, the severity
 * overrides, and `--strict` — fits in a URL fragment once compressed, so a
 * single click produces a link that reopens the session exactly as it was.
 *
 * The fragment is the right place for it: whatever follows `#` is never sent to
 * a server, so the file here does not pass through a proxy log or an access
 * review on its way to the person who can read it.
 *
 * Wire format, after the `#state=` prefix:
 *
 * ```text
 * <mode><codec>.<checksum>.<base64url(payload)>
 *   mode     's' an inline snippet, 'u' a domain to fetch on load
 *   codec    'd' DEFLATE, 'p' stored — the engine had no CompressionStream
 *   checksum 8 hex characters of SHA-256 over the uncompressed payload, or '0'
 *            when the engine offered no digest
 * ```
 *
 * Nothing is added to `dependencies`, per CONTRIBUTING's "no new runtime
 * dependencies without discussion" and the `test/package.test.ts` guard that
 * enforces it. DEFLATE comes from the Web Compression API
 * (`CompressionStream('deflate')`: Chromium 80, Firefox 113, Safari 16.4),
 * SHA-256 from `crypto.subtle`, and base64url is packed here rather than
 * borrowed, because `node:buffer` — which would make this trivial — is exactly
 * what the browser bundle shims to a throwing stub.
 *
 * Two properties are worth stating plainly rather than glossing over:
 *
 * - **Length.** A fragment survives about 2,000 characters in every client a
 *   share link realistically passes through. DEFLATE reaches roughly half the
 *   source size and base64url then adds a third of that back, so an inline
 *   snippet fits up to around 2 KB of TOML — which covers the broken excerpt
 *   these links exist to share, and not a complete anchor file. {@link
 *   encodeShareLink} measures the result instead of emitting a link a client
 *   silently truncates, and falls back to domain mode when the session names a
 *   domain: twenty characters for a hostname beats twenty times that for the
 *   text it serves.
 * - **Secrecy.** A fragment is not a secret. Whoever holds the link holds the
 *   file, and the checksum proves nobody altered it in transit without hiding
 *   anything from them. Say so in the UI when a file might carry credentials.
 */
import type { RuleOverrides } from '../types.js';

/** The hash key the playground reads and writes. */
export const SHARE_STATE_KEY = 'state';

/**
 * The length budget a share link is measured against.
 *
 * 2,000 characters is what every browser, terminal, and chat client is known to
 * keep intact — not a limit any of them documents as a promise.
 */
export const MAX_SHARE_URL_LENGTH = 2_000;

/** Whether a link carries the text itself or a domain to fetch it from. */
export type ShareMode = 'source' | 'domain';

/** The session state a share link carries. */
export interface ShareState {
  /** The `stellar.toml` text, as typed. Present for {@link ShareMode} `'source'`. */
  source?: string;
  /** Domain to re-fetch on load. Used when {@link source} is absent. */
  domain?: string;
  /** Severity overrides active in the shared session. */
  rules?: RuleOverrides;
  /** Whether warnings were being treated as errors. */
  strict?: boolean;
}

/** What an {@link encodeShareLink} call produced, and what it had to give up. */
export interface ShareLink {
  /** The fragment on its own, e.g. `#state=sd.1a2b3c4d.e39A…`. */
  hash: string;
  /** The page URL with {@link hash} appended. */
  url: string;
  /** Characters in {@link url}. */
  chars: number;
  /** Whether {@link chars} stays within the budget. */
  fits: boolean;
  mode: ShareMode;
  /** `false` when the engine has no `CompressionStream`, so the payload was stored. */
  compressed: boolean;
  /** The checksum, or absent when the engine had no digest to offer. */
  checksum?: string;
  /**
   * Which rung of the fallback ladder produced this link.
   *
   * `'none'` encoded the state whole. `'flags-dropped'` left the overrides and
   * `--strict` out so the text could stay. `'domain-only'` replaced the inline
   * text with its domain. `'over-budget'` means nothing further could be
   * dropped and the link is still too long — {@link url} is returned anyway,
   * because an honest long link beats a truncated one that looks fine.
   */
  degraded: 'none' | 'flags-dropped' | 'domain-only' | 'over-budget';
}

/** The outcome of a {@link decodeShareLink} call. */
export type ShareDecode =
  | { status: 'absent' }
  /** `verified` is `false` when the link carried no checksum to check. */
  | { status: 'ok'; state: ShareState; verified: boolean }
  | { status: 'invalid'; reason: string };

/** A compressor reports whether it actually deflated, so the codec tag tells the truth. */
export type ShareCompressor = (
  bytes: Uint8Array,
) => Promise<{ bytes: Uint8Array; deflated: boolean }>;

/** Reverses a {@link ShareCompressor} for the given codec tag. */
export type ShareDecompressor = (bytes: Uint8Array, deflated: boolean) => Promise<Uint8Array>;

/** Truncated SHA-256 of the uncompressed payload, or `undefined` when unavailable. */
export type ShareDigest = (bytes: Uint8Array) => Promise<string | undefined>;

export interface ShareStateOptions {
  /** Budget for {@link ShareLink.fits}. Defaults to {@link MAX_SHARE_URL_LENGTH}. */
  maxLength?: number;
  /** Page URL the fragment is appended to. Defaults to `https://localhost/#`. */
  pageUrl?: string;
  /** Replaces the compressor — for tests, and for embedders without the API. */
  compress?: ShareCompressor;
  /** Replaces the decompressor. */
  decompress?: ShareDecompressor;
  /** Replaces the digest. Return `undefined` to produce an unsigned link. */
  digest?: ShareDigest;
}

const BASE64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/** Reverse lookup for {@link BASE64URL_ALPHABET}, built once at module load. */
const BASE64URL_VALUES: Record<string, number> = Object.fromEntries(
  [...BASE64URL_ALPHABET].map((character, index) => [character, index]),
);

/**
 * Packs bytes into base64url without `btoa` or `Buffer`.
 *
 * `Buffer` is what the browser bundle shims to a throwing stub, and `btoa`
 * wants a binary string rather than the bytes in hand. Three bytes become four
 * characters; a trailing group is simply shorter, since a URL has no room for
 * `=` padding and no use for it.
 */
export function toBase64Url(bytes: Uint8Array): string {
  let out = '';
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      out += BASE64URL_ALPHABET[(buffer >> bits) & 63];
    }
  }
  if (bits > 0) out += BASE64URL_ALPHABET[(buffer << (6 - bits)) & 63];
  return out;
}

/** Reverses {@link toBase64Url}; `undefined` when the string is not base64url. */
export function fromBase64Url(value: string): Uint8Array | undefined {
  // A 1-character remainder would encode 6 bits with nowhere to go.
  if (value.length % 4 === 1) return undefined;
  const out = new Uint8Array(Math.floor((value.length * 6) / 8));
  let buffer = 0;
  let bits = 0;
  let written = 0;
  for (const character of value) {
    const sextet = BASE64URL_VALUES[character];
    if (sextet === undefined) return undefined;
    buffer = (buffer << 6) | sextet;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[written] = (buffer >> bits) & 255;
      written += 1;
    }
  }
  return out;
}

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

/** Drains a `ReadableStream` of byte chunks into one array. */
async function readStream(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value === undefined) continue;
    chunks.push(value);
    total += value.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

/** The halves of a compression transform, as the Web API exposes them. */
interface ByteTransformer {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<BufferSource>;
}

/**
 * Takes one chunk and closes, then waits for the pipe to drain.
 *
 * `writer.close()` alone would resolve before a rejected `write()` had been
 * reported, so an engine that refused the chunk would surface as a
 * `writer.closed` rejection nobody classified — an unhandled rejection that
 * vitest counts as a failed test. Awaiting the write first keeps both failures
 * inside this call.
 */
async function writeAll(
  writer: WritableStreamDefaultWriter<BufferSource>,
  bytes: Uint8Array<ArrayBuffer>,
): Promise<void> {
  try {
    await writer.write(bytes);
  } finally {
    await writer.close().catch(() => undefined);
  }
}

/**
 * Pushes bytes through a transform and collects the result.
 *
 * `pipeThrough` would be the one-line version, but `CompressionStream.writable`
 * is typed to accept any `BufferSource` rather than `Uint8Array` specifically,
 * so the generic does not line up and the pair has to be driven by hand. The
 * read is started before the write so a large file meets backpressure the way
 * the API intends instead of buffering twice.
 */
async function transformBytes(
  bytes: Uint8Array,
  transformer: ByteTransformer,
): Promise<Uint8Array> {
  const reading = readStream(transformer.readable);
  const writer = transformer.writable.getWriter();
  // A view over a fresh buffer: the transform's `write` is typed to an
  // `ArrayBuffer`-backed view, and a caller's slice may sit on shared memory.
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  await writeAll(writer, copy);
  return reading;
}

/**
 * The engine's DEFLATE, or the bytes unchanged when it has none.
 *
 * Safari before 16.4 and Firefox before 113 are the engines still without the
 * API. They get a stored payload — larger, tagged `'p'` on the wire, and
 * readable by every engine, so the fallback costs length rather than reach.
 */
export const deflateCompress: ShareCompressor = async (bytes) => {
  if (typeof CompressionStream !== 'function') return { bytes, deflated: false };
  return {
    bytes: await transformBytes(bytes, new CompressionStream('deflate')),
    deflated: true,
  };
};

export const inflateDecompress: ShareDecompressor = async (bytes, deflated) => {
  if (!deflated) return bytes;
  if (typeof DecompressionStream !== 'function') {
    throw new Error('this browser has no DecompressionStream to read a deflated share link');
  }
  return transformBytes(bytes, new DecompressionStream('deflate'));
};

/**
 * First four bytes of SHA-256 as hex, or `undefined` with no digest available.
 *
 * `crypto.subtle` is absent outright in an insecure context, so a playground
 * served over plain HTTP produces an unsigned link instead of throwing; {@link
 * decodeShareLink} then reports `verified: false` rather than claiming a check
 * it never ran. Four bytes is 1 in 4 billion — ample to notice a URL shortener
 * or a copy through a terminal that dropped a character, and not a claim of
 * authenticity.
 */
export const sha256Digest: ShareDigest = async (bytes) => {
  const subtle = globalThis.crypto?.subtle;
  if (subtle === undefined) return undefined;
  // `digest` wants a view over a real `ArrayBuffer`, and a caller may hold a
  // view onto shared or offset memory, so the bytes are copied forward.
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  const digest = await subtle.digest('SHA-256', copy);
  return [...new Uint8Array(digest).subarray(0, 4)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
};

/** `domain` mode only when there is no text to carry and a hostname to name. */
function modeOf(state: ShareState): ShareMode {
  return state.source === undefined && state.domain !== undefined ? 'domain' : 'source';
}

/** The lint flags, minus the ones nobody set. */
function flagsOf(state: ShareState): Pick<ShareState, 'rules' | 'strict'> {
  const flags: Pick<ShareState, 'rules' | 'strict'> = {};
  if (state.rules !== undefined && Object.keys(state.rules).length > 0) flags.rules = state.rules;
  if (state.strict === true) flags.strict = true;
  return flags;
}

/** Serialises the state, omitting the keys that hold nothing. */
function envelopeOf(state: ShareState): string {
  const envelope: Record<string, unknown> =
    modeOf(state) === 'domain' ? { domain: state.domain } : { source: state.source ?? '' };
  const flags = flagsOf(state);
  if (flags.rules !== undefined) envelope.rules = flags.rules;
  if (flags.strict === true) envelope.strict = true;
  return JSON.stringify(envelope);
}

/** Builds the `#state=…` fragment for one candidate state. */
async function pack(
  state: ShareState,
  options: ShareStateOptions,
): Promise<{ hash: string; checksum?: string; compressed: boolean }> {
  const plain = textEncoder.encode(envelopeOf(state));
  const compress = options.compress ?? deflateCompress;
  const payload = await compress(plain);
  const checksum = await (options.digest ?? sha256Digest)(plain);
  const head = `${modeOf(state) === 'domain' ? 'u' : 's'}${payload.deflated ? 'd' : 'p'}`;
  const value = `${head}.${checksum ?? '0'}.${toBase64Url(payload.bytes)}`;
  return {
    hash: `#${SHARE_STATE_KEY}=${value}`,
    ...(checksum === undefined ? {} : { checksum }),
    compressed: payload.deflated,
  };
}

/** Joins a page URL and a fragment, replacing any fragment already present. */
function urlFor(pageUrl: string, hash: string): string {
  const bare = pageUrl.split('#')[0] as string;
  return `${bare}${hash}`;
}

async function linkFor(
  state: ShareState,
  degraded: ShareLink['degraded'],
  pageUrl: string,
  maxLength: number,
  options: ShareStateOptions,
): Promise<ShareLink> {
  const packed = await pack(state, options);
  const url = urlFor(pageUrl, packed.hash);
  return {
    hash: packed.hash,
    url,
    chars: url.length,
    fits: url.length <= maxLength,
    mode: modeOf(state),
    compressed: packed.compressed,
    ...(packed.checksum === undefined ? {} : { checksum: packed.checksum }),
    degraded,
  };
}

/**
 * Encodes playground state as a share link.
 *
 * The ladder is deliberately conservative, and always reports the rung it
 * landed on: inline text with the flags, then inline text alone, then the
 * domain with the flags, then the domain alone. If none of those fit, the
 * result is the full state with `fits: false` and `degraded: 'over-budget'`,
 * because the length a caller has to explain is the length of the file the user
 * meant to share, not of the compromise that also failed.
 */
export async function encodeShareLink(
  state: ShareState,
  options: ShareStateOptions = {},
): Promise<ShareLink> {
  const maxLength = options.maxLength ?? MAX_SHARE_URL_LENGTH;
  const pageUrl = options.pageUrl ?? 'https://localhost/';
  const flags = flagsOf(state);

  const ladder: { state: ShareState; degraded: ShareLink['degraded'] }[] = [];
  if (modeOf(state) === 'domain') {
    ladder.push({ state, degraded: 'none' });
  } else {
    ladder.push({ state, degraded: 'none' });
    ladder.push({ state: { source: state.source }, degraded: 'flags-dropped' });
    if (state.domain !== undefined) {
      ladder.push({ state: { domain: state.domain, ...flags }, degraded: 'domain-only' });
      ladder.push({ state: { domain: state.domain }, degraded: 'domain-only' });
    }
  }

  const links: ShareLink[] = [];
  for (const rung of ladder) {
    const link = await linkFor(rung.state, rung.degraded, pageUrl, maxLength, options);
    if (link.fits) return link;
    links.push(link);
  }

  const widest = links.reduce((a, b) => (b.chars > a.chars ? b : a));
  return { ...widest, fits: false, degraded: 'over-budget' };
}

/**
 * Decodes a `#state=` fragment back into playground state.
 *
 * A malformed fragment is reported, never thrown: a link that came through a
 * URL shortener which mangled one character is common enough that the page has
 * to load and say "this link is corrupt" rather than sit there with a blank
 * editor and no explanation.
 */
export async function decodeShareLink(
  fragment: string,
  options: ShareStateOptions = {},
): Promise<ShareDecode> {
  const raw = fragment.startsWith('#') ? fragment.slice(1) : fragment;
  const marker = `${SHARE_STATE_KEY}=`;
  const start = raw.indexOf(marker);
  if (start === -1) return { status: 'absent' };
  const value = raw.slice(start + marker.length).split('&')[0] as string;
  if (value.length === 0) return { status: 'absent' };

  const parts = value.split('.');
  if (parts.length !== 3) {
    return { status: 'invalid', reason: 'expected <mode><codec>.<checksum>.<payload>' };
  }
  const [head, checksum, payload] = parts as [string, string, string];
  if (head.length !== 2 || !'su'.includes(head[0] as string) || !'dp'.includes(head[1] as string)) {
    return { status: 'invalid', reason: `unknown mode or codec in "${head}"` };
  }
  const bytes = fromBase64Url(payload);
  if (bytes === undefined) return { status: 'invalid', reason: 'payload is not base64url' };

  let plain: Uint8Array;
  try {
    plain = await (options.decompress ?? inflateDecompress)(bytes, head[1] === 'd');
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    // A `DecompressionStream` that meets bytes which are not DEFLATE rejects
    // with an empty message, so name the failure here rather than showing the
    // reader a sentence that ends in a colon.
    return {
      status: 'invalid',
      reason: `could not inflate: ${detail === '' ? 'the payload is not valid DEFLATE' : detail}`,
    };
  }
  if (plain.length === 0) return { status: 'invalid', reason: 'payload inflated to nothing' };

  const expected = await (options.digest ?? sha256Digest)(plain);
  if (checksum !== '0' && expected !== undefined && checksum !== expected) {
    return {
      status: 'invalid',
      reason: `checksum mismatch: link says ${checksum}, payload is ${expected}`,
    };
  }

  let envelope: Record<string, unknown>;
  try {
    envelope = JSON.parse(textDecoder.decode(plain)) as Record<string, unknown>;
  } catch {
    return { status: 'invalid', reason: 'payload is not JSON' };
  }

  const state: ShareState = {};
  if (head[0] === 'u') {
    if (typeof envelope.domain !== 'string') {
      return { status: 'invalid', reason: 'domain link without a domain' };
    }
    state.domain = envelope.domain;
  } else if (typeof envelope.source === 'string') {
    state.source = envelope.source;
  } else {
    return { status: 'invalid', reason: 'snippet link without a source' };
  }
  if (typeof envelope.domain === 'string' && head[0] === 's') state.domain = envelope.domain;
  const rules = envelope.rules;
  if (typeof rules === 'object' && rules !== null && !Array.isArray(rules)) {
    state.rules = rules as RuleOverrides;
  }
  if (envelope.strict === true) state.strict = true;

  return { status: 'ok', state, verified: checksum !== '0' };
}

/** Default label for {@link toMarkdownLink}. */
export const SHARE_LINK_LABEL = 'Open this stellar.toml in the playground';

/**
 * The markdown form a forum reply takes.
 *
 * `[label](url)` is the shortened link the issue asks for: it reads as a
 * sentence in Discord or a README while still carrying the whole session, which
 * is the point — that is exactly where these links get posted.
 */
export function toMarkdownLink(link: ShareLink, label = SHARE_LINK_LABEL): string {
  return `[${label}](${link.url})`;
}

/**
 * The one-line notice a share button shows beside the link.
 *
 * Empty when the link is whole and fits; otherwise it says what changed, because
 * a link that quietly dropped the rule overrides teaches the recipient that the
 * file is clean when the sender's run said otherwise.
 */
export function shareLinkNotice(link: ShareLink, maxLength = MAX_SHARE_URL_LENGTH): string {
  if (link.degraded === 'none' && link.fits) {
    return link.checksum === undefined
      ? `Share link is ${link.chars} characters. This page has no crypto.subtle, so nothing checks it on arrival.`
      : '';
  }
  if (link.degraded === 'flags-dropped') {
    return `Share link fits in ${link.chars} characters by dropping the rule overrides and --strict — mention them in the post.`;
  }
  if (link.degraded === 'domain-only') {
    return `Share link fits in ${link.chars} characters by carrying the domain only; the playground re-fetches the file on load.`;
  }
  if (link.fits) return `Share link is ${link.chars} characters.`;
  return `Share link is ${link.chars} characters, over the ${maxLength}-character budget most clients keep intact. Paste the file instead, or share its domain with --domain.`;
}
