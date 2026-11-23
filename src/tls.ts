/**
 * TLS session auditing for network mode.
 *
 * `--domain` already checks that a file is reachable over HTTPS, but a
 * reachable host can still be speaking TLS 1.0 or offering a CBC/RC4 suite.
 * Anchors sign SEP-10 challenges over that connection, so a deprecated
 * protocol or a weak suite is worth surfacing.
 *
 * Node's global `fetch` (undici) does not expose the socket it negotiated on,
 * so the session is measured with a short, separate handshake. This module is
 * never touched by offline linting.
 */
import type { TlsSession } from './types.js';
import { DEPRECATED_TLS_VERSIONS, WEAK_CIPHER_MARKERS } from './spec.js';

/** Opens a TLS connection and reports what was negotiated. Never rejects. */
export type TlsProbe = (host: string, port: number) => Promise<TlsSession>;

/** How long to wait for a handshake before abandoning the audit. */
const PROBE_TIMEOUT_MS = 5_000;

/** Returned whenever the session could not be observed. */
export const UNKNOWN_TLS_SESSION: TlsSession = { protocol: null, cipher: null };

/**
 * A whole-token match against the weak markers.
 *
 * Token boundaries matter: a substring test would flag a strong suite that
 * merely happened to contain a marker, and the cost of a false positive here
 * is an anchor chasing a non-problem. `3DES` is listed before `DES` so the
 * longer marker wins on a name like `_3DES_`.
 */
const WEAK_CIPHER_PATTERN = new RegExp(
  `(?:^|[^A-Za-z0-9])(?:${WEAK_CIPHER_MARKERS.join('|')})(?:[^A-Za-z0-9]|$)`,
  'i',
);

/** True for protocol versions RFC 8996 (and history) retired. */
export function isDeprecatedTlsVersion(protocol: string | null | undefined): boolean {
  if (typeof protocol !== 'string') return false;
  const normalized = protocol.trim().toLowerCase();
  return DEPRECATED_TLS_VERSIONS.some((version) => version.toLowerCase() === normalized);
}

/** True when a cipher suite name uses a known weak primitive. */
export function isWeakCipherSuite(name: string | null | undefined): boolean {
  if (typeof name !== 'string' || name.length === 0) return false;
  return WEAK_CIPHER_PATTERN.test(name);
}

/**
 * The first weak suite name in the session, if any.
 *
 * Both names are consulted: Node reports the OpenSSL name, which omits the mode
 * (`AES128-SHA256` is CBC) while the IANA `standardName` spells it out.
 */
export function weakCipherSuiteIn(session: TlsSession): string | undefined {
  for (const name of [session.cipher, session.cipherStandard]) {
    if (typeof name === 'string' && isWeakCipherSuite(name)) return name;
  }
  return undefined;
}

/**
 * Performs one handshake against `host` and returns the negotiated parameters.
 *
 * Certificate verification stays on: if the certificate is bad the run's own
 * fetch has already failed and reported it, so the audit simply yields nothing
 * rather than inventing a second, less useful diagnostic.
 */
export async function probeTls(host: string, port = 443): Promise<TlsSession> {
  // `node:tls` is loaded lazily on purpose. `lint.ts` imports this module, and
  // the browser entry point imports `lint.ts` — a static import here would drag
  // a Node built-in into every browser bundle, which is exactly the boundary
  // issue #105 exists to fix. A browser can never reach this call: it has no way
  // to observe a TLS session, so browser callers pass an explicit probe.
  const { connect } = await import('node:tls');

  return new Promise((resolve) => {
    let settled = false;

    const socket = connect({ host, port, servername: host });

    const settle = (session: TlsSession): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(session);
    };

    socket.setTimeout(PROBE_TIMEOUT_MS);

    socket.once('secureConnect', () => {
      const cipher = socket.getCipher();
      settle({
        protocol: socket.getProtocol(),
        cipher: cipher?.name ?? null,
        cipherStandard: cipher?.standardName ?? null,
      });
    });

    // A probe that cannot complete is not a finding. Reachability is the
    // fetch's job; this audit must never turn into a misleading error.
    socket.once('timeout', () => settle(UNKNOWN_TLS_SESSION));
    socket.once('error', () => settle(UNKNOWN_TLS_SESSION));
  });
}
