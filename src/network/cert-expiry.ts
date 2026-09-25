/**
 * TLS certificate expiration auditing for network mode.
 *
 * Anchors must keep valid certificates on every endpoint they declare: the
 * moment one expires, wallets terminate the connection and the anchor's
 * services stop working — often quietly, and always at the worst time. The
 * session audit in `security.ts` judges how the host negotiates a connection;
 * this module judges whether the certificate behind it is still good, reading
 * `valid_to` from the peer certificate of every declared HTTPS endpoint.
 *
 * Runs only under opt-in `--check-network`. A host that cannot be reached, or
 * that completes no handshake, yields nothing rather than a finding: reachability
 * is other checks' job, and an unobservable certificate is not evidence of an
 * expired one.
 */
import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';
import { HTTPS_ENDPOINT_FIELDS, TLS_SECURITY_DOC_URL } from '../spec.js';
import { isString } from '../predicates.js';

/** How long to wait for a handshake before abandoning the audit. */
const PROBE_TIMEOUT_MS = 5_000;

/** Warn once a certificate has fewer than this many days left. */
const WARN_WITHIN_DAYS = 30;

const MS_PER_DAY = 86_400_000;

/** Opens a TLS connection and returns the peer certificate's expiry date. Never rejects. */
export type CertExpiryProbe = (host: string, port: number) => Promise<Date | null>;

/** Endpoint fields worth presenting a certificate for, plus Horizon. */
const CERT_CHECKED_FIELDS: readonly string[] = [...HTTPS_ENDPOINT_FIELDS, 'HORIZON_URL'];

const EXPIRING_RULE = 'security/tls-cert-expiring-soon';
const EXPIRED_RULE = 'security/tls-cert-expired';

/**
 * The rule objects behind the certificate-expiry audit.
 *
 * Like the other network-bound rules, `run()` is empty: the diagnostics are
 * emitted by the async {@link checkCertExpiry}, and these entries exist so
 * `--list-rules` and `--off`/`--warn`/`--error` know the ids.
 */
export const certExpiryRules: Rule[] = [
  {
    id: EXPIRED_RULE,
    category: 'network',
    severity: 'error',
    description: 'A declared endpoint must not serve a TLS certificate that has expired',
    run() {},
  },
  {
    id: EXPIRING_RULE,
    category: 'network',
    severity: 'warning',
    description:
      'A declared endpoint should renew its TLS certificate before it expires within 30 days',
    run() {},
  },
];

/** The HTTPS endpoints the file declares, deduplicated by host and port. */
function endpointsOf(
  doc: Record<string, unknown>,
): { host: string; port: number; field: string }[] {
  const endpoints: { host: string; port: number; field: string }[] = [];
  const seen = new Set<string>();

  for (const field of CERT_CHECKED_FIELDS) {
    const value = doc[field];
    if (!isString(value)) continue;

    let url: URL;
    try {
      url = new URL(value);
    } catch {
      // Not a URL at all — the offline rules report that with a position.
      continue;
    }
    if (url.protocol !== 'https:') continue;

    const port = url.port === '' ? 443 : Number(url.port);
    const key = `${url.hostname}:${port}`;
    if (seen.has(key)) continue;
    seen.add(key);
    endpoints.push({ host: url.hostname, port, field });
  }

  return endpoints;
}

/** Severity for one of this module's rules, or `undefined` when switched off. */
function severityFor(
  rule: string,
  fallback: Severity,
  rules: RuleOverrides | undefined,
): Severity | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' || override === 'info'
    ? override
    : fallback;
}

/**
 * The default probe: one short TLS handshake per host, reading the expiry date
 * off the peer certificate.
 *
 * `node:tls` is loaded lazily for the same reason `tls.ts` loads it that way:
 * this module sits in the shared rule registry the browser bundle walks, and a
 * static import would drag a Node built-in into every browser build. A browser
 * (or any failed handshake) reports "not observed", never a guess.
 */
const handshakeProbe: CertExpiryProbe = async (host, port) => {
  const tls = await import('node:tls').catch(() => null);
  if (tls === null) return null;

  return new Promise((resolve) => {
    let settled = false;
    const socket = tls.connect({ host, port, servername: host });

    const settle = (value: Date | null): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(value);
    };

    socket.setTimeout(PROBE_TIMEOUT_MS);

    socket.once('secureConnect', () => {
      const certificate = socket.getPeerCertificate();
      const validTo = certificate?.valid_to;
      const expiry = typeof validTo === 'string' ? new Date(validTo) : undefined;
      settle(expiry !== undefined && !Number.isNaN(expiry.getTime()) ? expiry : null);
    });

    socket.once('timeout', () => settle(null));
    socket.once('error', () => settle(null));
  });
};

/**
 * Audits the TLS certificate expiry of every HTTPS endpoint the file declares.
 *
 * A certificate already past its expiration date is a `security/tls-cert-expired`
 * error; one with fewer than 30 days left is a `security/tls-cert-expiring-soon`
 * warning, so a renewal lands on a calendar rather than on an outage. Hosts
 * that share an endpoint are probed once, and an unobservable certificate is
 * skipped rather than reported.
 */
export async function checkCertExpiry(
  doc: Record<string, unknown>,
  options: {
    rules?: RuleOverrides;
    probe?: CertExpiryProbe;
    /** Evaluated once, so every endpoint is judged against the same clock. */
    now?: Date;
  } = {},
): Promise<Diagnostic[]> {
  const endpoints = endpointsOf(doc);
  if (endpoints.length === 0) return [];

  // Nothing to report when every rule here is off — and, more importantly,
  // no reason to open sockets for it.
  const expiredSeverity = severityFor(EXPIRED_RULE, 'error', options.rules);
  const expiringSeverity = severityFor(EXPIRING_RULE, 'warning', options.rules);
  if (expiredSeverity === undefined && expiringSeverity === undefined) return [];

  const probe = options.probe ?? handshakeProbe;
  const now = options.now ?? new Date();
  const diagnostics: Diagnostic[] = [];

  for (const endpoint of endpoints) {
    const expiry = await probe(endpoint.host, endpoint.port);
    if (expiry === null) continue;

    const remaining = expiry.getTime() - now.getTime();

    if (remaining <= 0) {
      if (expiredSeverity !== undefined) {
        diagnostics.push({
          rule: EXPIRED_RULE,
          severity: expiredSeverity,
          category: 'network',
          message: `TLS certificate for ${endpoint.host} expired on ${expiry.toISOString().slice(0, 10)}`,
          path: endpoint.field,
          helpUri: TLS_SECURITY_DOC_URL,
          suggestion:
            'Renew and redeploy the certificate now — wallets and exchanges have already stopped connecting',
        });
      }
      continue;
    }

    if (remaining < WARN_WITHIN_DAYS * MS_PER_DAY && expiringSeverity !== undefined) {
      const days = Math.ceil(remaining / MS_PER_DAY);
      diagnostics.push({
        rule: EXPIRING_RULE,
        severity: expiringSeverity,
        category: 'network',
        message: `TLS certificate for ${endpoint.host} expires in ${days} day${days === 1 ? '' : 's'}, on ${expiry.toISOString().slice(0, 10)}`,
        path: endpoint.field,
        helpUri: TLS_SECURITY_DOC_URL,
        suggestion:
          'Renew the certificate before it expires — an expired endpoint breaks every client at once',
      });
    }
  }

  return diagnostics;
}
