/**
 * TLS cipher suite and downgrade auditor.
 *
 * Runs under `audit-ciphers --domain <domain>`.
 *
 * Anchors sign SEP-10 challenges and move money over TLS, so the server must
 * refuse TLS 1.0/1.1 (RFC 8996), negotiate forward-secret (ECDHE/DHE) and AEAD
 * (GCM, CHACHA20-POLY1305, CCM) suites, and never fall back to RC4, 3DES or
 * CBC. Each protocol version is probed with a handshake pinned to that single
 * version, so a server that quietly accepts a legacy version is caught.
 *
 * Only native `node:tls` is used. The probe is injectable so tests never open
 * a socket.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { weakCipherSuiteIn } from '../tls.js';
import { errorMessage, severityFor } from '../protocols/verifierSupport.js';

const LEGACY_RULE = 'tlscipher/legacy-protocol-accepted';
const NO_MODERN_RULE = 'tlscipher/no-modern-protocol';
const NO_PFS_RULE = 'tlscipher/no-forward-secrecy';
const NO_AEAD_RULE = 'tlscipher/non-aead-cipher';
const WEAK_RULE = 'tlscipher/weak-cipher';
const UNREACHABLE_RULE = 'tlscipher/unreachable';

const SPEC = 'https://datatracker.ietf.org/doc/html/rfc8996';

export const TLS_VERSIONS = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'] as const;
export type TlsVersion = (typeof TLS_VERSIONS)[number];
const LEGACY: readonly TlsVersion[] = ['TLSv1', 'TLSv1.1'];

export type CipherGrade = 'A+' | 'A' | 'B' | 'F';

/** Outcome of one handshake pinned to one protocol version. */
export interface HandshakeResult {
  /** `rejected`: the server refused the version. `error`: no verdict (network, certificate). */
  status: 'accepted' | 'rejected' | 'error';
  cipher?: string;
  cipherStandard?: string;
  error?: string;
}

/** Performs one handshake restricted to `version`. Must never reject. */
export type HandshakeProbe = (
  host: string,
  port: number,
  version: TlsVersion,
) => Promise<HandshakeResult>;

export interface TlsCipherOptions {
  rules?: RuleOverrides;
  port?: number;
  timeoutMs?: number;
  probe?: HandshakeProbe;
}

export interface TlsCipherReport {
  host: string;
  /** `null` when the host could not be assessed. */
  grade: CipherGrade | null;
  versions: Record<string, HandshakeResult>;
}

export interface TlsCipherResult {
  diagnostics: Diagnostic[];
  report: TlsCipherReport;
}

/** TLS 1.3 suites are all ephemeral; below that the name must say ECDHE or DHE. */
export function hasForwardSecrecy(version: TlsVersion, cipher: string | undefined): boolean {
  if (version === 'TLSv1.3') return true;
  return cipher !== undefined && /(^|[-_])(ECDHE|DHE|EDH)([-_]|$)/i.test(cipher);
}

/** AEAD suites: GCM, CHACHA20-POLY1305 and CCM. CBC and RC4 are not. */
export function isAeadCipher(cipher: string | undefined): boolean {
  return cipher !== undefined && /GCM|CHACHA20[-_]POLY1305|CCM/i.test(cipher);
}

/** Default probe: a real handshake pinned to one version, torn down on every path. */
export const nodeTlsProbe =
  (timeoutMs = 5000): HandshakeProbe =>
  async (host, port, version) => {
    const { connect } = await import('node:tls');
    return new Promise<HandshakeResult>((resolve) => {
      let done = false;
      let socket: ReturnType<typeof connect> | undefined;
      const finish = (result: HandshakeResult): void => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        socket?.destroy();
        resolve(result);
      };
      const timer = setTimeout(() => finish({ status: 'error', error: 'timeout' }), timeoutMs);
      try {
        socket = connect({
          host,
          port,
          servername: host,
          minVersion: version,
          maxVersion: version,
        });
      } catch (error) {
        // The local OpenSSL may refuse to offer a retired version at all.
        finish({ status: 'error', error: errorMessage(error) });
        return;
      }
      socket.once('secureConnect', () => {
        const info = socket?.getCipher();
        finish({
          status: 'accepted',
          ...(info?.name !== undefined ? { cipher: info.name } : {}),
          ...(info?.standardName !== undefined ? { cipherStandard: info.standardName } : {}),
        });
      });
      socket.once('error', (error: NodeJS.ErrnoException) => {
        // An alert (handshake_failure, protocol_version) means the server said no;
        // anything else (DNS, refused, bad certificate) says nothing about versions.
        const alert = /alert|protocol version|handshake failure|wrong version/i.test(error.message);
        finish({ status: alert ? 'rejected' : 'error', error: error.message });
      });
    });
  };

export class TlsCipherSecurityAuditor {
  private readonly probe: HandshakeProbe;

  constructor(private readonly options: TlsCipherOptions = {}) {
    this.probe = options.probe ?? nodeTlsProbe(options.timeoutMs);
  }

  async audit(host: string): Promise<TlsCipherResult> {
    const diagnostics: Diagnostic[] = [];
    const push = (
      rule: string,
      fallback: 'error' | 'warning',
      message: string,
      suggestion: string,
    ): void => {
      const severity = severityFor(rule, fallback, this.options.rules);
      if (severity === undefined) return;
      diagnostics.push({
        rule,
        severity,
        category: 'network',
        message,
        path: host,
        helpUri: SPEC,
        suggestion,
      });
    };

    const port = this.options.port ?? 443;
    const versions: Record<string, HandshakeResult> = {};
    for (const version of TLS_VERSIONS) {
      versions[version] = await this.probe(host, port, version);
    }

    const modern = (['TLSv1.2', 'TLSv1.3'] as const).filter(
      (v) => versions[v]?.status === 'accepted',
    );
    const unknownModern = (['TLSv1.2', 'TLSv1.3'] as const).every(
      (v) => versions[v]?.status === 'error',
    );
    if (unknownModern) {
      push(
        UNREACHABLE_RULE,
        'warning',
        `${host}:${port} could not be assessed (${versions['TLSv1.3']?.error ?? 'no handshake'})`,
        'Make sure the host is reachable and serves a valid certificate.',
      );
      return { diagnostics, report: { host, grade: null, versions } };
    }

    let fail = false;
    let degraded = false;
    for (const version of LEGACY) {
      if (versions[version]?.status === 'accepted') {
        fail = true;
        push(
          LEGACY_RULE,
          'error',
          `${host} accepts ${version} handshakes`,
          'Disable TLS 1.0 and 1.1; support TLS 1.2 and 1.3 only.',
        );
      }
    }
    if (modern.length === 0) {
      fail = true;
      push(
        NO_MODERN_RULE,
        'error',
        `${host} negotiated neither TLS 1.2 nor TLS 1.3`,
        'Enable TLS 1.2 and TLS 1.3.',
      );
    }
    for (const version of modern) {
      const result = versions[version] as HandshakeResult;
      const name = result.cipherStandard ?? result.cipher;
      const label = `${version} ${name ?? 'unknown suite'}`;
      if (
        weakCipherSuiteIn({
          protocol: version,
          cipher: result.cipher ?? null,
          ...(result.cipherStandard ? { cipherStandard: result.cipherStandard } : {}),
        })
      ) {
        fail = true;
        push(
          WEAK_RULE,
          'error',
          `${host} negotiates a weak cipher (${label})`,
          'Remove RC4, 3DES, DES and export suites from the server cipher list.',
        );
        continue;
      }
      if (!hasForwardSecrecy(version, name)) {
        degraded = true;
        push(
          NO_PFS_RULE,
          'warning',
          `${host} negotiates a suite without forward secrecy (${label})`,
          'Prefer ECDHE key exchange so past traffic stays safe if the key leaks.',
        );
      }
      if (version !== 'TLSv1.3' && !isAeadCipher(name)) {
        degraded = true;
        push(
          NO_AEAD_RULE,
          'warning',
          `${host} negotiates a non-AEAD suite (${label})`,
          'Prefer AES-GCM or CHACHA20-POLY1305 over CBC-mode suites.',
        );
      }
    }

    let grade: CipherGrade;
    if (fail) grade = 'F';
    else if (degraded) grade = 'B';
    else grade = modern.length === 2 ? 'A+' : 'A';
    return { diagnostics, report: { host, grade, versions } };
  }
}

export async function auditTlsCiphers(
  host: string,
  options: TlsCipherOptions = {},
): Promise<TlsCipherResult> {
  return new TlsCipherSecurityAuditor(options).audit(host);
}

export function renderCipherReport(report: TlsCipherReport): string {
  const lines = [`TLS cipher audit: ${report.host}  grade ${report.grade ?? 'n/a'}`];
  for (const version of TLS_VERSIONS) {
    const r = report.versions[version];
    const detail =
      r?.status === 'accepted'
        ? `accepted (${r.cipherStandard ?? r.cipher ?? '?'})`
        : (r?.status ?? 'n/a');
    lines.push(`  ${version.padEnd(8)} ${detail}`);
  }
  return `${lines.join('\n')}\n`;
}

const def = (id: string, description: string): Rule => ({
  id,
  category: 'network',
  severity: 'warning',
  description,
  run() {},
});

export const tlsCipherRules: Rule[] = [
  def(LEGACY_RULE, 'The server must reject TLS 1.0 and TLS 1.1 handshakes'),
  def(NO_MODERN_RULE, 'The server must support TLS 1.2 or TLS 1.3'),
  def(NO_PFS_RULE, 'Negotiated cipher suites must provide forward secrecy'),
  def(NO_AEAD_RULE, 'Negotiated TLS 1.2 cipher suites must be AEAD'),
  def(WEAK_RULE, 'The server must not negotiate RC4, 3DES or other weak ciphers'),
  def(UNREACHABLE_RULE, 'The TLS endpoint must be reachable for assessment'),
];

export const tlsCipherRuleIds: readonly string[] = tlsCipherRules.map((r) => r.id);
