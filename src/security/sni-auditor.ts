import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { endpointsOf } from '../network/cert-expiry.js';

export const SECURITY_SNI_FALLBACK_INFORMATION_LEAK = 'security/sni-fallback-information-leak';

export interface SniCertificateInfo {
  commonName?: string;
  subjectAltName?: string;
}

export type SniProbe = (
  host: string,
  port: number,
  servername?: string,
) => Promise<SniCertificateInfo | null>;

function severityFor(rules: RuleOverrides | undefined): 'warning' | 'error' | undefined {
  const override = rules?.[SECURITY_SNI_FALLBACK_INFORMATION_LEAK];
  if (override === 'off') return undefined;
  return override === 'warning' || override === 'error' ? override : 'warning';
}

function isPrivateIp(value: string): boolean {
  const address = value.replace(/^\[|\]$/g, '').toLowerCase();
  const octets = address.split('.').map(Number);
  if (
    octets.length === 4 &&
    octets.every((octet) => Number.isInteger(octet) && octet >= 0 && octet <= 255)
  ) {
    const [first, second] = octets;
    return (
      first === 10 ||
      (first === 172 && second !== undefined && second >= 16 && second <= 31) ||
      (first === 192 && second === 168) ||
      first === 127 ||
      (first === 169 && second === 254) ||
      first === 0
    );
  }
  return (
    address === '::1' ||
    address.startsWith('fc') ||
    address.startsWith('fd') ||
    address.startsWith('fe80:') ||
    address.startsWith('::ffff:10.') ||
    address.startsWith('::ffff:192.168.')
  );
}

function isInternalName(value: string): boolean {
  const name = value.toLowerCase().replace(/^\*\./, '').replace(/\.$/, '');
  return (
    !name.includes('.') ||
    /\.(?:internal|local|localhost|lan|corp|intranet|home|test)$/.test(name) ||
    /^(?:localhost|localhost\.localdomain|ip6-localhost)$/.test(name)
  );
}

function certificateNames(certificate: SniCertificateInfo): string[] {
  const names =
    certificate.subjectAltName
      ?.split(/,\s*/)
      .map((entry) => entry.replace(/^(?:DNS|IP Address):/i, '').trim())
      .filter(Boolean) ?? [];
  if (certificate.commonName) names.push(certificate.commonName);
  return [...new Set(names)];
}

function privateNames(certificate: SniCertificateInfo): string[] {
  return certificateNames(certificate).filter((name) => {
    const isIpLiteral = /^[\d.]+$/.test(name) || name.includes(':');
    return isIpLiteral ? isPrivateIp(name) : isInternalName(name);
  });
}

/** Opens a TLS connection with exactly the requested SNI behavior. */
export const sniHandshakeProbe: SniProbe = async (host, port, servername) => {
  const tls = await import('node:tls').catch(() => null);
  if (tls === null) return null;

  return new Promise((resolve) => {
    let settled = false;
    const socket = tls.connect({
      host,
      port,
      rejectUnauthorized: false,
      ...(servername === undefined ? {} : { servername }),
    });
    const settle = (result: SniCertificateInfo | null): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    };
    socket.setTimeout(5_000);
    socket.once('secureConnect', () => {
      const certificate = socket.getPeerCertificate();
      settle({
        ...(typeof certificate.subject?.CN === 'string'
          ? { commonName: certificate.subject.CN }
          : {}),
        ...(typeof certificate.subjectaltname === 'string'
          ? { subjectAltName: certificate.subjectaltname }
          : {}),
      });
    });
    socket.once('timeout', () => settle(null));
    socket.once('error', () => settle(null));
  });
};

export async function checkSniFallback(
  doc: Record<string, unknown>,
  options: { rules?: RuleOverrides; probe?: SniProbe } = {},
): Promise<Diagnostic[]> {
  const severity = severityFor(options.rules);
  if (severity === undefined) return [];

  const probe = options.probe ?? sniHandshakeProbe;
  const diagnostics: Diagnostic[] = [];
  for (const endpoint of endpointsOf(doc)) {
    const certificates = await Promise.all([
      probe(endpoint.host, endpoint.port),
      probe(endpoint.host, endpoint.port, 'stellar-toml-lint.invalid'),
    ]);
    const leakedNames = [
      ...new Set(
        certificates.flatMap((certificate) =>
          certificate === null ? [] : privateNames(certificate),
        ),
      ),
    ];
    if (leakedNames.length === 0) continue;
    diagnostics.push({
      rule: SECURITY_SNI_FALLBACK_INFORMATION_LEAK,
      severity,
      category: 'network',
      message: `TLS fallback certificate for ${endpoint.host} exposes internal name(s): ${leakedNames.join(', ')}`,
      path: endpoint.field,
      suggestion:
        'Configure a rejecting default TLS virtual host or serve a certificate that contains no internal hostnames or private IP addresses.',
    });
  }
  return diagnostics;
}

export const sniAuditorRules: Rule[] = [
  {
    id: SECURITY_SNI_FALLBACK_INFORMATION_LEAK,
    category: 'network',
    severity: 'warning',
    description: 'TLS fallback certificates must not disclose internal names or private addresses',
    run() {},
  },
];
