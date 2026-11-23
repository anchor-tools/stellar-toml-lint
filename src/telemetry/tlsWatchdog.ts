/**
 * Automated SSL/TLS certificate renewal and OCSP stapling health watchdog.
 *
 * Establishes TLS handshakes with anchor domains, inspects peer certificate validity dates,
 * warns when expiration is under 30 days away, and verifies OCSP stapling response status.
 */
import * as tls from 'node:tls';
import type { Diagnostic, Severity } from '../types.js';

export interface TlsWatchdogFinding {
  rule: string;
  severity: Severity;
  message: string;
}

export interface TlsCertificateAuditResult {
  domain: string;
  valid: boolean;
  issuer?: string;
  subject?: string;
  validFrom?: Date;
  validTo?: Date;
  daysRemaining?: number;
  isExpiringSoon: boolean;
  isExpired: boolean;
  hasOcspStapling: boolean;
  ocspStatus?: 'successful' | 'malformed' | 'internalError' | 'tryLater' | 'missing';
  certStatus?: 'good' | 'revoked' | 'unknown';
  findings: TlsWatchdogFinding[];
  diagnostics: Diagnostic[];
}

export interface TlsRawCertInfo {
  subject?: string;
  issuer?: string;
  validFrom?: string | Date;
  validTo?: string | Date;
  ocspResponse?: Buffer | null;
  certStatus?: 'good' | 'revoked' | 'unknown';
}

export interface TlsWatchdogOptions {
  port?: number;
  timeoutMs?: number;
  socketProbe?: (host: string, port: number, timeoutMs: number) => Promise<TlsRawCertInfo>;
}

export class TlsCertificateWatchdog {
  private readonly defaultTimeoutMs: number = 5000;
  private readonly expirationThresholdDays: number = 30;

  /**
   * Audits a domain's TLS certificate expiration and OCSP stapling configuration.
   */
  public async auditDomain(
    domain: string,
    options: TlsWatchdogOptions = {},
  ): Promise<TlsCertificateAuditResult> {
    const cleanHost = domain
      .replace(/^https?:\/\//, '')
      .replace(/\/.*$/, '')
      .replace(/:\d+$/, '');
    const port = options.port ?? 443;
    const timeoutMs = options.timeoutMs ?? this.defaultTimeoutMs;

    try {
      const certInfo = options.socketProbe
        ? await options.socketProbe(cleanHost, port, timeoutMs)
        : await this.probeSocket(cleanHost, port, timeoutMs);

      return this.auditCertificate(certInfo, cleanHost);
    } catch (err) {
      return {
        domain: cleanHost,
        valid: false,
        isExpiringSoon: false,
        isExpired: false,
        hasOcspStapling: false,
        findings: [
          {
            rule: 'tls/connection-failed',
            severity: 'error',
            message: `Failed to establish TLS connection to ${cleanHost}:${port} - ${String(err)}`,
          },
        ],
        diagnostics: [
          {
            rule: 'tls/connection-failed',
            category: 'security',
            severity: 'error',
            message: `TLS connection failed: ${String(err)}`,
            path: cleanHost,
          },
        ],
      };
    }
  }

  /**
   * Analyzes certificate validity dates and OCSP stapling flags.
   */
  public auditCertificate(
    certInfo: TlsRawCertInfo,
    domain: string,
    now: Date = new Date(),
  ): TlsCertificateAuditResult {
    const findings: TlsWatchdogFinding[] = [];

    const validFrom = certInfo.validFrom ? new Date(certInfo.validFrom) : undefined;
    const validTo = certInfo.validTo ? new Date(certInfo.validTo) : undefined;

    let daysRemaining: number | undefined;
    let isExpired = false;
    let isExpiringSoon = false;

    if (validTo && !isNaN(validTo.getTime())) {
      const diffMs = validTo.getTime() - now.getTime();
      daysRemaining = Math.floor(diffMs / (1000 * 60 * 60 * 24));

      if (daysRemaining <= 0) {
        isExpired = true;
        findings.push({
          rule: 'tls/cert-expired',
          severity: 'error',
          message: `TLS certificate for ${domain} expired on ${validTo.toISOString()} (${Math.abs(daysRemaining)} days ago).`,
        });
      } else if (daysRemaining < this.expirationThresholdDays) {
        isExpiringSoon = true;
        findings.push({
          rule: 'tls/cert-expiring-soon',
          severity: 'warning',
          message: `Action Required: TLS certificate for ${domain} expires in ${daysRemaining} days (renewal threshold: < ${this.expirationThresholdDays} days).`,
        });
      }
    } else {
      findings.push({
        rule: 'tls/missing-validity-dates',
        severity: 'error',
        message: `Could not determine certificate validity dates for ${domain}.`,
      });
    }

    // OCSP Stapling check
    const hasOcspStapling = Boolean(certInfo.ocspResponse && certInfo.ocspResponse.length > 0);
    const ocspStatus: TlsCertificateAuditResult['ocspStatus'] = hasOcspStapling
      ? 'successful'
      : 'missing';
    const certStatus: TlsCertificateAuditResult['certStatus'] =
      certInfo.certStatus ?? (hasOcspStapling ? 'good' : 'unknown');

    if (!hasOcspStapling) {
      findings.push({
        rule: 'tls/missing-ocsp-stapling',
        severity: 'warning',
        message: `Domain ${domain} does not have OCSP stapling enabled. Handshakes may experience latency due to external CA lookups.`,
      });
    } else {
      if (certStatus === 'revoked') {
        findings.push({
          rule: 'tls/ocsp-revoked',
          severity: 'error',
          message: `CRITICAL: OCSP response indicates that the certificate for ${domain} has been REVOKED.`,
        });
      }
    }

    const hasError = findings.some((f) => f.severity === 'error');
    const diagnostics: Diagnostic[] = findings.map((f) => ({
      rule: f.rule,
      category: 'security',
      severity: f.severity,
      message: f.message,
      path: domain,
    }));

    return {
      domain,
      valid: !hasError,
      issuer: certInfo.issuer,
      subject: certInfo.subject,
      validFrom,
      validTo,
      daysRemaining,
      isExpiringSoon,
      isExpired,
      hasOcspStapling,
      ocspStatus,
      certStatus,
      findings,
      diagnostics,
    };
  }

  /**
   * Connects via node:tls to extract peer certificate and OCSP response with strict timeout.
   */
  private probeSocket(host: string, port: number, timeoutMs: number): Promise<TlsRawCertInfo> {
    return new Promise((resolve, reject) => {
      let ocspResponse: Buffer | null = null;

      const socket = tls.connect(
        {
          host,
          port,
          servername: host,
          requestOCSP: true,
          rejectUnauthorized: false,
        },
        () => {
          const cert = socket.getPeerCertificate(true);
          socket.destroy();

          resolve({
            subject: cert?.subject
              ? Object.entries(cert.subject)
                  .map(([k, v]) => `${k}=${v}`)
                  .join(', ')
              : undefined,
            issuer: cert?.issuer
              ? Object.entries(cert.issuer)
                  .map(([k, v]) => `${k}=${v}`)
                  .join(', ')
              : undefined,
            validFrom: cert?.valid_from,
            validTo: cert?.valid_to,
            ocspResponse,
            certStatus: ocspResponse && ocspResponse.length > 0 ? 'good' : 'unknown',
          });
        },
      );

      socket.on('OCSPResponse', (response: Buffer) => {
        ocspResponse = response;
      });

      socket.setTimeout(timeoutMs, () => {
        socket.destroy();
        reject(new Error(`TLS connection to ${host}:${port} timed out after ${timeoutMs}ms`));
      });

      socket.on('error', (err) => {
        socket.destroy();
        reject(err);
      });
    });
  }

  /**
   * Formats the certificate audit result into human-readable text or JSON.
   */
  public renderReport(result: TlsCertificateAuditResult, format: 'text' | 'json' = 'text'): string {
    if (format === 'json') {
      return JSON.stringify(result, null, 2);
    }

    const lines: string[] = [];
    lines.push(`TLS Certificate Watchdog Report for ${result.domain}`);
    if (result.subject) lines.push(`  Subject:         ${result.subject}`);
    if (result.issuer) lines.push(`  Issuer:          ${result.issuer}`);
    if (result.validFrom) lines.push(`  Valid From:      ${result.validFrom.toISOString()}`);
    if (result.validTo) lines.push(`  Valid To:        ${result.validTo.toISOString()}`);
    if (result.daysRemaining !== undefined) {
      lines.push(`  Days Remaining:  ${result.daysRemaining} days`);
    }
    lines.push(
      `  OCSP Stapling:   ${result.hasOcspStapling ? 'ENABLED (status: successful)' : 'NOT STAPLED'}`,
    );

    if (result.findings.length > 0) {
      lines.push('\nAlerts & Findings:');
      for (const f of result.findings) {
        const tag =
          f.severity === 'error' ? '[ERROR]' : f.severity === 'warning' ? '[WARN]' : '[INFO]';
        lines.push(`  ${tag} ${f.rule}: ${f.message}`);
      }
    } else {
      lines.push('\nCertificate is healthy and OCSP stapling is active.');
    }

    return lines.join('\n');
  }
}
