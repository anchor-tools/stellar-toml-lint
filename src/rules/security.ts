import type { Rule } from '../types.js';
import { TLS_SECURITY_DOC_URL } from '../spec.js';
import { isDeprecatedTlsVersion, weakCipherSuiteIn } from '../tls.js';

/**
 * Network-transport rules.
 *
 * These read the TLS session that {@link lintDomain} observed and placed on
 * `options.tls`. Offline runs never set it, so the rules are silent unless a
 * live connection was actually made — which is the point: an anchor's TLS
 * configuration cannot be judged from a file on disk.
 */
export const securityRules: Rule[] = [
  {
    id: 'security/deprecated-tls-version',
    category: 'network',
    severity: 'warning',
    description: 'Host must not negotiate a deprecated TLS protocol version',
    run(ctx) {
      const protocol = ctx.options.tls?.protocol;
      if (!isDeprecatedTlsVersion(protocol)) return;

      ctx.report({
        rule: 'security/deprecated-tls-version',
        category: 'network',
        message: `Host negotiated deprecated protocol ${protocol}. Upgrade to TLS 1.2 or TLS 1.3.`,
        helpUri: TLS_SECURITY_DOC_URL,
        suggestion:
          'Remove TLS 1.0 and TLS 1.1 from the server configuration; SEP-1 clients and wallets expect TLS 1.2 or newer.',
      });
    },
  },

  {
    id: 'security/weak-cipher-suite',
    category: 'network',
    severity: 'warning',
    description: 'Host must not negotiate a weak cipher suite',
    run(ctx) {
      const tls = ctx.options.tls;
      if (!tls) return;

      const suite = weakCipherSuiteIn(tls);
      if (!suite) return;

      ctx.report({
        rule: 'security/weak-cipher-suite',
        category: 'network',
        message: `Host negotiated weak cipher suite ${suite}.`,
        helpUri: TLS_SECURITY_DOC_URL,
        suggestion:
          'Restrict the cipher list to AEAD suites (AES-GCM or ChaCha20-Poly1305) and disable 3DES, RC4, and CBC-mode suites.',
      });
    },
  },

  {
    id: 'security/jwt-rejected-by-transfer-server',
    category: 'network',
    severity: 'error',
    description: 'Downstream anchor service must accept JWT issued by WEB_AUTH_ENDPOINT',
    run() {},
  },

  {
    id: 'security/jwt-domain-mismatch',
    category: 'network',
    severity: 'error',
    description: 'JWT iss claim must match the anchor home domain',
    run() {},
  },
];

/** Rule ids that require a live TLS session. Used to skip the probe when off. */
export const securityRuleIds: readonly string[] = [
  'security/deprecated-tls-version',
  'security/weak-cipher-suite',
];
