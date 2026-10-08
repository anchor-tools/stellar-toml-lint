import type { Rule } from '../types.js';
import { specUrl } from '../spec.js';

/**
 * Returns true if an http:// URL points to a local testing environment,
 * e.g. localhost, 127.0.0.1, 0.0.0.0, [::1], or .local/.test domains.
 */
function isIpv4Loopback(host: string): boolean {
  const parts = host.split('.');
  if (parts.length !== 4) return false;
  if (parts[0] !== '127') return false;
  return parts.every((p) => {
    const num = Number(p);
    return /^\d+$/.test(p) && num >= 0 && num <= 255;
  });
}

export function isLocalMockUrl(urlStr: string): boolean {
  try {
    const parsed = new URL(urlStr);
    const host = parsed.hostname.toLowerCase();
    return (
      host === 'localhost' ||
      host.endsWith('.localhost') ||
      isIpv4Loopback(host) ||
      host === '0.0.0.0' ||
      host === '[::1]' ||
      host === '::1' ||
      host.endsWith('.local') ||
      host.endsWith('.test') ||
      host.endsWith('.internal')
    );
  } catch {
    const lower = urlStr.toLowerCase();
    return (
      lower.startsWith('http://localhost') ||
      /^http:\/\/127\.\d+\.\d+\.\d+(?::\d+)?(?:\/.*)?$/.test(lower) ||
      lower.startsWith('http://0.0.0.0') ||
      lower.startsWith('http://[::1]')
    );
  }
}

/**
 * Returns the relevant section of SEP-1 for a given field path.
 */
function helpUriFor(path: string): string {
  if (path.startsWith('DOCUMENTATION')) return specUrl('organization-documentation');
  if (path.startsWith('CURRENCIES')) return specUrl('currencies');
  if (path.startsWith('VALIDATORS')) return specUrl('validators');
  if (path.startsWith('PRINCIPALS')) return specUrl('principals');
  return specUrl('general-information');
}

/**
 * Recursively scans all fields across the document and flags any insecure http:// URLs,
 * allowing exceptions only for local mock testing.
 */
function scanForInsecureHttp(value: unknown, path: string, ctx: Parameters<Rule['run']>[0]): void {
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (/^http:\/\//i.test(trimmed)) {
      if (!isLocalMockUrl(trimmed)) {
        const httpsUrl = trimmed.replace(/^http:\/\//i, 'https://');
        ctx.report({
          rule: 'general/insecure-http-url',
          category: 'general',
          severity: 'error',
          message: `${path} must use https:// instead of insecure http://`,
          path,
          position: ctx.locate(path),
          helpUri: helpUriFor(path),
          suggestion: `Replace ${trimmed} with ${httpsUrl}.`,
          fix: {
            value: httpsUrl,
          },
        });
      }
    }
  } else if (Array.isArray(value)) {
    value.forEach((item, index) => {
      scanForInsecureHttp(item, `${path}[${index}]`, ctx);
    });
  } else if (value && typeof value === 'object') {
    for (const [key, nestedValue] of Object.entries(value)) {
      const nestedPath = path ? `${path}.${key}` : key;
      scanForInsecureHttp(nestedValue, nestedPath, ctx);
    }
  }
}

/**
 * Detects insecure http:// URLs across all fields in stellar.toml.
 * SEP-1 requires endpoints, official websites, and documentation links to use
 * secure HTTPS in production to prevent man-in-the-middle attacks.
 */
export const insecureHttpRule: Rule = {
  id: 'general/insecure-http-url',
  category: 'general',
  severity: 'error',
  description: 'Flags insecure http:// URLs across configuration fields in production',
  run(ctx) {
    if (!ctx.doc || typeof ctx.doc !== 'object') return;
    scanForInsecureHttp(ctx.doc, '', ctx);
  },
};
