import type { Diagnostic, Rule, RuleOverrides } from '../types.js';

export const SUSPICIOUS_VANITY_ADDRESS_RULE = 'crypto/suspicious-vanity-address';

export const VANITY_SECURITY_ADVISORY_URL =
  'https://blog.1inch.io/a-vulnerability-disclosed-in-profanity-an-ethereum-vanity-address-tool/';

const STELLAR_DOC_URL =
  'https://developers.stellar.org/docs/learn/fundamentals/stellar-data-structures/accounts';

const VANITY_WORDS = [
  'ANCHOR',
  'STELLAR',
  'LUMEN',
  'XLM',
  'CRYPTO',
  'WALLET',
  'BANK',
  'MONEY',
  'COIN',
  'TOKEN',
  'PAYMENT',
  'FINANCE',
  'EXCHANGE',
  'MARKET',
  'TRUST',
  'GOLD',
  'SILVER',
  'BLOCK',
  'CHAIN',
  'LEDGER',
  'DEFI',
  'USDC',
  'USDT',
  'EURC',
  'VANITY',
  'ADDRESS',
  'HODL',
  'MOON',
  'LUMENS',
] as const;

export interface VanityAnalysis {
  suspicious: boolean;
  publicKey: string;
  prefix: string;
  reason?: string;
  advisoryUrl?: string;
}

function base32Body(publicKey: string): string {
  const upper = publicKey.trim().toUpperCase();
  return upper.startsWith('G') ? upper.slice(1) : upper;
}

function repeatedPrefix(body: string): string | undefined {
  if (body.length < 7) return undefined;
  const first = body[0];
  if (first === undefined) return undefined;
  let length = 1;
  while (length < body.length && body[length] === first) length++;
  return length >= 7 ? body.slice(0, length) : undefined;
}

function alternatingPrefix(body: string): string | undefined {
  for (const period of [1, 2, 3]) {
    if (body.length < 8) return undefined;
    let length = 0;
    while (length < body.length && body[length] === body[length % period]) {
      length++;
    }
    if (length >= 8) return body.slice(0, length);
  }
  return undefined;
}

function sequentialPrefix(body: string): string | undefined {
  if (body.length < 7) return undefined;
  let length = 1;
  for (let i = 1; i < body.length; i++) {
    const previous = body.charCodeAt(i - 1);
    const current = body.charCodeAt(i);
    if (current - previous !== 1) break;
    length++;
  }
  return length >= 7 ? body.slice(0, length) : undefined;
}

function dictionaryPrefix(body: string): string | undefined {
  const upper = body.toUpperCase();
  for (const word of VANITY_WORDS) {
    if (word.length >= 6 && upper.startsWith(word)) return word;
  }
  const window = upper.slice(0, 12);
  for (const word of VANITY_WORDS) {
    const index = window.indexOf(word);
    if (word.length >= 6 && index >= 0) return window.slice(0, index + word.length);
  }
  return undefined;
}

/** Classifies a Stellar public key's leading characters for vanity patterns. */
export function analyzeVanityAddress(publicKey: string): VanityAnalysis {
  const body = base32Body(publicKey);
  const prefix = body.slice(0, 12);

  const word = dictionaryPrefix(body);
  if (word !== undefined) {
    return {
      suspicious: true,
      publicKey,
      prefix: `G${prefix}`,
      reason: `starts with the vanity word "${word}"`,
      advisoryUrl: VANITY_SECURITY_ADVISORY_URL,
    };
  }

  const repeated = repeatedPrefix(body);
  if (repeated !== undefined) {
    return {
      suspicious: true,
      publicKey,
      prefix: `G${repeated}`,
      reason: `has a degenerate repeated-character prefix "${repeated}"`,
      advisoryUrl: VANITY_SECURITY_ADVISORY_URL,
    };
  }

  const alternating = alternatingPrefix(body);
  if (alternating !== undefined) {
    return {
      suspicious: true,
      publicKey,
      prefix: `G${alternating}`,
      reason: `has a predictable repeating prefix "${alternating}"`,
      advisoryUrl: VANITY_SECURITY_ADVISORY_URL,
    };
  }

  const sequential = sequentialPrefix(body);
  if (sequential !== undefined) {
    return {
      suspicious: true,
      publicKey,
      prefix: `G${sequential}`,
      reason: `has a sequential vanity prefix "${sequential}"`,
      advisoryUrl: VANITY_SECURITY_ADVISORY_URL,
    };
  }

  return { suspicious: false, publicKey, prefix: `G${prefix}` };
}

function severityFor(rules?: RuleOverrides): 'error' | 'warning' | undefined {
  const override = rules?.[SUSPICIOUS_VANITY_ADDRESS_RULE];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : 'warning';
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function keySources(doc: Record<string, unknown>): { publicKey: string; path: string }[] {
  const sources: { publicKey: string; path: string }[] = [];
  if (typeof doc.SIGNING_KEY === 'string') {
    sources.push({ publicKey: doc.SIGNING_KEY, path: 'SIGNING_KEY' });
  }
  if (Array.isArray(doc.ACCOUNTS)) {
    doc.ACCOUNTS.forEach((account, index) => {
      if (typeof account === 'string') {
        sources.push({ publicKey: account, path: `ACCOUNTS[${index}]` });
      }
    });
  }
  if (Array.isArray(doc.CURRENCIES)) {
    doc.CURRENCIES.forEach((entry, index) => {
      if (!isRecord(entry)) return;
      if (typeof entry.issuer === 'string') {
        sources.push({ publicKey: entry.issuer, path: `CURRENCIES[${index}].issuer` });
      }
    });
  }
  if (Array.isArray(doc.VALIDATORS)) {
    doc.VALIDATORS.forEach((validator, index) => {
      if (!isRecord(validator)) return;
      if (typeof validator.PUBLIC_KEY === 'string') {
        sources.push({
          publicKey: validator.PUBLIC_KEY,
          path: `VALIDATORS[${index}].PUBLIC_KEY`,
        });
      }
    });
  }
  return sources;
}

/**
 * Flags public keys whose prefixes look like GPU-brute-forced vanity output.
 *
 * Vanity tools that leak entropy or use a flawed PRNG (as Profanity did for
 * Ethereum) can make a long, recognizable prefix a liability rather than a
 * branding win. The check is offline and advisory: a suspicious prefix emits
 * a warning with the advisory link for the known vulnerable generator class.
 */
export function auditVanityAddresses(
  doc: Record<string, unknown>,
  options: { rules?: RuleOverrides } = {},
): Diagnostic[] {
  const severity = severityFor(options.rules);
  if (severity === undefined) return [];

  const diagnostics: Diagnostic[] = [];
  const seen = new Set<string>();

  for (const { publicKey, path } of keySources(doc)) {
    const analysis = analyzeVanityAddress(publicKey);
    if (!analysis.suspicious) continue;
    const dedupeKey = `${path}:${analysis.prefix}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);

    diagnostics.push({
      rule: SUSPICIOUS_VANITY_ADDRESS_RULE,
      severity,
      category: 'general',
      message: `${path} looks like a vanity address: it ${analysis.reason}`,
      path,
      helpUri: analysis.advisoryUrl ?? STELLAR_DOC_URL,
      suggestion:
        'Verify the key was generated with a cryptographically secure PRNG and enough entropy; rotate it if it came from a known vulnerable vanity generator such as Profanity.',
    });
  }

  return diagnostics;
}

export const checkVanityAddresses = auditVanityAddresses;
export const auditVanityAddress = auditVanityAddresses;

export const vanityAuditorRules: Rule[] = [
  {
    id: SUSPICIOUS_VANITY_ADDRESS_RULE,
    category: 'general',
    severity: 'warning',
    description:
      'Public keys with long vanity prefixes may come from weak PRNGs and should be reviewed',
    run() {},
  },
];

export const vanityAuditorRuleIds: readonly string[] = vanityAuditorRules.map((rule) => rule.id);
