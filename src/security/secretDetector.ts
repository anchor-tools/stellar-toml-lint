/**
 * High-entropy secret and credential leak detector.
 *
 * A `stellar.toml` is a public file, yet developers occasionally paste a Stellar
 * seed (`S…`), an AWS access key, a GitHub token or a PEM block into a field or
 * a comment. Anything published there must be treated as compromised.
 *
 * The detector is scrub-first: raw secret values are used for *matching* only.
 * Every value that reaches a diagnostic, a report or a log line has been
 * through {@link maskSecret}, which keeps at most four leading and three
 * trailing characters. Source redaction is provided for callers that want to
 * echo the file safely.
 */
import { StrKey } from '@stellar/stellar-base';
import type { Diagnostic, Position, Rule, RuleOverrides } from '../types.js';

export const SECURITY_SECRET_STELLAR_SEED = 'security/secret-stellar-seed';
export const SECURITY_SECRET_AWS_ACCESS_KEY = 'security/secret-aws-access-key';
export const SECURITY_SECRET_AWS_SECRET_KEY = 'security/secret-aws-secret-key';
export const SECURITY_SECRET_GITHUB_TOKEN = 'security/secret-github-token';
export const SECURITY_SECRET_PRIVATE_KEY = 'security/secret-private-key';
export const SECURITY_SECRET_BEARER_TOKEN = 'security/secret-bearer-token';
export const SECURITY_SECRET_HIGH_ENTROPY = 'security/secret-high-entropy';

export type SecretKind =
  | 'stellar-seed'
  | 'aws-access-key'
  | 'aws-secret-key'
  | 'github-token'
  | 'private-key'
  | 'bearer-token'
  | 'high-entropy';

export interface SecretFinding {
  rule: string;
  kind: SecretKind;
  /** Always masked; never the raw value. */
  masked: string;
  entropy: number;
  message: string;
  suggestion: string;
  path?: string;
  position?: Position;
}

export interface SecretScanResult {
  findings: SecretFinding[];
  /** True when at least one credential was found — the caller should halt. */
  halt: boolean;
  /** The supplied source with every detected value replaced by its mask. */
  redactedSource: string;
}

export interface SecretDetectorOptions {
  rules?: RuleOverrides;
  /** Minimum Shannon entropy for generic credential candidates. Default 3.5. */
  entropyThreshold?: number;
}

interface DetectedSecret {
  kind: SecretKind;
  rule: string;
  value: string;
  start: number;
  end: number;
  entropy: number;
  suggestion: string;
  path?: string;
}

const PLACEHOLDER =
  /(?:EXAMPLE|DUMMY|SAMPLE|FAKE|PLACEHOLDER|REDACTED|YOUR_|XXXX|0000000000|1111111111)/i;
const SENSITIVE_CONTEXT =
  /(?:secret|token|password|passwd|credential|api[_-]?key|private[_-]?key|bearer|authorization|auth)/i;
const BENIGN_CONTEXT =
  /(?:id_photo_hash|verification_photo_hash|photo_hash|hash|image|logo|issuer|contract|public_key|signing_key|tls_cert|checksum|digest)/i;

const AWS_ACCESS_KEY = /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}\b/g;
const AWS_SECRET_ASSIGNMENT =
  /\b(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi;
const GITHUB_TOKEN = /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{40,255})\b/g;
const BEARER_TOKEN = /\bBearer\s+([A-Za-z0-9._~+/=-]{20,})/gi;
const STELLAR_SEED = /\bS[A-Z2-7]{55}\b/g;
const GENERIC_TOKEN = /\b[A-Za-z0-9+/=_-]{32,}\b/g;

/** Shannon entropy in bits per character. */
export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Masks a value for display. Keeps four leading and three trailing characters
 * so a maintainer can recognise which credential leaked without the log
 * becoming a second leak.
 */
export function maskSecret(value: string): string {
  if (value.length <= 8) return '[REDACTED]';
  return `${value.slice(0, 4)}...${value.slice(-3)}`;
}

function lineColumn(source: string, index: number): Position {
  const before = source.slice(0, index);
  const lines = before.split('\n');
  return { line: lines.length, column: (lines[lines.length - 1]?.length ?? 0) + 1 };
}

function overlaps(intervals: Array<[number, number]>, start: number, end: number): boolean {
  return intervals.some(([from, to]) => start < to && end > from);
}

function contextAround(source: string, start: number): string {
  const lineStart = source.lastIndexOf('\n', Math.max(0, start - 1)) + 1;
  return source.slice(lineStart, start).slice(-120);
}

function push(
  detected: DetectedSecret[],
  intervals: Array<[number, number]>,
  candidate: DetectedSecret,
): void {
  if (PLACEHOLDER.test(candidate.value)) return;
  if (overlaps(intervals, candidate.start, candidate.end)) return;
  detected.push(candidate);
  intervals.push([candidate.start, candidate.end]);
}

const PEM_BEGIN = '-----BEGIN ';
const PEM_END = '-----END ';
const PEM_KEY_SUFFIX = 'PRIVATE KEY-----';
const PEM_LABELS = ['RSA', 'EC', 'DSA', 'OPENSSH', 'PGP', 'ENCRYPTED'] as const;

/**
 * Returns the offset just past a PEM private-key marker, or `undefined` when
 * the marker at `start` is not a private-key marker.
 *
 * Used instead of a single `BEGIN … END` regex: `[\s\S]*?` combined with the
 * optional key-type label made the old detector quadratic on input containing
 * many BEGIN markers without a matching END (CodeQL js/polynomial-redos).
 */
function privateKeyMarkerEnd(text: string, start: number, prefix: string): number | undefined {
  const suffixAt = start + prefix.length;
  if (text.startsWith(PEM_KEY_SUFFIX, suffixAt)) return suffixAt + PEM_KEY_SUFFIX.length;
  for (const label of PEM_LABELS) {
    const afterLabel = suffixAt + label.length + 1;
    if (text.startsWith(`${label} `, suffixAt) && text.startsWith(PEM_KEY_SUFFIX, afterLabel)) {
      return afterLabel + PEM_KEY_SUFFIX.length;
    }
  }
  return undefined;
}

/**
 * Finds PEM private-key blocks in a single forward pass. Each marker is
 * examined once, so repeated BEGIN/END markers cannot trigger backtracking.
 */
function findPrivateKeyBlocks(text: string): Array<[number, number]> {
  const blocks: Array<[number, number]> = [];
  let cursor = 0;
  let open: number | undefined;
  while (cursor < text.length) {
    const begin = text.indexOf(PEM_BEGIN, cursor);
    const end = text.indexOf(PEM_END, cursor);
    if (begin !== -1 && (end === -1 || begin < end)) {
      const markerEnd = privateKeyMarkerEnd(text, begin, PEM_BEGIN);
      if (markerEnd !== undefined && open === undefined) open = begin;
      cursor = markerEnd ?? begin + PEM_BEGIN.length;
      continue;
    }
    if (end !== -1) {
      const markerEnd = privateKeyMarkerEnd(text, end, PEM_END);
      if (markerEnd !== undefined && open !== undefined) {
        blocks.push([open, markerEnd]);
        open = undefined;
      }
      cursor = markerEnd ?? end + PEM_END.length;
      continue;
    }
    break;
  }
  return blocks;
}

/** Applies all regex detectors to one blob of text. */
function detectInText(text: string, threshold: number, base = 0): DetectedSecret[] {
  const detected: DetectedSecret[] = [];
  const intervals: Array<[number, number]> = [];
  const absolute = (index: number): number => base + index;

  for (const [start, end] of findPrivateKeyBlocks(text)) {
    const value = text.slice(start, end);
    push(detected, intervals, {
      kind: 'private-key',
      rule: SECURITY_SECRET_PRIVATE_KEY,
      value,
      start: absolute(start),
      end: absolute(end),
      entropy: shannonEntropy(value),
      suggestion:
        'Revoke the key immediately and remove the block from this public file and its history.',
    });
  }

  for (const match of text.matchAll(STELLAR_SEED)) {
    const value = match[0];
    if (!StrKey.isValidEd25519SecretSeed(value)) continue;
    const start = match.index ?? 0;
    push(detected, intervals, {
      kind: 'stellar-seed',
      rule: SECURITY_SECRET_STELLAR_SEED,
      value,
      start: absolute(start),
      end: absolute(start + value.length),
      entropy: shannonEntropy(value),
      suggestion:
        'Generate a fresh keypair, move the funds, and rotate every service that used this seed.',
    });
  }

  for (const match of text.matchAll(AWS_ACCESS_KEY)) {
    const value = match[0];
    if (shannonEntropy(value) < 3) continue;
    const start = match.index ?? 0;
    push(detected, intervals, {
      kind: 'aws-access-key',
      rule: SECURITY_SECRET_AWS_ACCESS_KEY,
      value,
      start: absolute(start),
      end: absolute(start + value.length),
      entropy: shannonEntropy(value),
      suggestion: 'Disable the access key in IAM, rotate it, and scrub it from git history.',
    });
  }

  for (const match of text.matchAll(AWS_SECRET_ASSIGNMENT)) {
    const value = match[1] ?? '';
    const start = (match.index ?? 0) + (match[0].indexOf(value) >= 0 ? match[0].indexOf(value) : 0);
    push(detected, intervals, {
      kind: 'aws-secret-key',
      rule: SECURITY_SECRET_AWS_SECRET_KEY,
      value,
      start: absolute(start),
      end: absolute(start + value.length),
      entropy: shannonEntropy(value),
      suggestion: 'Rotate the AWS secret access key and remove it from this repository.',
    });
  }

  for (const match of text.matchAll(GITHUB_TOKEN)) {
    const value = match[0];
    const start = match.index ?? 0;
    push(detected, intervals, {
      kind: 'github-token',
      rule: SECURITY_SECRET_GITHUB_TOKEN,
      value,
      start: absolute(start),
      end: absolute(start + value.length),
      entropy: shannonEntropy(value),
      suggestion: 'Revoke the token in GitHub settings and reissue it with the minimum scopes.',
    });
  }

  for (const match of text.matchAll(BEARER_TOKEN)) {
    const value = match[1] ?? '';
    const start = (match.index ?? 0) + (match[0].indexOf(value) >= 0 ? match[0].indexOf(value) : 0);
    push(detected, intervals, {
      kind: 'bearer-token',
      rule: SECURITY_SECRET_BEARER_TOKEN,
      value,
      start: absolute(start),
      end: absolute(start + value.length),
      entropy: shannonEntropy(value),
      suggestion: 'Revoke the bearer token and stop embedding credentials in TOML comments.',
    });
  }

  for (const match of text.matchAll(GENERIC_TOKEN)) {
    const value = match[0];
    if (shannonEntropy(value) < threshold) continue;
    const context = contextAround(text, match.index ?? 0);
    if (!SENSITIVE_CONTEXT.test(context) || BENIGN_CONTEXT.test(context)) continue;
    const start = match.index ?? 0;
    push(detected, intervals, {
      kind: 'high-entropy',
      rule: SECURITY_SECRET_HIGH_ENTROPY,
      value,
      start: absolute(start),
      end: absolute(start + value.length),
      entropy: shannonEntropy(value),
      suggestion: 'Move the credential to a secret manager and inject it at runtime.',
    });
  }

  return detected;
}

/** Walks parsed values so secrets hidden behind TOML escapes are still found. */
function detectInDocument(doc: Record<string, unknown>, threshold: number): DetectedSecret[] {
  const found: DetectedSecret[] = [];
  const visit = (value: unknown, path: string): void => {
    if (typeof value === 'string') {
      for (const detected of detectInText(value, threshold)) {
        found.push({
          ...detected,
          // Paths, not offsets, are meaningful for a parsed value.
          start: -1,
          end: -1,
          ...(path === '' ? {} : { path }),
        });
      }
      // A bare high-entropy value in a sensitive field has no local context.
      if (!BENIGN_CONTEXT.test(path) && SENSITIVE_CONTEXT.test(path) && value.length >= 32) {
        const entropy = shannonEntropy(value);
        if (entropy >= threshold && !PLACEHOLDER.test(value)) {
          found.push({
            kind: 'high-entropy',
            rule: SECURITY_SECRET_HIGH_ENTROPY,
            value,
            start: -1,
            end: -1,
            entropy,
            suggestion: 'Move the credential to a secret manager and inject it at runtime.',
            path,
          });
        }
      }
      return;
    }
    if (Array.isArray(value)) {
      value.forEach((item, index) => visit(item, `${path}[${index}]`));
      return;
    }
    if (typeof value === 'object' && value !== null) {
      for (const [key, item] of Object.entries(value)) {
        visit(item, path === '' ? key : `${path}.${key}`);
      }
    }
  };
  visit(doc, '');
  return found;
}

function toFinding(detected: DetectedSecret, source?: string): SecretFinding {
  const finding: SecretFinding = {
    rule: detected.rule,
    kind: detected.kind,
    masked:
      detected.kind === 'private-key' ? '[REDACTED PRIVATE KEY BLOCK]' : maskSecret(detected.value),
    entropy: Math.round(detected.entropy * 100) / 100,
    message: `Possible ${detected.kind.replace(/-/g, ' ')} credential ${findingMask(detected)} detected`,
    suggestion: detected.suggestion,
  };
  if (detected.path !== undefined) finding.path = detected.path;
  if (source !== undefined && detected.start >= 0) {
    finding.position = lineColumn(source, detected.start);
  }
  return finding;
}

function findingMask(detected: DetectedSecret): string {
  return detected.kind === 'private-key' ? '(PEM block)' : `(${maskSecret(detected.value)})`;
}

function redact(source: string, detected: DetectedSecret[]): string {
  let result = source;
  const inSource = detected
    .filter((secret) => secret.start >= 0 && secret.end <= source.length)
    .sort((left, right) => right.start - left.start);
  for (const secret of inSource) {
    const replacement =
      secret.kind === 'private-key' ? '[REDACTED PRIVATE KEY BLOCK]' : maskSecret(secret.value);
    result = result.slice(0, secret.start) + replacement + result.slice(secret.end);
  }
  return result;
}

/**
 * Scans raw source (including comments) and the parsed document.
 *
 * Findings are deduplicated by kind and masked value, so a seed that appears
 * both in a field and in its trailing comment is reported once.
 */
export function scanSecrets(
  source: string,
  doc?: Record<string, unknown>,
  options: SecretDetectorOptions = {},
): SecretScanResult {
  const threshold = options.entropyThreshold ?? 3.5;
  const raw = detectInText(source, threshold);
  const parsed = doc === undefined ? [] : detectInDocument(doc, threshold);
  const seen = new Set<string>();
  const findings: SecretFinding[] = [];

  for (const detected of [...raw, ...parsed]) {
    const key = `${detected.kind}:${detected.kind === 'private-key' ? 'pem' : maskSecret(detected.value)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push(toFinding(detected, source));
  }

  return {
    findings,
    halt: findings.length > 0,
    redactedSource: redact(source, raw),
  };
}

/** Diagnostic form used by the CLI audit. */
export function checkSecrets(
  source: string,
  doc?: Record<string, unknown>,
  options: SecretDetectorOptions = {},
): Diagnostic[] {
  const result = scanSecrets(source, doc, options);
  const diagnostics: Diagnostic[] = [];
  for (const finding of result.findings) {
    const override = options.rules?.[finding.rule];
    if (override === 'off') continue;
    const severity =
      override === 'error' || override === 'warning' || override === 'info'
        ? override
        : ('error' as const);
    const diagnostic: Diagnostic = {
      rule: finding.rule,
      severity,
      category: 'security',
      message: finding.message,
      suggestion: finding.suggestion,
    };
    if (finding.path !== undefined) diagnostic.path = finding.path;
    if (finding.position !== undefined) diagnostic.position = finding.position;
    diagnostics.push(diagnostic);
  }
  return diagnostics;
}

/** Text report for the CLI. Contains masked values only. */
export function renderSecretReport(result: SecretScanResult): string {
  if (!result.halt) return 'Secret scan: no credentials detected\n';
  const lines = [
    'Secret scan: CREDENTIALS DETECTED — halt',
    `  ${result.findings.length} finding(s)`,
  ];
  for (const finding of result.findings) {
    lines.push(`  [${finding.rule}] ${finding.message}`);
    lines.push(`      ${finding.suggestion}`);
  }
  return `${lines.join('\n')}\n`;
}

/** Registered so `--off`/`--warn`/`--error` and `--list-rules` know these ids. */
export const secretDetectorRules: Rule[] = [
  {
    id: SECURITY_SECRET_STELLAR_SEED,
    category: 'security',
    severity: 'error',
    description: 'Public stellar.toml files must not contain Stellar secret seeds',
    run() {},
  },
  {
    id: SECURITY_SECRET_AWS_ACCESS_KEY,
    category: 'security',
    severity: 'error',
    description: 'Public TOML files must not contain AWS access key ids',
    run() {},
  },
  {
    id: SECURITY_SECRET_AWS_SECRET_KEY,
    category: 'security',
    severity: 'error',
    description: 'Public TOML files must not contain AWS secret access keys',
    run() {},
  },
  {
    id: SECURITY_SECRET_GITHUB_TOKEN,
    category: 'security',
    severity: 'error',
    description: 'Public TOML files must not contain GitHub access tokens',
    run() {},
  },
  {
    id: SECURITY_SECRET_PRIVATE_KEY,
    category: 'security',
    severity: 'error',
    description: 'Public TOML files must not contain PEM private key blocks',
    run() {},
  },
  {
    id: SECURITY_SECRET_BEARER_TOKEN,
    category: 'security',
    severity: 'error',
    description: 'Public TOML files must not contain bearer tokens',
    run() {},
  },
  {
    id: SECURITY_SECRET_HIGH_ENTROPY,
    category: 'security',
    severity: 'error',
    description: 'Credential-looking fields must not hold high-entropy values',
    run() {},
  },
];

export const secretDetectorRuleIds: readonly string[] = secretDetectorRules.map((rule) => rule.id);
