/**
 * Browser bundle boundary verifier.
 *
 * The browser entry points (`dist/browser/index.js`, the UMD build, and the
 * worker bundle) must run in a page and in a Worker, where `node:fs`,
 * `node:crypto`, and friends do not exist. A dependency that reaches for one
 * makes Vite or Webpack fail the consumer's build with a cryptic resolve error,
 * so the package checks its own artifacts before publishing.
 *
 * `BrowserBoundaryVerifier` scans the emitted bundles for Node built-ins, for
 * Node-only globals, and for crypto code that bypasses
 * `globalThis.crypto.subtle`. It also enforces an uncompressed size budget,
 * because a bundle regression is a browser boundary failure too.
 */

export type BrowserBoundaryCode =
  | 'browser/node-builtin'
  | 'browser/node-global'
  | 'browser/crypto-polyfill'
  | 'browser/bundle-too-large'
  | 'browser/missing-artifact';

export interface BrowserBoundaryFinding {
  code: BrowserBoundaryCode;
  severity: 'error' | 'warning';
  path: string;
  message: string;
  suggestion: string;
  /** Matched text or specifier, when there is one. */
  detail?: string;
}

export interface BundleArtifact {
  path: string;
  source: string;
  /** Compressed/uncompressed size; defaults to the UTF-8 byte length. */
  bytes?: number;
}

export interface BrowserBoundaryOptions {
  /** Maximum uncompressed bytes per bundle (250KB by default). */
  maxBundleBytes?: number;
  /** Artifacts that must exist; missing ones are errors. */
  requiredFiles?: string[];
}

export interface BrowserBoundaryReport {
  ok: boolean;
  findings: BrowserBoundaryFinding[];
  artifacts: { path: string; bytes: number; clean: boolean }[];
  totalBytes: number;
}

const DEFAULT_MAX_BYTES = 250 * 1024;

/** Node core modules that have no browser equivalent. */
export const NODE_BUILTINS = [
  'assert',
  'buffer',
  'child_process',
  'cluster',
  'crypto',
  'dgram',
  'dns',
  'fs',
  'http',
  'https',
  'net',
  'os',
  'path',
  'process',
  'readline',
  'stream',
  'tls',
  'tty',
  'url',
  'util',
  'v8',
  'vm',
  'worker_threads',
  'zlib',
] as const;

const NODE_GLOBALS = ['process.', 'Buffer.', '__dirname', '__filename', 'require('];

const CRYPTO_NODE_PATTERN = /\b(?:node:)?crypto\b/g;
const WEB_CRYPTO_PATTERN = /(?:globalThis\.)?crypto\s*\.\s*subtle/;

function byteLength(source: string): number {
  return new TextEncoder().encode(source).length;
}

function lineAt(source: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < source.length; i++) {
    if (source.charCodeAt(i) === 10) line++;
  }
  return line;
}

/** All `from '...'` / `import('...')` / `require('...')` specifiers. */
export function extractBundleSpecifiers(source: string): { specifier: string; line: number }[] {
  const found: { specifier: string; line: number }[] = [];
  const patterns = [
    /\bfrom\s*['"]([^'"]+)['"]/g,
    /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
    /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
  ];
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) {
      const specifier = match[1];
      if (specifier === undefined) continue;
      found.push({ specifier, line: lineAt(source, match.index ?? 0) });
    }
  }
  return found;
}

/** `node:` specifiers and bare names that resolve to a Node core module. */
export function isNodeBuiltin(specifier: string): boolean {
  const bare = specifier.startsWith('node:') ? specifier.slice('node:'.length) : specifier;
  const root = bare.split('/')[0] ?? bare;
  return (NODE_BUILTINS as readonly string[]).includes(root);
}

export class BrowserBoundaryVerifier {
  private readonly maxBundleBytes: number;
  private readonly requiredFiles: string[];

  constructor(options: BrowserBoundaryOptions = {}) {
    this.maxBundleBytes = options.maxBundleBytes ?? DEFAULT_MAX_BYTES;
    this.requiredFiles = options.requiredFiles ?? [];
  }

  verify(artifacts: BundleArtifact[]): BrowserBoundaryReport {
    const findings: BrowserBoundaryFinding[] = [];
    const summaries: BrowserBoundaryReport['artifacts'] = [];
    let totalBytes = 0;

    for (const required of this.requiredFiles) {
      if (!artifacts.some((artifact) => artifact.path === required)) {
        findings.push({
          code: 'browser/missing-artifact',
          severity: 'error',
          path: required,
          message: `${required} is missing from the browser build output`,
          suggestion: 'Run `npm run build` before verifying the browser boundary.',
        });
      }
    }

    for (const artifact of artifacts) {
      const bytes = artifact.bytes ?? byteLength(artifact.source);
      totalBytes += bytes;
      const before = findings.length;

      findings.push(...this.checkSource(artifact.path, artifact.source));

      if (bytes > this.maxBundleBytes) {
        findings.push({
          code: 'browser/bundle-too-large',
          severity: 'error',
          path: artifact.path,
          message: `${artifact.path} is ${(bytes / 1024).toFixed(1)}KB, above the ${(this.maxBundleBytes / 1024).toFixed(0)}KB browser budget`,
          suggestion: 'Tree-shake the browser entry point or raise the budget deliberately.',
          detail: String(bytes),
        });
      }

      summaries.push({ path: artifact.path, bytes, clean: findings.length === before });
    }

    return {
      ok: findings.every((finding) => finding.severity !== 'error'),
      findings,
      artifacts: summaries,
      totalBytes,
    };
  }

  /** Static import and API analysis for one emitted file. */
  checkSource(path: string, source: string): BrowserBoundaryFinding[] {
    const findings: BrowserBoundaryFinding[] = [];

    for (const { specifier, line } of extractBundleSpecifiers(source)) {
      if (!isNodeBuiltin(specifier)) continue;
      findings.push({
        code: 'browser/node-builtin',
        severity: 'error',
        path,
        detail: specifier,
        message: `${path}:${line} imports Node built-in "${specifier}"`,
        suggestion: 'Remove the dependency or provide a browser implementation.',
      });
    }

    for (const global of NODE_GLOBALS) {
      const index = source.indexOf(global);
      if (index === -1) continue;
      // `require(` is only a problem when it is not the bundler's own shim of a
      // browser module, so report it once with the first occurrence.
      findings.push({
        code: 'browser/node-global',
        severity: 'error',
        path,
        detail: global,
        message: `${path}:${lineAt(source, index)} uses Node-only global "${global.replace(/[.(]$/, '')}"`,
        suggestion: 'Guard the code path or replace it with a Web API.',
      });
    }

    // Crypto: a `node:crypto` import is already caught above; this catches a
    // bundled polyfill that pre-empts `globalThis.crypto.subtle`.
    if (CRYPTO_NODE_PATTERN.test(source) && !WEB_CRYPTO_PATTERN.test(source)) {
      const index = source.search(CRYPTO_NODE_PATTERN);
      findings.push({
        code: 'browser/crypto-polyfill',
        severity: 'warning',
        path,
        detail: 'crypto',
        message: `${path}:${lineAt(source, Math.max(index, 0))} references crypto without Web Crypto`,
        suggestion: 'Use `globalThis.crypto.subtle` rather than a Node crypto binding.',
      });
    }

    return findings;
  }
}

export function renderBrowserBoundaryReport(report: BrowserBoundaryReport): string {
  const lines: string[] = [];
  lines.push(
    `Browser bundle boundary: ${report.ok ? 'clean' : 'FAILED'} (${(report.totalBytes / 1024).toFixed(1)}KB total)`,
  );
  for (const artifact of report.artifacts) {
    lines.push(
      `  ${artifact.clean ? 'ok  ' : 'fail'}  ${artifact.path}  ${(artifact.bytes / 1024).toFixed(1)}KB`,
    );
  }
  if (report.findings.length > 0) {
    lines.push('');
    for (const finding of report.findings) {
      lines.push(`  ${finding.severity}  ${finding.code}  ${finding.message}`);
      lines.push(`         fix: ${finding.suggestion}`);
    }
  }
  return `${lines.join('\n')}\n`;
}
