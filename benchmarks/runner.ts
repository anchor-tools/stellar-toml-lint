import { lint } from '../src/lint.js';
import { performance } from 'perf_hooks';
import { mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';

const BENCHMARK_DIR = join(process.cwd(), 'benchmarks', 'fixtures');
const THRESHOLDS = {
  '10KB': 5,
  '100KB': 20,
  '1MB': 50,
  '5MB': 200,
};
const LINE_THRESHOLD_MS = 50;

interface BenchmarkResult {
  label: string;
  fileSize: number;
  lineCount: number;
  parseTimeMs: number;
  lintTimeMs: number;
  memoryMb: number;
  passed: boolean;
}

function generateTOML(entryCount: number): string {
  const lines: string[] = [];
  lines.push('VERSION = "1.0"');
  lines.push(`NETWORK_PASSPHRASE = "Public Global Stellar Network ; September 2015"`);
  lines.push(`SIGNING_KEY = "GAIU5J3XK7K4VJQZ6X5Y3K2M1N0P9Q8R7S6T5U4V3W2X1Y0Z"`);
  lines.push(`DOMAIN = "example.com"`);
  lines.push('');
  lines.push('[DOCUMENTATION]');
  lines.push('ORG_NAME = "Example Anchor"');
  lines.push('ORG_URL = "https://example.com"');
  lines.push('ORG_EMAIL = "admin@example.com"');
  lines.push('');
  lines.push('[[CURRENCIES]]');
  lines.push('CODE = "USD"');
  lines.push('ISSUER = "GAIU5J3XK7K4VJQZ6X5Y3K2M1N0P9Q8R7S6T5U4V3W2X1Y0Z"');
  lines.push('STATUS = "active"');
  lines.push('ANCHOR_ASSET_TYPE = "fiat"');
  lines.push('DISPLAY_DECIMALS = 7');
  lines.push('');

  for (let i = 0; i < entryCount; i++) {
    lines.push(`[[CURRENCIES]]`);
    lines.push(`CODE = "ASSET_${i}"`);
    lines.push(`ISSUER = "GAIU5J3XK7K4VJQZ6X5Y3K2M1N0P9Q8R7S6T5U4V3W2X1Y0Z"`);
    lines.push('STATUS = "active"');
    lines.push('ANCHOR_ASSET_TYPE = "fiat"');
    lines.push('DISPLAY_DECIMALS = 7');
    lines.push('');

    lines.push(`[[VALIDATORS]]`);
    lines.push(`ALIAS = "validator_${i}"`);
    lines.push(`PUBLIC_KEY = "GAIU5J3XK7K4VJQZ6X5Y3K2M1N0P9Q8R7S6T5U4V3W2X1Y0Z"`);
    lines.push(`HOST = "validator-${i}.example.com:11625"`);
    lines.push('');
  }

  lines.push('[PRINCIPALS]');
  lines.push('NAME = "Example Principal"');
  lines.push('EMAIL = "principal@example.com"');

  return lines.join('\n');
}

function getFileSizeCategory(content: string): string {
  const bytes = Buffer.byteLength(content, 'utf8');
  if (bytes < 10 * 1024) return '10KB';
  if (bytes < 100 * 1024) return '100KB';
  if (bytes < 1024 * 1024) return '1MB';
  return '5MB';
}

function getLineCount(content: string): number {
  return content.split('\n').length;
}

function getMemoryUsage(): number {
  const usage = process.memoryUsage();
  return usage.heapUsed / (1024 * 1024);
}

function benchmark(label: string, content: string): BenchmarkResult {
  const startMemory = getMemoryUsage();
  const parseStart = performance.now();
  lint(content);
  const parseEnd = performance.now();
  const endMemory = getMemoryUsage();

  const parseTimeMs = parseEnd - parseStart;
  const memoryMb = endMemory - startMemory;
  const fileSize = Buffer.byteLength(content, 'utf8');
  const lineCount = getLineCount(content);

  const category = getFileSizeCategory(content);
  const threshold = THRESHOLDS[category as keyof typeof THRESHOLDS] ?? 200;
  const passed = parseTimeMs < threshold;

  return {
    label,
    fileSize,
    lineCount,
    parseTimeMs: Math.round(parseTimeMs * 100) / 100,
    lintTimeMs: Math.round(parseTimeMs * 100) / 100,
    memoryMb: Math.round(memoryMb * 100) / 100,
    passed,
  };
}

function runBenchmarks(): void {
  mkdirSync(BENCHMARK_DIR, { recursive: true });

  const configs = [
    { name: 'small', entryCount: 1 },
    { name: 'medium', entryCount: 10 },
    { name: 'large', entryCount: 100 },
    { name: 'xlarge', entryCount: 1000 },
  ];

  console.log('='.repeat(80));
  console.log('stellar-toml-lint Performance Benchmarks');
  console.log('='.repeat(80));
  console.log('');

  const results: BenchmarkResult[] = [];

  for (const config of configs) {
    const content = generateTOML(config.entryCount);
    const result = benchmark(config.name, content);
    results.push(result);

    const status = result.passed ? 'PASS' : 'FAIL';
    console.log(
      `[${status}] ${result.label.padEnd(10)} | Lines: ${String(result.lineCount).padStart(6)} | Size: ${(result.fileSize / 1024).toFixed(1)}KB | Time: ${result.parseTimeMs.toFixed(2)}ms | Memory: ${result.memoryMb.toFixed(2)}MB`,
    );
  }

  console.log('');
  console.log('-'.repeat(80));
  console.log('Regression Thresholds (< 50ms per 1,000 lines):');
  console.log('-'.repeat(80));

  const allPassed = results.every((r) => r.passed);
  const xlargeResult = results.find((r) => r.label === 'xlarge');
  if (xlargeResult) {
    const msPer1000Lines = (xlargeResult.parseTimeMs / xlargeResult.lineCount) * 1000;
    console.log(
      `  ${msPer1000Lines.toFixed(2)}ms per 1,000 lines (threshold: ${LINE_THRESHOLD_MS}ms)`,
    );
    const linePassed = msPer1000Lines < LINE_THRESHOLD_MS;
    if (!linePassed) {
      console.log('  WARNING: Performance regression detected!');
    }
  }

  if (!allPassed) {
    console.log('');
    console.log('ERROR: Some benchmarks exceeded their thresholds!');
    process.exit(1);
  }

  console.log('');
  console.log('All benchmarks passed!');

  rmSync(BENCHMARK_DIR, { recursive: true, force: true });
}

runBenchmarks();
