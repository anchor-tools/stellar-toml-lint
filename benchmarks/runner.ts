import { lint } from '../src/lint.js';
import { SemanticRuleEngine } from '../src/engine/semanticRuleEngine.js';
import type { AstVisitor, PluginContext, SemanticRule } from '../src/engine/semanticRuleEngine.js';
import { parse } from 'smol-toml';
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

/**
 * The plugin rule budget: a hundred-plus rules have to run inside one traversal,
 * not one traversal each, so the whole set costs less than a single extra parse.
 */
const RULE_COUNT = 120;
const RULES_THRESHOLD_MS = 10;

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

/**
 * `count` rules shaped like the ones a team writes: read the identity fields off
 * a currency, test a string value, and keep a tally across a table's keys.
 */
function generateRules(count: number): SemanticRule[] {
  const makeVisitor =
    (index: number) =>
    (ctx: PluginContext): AstVisitor => {
      let characters = 0;
      return {
        visitCurrency: (node) => {
          if (node.code === 'ASSET_0' && node.status !== 'live') {
            ctx.report({ message: `rule ${index} saw an inactive asset`, path: node.path });
          }
        },
        visitKeyValue: (node) => {
          if (typeof node.value === 'string') characters += node.value.length;
        },
        leaveTable: (node) => {
          if (characters > 512) {
            ctx.report({ message: `rule ${index} saw an unusually long table`, path: node.path });
          }
          characters = 0;
        },
      };
    };

  return Array.from({ length: count }, (_unused, index) => ({
    id: `bench/rule-${index}`,
    category: 'currencies' as const,
    severity: 'warning' as const,
    description: 'A rule that costs about what a real rule costs.',
    create: makeVisitor(index),
  }));
}

function median(samples: number[]): number {
  const sorted = [...samples].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)] ?? Number.NaN;
}

/**
 * Times one engine run over `content`: the walk plus the 120 visitors it builds.
 *
 * The median of a dozen samples, because a single run on a laptop is more noise
 * than signal and this number is a gate.
 */
function benchmarkRules(content: string): { ms: number; passed: boolean } {
  const doc = parse(content) as Record<string, unknown>;
  const engine = new SemanticRuleEngine(generateRules(RULE_COUNT));

  for (let warm = 0; warm < 5; warm++) engine.run({ doc, source: content });

  const samples: number[] = [];
  for (let attempt = 0; attempt < 12; attempt++) {
    const start = performance.now();
    engine.run({ doc, source: content });
    samples.push(performance.now() - start);
  }

  const ms = median(samples);
  return { ms, passed: ms < RULES_THRESHOLD_MS };
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
  console.log(
    `Plugin rules: ${RULE_COUNT} rules over one traversal (threshold: ${RULES_THRESHOLD_MS}ms)`,
  );
  console.log('-'.repeat(80));

  // The "large" document, which is the size a real anchor's file reaches: a
  // hundred assets and a hundred validators.
  const largeDoc = generateTOML(100);
  const rules = benchmarkRules(largeDoc);
  console.log(
    `  [${rules.passed ? 'PASS' : 'FAIL'}] ${String(RULE_COUNT).padStart(3)} rules over ${String(
      getLineCount(largeDoc),
    ).padStart(5)} lines | median ${rules.ms.toFixed(2)}ms per run | ${(
      rules.ms / RULE_COUNT
    ).toFixed(3)}ms per rule`,
  );
  if (!rules.passed) {
    console.log('  WARNING: rule traversal regression detected!');
  }
  // The same set over ten times as much file, printed so the shape of the curve
  // is visible and a future change that makes the engine pay per rule rather than
  // per node cannot hide inside the gated document. This line is not a threshold.
  const hugeDoc = generateTOML(1000);
  const huge = benchmarkRules(hugeDoc);
  console.log(
    `          same rules over ${String(getLineCount(hugeDoc)).padStart(5)} lines (not gated) | median ${huge.ms.toFixed(2)}ms per run`,
  );
  console.log('');

  console.log('-'.repeat(80));
  console.log('Regression Thresholds (< 50ms per 1,000 lines):');
  console.log('-'.repeat(80));

  const allPassed = results.every((r) => r.passed) && rules.passed;
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
