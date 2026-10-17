/**
 * Client-side ZIP archive unpacker and multi-tenant batch validator.
 *
 * Reads a `stellar.toml`-containing ZIP entirely in memory (no upload),
 * lints every `*.toml` it finds with a bounded concurrency pool, and returns
 * an aggregate batch summary. Intended for the web playground and any other
 * browser-based tooling that audits many anchors offline.
 */

import JSZip from 'jszip';
import { lintBrowser, type BrowserLintOptions } from '../browser.js';
import type { LintResult } from '../types.js';

/** One file's lint outcome within a batch. */
export interface ZipFileResult {
  /** Name of the file as stored in the archive. */
  name: string;
  /** Full path within the archive. */
  path: string;
  result: LintResult;
}

/** An error rule that recurses across multiple files in the batch. */
export interface CommonError {
  rule: string;
  /** Number of diagnostics carrying this rule across the batch. */
  count: number;
  /** Distinct archive paths that produced this rule. */
  files: string[];
}

/** Aggregate outcome of validating every TOML in a ZIP. */
export interface BatchSummary {
  totalFiles: number;
  passed: number;
  failed: number;
  passRate: number;
  totalErrors: number;
  totalWarnings: number;
  totalInfos: number;
  commonErrors: CommonError[];
  results: ZipFileResult[];
}

/** Options for {@link validateZip}. */
export interface ZipValidatorOptions extends BrowserLintOptions {
  /** Maximum number of files linted concurrently (the worker pool size). */
  concurrency?: number;
}

const DEFAULT_CONCURRENCY = 4;

/** Lints every `*.toml` in `buffer` and returns an aggregate batch summary. */
export async function validateZip(
  buffer: ArrayBuffer | Uint8Array,
  options: ZipValidatorOptions = {},
): Promise<BatchSummary> {
  const { concurrency = DEFAULT_CONCURRENCY, ...lintOptions } = options;

  const zip = await JSZip.loadAsync(buffer);
  const tomlFiles: Array<{ name: string; path: string; getContent: () => Promise<string> }> = [];

  for (const [path, entry] of Object.entries(zip.files)) {
    if (entry.dir || !path.endsWith('.toml')) continue;
    tomlFiles.push({
      name: path.split('/').pop() ?? path,
      path,
      getContent: () => entry.async('text'),
    });
  }

  const results = await mapConcurrency(tomlFiles, concurrency, async (file) => {
    const content = await file.getContent();
    const result = await lintBrowser(content, lintOptions);
    return { name: file.name, path: file.path, result };
  });

  let passed = 0;
  let failed = 0;
  let totalErrors = 0;
  let totalWarnings = 0;
  let totalInfos = 0;

  const ruleToCount = new Map<string, number>();
  const ruleToFiles = new Map<string, Set<string>>();

  for (const { path, result } of results) {
    if (result.ok) passed += 1;
    else failed += 1;
    totalErrors += result.counts['error'];
    totalWarnings += result.counts['warning'];
    totalInfos += result.counts['info'];

    for (const diag of result.diagnostics) {
      if (diag.severity !== 'error') continue;
      ruleToCount.set(diag.rule, (ruleToCount.get(diag.rule) ?? 0) + 1);
      const files = ruleToFiles.get(diag.rule);
      if (files === undefined) {
        ruleToFiles.set(diag.rule, new Set([path]));
      } else {
        files.add(path);
      }
    }
  }

  const commonErrors = [...ruleToCount.entries()]
    .map(([rule, count]) => ({
      rule,
      count,
      files: [...(ruleToFiles.get(rule) ?? new Set())].sort(),
    }))
    .sort((a, b) => b.count - a.count || a.rule.localeCompare(b.rule));

  return {
    totalFiles: results.length,
    passed,
    failed,
    passRate: results.length === 0 ? 0 : Math.round((passed / results.length) * 100),
    totalErrors,
    totalWarnings,
    totalInfos,
    commonErrors,
    results,
  };
}

function mapConcurrency<T, U>(
  items: T[],
  concurrency: number,
  mapper: (item: T) => Promise<U>,
): Promise<U[]> {
  const results: U[] = new Array(items.length);
  let next = 0;
  let running = 0;
  let done = 0;

  return new Promise<U[]>((resolve, reject) => {
    const tick = (): void => {
      while (running < concurrency && next < items.length) {
        const index = next++;
        const item = items[index];
        if (item === undefined) continue;
        running += 1;
        mapper(item).then(
          (value) => {
            results[index] = value;
            finish();
          },
          (error) => {
            reject(error);
          },
        );
      }
      if (running === 0 && done === items.length) resolve(results);
    };

    const finish = (): void => {
      running -= 1;
      done += 1;
      tick();
    };

    tick();
  });
}
