/**
 * Project-level configuration: `.stellartomlrc.json`.
 *
 * Linter policy belongs next to the file it tunes — teams already keep
 * `stellar.toml` in-repo, so a config file beside it lets `--off`/`--warn`
 * chains be written once instead of repeated in every CI workflow, Makefile,
 * and pre-commit hook. The file is discovered by walking up from the linted
 * file's directory (from the current directory for stdin and `--domain`),
 * stopping at the filesystem root, so a repo-level config covers every file
 * beneath it.
 *
 * CLI flags always win over the file: the config supplies project defaults,
 * the command line records this run's intent.
 */
import { readFile, stat } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { allRules } from './rules/index.js';
import type { RuleOverrides } from './types.js';

/** The filename looked for, walking upward from the start directory. */
export const CONFIG_FILENAME = '.stellartomlrc.json';

/** The only top-level keys the file may carry; anything else is a typo. */
const KNOWN_KEYS: readonly string[] = ['rules', 'strict', 'maxWarnings', 'knownKeys'];

/** Severities a `rules` entry may take. */
const SEVERITIES: readonly string[] = ['off', 'error', 'warning', 'info'];

/** What a config file can set. CLI flags override each of these. */
export interface ProjectConfig {
  /** Per-rule severity overrides, keyed by rule id. */
  rules: RuleOverrides;
  /** Treat warnings as errors, like `--strict`. */
  strict: boolean;
  /** Fail when warnings exceed this count, like `--max-warnings`. */
  maxWarnings?: number;
  /**
   * Names accepted by `--detect-orphans` / `--prune-orphaned` as intentional,
   * like a repeated `--allow-key`. A project's vendor section is known to the
   * team, so the blessing belongs in the file next to the config rather than in
   * every CI invocation.
   */
  knownKeys?: string[];
}

/** One config file's parse result. Failures are cached too, so they are stable. */
type ParsedEntry = { ok: true; config: ProjectConfig } | { ok: false; error: Error };

/** Directory → the config file a walk from it reaches (`null` = none exists). */
const walkCache = new Map<string, string | null>();

/** Config file path + the run's plugin ids → its parse result, so each file is read once. */
const parseCache = new Map<string, ParsedEntry>();

/**
 * Loads the nearest `.stellartomlrc.json` for `startDir`, walking parents up
 * to the filesystem root. Resolves to an empty config when there is none.
 *
 * `pluginRuleIds` are the ids a run's `--rules-dir`/`--plugin` sources
 * contributed: a project should be able to set a third-party rule's severity in
 * the same file it tunes the built-ins with, and the only way to know those ids
 * exist is to have loaded them.
 *
 * Throws (so the CLI exits 2) when the file is malformed or names an unknown
 * rule: a config that is silently ignored is worse than one that fails, since
 * the team believes the policy is recorded.
 */
export async function loadConfig(
  startDir: string,
  pluginRuleIds: readonly string[] = [],
): Promise<ProjectConfig> {
  const path = await findConfig(resolve(startDir));
  if (path === null) return { rules: {}, strict: false };

  // The plugin ids are part of the key, not just an argument: the same file is a
  // different verdict depending on which third-party rule ids exist this run.
  const key = cacheKey(path, pluginRuleIds);
  let entry = parseCache.get(key);
  if (entry === undefined) {
    entry = await readAndParse(path, pluginRuleIds);
    parseCache.set(key, entry);
  }
  if (!entry.ok) throw entry.error;
  return entry.config;
}

/** A cached parse is only reusable for the exact rule id set it was validated against. */
function cacheKey(path: string, pluginRuleIds: readonly string[]): string {
  return pluginRuleIds.length === 0 ? path : `${path}\u0000${[...pluginRuleIds].sort().join(',')}`;
}

/**
 * The same "did you mean" rejection `--off`/`--warn`/`--error` give, applied to
 * config file rule ids, so a typo there fails as loudly as a typo on the CLI.
 * `source` names the file when the id came from a config, and `pluginRuleIds`
 * carries the ids loaded from plugins this run.
 */
export function assertKnownRule(
  id: string,
  source?: string,
  pluginRuleIds: readonly string[] = [],
): void {
  if (allRules.some((rule) => rule.id === id) || pluginRuleIds.includes(id)) return;
  const near = [...allRules.map((rule) => rule.id), ...pluginRuleIds]
    .filter((candidate) => candidate.includes(id) || id.includes(candidate.split('/')[1] ?? ''))
    .slice(0, 3);
  const where = source === undefined ? '' : ` in ${source}`;
  throw new Error(
    `Unknown rule "${id}"${where}.${near.length > 0 ? ` Did you mean: ${near.join(', ')}?` : ''} Run --list-rules to see them all.`,
  );
}

/** Walks from `startDir` to the filesystem root, looking for the config file. */
async function findConfig(startDir: string): Promise<string | null> {
  const traversed: string[] = [];
  let dir = startDir;

  for (;;) {
    traversed.push(dir);

    // A cached walk answers for every directory it passed through, so a second
    // lint in the same run never re-stats the chain.
    const known = walkCache.get(dir);
    if (known !== undefined) {
      rememberWalk(traversed, known);
      return known;
    }

    const candidate = join(dir, CONFIG_FILENAME);
    if (await isFile(candidate)) {
      rememberWalk(traversed, candidate);
      return candidate;
    }

    const parent = dirname(dir);
    if (parent === dir) {
      rememberWalk(traversed, null);
      return null;
    }
    dir = parent;
  }
}

function rememberWalk(dirs: string[], found: string | null): void {
  for (const dir of dirs) walkCache.set(dir, found);
}

async function isFile(path: string): Promise<boolean> {
  try {
    return (await stat(path)).isFile();
  } catch {
    return false;
  }
}

async function readAndParse(path: string, pluginRuleIds: readonly string[]): Promise<ParsedEntry> {
  try {
    const content = await readFile(path, 'utf8');
    return { ok: true, config: validate(path, content, pluginRuleIds) };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error : new Error(String(error)) };
  }
}

/** Parses and defensively validates one config file's contents. */
function validate(path: string, content: string, pluginRuleIds: readonly string[]): ProjectConfig {
  let raw: unknown;
  try {
    raw = JSON.parse(content);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`Malformed JSON in ${path}: ${detail}`, { cause: error });
  }

  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new Error(`${path} must contain a JSON object.`);
  }
  const source = raw as Record<string, unknown>;

  const unknownKeys = Object.keys(source).filter((key) => !KNOWN_KEYS.includes(key));
  if (unknownKeys.length > 0) {
    throw new Error(
      `${path} contains unknown field${unknownKeys.length > 1 ? 's' : ''}: ${unknownKeys.join(', ')}. Expected ${KNOWN_KEYS.join(', ')}.`,
    );
  }

  const rules: RuleOverrides = {};
  if (source.rules !== undefined) {
    if (typeof source.rules !== 'object' || source.rules === null || Array.isArray(source.rules)) {
      throw new Error(`${path}: "rules" must be an object mapping rule ids to severities.`);
    }
    for (const [id, value] of Object.entries(source.rules as Record<string, unknown>)) {
      assertKnownRule(id, path, pluginRuleIds);
      if (value === 'off' || value === 'error' || value === 'warning' || value === 'info') {
        rules[id] = value;
      } else {
        throw new Error(
          `${path}: rule "${id}" has severity ${JSON.stringify(value)}. Expected one of ${SEVERITIES.join(', ')}.`,
        );
      }
    }
  }

  let strict = false;
  if (source.strict !== undefined) {
    if (typeof source.strict !== 'boolean') {
      throw new Error(`${path}: "strict" must be a boolean.`);
    }
    strict = source.strict;
  }

  let maxWarnings: number | undefined;
  if (source.maxWarnings !== undefined) {
    const value = source.maxWarnings;
    if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
      throw new Error(`${path}: "maxWarnings" must be a non-negative integer.`);
    }
    maxWarnings = value;
  }

  let knownKeys: string[] | undefined;
  if (source.knownKeys !== undefined) {
    const value = source.knownKeys;
    if (!Array.isArray(value) || value.some((name) => typeof name !== 'string')) {
      throw new Error(`${path}: "knownKeys" must be an array of key names.`);
    }
    knownKeys = [...(value as string[])];
  }

  const config: ProjectConfig = {
    rules,
    strict,
    ...(maxWarnings === undefined ? {} : { maxWarnings }),
    ...(knownKeys === undefined ? {} : { knownKeys }),
  };
  // Callers merge into fresh objects; freezing catches accidental mutation of
  // the cached instance that every file in a multi-file run shares.
  Object.freeze(config.rules);
  if (config.knownKeys !== undefined) Object.freeze(config.knownKeys);
  return Object.freeze(config);
}
