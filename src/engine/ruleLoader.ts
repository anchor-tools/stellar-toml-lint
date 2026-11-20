/**
 * Loads plugin rules from outside the package.
 *
 * `--rules-dir <dir>` reads every JavaScript module in a directory; `--plugin
 * <name>` reads one module by package name or path. Both feed the same
 * validator, and both are the only place the linter touches the filesystem on a
 * rule's behalf — which is why this sits apart from
 * {@link ./semanticRuleEngine.ts}, which stays free of Node built-ins so it can
 * be embedded anywhere the browser bundle runs.
 *
 * A rule module is arbitrary code the user asked for by path or by name, and it
 * runs with this process's permissions. That is the feature: a team that wants
 * its own checks has to be able to write them in TypeScript, shell out, or read
 * a policy file. It is also why nothing here is discovered on its own — no
 * `node_modules` scan, no autoload of a directory beside `stellar.toml`. Rules
 * run because a human named them on the command line.
 *
 * Failure policy follows `.stellartomlrc.json`: a plugin that cannot be read or
 * does not hold a usable rule is a hard error rather than a warning, because a
 * silently ignored rule is a check the team believes it has and does not. A rule
 * that throws *while running* is different — that one is contained by the engine
 * so a bad Friday deploy does not stop the pipeline.
 */
import { readdir, stat } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { assertSemanticRule, type SemanticRule } from './semanticRuleEngine.js';

/** Module extensions a rules directory is scanned for. */
const MODULE_EXTENSION = /\.(?:js|mjs|cjs)$/;

/** Where a plugin rule came from, for the message that says why it was refused. */
export interface PluginSources {
  /** Directories whose modules each export plugin rules. */
  dirs?: readonly string[];
  /** Package names, or paths to a single module. */
  modules?: readonly string[];
  /** Rule ids a plugin may not take, so `--off` keeps naming exactly one rule. */
  reservedIds?: readonly string[];
}

/** Thrown for a source that cannot be read or holds a rule that cannot be used. */
export class PluginLoadError extends Error {
  constructor(message: string, cause?: unknown) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'PluginLoadError';
  }
}

/**
 * Reads every rule the sources export, in the order they were given.
 *
 * @throws {PluginLoadError} when a source is missing, cannot be imported,
 * exports something rule-shaped but invalid, or takes an id already in use.
 */
export async function loadPluginRules(sources: PluginSources = {}): Promise<SemanticRule[]> {
  const dirs = sources.dirs ?? [];
  const modules = sources.modules ?? [];
  const reserved = new Set(sources.reservedIds ?? []);
  const loaded: SemanticRule[] = [];
  const owners = new Map<string, string>();

  for (const dir of dirs) {
    const origin = `--rules-dir ${dir}`;
    for (const file of await ruleModulesIn(dir)) {
      const module = await importModule(pathToFileURL(file).href, file);
      collect(module, origin, owners, loaded, reserved);
    }
  }
  for (const specifier of modules) {
    const origin = `--plugin ${specifier}`;
    collect(
      await importModule(await moduleSpecifier(specifier), specifier),
      origin,
      owners,
      loaded,
      reserved,
    );
  }
  return loaded;
}

/**
 * Adds every rule one module exports.
 *
 * A module may export one rule as its default, an array as `rules`, or both; a
 * module exporting nothing rule-shaped at all is passed over, because a shared
 * helper file in a rules directory is normal and refusing it would make the
 * directory unusable.
 */
function collect(
  mod: unknown,
  origin: string,
  owners: Map<string, string>,
  out: SemanticRule[],
  reserved: ReadonlySet<string>,
): void {
  for (const candidate of exportsOf(mod)) {
    const rule = assertSemanticRule(candidate, origin);
    const takenBy = reserved.has(rule.id) ? 'a built-in rule' : owners.get(rule.id);
    if (takenBy !== undefined) {
      throw new PluginLoadError(
        `${origin} exports the rule id "${rule.id}", already used by ${takenBy}.`,
      );
    }
    owners.set(rule.id, origin);
    out.push(rule);
  }
}

/** The rule-shaped exports of one module: its default and its `rules`, either a rule or a list. */
function exportsOf(mod: unknown): unknown[] {
  if (typeof mod !== 'object' || mod === null) return [];
  const record = mod as Record<string, unknown>;
  const out: unknown[] = [];
  for (const value of [record.default, record.rules]) {
    if (Array.isArray(value)) out.push(...value);
    else if (value !== undefined && value !== null) out.push(value);
  }
  return out;
}

/**
 * The `.js`, `.mjs` and `.cjs` files directly in `dir`, by name.
 *
 * One level, sorted: a directory of plugins is small and the order the rules run
 * in should be readable off `ls`, not off a walk. A subdirectory is a place for
 * a helper module, not a second plugin source.
 */
async function ruleModulesIn(dir: string): Promise<string[]> {
  const path = resolve(dir);
  const info = await stat(path).catch(() => undefined);
  if (info === undefined) {
    throw new PluginLoadError(`Could not find rules directory "${dir}".`);
  }
  // Named rather than left to `readdir`, whose raw ENOTDIR says nothing about
  // the flag that does take a file.
  if (!info.isDirectory()) {
    throw new PluginLoadError(
      `Rules directory "${dir}" is not a directory. Use --plugin to load a single module.`,
    );
  }
  const entries = await readdir(path, { withFileTypes: true });
  return entries
    .filter(
      (entry) => entry.isFile() && MODULE_EXTENSION.test(entry.name) && !entry.name.startsWith('.'),
    )
    .map((entry) => join(path, entry.name))
    .sort();
}

/**
 * Turns a `--plugin` value into something `import()` accepts.
 *
 * A relative path resolves against the working directory the command was typed
 * in, not against this file's own directory inside `dist/`, which is what a bare
 * `import('./x.js')` would do. Anything that is not a path is left alone for the
 * package resolver.
 */
async function moduleSpecifier(spec: string): Promise<string> {
  const looksLikePath = spec.startsWith('./') || spec.startsWith('../') || isAbsolute(spec);
  if (looksLikePath) return pathToFileURL(resolve(spec)).href;
  if (await exists(resolve(spec))) return pathToFileURL(resolve(spec)).href;
  return spec;
}

async function importModule(target: string, described: string): Promise<unknown> {
  try {
    return await import(target);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new PluginLoadError(`Could not load plugin "${described}": ${detail}`, error);
  }
}

async function exists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}
