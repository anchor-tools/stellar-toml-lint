/**
 * The external rule sources: what `--rules-dir` and `--plugin` accept, refuse,
 * and how a refused source surfaces to the person who typed the flag.
 *
 * The loader is the only part of the linter that runs code the project wrote, so
 * these tests are less about traversal — that is `semantic-rule-engine.test.ts` —
 * and more about the door: a module that is not a rule has to say so by name, and
 * a rule that conflicts with one already loaded has to lose, loudly. The CLI
 * section below the unit tests is what proves the door is actually wired to the
 * flags, including the parts that only exist in a subprocess: module resolution
 * against the working directory, and an exit code of 2 for a source that cannot
 * be used.
 */
import { afterAll, describe, expect, it } from 'vitest';
import { execFile } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { PluginLoadError, loadPluginRules } from '../src/engine/ruleLoader.js';
import { PluginRuleError } from '../src/engine/semanticRuleEngine.js';
import { allRules } from '../src/rules/index.js';

const run = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, '..', 'dist', 'cli.js');

const temps: string[] = [];

afterAll(async () => {
  await Promise.all(temps.map((dir) => rm(dir, { recursive: true, force: true })));
});

/** One rule as source text, valid in every field the loader checks. */
function ruleBody(id: string): string {
  return `{
  id: '${id}',
  category: 'currencies',
  severity: 'warning',
  description: 'A rule that exists to be loaded.',
  create: () => ({}),
}`;
}

/**
 * A directory of rule modules.
 *
 * `type: module` is declared so a `.js` file is read as ESM: outside this
 * package's own tree, Node has no other way to know which one the author meant,
 * and a test that failed on that would be testing Node rather than the loader.
 */
async function sourceDir(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'stellartoml-plugins-'));
  temps.push(dir);
  await writeFile(join(dir, 'package.json'), '{"type":"module"}\n');
  for (const [name, body] of Object.entries(files)) {
    if (name.includes('/')) {
      const nested = join(dir, dirname(name));
      await mkdir(nested, { recursive: true });
      await writeFile(join(dir, name), body);
    } else {
      await writeFile(join(dir, name), body);
    }
  }
  return dir;
}

/** The ids, in load order, that `sources` contributes. */
async function ids(sources: Parameters<typeof loadPluginRules>[0]): Promise<string[]> {
  return (await loadPluginRules(sources)).map((rule) => rule.id);
}

/** One rule's failure, so a rejection can be inspected rather than matched. */
async function failure(promise: Promise<unknown>): Promise<Error> {
  return promise.then(
    () => {
      throw new Error('expected the load to fail');
    },
    (error: unknown) => error as Error,
  );
}

describe('loadPluginRules', () => {
  it('loads a rule exported as the default', async () => {
    const dir = await sourceDir({ 'one.mjs': `export default ${ruleBody('acme/one')};\n` });
    expect(await ids({ dirs: [dir] })).toEqual(['acme/one']);
  });

  it('loads every rule in a `rules` array', async () => {
    const dir = await sourceDir({
      'many.mjs': `export const rules = [${ruleBody('acme/one')}, ${ruleBody('acme/two')}];\n`,
    });
    expect(await ids({ dirs: [dir] })).toEqual(['acme/one', 'acme/two']);
  });

  it('takes a default and a `rules` array from one module', async () => {
    const dir = await sourceDir({
      'both.mjs':
        `const extra = [${ruleBody('acme/two')}, ${ruleBody('acme/three')}];\n` +
        `export const rules = extra;\n` +
        `export default ${ruleBody('acme/one')};\n`,
    });
    expect(await ids({ dirs: [dir] })).toEqual(['acme/one', 'acme/two', 'acme/three']);
  });

  it('loads a CommonJS module that exports the rule directly', async () => {
    const dir = await sourceDir({});
    // `.cjs` is CommonJS wherever it sits, which is what makes this the CJS case.
    await writeFile(join(dir, 'legacy.cjs'), `module.exports = ${ruleBody('acme/legacy')};\n`);
    expect(await ids({ dirs: [dir] })).toEqual(['acme/legacy']);
  });

  it('passes over a module that exports nothing rule-shaped', async () => {
    const dir = await sourceDir({
      'helpers.mjs': 'export function codeOf(node) {\n  return node.code;\n}\n',
      'real.mjs': `export default ${ruleBody('acme/real')};\n`,
    });
    expect(await ids({ dirs: [dir] })).toEqual(['acme/real']);
  });

  it('reads the sources in the order they were given', async () => {
    const second = await sourceDir({ 'b.mjs': `export default ${ruleBody('acme/b')};\n` });
    const first = await sourceDir({ 'a.mjs': `export default ${ruleBody('acme/a')};\n` });
    const single = await sourceDir({ 'z.mjs': `export default ${ruleBody('acme/z')};\n` });

    expect(await ids({ dirs: [first, second], modules: [join(single, 'z.mjs')] })).toEqual([
      'acme/a',
      'acme/b',
      'acme/z',
    ]);
  });

  it('only scans module files, and only the ones it can name', async () => {
    const dir = await sourceDir({
      '10-second.mjs': `export default ${ruleBody('acme/ten')};\n`,
      '20-first.js': `export default ${ruleBody('acme/twenty')};\n`,
      'notes.md': '# written by hand, not loaded\n',
      'rules.ts': `export default ${ruleBody('acme/typescript')};\n`,
      '.swp.mjs': 'this file is not valid JavaScript at all ((',
      'nested/hidden.mjs': `export default ${ruleBody('acme/nested')};\n`,
    });
    // Sorted by name, so `10-second` lands before `20-first` and the run order is
    // readable straight off `ls` — and nothing outside the directory's top level.
    expect(await ids({ dirs: [dir] })).toEqual(['acme/ten', 'acme/twenty']);
  });

  it('refuses a rule that is missing its metadata and says where it came from', async () => {
    const dir = await sourceDir({
      'bad.mjs': 'export default { id: "acme/bad", create: () => ({}) };\n',
    });
    const error = await failure(loadPluginRules({ dirs: [dir] }));

    expect(error).toBeInstanceOf(PluginRuleError);
    expect((error as PluginRuleError).origin).toBe(`--rules-dir ${dir}`);
    expect((error as PluginRuleError).problems).toEqual([
      '`category` must be one of file, general, documentation, principals, currencies, validators, network, policy, sep12',
      '`severity` must be one of error, warning, info',
      '`description` must be a non-empty string',
    ]);
  });

  it('refuses an id a built-in rule already owns', async () => {
    const builtIn = allRules[0]!.id;
    const dir = await sourceDir({
      'clash.mjs': `export default ${ruleBody(builtIn)};\n`,
    });
    const error = await failure(loadPluginRules({ dirs: [dir], reservedIds: [builtIn] }));

    expect(error).toBeInstanceOf(PluginLoadError);
    expect(error.message).toContain(`already used by a built-in rule`);
    expect(error.message).toContain(`--rules-dir ${dir}`);
  });

  it('refuses an id a plugin loaded earlier already owns and names that source', async () => {
    const first = await sourceDir({ 'one.mjs': `export default ${ruleBody('acme/same')};\n` });
    const second = await sourceDir({ 'two.mjs': `export default ${ruleBody('acme/same')};\n` });
    const error = await failure(loadPluginRules({ dirs: [first, second] }));

    expect(error.message).toBe(
      `--rules-dir ${second} exports the rule id "acme/same", already used by --rules-dir ${first}.`,
    );
  });

  it('refuses a second rule with the same id inside one module', async () => {
    const dir = await sourceDir({
      'twice.mjs': `export const rules = [${ruleBody('acme/twice')}, ${ruleBody('acme/twice')}];\n`,
    });
    const error = await failure(loadPluginRules({ dirs: [dir] }));

    expect(error.message).toContain('already used by');
  });

  it('reports a missing rules directory by the name typed', async () => {
    const dir = join(await sourceDir({}), 'not-here');
    const error = await failure(loadPluginRules({ dirs: [dir] }));

    expect(error).toBeInstanceOf(PluginLoadError);
    expect(error.message).toBe(`Could not find rules directory "${dir}".`);
  });

  it('points a file given to --rules-dir at --plugin', async () => {
    const dir = await sourceDir({ 'one.mjs': `export default ${ruleBody('acme/one')};\n` });
    const file = join(dir, 'one.mjs');
    const error = await failure(loadPluginRules({ dirs: [file] }));

    expect(error.message).toBe(
      `Rules directory "${file}" is not a directory. Use --plugin to load a single module.`,
    );
  });

  it('loads a single module named by path', async () => {
    const dir = await sourceDir({ 'solo.mjs': `export default ${ruleBody('acme/solo')};\n` });
    const module = join(dir, 'solo.mjs');

    expect(await ids({ modules: [module] })).toEqual(['acme/solo']);
  });

  it('names the plugin when its module cannot be read', async () => {
    const dir = await sourceDir({});
    const path = join(dir, 'syntax-error.mjs');
    await writeFile(path, 'export default { id: oops;\n');

    const error = await failure(loadPluginRules({ modules: [path] }));

    expect(error).toBeInstanceOf(PluginLoadError);
    expect(error.message).toContain(`Could not load plugin "${path}"`);
    // The reason is the loader's own words, which differ between Node and the
    // test runner's transform. What the wrapper owes the reader is that it says
    // which plugin failed — the CLI section checks the text end to end.
    expect(error.message.length).toBeGreaterThan(`Could not load plugin "${path}": `.length);
  });

  it('leaves a bare specifier to the package resolver', async () => {
    const error = await failure(loadPluginRules({ modules: ['@stellartoml/no-such-plugin'] }));

    // The point is that the loader did not turn it into a path and look for it on
    // disk: the message that comes back is the resolver's own.
    expect(error.message).toContain('Cannot find package');
    expect(error.message).not.toContain(join(tmpdir(), '@stellartoml'));
  });

  it('resolves a plugin path against the working directory it was typed in', async () => {
    const dir = await sourceDir({
      'cwd-relative.mjs': `export default ${ruleBody('acme/relative')};\n`,
    });
    const spec = join(dir, 'cwd-relative.mjs');

    expect(await ids({ modules: [spec] })).toEqual(['acme/relative']);
  });

  it('takes a bare spec that names a file in the working directory as that file', async () => {
    // `--plugin my-rules.mjs` sits next to the person typing it. The spec has no
    // `./` and is not absolute, so the only thing that tells the loader it is a
    // file and not a package is that the path is there — which needs a real
    // working directory, hence a file in the repository for the length of one
    // test rather than a temporary directory elsewhere.
    const name = `tmp-cwd-plugin-${process.pid}.mjs`;
    const path = join(process.cwd(), name);
    await writeFile(path, `export default ${ruleBody('acme/here')};\n`);
    try {
      expect(await ids({ modules: [name] })).toEqual(['acme/here']);
    } finally {
      await rm(path, { force: true });
    }
  });

  it('names the plugin when its module throws something that is not an Error', async () => {
    const dir = await sourceDir({ 'thrower.mjs': "throw 'not a plugin you can use';\n" });
    const path = join(dir, 'thrower.mjs');

    const error = await failure(loadPluginRules({ modules: [path] }));

    expect(error).toBeInstanceOf(PluginLoadError);
    expect(error.message).toContain(`Could not load plugin "${path}": not a plugin you can use`);
  });
});

describe('plugin rules through the cli', () => {
  /** A rule that reports on the `EXPL` entry of `test/fixtures/valid.toml`. */
  function exclaimRule(id: string, severity = 'error'): string {
    return `export default {
  id: '${id}',
  category: 'currencies',
  severity: '${severity}',
  description: 'Flags Example Points for a team that does not want it listed.',
  create(ctx) {
    return {
      visitCurrency(node) {
        if (node.code === 'EXPL') {
          ctx.report({
            message: 'Example Points is not on this team\\u2019s approved list',
            path: node.path,
            position: node.position,
          });
        }
      },
    };
  },
};
`;
  }

  /** A directory holding one rule module, so several tests share the same shape. */
  async function pluginDir(source: string): Promise<string> {
    return sourceDir({ 'rule.mjs': source });
  }

  async function cli(
    args: string[],
    options: { cwd?: string } = {},
  ): Promise<{ code: number; stdout: string; stderr: string }> {
    try {
      const { stdout, stderr } = await run('node', [CLI, ...args], {
        env: { ...process.env, NO_COLOR: '1' },
        ...(options.cwd === undefined ? {} : { cwd: options.cwd }),
      });
      return { code: 0, stdout, stderr };
    } catch (error) {
      const e = error as { code?: number; stdout?: string; stderr?: string };
      return { code: e.code ?? 1, stdout: e.stdout ?? '', stderr: e.stderr ?? '' };
    }
  }

  interface JsonReport {
    ok: boolean;
    counts: Record<string, number>;
    diagnostics: { rule: string; severity: string; message: string; path?: string }[];
  }

  function report(stdout: string): JsonReport {
    return JSON.parse(stdout) as JsonReport;
  }

  const toml = join(here, 'fixtures', 'valid.toml');

  /** The no-false-positives fixture, for runs that need a file of their own. */
  async function validToml(): Promise<string> {
    return readFile(toml, 'utf8');
  }

  function ruleModule(id: string): string {
    return `export default ${ruleBody(id)};\n`;
  }

  it('runs a plugin rule beside the built-in catalog', async () => {
    const dir = await pluginDir(exclaimRule('acme/unapproved'));
    const { code, stdout } = await cli([toml, '--rules-dir', dir, '--format', 'json']);
    const parsed = report(stdout);

    // `valid.toml` is the no-false-positives fixture, so anything reported here
    // came from the plugin.
    expect(parsed.diagnostics).toEqual([
      {
        rule: 'acme/unapproved',
        severity: 'error',
        category: 'currencies',
        message: 'Example Points is not on this team’s approved list',
        path: 'CURRENCIES[1]',
        position: { line: 62, column: 1 },
      },
    ]);
    expect(parsed.ok).toBe(false);
    expect(code).toBe(1);
  });

  for (const spec of ['./rule.mjs', 'rule.mjs']) {
    it(`loads a rule by --plugin ${spec} from the working directory`, async () => {
      const dir = await sourceDir({
        'rule.mjs': exclaimRule('acme/relative'),
        'stellar.toml': await validToml(),
      });
      const { stdout, stderr } = await cli(['stellar.toml', '--plugin', spec, '--format', 'json'], {
        cwd: dir,
      });

      // Both spellings resolve against the directory the command was typed in.
      // Left to `import()`, `./rule.mjs` would resolve against `dist/` and the
      // other would go looking for an installed package called `rule.mjs`.
      expect(stderr).toContain('Loaded 1 plugin rule(s): acme/relative');
      expect(report(stdout).diagnostics.map((d) => d.rule)).toEqual(['acme/relative']);
    });
  }

  it('says which plugin rules it loaded', async () => {
    const dir = await pluginDir(
      `export const rules = [${ruleBody('acme/one')}, ${ruleBody('acme/two')}];\n`,
    );
    const { stdout, stderr } = await cli([toml, '--rules-dir', dir]);

    expect(stderr).toContain('Loaded 2 plugin rule(s): acme/one, acme/two');
    expect(stdout).not.toContain('acme/one');
  });

  it('stays quiet about the load under --quiet', async () => {
    const dir = await pluginDir(ruleModule('acme/quiet'));
    const { stderr } = await cli([toml, '--rules-dir', dir, '--quiet']);

    expect(stderr).not.toContain('Loaded');
  });

  it('exits 2 on a missing rules directory without reporting a file', async () => {
    const dir = join(await sourceDir({}), 'absent');
    const { code, stdout, stderr } = await cli([toml, '--rules-dir', dir]);

    expect(code).toBe(2);
    expect(stdout).toBe('');
    expect(stderr).toBe(`Could not find rules directory "${dir}".\n`);
  });

  it('exits 2 when a plugin exports something that is not a rule', async () => {
    const dir = await pluginDir('export default { id: "acme/half-a-rule" };\n');
    const { code, stdout, stderr } = await cli([toml, '--rules-dir', dir]);

    expect(code).toBe(2);
    expect(stdout).toBe('');
    expect(stderr).toContain('is not a usable rule');
    expect(stderr).toContain('`category` must be one of');
  });

  it('exits 2 when a plugin takes a built-in rule id', async () => {
    const dir = await pluginDir(ruleModule(allRules[0]!.id));
    const { code, stderr } = await cli([toml, '--rules-dir', dir]);

    expect(code).toBe(2);
    expect(stderr).toContain(`already used by a built-in rule`);
  });

  it('exits 2 when a plugin module throws while it is being imported', async () => {
    const dir = await pluginDir(
      `throw new Error('the keyring was not unlocked');\n${exclaimRule('acme/never')}`,
    );
    const { code, stdout, stderr } = await cli([toml, '--plugin', join(dir, 'rule.mjs')]);

    expect(code).toBe(2);
    expect(stdout).toBe('');
    expect(stderr).toContain('Could not load plugin');
    expect(stderr).toContain('the keyring was not unlocked');
  });

  it('still rejects an unknown rule id when plugins are in play', async () => {
    const dir = await pluginDir(exclaimRule('acme/approved-only'));
    const { code, stderr } = await cli([toml, '--rules-dir', dir, '--off', 'acme/approved-onlyy']);

    expect(code).toBe(2);
    expect(stderr).toContain('Unknown rule "acme/approved-onlyy"');
  });

  it('honours --off for a plugin rule', async () => {
    const dir = await pluginDir(exclaimRule('acme/unapproved'));
    const { stdout } = await cli([
      toml,
      '--rules-dir',
      dir,
      '--off',
      'acme/unapproved',
      '--format',
      'json',
    ]);

    expect(report(stdout).diagnostics).toEqual([]);
  });

  it('honours --warn for a plugin rule', async () => {
    const dir = await pluginDir(exclaimRule('acme/unapproved'));
    const { code, stdout } = await cli([
      toml,
      '--rules-dir',
      dir,
      '--warn',
      'acme/unapproved',
      '--format',
      'json',
    ]);
    const parsed = report(stdout);

    // The flag is spelled `--warn`; the severity token is `warning`. A run whose
    // summary counted `warning: NaN` failed this until the mapping was fixed.
    expect(parsed.diagnostics[0]!.severity).toBe('warning');
    expect(parsed.counts).toEqual({ error: 0, warning: 1, info: 0 });
    expect(code).toBe(0);
  });

  it('honours --error for a plugin rule declared as a warning', async () => {
    const dir = await pluginDir(exclaimRule('acme/unapproved', 'warning'));
    const { stdout } = await cli([
      toml,
      '--rules-dir',
      dir,
      '--error',
      'acme/unapproved',
      '--format',
      'json',
    ]);

    expect(report(stdout).counts).toEqual({ error: 1, warning: 0, info: 0 });
  });

  it('lets the project config set a plugin rule severity', async () => {
    const dir = await pluginDir(exclaimRule('acme/unapproved'));
    const work = await sourceDir({});
    await writeFile(join(work, 'stellar.toml'), await validToml());
    await writeFile(
      join(work, '.stellartomlrc.json'),
      JSON.stringify({ rules: { 'acme/unapproved': 'off' } }),
    );
    const { code, stdout, stderr } = await cli(
      ['stellar.toml', '--rules-dir', dir, '--format', 'json'],
      { cwd: work },
    );

    // Before the plugin ids reached `loadConfig`, this run died on
    // `Unknown rule "acme/unapproved" in .stellartomlrc.json`.
    expect(stderr).not.toContain('Unknown rule');
    expect(code).toBe(0);
    expect(report(stdout).diagnostics).toEqual([]);
  });

  it('keeps running when a plugin rule throws on one node', async () => {
    const dir = await pluginDir(`export default {
  id: 'acme/explodes',
  category: 'currencies',
  severity: 'error',
  description: 'A rule with a bug in it.',
  create() {
    return {
      visitCurrency() {
        throw new TypeError('cannot read properties of undefined');
      },
    };
  },
};
`);
    const { code, stdout } = await cli([toml, '--rules-dir', dir, '--format', 'json']);
    const parsed = report(stdout);

    expect(parsed.diagnostics).toEqual([
      expect.objectContaining({
        rule: 'internal/plugin-error',
        severity: 'warning',
        message: expect.stringContaining(
          'Plugin rule acme/explodes failed on 3 nodes: cannot read properties of undefined',
        ),
      }),
    ]);
    // A rule that cannot run is the plugin author's problem, not a failed deploy.
    expect(code).toBe(0);
  });

  it('loads the plugins once for a run of several files', async () => {
    const dir = await pluginDir(exclaimRule('acme/unapproved'));
    // Two distinct paths: identical arguments are collapsed before linting.
    const work = await sourceDir({
      'one.toml': await validToml(),
      'two.toml': await validToml(),
    });
    const { stdout, stderr } = await cli(['one.toml', 'two.toml', '--rules-dir', dir], {
      cwd: work,
    });

    expect(stdout.match(/acme\/unapproved/g) ?? []).toHaveLength(2);
    expect(stderr.match(/Loaded 1 plugin rule\(s\)/g) ?? []).toHaveLength(1);
  });
});
