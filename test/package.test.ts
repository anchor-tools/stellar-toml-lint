import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { load } from 'js-yaml';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const read = (...parts: string[]): string => readFileSync(join(root, ...parts), 'utf8');

const pkg = JSON.parse(read('package.json'));

describe('package metadata', () => {
  it('keeps the CLI version in step with package.json', () => {
    // The CLI cannot import package.json at runtime without shipping it, so the
    // version is duplicated as a constant. This test is what keeps them honest.
    const cli = read('src', 'cli.ts');
    const declared = /const VERSION = '([^']+)'/.exec(cli)?.[1];
    expect(declared).toBe(pkg.version);
  });

  it('declares the two runtime dependencies and no more', () => {
    // This tool runs inside other people's CI, so dependency growth is a
    // deliberate decision rather than an accident.
    expect(Object.keys(pkg.dependencies).sort()).toEqual(['@stellar/stellar-base', 'smol-toml']);
  });

  it('publishes the built output and the license', () => {
    expect(pkg.files).toContain('dist');
    expect(pkg.files).toContain('LICENSE');
    expect(pkg.license).toBe('Apache-2.0');
  });

  it('publishes the GitLab CI template with the package', () => {
    expect(pkg.files).toContain('templates');
  });

  it('exposes the bin entry the README documents', () => {
    expect(pkg.bin['stellar-toml-lint']).toBe('./dist/cli.js');
  });

  it('requires a Node version that supports the APIs used', () => {
    // `fetch` and `node:test`-era ESM behaviour assume 20+.
    expect(pkg.engines.node).toBe('>=20');
  });
});

describe('FUNDING.json', () => {
  const funding = JSON.parse(read('FUNDING.json'));

  it('is shaped the way the Drips oracle expects', () => {
    expect(typeof funding.drips.ethereum.ownedBy).toBe('string');
    expect(funding.drips.ethereum.ownedBy).toMatch(/^0x[0-9a-fA-F]{40}$/);
  });
});

describe('GitLab CI template', () => {
  // Parsing at all is the first assertion: a broken YAML file must fail here.
  const doc = load(read('templates', 'gitlab-ci.yml')) as Record<string, any>;
  const job = doc['stellar-toml-lint'];
  const script: string = job.script.join('\n');
  const action = load(read('action.yml')) as Record<string, any>;

  it('defines the stellar-toml-lint job on an official Node.js image', () => {
    expect(Object.keys(doc)).toEqual(['stellar-toml-lint']);
    expect(job.stage).toBe('test');
    expect(job.image).toMatch(/^node:(20|22)-alpine$/);
    expect(script).toContain('npx --yes stellar-toml-lint@latest');
  });

  it('exposes the documented pipeline variables', () => {
    expect(job.variables).toMatchObject({
      STELLAR_TOML_PATH: expect.any(String),
      STELLAR_TOML_DOMAIN: expect.any(String),
      STELLAR_TOML_STRICT: expect.any(String),
      STELLAR_TOML_MAX_WARNINGS: expect.any(String),
      STELLAR_TOML_FORMAT: expect.any(String),
    });
  });

  it('defaults the variables the same way action.yml does', () => {
    // Path and strictness must behave identically to the GitHub Action.
    expect(job.variables.STELLAR_TOML_PATH).toBe(action.inputs.file.default);
    expect(job.variables.STELLAR_TOML_DOMAIN).toBe('');
    expect(job.variables.STELLAR_TOML_STRICT).toBe(action.inputs.strict.default);
    expect(job.variables.STELLAR_TOML_MAX_WARNINGS).toBe(
      String(action.inputs['max-warnings'].default ?? ''),
    );
    // The GitHub Action defaults to `github` for inline PR annotations, which
    // GitLab has no equivalent of, so the template falls back to the CLI's own
    // default instead.
    expect(action.inputs.format.default).toBe('github');
    expect(job.variables.STELLAR_TOML_FORMAT).toBe('text');
  });

  it('builds the same CLI arguments as action.yml', () => {
    expect(script).toContain('--domain "$STELLAR_TOML_DOMAIN"');
    expect(script).toContain('${STELLAR_TOML_STRICT:-false}" = "true"');
    expect(script).toContain('--max-warnings "$STELLAR_TOML_MAX_WARNINGS"');
    expect(script).toContain('--format "$format"');
    // Like the action, a file beside a domain gets same-domain checks, and a
    // domain on its own fetches the live site.
    expect(script).toContain('[ -f "$path" ]');
  });

  it('propagates the linter exit code to the job', () => {
    const lines = script.trim().split('\n');
    const last = lines[lines.length - 1] ?? '';
    expect(last.startsWith('npx --yes stellar-toml-lint@latest')).toBe(true);
    expect(script).not.toMatch(/\|\|\s*true/);
  });

  it('caches the npx download between pipeline runs', () => {
    expect(job.variables.npm_config_cache).toBe('$CI_PROJECT_DIR/.npm');
    expect(job.cache.paths).toContain('.npm/');
  });
});
