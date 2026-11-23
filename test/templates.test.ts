import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { parseDocument } from 'yaml';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');

const asObject = (value: unknown): Record<string, unknown> => value as Record<string, unknown>;
const asArray = (value: unknown): unknown[] => value as unknown[];
const asString = (value: unknown): string => String(value ?? '');

interface Loaded {
  errors: string[];
  warnings: string[];
  data: Record<string, unknown>;
}

/** Parses a template and reports any syntax problems found by the YAML parser. */
function load(name: string): Loaded {
  const source = readFileSync(join(root, 'templates', name), 'utf8');
  const doc = parseDocument(source);
  return {
    errors: doc.errors.map(String),
    warnings: doc.warnings.map(String),
    data: asObject(doc.toJS()),
  };
}

/** Narrows an optional to a definitely-present value, failing the test otherwise. */
function mustBe<T>(value: T | undefined, message: string): T {
  expect(value, message).toBeDefined();
  return value as T;
}

function findByName(
  name: string,
  list: Record<string, unknown>[],
  kind: string,
): Record<string, unknown> {
  return mustBe(
    list.find((entry) => entry.name === name),
    `missing ${kind} ${name}`,
  );
}

describe('templates/azure-pipelines.yml', () => {
  const azure = load('azure-pipelines.yml');
  const steps = asArray(azure.data.steps).map((s) => asObject(s));

  it('is syntactically valid YAML', () => {
    expect(azure.errors).toEqual([]);
    expect(azure.warnings).toEqual([]);
  });

  it('declares the documented parameters with defaults and allowed values', () => {
    const parameters = asArray(azure.data.parameters).map((p) => asObject(p));

    expect(findByName('stellarTomlPath', parameters, 'parameter')).toMatchObject({
      type: 'string',
      default: 'stellar.toml',
    });
    expect(findByName('strict', parameters, 'parameter')).toMatchObject({
      type: 'boolean',
      default: false,
    });
    expect(findByName('args', parameters, 'parameter')).toMatchObject({
      type: 'string',
      default: '',
    });

    const format = findByName('format', parameters, 'parameter');
    expect(format).toMatchObject({ type: 'string', default: 'text' });
    const allowed = asArray(format.values).map(asString);
    expect(allowed).toContain('junit');
    expect(allowed).toContain('sarif');
  });

  it('installs Node.js only for the npx path', () => {
    const nodeStep = mustBe(
      steps.find((s) => s.task === 'NodeTool@0'),
      'NodeTool@0 must be present for the npx path',
    );
    const nodeImage = asObject(nodeStep.inputs);
    expect(asString(nodeImage.versionSpec)).toBeTruthy();
    expect(asString(nodeStep.condition)).toContain('containerImage');
  });

  it('runs the linter via npx or the published container', () => {
    const lintStep = mustBe(
      steps.find((s) => s.displayName === 'Lint stellar.toml (SEP-1)'),
      'lint step must be present',
    );
    const script = asString(lintStep.bash);

    expect(script).toContain('npx --yes stellar-toml-lint@latest');
    expect(script).toContain('--format');
    expect(script).toContain('--strict');
    expect(script).toContain('docker run --rm');
    expect(script).toContain('parameters.containerImage');
  });

  it('can publish the JUnit report to the Tests tab', () => {
    const publish = mustBe(
      steps.find((s) => s.task === 'PublishTestResults@2'),
      'PublishTestResults@2 must be present',
    );
    expect(asObject(publish.inputs)).toMatchObject({ testResultsFormat: 'JUnit' });
    expect(asString(publish.condition)).toContain('publishTestResults');
  });
});

describe('templates/bitbucket-pipelines.yml', () => {
  const bitbucket = load('bitbucket-pipelines.yml');
  const source = readFileSync(join(root, 'templates', 'bitbucket-pipelines.yml'), 'utf8');
  const definedSteps = asArray(asObject(bitbucket.data.definitions).steps).map((s) =>
    asObject(asObject(s).step),
  );

  it('is syntactically valid YAML', () => {
    expect(bitbucket.errors).toEqual([]);
    expect(bitbucket.warnings).toEqual([]);
  });

  it('defines the npm-cache step', () => {
    const nodeStep = mustBe(definedSteps[0], 'npm-cache step must be defined');
    expect(nodeStep.name).toBe('Lint stellar.toml (SEP-1)');
    expect(asArray(nodeStep.caches)).toContain('npm');
    expect(asArray(nodeStep.script).map(asString).join('\n')).toContain(
      'npx --yes stellar-toml-lint@latest',
    );
  });

  it('defines the pre-built container step', () => {
    const containerStep = mustBe(definedSteps[1], 'container step must be defined');
    expect(containerStep.image).toBe('ghcr.io/anchor-tools/stellar-toml-lint:latest');
    const script = asArray(containerStep.script).map(asString).join('\n');
    expect(script).not.toContain('npx');
    expect(script).toContain('stellar-toml-lint "$@"');
  });

  it('names the anchors exactly as documented', () => {
    expect(source).toContain('&stellar-toml-lint-step');
    expect(source).toContain('&stellar-toml-lint-container-step');
  });

  it('resolves the pipelines reference back to the npm-cache definition', () => {
    const pipelines = asObject(bitbucket.data.pipelines);
    const used = asObject(asObject(asArray(asObject(pipelines.default))[0]).step);
    expect(used).toEqual(definedSteps[0]);
  });
});
