import { describe, expect, it } from 'vitest';
import * as YAML from 'js-yaml';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const task: any = YAML.load(readFileSync(join('integrations', 'tekton', 'task.yaml'), 'utf8'));

describe('tekton task catalog manifest', () => {
  it('is a Tekton Task named stellar-toml-lint', () => {
    expect(task.apiVersion).toBe('tekton.dev/v1');
    expect(task.kind).toBe('Task');
    expect(task.metadata.name).toBe('stellar-toml-lint');
    expect(task.metadata.labels['app.kubernetes.io/name']).toBe('stellar-toml-lint');
  });

  it('declares the TOML_PATH, FORMAT and STRICT parameters', () => {
    const tomlPath = task.spec.params.find((p: any) => p.name === 'TOML_PATH')!;
    expect(tomlPath.type).toBe('string');
    expect(tomlPath.default).toBe('stellar.toml');

    const format = task.spec.params.find((p: any) => p.name === 'FORMAT')!;
    expect(format.type).toBe('string');
    expect(format.default).toBe('text');
    expect(format.description).toContain('sonar');

    const strict = task.spec.params.find((p: any) => p.name === 'STRICT')!;
    expect(strict.type).toBe('string');
    expect(strict.default).toBe('false');
  });

  it('emits the PROBLEMS_COUNT and VERDICT results', () => {
    const results = Object.fromEntries(task.spec.results.map((r: any) => [r.name, r]));
    expect(results.PROBLEMS_COUNT).toBeDefined();
    expect(results.VERDICT).toBeDefined();
    expect(results.PROBLEMS_COUNT.description).toBeDefined();
    expect(results.VERDICT.description).toBeDefined();
  });

  it('supports a source workspace', () => {
    const [workspace] = task.spec.workspaces;
    expect(workspace.name).toBe('source');
    expect(workspace.mountPath).toBe('/workspace/source');
    expect(workspace.description).toBeDefined();
  });

  it('runs the published stellar-toml-lint image', () => {
    const [step] = task.spec.steps;
    expect(step.name).toBe('lint');
    expect(step.image).toBe('ghcr.io/anchor-tools/stellar-toml-lint:latest');
    expect(step.command).toEqual(['sh']);
    expect(step.script).toBeDefined();
    expect(step.script).toContain('stellar-toml-lint');
    expect(step.script).toContain('$(params.FORMAT)');
    expect(step.script).toContain('$(params.STRICT)');
    expect(step.script).toContain('$(results.PROBLEMS_COUNT.path)');
    expect(step.script).toContain('$(results.VERDICT.path)');
  });
});
