import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as assert from 'node:assert';
import * as path from 'node:path';
import { IacDeploymentValidator } from '../src/gitops/iacValidator.js';

describe('IacDeploymentValidator', () => {
  const validator = new IacDeploymentValidator();

  it('should validate secure Terraform fixtures without error', () => {
    const fixturePath = path.join(import.meta.dirname, 'fixtures/iac/terraform-secure');
    const result = validator.audit(fixturePath);
    // Should not contain any error severity issues
    const errors = result.issues.filter((i) => i.severity === 'error');
    assert.strictEqual(errors.length, 0);
  });

  it('should flag unencrypted and public S3 buckets in Terraform', () => {
    const fixturePath = path.join(import.meta.dirname, 'fixtures/iac/terraform-insecure');
    const result = validator.audit(fixturePath);
    const errors = result.issues.filter((i) => i.severity === 'error');
    assert.ok(errors.length > 0);
    assert.ok(errors.some((e) => e.message.includes('encryption')));
  });

  it('should validate Ansible playbooks for stellar.toml deployment', () => {
    const fixturePath = path.join(import.meta.dirname, 'fixtures/iac/ansible-playbook.yml');
    const result = validator.audit(fixturePath);
    assert.ok(result.issues);
  });
});

describe('--audit-iac', () => {
  it('reports invalid Terraform through the existing CLI formatter', () => {
    const cliPath = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
    const fixture = path.join(import.meta.dirname, 'fixtures/iac/terraform-insecure');
    const run = spawnSync(process.execPath, [cliPath, '--audit-iac', fixture, '--format', 'json'], {
      encoding: 'utf8',
    });

    expect(run.status).toBe(1);
    expect(run.stdout).toContain('gitops/iac-deployment');
    expect(run.stdout).toContain('server-side encryption');
  });
});
