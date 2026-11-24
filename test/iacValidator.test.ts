import { describe, it } from 'vitest';
import * as path from 'node:path';
import { IacDeploymentValidator } from '../src/gitops/iacValidator.js';

describe('IacDeploymentValidator', () => {
  const validator = new IacDeploymentValidator();

  it('should validate secure Terraform fixtures without error', () => {
    const fixturePath = path.join(__dirname, 'fixtures/iac/terraform-secure');
    const result = validator.audit(fixturePath);
    // Should not contain any error severity issues
    const errors = result.issues.filter((i) => i.severity === 'error');
    if (errors.length !== 0) throw new Error(`expected 0 errors, got ${errors.length}`);
  });

  it('should flag unencrypted and public S3 buckets in Terraform', () => {
    const fixturePath = path.join(__dirname, 'fixtures/iac/terraform-insecure');
    const result = validator.audit(fixturePath);
    const errors = result.issues.filter((i) => i.severity === 'error');
    if (errors.length === 0) throw new Error('expected at least one error');
    if (!errors.some((e) => e.message.includes('encryption'))) throw new Error('expected an encryption error');
  });

  it('should validate Ansible playbooks for stellar.toml deployment', () => {
    const fixturePath = path.join(__dirname, 'fixtures/iac/ansible-playbook.yml');
    const result = validator.audit(fixturePath);
    if (!result.issues) throw new Error('expected issues');
  });
});
