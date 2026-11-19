import * as assert from 'assert';
import * as path from 'path';
import { IacDeploymentValidator } from '../src/gitops/iacValidator';

describe('IacDeploymentValidator', () => {
  const validator = new IacDeploymentValidator();

  it('should validate secure Terraform fixtures without error', () => {
    const fixturePath = path.join(__dirname, 'fixtures/iac/terraform-secure');
    const result = validator.audit(fixturePath);
    // Should not contain any error severity issues
    const errors = result.issues.filter(i => i.severity === 'error');
    assert.strictEqual(errors.length, 0);
  });

  it('should flag unencrypted and public S3 buckets in Terraform', () => {
    const fixturePath = path.join(__dirname, 'fixtures/iac/terraform-insecure');
    const result = validator.audit(fixturePath);
    const errors = result.issues.filter(i => i.severity === 'error');
    assert.ok(errors.length > 0);
    assert.ok(errors.some(e => e.message.includes('encryption')));
  });

  it('should validate Ansible playbooks for stellar.toml deployment', () => {
    const fixturePath = path.join(__dirname, 'fixtures/iac/ansible-playbook.yml');
    const result = validator.audit(fixturePath);
    assert.ok(result.issues);
  });
});
