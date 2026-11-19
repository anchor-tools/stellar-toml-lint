import * as path from 'path';
import { IacDeploymentValidator } from '../../src/gitops/iacValidator';

describe('IacDeploymentValidator', () => {
  const validator = new IacDeploymentValidator();

  it('audits valid/invalid Terraform fixtures', () => {
    const fixturePath = path.join(__dirname, '../fixtures/iac/terraform');
    const report = validator.audit(fixturePath);
    expect(report.scannedFiles.length).toBeGreaterThan(0);
    expect(report.issues.some(i => i.code === 'IAC_S3_PUBLIC_EXPOSED')).toBe(true);
  });

  it('audits Ansible playbooks', () => {
    const fixturePath = path.join(__dirname, '../fixtures/iac/ansible/playbook.yml');
    const report = validator.audit(fixturePath);
    expect(report.scannedFiles.length).toBe(1);
  });
});
