#!/usr/bin/env node
import * as fs from 'fs';
import * as path from 'path';
import { IacDeploymentValidator } from './gitops/iacValidator';

const args = process.argv.slice(2);

if (args.includes('--audit-iac')) {
  const targetIndex = args.indexOf('--audit-iac') + 1;
  const targetPath = args[targetIndex] || '.';

  console.log(`Auditing IaC deployment at: ${targetPath}`);
  const validator = new IacDeploymentValidator();
  const report = validator.audit(targetPath);

  for (const issue of report.issues) {
    const prefix = issue.severity === 'error' ? 'ERROR' : 'WARNING';
    console.log(`[${prefix}] ${issue.code} (${issue.file}): ${issue.message}`);
  }

  if (!report.valid) {
    console.error('IaC validation failed with errors.');
    process.exit(1);
  } else {
    console.log('IaC validation passed successfully.');
    process.exit(0);
  }
} else {
  console.log('stellar-toml-lint CLI. Use --audit-iac <path> to validate infrastructure-as-code.');
}
