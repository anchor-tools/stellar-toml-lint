import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';

export interface IacValidationIssue {
  severity: 'error' | 'warning';
  code: string;
  message: string;
  file?: string;
}

export interface IacValidationReport {
  valid: boolean;
  issues: IacValidationIssue[];
  scannedFiles: string[];
}

export class IacDeploymentValidator {
  /**
   * Lightweight Terraform HCL parser & YAML Ansible playbook parser
   * to validate infrastructure-as-code deployments for anchors.
   */
  public audit(targetPath: string): IacValidationReport {
    const issues: IacValidationIssue[] = [];
    const scannedFiles: string[] = [];

    const stats = fs.statSync(targetPath);
    const filesToAudit: string[] = [];

    if (stats.isDirectory()) {
      this.walkDir(targetPath, filesToAudit);
    } else {
      filesToAudit.push(targetPath);
    }

    for (const filePath of filesToAudit) {
      const ext = path.extname(filePath).toLowerCase();
      const content = fs.readFileSync(filePath, 'utf8');
      scannedFiles.push(filePath);

      if (ext === '.tf') {
        this.auditTerraform(content, filePath, issues);
      } else if (ext === '.yml' || ext === '.yaml') {
        this.auditAnsible(content, filePath, issues);
      }
    }

    const hasErrors = issues.some(i => i.severity === 'error');
    return {
      valid: !hasErrors,
      issues,
      scannedFiles,
    };
  }

  private walkDir(dir: string, fileList: string[]): void {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name !== 'node_modules' && entry.name !== '.git') {
          this.walkDir(fullPath, fileList);
        }
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (['.tf', '.yml', '.yaml'].includes(ext)) {
          fileList.push(fullPath);
        }
      }
    }
  }

  private auditTerraform(content: string, filePath: string, issues: IacValidationIssue[]): void {
    // Check for S3 bucket encryption & public access blocks
    if (content.includes('aws_s3_bucket')) {
      if (!content.includes('server_side_encryption_configuration') && !content.includes('aws_s3_bucket_server_side_encryption')) {
        issues.push({
          severity: 'warning',
          code: 'IAC_S3_UNENCRYPTED',
          message: 'Terraform S3 bucket missing explicit server-side encryption configuration.',
          file: filePath,
        });
      }
      if (!content.includes('aws_s3_bucket_public_access_block') && !content.includes('block_public_acls')) {
        issues.push({
          severity: 'error',
          code: 'IAC_S3_PUBLIC_EXPOSED',
          message: 'Terraform S3 bucket missing public access block configuration.',
          file: filePath,
        });
      }
    }

    // Check for WAF association
    if (content.includes('aws_cloudfront_distribution') || content.includes('aws_lb')) {
      if (!content.includes('web_acl_id') && !content.includes('aws_wafv2_web_acl_association')) {
        issues.push({
          severity: 'warning',
          code: 'IAC_MISSING_WAF',
          message: 'CloudFront distribution or Load Balancer lacks WAF association.',
          file: filePath,
        });
      }
    }

    // Check HTTPS redirection
    if (content.includes('viewer_protocol_policy') && content.includes('allow-all')) {
      issues.push({
        severity: 'error',
        code: 'IAC_NO_HTTPS_REDIRECT',
        message: 'CloudFront or load balancer viewer protocol policy allows unencrypted HTTP traffic.',
        file: filePath,
      });
    }

    // Check stellar.toml canonical path
    if ((content.includes('aws_s3_object') || content.includes('aws_s3_bucket_object')) && !content.includes('.well-known/stellar.toml')) {
      issues.push({
        severity: 'warning',
        code: 'IAC_STELLAR_TOML_PATH',
        message: 'S3 static object upload does not explicitly target the canonical /.well-known/stellar.toml path.',
        file: filePath,
      });
    }
  }

  private auditAnsible(content: string, filePath: string, issues: IacValidationIssue[]): void {
    try {
      const docs = yaml.loadAll(content);
      for (const doc of docs as any[]) {
        if (!doc || typeof doc !== 'object') continue;
        const tasks = doc.tasks || [];
        for (const task of tasks) {
          const moduleName = Object.keys(task).find(k => k !== 'name' && k !== 'when' && k !== 'register' && k !== 'tags');
          if (!moduleName) continue;
          const args = task[moduleName];

          // Check nginx configuration or template tasks
          if (moduleName === 'template' || moduleName === 'copy') {
            const dest = typeof args === 'object' && args !== null ? args.dest : '';
            if (dest && typeof dest === 'string' && dest.includes('nginx') && !content.includes('return 301 https')) {
              issues.push({
                severity: 'warning',
                code: 'IAC_ANSIBLE_NGINX_HTTPS',
                message: 'Ansible Nginx configuration task does not enforce HTTPS redirection.',
                file: filePath,
              });
            }
          }

          // Check CORS headers
          if (moduleName === 'uri' || moduleName === 'command' || moduleName === 'shell') {
            // placeholder check for general headers
          }
        }
      }
    } catch (err) {
      // YAML parse error if invalid format
      issues.push({
        severity: 'error',
        code: 'IAC_YAML_PARSE_ERROR',
        message: `Failed to parse Ansible YAML playbook: ${(err as Error).message}`,
        file: filePath,
      });
    }
  }
}
