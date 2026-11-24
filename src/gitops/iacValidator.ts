import * as fs from 'node:fs';
import * as path from 'node:path';

export interface IacValidationIssue {
  severity: 'error' | 'warning';
  category: 'dns' | 'cors' | 'https' | 'well-known' | 'security';
  message: string;
  file: string;
}

export interface IacValidationResult {
  valid: boolean;
  issues: IacValidationIssue[];
}

export class IacDeploymentValidator {
  /**
   * Lightweight HCL and YAML parser / validator for Terraform and Ansible anchor deployments.
   */
  public audit(targetPath: string): IacValidationResult {
    const issues: IacValidationIssue[] = [];
    const stats = fs.statSync(targetPath);

    const files = stats.isDirectory() ? this.walkDir(targetPath) : [targetPath];

    let foundTfOrYaml = false;

    for (const file of files) {
      const ext = path.extname(file).toLowerCase();
      const content = fs.readFileSync(file, 'utf8');

      if (ext === '.tf' || file.endsWith('.tfvars')) {
        foundTfOrYaml = true;
        this.auditTerraformContent(content, file, issues);
      } else if (ext === '.yml' || ext === '.yaml') {
        foundTfOrYaml = true;
        this.auditAnsibleContent(content, file, issues);
      }
    }

    if (!foundTfOrYaml && files.length > 0) {
      issues.push({
        severity: 'warning',
        category: 'security',
        message: 'No Terraform (.tf) or Ansible playbook (.yml/.yaml) files found in path.',
        file: targetPath,
      });
    }

    return {
      valid: !issues.some((i) => i.severity === 'error'),
      issues,
    };
  }

  private walkDir(dir: string): string[] {
    let results: string[] = [];
    const list = fs.readdirSync(dir);
    for (const file of list) {
      const filePath = path.join(dir, file);
      const stat = fs.statSync(filePath);
      if (stat && stat.isDirectory()) {
        if (!filePath.includes('node_modules') && !filePath.includes('.git')) {
          results = results.concat(this.walkDir(filePath));
        }
      } else {
        results.push(filePath);
      }
    }
    return results;
  }

  private auditTerraformContent(content: string, file: string, issues: IacValidationIssue[]): void {
    // Check for HTTPS redirection
    if (content.includes('aws_lb_listener') || content.includes('aws_cloudfront_distribution')) {
      if (
        !content.includes('REDIRECT_TO_HTTPS') &&
        !content.includes('https') &&
        !content.includes('viewer_protocol_policy = "redirect-to-https"')
      ) {
        issues.push({
          severity: 'warning',
          category: 'https',
          message:
            'Terraform load balancer or CloudFront distribution may lack explicit HTTPS redirection.',
          file,
        });
      }
    }

    // Check for CORS
    if (
      !content.includes('Access-Control-Allow-Origin') &&
      !content.includes('cors') &&
      !content.includes('Access-Control')
    ) {
      issues.push({
        severity: 'warning',
        category: 'cors',
        message:
          'Terraform configuration does not appear to configure CORS headers required for SEP-1 stellar.toml.',
        file,
      });
    }

    // Check for well-known static file path / upload
    if (content.includes('aws_s3_bucket') || content.includes('aws_s3_object')) {
      if (!content.includes('.well-known') && !content.includes('stellar.toml')) {
        issues.push({
          severity: 'warning',
          category: 'well-known',
          message:
            'S3 bucket or object configuration does not explicitly reference /.well-known/stellar.toml path.',
          file,
        });
      }

      // Check unencrypted S3 bucket
      if (
        content.includes('aws_s3_bucket') &&
        !content.includes('aws_s3_bucket_server_side_encryption_configuration')
      ) {
        issues.push({
          severity: 'error',
          category: 'security',
          message: 'S3 bucket defined without server-side encryption configuration.',
          file,
        });
      }

      // Check exposed public S3 buckets
      if (
        content.includes('acl = "public-read"') ||
        content.includes('block_public_acls = false')
      ) {
        issues.push({
          severity: 'error',
          category: 'security',
          message: 'S3 bucket is configured with public access enabled.',
          file,
        });
      }
    }

    // Check missing WAF associations for production APIs / Distributions
    if (content.includes('aws_cloudfront_distribution') && !content.includes('web_acl_id')) {
      issues.push({
        severity: 'warning',
        category: 'security',
        message: 'CloudFront distribution lacks a WAF web_acl_id association.',
        file,
      });
    }
  }

  private auditAnsibleContent(content: string, file: string, issues: IacValidationIssue[]): void {
    if (content.includes('nginx') || content.includes('template') || content.includes('copy')) {
      if (!content.includes('stellar.toml') && !content.includes('.well-known')) {
        issues.push({
          severity: 'warning',
          category: 'well-known',
          message: 'Ansible playbook does not deploy stellar.toml to /.well-known/ path.',
          file,
        });
      }

      if (
        !content.includes('ssl_certificate') &&
        !content.includes('listen 443') &&
        !content.includes('https')
      ) {
        issues.push({
          severity: 'warning',
          category: 'https',
          message: 'Ansible Nginx configuration does not enforce HTTPS.',
          file,
        });
      }

      if (!content.includes('Access-Control-Allow-Origin') && !content.includes('add_header')) {
        issues.push({
          severity: 'warning',
          category: 'cors',
          message: 'Ansible playbook does not configure CORS headers for stellar.toml.',
          file,
        });
      }
    }
  }
}
