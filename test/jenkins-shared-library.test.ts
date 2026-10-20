import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

const source = readFileSync('integrations/jenkins/vars/stellarTomlLint.groovy', 'utf8');

describe('Jenkins shared library step', () => {
  it('provides container, report, and quality-gate parameters', () => {
    expect(source).toContain('def call(Map config = [:])');
    expect(source).toContain('docker.image(image).inside');
    expect(source).toContain('config.file');
    expect(source).toContain('config.image');
    expect(source).toContain('config.maxErrors');
    expect(source).toContain('config.maxWarnings');
    expect(source).toContain('--format checkstyle');
    expect(source).toContain('--format junit');
    expect(source).toContain('recordIssues');
    expect(source).toContain('junit testResults');
    expect(source).toContain('report.counts.error');
    expect(source).toContain('report.counts.warning');
  });

  it.skipIf(spawnSync('groovy', ['--version'], { stdio: 'ignore' }).status !== 0)(
    'parses with the Groovy compiler',
    () => {
      const result = spawnSync(
        'groovy',
        [
          '-e',
          'new GroovyShell().parse(new File(args[0]))',
          'integrations/jenkins/vars/stellarTomlLint.groovy',
        ],
        { encoding: 'utf8' },
      );
      expect(result.status, result.stderr).toBe(0);
    },
  );
});
