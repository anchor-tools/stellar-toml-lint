import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  ContainerSecurityAuditor,
  DEFAULT_IMAGE_SIZE_BUDGET,
  analyzeDockerignore,
  auditDockerfile,
  classifyBaseImage,
  parseDockerfile,
  parseDockerStages,
  parseFrom,
  renderContainerReport,
  resolveUserStage,
} from '../src/gitops/containerAuditor.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string): string =>
  readFileSync(join(here, 'fixtures', 'gitops', 'docker', name), 'utf8');

const hardened = fixture('Dockerfile.hardened');
const vulnerable = fixture('Dockerfile.vulnerable');

const codes = (report: ReturnType<typeof auditDockerfile>): string[] =>
  report.findings.map((finding) => finding.code);

describe('Dockerfile parser', () => {
  it('joins continuation lines and keeps the first line number', () => {
    const instructions = parseDockerfile(
      [
        'FROM alpine:3.20',
        'RUN apk add --no-cache \\',
        '    ca-certificates curl',
        'USER app',
      ].join('\n'),
    );
    expect(instructions.map((instruction) => instruction.instruction)).toEqual([
      'FROM',
      'RUN',
      'USER',
    ]);
    expect(instructions[1]?.args).toContain('ca-certificates curl');
    expect(instructions[1]?.line).toBe(2);
  });

  it('ignores comments, blank lines, and parser directives', () => {
    const instructions = parseDockerfile(
      '# syntax=docker/dockerfile:1\n\n# a comment\nFROM scratch',
    );
    expect(instructions).toHaveLength(1);
    expect(instructions[0]?.instruction).toBe('FROM');
  });

  it('groups instructions into stages and marks the last one final', () => {
    const stages = parseDockerStages(parseDockerfile(hardened));
    expect(stages).toHaveLength(2);
    expect(stages[0]?.name).toBe('build');
    expect(stages[0]?.isFinal).toBe(false);
    expect(stages[1]?.name).toBe('runtime');
    expect(stages[1]?.isFinal).toBe(true);
    expect(stages[1]?.image).toBe('gcr.io/distroless/nodejs20-debian12:nonroot');
  });

  it('parses FROM platform flags and AS aliases', () => {
    expect(parseFrom('--platform=linux/amd64 node:20-alpine AS builder')).toEqual({
      image: 'node:20-alpine',
      name: 'builder',
    });
    expect(parseFrom('alpine:3.20')).toEqual({ image: 'alpine:3.20' });
  });

  it('classifies minimal and full base images', () => {
    expect(classifyBaseImage('gcr.io/distroless/static-debian12')).toBe('distroless');
    expect(classifyBaseImage('alpine:3.20')).toBe('alpine');
    expect(classifyBaseImage('scratch')).toBe('scratch');
    expect(classifyBaseImage('debian:12-slim')).toBe('slim');
    expect(classifyBaseImage('ubuntu:24.04')).toBe('ubuntu');
    expect(classifyBaseImage('node:20')).toBe('debian');
    expect(classifyBaseImage('ghcr.io/anchor/custom')).toBe('unknown');
  });

  it('resolves root and non-root USER directives, including numeric ids', () => {
    const stage = (user: string | undefined) =>
      parseDockerStages(
        parseDockerfile(`FROM alpine:3.20\n${user !== undefined ? `USER ${user}\n` : ''}`),
      )[0] as ReturnType<typeof parseDockerStages>[number];

    expect(resolveUserStage(stage(undefined)).isRoot).toBe(true);
    expect(resolveUserStage(stage('root')).isRoot).toBe(true);
    expect(resolveUserStage(stage('0')).isRoot).toBe(true);
    expect(resolveUserStage(stage('nonroot'))).toEqual({ isRoot: false, user: 'nonroot' });
    expect(resolveUserStage(stage('10001:10001'))).toEqual({ isRoot: false, user: '10001:10001' });
  });
});

describe('ContainerSecurityAuditor', () => {
  it('passes a hardened multi-stage distroless build', () => {
    const report = auditDockerfile(hardened, {
      dockerfilePath: 'Dockerfile',
      dockerignore: fixture('hardened.dockerignore'),
    });

    expect(report.ok).toBe(true);
    expect(report.multiStage).toBe(true);
    expect(report.nonRootUser).toBe(true);
    expect(report.finalUser).toBe('nonroot');
    expect(report.baseImageFamily).toBe('distroless');
    expect(report.runtimePackageManagers).toEqual([]);
    expect(report.stages).toHaveLength(2);
    expect(report.findings).toEqual([]);
    expect(report.cisControls).toEqual([]);
  });

  it('flags a root single-stage image that installs packages and pipes curl into sh', () => {
    const report = auditDockerfile(vulnerable, { dockerfilePath: 'Dockerfile.vulnerable' });
    const found = codes(report);

    expect(report.ok).toBe(false);
    expect(report.multiStage).toBe(false);
    expect(report.nonRootUser).toBe(false);
    expect(report.baseImageFamily).toBe('ubuntu');
    expect(report.runtimePackageManagers).toEqual(['apt-get']);
    expect(found).toEqual(
      expect.arrayContaining([
        'container/base-image-unhardened',
        'container/base-image-unpinned',
        'container/single-stage',
        'container/runs-as-root',
        'container/package-manager-in-runtime',
        'container/build-tools-in-runtime',
        'container/remote-add',
        'container/curl-pipe-shell',
        'container/privileged-port',
        'container/secret-in-layer',
        'container/healthcheck-missing',
        'dockerignore/missing',
      ]),
    );
    const root = report.findings.find((finding) => finding.code === 'container/runs-as-root');
    expect(root?.cisControl).toBe('4.1');
    const curl = report.findings.find((finding) => finding.code === 'container/curl-pipe-shell');
    expect(curl?.line).toBe(3);
    expect(report.recommendations.join(' ')).toContain('non-root');
    expect(report.cisControls).toContain('4.1');
  });

  it('treats a slim base as a warning and an unhardened base as an error', () => {
    const slim = auditDockerfile('FROM node:20.11.1-slim\nUSER app\n');
    const severity = slim.findings.find(
      (finding) => finding.code === 'container/base-image-unhardened',
    )?.severity;
    expect(severity).toBe('warning');
    expect(auditDockerfile('FROM alpine:3.20\nUSER app\n').ok).toBe(true);
  });

  it('requires a non-root user even on a hardened base', () => {
    const report = auditDockerfile('FROM alpine:3.20\nCMD ["node", "server.js"]\n');
    expect(codes(report)).toContain('container/runs-as-root');
    expect(
      report.findings.find((finding) => finding.code === 'container/runs-as-root')?.message,
    ).toContain('root');
  });

  it('detects unpinned and :latest base images', () => {
    const unpinned = auditDockerfile('FROM alpine\nUSER app\n');
    expect(codes(unpinned)).toContain('container/base-image-unpinned');

    const latest = auditDockerfile('FROM alpine:latest\nUSER app\n');
    expect(codes(latest)).toContain('container/base-image-unpinned');

    const digest = auditDockerfile(
      'FROM alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nUSER app\n',
    );
    expect(codes(digest)).not.toContain('container/base-image-unpinned');
  });

  it('only audits the final stage for runtime package managers', () => {
    const report = auditDockerfile(
      [
        'FROM node:20.11.1-alpine AS build',
        'RUN apk add --no-cache git',
        'FROM gcr.io/distroless/nodejs20-debian12',
        'COPY --from=build /app /app',
        'USER nonroot',
      ].join('\n'),
    );
    expect(report.runtimePackageManagers).toEqual([]);
    expect(codes(report)).not.toContain('container/package-manager-in-runtime');
  });

  it('reports an image above the size budget and honours a custom budget', () => {
    const oversized = auditDockerfile(hardened, { imageSizeBytes: 140 * 1024 * 1024 });
    expect(oversized.ok).toBe(false);
    expect(codes(oversized)).toContain('container/image-too-large');
    expect(DEFAULT_IMAGE_SIZE_BUDGET).toBe(100 * 1024 * 1024);

    const raised = auditDockerfile(hardened, {
      imageSizeBytes: 140 * 1024 * 1024,
      sizeBudgetBytes: 200 * 1024 * 1024,
    });
    expect(codes(raised)).not.toContain('container/image-too-large');
  });

  it('handles a Dockerfile without FROM as an error rather than throwing', () => {
    const report = auditDockerfile('# empty\n');
    expect(report.ok).toBe(false);
    expect(report.baseImageFamily).toBe('unknown');
    expect(codes(report)).toContain('container/dockerfile-missing');
  });

  it('accepts fs promises-style injection through the class constructor', () => {
    const auditor = new ContainerSecurityAuditor({
      dockerfilePath: 'Dockerfile',
      dockerignore: fixture('hardened.dockerignore'),
    });
    const report = auditor.audit(hardened);
    expect(report.ok).toBe(true);
  });
});

describe('.dockerignore analysis', () => {
  it('reports missing entries when no .dockerignore exists', () => {
    const analysis = analyzeDockerignore(undefined);
    expect(analysis.present).toBe(false);
    expect(analysis.missing).toEqual(['.git', 'node_modules', '.env']);
  });

  it('accepts a hardened ignore file and flags secrets in an insecure one', () => {
    expect(analyzeDockerignore(fixture('hardened.dockerignore')).missing).toEqual([]);

    const report = auditDockerfile(hardened, {
      dockerignore: fixture('insecure.dockerignore'),
    });
    expect(codes(report)).toEqual(
      expect.arrayContaining([
        'dockerignore/includes-git',
        'dockerignore/includes-node-modules',
        'dockerignore/includes-secrets',
      ]),
    );
    expect(
      report.findings.find((finding) => finding.code === 'dockerignore/includes-secrets')?.severity,
    ).toBe('error');
  });

  it('treats a blanket wildcard and .env wildcards as coverage', () => {
    expect(analyzeDockerignore('*\n').missing).toEqual([]);
    expect(analyzeDockerignore('.git\nnode_modules\n.env*\n').missing).toEqual([]);
    expect(analyzeDockerignore('node_modules/\n.git/\n.env\n').missing).toEqual([]);
  });
});

describe('renderContainerReport', () => {
  it('renders the stage map, findings, recommendations, and verdict', () => {
    const report = auditDockerfile(vulnerable);
    const text = renderContainerReport(report);
    expect(text).toContain('Container security audit');
    expect(text).toContain('ubuntu');
    expect(text).toContain('CIS 4.1');
    expect(text).toContain('Recommendations');
    expect(text).toContain('Result: fail');

    const clean = renderContainerReport(
      auditDockerfile(hardened, { dockerignore: fixture('hardened.dockerignore') }),
    );
    expect(clean).toContain('no container hardening findings');
    expect(clean).toContain('Result: pass');
  });
});
