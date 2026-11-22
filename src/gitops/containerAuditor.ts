/**
 * Dockerfile footprint and container hardening auditor.
 *
 * An anchor that ships stellar-toml-lint as a sidecar or a lint service runs the
 * image next to its own infrastructure. A final image that keeps a package
 * manager, build toolchain, or root user around turns any code-execution bug in
 * the linter into a foothold on the host, and a multi-hundred-megabyte base
 * image hides hundreds of packages nobody audits.
 *
 * This module parses a Dockerfile into stages, inspects the *final* stage (the
 * one that becomes the runtime image), and checks the `.dockerignore` that
 * decides what build context the daemon can see. Findings carry the matching CIS
 * Docker Benchmark control so a security review can trace each rule.
 *
 * Parsing is deliberately line-oriented: Dockerfile is not a general-purpose
 * language, and a full AST would add a dependency for no extra safety.
 */

export type ContainerSeverity = 'error' | 'warning' | 'info';

export type ContainerFindingCode =
  | 'container/dockerfile-missing'
  | 'container/base-image-unhardened'
  | 'container/base-image-unpinned'
  | 'container/single-stage'
  | 'container/runs-as-root'
  | 'container/package-manager-in-runtime'
  | 'container/build-tools-in-runtime'
  | 'container/remote-add'
  | 'container/curl-pipe-shell'
  | 'container/privileged-port'
  | 'container/secret-in-layer'
  | 'container/image-too-large'
  | 'container/healthcheck-missing'
  | 'dockerignore/missing'
  | 'dockerignore/includes-git'
  | 'dockerignore/includes-node-modules'
  | 'dockerignore/includes-secrets';

export interface ContainerFinding {
  code: ContainerFindingCode;
  severity: ContainerSeverity;
  message: string;
  /** Dockerfile line the finding points at, when there is one. */
  line?: number;
  /** Instruction (`USER`, `RUN`, …) the finding points at. */
  instruction?: string;
  /** CIS Docker Benchmark control, e.g. `4.1`. */
  cisControl?: string;
  recommendation: string;
}

export interface DockerInstruction {
  instruction: string;
  args: string;
  line: number;
}

export interface DockerfileStage {
  index: number;
  image: string;
  name?: string;
  isFinal: boolean;
  instructions: DockerInstruction[];
}

export type BaseImageFamily =
  'distroless' | 'scratch' | 'alpine' | 'slim' | 'debian' | 'ubuntu' | 'unknown';

export interface DockerfileAnalysis {
  stages: DockerfileStage[];
  finalStage?: DockerfileStage;
  baseImage?: string;
  baseImageFamily: BaseImageFamily;
  multiStage: boolean;
  copiesFromBuildStage: boolean;
  nonRootUser: boolean;
  finalUser?: string;
  runtimePackageManagers: string[];
  exposedPorts: number[];
}

export interface ContainerAuditOptions {
  /** Path reported in the result; purely informational. */
  dockerfilePath?: string;
  /** Content of `.dockerignore`, or `undefined` when the file is absent. */
  dockerignore?: string;
  /** Measured image size, e.g. from `docker image inspect`. */
  imageSizeBytes?: number;
  /** Size budget in bytes. Default 100 MB, per the issue's `< 100 MB` target. */
  sizeBudgetBytes?: number;
  /** Emit the missing-HEALTHCHECK warning. Default true. */
  checkHealthcheck?: boolean;
}

export interface ContainerAuditReport {
  ok: boolean;
  dockerfilePath?: string;
  stages: { index: number; image: string; name?: string; isFinal: boolean }[];
  baseImage?: string;
  baseImageFamily: BaseImageFamily;
  multiStage: boolean;
  nonRootUser: boolean;
  finalUser?: string;
  runtimePackageManagers: string[];
  imageSizeBytes?: number;
  sizeBudgetBytes: number;
  findings: ContainerFinding[];
  recommendations: string[];
  cisControls: string[];
}

export const DEFAULT_IMAGE_SIZE_BUDGET = 100 * 1024 * 1024;

/** Hardened base images. `slim` is tolerated (warning), not preferred. */
const HARDENED_FAMILIES: ReadonlySet<BaseImageFamily> = new Set<BaseImageFamily>([
  'distroless',
  'scratch',
  'alpine',
]);

const PACKAGE_MANAGERS = [
  'apt-get',
  'apt',
  'apk',
  'yum',
  'dnf',
  'microdnf',
  'zypper',
  'pacman',
  'rpm',
  'dpkg',
] as const;

const BUILD_TOOLS = [
  'gcc',
  'g++',
  'make',
  'cmake',
  'cargo',
  'rustc',
  'python3-dev',
  'build-essential',
] as const;

const SECRET_ENV = /(?:^|_)(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|ACCESS_KEY)(?:$|_)/i;

const DEFAULT_DOCKERIGNORE_ENTRIES = ['.git', 'node_modules', '.env'] as const;

/** Strips a trailing continuation, comments, and surrounding whitespace. */
function stripContinuation(line: string): { text: string; continued: boolean } {
  const trimmed = line.replace(/\r$/, '').trimEnd();
  if (!trimmed.endsWith('\\')) return { text: trimmed, continued: false };
  return { text: trimmed.slice(0, -1).trimEnd(), continued: true };
}

/**
 * Tokenises a Dockerfile into instructions. Continuation lines are joined so a
 * multi-line `RUN` is checked as one command, which matters for `curl | sh`
 * and `apt-get install` patterns.
 */
export function parseDockerfile(source: string): DockerInstruction[] {
  const instructions: DockerInstruction[] = [];
  const lines = source.split('\n');
  let pending: { text: string; line: number } | undefined;

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i] as string;
    const trimmed = raw.trim();
    // Parser directives (`# syntax=…`) and comments never reach the daemon.
    if (trimmed === '' || trimmed.startsWith('#')) {
      if (pending !== undefined) {
        instructions.push(splitInstruction(pending.text, pending.line));
        pending = undefined;
      }
      continue;
    }

    const { text, continued } = stripContinuation(raw);
    if (pending === undefined) pending = { text, line: i + 1 };
    else pending.text += ` ${text}`;

    if (!continued) {
      instructions.push(splitInstruction(pending.text, pending.line));
      pending = undefined;
    }
  }

  if (pending !== undefined) instructions.push(splitInstruction(pending.text, pending.line));
  return instructions;
}

function splitInstruction(text: string, line: number): DockerInstruction {
  const match = /^(\S+)\s*(.*)$/s.exec(text);
  if (match === null) return { instruction: '', args: '', line };
  return {
    instruction: (match[1] as string).toUpperCase(),
    args: (match[2] as string).trim(),
    line,
  };
}

/** Groups flat instructions into build stages. */
export function parseDockerStages(instructions: readonly DockerInstruction[]): DockerfileStage[] {
  const stages: DockerfileStage[] = [];
  let current: DockerfileStage | undefined;

  for (const instruction of instructions) {
    if (instruction.instruction === 'FROM') {
      const parsed = parseFrom(instruction.args);
      current = {
        index: stages.length,
        image: parsed.image,
        ...(parsed.name !== undefined ? { name: parsed.name } : {}),
        isFinal: false,
        instructions: [instruction],
      };
      stages.push(current);
      continue;
    }
    if (current !== undefined) current.instructions.push(instruction);
  }

  const last = stages[stages.length - 1];
  if (last !== undefined) last.isFinal = true;
  return stages;
}

/** `FROM [--platform=…] image[:tag|@digest] [AS name]`. */
export function parseFrom(args: string): { image: string; name?: string } {
  const tokens = args.split(/\s+/).filter((token) => token !== '' && !token.startsWith('--'));
  const image = tokens[0] ?? '';
  const asIndex = tokens.findIndex((token) => token.toLowerCase() === 'as');
  const name = asIndex >= 0 ? tokens[asIndex + 1] : undefined;
  return { image, ...(name !== undefined ? { name } : {}) };
}

export function classifyBaseImage(image: string): BaseImageFamily {
  const normalized = image.toLowerCase().replace(/^docker\.io\//, '');
  if (normalized === '' || normalized === 'scratch') return 'scratch';
  if (normalized.includes('distroless')) return 'distroless';
  if (/(?:^|[/:])alpine(?:$|[:@-])/.test(normalized)) return 'alpine';
  if (normalized.includes('slim')) return 'slim';
  if (/(?:^|[/:])ubuntu(?:$|[:@-])/.test(normalized)) return 'ubuntu';
  if (/(?:^|[/:])(?:debian|node|python|ruby|php|openjdk|golang|rust)(?:$|[:@-])/.test(normalized)) {
    return 'debian';
  }
  return 'unknown';
}

function hasExplicitTag(image: string): boolean {
  if (image === '' || image === 'scratch') return true;
  if (image.includes('@sha256:')) return true;
  const lastSlash = image.lastIndexOf('/');
  const lastColon = image.lastIndexOf(':');
  if (lastColon <= lastSlash) return false;
  return image.slice(lastColon + 1).toLowerCase() !== 'latest';
}

function runtimeInstructions(stage: DockerfileStage): DockerInstruction[] {
  return stage.instructions.filter((instruction) => instruction.instruction !== 'FROM');
}

function packageManagersIn(stage: DockerfileStage): string[] {
  const found = new Set<string>();
  for (const instruction of runtimeInstructions(stage)) {
    if (instruction.instruction !== 'RUN') continue;
    for (const manager of PACKAGE_MANAGERS) {
      if (new RegExp(`(?:^|[\\s;&|(])${manager}(?:[\\s&|;)]|$)`, 'i').test(instruction.args)) {
        found.add(manager);
      }
    }
  }
  return [...found];
}

function buildToolsIn(stage: DockerfileStage): string[] {
  const found = new Set<string>();
  for (const instruction of runtimeInstructions(stage)) {
    if (instruction.instruction !== 'RUN') continue;
    for (const tool of BUILD_TOOLS) {
      if (
        new RegExp(`(?:^|[\\s;&|(])${tool.replace(/\+/g, '\\+')}(?:[\\s&|;)]|$)`, 'i').test(
          instruction.args,
        )
      ) {
        found.add(tool);
      }
    }
  }
  return [...found];
}

/** Docker's `USER` value, resolving numeric ids and `name:group` forms. */
export function resolveUserStage(stage: DockerfileStage): { isRoot: boolean; user?: string } {
  const users = runtimeInstructions(stage).filter(
    (instruction) => instruction.instruction === 'USER',
  );
  const last = users[users.length - 1];
  if (last === undefined) return { isRoot: true };
  const value = last.args.split(/\s+/)[0] ?? '';
  const numeric = /^\d+$/.test(value) ? Number(value) : undefined;
  const isRoot =
    value === '' ||
    value.toLowerCase() === 'root' ||
    value.toLowerCase() === '0:0' ||
    numeric === 0;
  return { isRoot, ...(value !== '' ? { user: value } : {}) };
}

function exposedPorts(stage: DockerfileStage): number[] {
  const ports: number[] = [];
  for (const instruction of runtimeInstructions(stage)) {
    if (instruction.instruction !== 'EXPOSE') continue;
    for (const token of instruction.args.split(/\s+/)) {
      const port = Number(token.split('/')[0]);
      if (Number.isInteger(port) && port > 0) ports.push(port);
    }
  }
  return ports;
}

function secretInstructions(stage: DockerfileStage): DockerInstruction[] {
  return runtimeInstructions(stage).filter((instruction) => {
    if (instruction.instruction !== 'ARG' && instruction.instruction !== 'ENV') return false;
    const [key] = instruction.args.split('=');
    return SECRET_ENV.test((key ?? '').trim());
  });
}

function analyzeDockerfile(instructions: readonly DockerInstruction[]): DockerfileAnalysis {
  const stages = parseDockerStages(instructions);
  const finalStage = stages[stages.length - 1];
  const baseImage = finalStage?.image;
  const user = finalStage === undefined ? { isRoot: true } : resolveUserStage(finalStage);
  const copiesFromBuildStage = instructions.some(
    (instruction) =>
      (instruction.instruction === 'COPY' || instruction.instruction === 'ADD') &&
      /--from=/.test(instruction.args),
  );

  return {
    stages,
    ...(finalStage !== undefined ? { finalStage } : {}),
    ...(baseImage !== undefined ? { baseImage } : {}),
    baseImageFamily: baseImage === undefined ? 'unknown' : classifyBaseImage(baseImage),
    multiStage: stages.length > 1,
    copiesFromBuildStage,
    nonRootUser: !user.isRoot,
    ...(user.user !== undefined ? { finalUser: user.user } : {}),
    runtimePackageManagers: finalStage === undefined ? [] : packageManagersIn(finalStage),
    exposedPorts: finalStage === undefined ? [] : exposedPorts(finalStage),
  };
}

// ── .dockerignore ────────────────────────────────────────────────────────────

export interface DockerignoreAnalysis {
  present: boolean;
  patterns: string[];
  missing: string[];
}

function normalizeIgnorePattern(pattern: string): string {
  return pattern
    .replace(/\r$/, '')
    .trim()
    .replace(/^\.?\//, '')
    .replace(/^!/, '');
}

/** Checks the entries that keep credentials and build caches out of the context. */
export function analyzeDockerignore(source: string | undefined): DockerignoreAnalysis {
  if (source === undefined)
    return { present: false, patterns: [], missing: [...DEFAULT_DOCKERIGNORE_ENTRIES] };
  const patterns = source
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line !== '' && !line.startsWith('#'))
    .map(normalizeIgnorePattern);

  const covers = (entry: string): boolean =>
    patterns.some((pattern) => {
      const normalized = pattern.replace(/\/+$/, '');
      if (normalized === entry) return true;
      if (normalized.endsWith('/**')) return normalized.slice(0, -3) === entry;
      if (normalized === '*') return true;
      return entry === '.env' && (normalized === '.env*' || normalized === '*.env');
    });

  return {
    present: true,
    patterns,
    missing: DEFAULT_DOCKERIGNORE_ENTRIES.filter((entry) => !covers(entry)),
  };
}

// ── Auditor ──────────────────────────────────────────────────────────────────

export class ContainerSecurityAuditor {
  private readonly options: Required<
    Pick<ContainerAuditOptions, 'sizeBudgetBytes' | 'checkHealthcheck'>
  > &
    Pick<ContainerAuditOptions, 'dockerfilePath' | 'dockerignore' | 'imageSizeBytes'>;

  constructor(options: ContainerAuditOptions = {}) {
    this.options = {
      sizeBudgetBytes: options.sizeBudgetBytes ?? DEFAULT_IMAGE_SIZE_BUDGET,
      checkHealthcheck: options.checkHealthcheck ?? true,
      ...(options.dockerfilePath !== undefined ? { dockerfilePath: options.dockerfilePath } : {}),
      ...(options.dockerignore !== undefined ? { dockerignore: options.dockerignore } : {}),
      ...(options.imageSizeBytes !== undefined ? { imageSizeBytes: options.imageSizeBytes } : {}),
    };
  }

  audit(source: string, options: ContainerAuditOptions = {}): ContainerAuditReport {
    const dockerfilePath = options.dockerfilePath ?? this.options.dockerfilePath;
    const dockerignore = options.dockerignore ?? this.options.dockerignore;
    const imageSizeBytes = options.imageSizeBytes ?? this.options.imageSizeBytes;
    const sizeBudgetBytes = options.sizeBudgetBytes ?? this.options.sizeBudgetBytes;
    const checkHealthcheck = options.checkHealthcheck ?? this.options.checkHealthcheck;

    const findings: ContainerFinding[] = [];
    const recommendations: string[] = [];
    const cisControls = new Set<string>();

    const instructions = parseDockerfile(source);
    const analysis = analyzeDockerfile(instructions);
    const finalStage = analysis.finalStage;

    if (finalStage === undefined) {
      findings.push({
        code: 'container/dockerfile-missing',
        severity: 'error',
        message: 'Dockerfile contains no FROM instruction, so there is no image to audit',
        recommendation: 'Start the Dockerfile with a pinned, minimal base image such as alpine.',
      });
    }

    if (finalStage !== undefined) {
      const push = (finding: ContainerFinding): void => {
        findings.push(finding);
        if (finding.cisControl !== undefined) cisControls.add(finding.cisControl);
      };

      if (!HARDENED_FAMILIES.has(analysis.baseImageFamily)) {
        const family = analysis.baseImageFamily;
        push({
          code: 'container/base-image-unhardened',
          severity: family === 'slim' ? 'warning' : 'error',
          message:
            family === 'slim'
              ? `Final stage uses "${analysis.baseImage}", a slim distribution rather than a hardened minimal image`
              : `Final stage uses "${analysis.baseImage ?? 'an unset image'}", which ships a full OS userland and package manager`,
          ...(analysis.baseImage !== undefined ? { instruction: 'FROM' } : {}),
          cisControl: '4.1',
          recommendation:
            'Use gcr.io/distroless/static, alpine, or scratch for the runtime stage and compile in a builder stage.',
        });
        recommendations.push(
          'Switch the runtime base image to distroless, alpine, or scratch; keep the toolchain in a builder stage.',
        );
      }

      if (!hasExplicitTag(analysis.baseImage ?? '')) {
        push({
          code: 'container/base-image-unpinned',
          severity: 'warning',
          message: `Base image "${analysis.baseImage}" is not pinned to a tag or digest`,
          instruction: 'FROM',
          cisControl: '4.1',
          recommendation:
            'Pin the base image to an exact version (or better, a digest) so a rebuild cannot silently pull a different image.',
        });
      }

      if (!analysis.multiStage) {
        push({
          code: 'container/single-stage',
          severity: 'warning',
          message:
            'Dockerfile builds and runs in a single stage, so build tools and caches stay in the runtime image',
          instruction: 'FROM',
          cisControl: '4.1',
          recommendation:
            'Split the build into a builder stage and copy only the compiled output into a minimal runtime stage.',
        });
        recommendations.push(
          'Adopt a multi-stage build: compile in a builder stage, copy `dist/` into a distroless runtime stage.',
        );
      }

      if (!analysis.nonRootUser) {
        push({
          code: 'container/runs-as-root',
          severity: 'error',
          message: 'Final stage has no non-root USER directive, so the container runs as root',
          ...(analysis.finalUser !== undefined ? { instruction: 'USER' } : {}),
          cisControl: '4.1',
          recommendation:
            'Create an unprivileged user and switch to it in the final stage, e.g. `USER nonroot` or `USER 10001`.',
        });
        recommendations.push(
          'Run the service as a non-root user (`USER nonroot`) in the final stage.',
        );
      }

      if (analysis.runtimePackageManagers.length > 0) {
        push({
          code: 'container/package-manager-in-runtime',
          severity: 'error',
          message: `Final stage invokes a package manager (${analysis.runtimePackageManagers.join(', ')}), leaving package tooling in production`,
          instruction: 'RUN',
          cisControl: '4.1',
          recommendation:
            'Install packages only in the builder stage; the runtime stage should contain no package manager.',
        });
        recommendations.push(
          'Remove package-manager invocations from the runtime stage and bake dependencies in the builder stage.',
        );
      }

      const tools = buildToolsIn(finalStage);
      if (tools.length > 0) {
        push({
          code: 'container/build-tools-in-runtime',
          severity: 'error',
          message: `Final stage installs build tools (${tools.join(', ')}) that should not ship to production`,
          instruction: 'RUN',
          cisControl: '4.1',
          recommendation:
            'Move compilers and build dependencies to the builder stage and copy only runtime artifacts forward.',
        });
        recommendations.push('Keep compilers out of the runtime stage.');
      }

      for (const instruction of runtimeInstructions(finalStage)) {
        if (instruction.instruction === 'ADD' && /https?:\/\//i.test(instruction.args)) {
          push({
            code: 'container/remote-add',
            severity: 'error',
            message:
              'ADD downloads a remote URL during the build, so the image is not reproducible',
            line: instruction.line,
            instruction: 'ADD',
            cisControl: '4.3',
            recommendation:
              'Download and verify artifacts in a builder stage with a pinned checksum, or vendor them.',
          });
        }

        if (
          instruction.instruction === 'RUN' &&
          /\b(?:curl|wget)\b[^|]*\|\s*(?:ba)?sh\b/i.test(instruction.args)
        ) {
          push({
            code: 'container/curl-pipe-shell',
            severity: 'error',
            message:
              'RUN pipes a downloaded script into a shell, so a compromised endpoint executes arbitrary code',
            line: instruction.line,
            instruction: 'RUN',
            cisControl: '4.3',
            recommendation:
              'Download to a file, verify a pinned checksum or signature, then execute the verified artifact.',
          });
        }
      }

      const privileged = analysis.exposedPorts.filter((port) => port < 1024);
      if (privileged.length > 0) {
        push({
          code: 'container/privileged-port',
          severity: 'warning',
          message: `Final stage exposes privileged port(s) ${privileged.join(', ')}, which require extra capabilities`,
          instruction: 'EXPOSE',
          cisControl: '4.1',
          recommendation:
            'Listen on an unprivileged port (>= 1024) and map it from the orchestrator instead.',
        });
      }

      for (const instruction of secretInstructions(finalStage)) {
        push({
          code: 'container/secret-in-layer',
          severity: 'error',
          message: `${instruction.instruction} looks like a secret and is baked into an image layer`,
          line: instruction.line,
          instruction: instruction.instruction,
          cisControl: '4.10',
          recommendation:
            'Pass secrets at runtime (mounted file or environment) and never store them in ARG or ENV.',
        });
      }

      if (
        checkHealthcheck &&
        !runtimeInstructions(finalStage).some(
          (instruction) => instruction.instruction === 'HEALTHCHECK',
        )
      ) {
        push({
          code: 'container/healthcheck-missing',
          severity: 'info',
          message:
            'Final stage declares no HEALTHCHECK, so the orchestrator cannot detect a wedged process',
          cisControl: '4.6',
          recommendation:
            'Add a HEALTHCHECK that probes a cheap endpoint, or configure readiness probes in the orchestrator.',
        });
      }
    }

    if (imageSizeBytes !== undefined && imageSizeBytes > sizeBudgetBytes) {
      findings.push({
        code: 'container/image-too-large',
        severity: 'error',
        message: `Image is ${formatBytes(imageSizeBytes)}, above the ${formatBytes(sizeBudgetBytes)} budget`,
        recommendation:
          'Trim the runtime stage, remove package caches and dev dependencies, and move to a distroless base.',
      });
      recommendations.push(
        `Reduce the image below ${formatBytes(sizeBudgetBytes)}: prune caches, dev dependencies, and unused locales.`,
      );
    }

    const ignore = analyzeDockerignore(dockerignore);
    if (!ignore.present) {
      findings.push({
        code: 'dockerignore/missing',
        severity: 'warning',
        message:
          'No .dockerignore was found, so the build context can include VCS history and local caches',
        recommendation:
          'Add a .dockerignore that excludes .git, node_modules, .env, and test output.',
      });
      recommendations.push(
        'Add a .dockerignore to keep .git, node_modules, and secrets out of the build context.',
      );
    } else if (ignore.missing.length > 0) {
      if (ignore.missing.includes('.git')) {
        findings.push({
          code: 'dockerignore/includes-git',
          severity: 'warning',
          message:
            '.dockerignore does not exclude .git, so repository history enters the build context',
          cisControl: '4.9',
          recommendation: 'Add `.git` (and `.gitignore`-adjacent caches) to .dockerignore.',
        });
      }
      if (ignore.missing.includes('node_modules')) {
        findings.push({
          code: 'dockerignore/includes-node-modules',
          severity: 'warning',
          message:
            '.dockerignore does not exclude node_modules, so host dependencies can shadow the image build',
          cisControl: '4.9',
          recommendation:
            'Add `node_modules` to .dockerignore and install dependencies inside the build.',
        });
      }
      if (ignore.missing.includes('.env')) {
        findings.push({
          code: 'dockerignore/includes-secrets',
          severity: 'error',
          message:
            '.dockerignore does not exclude .env files, so local credentials can be copied into a layer',
          cisControl: '4.10',
          recommendation:
            'Add `.env` and `.env.*` to .dockerignore; never COPY credentials into the image.',
        });
      }
      if (ignore.missing.length > 0) {
        recommendations.push(
          `Add the missing .dockerignore entries: ${ignore.missing.join(', ')}.`,
        );
      }
    }

    const uniqueRecommendations = [...new Set(recommendations)];
    return {
      ok: findings.every((finding) => finding.severity !== 'error'),
      ...(dockerfilePath !== undefined ? { dockerfilePath } : {}),
      stages: analysis.stages.map((stage) => ({
        index: stage.index,
        image: stage.image,
        ...(stage.name !== undefined ? { name: stage.name } : {}),
        isFinal: stage.isFinal,
      })),
      ...(analysis.baseImage !== undefined ? { baseImage: analysis.baseImage } : {}),
      baseImageFamily: analysis.baseImageFamily,
      multiStage: analysis.multiStage,
      nonRootUser: analysis.nonRootUser,
      ...(analysis.finalUser !== undefined ? { finalUser: analysis.finalUser } : {}),
      runtimePackageManagers: analysis.runtimePackageManagers,
      ...(imageSizeBytes !== undefined ? { imageSizeBytes } : {}),
      sizeBudgetBytes,
      findings,
      recommendations: uniqueRecommendations,
      cisControls: [...cisControls].sort(),
    };
  }
}

export function auditDockerfile(
  source: string,
  options: ContainerAuditOptions = {},
): ContainerAuditReport {
  return new ContainerSecurityAuditor(options).audit(source, options);
}

function formatBytes(bytes: number): string {
  const mb = bytes / (1024 * 1024);
  if (mb >= 1) return `${mb.toFixed(mb >= 10 ? 0 : 1)} MB`;
  return `${bytes} B`;
}

const MARKERS: Record<ContainerSeverity, string> = {
  error: '✖',
  warning: '⚠',
  info: 'ℹ',
};

export function renderContainerReport(report: ContainerAuditReport): string {
  const lines: string[] = [];
  lines.push(
    `Container security audit${report.dockerfilePath ? ` — ${report.dockerfilePath}` : ''}`,
  );
  lines.push(
    `  base image: ${report.baseImage ?? '—'} (${report.baseImageFamily})${
      report.imageSizeBytes !== undefined
        ? `, image: ${formatBytes(report.imageSizeBytes)} / ${formatBytes(report.sizeBudgetBytes)}`
        : ''
    }`,
  );
  lines.push(
    `  stages: ${report.stages.length} (${report.multiStage ? 'multi-stage' : 'single-stage'}), user: ${
      report.nonRootUser ? (report.finalUser ?? 'non-root') : 'root'
    }`,
  );
  if (report.stages.length > 0) {
    lines.push(
      `  ${report.stages
        .map(
          (stage) =>
            `${stage.index + 1}.${stage.name !== undefined ? ` ${stage.name}` : ''} ${stage.image}${stage.isFinal ? ' ← runtime' : ''}`,
        )
        .join(', ')}`,
    );
  }

  if (report.findings.length === 0) {
    lines.push('  ✔ no container hardening findings');
  } else {
    for (const finding of report.findings) {
      const location = finding.line !== undefined ? ` (line ${finding.line})` : '';
      const control = finding.cisControl !== undefined ? ` [CIS ${finding.cisControl}]` : '';
      lines.push(
        `  ${MARKERS[finding.severity]} ${finding.code}${location}${control}: ${finding.message}`,
      );
      lines.push(`      → ${finding.recommendation}`);
    }
  }

  if (report.recommendations.length > 0) {
    lines.push('', 'Recommendations');
    for (const recommendation of report.recommendations) lines.push(`  • ${recommendation}`);
  }

  lines.push('', report.ok ? 'Result: pass' : 'Result: fail');
  return `${lines.join('\n')}\n`;
}
