/**
 * Generates a hardened GitHub Actions workflow that validates one
 * `stellar.toml` per deployment environment across a Node.js version matrix.
 *
 * Every matrix cell lints its tenant's file (schema, link reachability and TLS
 * through `--check-network`), asserts the file only references its own Stellar
 * network, exports SARIF for code scanning, and hands a scorecard to a final job
 * that upserts one structured comment on the pull request.
 *
 * Hardening follows GitHub's security guidance: actions are pinned to full
 * commit SHAs, the default token has no permissions and each job opts into the
 * narrowest scopes it needs, checkout does not persist credentials, untrusted
 * values reach scripts only through environment variables, the commenting job
 * never checks out pull request code, and fork pull requests (whose tokens are
 * read-only) skip the steps that need write access.
 */

import { toYaml, type YamlValue } from './ciYaml.js';
import { CI_ENVIRONMENTS, type CiEnvironmentName } from './ciEnvironments.js';

/** A third-party action pinned to an immutable commit. */
export interface PinnedAction {
  /** `owner/repo` or `owner/repo/path`. */
  uses: string;
  /** Full 40-character commit SHA. */
  sha: string;
  /** Human-readable tag the SHA corresponds to, emitted as a comment. */
  version: string;
}

export type CiActionName =
  | 'checkout'
  | 'setupNode'
  | 'cache'
  | 'uploadArtifact'
  | 'downloadArtifact'
  | 'uploadSarif'
  | 'githubScript';

/**
 * Default pins, each verified against the tag in its upstream repository.
 * Dependabot's `github-actions` ecosystem keeps SHA pins with version comments
 * up to date, so generated workflows do not rot.
 */
export const DEFAULT_PINNED_ACTIONS: Readonly<Record<CiActionName, PinnedAction>> = {
  checkout: {
    uses: 'actions/checkout',
    sha: '11bd71901bbe5b1630ceea73d27597364c9af683',
    version: 'v4.2.2',
  },
  setupNode: {
    uses: 'actions/setup-node',
    sha: '49933ea5288caeca8642d1e84afbd3f7d6820020',
    version: 'v4.4.0',
  },
  cache: {
    uses: 'actions/cache',
    sha: '5a3ec84eff668545956fd18022155c47e93e2684',
    version: 'v4.2.3',
  },
  uploadArtifact: {
    uses: 'actions/upload-artifact',
    sha: 'ea165f8d65b6e75b540449e92b4886f43607fa02',
    version: 'v4.6.2',
  },
  downloadArtifact: {
    uses: 'actions/download-artifact',
    sha: 'd3f86a106a0bac45b974a628896c90dbdf5c8093',
    version: 'v4.3.0',
  },
  uploadSarif: {
    uses: 'github/codeql-action/upload-sarif',
    sha: 'ff0a06e83cb2de871e5a09832bc6a81e7276941f',
    version: 'v3.28.18',
  },
  githubScript: {
    uses: 'actions/github-script',
    sha: '60a0d83039c74a4aee543508d2ffcb1c3799cdea',
    version: 'v7.0.1',
  },
};

/** Marker the PR bot uses to find and update its own comment. */
export const SCORECARD_MARKER = '<!-- stellar-toml-lint:ci-scorecard -->';

/** Directory the linter's remote asset cache lives in, relative to the workspace. */
export const ASSET_CACHE_DIR = '.stellar-toml-lint/cache';

export const DEFAULT_WORKFLOW_PATH = '.github/workflows/stellar-toml-lint-matrix.yml';
export const DEFAULT_FILE_PATTERN = 'environments/{environment}/stellar.toml';

export interface CiMatrixWorkflowOptions {
  /** Environments in the matrix, in order. Default: `testnet`, `public`. */
  environments?: readonly CiEnvironmentName[];
  /** Node.js major versions. The first one is primary. Default: `20`, `22`. */
  nodeVersions?: readonly string[];
  /** Path template; `{environment}` is replaced per environment. */
  filePattern?: string;
  /** Explicit per-environment paths, overriding {@link filePattern}. */
  files?: Partial<Record<CiEnvironmentName, string>>;
  /**
   * Run `--check-network` (link reachability, TLS, Horizon) per environment.
   * A boolean applies to every environment; omitted, each profile decides.
   */
  checkNetwork?: boolean | Partial<Record<CiEnvironmentName, boolean>>;
  /** Treat warnings as failures. */
  strict?: boolean;
  /** Upload SARIF to GitHub code scanning. Default `true`. */
  sarif?: boolean;
  /** Post the scorecard as a pull request comment. Default `true`. */
  prComment?: boolean;
  /** Cache the tool install and fetched remote assets. Default `true`. */
  cache?: boolean;
  /** `stellar-toml-lint` version installed in CI. */
  toolVersion?: string;
  /** Workflow display name. */
  workflowName?: string;
  /** Branches whose pushes trigger the workflow. Default `main`. */
  branches?: readonly string[];
  /** Job timeout. Default 5 minutes; a warm-cache run takes well under 30 s. */
  timeoutMinutes?: number;
  /** Where the workflow will be written, used for the `paths` filter. */
  workflowPath?: string;
  /** Override individual action pins. */
  actions?: Partial<Record<CiActionName, PinnedAction>>;
}

interface ResolvedOptions {
  environments: CiEnvironmentName[];
  nodeVersions: string[];
  files: Record<CiEnvironmentName, string>;
  checkNetwork: Record<CiEnvironmentName, boolean>;
  strict: boolean;
  sarif: boolean;
  prComment: boolean;
  cache: boolean;
  toolVersion: string;
  workflowName: string;
  branches: string[];
  timeoutMinutes: number;
  workflowPath: string;
  actions: Record<CiActionName, PinnedAction>;
}

type Mapping = { [key: string]: YamlValue | undefined };

const NODE_VERSION = /^\d{1,2}(?:\.\d{1,3}){0,2}$/;
const SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const SHA = /^[0-9a-f]{40}$/;
/** Characters that could break out of a YAML scalar or a shell word. */
const UNSAFE_PATH = /[`$"'\\;|&<>*?[\]{}]/;

function hasControlCharacter(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

export class CiMatrixWorkflowGenerator {
  private readonly options: ResolvedOptions;

  constructor(options: CiMatrixWorkflowOptions = {}) {
    this.options = resolve(options);
  }

  /** The repository-relative path the workflow should be written to. */
  get workflowPath(): string {
    return this.options.workflowPath;
  }

  /** The tenant file each environment validates. */
  get files(): Readonly<Record<CiEnvironmentName, string>> {
    return this.options.files;
  }

  /** The workflow as a plain object, ready for serialisation or inspection. */
  build(): Mapping {
    const o = this.options;
    const watched = [
      ...new Set([...o.environments.map((env) => o.files[env]), '.stellartomlrc.json']),
      o.workflowPath,
    ];
    const jobs: Mapping = { validate: this.validateJob() };
    if (o.prComment) jobs.scorecard = this.scorecardJob();

    return {
      name: o.workflowName,
      on: {
        pull_request: { paths: watched },
        push: { branches: o.branches, paths: watched },
        workflow_dispatch: {},
      },
      // Deny everything by default; each job grants only what it uses.
      permissions: {},
      concurrency: {
        group: '${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}',
        'cancel-in-progress': true,
      },
      jobs,
    };
  }

  /** The workflow as YAML, with a provenance header. */
  generate(): string {
    const o = this.options;
    const header = [
      `# Generated by stellar-toml-lint ${o.toolVersion} (init-ci).`,
      `# Regenerate with: stellar-toml-lint init-ci --matrix ${o.environments.join(',')} --node ${o.nodeVersions.join(',')} --force`,
      '#',
      '# Actions are pinned to commit SHAs; let Dependabot (github-actions) bump them.',
      '',
    ].join('\n');
    return pinComments(header + toYaml(this.build()), o.actions);
  }

  private uses(name: CiActionName): string {
    const action = this.options.actions[name];
    return `${action.uses}@${action.sha}`;
  }

  private get primaryNode(): string {
    return this.options.nodeVersions[0] as string;
  }

  private installSteps(cacheKeySuffix: string): Mapping[] {
    const o = this.options;
    const steps: Mapping[] = [];
    if (o.cache) {
      steps.push({
        name: 'Restore tool and remote asset cache',
        uses: this.uses('cache'),
        with: {
          path: `~/.npm/_cacache\n${ASSET_CACHE_DIR}\n`,
          key: `stellar-toml-lint-${o.toolVersion}-\${{ runner.os }}-node\${{ matrix.node }}-${cacheKeySuffix}`,
          'restore-keys': `stellar-toml-lint-${o.toolVersion}-\${{ runner.os }}-node\${{ matrix.node }}-\n`,
        },
      });
    }
    steps.push({
      name: 'Install stellar-toml-lint',
      env: { TOOL: `stellar-toml-lint@${o.toolVersion}` },
      // --ignore-scripts: no install-time code runs with the job's token.
      run: 'npm install --global --no-audit --no-fund --ignore-scripts --prefer-offline "$TOOL"',
    });
    return steps;
  }

  private validateJob(): Mapping {
    const o = this.options;
    const sameRepo =
      "(github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository)";
    const primary = `matrix.node == '${this.primaryNode}'`;

    const steps: Mapping[] = [
      {
        name: 'Check out',
        uses: this.uses('checkout'),
        with: { 'persist-credentials': false },
      },
      {
        name: 'Set up Node.js ${{ matrix.node }}',
        uses: this.uses('setupNode'),
        with: { 'node-version': '${{ matrix.node }}' },
      },
      ...this.installSteps('${{ matrix.environment }}-${{ hashFiles(matrix.file) }}'),
      {
        name: 'Lint ${{ matrix.environment }} stellar.toml',
        id: 'lint',
        env: {
          FILE: '${{ matrix.file }}',
          CHECK_NETWORK: '${{ matrix.check-network }}',
          STRICT: o.strict ? 'true' : 'false',
          ...(o.cache ? { STELLAR_TOML_LINT_ASSET_CACHE: ASSET_CACHE_DIR } : {}),
        },
        run:
          [
            'set -uo pipefail',
            'mkdir -p reports',
            'args=("$FILE" --format json)',
            '[[ "$CHECK_NETWORK" == "true" ]] && args+=(--check-network)',
            '[[ "$STRICT" == "true" ]] && args+=(--strict)',
            // The runner's default `bash -e` would abort on findings before the
            // exit code is recorded, so capture it explicitly.
            'stellar-toml-lint "${args[@]}" > reports/lint-output.json && code=0 || code=$?',
            'echo "exit-code=$code" >> "$GITHUB_OUTPUT"',
          ].join('\n') + '\n',
      },
      {
        name: 'Assert network isolation and build reports',
        id: 'report',
        if: 'always()',
        env: {
          ENVIRONMENT: '${{ matrix.environment }}',
          FILE: '${{ matrix.file }}',
          NODE: '${{ matrix.node }}',
          CHECK_NETWORK: '${{ matrix.check-network }}',
          LINT_EXIT_CODE: '${{ steps.lint.outputs.exit-code }}',
        },
        run:
          [
            'set -uo pipefail',
            'args=(--environment "$ENVIRONMENT" --file "$FILE" --node "$NODE"',
            '  --lint-json reports/lint-output.json --lint-exit-code "${LINT_EXIT_CODE:-2}"',
            '  --out-dir reports)',
            '[[ "$CHECK_NETWORK" == "true" ]] && args+=(--check-network)',
            'stellar-toml-lint ci-report "${args[@]}" >> "$GITHUB_STEP_SUMMARY"',
          ].join('\n') + '\n',
      },
    ];

    if (o.sarif) {
      steps.push({
        name: 'Upload SARIF to code scanning',
        if: `always() && ${primary} && ${sameRepo} && hashFiles(format('reports/{0}.sarif', matrix.environment)) != ''`,
        uses: this.uses('uploadSarif'),
        with: {
          sarif_file: 'reports/${{ matrix.environment }}.sarif',
          category: 'stellar-toml-lint/${{ matrix.environment }}',
        },
      });
    }

    if (o.prComment) {
      steps.push({
        name: 'Upload scorecard',
        if: `always() && ${primary}`,
        uses: this.uses('uploadArtifact'),
        with: {
          name: 'stellar-toml-lint-${{ matrix.environment }}',
          path: 'reports/${{ matrix.environment }}.json',
          'if-no-files-found': 'warn',
          'retention-days': 7,
        },
      });
    }

    steps.push({
      name: 'Fail on findings',
      if: 'always()',
      env: { OK: '${{ steps.report.outputs.ok }}', ENVIRONMENT: '${{ matrix.environment }}' },
      run:
        [
          'if [[ "$OK" != "true" ]]; then',
          '  echo "::error::stellar.toml validation failed for ${ENVIRONMENT}; see the job summary"',
          '  exit 1',
          'fi',
        ].join('\n') + '\n',
    });

    const include: Mapping[] = o.environments.map((env) => ({
      environment: env,
      file: o.files[env],
      'check-network': o.checkNetwork[env],
    }));

    return {
      name: '${{ matrix.environment }} · Node ${{ matrix.node }}',
      'runs-on': 'ubuntu-latest',
      'timeout-minutes': o.timeoutMinutes,
      permissions: {
        contents: 'read',
        ...(o.sarif ? { 'security-events': 'write', actions: 'read' } : {}),
      },
      strategy: {
        'fail-fast': false,
        matrix: {
          environment: o.environments,
          node: o.nodeVersions,
          include,
        },
      },
      steps,
    };
  }

  private scorecardJob(): Mapping {
    const o = this.options;
    return {
      name: 'PR scorecard',
      needs: 'validate',
      if: "always() && github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository",
      'runs-on': 'ubuntu-latest',
      'timeout-minutes': o.timeoutMinutes,
      // No checkout: this job holds a write token, so it never runs PR code.
      permissions: { 'pull-requests': 'write' },
      steps: [
        {
          name: 'Set up Node.js',
          uses: this.uses('setupNode'),
          with: { 'node-version': this.primaryNode },
        },
        {
          name: 'Install stellar-toml-lint',
          env: { TOOL: `stellar-toml-lint@${o.toolVersion}` },
          run: 'npm install --global --no-audit --no-fund --ignore-scripts "$TOOL"',
        },
        {
          name: 'Download scorecards',
          uses: this.uses('downloadArtifact'),
          with: { pattern: 'stellar-toml-lint-*', path: 'scorecards' },
        },
        {
          name: 'Render scorecard',
          env: {
            RUN_URL:
              '${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}',
            COMMIT_SHA: '${{ github.event.pull_request.head.sha }}',
          },
          run: 'stellar-toml-lint ci-scorecard --input scorecards --output scorecard.md --run-url "$RUN_URL" --commit "$COMMIT_SHA"',
        },
        {
          name: 'Post scorecard comment',
          uses: this.uses('githubScript'),
          env: { MARKER: SCORECARD_MARKER },
          with: { script: PR_COMMENT_SCRIPT },
        },
      ],
    };
  }
}

/**
 * Upserts the bot comment: edits the previous scorecard in place so a busy pull
 * request carries one current comment rather than one per push.
 */
const PR_COMMENT_SCRIPT = `const fs = require('node:fs');
const body = fs.readFileSync('scorecard.md', 'utf8');
const marker = process.env.MARKER;
const { owner, repo } = context.repo;
const issue_number = context.payload.pull_request.number;
const comments = await github.paginate(github.rest.issues.listComments, {
  owner,
  repo,
  issue_number,
  per_page: 100,
});
const previous = comments.find(
  (c) => c.user?.type === 'Bot' && typeof c.body === 'string' && c.body.includes(marker),
);
if (previous) {
  await github.rest.issues.updateComment({ owner, repo, comment_id: previous.id, body });
} else {
  await github.rest.issues.createComment({ owner, repo, issue_number, body });
}
`;

/** Appends `# vX.Y.Z` after every pinned SHA so reviewers can read the version. */
function pinComments(yaml: string, actions: Record<CiActionName, PinnedAction>): string {
  let out = yaml;
  for (const action of Object.values(actions)) {
    const ref = `${action.uses}@${action.sha}`;
    out = out.split(`${ref}\n`).join(`${ref} # ${action.version}\n`);
  }
  return out;
}

function resolve(options: CiMatrixWorkflowOptions): ResolvedOptions {
  const environments = [...(options.environments ?? ['testnet', 'public'])];
  if (environments.length === 0) throw new Error('At least one environment is required');
  if (new Set(environments).size !== environments.length) {
    throw new Error('Environments must be unique');
  }
  for (const env of environments) {
    if (!(env in CI_ENVIRONMENTS)) throw new Error(`Unknown environment "${env}"`);
  }

  const nodeVersions = [...new Set(options.nodeVersions ?? ['20', '22'])];
  if (nodeVersions.length === 0) throw new Error('At least one Node.js version is required');
  for (const version of nodeVersions) {
    if (!NODE_VERSION.test(version)) throw new Error(`Invalid Node.js version "${version}"`);
    if (Number(version.split('.')[0]) < 20) {
      throw new Error(`stellar-toml-lint requires Node.js 20 or newer, got "${version}"`);
    }
  }

  const pattern = options.filePattern ?? DEFAULT_FILE_PATTERN;
  const files = {} as Record<CiEnvironmentName, string>;
  const checkNetwork = {} as Record<CiEnvironmentName, boolean>;
  for (const env of environments) {
    const file = options.files?.[env] ?? pattern.split('{environment}').join(env);
    assertSafePath(file, `file for ${env}`);
    files[env] = file;
    const flag = options.checkNetwork;
    checkNetwork[env] =
      typeof flag === 'boolean'
        ? flag
        : (flag?.[env] ?? CI_ENVIRONMENTS[env].checkNetworkByDefault);
  }

  const toolVersion = options.toolVersion ?? '0.1.0';
  if (!SEMVER.test(toolVersion)) {
    throw new Error(`toolVersion must be an exact semver version, got "${toolVersion}"`);
  }

  const timeoutMinutes = options.timeoutMinutes ?? 5;
  if (!Number.isInteger(timeoutMinutes) || timeoutMinutes < 1 || timeoutMinutes > 360) {
    throw new Error('timeoutMinutes must be an integer between 1 and 360');
  }

  const branches = [...(options.branches ?? ['main'])];
  for (const branch of branches) assertSafePath(branch, 'branch');

  const workflowPath = options.workflowPath ?? DEFAULT_WORKFLOW_PATH;
  assertSafePath(workflowPath, 'workflow path');

  const actions = { ...DEFAULT_PINNED_ACTIONS, ...options.actions };
  for (const [name, action] of Object.entries(actions)) {
    if (!SHA.test(action.sha)) {
      throw new Error(`Action "${name}" must be pinned to a full 40-character commit SHA`);
    }
  }

  const workflowName = options.workflowName ?? 'stellar.toml environment matrix';
  if (/[\r\n]/.test(workflowName)) throw new Error('workflowName must be a single line');

  return {
    environments,
    nodeVersions,
    files,
    checkNetwork,
    strict: options.strict ?? false,
    sarif: options.sarif ?? true,
    prComment: options.prComment ?? true,
    cache: options.cache ?? true,
    toolVersion,
    workflowName,
    branches,
    timeoutMinutes,
    workflowPath,
    actions,
  };
}

function assertSafePath(value: string, what: string): void {
  if (
    value.trim() === '' ||
    UNSAFE_PATH.test(value) ||
    hasControlCharacter(value) ||
    value.startsWith('/') ||
    value.includes('..')
  ) {
    throw new Error(`Unsafe ${what} "${value}": use a plain repository-relative path`);
  }
}

// ---------------------------------------------------------------------------
// Structural validation against the GitHub Actions workflow schema.
// ---------------------------------------------------------------------------

const WORKFLOW_KEYS = new Set([
  'name',
  'run-name',
  'on',
  'permissions',
  'env',
  'defaults',
  'concurrency',
  'jobs',
]);
const JOB_KEYS = new Set([
  'name',
  'needs',
  'runs-on',
  'environment',
  'outputs',
  'env',
  'defaults',
  'if',
  'steps',
  'timeout-minutes',
  'strategy',
  'continue-on-error',
  'container',
  'services',
  'permissions',
  'concurrency',
  'uses',
  'with',
  'secrets',
]);
const STEP_KEYS = new Set([
  'id',
  'if',
  'name',
  'uses',
  'run',
  'working-directory',
  'shell',
  'with',
  'env',
  'continue-on-error',
  'timeout-minutes',
]);
const PERMISSION_SCOPES = new Set([
  'actions',
  'attestations',
  'checks',
  'contents',
  'deployments',
  'discussions',
  'id-token',
  'issues',
  'models',
  'packages',
  'pages',
  'pull-requests',
  'repository-projects',
  'security-events',
  'statuses',
]);
const EVENTS = new Set([
  'pull_request',
  'pull_request_target',
  'push',
  'workflow_dispatch',
  'schedule',
  'workflow_call',
  'merge_group',
  'release',
]);
const JOB_ID = /^[A-Za-z_][A-Za-z0-9_-]*$/;
const PINNED_USES = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}$/;
/** Contexts an attacker controls; interpolating them into `run` is injection. */
const UNTRUSTED_IN_RUN = /\$\{\{[^}]*github\.(?:event\.|head_ref)/;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function checkPermissions(value: unknown, where: string, problems: string[]): void {
  if (value === 'read-all' || value === 'write-all') {
    problems.push(`${where}: broad "${value}" permissions; grant individual scopes instead`);
    return;
  }
  if (!isObject(value)) {
    problems.push(`${where}: permissions must be a mapping`);
    return;
  }
  for (const [scope, level] of Object.entries(value)) {
    if (!PERMISSION_SCOPES.has(scope)) problems.push(`${where}: unknown permission "${scope}"`);
    if (level !== 'read' && level !== 'write' && level !== 'none') {
      problems.push(`${where}: permission "${scope}" must be read, write, or none`);
    }
  }
}

/**
 * Checks a parsed workflow against the parts of the GitHub Actions schema (and
 * the hardening rules) that the generator relies on. Returns one message per
 * problem; an empty array means the workflow is valid.
 */
export function validateWorkflow(workflow: unknown): string[] {
  const problems: string[] = [];
  if (!isObject(workflow)) return ['workflow must be a mapping'];

  for (const key of Object.keys(workflow)) {
    if (!WORKFLOW_KEYS.has(key)) problems.push(`unknown top-level key "${key}"`);
  }
  if (typeof workflow.name !== 'string' || workflow.name === '') {
    problems.push('workflow needs a name');
  }

  const on = workflow.on;
  if (!isObject(on) || Object.keys(on).length === 0) {
    problems.push('"on" must map at least one event');
  } else {
    for (const event of Object.keys(on)) {
      if (!EVENTS.has(event)) problems.push(`unsupported event "${event}"`);
      if (event === 'pull_request_target') {
        problems.push('pull_request_target runs fork code with a write token; use pull_request');
      }
    }
  }

  if (workflow.permissions === undefined) {
    problems.push('top-level permissions must be set explicitly');
  } else {
    checkPermissions(workflow.permissions, 'workflow', problems);
  }

  const jobs = workflow.jobs;
  if (!isObject(jobs) || Object.keys(jobs).length === 0) {
    problems.push('"jobs" must define at least one job');
    return problems;
  }

  for (const [id, job] of Object.entries(jobs)) {
    const where = `jobs.${id}`;
    if (!JOB_ID.test(id)) problems.push(`${where}: invalid job id`);
    if (!isObject(job)) {
      problems.push(`${where}: must be a mapping`);
      continue;
    }
    for (const key of Object.keys(job)) {
      if (!JOB_KEYS.has(key)) problems.push(`${where}: unknown key "${key}"`);
    }
    if (job['runs-on'] === undefined) problems.push(`${where}: missing runs-on`);
    if (job.permissions === undefined) {
      problems.push(`${where}: permissions must be set explicitly`);
    } else {
      checkPermissions(job.permissions, where, problems);
    }
    const timeout = job['timeout-minutes'];
    if (typeof timeout !== 'number' || timeout <= 0) {
      problems.push(`${where}: timeout-minutes must be a positive number`);
    }
    const needs = job.needs === undefined ? [] : [job.needs].flat();
    for (const need of needs) {
      if (typeof need !== 'string' || !(need in jobs)) {
        problems.push(`${where}: needs unknown job "${String(need)}"`);
      }
    }

    const strategy = job.strategy;
    if (strategy !== undefined) {
      const matrix = isObject(strategy) ? strategy.matrix : undefined;
      if (!isObject(matrix)) {
        problems.push(`${where}: strategy.matrix must be a mapping`);
      } else {
        for (const [axis, values] of Object.entries(matrix)) {
          if (!Array.isArray(values) || values.length === 0) {
            problems.push(`${where}: matrix axis "${axis}" must be a non-empty list`);
          }
        }
      }
    }

    const steps = job.steps;
    if (!Array.isArray(steps) || steps.length === 0) {
      problems.push(`${where}: steps must be a non-empty list`);
      continue;
    }
    const ids = new Set<string>();
    steps.forEach((step: unknown, i) => {
      const at = `${where}.steps[${i}]`;
      if (!isObject(step)) {
        problems.push(`${at}: must be a mapping`);
        return;
      }
      for (const key of Object.keys(step)) {
        if (!STEP_KEYS.has(key)) problems.push(`${at}: unknown key "${key}"`);
      }
      const hasUses = typeof step.uses === 'string';
      const hasRun = typeof step.run === 'string';
      if (hasUses === hasRun) problems.push(`${at}: needs exactly one of uses or run`);
      if (hasUses && !PINNED_USES.test(step.uses as string)) {
        problems.push(`${at}: "${String(step.uses)}" is not pinned to a full commit SHA`);
      }
      if (hasRun && UNTRUSTED_IN_RUN.test(step.run as string)) {
        problems.push(`${at}: run interpolates untrusted event data; pass it through env`);
      }
      if (step.with !== undefined && !hasUses) problems.push(`${at}: "with" requires "uses"`);
      if (step.with !== undefined) {
        if (!isObject(step.with)) problems.push(`${at}: "with" must be a mapping`);
        else {
          for (const [input, value] of Object.entries(step.with)) {
            if (isObject(value) || Array.isArray(value)) {
              problems.push(`${at}: input "${input}" must be a scalar`);
            }
          }
        }
      }
      if (typeof step.id === 'string') {
        if (ids.has(step.id)) problems.push(`${at}: duplicate step id "${step.id}"`);
        ids.add(step.id);
      }
    });

    const checkout = steps.find(
      (s: unknown) =>
        isObject(s) && typeof s.uses === 'string' && s.uses.startsWith('actions/checkout@'),
    ) as Record<string, unknown> | undefined;
    if (checkout && !(isObject(checkout.with) && checkout.with['persist-credentials'] === false)) {
      problems.push(`${where}: actions/checkout must set persist-credentials: false`);
    }
  }

  return problems;
}
