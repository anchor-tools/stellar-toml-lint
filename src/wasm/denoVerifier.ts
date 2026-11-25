/**
 * Deno and JSR compatibility, checked from Node.
 *
 * Deno runs the TypeScript sources directly, which changes three things a
 * Node-first package has to get right: every relative import needs an explicit
 * extension, bare specifiers need an import map (or a `jsr:`/`npm:` prefix),
 * and CommonJS globals do not exist. It also runs with permissions rather than
 * ambient access, so the CLI's own behaviour has to be expressible as
 * `--allow-read` for the files it lints and `--allow-net` for the domains it
 * probes.
 *
 * `DenoCompatibilityVerifier` checks those rules over source text without
 * executing anything, infers the minimal permission set for a run, and
 * validates that a `mod.ts` entry point re-exports only relative, explicit
 * specifiers — the shape JSR publishes. Nothing here imports Deno, so the check
 * runs in the existing test suite; the same verifier is what a `deno test` job
 * would call.
 */
export type DenoFindingKind =
  | 'commonjs'
  | 'missing-extension'
  | 'bare-specifier'
  | 'node-builtin'
  | 'test-runner'
  | 'over-broad-permission';

export interface DenoCompatibilityFinding {
  path: string;
  line: number;
  kind: DenoFindingKind;
  severity: 'error' | 'warning';
  message: string;
  specifier?: string;
}

export interface ImportedSpecifier {
  path: string;
  line: number;
  specifier: string;
}

export interface PermissionRequest {
  permission: 'read' | 'net' | 'env' | 'run';
  value: string;
}

export interface PermissionUsage {
  /** Files the linter reads: the target stellar.toml and config. */
  paths?: string[];
  /** Hosts contacted by the network checks. */
  domains?: string[];
  /** Environment variables read from the process. */
  env?: string[];
  /** Subprocesses spawned (none for a linter: this exists to be empty). */
  commands?: string[];
}

export interface DenoEntryPointReport {
  path: string;
  clean: boolean;
  findings: DenoCompatibilityFinding[];
}

export interface DenoCompatibilityReport {
  ok: boolean;
  findings: DenoCompatibilityFinding[];
  imports: ImportedSpecifier[];
  permissions: PermissionRequest[];
  permissionFlags: string[];
  entryPoint: DenoEntryPointReport;
}

export interface DenoVerifierOptions {
  /** Bare specifiers resolvable through the project's import map. */
  allowedBareSpecifiers?: string[];
  /** How to treat `node:` imports: Deno maps them through its Node compat layer. */
  nodeBuiltins?: 'allow' | 'warn' | 'error';
  entryPoint?: string;
  usage?: PermissionUsage;
}

const MODULE_EXTENSIONS = ['.ts', '.js', '.mjs', '.mts', '.json', '.wasm'];

const COMMONJS_PATTERNS: { pattern: RegExp; label: string }[] = [
  { pattern: /\brequire\s*\(/, label: 'CommonJS require()' },
  { pattern: /\bmodule\.exports\b/, label: 'CommonJS module.exports' },
  { pattern: /\bexports\.[A-Za-z_$]/, label: 'CommonJS exports' },
  { pattern: /\b__dirname\b/, label: '__dirname' },
  { pattern: /\b__filename\b/, label: '__filename' },
];

const READ_BUILTINS = new Set(['node:fs', 'node:fs/promises', 'node:path']);

function lineAt(source: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < source.length; i++) {
    if (source.charCodeAt(i) === 10) line++;
  }
  return line;
}

/**
 * Blanks out comments while preserving offsets and line breaks.
 *
 * A JSDoc example is documentation, not an import: flagging the `from` inside
 * it would make the package's own entry point look Deno-hostile. Strings are
 * left intact so an `https://` specifier survives.
 */
function stripComments(source: string): string {
  let out = '';
  let quote: string | null = null;

  for (let i = 0; i < source.length; i++) {
    const char = source[i] as string;

    if (quote !== null) {
      out += char;
      if (char === '\\') {
        out += source[i + 1] ?? '';
        i++;
      } else if (char === quote) {
        quote = null;
      }
      continue;
    }

    if (char === '"' || char === "'" || char === '`') {
      quote = char;
      out += char;
      continue;
    }

    if (char === '/' && source[i + 1] === '/') {
      while (i < source.length && source[i] !== '\n') {
        out += ' ';
        i++;
      }
      out += '\n';
      continue;
    }

    if (char === '/' && source[i + 1] === '*') {
      out += '  ';
      i += 2;
      while (i < source.length && !(source[i] === '*' && source[i + 1] === '/')) {
        out += source[i] === '\n' ? '\n' : ' ';
        i++;
      }
      out += '  ';
      i++;
      continue;
    }

    out += char;
  }

  return out;
}

/** Every specifier a module imports or re-exports, in source order. */
export function extractSpecifiers(path: string, source: string): ImportedSpecifier[] {
  const found: ImportedSpecifier[] = [];
  const code = stripComments(source);
  const patterns = [
    /\bfrom\s*['"]([^'"]+)['"]/g,
    /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
    /\bimport\s+['"]([^'"]+)['"]/g,
  ];

  for (const pattern of patterns) {
    for (const match of code.matchAll(pattern)) {
      const specifier = match[1];
      if (specifier === undefined) continue;
      const index = match.index ?? 0;
      if (
        found.some((entry) => entry.specifier === specifier && entry.line === lineAt(code, index))
      ) {
        continue;
      }
      found.push({ path, line: lineAt(code, index), specifier });
    }
  }

  return found.sort((a, b) => a.line - b.line);
}

/** Turns a permission usage into the narrowest Deno flags that allow it. */
export function permissionFlags(usage: PermissionUsage): string[] {
  const flags: string[] = [];
  if (usage.paths !== undefined && usage.paths.length > 0) {
    flags.push(`--allow-read=${usage.paths.join(',')}`);
  }
  if (usage.domains !== undefined && usage.domains.length > 0) {
    flags.push(`--allow-net=${usage.domains.join(',')}`);
  }
  if (usage.env !== undefined && usage.env.length > 0) {
    flags.push(`--allow-env=${usage.env.join(',')}`);
  }
  if (usage.commands !== undefined && usage.commands.length > 0) {
    flags.push(`--allow-run=${usage.commands.join(',')}`);
  }
  return flags;
}

/** A JSR-compatible manifest whose only export is the checked entry point. */
export function buildDenoManifest(options: {
  name: string;
  version: string;
  entryPoint?: string;
}): { name: string; version: string; exports: Record<string, string>; nodeModulesDir: false } {
  const entryPoint = options.entryPoint ?? 'mod.ts';
  return {
    name: options.name,
    version: options.version,
    exports: { '.': `./${entryPoint}` },
    nodeModulesDir: false,
  };
}

export class DenoCompatibilityVerifier {
  private readonly allowedBareSpecifiers: Set<string>;
  private readonly nodeBuiltins: 'allow' | 'warn' | 'error';
  private readonly entryPoint: string;
  private readonly usage: PermissionUsage;

  constructor(options: DenoVerifierOptions = {}) {
    this.allowedBareSpecifiers = new Set(options.allowedBareSpecifiers ?? []);
    this.nodeBuiltins = options.nodeBuiltins ?? 'warn';
    this.entryPoint = options.entryPoint ?? 'mod.ts';
    this.usage = options.usage ?? {};
  }

  /** Checks a set of source modules and the permissions their run needs. */
  verify(files: { path: string; source: string }[]): DenoCompatibilityReport {
    const findings: DenoCompatibilityFinding[] = [];
    const imports: ImportedSpecifier[] = [];

    for (const file of files) {
      imports.push(...extractSpecifiers(file.path, file.source));

      for (const { pattern, label } of COMMONJS_PATTERNS) {
        const match = pattern.exec(file.source);
        if (match !== null) {
          findings.push({
            path: file.path,
            line: lineAt(file.source, match.index),
            kind: 'commonjs',
            severity: 'error',
            message: `${label} does not exist under Deno's ESM runtime.`,
          });
        }
      }

      if (/\bfrom\s*['"]vitest['"]/.test(file.source)) {
        findings.push({
          path: file.path,
          line: 1,
          kind: 'test-runner',
          severity: 'warning',
          message:
            'Imports vitest; run the suite with `deno test` only if it is rewritten against Deno.test.',
        });
      }
    }

    for (const entry of imports) {
      findings.push(...this.checkSpecifier(entry));
    }

    const permissions = this.inferPermissions(files);
    findings.push(...this.checkPermissions(permissions));

    const entryPoint = this.checkEntryPoint(files);
    findings.push(...entryPoint.findings);

    return {
      ok: findings.every((finding) => finding.severity !== 'error'),
      findings,
      imports,
      permissions,
      permissionFlags: permissionFlags(this.usage),
      entryPoint,
    };
  }

  private checkSpecifier(entry: ImportedSpecifier): DenoCompatibilityFinding[] {
    const { specifier } = entry;

    if (specifier.startsWith('node:')) {
      if (this.nodeBuiltins === 'allow') return [];
      return [
        {
          path: entry.path,
          line: entry.line,
          kind: 'node-builtin',
          specifier,
          severity: this.nodeBuiltins === 'error' ? 'error' : 'warning',
          message: `${specifier} resolves through Deno's Node compatibility layer; a browser or JSR-only build cannot.`,
        },
      ];
    }

    if (
      specifier.startsWith('jsr:') ||
      specifier.startsWith('npm:') ||
      specifier.startsWith('https://')
    ) {
      return [];
    }

    if (specifier.startsWith('.') || specifier.startsWith('/')) {
      if (MODULE_EXTENSIONS.some((extension) => specifier.endsWith(extension))) return [];
      return [
        {
          path: entry.path,
          line: entry.line,
          kind: 'missing-extension',
          specifier,
          severity: 'error',
          message: `"${specifier}" needs an explicit .ts or .js extension under Deno.`,
        },
      ];
    }

    if (this.allowedBareSpecifiers.has(specifier)) return [];

    return [
      {
        path: entry.path,
        line: entry.line,
        kind: 'bare-specifier',
        specifier,
        severity: 'error',
        message: `"${specifier}" is a bare specifier; publish it as jsr:/npm: or map it in the import map.`,
      },
    ];
  }

  /** Infers the smallest permission set the run needs. */
  private inferPermissions(files: { path: string; source: string }[]): PermissionRequest[] {
    const requests: PermissionRequest[] = [];
    const add = (permission: PermissionRequest['permission'], value: string): void => {
      if (
        !requests.some((request) => request.permission === permission && request.value === value)
      ) {
        requests.push({ permission, value });
      }
    };

    for (const path of this.usage.paths ?? []) add('read', path);
    for (const domain of this.usage.domains ?? []) add('net', domain);
    for (const name of this.usage.env ?? []) add('env', name);
    for (const command of this.usage.commands ?? []) add('run', command);

    for (const file of files) {
      for (const entry of extractSpecifiers(file.path, file.source)) {
        if (READ_BUILTINS.has(entry.specifier) && (this.usage.paths ?? []).length === 0) {
          add('read', file.path);
        }
      }
      // A literal URL in a network check is the host the run must reach.
      for (const match of file.source.matchAll(/https?:\/\/([A-Za-z0-9.-]+)/g)) {
        const host = match[1];
        if (host !== undefined) add('net', host);
      }
      if (/\bprocess\.env\b/.test(file.source)) add('env', 'STELLAR_TOML_LINT_*');
    }

    return requests;
  }

  /** A wildcard permission asks for everything; that is not least privilege. */
  private checkPermissions(requests: PermissionRequest[]): DenoCompatibilityFinding[] {
    const findings: DenoCompatibilityFinding[] = [];
    for (const request of requests) {
      if (request.value === '' || request.value === '*' || request.value === '/') {
        findings.push({
          path: this.entryPoint,
          line: 1,
          kind: 'over-broad-permission',
          severity: 'error',
          message: `--allow-${request.permission} was requested without a concrete scope. Name the file or host instead.`,
        });
      }
    }
    return findings;
  }

  /** A `mod.ts` must re-export only relative specifiers with extensions. */
  checkEntryPoint(files: { path: string; source: string }[]): DenoEntryPointReport {
    const entry = files.find(
      (file) => file.path === this.entryPoint || file.path.endsWith(`/${this.entryPoint}`),
    );
    if (entry === undefined) {
      return {
        path: this.entryPoint,
        clean: false,
        findings: [
          {
            path: this.entryPoint,
            line: 1,
            kind: 'missing-extension',
            severity: 'warning',
            message: `No ${this.entryPoint} in the checked sources; JSR publishes the "exports" map instead.`,
          },
        ],
      };
    }

    const findings: DenoCompatibilityFinding[] = [];
    for (const imported of extractSpecifiers(entry.path, entry.source)) {
      const isRelative =
        imported.specifier.startsWith('./') || imported.specifier.startsWith('../');
      const hasExtension = MODULE_EXTENSIONS.some((extension) =>
        imported.specifier.endsWith(extension),
      );
      if (isRelative && hasExtension) continue;
      findings.push({
        path: entry.path,
        line: imported.line,
        kind: isRelative ? 'missing-extension' : 'bare-specifier',
        specifier: imported.specifier,
        severity: 'error',
        message: `Entry point must re-export a relative module with an explicit extension, not "${imported.specifier}".`,
      });
    }

    return { path: entry.path, clean: findings.length === 0, findings };
  }
}
