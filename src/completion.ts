/**
 * Native shell completion scripts for the CLI.
 *
 * `--completion <shell>` prints a script to stdout that teaches the named shell
 * how to complete `stellar-toml-lint`'s flags, its output formats, the rule
 * ids accepted by `--off`/`--warn`/`--error`, and the `--preset` bundles. The
 * scripts are generated rather than hand-maintained so those values can never
 * drift from `allRules` and the preset registry:
 *
 * ```console
 * $ stellar-toml-lint --completion bash >> ~/.bashrc
 * $ eval "$(stellar-toml-lint --completion zsh)"
 * $ stellar-toml-lint --completion fish | source
 * ```
 */
import type { Rule } from './types.js';
import { PRESET_NAMES } from './presets.js';

/** Shells `--completion` knows how to emit a script for. */
export type CompletionShell = 'bash' | 'zsh' | 'fish';

/** Every shell the CLI can generate completions for, in help order. */
export const COMPLETION_SHELLS: readonly CompletionShell[] = ['bash', 'zsh', 'fish'];

/** True when `value` names a shell `--completion` supports. */
export function isCompletionShell(value: string): value is CompletionShell {
  return (COMPLETION_SHELLS as readonly string[]).includes(value);
}

/** `--format` choices, kept in step with the `Format` union in `cli.ts`. */
const FORMATS = [
  'text',
  'json',
  'ndjson',
  'sarif',
  'github',
  'junit',
  'html',
  'checkstyle',
  'markdown',
] as const;

/** `--graph` choices. */
const GRAPH_FORMATS = ['mermaid', 'dot'] as const;

interface FlagSpec {
  /** Long form, e.g. `--format`. */
  long: string;
  /** Short form when the CLI defines one, e.g. `-f`. */
  short?: string;
  /** One-line description shown by zsh and fish. */
  description: string;
  /** Fixed suggestions for the flag's value, when it takes one. */
  values?: readonly string[];
  /** The flag takes a value with no fixed suggestion set (paths, URLs, ...). */
  takesValue?: boolean;
}

/**
 * Every flag the CLI parses, with the metadata each shell generator needs.
 * Declared once so the three scripts cannot advertise different flag sets.
 */
const FLAGS: readonly FlagSpec[] = [
  { long: '--domain', short: '-d', description: 'Domain serving the file', takesValue: true },
  { long: '--format', short: '-f', description: 'Output format', values: FORMATS },
  { long: '--strict', description: 'Treat warnings as errors' },
  { long: '--max-warnings', description: 'Fail if warnings exceed n', takesValue: true },
  { long: '--off', description: 'Disable a rule' },
  { long: '--error', description: 'Raise a rule to error' },
  { long: '--warn', description: 'Lower a rule to warning' },
  { long: '--preset', description: 'Role-based rule bundle', values: PRESET_NAMES },
  { long: '--interactive', short: '-i', description: 'Full-screen dashboard of the findings' },
  { long: '--lsp', description: 'Run as a Language Server on stdio' },
  { long: '--quiet', short: '-q', description: 'Report errors only' },
  { long: '--show-help-urls', description: 'Print the spec link for each finding' },
  { long: '--no-suggestions', description: 'Hide diagnostic suggestions' },
  { long: '--check-network', description: 'Verify accounts and endpoints online' },
  { long: '--verify-sep10', description: 'Verify SEP-10 nonce replay resistance' },
  { long: '--check-contracts', description: 'Verify Soroban contract TTL liveliness' },
  { long: '--soroban-rpc', description: 'Soroban RPC endpoint', takesValue: true },
  { long: '--mock-fixtures', description: 'Serve network checks from fixtures', takesValue: true },
  { long: '--webhook-slack', description: 'Slack webhook URL', takesValue: true },
  { long: '--webhook-discord', description: 'Discord webhook URL', takesValue: true },
  { long: '--badge-svg', description: 'Write an SVG compliance badge', takesValue: true },
  { long: '--badge-json', description: 'Write a Shields.io JSON endpoint', takesValue: true },
  { long: '--export-ap-config', description: 'Export Anchor Platform YAML config' },
  { long: '--generate-openapi', description: 'Write an OpenAPI 3.1 spec', takesValue: true },
  { long: '--graph', description: 'Generate an architecture diagram', values: GRAPH_FORMATS },
  { long: '--graph-contracts', description: 'Include Soroban contracts in the diagram' },
  { long: '--graph-validators', description: 'Include validators in the diagram' },
  { long: '--graph-color', description: 'Color diagram nodes by protocol type' },
  { long: '--policy', description: 'Evaluate an enterprise policy file', takesValue: true },
  { long: '--json-schema', description: 'Print a JSON Schema for stellar.toml' },
  { long: '--color', description: 'Force colour on' },
  { long: '--no-color', description: 'Force colour off' },
  { long: '--list-rules', description: 'Print every rule and exit' },
  {
    long: '--completion',
    description: 'Print a shell completion script',
    values: COMPLETION_SHELLS,
  },
  { long: '--version', short: '-v', description: 'Print the version' },
  { long: '--help', short: '-h', description: 'Print usage' },
];

/** Rule-override flags, which complete to the registered rule ids. */
const RULE_FLAGS = ['--off', '--error', '--warn'] as const;

function ruleIds(rules: Rule[]): string[] {
  return rules.map((rule) => rule.id).sort();
}

/** Long flags plus short flags, as a single space-separated word list. */
function flagWords(): string[] {
  const words: string[] = [];
  for (const flag of FLAGS) {
    words.push(flag.long);
    if (flag.short) words.push(flag.short);
  }
  return words;
}

/**
 * Builds the completion script for `shell`, completing `--off`/`--warn`/
 * `--error` with the ids of every rule in `rules`.
 */
export function generateCompletion(shell: CompletionShell, rules: Rule[]): string {
  switch (shell) {
    case 'bash':
      return bashCompletion(rules);
    case 'zsh':
      return zshCompletion(rules);
    case 'fish':
      return fishCompletion(rules);
  }
}

function bashValueCase(): string[] {
  const lines: string[] = [];
  for (const flag of FLAGS) {
    if (flag.values === undefined) continue;
    const patterns = [flag.long, ...(flag.short ? [flag.short] : [])].join('|');
    lines.push(`    ${patterns})`);
    lines.push(`      COMPREPLY=( $(compgen -W "${flag.values.join(' ')}" -- "$cur") )`);
    lines.push('      return 0');
    lines.push('      ;;');
  }
  for (const flag of RULE_FLAGS) {
    lines.push(`    ${flag})`);
    lines.push('      COMPREPLY=( $(compgen -W "$rules" -- "$cur") )');
    lines.push('      return 0');
    lines.push('      ;;');
  }
  return lines;
}

function bashCompletion(rules: Rule[]): string {
  const ids = ruleIds(rules);
  return [
    '# stellar-toml-lint completion for bash.',
    '# Load it with: eval "$(stellar-toml-lint --completion bash)"',
    '_stellar_toml_lint() {',
    '  local cur prev rules',
    '  COMPREPLY=()',
    '  cur="${COMP_WORDS[COMP_CWORD]}"',
    '  prev="${COMP_WORDS[COMP_CWORD-1]}"',
    `  rules="${ids.join(' ')}"`,
    '',
    '  case "$prev" in',
    ...bashValueCase(),
    '  esac',
    '',
    '  if [[ "$cur" == -* ]]; then',
    `    COMPREPLY=( $(compgen -W "${flagWords().join(' ')}" -- "$cur") )`,
    '    return 0',
    '  fi',
    '',
    '  COMPREPLY=( $(compgen -f -- "$cur") )',
    '}',
    'complete -F _stellar_toml_lint stellar-toml-lint',
    '',
  ].join('\n');
}

function zshCompletion(rules: Rule[]): string {
  const ids = ruleIds(rules);
  const lines: string[] = [
    '#compdef stellar-toml-lint',
    '# stellar-toml-lint completion for zsh.',
    '# Load it with: eval "$(stellar-toml-lint --completion zsh)"',
    '',
    '_stellar_toml_lint() {',
    '  local -a rules',
    `  rules=(${ids.join(' ')})`,
    '',
    '  _arguments -s \\',
  ];

  const entries: string[] = [];
  for (const flag of FLAGS) {
    const target = flag.short ? `{${flag.short},${flag.long}}` : flag.long;
    let spec = `'${target}[${flag.description.replace(/'/g, "'\\''")}]`;
    if (flag.values !== undefined) {
      spec += `:value:(${flag.values.join(' ')})`;
    } else if (flag.takesValue) {
      spec += ':value:_files';
    }
    entries.push(`    ${spec}' \\`);
  }
  for (const flag of RULE_FLAGS) {
    entries.push(`    '${flag}[rule id]:rule:($rules)' \\`);
  }
  entries.push("    '*:file:_files'");

  lines.push(...entries);
  lines.push('}');
  lines.push('');
  lines.push('_stellar_toml_lint "$@"');
  lines.push('');
  return lines.join('\n');
}

function fishCompletion(rules: Rule[]): string {
  const ids = ruleIds(rules);
  const lines: string[] = [
    '# stellar-toml-lint completion for fish.',
    '# Load it with: stellar-toml-lint --completion fish | source',
  ];

  for (const flag of FLAGS) {
    const parts = ['complete', '-c', 'stellar-toml-lint', '-l', flag.long.slice(2)];
    if (flag.short) parts.push('-s', flag.short.slice(1));
    parts.push('-d', `'${flag.description.replace(/'/g, "\\'")}'`);
    if (flag.values !== undefined) {
      parts.push('-r', '-a', `'${flag.values.join(' ')}'`);
    } else if (flag.takesValue) {
      parts.push('-r', '-F');
    }
    lines.push(parts.join(' '));
  }

  for (const flag of RULE_FLAGS) {
    lines.push(
      `complete -c stellar-toml-lint -l ${flag.slice(2)} -r -d 'Rule id' -a '${ids.join(' ')}'`,
    );
  }

  lines.push('');
  return lines.join('\n');
}
