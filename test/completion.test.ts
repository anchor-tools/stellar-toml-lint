import { describe, expect, it } from 'vitest';
import { allRules } from '../src/rules/index.js';
import { COMPLETION_SHELLS, generateCompletion, isCompletionShell } from '../src/completion.js';

/** A representative sample of the flags every script must advertise. */
const LONG_FLAGS = [
  '--domain',
  '--format',
  '--strict',
  '--max-warnings',
  '--off',
  '--error',
  '--warn',
  '--check-network',
  '--check-contracts',
  '--mock-fixtures',
  '--completion',
];

describe('generateCompletion', () => {
  it('produces a bash script that knows every flag and rule id', () => {
    const bash = generateCompletion('bash', allRules);

    for (const flag of LONG_FLAGS) expect(bash).toContain(flag);
    for (const rule of allRules) expect(bash).toContain(rule.id);

    expect(bash).toContain('_stellar_toml_lint');
    expect(bash).toContain('complete -F _stellar_toml_lint stellar-toml-lint');
    expect(bash).toContain('compgen -W');
  });

  it('offers the format choices, including the newer reporters', () => {
    const bash = generateCompletion('bash', allRules);
    for (const format of ['text', 'json', 'sarif', 'checkstyle', 'markdown']) {
      expect(bash).toContain(format);
    }
  });

  it('produces a zsh script with a completion function', () => {
    const zsh = generateCompletion('zsh', allRules);

    expect(zsh.startsWith('#compdef stellar-toml-lint')).toBe(true);
    expect(zsh).toContain('_arguments');
    expect(zsh).toContain('_files');
    for (const rule of allRules) expect(zsh).toContain(rule.id);
    for (const flag of LONG_FLAGS) expect(zsh).toContain(flag);
  });

  it('produces valid fish completion syntax', () => {
    const fish = generateCompletion('fish', allRules);

    expect(fish).toContain('complete -c stellar-toml-lint');
    expect(fish).toContain('-l format');
    expect(fish).toContain('-l domain');
    expect(fish).toContain('markdown');
    for (const rule of allRules) expect(fish).toContain(rule.id);

    // Every non-comment line is a `complete` invocation.
    for (const line of fish.split('\n')) {
      if (line.trim() === '' || line.startsWith('#')) continue;
      expect(line.startsWith('complete -c stellar-toml-lint')).toBe(true);
    }
  });

  it('lets --off/--warn/--error complete to rule ids in every shell', () => {
    for (const shell of COMPLETION_SHELLS) {
      const script = generateCompletion(shell, allRules);
      for (const flag of ['--off', '--error', '--warn']) {
        expect(script, `${shell} missing ${flag}`).toContain(flag.slice(2));
      }
    }
  });
});

describe('isCompletionShell', () => {
  it('accepts bash, zsh, and fish and rejects anything else', () => {
    for (const shell of COMPLETION_SHELLS) expect(isCompletionShell(shell)).toBe(true);
    expect(isCompletionShell('powershell')).toBe(false);
    expect(isCompletionShell('unknown')).toBe(false);
  });
});
