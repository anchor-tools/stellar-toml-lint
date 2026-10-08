import { describe, expect, it } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const vscodeDir = join(root, 'editors', 'vscode');

function read(rel: string): string {
  return readFileSync(join(vscodeDir, rel), 'utf8');
}

const manifest = JSON.parse(read('package.json'));
const clientSource = read(join('src', 'extension.ts'));

describe('vscode extension manifest', () => {
  it('activates for stellar.toml and .well-known files', () => {
    const events: string[] = manifest.activationEvents ?? [];
    const blob = events.join('\n');
    expect(blob).toContain('stellar.toml');
    expect(blob).toContain('.well-known');
  });

  it('registers the lint, format, and readiness commands', () => {
    const ids = (manifest.contributes.commands as { command: string }[]).map((c) => c.command);
    expect(ids).toContain('stellar-toml.lint');
    expect(ids).toContain('stellar-toml.format');
    expect(ids).toContain('stellar-toml.readiness');
  });

  it('contributes the stellarToml strict/domain/rules settings', () => {
    const props = manifest.contributes.configuration.properties as Record<string, unknown>;
    expect(props).toHaveProperty('stellarToml.strict');
    expect(props).toHaveProperty('stellarToml.domain');
    expect(props).toHaveProperty('stellarToml.rules');
  });

  it('keeps the SEP-1 TextMate injection grammar', () => {
    const grammars = manifest.contributes.grammars as { scopeName: string; path: string }[];
    expect(grammars.some((g) => g.scopeName === 'stellar.toml.injection')).toBe(true);
    const grammarPath = join(vscodeDir, grammars[0]!.path);
    expect(existsSync(grammarPath)).toBe(true);
  });

  it('vendors the grammar inside the extension so the .vsix ships it', () => {
    const grammars = manifest.contributes.grammars as { scopeName: string; path: string }[];
    // Paths escaping the extension dir (../..) are excluded from the .vsix.
    for (const grammar of grammars) expect(grammar.path).not.toContain('..');
    const vendored = readFileSync(join(vscodeDir, grammars[0]!.path), 'utf8');
    const canonical = readFileSync(join(root, 'syntaxes', 'stellar-toml.tmLanguage.json'), 'utf8');
    expect(vendored).toBe(canonical);
  });

  it('depends on vscode-languageclient and packages with vsce', () => {
    expect(manifest.dependencies).toHaveProperty('vscode-languageclient');
    expect(manifest.devDependencies).toHaveProperty('@vscode/vsce');
  });

  it('points main at the compiled client', () => {
    expect(manifest.main as string).toMatch(/out\/extension\.js/);
  });
});

describe('vscode extension client', () => {
  it('launches stellar-toml-lint --lsp over stdio', () => {
    expect(clientSource).toContain('--lsp');
    expect(clientSource).toContain('TransportKind.stdio');
    expect(clientSource).toContain('LanguageClient');
    expect(clientSource).toContain('dist/cli.js');
  });

  it('selects stellar.toml and .well-known documents', () => {
    expect(clientSource).toContain('stellar.toml');
    expect(clientSource).toContain('.well-known');
    expect(clientSource).toContain('documentSelector');
  });

  it('registers all three commands and a status bar item', () => {
    expect(clientSource).toContain('stellar-toml.lint');
    expect(clientSource).toContain('stellar-toml.format');
    expect(clientSource).toContain('stellar-toml.readiness');
    expect(clientSource).toContain('createStatusBarItem');
    expect(clientSource).toContain('SEP-1 Valid');
  });

  it('shows readiness with the badge score formula and grades', () => {
    // 100 - 10*errors - 3*warnings - info, grades A-F at 90/80/70/60.
    expect(clientSource).toContain('counts.error * 10');
    expect(clientSource).toContain('counts.warning * 3');
    expect(clientSource).toContain('Wallet Readiness');
  });

  it('formats via the --fix pass', () => {
    expect(clientSource).toContain('--fix');
  });

  it('publishes unfixable-safe behaviour: parse errors never produce edits here', () => {
    // The client delegates fixes to the server/CLI; it must not invent edits.
    expect(clientSource).not.toMatch(/newText:\s*['"]fixed['"]/i);
  });
});

describe('vscode packaging and docs', () => {
  it('adds build:vscode and package:vscode scripts to the root package.json', () => {
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    expect(Object.keys(pkg.scripts)).toContain('build:vscode');
    expect(pkg.scripts['build:vscode']).toContain('editors/vscode');
    expect(Object.keys(pkg.scripts)).toContain('package:vscode');
    expect(pkg.scripts['package:vscode']).toContain('vsce');
  });

  it('ships an extension README documenting commands and settings', () => {
    const readme = read('README.md');
    expect(readme).toContain('stellar-toml.lint');
    expect(readme).toContain('stellar-toml.format');
    expect(readme).toContain('stellar-toml.readiness');
    expect(readme).toContain('stellarToml.strict');
    expect(readme).toContain('stellarToml.domain');
    expect(readme).toContain('--lsp');
  });

  it('mentions the extension in the root README', () => {
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    expect(readme).toContain('editors/vscode');
    expect(readme).toContain('stellar-toml.lint');
  });
});
