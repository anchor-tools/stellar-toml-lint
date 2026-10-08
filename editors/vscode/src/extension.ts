/**
 * Official VS Code extension client for `stellar-toml-lint --lsp`.
 *
 * Launches the background language server over stdio, routes SEP-1
 * diagnostics into the Problems panel, and exposes the three editor
 * commands the issue tracks: lint, format (safe `--fix` rewrites), and
 * wallet-readiness scoring.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { execFile } from 'node:child_process';
import * as vscode from 'vscode';
import { LanguageClient, TransportKind } from 'vscode-languageclient/node';
import type { LanguageClientOptions, ServerOptions } from 'vscode-languageclient/node';

let client: LanguageClient | undefined;
let statusBar: vscode.StatusBarItem | undefined;
let readinessChannel: vscode.OutputChannel | undefined;

/** File names this extension cares about: stellar.toml or anything under .well-known/. */
export function isStellarTomlDocument(document: vscode.TextDocument): boolean {
  const base = path.basename(document.fileName);
  if (base === 'stellar.toml') return true;
  const normalized = document.fileName.replace(/\\/g, '/');
  if (normalized.includes('/.well-known/')) return true;
  if (document.languageId === 'toml' && base.endsWith('.toml')) {
    // A bare *.toml is only treated as stellar.toml by file name; the
    // documentSelector below narrows activation the same way.
    return base === 'stellar.toml';
  }
  return false;
}

/** Document selector matching a file named stellar.toml or any file within .well-known/. */
function documentSelector(): LanguageClientOptions['documentSelector'] {
  return [
    { scheme: 'file', pattern: '**/stellar.toml' },
    { scheme: 'file', pattern: '**/.well-known/*' },
    { scheme: 'file', pattern: '**/.well-known/**/*' },
    { scheme: 'untitled', pattern: '**/stellar.toml' },
  ];
}

interface StellarTomlSettings {
  strict: boolean;
  domain: string;
  rules: Record<string, string>;
}

/** Reads the `stellarToml.*` settings contributed in package.json. */
export function readSettings(): StellarTomlSettings {
  const config = vscode.workspace.getConfiguration('stellarToml');
  return {
    strict: config.get<boolean>('strict', false),
    domain: config.get<string>('domain', ''),
    rules: config.get<Record<string, string>>('rules', {}),
  };
}

/**
 * Locates the `stellar-toml-lint` CLI to spawn with `--lsp`.
 *
 * Prefers an explicit `stellarToml.serverPath`, then the built
 * `dist/cli.js` next to the checkout (`editors/vscode/../../dist/cli.js`),
 * and finally falls back to `stellar-toml-lint` on PATH so the packaged
 * `.vsix` works without shipping the whole repo.
 */
export function resolveServerCommand(context: vscode.ExtensionContext): {
  command: string;
  args: string[];
} {
  const configured = vscode.workspace
    .getConfiguration('stellarToml')
    .get<string>('serverPath', '')
    .trim();
  if (configured !== '') return { command: configured, args: ['--lsp'] };

  const candidates = [
    // Dev checkout: editors/vscode -> repo root -> dist/cli.js
    path.resolve(context.extensionPath, '..', '..', 'dist', 'cli.js'),
    path.resolve(context.extensionPath, 'dist', 'cli.js'),
  ];
  for (const candidate of candidates) {
    try {
      if (candidate.endsWith('.js') && fs.existsSync(candidate)) {
        return { command: process.execPath, args: [candidate, '--lsp'] };
      }
      if (fs.existsSync(candidate)) return { command: candidate, args: ['--lsp'] };
    } catch {
      // Try the next candidate.
    }
  }
  // Packaged install: the CLI is on PATH (npm i -g stellar-toml-lint).
  return { command: 'stellar-toml-lint', args: ['--lsp'] };
}

/** Same deductions as `computeScore` in src/generators/badge.ts. */
export function computeReadinessScore(counts: {
  error: number;
  warning: number;
  info: number;
}): number {
  const total = counts.error + counts.warning + counts.info;
  if (total === 0) return 100;
  return Math.max(0, Math.round(100 - (counts.error * 10 + counts.warning * 3 + counts.info)));
}

/** Same thresholds as the HTML report and the PR comment. */
export function gradeOf(score: number): string {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

function countsFor(document: vscode.TextDocument): {
  error: number;
  warning: number;
  info: number;
} {
  const counts = { error: 0, warning: 0, info: 0 };
  for (const diagnostic of vscode.languages.getDiagnostics(document.uri)) {
    if (diagnostic.source !== undefined && diagnostic.source !== 'stellar-toml-lint') continue;
    switch (diagnostic.severity) {
      case vscode.DiagnosticSeverity.Error:
        counts.error++;
        break;
      case vscode.DiagnosticSeverity.Warning:
        counts.warning++;
        break;
      default:
        counts.info++;
        break;
    }
  }
  return counts;
}

/** Refreshes the status bar from the active document's diagnostics. */
export function updateStatusBar(document?: vscode.TextDocument): void {
  if (!statusBar) return;
  const active = document ?? vscode.window.activeTextEditor?.document;
  if (!active || !isStellarTomlDocument(active)) {
    statusBar.hide();
    return;
  }
  const counts = countsFor(active);
  const { strict } = readSettings();
  const failing = strict ? counts.error + counts.warning : counts.error;
  if (failing === 0 && counts.error + counts.warning + counts.info === 0) {
    statusBar.text = '$(check) SEP-1 Valid';
    statusBar.tooltip = 'stellar.toml passes SEP-1';
  } else if (failing === 0) {
    statusBar.text = `$(check) SEP-1 Valid (${counts.warning} warning${counts.warning === 1 ? '' : 's'})`;
    statusBar.tooltip = 'stellar.toml passes SEP-1 with warnings';
  } else if (counts.error > 0) {
    statusBar.text = `$(error) ${counts.error} Error${counts.error === 1 ? '' : 's'}${
      counts.warning > 0 ? `, ${counts.warning} Warning${counts.warning === 1 ? '' : 's'}` : ''
    }`;
    statusBar.tooltip = 'stellar.toml has SEP-1 errors — see Problems panel';
  } else {
    statusBar.text = `$(warning) ${counts.warning} Warning${counts.warning === 1 ? '' : 's'}`;
    statusBar.tooltip = 'stellar.toml has SEP-1 warnings (strict mode)';
  }
  statusBar.show();
}

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  const { command, args } = resolveServerCommand(context);
  const settings = readSettings();

  const serverOptions: ServerOptions = {
    run: { command, args, transport: TransportKind.stdio },
    debug: { command, args, transport: TransportKind.stdio },
  };

  const clientOptions: LanguageClientOptions = {
    documentSelector: documentSelector(),
    synchronize: {
      // Notify the server when the linter policy changes so a saved
      // .stellartomlrc.json or settings edit re-lints without a restart.
      configurationSection: 'stellarToml',
      fileEvents: vscode.workspace.createFileSystemWatcher('**/stellar.toml'),
    },
    initializationOptions: {
      strict: settings.strict,
      domain: settings.domain || undefined,
      rules: settings.rules,
    },
  };

  client = new LanguageClient(
    'stellar-toml-lint',
    'Stellar TOML Lint',
    serverOptions,
    clientOptions,
  );

  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBar.command = 'stellar-toml.readiness';
  context.subscriptions.push(statusBar);

  readinessChannel =
    readinessChannel ?? vscode.window.createOutputChannel('Stellar TOML Readiness');
  context.subscriptions.push(readinessChannel);

  context.subscriptions.push(
    vscode.commands.registerCommand('stellar-toml.lint', async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor || !isStellarTomlDocument(editor.document)) {
        await vscode.window.showInformationMessage('Open a stellar.toml file to lint it.');
        return;
      }
      // Nudge the server (it re-publishes diagnostics on configuration
      // changes) and refresh the local status bar from the Problems panel.
      await client?.sendNotification('workspace/didChangeConfiguration', {
        settings: readSettings(),
      });
      updateStatusBar(editor.document);
      const counts = countsFor(editor.document);
      const total = counts.error + counts.warning + counts.info;
      if (total === 0) {
        await vscode.window.showInformationMessage('$(check) stellar.toml: no SEP-1 issues found.');
      }
    }),
    vscode.commands.registerCommand('stellar-toml.format', async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor || !isStellarTomlDocument(editor.document)) {
        await vscode.window.showInformationMessage('Open a stellar.toml file to format it.');
        return;
      }
      if (editor.document.isUntitled) {
        await vscode.window.showWarningMessage(
          'Save stellar.toml to a file before applying safe fixes.',
        );
        return;
      }
      await editor.document.save();
      const { command: cli, args: cliArgs } = resolveServerCommand(context);
      // Canonical formatting is the CLI's mechanical `--fix` pass.
      const fixArgs = cli.endsWith('cli.js')
        ? [cliArgs[0]!, '--fix', editor.document.fileName]
        : ['--fix', editor.document.fileName];
      const fixCommand = cli.endsWith('cli.js') ? process.execPath : cli;
      await new Promise<void>((resolve, reject) => {
        execFile(fixCommand, fixArgs, { timeout: 30_000 }, (error, stdout, stderr) => {
          if (error) {
            const detail = (stderr || stdout || error.message).trim();
            void vscode.window.showErrorMessage(`Stellar TOML format failed: ${detail}`);
            reject(error);
            return;
          }
          resolve();
        });
      }).catch(() => undefined);
      updateStatusBar(editor.document);
    }),
    vscode.commands.registerCommand('stellar-toml.readiness', async () => {
      const editor = vscode.window.activeTextEditor;
      const document = editor?.document;
      if (!document || !isStellarTomlDocument(document)) {
        await vscode.window.showInformationMessage('Open a stellar.toml file to score it.');
        return;
      }
      const counts = countsFor(document);
      const score = computeReadinessScore(counts);
      const grade = gradeOf(score);
      const line =
        counts.error + counts.warning + counts.info === 0
          ? `Wallet Readiness ${score}/100 (${grade}) — no SEP-1 findings in ${path.basename(document.fileName)}.`
          : `Wallet Readiness ${score}/100 (${grade}) — ${counts.error} error(s), ${counts.warning} warning(s), ${counts.info} info in ${path.basename(document.fileName)}.`;
      readinessChannel?.clear();
      readinessChannel?.appendLine(line);
      readinessChannel?.show(true);
      statusBar!.text =
        counts.error === 0
          ? `$(check) Readiness ${score}/100 (${grade})`
          : `$(error) Readiness ${score}/100 (${grade})`;
      statusBar!.show();
    }),
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      updateStatusBar(editor?.document);
    }),
    vscode.languages.onDidChangeDiagnostics(() => {
      updateStatusBar();
    }),
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (event.affectsConfiguration('stellarToml')) {
        void client?.sendNotification('workspace/didChangeConfiguration', {
          settings: readSettings(),
        });
        updateStatusBar();
      }
    }),
  );

  await client.start();
  updateStatusBar();
}

export async function deactivate(): Promise<void> {
  await client?.stop();
  client = undefined;
}
