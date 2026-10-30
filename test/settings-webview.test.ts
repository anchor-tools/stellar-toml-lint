import { afterEach, describe, expect, it } from 'vitest';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  applyWebviewMessage,
  parseRuleList,
  readProjectConfig,
  registerSettingsWebview,
  renderSettingsHtml,
  SETTINGS_COMMAND,
  writeProjectConfigAtomic,
} from '../editors/vscode/src/settings-webview.mjs';
import type { RuleInfo, SettingsSnapshot } from '../editors/vscode/src/settings-webview.mjs';

const RULES: RuleInfo[] = [
  {
    id: 'general/unknown-field',
    category: 'general',
    severity: 'warning',
    description: 'Unknown top-level field',
  },
  {
    id: 'currencies/issuance-exclusive',
    category: 'currencies',
    severity: 'error',
    description: 'A currency has both issuer and contract',
  },
];

const SNAPSHOT: SettingsSnapshot = {
  rules: { 'general/unknown-field': 'off' },
  strict: true,
  checkNetwork: false,
  domain: 'example.com',
  source: 'vscode',
};

const tempDirs: string[] = [];

afterEach(async () => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir !== undefined) await rm(dir, { recursive: true, force: true });
  }
});

async function tempDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'stellar-settings-'));
  tempDirs.push(dir);
  return dir;
}

function fakeVscode(projectPath?: string) {
  let command: ((...args: unknown[]) => unknown) | undefined;
  let message: ((value: unknown) => void | Promise<void>) | undefined;
  let disposePanel: (() => void) | undefined;
  const updates: [string, unknown][] = [];
  const panel = {
    webview: {
      html: '',
      onDidReceiveMessage(listener: (value: unknown) => void | Promise<void>) {
        message = listener;
        return { dispose: () => undefined };
      },
      postMessage: async () => true,
    },
    onDidDispose(listener: () => void) {
      disposePanel = listener;
      return { dispose: () => undefined };
    },
    dispose: () => undefined,
  };

  const api = {
    commands: {
      registerCommand(id: string, callback: (...args: unknown[]) => unknown) {
        expect(id).toBe(SETTINGS_COMMAND);
        command = callback;
        return { dispose: () => undefined };
      },
    },
    window: {
      createWebviewPanel: () => panel,
      showErrorMessage: () => undefined,
    },
    workspace: {
      findFiles: async () => (projectPath === undefined ? [] : [{ fsPath: projectPath }]),
      getConfiguration: () => ({
        get: <T>(_key: string, fallback?: T): T => fallback as T,
        update: async (key: string, value: unknown) => {
          updates.push([key, value]);
        },
      }),
    },
  };

  return {
    api,
    updates,
    panel,
    runCommand: async () => {
      await command?.();
      await new Promise((resolve) => setTimeout(resolve, 0));
    },
    send: async (value: unknown) => {
      await message?.(value);
    },
    close: () => disposePanel?.(),
  };
}

describe('settings webview', () => {
  it('parses --list-rules output into categorized rules', () => {
    const rules = parseRuleList(
      [
        '2 rules',
        '',
        '  currencies/issuance-exclusive  error    A currency has both issuer and contract',
        '  general/unknown-field          warning  Unknown top-level field',
        '',
      ].join('\n'),
    );

    expect(rules.map((r) => r.category).sort()).toEqual(['currencies', 'general']);
    expect(rules.map((r) => r.id).sort()).toEqual([
      'currencies/issuance-exclusive',
      'general/unknown-field',
    ]);
  });

  it('renders every rule with toggle, severity, and persistence script', () => {
    const html = renderSettingsHtml(RULES, SNAPSHOT);

    expect(html).toContain('general/unknown-field');
    expect(html).toContain('currencies/issuance-exclusive');
    expect(html).toContain('type="checkbox"');
    expect(html).toContain("vscode.postMessage({ type: 'update'");
    expect(html).toContain('Treat warnings as errors');
    expect(html).toContain('Saving to VS Code workspace settings');
  });

  it('applies snapshot and single-rule messages', () => {
    const updated = applyWebviewMessage(SNAPSHOT, {
      type: 'update',
      settings: {
        rules: { 'currencies/issuance-exclusive': 'info' },
        strict: false,
        checkNetwork: true,
        domain: 'anchor.example',
      },
    });
    expect(updated).toEqual({
      rules: { 'currencies/issuance-exclusive': 'info' },
      strict: false,
      checkNetwork: true,
      domain: 'anchor.example',
      source: 'vscode',
    });

    const one = applyWebviewMessage(updated, {
      type: 'setRule',
      id: 'general/unknown-field',
      severity: 'error',
    });
    expect(one.rules['general/unknown-field']).toBe('error');
  });

  it('writes a project config atomically and drops values equal to defaults', async () => {
    const dir = await tempDir();
    const path = join(dir, '.stellartomlrc.json');

    await writeProjectConfigAtomic(path, SNAPSHOT, RULES);
    const body = JSON.parse(await readFile(path, 'utf8'));

    expect(body).toEqual({
      rules: { 'general/unknown-field': 'off' },
      strict: true,
    });
    expect(await readProjectConfig(path)).toEqual({
      rules: { 'general/unknown-field': 'off' },
      strict: true,
    });
  });

  it('persists a webview update through the registered command', async () => {
    const dir = await tempDir();
    const path = join(dir, '.stellartomlrc.json');
    await writeFile(path, '{"rules":{"general/unknown-field":"off"},"strict":true}\n');
    const harness = fakeVscode(path);

    registerSettingsWebview(harness.api, { rules: RULES });
    await harness.runCommand();
    expect(harness.panel.webview.html).toContain('Saving to .stellartomlrc.json');

    await harness.send({
      type: 'update',
      settings: {
        rules: {
          'general/unknown-field': 'error',
          'currencies/issuance-exclusive': 'info',
        },
        strict: false,
        checkNetwork: false,
        domain: '',
      },
    });

    const body = JSON.parse(await readFile(path, 'utf8'));
    expect(body.rules).toEqual({
      'general/unknown-field': 'error',
      'currencies/issuance-exclusive': 'info',
    });
    expect(body.strict).toBe(false);
    harness.close();
  });

  it('updates VS Code settings when no project config exists', async () => {
    const harness = fakeVscode();
    registerSettingsWebview(harness.api, { rules: RULES });
    await harness.runCommand();

    await harness.send({
      type: 'update',
      settings: { rules: { 'general/unknown-field': 'error' }, strict: true },
    });

    expect(harness.updates).toContainEqual(['rules', { 'general/unknown-field': 'error' }]);
    expect(harness.updates).toContainEqual(['strict', true]);
    harness.close();
  });
});
