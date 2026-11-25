/**
 * Interactive rule settings for the VS Code extension.
 *
 * Editing `stellarToml.rules` in `settings.json` means remembering rule ids,
 * quoting severity strings, and getting the object shape right. This module
 * contributes `stellarToml.openSettings`, which renders every rule grouped by
 * the track it belongs to, lets the reader toggle a rule or change its
 * severity, and persists the change to the nearest `.stellartomlrc.json` when
 * the project has one (or to VS Code settings otherwise).
 *
 * The command host is injected rather than imported so the HTML renderer,
 * message reducer, and atomic file writer can be tested without a running
 * editor.
 */
import { execFile } from 'node:child_process';
import { readFile, rename, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

export const SETTINGS_VIEW_TYPE = 'stellarToml.settings';
export const SETTINGS_COMMAND = 'stellarToml.openSettings';
export const SETTINGS_COMMAND_ALIAS = 'stellar-toml.openSettings';

export type RuleSeverity = 'error' | 'warning' | 'info';
export type RuleSetting = RuleSeverity | 'off';

export interface RuleInfo {
  id: string;
  category: string;
  severity: RuleSeverity;
  description: string;
}

export interface SettingsSnapshot {
  /** Effective overrides, keyed by rule id. */
  rules: Record<string, RuleSetting>;
  strict: boolean;
  checkNetwork: boolean;
  domain: string;
  /** Where the settings came from, so the webview can say which file wins. */
  source: 'project' | 'vscode';
}

export interface ProjectConfigFile {
  rules?: Record<string, RuleSetting>;
  strict?: boolean;
  maxWarnings?: number;
}

export interface CliCommand {
  command: string;
  args: string[];
}

export interface SettingsWebviewOptions {
  /** CLI command used to discover every registered rule. */
  cli?: CliCommand;
  /** Pre-supplied catalogue, mainly for tests and embedders. */
  rules?: RuleInfo[];
  /** Called after a change is persisted so the extension can re-lint. */
  onSettingsChanged?: (snapshot: SettingsSnapshot) => void;
}

interface Disposable {
  dispose(): void;
}

interface Webview {
  html: string;
  onDidReceiveMessage(listener: (message: unknown) => void | Promise<void>): Disposable;
  postMessage(message: unknown): PromiseLike<boolean> | boolean;
}

interface WebviewPanel {
  webview: Webview;
  onDidDispose?(listener: () => void): Disposable;
  reveal?(viewColumn?: number): void;
  dispose(): void;
}

interface UriLike {
  fsPath: string;
  toString(): string;
}

interface VscodeApi {
  commands: {
    registerCommand(command: string, callback: (...args: unknown[]) => unknown): Disposable;
  };
  window: {
    createWebviewPanel(
      viewType: string,
      title: string,
      showOptions: number,
      options: { enableScripts?: boolean; retainContextWhenHidden?: boolean },
    ): WebviewPanel;
    showInformationMessage?(message: string): unknown;
    showErrorMessage?(message: string): unknown;
  };
  workspace: {
    findFiles?(
      include: string,
      exclude?: string | null,
      maxResults?: number,
    ): PromiseLike<UriLike[]> | UriLike[];
    getConfiguration(section: string): {
      get<T>(key: string, defaultValue?: T): T;
      update(key: string, value: unknown, target?: number | boolean | null): PromiseLike<void>;
    };
  };
  ViewColumn?: { Active: number };
  ConfigurationTarget?: { Workspace: number; Global: number };
}

const CATEGORY_TITLES: Record<string, string> = {
  file: 'File and size',
  general: 'General SEP-1',
  documentation: 'Organization documentation',
  principals: 'Principals',
  currencies: 'Currencies',
  validators: 'Validators',
  network: 'Network and endpoints',
  security: 'Security',
  soroban: 'Soroban contracts',
  sep12: 'SEP-12 customer data',
  monitor: 'Monitoring',
  policy: 'Policy engine',
  codemod: 'Codemods',
  history: 'History archives',
  overlay: 'Overlay',
  protocols: 'Protocols',
  corridor: 'Corridors',
};

/** A rule's track is the prefix of its id; `general/unknown-field` is general. */
export function categoryOf(ruleId: string): string {
  const slash = ruleId.indexOf('/');
  return slash < 0 ? 'general' : ruleId.slice(0, slash);
}

/** Human-readable heading for a track. */
export function categoryTitle(category: string): string {
  if (CATEGORY_TITLES[category] !== undefined) return CATEGORY_TITLES[category];
  return category
    .split(/[-_]/)
    .map((part) => (part === '' ? part : part[0]!.toUpperCase() + part.slice(1)))
    .join(' ');
}

/**
 * Parses `stellar-toml-lint --list-rules` into rule metadata.
 *
 * The CLI's output is stable (`id severity description`), but the parser
 * tolerates the count header and blank lines so a future formatting tweak does
 * not empty the settings panel.
 */
export function parseRuleList(output: string): RuleInfo[] {
  const rules: RuleInfo[] = [];
  for (const line of output.split(/\r?\n/)) {
    const match = /^\s{2,}(\S+)\s+(error|warning|info)\s+(.+?)\s*$/.exec(line);
    if (match === null) continue;
    const [, id, severity, description] = match;
    if (id === undefined || severity === undefined || description === undefined) continue;
    rules.push({
      id,
      category: categoryOf(id),
      severity: severity as RuleSeverity,
      description,
    });
  }
  return rules;
}

/** Runs `--list-rules` through the same CLI the language server uses. */
export async function loadRuleCatalog(cli: CliCommand): Promise<RuleInfo[]> {
  const args = cli.args.filter((arg) => arg !== '--lsp');
  args.push('--list-rules');
  const { stdout } = await execFileAsync(cli.command, args, { timeout: 15_000 });
  return parseRuleList(stdout);
}

/** Groups rules by track, preserving the catalogue's order inside each group. */
export function groupRules(
  rules: RuleInfo[],
): { category: string; title: string; rules: RuleInfo[] }[] {
  const groups = new Map<string, RuleInfo[]>();
  for (const rule of rules) {
    const list = groups.get(rule.category) ?? [];
    list.push(rule);
    groups.set(rule.category, list);
  }
  return [...groups.entries()]
    .sort(([a], [b]) => categoryTitle(a).localeCompare(categoryTitle(b)))
    .map(([category, list]) => ({
      category,
      title: categoryTitle(category),
      rules: list,
    }));
}

/** The severity the UI should show for a rule. */
export function severityFor(rule: RuleInfo, overrides: Record<string, RuleSetting>): RuleSetting {
  return overrides[rule.id] ?? rule.severity;
}

/** Reads and validates a project config file; malformed files are rejected. */
export async function readProjectConfig(path: string): Promise<ProjectConfigFile> {
  const raw = JSON.parse(await readFile(path, 'utf8')) as unknown;
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new Error(`${path} must contain a JSON object.`);
  }
  const source = raw as Record<string, unknown>;
  const rules: Record<string, RuleSetting> = {};
  if (typeof source.rules === 'object' && source.rules !== null && !Array.isArray(source.rules)) {
    for (const [id, value] of Object.entries(source.rules as Record<string, unknown>)) {
      if (value === 'off' || value === 'error' || value === 'warning' || value === 'info') {
        rules[id] = value;
      }
    }
  }
  return {
    rules,
    strict: source.strict === true,
    ...(typeof source.maxWarnings === 'number' ? { maxWarnings: source.maxWarnings } : {}),
  };
}

/**
 * Writes a project config atomically: a sibling temp file is written first and
 * renamed over the target, so a watcher never sees a half-written JSON object.
 */
export async function writeProjectConfigAtomic(
  path: string,
  snapshot: SettingsSnapshot,
  rules: RuleInfo[] = [],
): Promise<void> {
  const defaults = new Map(rules.map((rule) => [rule.id, rule.severity]));
  const overrides: Record<string, RuleSetting> = {};
  for (const [id, value] of Object.entries(snapshot.rules)) {
    if (defaults.get(id) !== value) overrides[id] = value;
  }

  const body: ProjectConfigFile = {
    rules: overrides,
    strict: snapshot.strict,
  };
  const temporary = join(dirname(path), `.stellartomlrc.${process.pid}.${Date.now()}.tmp`);
  await writeFile(temporary, `${JSON.stringify(body, null, 2)}\n`, 'utf8');
  await rename(temporary, path);
}

/**
 * Applies one webview message to the current settings.
 *
 * Two forms are accepted so the HTML can send a whole form snapshot while a
 * future embedder can send a single rule change:
 *
 * - `{ type: 'update', settings: { rules, strict, checkNetwork, domain } }`
 * - `{ type: 'setRule', id, severity }`
 */
export function applyWebviewMessage(current: SettingsSnapshot, message: unknown): SettingsSnapshot {
  if (typeof message !== 'object' || message === null) return current;
  const source = message as Record<string, unknown>;

  if (source.type === 'setRule' && typeof source.id === 'string') {
    const severity = normalizeSeverity(source.severity);
    if (severity === undefined) return current;
    return { ...current, rules: { ...current.rules, [source.id]: severity } };
  }

  if (source.type !== 'update') return current;
  if (typeof source.settings !== 'object' || source.settings === null) return current;
  const settings = source.settings as Record<string, unknown>;

  const rules: Record<string, RuleSetting> = {};
  if (typeof settings.rules === 'object' && settings.rules !== null) {
    for (const [id, value] of Object.entries(settings.rules as Record<string, unknown>)) {
      const severity = normalizeSeverity(value);
      if (severity !== undefined) rules[id] = severity;
    }
  }

  return {
    rules,
    strict: settings.strict === true,
    checkNetwork: settings.checkNetwork === true,
    domain: typeof settings.domain === 'string' ? settings.domain : '',
    source: current.source,
  };
}

function normalizeSeverity(value: unknown): RuleSetting | undefined {
  return value === 'off' || value === 'error' || value === 'warning' || value === 'info'
    ? value
    : undefined;
}

/**
 * Renders the panel. Plain HTML + a small inline script keeps the extension
 * dependency-free; the markup is deliberately responsive so it works in a
 * narrow side panel as well as a full editor tab.
 */
export function renderSettingsHtml(
  rules: RuleInfo[],
  snapshot: SettingsSnapshot,
  nonce = 'stellar-toml',
): string {
  const groups = groupRules(rules);
  const sections = groups
    .map((group) => {
      const rows = group.rules
        .map((rule) => {
          const severity = severityFor(rule, snapshot.rules);
          const disabled = severity === 'off';
          return `
            <div class="rule" data-rule="${escapeHtml(rule.id)}" data-default="${rule.severity}">
              <label class="rule-main">
                <input type="checkbox" class="enabled" data-rule="${escapeHtml(rule.id)}" ${disabled ? '' : 'checked'} />
                <span class="rule-id">${escapeHtml(rule.id)}</span>
                <span class="rule-detail">${escapeHtml(rule.description)}</span>
              </label>
              <select class="severity" data-rule="${escapeHtml(rule.id)}" ${disabled ? 'disabled' : ''}>
                ${severityOptions(severity)}
              </select>
            </div>`;
        })
        .join('\n');
      return `
        <section class="track">
          <h2>${escapeHtml(group.title)} <span class="count">${group.rules.length}</span></h2>
          ${rows}
        </section>`;
    })
    .join('\n');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';" />
  <title>Stellar TOML Settings</title>
  <style>
    :root { color-scheme: light dark; }
    * { box-sizing: border-box; }
    body {
      margin: 0; padding: 24px; color: var(--vscode-foreground);
      background: var(--vscode-editor-background);
      font: 13px/1.45 var(--vscode-font-family, system-ui, sans-serif);
    }
    header { display: flex; flex-wrap: wrap; gap: 16px; align-items: baseline; justify-content: space-between; margin-bottom: 20px; }
    h1 { margin: 0; font-size: 20px; }
    .source { opacity: .72; }
    .global { display: grid; gap: 10px; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); margin-bottom: 28px; }
    .global label { display: flex; gap: 8px; align-items: center; padding: 10px 12px; border: 1px solid var(--vscode-panel-border); border-radius: 6px; }
    .track { margin: 0 0 24px; }
    h2 { display: flex; gap: 8px; align-items: center; font-size: 13px; letter-spacing: .04em; text-transform: uppercase; opacity: .85; margin: 0 0 8px; }
    .count { font-weight: 400; opacity: .6; }
    .rule { display: grid; grid-template-columns: minmax(0, 1fr) 120px; gap: 12px; align-items: center; padding: 8px 10px; border-radius: 6px; }
    .rule:nth-child(odd) { background: color-mix(in srgb, var(--vscode-editor-foreground) 4%, transparent); }
    .rule-main { display: flex; gap: 10px; align-items: baseline; min-width: 0; cursor: pointer; }
    .rule-id { font-family: var(--vscode-editor-font-family, monospace); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .rule-detail { opacity: .65; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    select { width: 100%; padding: 4px 6px; color: var(--vscode-dropdown-foreground); background: var(--vscode-dropdown-background); border: 1px solid var(--vscode-dropdown-border); border-radius: 4px; }
    select:disabled { opacity: .45; }
    .status { position: sticky; bottom: 0; padding: 8px 0; min-height: 22px; opacity: .7; }
    @media (max-width: 560px) {
      body { padding: 14px; }
      .rule { grid-template-columns: 1fr; }
      .rule-detail { display: none; }
    }
  </style>
</head>
<body>
  <header>
    <h1>Stellar TOML rules</h1>
    <span class="source">Saving to ${snapshot.source === 'project' ? '.stellartomlrc.json' : 'VS Code workspace settings'}</span>
  </header>
  <div class="global">
    <label><input type="checkbox" id="strict" ${snapshot.strict ? 'checked' : ''} /> Treat warnings as errors (strict)</label>
    <label><input type="checkbox" id="checkNetwork" ${snapshot.checkNetwork ? 'checked' : ''} /> Run network checks</label>
    <label><input type="text" id="domain" value="${escapeHtml(snapshot.domain)}" placeholder="example.com" /> Serving domain (optional)</label>
  </div>
  ${sections}
  <div class="status" id="status">${rules.length} rules across ${groups.length} tracks</div>
  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
    const status = document.getElementById('status');
    let timer;

    function collect() {
      const rules = {};
      for (const row of document.querySelectorAll('.rule')) {
        const id = row.dataset.rule;
        const enabled = row.querySelector('.enabled').checked;
        const select = row.querySelector('.severity');
        rules[id] = enabled ? select.value : 'off';
      }
      return {
        rules,
        strict: document.getElementById('strict').checked,
        checkNetwork: document.getElementById('checkNetwork').checked,
        domain: document.getElementById('domain').value.trim(),
      };
    }

    function send() {
      status.textContent = 'Saving...';
      clearTimeout(timer);
      timer = setTimeout(() => vscode.postMessage({ type: 'update', settings: collect() }), 120);
    }

    for (const checkbox of document.querySelectorAll('.enabled')) {
      checkbox.addEventListener('change', () => {
        const row = checkbox.closest('.rule');
        row.querySelector('.severity').disabled = !checkbox.checked;
        send();
      });
    }
    for (const select of document.querySelectorAll('.severity')) {
      select.addEventListener('change', send);
    }
    document.getElementById('strict').addEventListener('change', send);
    document.getElementById('checkNetwork').addEventListener('change', send);
    document.getElementById('domain').addEventListener('change', send);
  </script>
</body>
</html>`;
}

function severityOptions(current: RuleSetting): string {
  return (['error', 'warning', 'info'] as const)
    .map(
      (severity) =>
        `<option value="${severity}" ${severity === current ? 'selected' : ''}>${severity}</option>`,
    )
    .join('');
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Registers the settings command. Returns the disposable so the extension can
 * put it in `context.subscriptions` like every other command.
 */
export function registerSettingsWebview(
  vscodeApi: VscodeApi,
  options: SettingsWebviewOptions = {},
): Disposable {
  const open = (): Promise<void> => showSettingsWebview(vscodeApi, options);
  return vscodeApi.commands.registerCommand(SETTINGS_COMMAND, open);
}

/** Alias that matches the extension's existing `stellar-toml.*` commands. */
export function registerSettingsWebviewAlias(
  vscodeApi: VscodeApi,
  options: SettingsWebviewOptions = {},
): Disposable {
  return vscodeApi.commands.registerCommand(SETTINGS_COMMAND_ALIAS, () =>
    showSettingsWebview(vscodeApi, options),
  );
}

let currentPanel: WebviewPanel | undefined;

/** Opens (or reveals) the settings panel and wires its message loop. */
export async function showSettingsWebview(
  vscodeApi: VscodeApi,
  options: SettingsWebviewOptions = {},
): Promise<void> {
  const projectPath = await findProjectConfig(vscodeApi);
  const project = projectPath === undefined ? undefined : await readProjectConfig(projectPath);
  const config = vscodeApi.workspace.getConfiguration('stellarToml');
  let snapshot: SettingsSnapshot = {
    rules: project?.rules ?? config.get<Record<string, RuleSetting>>('rules', {}),
    strict: project?.strict ?? config.get<boolean>('strict', false),
    checkNetwork: config.get<boolean>('checkNetwork', false),
    domain: config.get<string>('domain', ''),
    source: projectPath === undefined ? 'vscode' : 'project',
  };

  let rules = options.rules;
  if (rules === undefined && options.cli !== undefined) {
    try {
      rules = await loadRuleCatalog(options.cli);
    } catch (error) {
      vscodeApi.window.showErrorMessage?.(
        `Could not list stellar-toml-lint rules: ${error instanceof Error ? error.message : String(error)}`,
      );
      rules = [];
    }
  }
  rules ??= [];

  if (currentPanel !== undefined) {
    currentPanel.reveal?.(vscodeApi.ViewColumn?.Active);
    currentPanel.webview.html = renderSettingsHtml(rules, snapshot);
    return;
  }

  const panel = vscodeApi.window.createWebviewPanel(
    SETTINGS_VIEW_TYPE,
    'Stellar TOML Settings',
    vscodeApi.ViewColumn?.Active ?? 1,
    { enableScripts: true, retainContextWhenHidden: true },
  );
  currentPanel = panel;
  panel.webview.html = renderSettingsHtml(rules, snapshot);
  panel.onDidDispose?.(() => {
    currentPanel = undefined;
  });

  panel.webview.onDidReceiveMessage(async (message) => {
    if (typeof message !== 'object' || message === null) return;
    if ((message as Record<string, unknown>).type !== 'update') return;

    snapshot = applyWebviewMessage(snapshot, message);
    try {
      if (projectPath !== undefined) {
        await writeProjectConfigAtomic(projectPath, snapshot, rules);
      } else {
        const configuration = vscodeApi.workspace.getConfiguration('stellarToml');
        const target = vscodeApi.ConfigurationTarget?.Workspace;
        await configuration.update('rules', snapshot.rules, target);
        await configuration.update('strict', snapshot.strict, target);
        await configuration.update('checkNetwork', snapshot.checkNetwork, target);
        await configuration.update('domain', snapshot.domain, target);
      }
      options.onSettingsChanged?.(snapshot);
      await panel.webview.postMessage({ type: 'saved', settings: snapshot });
    } catch (error) {
      await panel.webview.postMessage({
        type: 'error',
        message: error instanceof Error ? error.message : String(error),
      });
    }
  });
}

async function findProjectConfig(vscodeApi: VscodeApi): Promise<string | undefined> {
  const findFiles = vscodeApi.workspace.findFiles;
  if (findFiles === undefined) return undefined;
  const results = await Promise.resolve(
    findFiles('**/.stellartomlrc.json', '**/node_modules/**', 1),
  );
  return results[0]?.fsPath;
}
