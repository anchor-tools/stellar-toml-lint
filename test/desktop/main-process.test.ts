import { describe, expect, it } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  APP_TITLE,
  isInternalUrl,
  isSafeExternalUrl,
  secureWindowOptions,
} from '../../apps/desktop/src/window-options.js';
import {
  ALL_CHANNELS,
  API_GLOBAL,
  EVENT_CHANNELS,
  INVOKE_CHANNELS,
  isFileStatus,
  isOpenExternalRequest,
  isRevealFileRequest,
} from '../../apps/desktop/src/ipc.js';
import {
  TRAY_COLORS,
  trayIconDataUrl,
  trayStateLabel,
  traySvg,
} from '../../apps/desktop/src/tray-icons.js';

const here = dirname(fileURLToPath(import.meta.url));
const desktop = join(here, '..', '..', 'apps', 'desktop');

const read = (...parts: string[]): string => readFileSync(join(desktop, ...parts), 'utf8');

const manifest = JSON.parse(read('package.json'));
const forgeConfig = read('forge.config.cjs');
const mainSource = read('src', 'main.ts');
const preloadSource = read('src', 'preload.ts');

/* ------------------------------------------------------------------ *
 * Window creation and IPC security flags
 * ------------------------------------------------------------------ */

describe('BrowserWindow security flags', () => {
  const options = secureWindowOptions('/tmp/preload.cjs');

  it('enables the sandbox and context isolation', () => {
    expect(options.webPreferences.sandbox).toBe(true);
    expect(options.webPreferences.contextIsolation).toBe(true);
  });

  it('disables Node integration everywhere a renderer can run', () => {
    // A worker or a subframe with Node integration is the same hole as the
    // main renderer having it.
    expect(options.webPreferences.nodeIntegration).toBe(false);
    expect(options.webPreferences.nodeIntegrationInWorker).toBe(false);
    expect(options.webPreferences.nodeIntegrationInSubFrames).toBe(false);
  });

  it('keeps web security on and insecure content off', () => {
    expect(options.webPreferences.webSecurity).toBe(true);
    expect(options.webPreferences.allowRunningInsecureContent).toBe(false);
    expect(options.webPreferences.experimentalFeatures).toBe(false);
  });

  it('points the preload at the path it is given', () => {
    expect(secureWindowOptions('/opt/app/out/preload.cjs').webPreferences.preload).toBe(
      '/opt/app/out/preload.cjs',
    );
  });

  it('creates a window that is sized, titled, and painted deliberately', () => {
    expect(options.title).toBe(APP_TITLE);
    expect(options.width).toBeGreaterThan(0);
    expect(options.height).toBeGreaterThan(0);
    expect(options.minWidth).toBeLessThanOrEqual(options.width);
    expect(options.minHeight).toBeLessThanOrEqual(options.height);
    // Shown on `ready-to-show` instead, so the user never sees a white flash.
    expect(options.show).toBe(false);
    expect(options.backgroundColor).toMatch(/^#[0-9a-f]{6}$/i);
  });

  it('exposes no way for a caller to weaken a flag', () => {
    // Every flag is a literal type, so this must not compile as `false`.
    // The runtime assertion is the backstop for a future refactor.
    const again = secureWindowOptions('/tmp/other.cjs');
    expect(again.webPreferences.sandbox).toBe(true);
    expect(again.webPreferences.contextIsolation).toBe(true);
  });
});

describe('the main process wires the window it declares', () => {
  it('creates a BrowserWindow from secureWindowOptions, not an inline literal', () => {
    // An inline options object is how these flags regress: this assertion
    // fails on the commit that stops going through the audited helper.
    expect(mainSource).toContain('new BrowserWindow(secureWindowOptions(preload))');
    expect(mainSource).not.toMatch(/webPreferences:\s*\{/);
  });

  it('loads the preload bundled as CommonJS', () => {
    // A sandboxed preload cannot be an ES module.
    expect(mainSource).toContain("join(here, 'preload.cjs')");
  });

  it('shows the window only once it is ready to paint', () => {
    expect(mainSource).toContain("window.once('ready-to-show'");
  });

  it('hides rather than closes, so watching survives the window', () => {
    expect(mainSource).toContain("window.on('close'");
    expect(mainSource).toContain('window.hide()');
    // Registering a `window-all-closed` quit would defeat the whole point of
    // a tray app. Matched as a handler registration, not as the word, so the
    // comment explaining the omission does not fail the test.
    expect(mainSource).not.toMatch(/app\.on\(\s*'window-all-closed'/);
  });

  it('denies in-window navigation to anything external', () => {
    expect(mainSource).toContain('setWindowOpenHandler');
    expect(mainSource).toContain("action: 'deny'");
    expect(mainSource).toContain("'will-navigate'");
    expect(mainSource).toContain('event.preventDefault()');
  });

  it('refuses webviews', () => {
    expect(mainSource).toContain("'did-attach-webview'");
  });

  it('screens every URL before handing it to the OS', () => {
    // `shell.openExternal` will launch any scheme the OS has a handler for.
    const opens = mainSource.match(/shell\.openExternal/g) ?? [];
    expect(opens.length).toBeGreaterThan(0);
    const guards = mainSource.match(/isSafeExternalUrl/g) ?? [];
    expect(guards.length).toBeGreaterThanOrEqual(opens.length);
  });

  it('takes the single-instance lock, so notifications are not doubled', () => {
    expect(mainSource).toContain('requestSingleInstanceLock');
  });

  it('lints with the same engine as the CLI', () => {
    // A desktop app with its own copy of the rules would drift from CI, which
    // is the one thing it must never do.
    expect(mainSource).toContain("from 'stellar-toml-lint'");
    expect(mainSource).toContain('lint(source)');
  });

  it('never writes to the console', () => {
    // `no-console` is an error across this repo; the main process has no
    // terminal to write to anyway.
    expect(mainSource).not.toMatch(/\bconsole\.(log|warn|error|info|debug)\b/);
  });
});

/* ------------------------------------------------------------------ *
 * IPC contract
 * ------------------------------------------------------------------ */

describe('the IPC surface', () => {
  it('names every channel in one place, with no duplicates', () => {
    expect(new Set(ALL_CHANNELS).size).toBe(ALL_CHANNELS.length);
    expect(ALL_CHANNELS.length).toBe(
      Object.keys(INVOKE_CHANNELS).length + Object.keys(EVENT_CHANNELS).length,
    );
  });

  it('distinguishes request channels from event channels by name', () => {
    for (const channel of Object.values(INVOKE_CHANNELS)) {
      expect(channel.startsWith('request/')).toBe(true);
    }
    for (const channel of Object.values(EVENT_CHANNELS)) {
      expect(channel.startsWith('event/')).toBe(true);
    }
  });

  it('accepts no filesystem path from the renderer', () => {
    // The renderer refers to files by index into the snapshot the main process
    // produced. A path-taking channel would hand back the access the sandbox
    // exists to remove.
    expect(isRevealFileRequest({ index: 0 })).toBe(true);
    expect(isRevealFileRequest({ path: '/etc/passwd' })).toBe(false);
    expect(isRevealFileRequest({ index: '/etc/passwd' })).toBe(false);
  });

  it('validates a reveal request strictly', () => {
    expect(isRevealFileRequest({ index: 3 })).toBe(true);
    expect(isRevealFileRequest({ index: -1 })).toBe(false);
    expect(isRevealFileRequest({ index: 1.5 })).toBe(false);
    expect(isRevealFileRequest({ index: Number.NaN })).toBe(false);
    expect(isRevealFileRequest({})).toBe(false);
    expect(isRevealFileRequest(null)).toBe(false);
    expect(isRevealFileRequest([0])).toBe(false);
    expect(isRevealFileRequest('0')).toBe(false);
  });

  it('validates an openExternal request strictly', () => {
    expect(isOpenExternalRequest({ url: 'https://example.com' })).toBe(true);
    expect(isOpenExternalRequest({ url: '' })).toBe(false);
    expect(isOpenExternalRequest({ url: 42 })).toBe(false);
    expect(isOpenExternalRequest(undefined)).toBe(false);
  });

  it('validates a file status', () => {
    expect(isFileStatus({ path: '/a/stellar.toml', errors: 0, warnings: 1 })).toBe(true);
    expect(isFileStatus({ path: '/a', errors: 0, warnings: 0, unreadable: true })).toBe(true);
    expect(isFileStatus({ path: '/a', errors: '0', warnings: 0 })).toBe(false);
    expect(isFileStatus({ errors: 0, warnings: 0 })).toBe(false);
  });

  it('is handled for every request channel, and validated on arrival', () => {
    for (const channel of Object.values(INVOKE_CHANNELS)) {
      // The handler is registered by the constant, not a retyped string.
      const name = Object.entries(INVOKE_CHANNELS).find(([, v]) => v === channel)?.[0];
      expect(mainSource).toContain(`INVOKE_CHANNELS.${name ?? ''}`);
    }
    // The two channels that take an argument both guard it first.
    expect(mainSource).toContain('if (!isRevealFileRequest(request)) return;');
    expect(mainSource).toContain('if (!isOpenExternalRequest(request)) return;');
  });
});

describe('the preload bridge', () => {
  it('exposes a frozen API object through contextBridge', () => {
    expect(preloadSource).toContain('contextBridge.exposeInMainWorld');
    expect(preloadSource).toContain(`API_GLOBAL`);
    expect(API_GLOBAL).toBe('stellarTomlLint');
  });

  it('never hands the renderer ipcRenderer itself', () => {
    // The classic context-isolation bypass: exposing the module, or a generic
    // `invoke(channel, ...args)`, lets a compromised page send on any channel.
    expect(preloadSource).not.toMatch(/exposeInMainWorld\([^)]*ipcRenderer\s*\)/);
    expect(preloadSource).not.toMatch(/invoke:\s*\(channel/);
    expect(preloadSource).not.toMatch(/\(channel: string/);
  });

  it('names a literal channel constant at every call', () => {
    const invokes = preloadSource.match(/ipcRenderer\.invoke\(/g) ?? [];
    const constants = preloadSource.match(/INVOKE_CHANNELS\.\w+/g) ?? [];
    expect(invokes.length).toBeGreaterThan(0);
    expect(constants.length).toBeGreaterThanOrEqual(invokes.length);
  });

  it('drops the IpcRendererEvent before calling a page listener', () => {
    // The event carries a `sender` the page has no business holding.
    expect(preloadSource).toContain('_event: IpcRendererEvent');
    expect(preloadSource).not.toMatch(/ipcRenderer\.on\([^,]+,\s*listener\s*\)/);
  });

  it('returns an unsubscribe function from each subscription', () => {
    expect(preloadSource).toContain('removeListener');
  });

  it('is bundled to CommonJS, because a sandboxed preload cannot be ESM', () => {
    const script = read('scripts', 'build-preload.mjs');
    expect(script).toContain("format: 'cjs'");
    expect(script).toContain('preload.cjs');
    expect(script).toContain("external: ['electron']");
    // Excluded from the tsc program so it is only ever produced by the bundler.
    expect(read('tsconfig.json')).toContain('src/preload.ts');
  });
});

/* ------------------------------------------------------------------ *
 * Navigation guards
 * ------------------------------------------------------------------ */

describe('navigation policy', () => {
  it('treats the bundled file and the dev server as internal', () => {
    expect(isInternalUrl('file:///opt/app/renderer/index.html')).toBe(true);
    expect(isInternalUrl('http://localhost:5173/', 'http://localhost:5173')).toBe(true);
  });

  it('treats everything else as external', () => {
    expect(isInternalUrl('https://example.com')).toBe(false);
    expect(isInternalUrl('http://localhost:5173/', '')).toBe(false);
    expect(isInternalUrl('https://evil.example/file://')).toBe(false);
  });

  it('opens only http and https externally', () => {
    expect(isSafeExternalUrl('https://developers.stellar.org')).toBe(true);
    expect(isSafeExternalUrl('http://example.com')).toBe(true);
  });

  it('refuses schemes the OS would happily launch', () => {
    // A linted document is untrusted input, and its URLs reach this check.
    for (const url of [
      'file:///etc/passwd',
      'javascript:alert(1)',
      'data:text/html,<script>alert(1)</script>',
      'smb://attacker.example/share',
      'vscode://file/etc/passwd',
      'ms-msdt:/id',
      'not a url',
      '',
    ]) {
      expect(isSafeExternalUrl(url)).toBe(false);
    }
  });
});

/* ------------------------------------------------------------------ *
 * Tray
 * ------------------------------------------------------------------ */

describe('tray status indicator', () => {
  it('has a colour and a glyph for every state', () => {
    for (const state of ['ok', 'warning', 'error', 'idle', 'scanning'] as const) {
      expect(TRAY_COLORS[state]).toMatch(/^#[0-9a-f]{6}$/i);
      expect(traySvg(state)).toContain('<svg');
      expect(trayStateLabel(state).length).toBeGreaterThan(0);
    }
  });

  it('shows a green check when everything is clean and a red alert when not', () => {
    // The issue asks for exactly this pair.
    expect(TRAY_COLORS.ok).toBe('#1f9d55');
    expect(TRAY_COLORS.error).toBe('#d13438');
    expect(traySvg('ok')).toContain('M6 11.6 9.4 15 16 7.6');
    expect(traySvg('error')).toContain('<circle');
  });

  it('distinguishes states by shape as well as colour', () => {
    // Roughly one man in twelve cannot tell this green from this red.
    const shapes = (['ok', 'warning', 'error', 'idle', 'scanning'] as const).map((state) =>
      traySvg(state, true).replace(/color="[^"]*"/, ''),
    );
    expect(new Set(shapes).size).toBe(shapes.length);
  });

  it('renders a monochrome variant so macOS can treat it as a template', () => {
    expect(traySvg('error', true)).toContain('color="#000000"');
    expect(traySvg('error', false)).toContain(TRAY_COLORS.error);
  });

  it('produces a data URL nativeImage accepts', () => {
    const url = trayIconDataUrl('ok');
    expect(url.startsWith('data:image/svg+xml;base64,')).toBe(true);
    const decoded = Buffer.from(url.split(',')[1] ?? '', 'base64').toString('utf8');
    expect(decoded).toBe(traySvg('ok'));
  });

  it('is marked as a template image on macOS only', () => {
    expect(mainSource).toContain("process.platform === 'darwin'");
    expect(mainSource).toContain('setTemplateImage(true)');
  });

  it('offers watch controls and a quit from the tray menu', () => {
    expect(mainSource).toContain('Menu.buildFromTemplate');
    expect(mainSource).toContain('Choose folder…');
    expect(mainSource).toContain('Rescan now');
    expect(mainSource).toContain('Stop watching');
    expect(mainSource).toContain('Quit ');
  });

  it('states the status in words, not only as a colour', () => {
    expect(mainSource).toContain('trayStateLabel(trayState)');
    expect(mainSource).toContain('tray.setToolTip(tooltipFor(');
  });
});

/* ------------------------------------------------------------------ *
 * Packaging
 * ------------------------------------------------------------------ */

describe('Electron Forge packaging', () => {
  it('declares the Forge CLI and Electron itself', () => {
    expect(manifest.devDependencies).toHaveProperty('@electron-forge/cli');
    expect(manifest.devDependencies).toHaveProperty('electron');
  });

  it('configures a maker for DMG, MSI, and AppImage', () => {
    expect(forgeConfig).toContain('@electron-forge/maker-dmg');
    expect(forgeConfig).toContain('@electron-forge/maker-wix');
    expect(forgeConfig).toContain('@reforged/maker-appimage');
  });

  it('targets each maker at the platform it belongs to', () => {
    expect(forgeConfig).toMatch(/maker-dmg'[\s\S]{0,120}platforms: \['darwin'\]/);
    expect(forgeConfig).toMatch(/maker-wix'[\s\S]{0,120}platforms: \['win32'\]/);
    expect(forgeConfig).toMatch(/maker-appimage'[\s\S]{0,120}platforms: \['linux'\]/);
  });

  it('exposes a make script per format', () => {
    expect(manifest.scripts['make:dmg']).toContain('maker-dmg');
    expect(manifest.scripts['make:msi']).toContain('maker-wix');
    expect(manifest.scripts['make:appimage']).toContain('maker-appimage');
    expect(manifest.scripts.make).toContain('electron-forge make');
  });

  it('builds the main process and the preload before packaging', () => {
    expect(manifest.scripts.build).toContain('tsc');
    expect(manifest.scripts.build).toContain('build-preload.mjs');
    for (const script of ['make', 'package', 'start']) {
      expect(manifest.scripts[script]).toContain('npm run build');
    }
  });

  it('pins a stable MSI upgrade code so installs upgrade in place', () => {
    // Regenerating this GUID would make every release install beside the last.
    expect(forgeConfig).toMatch(/upgradeCode: '[0-9a-f-]{36}'/);
  });

  it('points main at the compiled entry, and keeps the app private', () => {
    expect(manifest.main).toBe('out/main.js');
    expect(manifest.private).toBe(true);
  });

  it('depends on the linter from the repository root', () => {
    expect(manifest.dependencies['stellar-toml-lint']).toBe('file:../..');
  });

  it('excludes the sources from the packaged app', () => {
    expect(forgeConfig).toContain('ignore:');
    expect(forgeConfig).toContain('/^\\/src\\//');
  });
});

describe('the renderer shell', () => {
  it('exists and is what the main process loads when there is no dev server', () => {
    expect(existsSync(join(desktop, 'renderer', 'index.html'))).toBe(true);
    expect(mainSource).toContain("join(here, '..', 'renderer', 'index.html')");
  });

  it('declares a content security policy that forbids network access', () => {
    const html = read('renderer', 'index.html');
    expect(html).toContain('Content-Security-Policy');
    expect(html).toContain("default-src 'none'");
    expect(html).toContain("connect-src 'none'");
    // No inline script: the CSP allows `script-src 'self'` only.
    expect(html).not.toMatch(/<script(?![^>]*\bsrc=)/);
  });

  it('writes file paths as text, never as markup', () => {
    const js = read('renderer', 'renderer.js');
    // A folder can be named `<img onerror=…>`, and that name reaches the DOM.
    // Matched as assignments and calls rather than as words, so the comment
    // explaining the rule does not fail the test that enforces it.
    expect(js).toContain('textContent');
    expect(js).not.toMatch(/\.innerHTML\s*=/);
    expect(js).not.toMatch(/\.outerHTML\s*=/);
    expect(js).not.toMatch(/insertAdjacentHTML\(/);
  });

  it('asks the main process to reveal a file by index', () => {
    expect(read('renderer', 'renderer.js')).toContain('revealFile({ index })');
  });
});
