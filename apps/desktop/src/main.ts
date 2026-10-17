/**
 * Electron main process (issue #371).
 *
 * This is the only file in the app that touches `electron`, and it is
 * deliberately thin: everything it decides — the window's security flags, what
 * counts as a relevant file change, when a notification is warranted, which
 * tray glyph to show — lives in a sibling module with no Electron import, so
 * the behaviour is covered by `test/desktop/` without launching a browser
 * process. What is left here is wiring, and wiring is what a static review of
 * this file can check.
 *
 * The app's shape:
 *
 * - **It lives in the tray, not the dock.** Closing the window hides it; the
 *   app keeps watching. Quitting is an explicit choice from the tray menu,
 *   because a compliance officer who closes the window has not asked to stop
 *   monitoring.
 * - **The renderer is sandboxed.** See `window-options.ts` for the flags and
 *   `ipc.ts` for the whole of what the renderer may ask for. No channel accepts
 *   a filesystem path.
 * - **Linting happens in the main process**, using the same `lint()` the CLI
 *   uses, so the desktop app and CI cannot disagree about whether a file is
 *   valid. The renderer receives counts and paths, never the authority to read
 *   a file itself.
 */
import {
  app,
  BrowserWindow,
  dialog,
  ipcMain,
  Menu,
  nativeImage,
  Notification,
  shell,
  Tray,
} from 'electron';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { lint } from 'stellar-toml-lint';
import {
  APP_TITLE,
  isInternalUrl,
  isSafeExternalUrl,
  secureWindowOptions,
} from './window-options.js';
import {
  EVENT_CHANNELS,
  INVOKE_CHANNELS,
  isOpenExternalRequest,
  isRevealFileRequest,
  type StatusPayload,
} from './ipc.js';
import { DirectoryWatcher, findTomlFiles } from './watcher.js';
import { mergeScan, scanFiles, type LintCounts } from './scanner.js';
import {
  notificationsFor,
  trayStateFor,
  tooltipFor,
  type ScanSnapshot,
  type TrayState,
} from './status.js';
import { trayIconDataUrl, trayStateLabel } from './tray-icons.js';

const here = dirname(fileURLToPath(import.meta.url));

/** Vite's dev server, set only when the app is started from source. */
const DEV_SERVER_URL = process.env.STELLAR_TOML_LINT_DEV_URL ?? '';

/** Everything mutable the app holds, in one place rather than scattered. */
interface AppState {
  window: BrowserWindow | undefined;
  tray: Tray | undefined;
  watcher: DirectoryWatcher | undefined;
  directory: string | undefined;
  snapshot: ScanSnapshot | undefined;
  quitting: boolean;
}

const state: AppState = {
  window: undefined,
  tray: undefined,
  watcher: undefined,
  directory: undefined,
  snapshot: undefined,
  quitting: false,
};

/**
 * Reads a file as UTF-8 text.
 *
 * Named rather than passing `readFileSync` straight to the scanner: without an
 * encoding it returns a Buffer, and the scanner would hand that to `lint()`,
 * which would throw and report every watched file as unreadable.
 */
const readText = (path: string): string => readFileSync(path, 'utf8');

/** Adapts `lint()` to the counts the scanner wants. */
const lintSource = (source: string): LintCounts => {
  const result = lint(source);
  return { errors: result.counts.error, warnings: result.counts.warning };
};

/** The payload the renderer gets after any change. */
function payload(): StatusPayload | undefined {
  if (state.snapshot === undefined) return undefined;
  return {
    snapshot: state.snapshot,
    tray: trayStateFor(state.snapshot),
    directory: state.directory,
    recursive: state.watcher?.recursive ?? true,
  };
}

/** Pushes the current status to the window and repaints the tray. */
function publish(): void {
  const current = payload();
  updateTray(trayStateFor(state.snapshot));
  if (current !== undefined && state.window !== undefined && !state.window.isDestroyed()) {
    state.window.webContents.send(EVENT_CHANNELS.statusChanged, current);
  }
}

/** Repaints the tray icon, tooltip, and menu for a state. */
function updateTray(trayState: TrayState): void {
  const tray = state.tray;
  if (tray === undefined) return;

  // On macOS the menu bar recolours a template image for light, dark, and
  // highlighted bars; elsewhere the coloured glyph is what users expect.
  const monochrome = process.platform === 'darwin';
  const icon = nativeImage.createFromDataURL(trayIconDataUrl(trayState, monochrome));
  if (monochrome) icon.setTemplateImage(true);
  tray.setImage(icon);
  tray.setToolTip(tooltipFor(state.snapshot, APP_TITLE));

  tray.setContextMenu(
    Menu.buildFromTemplate([
      { label: trayStateLabel(trayState), enabled: false },
      {
        label: state.directory === undefined ? 'No folder watched' : state.directory,
        enabled: false,
      },
      { type: 'separator' },
      { label: 'Show window', click: showWindow },
      { label: 'Choose folder…', click: () => void chooseFolder() },
      { label: 'Rescan now', click: () => rescan(), enabled: state.directory !== undefined },
      {
        label: 'Stop watching',
        click: stopWatching,
        enabled: state.directory !== undefined,
      },
      { type: 'separator' },
      {
        label: `Quit ${APP_TITLE}`,
        click: () => {
          state.quitting = true;
          app.quit();
        },
      },
    ]),
  );
}

/** Raises the OS notifications a scan transition deserves. */
function notify(previous: ScanSnapshot | undefined, current: ScanSnapshot): void {
  if (!Notification.isSupported()) return;

  for (const spec of notificationsFor(previous, current)) {
    const notification = new Notification({ title: spec.title, body: spec.body });
    // Clicking a notification should land the user on the problem, not just
    // raise an empty window.
    notification.on('click', () => {
      showWindow();
      if (spec.path.length > 0 && existsSync(spec.path)) shell.showItemInFolder(spec.path);
    });
    notification.show();
  }
}

/** Re-lints every watched file and publishes the result. */
function rescan(): void {
  if (state.directory === undefined) return;
  const previous = state.snapshot;
  state.snapshot = scanFiles(findTomlFiles(state.directory), readText, lintSource);
  notify(previous, state.snapshot);
  publish();
}

/** Re-lints only the files a watch batch named, merging into the snapshot. */
function rescanChanged(paths: string[]): void {
  if (state.directory === undefined) return;

  const previous = state.snapshot;
  const rescanned = scanFiles(paths, readText, lintSource);
  state.snapshot =
    previous === undefined ? rescanned : mergeScan(previous, rescanned, (path) => existsSync(path));

  notify(previous, state.snapshot);
  publish();
}

/** Stops watching and clears the status. */
function stopWatching(): void {
  state.watcher?.stop();
  state.watcher = undefined;
  state.directory = undefined;
  state.snapshot = undefined;
  updateTray('idle');
  if (state.window !== undefined && !state.window.isDestroyed()) {
    state.window.webContents.send(EVENT_CHANNELS.folderChanged, undefined);
  }
}

/** Reports a watch failure to the window, which is the only place it can show. */
function reportWatchFailure(error: Error): void {
  if (state.window === undefined || state.window.isDestroyed()) return;
  state.window.webContents.send(EVENT_CHANNELS.watchFailed, error.message);
}

/** Begins watching `directory`, replacing any previous watch. */
function watchDirectory(directory: string): void {
  state.watcher?.stop();
  state.directory = directory;
  state.watcher = new DirectoryWatcher({
    directory,
    onChange: rescanChanged,
    onError: reportWatchFailure,
  });
  state.watcher.start();

  // The first scan after choosing a folder notifies about files that are
  // already broken: the user just pointed the app here and that is the answer
  // they asked for.
  state.snapshot = undefined;
  rescan();

  if (state.window !== undefined && !state.window.isDestroyed()) {
    state.window.webContents.send(EVENT_CHANNELS.folderChanged, directory);
  }
}

/** Opens the OS folder picker and watches what the user chose. */
async function chooseFolder(): Promise<StatusPayload | undefined> {
  const result = await dialog.showOpenDialog({
    title: 'Choose a folder to watch',
    properties: ['openDirectory', 'createDirectory'],
    buttonLabel: 'Watch folder',
  });
  const directory = result.filePaths[0];
  if (result.canceled || directory === undefined) return payload();

  watchDirectory(directory);
  return payload();
}

/** The page the window loads: the dev server, or the bundled playground. */
function rendererEntry(): { url?: string; file?: string } {
  if (DEV_SERVER_URL.length > 0) return { url: DEV_SERVER_URL };
  return { file: join(here, '..', 'renderer', 'index.html') };
}

function createWindow(): void {
  const preload = join(here, 'preload.cjs');
  const window = new BrowserWindow(secureWindowOptions(preload));
  state.window = window;

  // A link in a linted document must open in the user's browser, never inside
  // a window that has this app's preload attached to it.
  window.webContents.setWindowOpenHandler(({ url }) => {
    if (isSafeExternalUrl(url)) void shell.openExternal(url);
    return { action: 'deny' };
  });
  window.webContents.on('will-navigate', (event, url) => {
    if (isInternalUrl(url, DEV_SERVER_URL)) return;
    event.preventDefault();
    if (isSafeExternalUrl(url)) void shell.openExternal(url);
  });
  // Nothing in this app needs a second renderer process.
  window.webContents.on('did-attach-webview', (event) => event.preventDefault());

  window.once('ready-to-show', () => window.show());

  // Closing hides: the point of the app is that it keeps watching.
  window.on('close', (event) => {
    if (state.quitting) return;
    event.preventDefault();
    window.hide();
  });

  const entry = rendererEntry();
  if (entry.url !== undefined) void window.loadURL(entry.url);
  else if (entry.file !== undefined) void window.loadFile(entry.file);
}

function showWindow(): void {
  if (state.window === undefined || state.window.isDestroyed()) {
    createWindow();
    return;
  }
  state.window.show();
  state.window.focus();
}

function createTray(): void {
  const monochrome = process.platform === 'darwin';
  const icon = nativeImage.createFromDataURL(trayIconDataUrl('idle', monochrome));
  if (monochrome) icon.setTemplateImage(true);
  state.tray = new Tray(icon);
  state.tray.on('click', showWindow);
  updateTray('idle');
}

/**
 * Registers the IPC handlers.
 *
 * Every handler validates its argument before using it: with the renderer
 * sandboxed, these channels are the entire attack surface, and a handler that
 * destructures its input is a handler that trusts the page.
 */
function registerIpc(): void {
  ipcMain.handle(INVOKE_CHANNELS.chooseFolder, () => chooseFolder());
  ipcMain.handle(INVOKE_CHANNELS.stopWatching, () => {
    stopWatching();
  });
  ipcMain.handle(INVOKE_CHANNELS.rescan, () => {
    rescan();
    return payload();
  });
  ipcMain.handle(INVOKE_CHANNELS.currentStatus, () => payload());

  ipcMain.handle(INVOKE_CHANNELS.revealFile, (_event, request: unknown) => {
    if (!isRevealFileRequest(request)) return;
    // An index into the snapshot the main process itself produced, never a
    // path from the renderer.
    const file = state.snapshot?.files[request.index];
    if (file === undefined || !existsSync(file.path)) return;
    shell.showItemInFolder(file.path);
  });

  ipcMain.handle(INVOKE_CHANNELS.openExternal, async (_event, request: unknown) => {
    if (!isOpenExternalRequest(request)) return;
    // `shell.openExternal` launches whatever the OS has a handler for, so the
    // scheme check is what keeps a `file:` or custom-scheme URL out of it.
    if (!isSafeExternalUrl(request.url)) return;
    await shell.openExternal(request.url);
  });
}

// One instance only: two copies watching the same folder would double every
// notification.
if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on('second-instance', showWindow);

  app.whenReady().then(
    () => {
      registerIpc();
      createTray();
      createWindow();

      app.on('activate', showWindow);
    },
    (error: unknown) => {
      process.stderr.write(`desktop: failed to start: ${String(error)}\n`);
      app.exit(1);
    },
  );

  // Deliberately no `window-all-closed` quit: this app outlives its window.
  app.on('before-quit', () => {
    state.quitting = true;
    state.watcher?.stop();
  });
}
