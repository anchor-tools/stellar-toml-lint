/**
 * The security posture of the desktop app's only window (issue #371).
 *
 * An Electron app that loads a page which lints whatever TOML a compliance
 * officer drags into it is, structurally, a browser pointed at untrusted input.
 * Electron's defaults have improved, but the flags that matter are easy to
 * regress silently in a refactor — and a regression here means a malformed
 * `stellar.toml` can reach Node's `fs` from the renderer.
 *
 * So the window's options live here as data, with no `electron` import, for two
 * reasons: the test suite can assert on them without launching a browser
 * process, and the one place that decides them is also the one place that
 * documents why. `main.ts` passes the result straight to `new BrowserWindow`.
 *
 * The four flags that carry the weight:
 *
 * - `sandbox: true` — the renderer runs in an OS-level sandboxed process. It is
 *   the difference between "the renderer cannot read your home directory" and
 *   "the renderer is a Node process".
 * - `contextIsolation: true` — the preload script's globals live in a separate
 *   V8 context from the page's, so a compromised page cannot reach into the
 *   preload's scope and borrow its privileges.
 * - `nodeIntegration: false` — no `require` in the renderer. Redundant with
 *   `sandbox` today, stated anyway because it is the flag whose absence is
 *   historically how Electron apps got owned.
 * - `webSecurity: true` — keeps the same-origin policy on. Disabling it is the
 *   usual shortcut for loading local files, and the usual root cause after.
 *
 * Everything the renderer legitimately needs — read a file, pick a folder,
 * receive lint results — arrives over the narrow IPC surface in `ipc.ts`.
 */

/** The `webPreferences` subset this app pins, as `BrowserWindow` takes it. */
export interface SecureWebPreferences {
  sandbox: true;
  contextIsolation: true;
  nodeIntegration: false;
  nodeIntegrationInWorker: false;
  nodeIntegrationInSubFrames: false;
  webSecurity: true;
  allowRunningInsecureContent: false;
  experimentalFeatures: false;
  /** Absolute path to the compiled preload script. */
  preload: string;
}

/** The window options `main.ts` hands to `new BrowserWindow`. */
export interface SecureWindowOptions {
  width: number;
  height: number;
  minWidth: number;
  minHeight: number;
  title: string;
  /** Painted only once the first frame is ready, to avoid a white flash. */
  show: false;
  backgroundColor: string;
  webPreferences: SecureWebPreferences;
}

/** Window title, also used as the tray tooltip prefix. */
export const APP_TITLE = 'Stellar TOML Lint';

/**
 * The window options, with `preload` pointing at the compiled preload script.
 *
 * Every flag is a literal rather than a parameter: a caller that could pass
 * `sandbox: false` is a caller that eventually will.
 */
export function secureWindowOptions(preloadPath: string): SecureWindowOptions {
  return {
    width: 1_280,
    height: 860,
    minWidth: 900,
    minHeight: 600,
    title: APP_TITLE,
    show: false,
    // Matches the playground's dark shell, so the first paint is not a flash.
    backgroundColor: '#11131a',
    webPreferences: {
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false,
      nodeIntegrationInWorker: false,
      nodeIntegrationInSubFrames: false,
      webSecurity: true,
      allowRunningInsecureContent: false,
      experimentalFeatures: false,
      preload: preloadPath,
    },
  };
}

/**
 * `true` when a URL is one this app is willing to load in its own window.
 *
 * Used for `will-navigate` and `setWindowOpenHandler`. A link in a linted
 * document — an `ORG_URL`, a `helpUri` — must open in the user's browser, not
 * replace the app's own page: a navigation inside the window would put a
 * third-party origin behind whatever the preload exposes.
 *
 * `devUrl` is the Vite dev server, present only when the app runs from source.
 */
export function isInternalUrl(url: string, devUrl?: string): boolean {
  if (url.startsWith('file://')) return true;
  if (devUrl !== undefined && devUrl.length > 0 && url.startsWith(devUrl)) return true;
  return false;
}

/**
 * `true` when a URL is safe to hand to the OS browser.
 *
 * `shell.openExternal` will launch anything the OS has a handler for,
 * including `file:` and custom schemes an installed app registered. A document
 * being linted is untrusted input, so only the two web schemes get through.
 */
export function isSafeExternalUrl(url: string): boolean {
  try {
    const protocol = new URL(url).protocol;
    return protocol === 'https:' || protocol === 'http:';
  } catch {
    return false;
  }
}
