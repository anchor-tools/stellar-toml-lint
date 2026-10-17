# Stellar TOML Lint — desktop app

A tray application for macOS, Windows, and Linux that watches a folder and
raises a native OS notification when a change introduces an error in a
`stellar.toml`.

It exists for the people who own the file but do not own a terminal: compliance
officers and anchor operators who edit `stellar.toml` in a text editor, commit
it, and find out it was wrong when a wallet stops resolving their asset. The
same rules the CLI runs in CI, running locally, saying nothing until something
breaks.

## What it does

- **Lives in the tray.** Closing the window hides it; the app keeps watching.
  Quitting is an explicit choice from the tray menu.
- **Shows status in the menu bar.** A green check when every watched file is
  clean, amber for warnings, a red alert for errors, grey when no folder is
  being watched. The glyphs differ in shape as well as colour, and the tooltip
  states the status in words.
- **Notifies only on change.** A new error, or more errors than before, raises
  a notification. Unchanged errors do not — a watcher that fires on every scan
  is one you mute within the hour. A file that goes back to clean gets one
  "resolved" notice so you learn the tray went green without looking.
- **Uses the same `lint()` as the CLI**, so the desktop app and your pipeline
  cannot disagree about whether a file is valid.

## Running it from source

From the repository root, build the linter first — the app depends on it as a
local file dependency:

```sh
npm ci
npm run build
```

Then, in this directory:

```sh
npm install
npm start
```

`npm start` compiles the main process, bundles the preload, and launches
Electron Forge.

## Building installers

```sh
npm run make           # every maker valid for the current platform
npm run make:dmg       # macOS .dmg
npm run make:msi       # Windows .msi
npm run make:appimage  # Linux .AppImage
```

Installers land in `out/make/`. Each maker runs only on its own platform —
Electron Forge cannot build a DMG from Linux — so a full release set needs a
runner per platform.

Toolchain notes:

- **MSI** needs the [WiX Toolset v3](https://wixtoolset.org/) on `PATH`. The
  Squirrel maker Forge defaults to would avoid that, but an MSI is what a
  corporate IT department can deploy by policy, and this app's users work at
  the kind of company that deploys software by policy.
- **AppImage** uses [`@reforged/maker-appimage`](https://www.npmjs.com/package/@reforged/maker-appimage),
  a community maker — Forge's own Linux makers are deb, rpm, flatpak, and snap.
  A single executable needs no package manager and no root, which is the point
  of shipping an AppImage rather than a `.deb`.
- **macOS code signing** is picked up from `OSX_SIGN_IDENTITY` when set.
  Unsigned builds still run locally, behind a Gatekeeper prompt.
- A **ZIP** maker is configured for all three platforms so CI can exercise
  packaging without any platform toolchain or signing identity.

## Security model

The renderer is treated as a browser pointed at untrusted input, because that
is what it is: it displays paths and counts derived from files the user did not
write.

| Setting                       | Value   | Why                                                               |
| ----------------------------- | ------- | ----------------------------------------------------------------- |
| `sandbox`                     | `true`  | The renderer runs in an OS-sandboxed process.                     |
| `contextIsolation`            | `true`  | Preload globals live in a separate V8 context from the page's.    |
| `nodeIntegration`             | `false` | No `require` in the renderer.                                     |
| `nodeIntegrationInWorker`     | `false` | A worker with Node access is the same hole as a renderer with it. |
| `nodeIntegrationInSubFrames`  | `false` | Likewise for subframes.                                           |
| `webSecurity`                 | `true`  | Same-origin policy stays on.                                      |
| `allowRunningInsecureContent` | `false` | No mixed content.                                                 |

Beyond the flags:

- **No IPC channel accepts a filesystem path.** The folder is chosen through
  the OS dialog, the main process remembers it, and the renderer refers to
  files by index into the snapshot the main process produced. A
  `readFile(path)` channel would hand back exactly the access the sandbox
  exists to remove.
- **The preload exposes functions, not `ipcRenderer`.** Each one names its
  channel as a literal. A generic `invoke(channel, …args)` passthrough is the
  well-known way a context-isolated app is still compromised.
- **Every handler validates its payload** before using it, with the guards in
  `src/ipc.ts`.
- **Navigation is denied.** A link in a linted document opens in the user's
  browser, and only if it is `http:` or `https:` — `shell.openExternal` will
  launch any scheme the OS has a handler for.
- **The renderer's CSP is `default-src 'none'`** with explicit additions, and
  it makes no network requests at all.

## Layout

Everything except `main.ts` and `preload.ts` is free of any `electron` import,
so the behaviour is covered by `test/desktop/` without launching a browser
process.

| File                    | Holds                                                          |
| ----------------------- | -------------------------------------------------------------- |
| `src/main.ts`           | Electron wiring: window, tray, IPC handlers, app lifecycle.    |
| `src/preload.ts`        | The `contextBridge` surface, bundled to CommonJS.              |
| `src/window-options.ts` | The security flags, and the navigation predicates.             |
| `src/ipc.ts`            | Channel names, payload types, and the validation guards.       |
| `src/watcher.ts`        | Recursive folder watching, with change batching.               |
| `src/scanner.ts`        | Files → a snapshot, with the reader and linter injected.       |
| `src/status.ts`         | Tray state, tooltip, and the notification policy.              |
| `src/tray-icons.ts`     | The tray glyphs, generated as SVG rather than shipped as PNGs. |
| `renderer/`             | The window: one HTML file and ~120 lines of DOM.               |

## Tests

Run from the repository root:

```sh
npx vitest run test/desktop/
```

They cover window creation and the IPC security flags, the navigation guards,
the channel contract and its validators, file selection and change batching,
the scanner's handling of unreadable files, the tray state machine, and the
notification policy — including the case that matters most, that an unchanged
error stays silent.

## Known limitations

- **Recursive watching** is native on macOS and Windows, and on Linux since
  Node 20. Where the platform refuses it, the app watches the chosen folder
  non-recursively and says so in the window rather than failing.
- **The window is a status list, not an editor.** It shows which files are
  broken and how badly; clicking one reveals it in the OS file manager. Editing
  happens in the editor you already use, or in the
  [playground](../playground).
