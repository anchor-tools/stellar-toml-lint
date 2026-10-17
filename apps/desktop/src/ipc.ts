/**
 * The IPC contract between main and renderer (issue #371).
 *
 * With `sandbox` and `contextIsolation` on, this surface is the *entire*
 * privilege the renderer has. Everything the window can do to the user's
 * machine, it does by sending one of these messages — so the list being short,
 * named in one place, and validated on arrival is the security model, not
 * paperwork around it.
 *
 * Two rules the main process follows for every handler:
 *
 * - **Validate the payload.** A renderer compromised by a malicious document
 *   can send any shape it likes down a channel, so a handler that destructures
 *   its argument is a handler that trusts the page. The `isX` guards here are
 *   what each handler checks first.
 * - **Never accept a path.** No channel takes a file path from the renderer.
 *   The folder is chosen through the OS dialog, the main process remembers it,
 *   and the renderer refers to files only by the paths the main process already
 *   sent it. A `readFile(path)` channel would hand the renderer back the
 *   filesystem access the sandbox exists to take away.
 *
 * No `electron` import here on purpose: the contract is data and predicates, so
 * the test suite can assert on it without a browser process.
 */
import type { FileStatus, ScanSnapshot, TrayState } from './status.js';

/**
 * Channels the renderer may invoke and expect a reply on.
 *
 * `request/` by convention, so a reviewer can tell at a glance which direction
 * a channel runs.
 */
export const INVOKE_CHANNELS = {
  /** Opens the OS folder picker and begins watching what the user chose. */
  chooseFolder: 'request/choose-folder',
  /** Stops watching and clears the status. */
  stopWatching: 'request/stop-watching',
  /** Re-lints every watched file now. */
  rescan: 'request/rescan',
  /** The current snapshot, for a window that opened after a scan. */
  currentStatus: 'request/current-status',
  /** Reveals one of the watched files in the OS file manager. */
  revealFile: 'request/reveal-file',
  /** Opens an external `https:` link in the user's browser. */
  openExternal: 'request/open-external',
} as const;

/** Channels the main process pushes to the renderer, unprompted. */
export const EVENT_CHANNELS = {
  /** A new scan finished; carries the snapshot and the tray state. */
  statusChanged: 'event/status-changed',
  /** The watched folder changed, or watching stopped (`undefined`). */
  folderChanged: 'event/folder-changed',
  /** A scan or the watcher itself failed, with a message fit to display. */
  watchFailed: 'event/watch-failed',
} as const;

/** Every channel name, for the preload's allow-list and for tests. */
export const ALL_CHANNELS: readonly string[] = [
  ...Object.values(INVOKE_CHANNELS),
  ...Object.values(EVENT_CHANNELS),
];

/** What the renderer learns after a scan. */
export interface StatusPayload {
  snapshot: ScanSnapshot;
  tray: TrayState;
  /** The folder being watched, or `undefined` when watching stopped. */
  directory: string | undefined;
  /** `false` when the platform refused a recursive watch. */
  recursive: boolean;
}

/** The `revealFile` request: an index into the last snapshot, never a path. */
export interface RevealFileRequest {
  /** Index into {@link StatusPayload.snapshot}`.files`. */
  index: number;
}

/** The `openExternal` request. */
export interface OpenExternalRequest {
  url: string;
}

/** `true` when `value` is a plain object, the precondition for every guard. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Validates a {@link RevealFileRequest} arriving from the renderer. */
export function isRevealFileRequest(value: unknown): value is RevealFileRequest {
  if (!isRecord(value)) return false;
  const index = value.index;
  return typeof index === 'number' && Number.isInteger(index) && index >= 0;
}

/**
 * Validates an {@link OpenExternalRequest}.
 *
 * Only checks the shape; whether the URL is one we are willing to open is
 * `isSafeExternalUrl`'s job in `window-options.ts`, and the handler checks
 * both.
 */
export function isOpenExternalRequest(value: unknown): value is OpenExternalRequest {
  return isRecord(value) && typeof value.url === 'string' && value.url.length > 0;
}

/** Validates a {@link FileStatus}, used when replaying a snapshot. */
export function isFileStatus(value: unknown): value is FileStatus {
  if (!isRecord(value)) return false;
  return (
    typeof value.path === 'string' &&
    typeof value.errors === 'number' &&
    typeof value.warnings === 'number' &&
    (value.unreadable === undefined || typeof value.unreadable === 'boolean')
  );
}

/**
 * The API the preload exposes on `window.stellarTomlLint`.
 *
 * Declared as a type here so main, preload, and renderer cannot drift: the
 * preload must implement it and the renderer may assume nothing else.
 */
export interface DesktopApi {
  chooseFolder(): Promise<StatusPayload | undefined>;
  stopWatching(): Promise<void>;
  rescan(): Promise<StatusPayload | undefined>;
  currentStatus(): Promise<StatusPayload | undefined>;
  revealFile(request: RevealFileRequest): Promise<void>;
  openExternal(request: OpenExternalRequest): Promise<void>;
  /** Subscribes to status pushes. Returns an unsubscribe function. */
  onStatusChanged(listener: (payload: StatusPayload) => void): () => void;
  /** Subscribes to watch failures. Returns an unsubscribe function. */
  onWatchFailed(listener: (message: string) => void): () => void;
}

/** The global the preload installs, for the renderer's type-checking. */
export const API_GLOBAL = 'stellarTomlLint';
