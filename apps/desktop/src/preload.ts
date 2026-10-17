/**
 * Preload script: the bridge between the sandboxed renderer and the app
 * (issue #371).
 *
 * This file runs with `contextIsolation` on, which means its globals live in a
 * separate V8 context from the page's. `contextBridge.exposeInMainWorld` is the
 * only way across, and what it copies is a frozen object of functions — not the
 * `ipcRenderer` itself.
 *
 * That distinction is the whole security value of the file. Exposing
 * `ipcRenderer` (or an `invoke(channel, ...args)` passthrough) would let a
 * compromised page send on *any* channel, including the ones Electron's own
 * internals use, which is the well-known way a context-isolated app is still
 * owned. So every function here names its channel as a literal, takes only the
 * arguments that channel accepts, and the main process validates them again on
 * arrival.
 *
 * Likewise, the event subscriptions hand the listener only the payload, never
 * the `IpcRendererEvent` — that object carries a `sender` the page has no
 * business holding.
 */
import { contextBridge, ipcRenderer, type IpcRendererEvent } from 'electron';
import {
  API_GLOBAL,
  EVENT_CHANNELS,
  INVOKE_CHANNELS,
  type DesktopApi,
  type OpenExternalRequest,
  type RevealFileRequest,
  type StatusPayload,
} from './ipc.js';

const api: DesktopApi = {
  chooseFolder: () =>
    ipcRenderer.invoke(INVOKE_CHANNELS.chooseFolder) as Promise<StatusPayload | undefined>,

  stopWatching: () => ipcRenderer.invoke(INVOKE_CHANNELS.stopWatching) as Promise<void>,

  rescan: () => ipcRenderer.invoke(INVOKE_CHANNELS.rescan) as Promise<StatusPayload | undefined>,

  currentStatus: () =>
    ipcRenderer.invoke(INVOKE_CHANNELS.currentStatus) as Promise<StatusPayload | undefined>,

  // Narrowed to the one field the channel accepts, so a page cannot smuggle
  // extra properties into the main process's handler.
  revealFile: (request: RevealFileRequest) =>
    ipcRenderer.invoke(INVOKE_CHANNELS.revealFile, {
      index: request.index,
    }) as Promise<void>,

  openExternal: (request: OpenExternalRequest) =>
    ipcRenderer.invoke(INVOKE_CHANNELS.openExternal, {
      url: request.url,
    }) as Promise<void>,

  onStatusChanged: (listener: (payload: StatusPayload) => void) => {
    // The wrapper exists to drop the event object: handing the page an
    // `IpcRendererEvent` would hand it the `sender` too.
    const handler = (_event: IpcRendererEvent, payload: StatusPayload): void => listener(payload);
    ipcRenderer.on(EVENT_CHANNELS.statusChanged, handler);
    return () => ipcRenderer.removeListener(EVENT_CHANNELS.statusChanged, handler);
  },

  onWatchFailed: (listener: (message: string) => void) => {
    const handler = (_event: IpcRendererEvent, message: string): void => listener(message);
    ipcRenderer.on(EVENT_CHANNELS.watchFailed, handler);
    return () => ipcRenderer.removeListener(EVENT_CHANNELS.watchFailed, handler);
  },
};

contextBridge.exposeInMainWorld(API_GLOBAL, api);
