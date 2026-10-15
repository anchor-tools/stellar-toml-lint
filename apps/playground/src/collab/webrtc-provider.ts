/**
 * WebRTC Peer-to-Peer Collaborative Editing Provider
 *
 * Uses Yjs CRDT and y-webrtc for browser-to-browser synchronization
 * of Monaco editor buffers and diagnostic markers without a central server.
 */

import * as Y from 'yjs';
import { WebrtcProvider } from 'y-webrtc';
import * as monaco from 'monaco-editor';
import type { Diagnostic } from '../types';
import type { Awareness } from 'y-protocols/awareness.js';

export interface Collaborator {
  clientId: number;
  name: string;
  color: string;
  cursorPosition?: { lineNumber: number; column: number };
  selectionStart?: { lineNumber: number; column: number };
  selectionEnd?: { lineNumber: number; column: number };
}

export interface WebRTCProviderOptions {
  roomId?: string;
  signalingServers?: string[];
  username?: string;
  onCollaboratorsChange?: (collaborators: Collaborator[]) => void;
  onConnectionChange?: (connected: boolean) => void;
  onSyncChange?: (synced: boolean) => void;
}

const DEFAULT_SIGNALING_SERVERS = [
  'wss://signaling.yjs.dev',
  'wss://signaling.yjs.org',
];

const COLLABORATOR_COLORS = [
  '#FF6B6B', '#4ECDC4', '#45B7D1', '#FFBE0B', '#FB5607',
  '#8338EC', '#3A86FF', '#06D6A0', '#FF006E', '#FF9F1C',
];

function generateRoomId(): string {
  const hash = window.location.hash.slice(1);
  if (hash && /^[a-zA-Z0-9_-]+$/.test(hash)) {
    return hash;
  }
  const newRoomId = `stellar-toml-${Math.random().toString(36).slice(2, 10)}`;
  window.location.hash = newRoomId;
  return newRoomId;
}

function generateUsername(): string {
  const adjectives = ['swift', 'bright', 'calm', 'keen', 'bold', 'wise', 'fair', 'grand'];
  const nouns = ['star', 'comet', 'orbit', 'nova', 'pulsar', 'quasar', 'zenith', 'apex'];
  const adj = adjectives[Math.floor(Math.random() * adjectives.length)];
  const noun = nouns[Math.floor(Math.random() * nouns.length)];
  const num = Math.floor(Math.random() * 1000).toString().padStart(3, '0');
  return `${adj}-${noun}-${num}`;
}

function getColorForClientId(clientId: number): string {
  return COLLABORATOR_COLORS[clientId % COLLABORATOR_COLORS.length] ?? '#FF6B6B';
}

export class WebRTCCollaborationProvider {
  private ydoc: Y.Doc;
  private provider: WebrtcProvider | null = null;
  private yText: Y.Text;
  private yDiagnostics: Y.Array<Diagnostic>;
  private yCursors: Y.Map<{
    user: string;
    color: string;
    cursor: { lineNumber: number; column: number } | null;
    selection: { start: { lineNumber: number; column: number }; end: { lineNumber: number; column: number } } | null;
  }>;
  private awareness: Awareness;
  private monacoModel: monaco.editor.ITextModel | null = null;
  private monacoEditor: monaco.editor.IStandaloneCodeEditor | null = null;
  private options: Required<WebRTCProviderOptions>;
  private isConnected = false;
  private isSynced = false;
  private localClientId: number;
  private collaboratorColors = new Map<number, string>();
  private cursorDecorations: string[] = [];
  private selectionDecorations: string[] = [];
  private username: string;
  private roomId: string;

  constructor(options: WebRTCProviderOptions = {}) {
    this.ydoc = new Y.Doc();
    this.yText = this.ydoc.getText('monaco');
    this.yDiagnostics = this.ydoc.getArray<Diagnostic>('diagnostics');
    this.yCursors = this.ydoc.getMap('cursors');
    this.awareness = (this.ydoc as unknown as { awareness: Awareness }).awareness;
    this.localClientId = this.ydoc.clientID;

    this.roomId = options.roomId ?? generateRoomId();
    this.username = options.username ?? generateUsername();

    this.options = {
      roomId: this.roomId,
      signalingServers: options.signalingServers ?? DEFAULT_SIGNALING_SERVERS,
      username: this.username,
      onCollaboratorsChange: options.onCollaboratorsChange ?? (() => {}),
      onConnectionChange: options.onConnectionChange ?? (() => {}),
      onSyncChange: options.onSyncChange ?? (() => {}),
    };

    this.collaboratorColors.set(this.localClientId, getColorForClientId(this.localClientId));
    this.setupAwareness();
  }

  private setupAwareness(): void {
    this.awareness.setLocalStateField('user', {
      name: this.username,
      color: this.collaboratorColors.get(this.localClientId),
    });

    this.awareness.on('change', () => {
      this.updateCollaborators();
    });
  }

  private updateCollaborators(): void {
    const collaborators: Collaborator[] = [];
    const states = this.awareness.getStates();

    states.forEach((state: Record<string, unknown>, clientId: number) => {
      if (clientId === this.localClientId) return;
      if (!state?.user) return;

      const color = this.collaboratorColors.get(clientId) ?? getColorForClientId(clientId);
      this.collaboratorColors.set(clientId, color);

      collaborators.push({
        clientId,
        name: state.user.name,
        color: state.user.color ?? color,
        cursorPosition: state.cursor?.cursor ?? undefined,
        selectionStart: state.cursor?.selection?.start ?? undefined,
        selectionEnd: state.cursor?.selection?.end ?? undefined,
      });
    });

    this.options.onCollaboratorsChange(collaborators);
    this.updateRemoteCursors(collaborators);
  }

  private updateRemoteCursors(collaborators: Collaborator[]): void {
    if (!this.monacoEditor) return;

    this.clearCursorDecorations();

    for (const collab of collaborators) {
      if (collab.cursorPosition) {
        const decoration = this.monacoEditor.deltaDecorations([], [{
          range: new monaco.Range(
            collab.cursorPosition.lineNumber,
            collab.cursorPosition.column,
            collab.cursorPosition.lineNumber,
            collab.cursorPosition.column + 1
          ),
          options: {
            className: 'remote-cursor',
            beforeContentClassName: `remote-cursor-caret-${collab.clientId}`,
            before: `<div class="remote-cursor-label" style="background: ${collab.color}">${collab.name}</div>`,
            stickiness: monaco.editor.TrackedRangeStickiness.NeverGrowsWhenTypingAtEdges,
          },
        }]);
        this.cursorDecorations.push(...decoration);
      }

      if (collab.selectionStart && collab.selectionEnd) {
        const decoration = this.monacoEditor.deltaDecorations([], [{
          range: new monaco.Range(
            collab.selectionStart.lineNumber,
            collab.selectionStart.column,
            collab.selectionEnd.lineNumber,
            collab.selectionEnd.column
          ),
          options: {
            className: 'remote-selection',
            inlineClassName: `remote-selection-bg-${collab.clientId}`,
            stickiness: monaco.editor.TrackedRangeStickiness.NeverGrowsWhenTypingAtEdges,
          },
        }]);
        this.selectionDecorations.push(...decoration);
      }
    }

    this.injectCursorStyles();
  }

  private injectCursorStyles(): void {
    if (document.getElementById('yjs-collab-styles')) return;

    const style = document.createElement('style');
    style.id = 'yjs-collab-styles';
    style.textContent = `
      .remote-cursor-caret {
        position: relative;
        border-left: 2px solid;
        margin-left: -1px;
        width: 0;
        height: 1.2em;
        display: inline-block;
      }
      .remote-cursor-label {
        position: absolute;
        top: -1.4em;
        left: -2px;
        font-size: 0.7em;
        padding: 1px 4px;
        border-radius: 3px;
        color: white;
        white-space: nowrap;
        font-family: monospace;
        z-index: 100;
      }
      .remote-selection {
        border-radius: 2px;
      }
    `;
    document.head.appendChild(style);

    for (const [clientId, color] of this.collaboratorColors) {
      const styleEl = document.createElement('style');
      styleEl.id = `yjs-collab-${clientId}`;
      styleEl.textContent = `
        .remote-cursor-caret-${clientId} { border-color: ${color} !important; }
        .remote-selection-bg-${clientId} { background-color: ${color}40 !important; }
      `;
      document.head.appendChild(styleEl);
    }
  }

  private clearCursorDecorations(): void {
    if (!this.monacoEditor) return;
    this.monacoEditor.deltaDecorations(this.cursorDecorations, []);
    this.monacoEditor.deltaDecorations(this.selectionDecorations, []);
    this.cursorDecorations = [];
    this.selectionDecorations = [];
  }

  connect(): void {
    if (this.provider) return;

    this.provider = new WebrtcProvider(this.roomId, this.ydoc, {
      signaling: this.options.signalingServers,
      awareness: this.awareness,
    });

    this.provider.on('status', (event: { connected: boolean }) => {
      this.isConnected = event.connected;
      this.options.onConnectionChange(event.connected);
    });

    this.provider.on('synced', (event: { synced: boolean }) => {
      this.isSynced = event.synced;
      this.options.onSyncChange(event.synced);
    });

    this.yText.observe(() => {
      this.syncToMonaco();
    });

    this.yDiagnostics.observe(() => {
      this.options.onCollaboratorsChange(this.getCollaborators());
    });
  }

  disconnect(): void {
    this.provider?.destroy();
    this.provider = null;
    this.isConnected = false;
    this.isSynced = false;
    this.clearCursorDecorations();
    this.options.onConnectionChange(false);
    this.options.onSyncChange(false);
  }

  bindMonaco(editor: monaco.editor.IStandaloneCodeEditor, model: monaco.editor.ITextModel): void {
    this.monacoEditor = editor;
    this.monacoModel = model;

    model.onDidChangeContent((e: monaco.editor.IModelContentChangedEvent) => {
      if (e.isUndoing || e.isRedoing) return;
      this.syncFromMonaco();
    });

    editor.onDidChangeCursorPosition((e: monaco.editor.ICursorPositionChangedEvent) => {
      this.updateLocalCursor(e.position);
    });

    editor.onDidChangeCursorSelection((e: monaco.editor.ISelection) => {
      this.updateLocalSelection(e);
    });

    this.syncFromMonaco();
    this.connect();
  }

  unbindMonaco(): void {
    this.monacoEditor = null;
    this.monacoModel = null;
    this.disconnect();
  }

  private syncFromMonaco(): void {
    if (!this.monacoModel) return;
    const content = this.monacoModel.getValue();
    const yTextContent = this.yText.toString();
    if (content !== yTextContent) {
      this.ydoc.transact(() => {
        this.yText.delete(0, this.yText.length);
        this.yText.insert(0, content);
      });
    }
  }

  private syncToMonaco(): void {
    if (!this.monacoModel) return;
    const yTextContent = this.yText.toString();
    const modelContent = this.monacoModel.getValue();
    if (yTextContent !== modelContent) {
      const cursorPos = this.monacoModel.getPositionAt(this.monacoEditor.getPosition() ?? { lineNumber: 1, column: 1 });
      this.monacoModel.setValue(yTextContent);
      this.monacoEditor.setPosition(cursorPos);
    }
  }

  private updateLocalCursor(position: { lineNumber: number; column: number } | null): void {
    if (!position) return;
    this.awareness.setLocalStateField('cursor', {
      cursor: position,
      selection: this.awareness.getLocalState()?.cursor?.selection ?? null,
    });
  }

  private updateLocalSelection(selection: { startLineNumber: number; startColumn: number; endLineNumber: number; endColumn: number } | null): void {
    const cursorState = this.awareness.getLocalState()?.cursor ?? { cursor: null, selection: null };
    if (selection && (selection.startLineNumber !== selection.endLineNumber || selection.startColumn !== selection.endColumn)) {
      cursorState.selection = {
        start: { lineNumber: selection.startLineNumber, column: selection.startColumn },
        end: { lineNumber: selection.endLineNumber, column: selection.endColumn },
      };
    } else {
      cursorState.selection = null;
    }
    this.awareness.setLocalStateField('cursor', cursorState);
  }

  setDiagnostics(diagnostics: Diagnostic[]): void {
    this.ydoc.transact(() => {
      this.yDiagnostics.delete(0, this.yDiagnostics.length);
      for (const diag of diagnostics) {
        this.yDiagnostics.push([diag]);
      }
    });
  }

  getDiagnostics(): Diagnostic[] {
    return this.yDiagnostics.toArray();
  }

  getCollaborators(): Collaborator[] {
    const collaborators: Collaborator[] = [];
    const states = this.awareness.getStates();

    states.forEach((state: Record<string, unknown>, clientId: number) => {
      if (clientId === this.localClientId) return;
      if (!state?.user) return;

      const color = this.collaboratorColors.get(clientId) ?? getColorForClientId(clientId);
      collaborators.push({
        clientId,
        name: state.user.name,
        color: state.user.color ?? color,
        cursorPosition: state.cursor?.cursor ?? undefined,
        selectionStart: state.cursor?.selection?.start ?? undefined,
        selectionEnd: state.cursor?.selection?.end ?? undefined,
      });
    });

    return collaborators;
  }

  getRoomId(): string {
    return this.roomId;
  }

  getUsername(): string {
    return this.username;
  }

  setUsername(username: string): void {
    this.username = username;
    this.awareness.setLocalStateField('user', {
      name: username,
      color: this.collaboratorColors.get(this.localClientId),
    });
  }

  isConnectedStatus(): boolean {
    return this.isConnected;
  }

  isSyncedStatus(): boolean {
    return this.isSynced;
  }

  destroy(): void {
    this.disconnect();
    this.ydoc.destroy();
    this.clearCursorDecorations();

    for (const [clientId] of this.collaboratorColors) {
      const styleEl = document.getElementById(`yjs-collab-${clientId}`);
      styleEl?.remove();
    }
    const mainStyle = document.getElementById('yjs-collab-styles');
    mainStyle?.remove();
  }
}

export function createWebRTCCollaborationProvider(options?: WebRTCProviderOptions): WebRTCCollaborationProvider {
  return new WebRTCCollaborationProvider(options);
}