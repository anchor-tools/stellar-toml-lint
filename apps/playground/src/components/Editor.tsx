import { useRef, useCallback, useState, useEffect } from 'react';
import Editor from '@monaco-editor/react';
import { decodeShareLink, type ShareState } from 'stellar-toml-lint/browser';
import type { Diagnostic } from '../types';
import { useCollaboration } from '../collab/useCollaboration';
import { CollaboratorList } from './CollaboratorList';
import { ShareControls } from './ShareControls';
import type * as monaco from 'monaco-editor';

interface EditorProps {
  onDiagnostics: (diagnostics: Diagnostic[]) => void;
}

/** The lint flags a decoded share link restores. */
interface SharedFlags {
  rules?: ShareState['rules'];
  strict?: boolean;
}

const defaultCode = `[general]
SIGNING_KEY = "GAI..."
ORG_URL = "https://example.com"

[DOCUMENTATION]
ORG_NAME = "Example Anchor"
ORG_LANG = "en"

[[VALIDATORS]]
ALIAS = "validator1"
PUBLIC_KEY = "GAAAA..."
HOST = "stellar-core.example.com:11625"
`;

/** Turns lint flags into the options object the worker forwards to `lintBrowser`. */
function lintOptionsOf(flags: SharedFlags): Record<string, unknown> {
  return {
    ...(flags.rules === undefined ? {} : { rules: flags.rules }),
    ...(flags.strict === true ? { strict: true } : {}),
  };
}

export default function EditorComponent({ onDiagnostics }: EditorProps) {
  const workerRef = useRef<Worker | null>(null);
  const editorRef = useRef<monaco.editor.IStandaloneCodeEditor | null>(null);
  const modelRef = useRef<monaco.editor.ITextModel | null>(null);
  // A share link usually resolves after Monaco mounts, but not always: the page
  // can decode while the editor is still loading, so the state waits here and
  // `handleMount` applies whatever arrived first.
  const pendingShareRef = useRef<{ source: string; flags: SharedFlags } | null>(null);
  const [loading, setLoading] = useState(false);
  const [collabEnabled, setCollaborationEnabled] = useState(false);
  const [flags, setFlags] = useState<SharedFlags>({});
  const [sharedDomain, setSharedDomain] = useState<string | undefined>(undefined);
  const [shareNotice, setShareNotice] = useState('');

  const {
    provider,
    collaborators,
    isConnected,
    isSynced,
    roomId,
    username,
    setUsername,
    setDiagnostics,
    connect,
    disconnect,
  } = useCollaboration({
    enabled: collabEnabled,
    onCollaboratorsChange: () => {
      if (provider) {
        setDiagnostics(provider.getDiagnostics());
      }
    },
  });

  useEffect(() => {
    return () => {
      workerRef.current?.terminate();
    };
  }, []);

  /** Sends the buffer to the worker with the flags the session carries. */
  const lint = useCallback((content: string, atFlags: SharedFlags) => {
    if (!workerRef.current) return;
    setLoading(true);
    workerRef.current.postMessage({ type: 'lint', content, options: lintOptionsOf(atFlags) });
  }, []);

  /**
   * Loads a shared snippet into the buffer and lints it (issue #372).
   *
   * The worker is created on mount, so a link that decodes first has to wait
   * for it rather than post into nothing.
   */
  const applyShared = useCallback(
    (source: string, atFlags: SharedFlags) => {
      const editor = editorRef.current;
      const worker = workerRef.current;
      if (editor === null || worker === null) {
        pendingShareRef.current = { source, flags: atFlags };
        return;
      }
      editor.setValue(source);
      lint(source, atFlags);
    },
    [lint],
  );

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const decoded = await decodeShareLink(window.location.hash);
      if (cancelled || decoded.status === 'absent') return;
      if (decoded.status === 'invalid') {
        // Say what is wrong instead of loading an empty editor: a link that
        // came through a URL shortener is usually one bad character away.
        setShareNotice(
          `This share link is corrupt: ${decoded.reason}. The editor shows the default file.`,
        );
        return;
      }
      const state = decoded.state;
      const sharedFlags: SharedFlags = { rules: state.rules, strict: state.strict };
      setFlags(sharedFlags);
      if (typeof state.source === 'string') {
        applyShared(state.source, sharedFlags);
        if (!decoded.verified) {
          setShareNotice('This share link carried no checksum, so nothing verified it on arrival.');
        }
        return;
      }
      if (typeof state.domain === 'string') {
        setSharedDomain(state.domain);
        // A domain link holds twenty characters instead of the file, so the
        // file has to be fetched to be edited. SEP-1 requires the very CORS
        // header that makes this work, and the failure says so when it does not.
        try {
          const response = await fetch(`https://${state.domain}/.well-known/stellar.toml`);
          if (!response.ok) throw new Error(`HTTP ${response.status}`);
          applyShared(await response.text(), sharedFlags);
        } catch (error) {
          setShareNotice(
            `The link points at ${state.domain}, but the file could not be fetched from this page: ${
              error instanceof Error ? error.message : String(error)
            }. Paste it into the editor to lint it.`,
          );
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [applyShared]);

  const handleMount = useCallback(
    (editor: monaco.editor.IStandaloneCodeEditor) => {
      editorRef.current = editor;
      modelRef.current = editor.getModel();

      workerRef.current = new Worker(new URL('../workers/linter.worker.ts', import.meta.url), {
        type: 'module',
      });

      workerRef.current.onmessage = (e: MessageEvent) => {
        const { type, result } = e.data;
        if (type === 'result') {
          const diags: Diagnostic[] = result.diagnostics ?? [];
          onDiagnostics(diags);
          if (provider) {
            setDiagnostics(diags);
          }
          setLoading(false);
        } else if (type === 'error') {
          setLoading(false);
        }
      };

      const pending = pendingShareRef.current;
      if (pending !== null) {
        pendingShareRef.current = null;
        editor.setValue(pending.source);
        lint(pending.source, pending.flags);
      }

      if (provider) {
        provider.bindMonaco(editor, editor.getModel());
      }
    },
    [onDiagnostics, provider, setDiagnostics, lint],
  );

  const handleChange = useCallback(
    (value: string | undefined) => {
      if (value === undefined) return;
      lint(value, flags);
    },
    [flags, lint],
  );

  /** The buffer, read only when a share link is asked for. */
  const getSource = useCallback(() => modelRef.current?.getValue() ?? defaultCode, []);

  const toggleCollaboration = useCallback(() => {
    if (collabEnabled) {
      disconnect();
      setCollaborationEnabled(false);
    } else {
      setCollaborationEnabled(true);
      setTimeout(() => connect(), 100);
    }
  }, [collabEnabled, connect, disconnect]);

  const handleUsernameChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setUsername(e.target.value);
  };

  return (
    <div className="h-full flex flex-col">
      <div className="bg-gray-900 px-4 py-2 border-b border-gray-800 flex items-center justify-between">
        <span className="text-sm font-medium text-gray-300">Editor</span>
        <div className="flex items-center gap-4">
          {loading && <span className="text-xs text-blue-400">Linting...</span>}
          <div className="flex items-center gap-2">
            <label className="text-xs text-gray-400">Collaborate</label>
            <button
              onClick={toggleCollaboration}
              className={`px-2 py-1 text-xs rounded transition-colors ${
                collabEnabled
                  ? 'bg-green-600 text-white'
                  : 'bg-gray-800 text-gray-300 hover:bg-gray-700'
              }`}
            >
              {collabEnabled ? 'Connected' : 'Connect'}
            </button>
            {collabEnabled && (
              <span
                className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-500' : 'bg-red-500'}`}
              />
            )}
          </div>
        </div>
      </div>
      {collabEnabled && (
        <div className="bg-gray-900 px-4 py-2 border-b border-gray-800 flex items-center gap-4 text-sm">
          <div className="flex items-center gap-2">
            <span className="text-gray-400">Room:</span>
            <code className="text-xs bg-gray-800 px-2 py-1 rounded">{roomId}</code>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-gray-400">You:</span>
            <input
              type="text"
              value={username}
              onChange={handleUsernameChange}
              className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-white text-sm w-40"
              placeholder="username"
            />
          </div>
          <div className="flex items-center gap-2">
            <span className="text-gray-400">Peers:</span>
            <span className="text-blue-400">{collaborators.length}</span>
          </div>
          {isSynced && <span className="text-xs text-green-400">Synced</span>}
        </div>
      )}
      <div className="flex-1">
        <Editor
          height="100%"
          defaultLanguage="toml"
          defaultValue={defaultCode}
          onChange={handleChange}
          onMount={handleMount}
          options={{
            minimap: { enabled: false },
            fontSize: 14,
            theme: 'vs-dark',
            scrollBeyondLastLine: false,
            automaticLayout: true,
          }}
        />
      </div>
      {shareNotice && (
        <div className="bg-gray-900 px-4 py-2 border-t border-gray-800 text-xs text-amber-400">
          {shareNotice}
        </div>
      )}
      <ShareControls
        getSource={getSource}
        domain={sharedDomain}
        rules={flags.rules}
        strict={flags.strict}
      />
      {collabEnabled && collaborators.length > 0 && (
        <CollaboratorList collaborators={collaborators} />
      )}
    </div>
  );
}
