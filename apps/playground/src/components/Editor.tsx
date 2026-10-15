import { useRef, useCallback, useState, useEffect } from 'react';
import Editor from '@monaco-editor/react';
import type { Diagnostic } from '../types';
import { useCollaboration } from '../collab/useCollaboration';
import { CollaboratorList } from './CollaboratorList';
import type * as monaco from 'monaco-editor';

interface EditorProps {
  onDiagnostics: (diagnostics: Diagnostic[]) => void;
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

export default function EditorComponent({ onDiagnostics }: EditorProps) {
  const workerRef = useRef<Worker | null>(null);
  const editorRef = useRef<monaco.editor.IStandaloneCodeEditor | null>(null);
  const modelRef = useRef<monaco.editor.ITextModel | null>(null);
  const [loading, setLoading] = useState(false);
  const [collabEnabled, setCollabEnabled] = useState(false);

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

  const handleMount = useCallback((editor: monaco.editor.IStandaloneCodeEditor) => {
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

    if (provider) {
      provider.bindMonaco(editor, editor.getModel());
    }
  }, [onDiagnostics, provider, setDiagnostics]);

  const handleChange = useCallback((value: string | undefined) => {
    if (!value || !workerRef.current) return;
    setLoading(true);
    workerRef.current.postMessage({
      type: 'lint',
      content: value,
    });
  }, []);

  const toggleCollaboration = useCallback(() => {
    if (collabEnabled) {
      disconnect();
      setCollabEnabled(false);
    } else {
      setCollabEnabled(true);
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
              <span className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-500' : 'bg-red-500'}`} />
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
      {collabEnabled && collaborators.length > 0 && (
        <CollaboratorList collaborators={collaborators} />
      )}
    </div>
  );
}