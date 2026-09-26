import { useRef, useCallback, useState, useEffect } from 'react';
import Editor from '@monaco-editor/react';
import type { Diagnostic } from '../types';

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
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    return () => {
      workerRef.current?.terminate();
    };
  }, []);

  const handleMount = useCallback(() => {
    workerRef.current = new Worker(new URL('../workers/linter.worker.ts', import.meta.url), {
      type: 'module',
    });

    workerRef.current.onmessage = (e: MessageEvent) => {
      const { type, result } = e.data;
      if (type === 'result') {
        const diags: Diagnostic[] = result.diagnostics ?? [];
        onDiagnostics(diags);
        setLoading(false);
      } else if (type === 'error') {
        setLoading(false);
      }
    };
  }, [onDiagnostics]);

  const handleChange = useCallback((value: string | undefined) => {
    if (!value || !workerRef.current) return;
    setLoading(true);
    workerRef.current.postMessage({
      type: 'lint',
      content: value,
    });
  }, []);

  return (
    <div className="h-full flex flex-col">
      <div className="bg-gray-900 px-4 py-2 border-b border-gray-800 flex items-center justify-between">
        <span className="text-sm font-medium text-gray-300">Editor</span>
        {loading && <span className="text-xs text-blue-400">Linting...</span>}
      </div>
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
    </div>
  );
}
