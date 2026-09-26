import { useState, useCallback } from 'react';
import Editor from './components/Editor';
import Diagnostics from './components/Diagnostics';
import QuorumVisualizer from './components/QuorumVisualizer';
import LiveNetworkProbe from './components/LiveNetworkProbe';
import FixActions from './components/FixActions';
import type { Diagnostic } from './types';

type TabId = 'diagnostics' | 'quorum' | 'network' | 'fix';

const TABS: { id: TabId; label: string }[] = [
  { id: 'diagnostics', label: 'Diagnostics' },
  { id: 'quorum', label: 'Quorum Visualizer' },
  { id: 'network', label: 'Live Network Probe' },
  { id: 'fix', label: 'Fix Actions' },
];

export default function App() {
  const [activeTab, setActiveTab] = useState<TabId>('diagnostics');
  const [diagnostics, setDiagnostics] = useState<Diagnostic[]>([]);

  const handleDiagnostics = useCallback((diags: Diagnostic[]) => {
    setDiagnostics(diags);
  }, []);

  return (
    <div className="h-screen flex flex-col bg-gray-950 text-white">
      <header className="bg-gray-900 border-b border-gray-800 px-6 py-3">
        <h1 className="text-xl font-bold text-white">Stellar TOML Lint Playground</h1>
      </header>
      <div className="flex flex-1 overflow-hidden">
        <div className="w-1/2 h-full">
          <Editor onDiagnostics={handleDiagnostics} />
        </div>
        <div className="w-1/2 h-full flex flex-col bg-gray-900 border-l border-gray-800">
          <div className="flex border-b border-gray-800 bg-gray-900">
            {TABS.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-4 py-3 text-sm font-medium transition-colors ${
                  activeTab === tab.id
                    ? 'text-white border-b-2 border-blue-500'
                    : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
          <div className="flex-1 overflow-auto p-4">
            {activeTab === 'diagnostics' && <Diagnostics diagnostics={diagnostics} />}
            {activeTab === 'quorum' && <QuorumVisualizer />}
            {activeTab === 'network' && <LiveNetworkProbe />}
            {activeTab === 'fix' && <FixActions />}
          </div>
        </div>
      </div>
    </div>
  );
}
