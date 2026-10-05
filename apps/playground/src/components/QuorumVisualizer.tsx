import { useRef } from 'react';
import type Cytoscape from 'cytoscape';
import ReactCytoscape from 'react-cytoscapejs';
import { Box, Typography } from '@mui/material';

interface ValidatorNode {
  group: string;
  data: {
    id: string;
    label: string;
    alias: string;
    publicKey: string;
    host: string;
  };
}

export default function QuorumVisualizer() {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Cytoscape.Core | null>(null);

  const elements: ValidatorNode[] = [
    {
      group: 'nodes',
      data: {
        id: 'v1',
        label: 'Validator 1',
        alias: 'validator1',
        publicKey: 'GAAAA...',
        host: 'host1:11625',
      },
    },
    {
      group: 'nodes',
      data: {
        id: 'v2',
        label: 'Validator 2',
        alias: 'validator2',
        publicKey: 'GBBBB...',
        host: 'host2:11625',
      },
    },
    {
      group: 'nodes',
      data: {
        id: 'v3',
        label: 'Validator 3',
        alias: 'validator3',
        publicKey: 'GCCCC...',
        host: 'host3:11625',
      },
    },
    { group: 'edges', data: { id: 'e1', source: 'v1', target: 'v2', weight: 0.5 } },
    { group: 'edges', data: { id: 'e2', source: 'v2', target: 'v3', weight: 0.5 } },
    { group: 'edges', data: { id: 'e3', source: 'v3', target: 'v1', weight: 0.5 } },
  ];

  return (
    <Box className="w-full h-full">
      <Typography variant="h6" className="text-white mb-4">
        Quorum DAG Visualizer
      </Typography>
      <Box className="w-full" style={{ height: 'calc(100% - 2rem)' }} ref={containerRef}>
        <ReactCytoscape
          elements={elements}
          style={{ width: '100%', height: '100%' }}
          layout={{ name: 'grid', rows: 1 }}
          cy={(cy) => {
            cyRef.current = cy;
          }}
          stylesheet={[
            {
              selector: 'node',
              style: {
                'background-color': '#3b82f6',
                label: 'data(label)',
                color: '#fff',
                'text-valign': 'center',
                'text-halign': 'center',
                width: 80,
                height: 80,
                shape: 'ellipse',
                'border-width': 2,
                'border-color': '#60a5fa',
              },
            },
            {
              selector: 'edge',
              style: {
                width: 2,
                'line-color': '#6b7280',
                'target-arrow-color': '#6b7280',
                'target-arrow-shape': 'triangle',
                'curve-style': 'bezier',
              },
            },
          ]}
        />
      </Box>
    </Box>
  );
}
