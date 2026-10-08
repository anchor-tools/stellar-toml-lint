import { useState, useCallback } from 'react';
import {
  Button,
  Box,
  Typography,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableRow,
  LinearProgress,
} from '@mui/material';

interface ProbeResult {
  name: string;
  status: 'pending' | 'success' | 'error';
  message: string;
  latency?: number;
}

export default function LiveNetworkProbe() {
  const [results, setResults] = useState<ProbeResult[]>([]);
  const [running, setRunning] = useState(false);

  const runProbe = useCallback(async (name: string, url: string) => {
    setRunning(true);
    setResults((prev) => [...prev, { name, status: 'pending', message: 'Testing...' }]);
    const start = Date.now();
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      const response = await fetch(url, { mode: 'cors', signal: controller.signal });
      clearTimeout(timeout);
      const latency = Date.now() - start;
      setResults((prev) =>
        prev.map((r) =>
          r.name === name
            ? {
                name,
                status: response.ok ? 'success' : 'error',
                message: `HTTP ${response.status}`,
                latency,
              }
            : r,
        ),
      );
    } catch {
      const latency = Date.now() - start;
      setResults((prev) =>
        prev.map((r) =>
          r.name === name ? { name, status: 'error', message: 'Connection failed', latency } : r,
        ),
      );
    }
    setRunning(false);
  }, []);

  return (
    <Box className="w-full">
      <Typography variant="h6" className="text-white mb-4">
        Network Probe
      </Typography>
      <Box className="flex gap-3 mb-4 flex-wrap">
        <Button
          variant="contained"
          onClick={() => runProbe('CORS', 'https://example.com/.well-known/stellar.toml')}
          disabled={running}
        >
          Test CORS
        </Button>
        <Button
          variant="contained"
          onClick={() => runProbe('TLS', 'https://example.com')}
          disabled={running}
        >
          Test TLS
        </Button>
        <Button
          variant="contained"
          onClick={() => runProbe('Horizon', 'https://horizon.stellar.org/info')}
          disabled={running}
        >
          Horizon State
        </Button>
      </Box>
      {running && <LinearProgress className="mb-4" />}
      <Paper className="bg-gray-800 border border-gray-700">
        {results.length === 0 ? (
          <Typography variant="body2" className="text-gray-400 p-4">
            Click a button to test network connectivity.
          </Typography>
        ) : (
          <Table size="small">
            <TableBody>
              {results.map((result, index) => (
                <TableRow key={index}>
                  <TableCell className="text-gray-300">{result.name}</TableCell>
                  <TableCell>
                    <span
                      className={
                        result.status === 'success'
                          ? 'text-green-400'
                          : result.status === 'error'
                            ? 'text-red-400'
                            : 'text-yellow-400'
                      }
                    >
                      {result.status === 'success' ? '✓' : result.status === 'error' ? '✗' : '...'}
                    </span>
                  </TableCell>
                  <TableCell className="text-gray-400">{result.message}</TableCell>
                  <TableCell className="text-gray-400">
                    {result.latency ? `${result.latency}ms` : '-'}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Paper>
    </Box>
  );
}
