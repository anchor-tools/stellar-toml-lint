import { useCallback, useState } from 'react';
import {
  Box,
  Button,
  Chip,
  CircularProgress,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from '@mui/material';
import type { BatchSummary } from 'stellar-toml-lint/browser';
import { validateZip } from 'stellar-toml-lint/browser';

export default function BatchValidator(): JSX.Element {
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [summary, setSummary] = useState<BatchSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleFileChange = useCallback(async (event: React.ChangeEvent<HTMLInputElement>) => {
    const selected = event.target.files?.[0] ?? null;
    setFile(selected);
    setError(null);
    setSummary(null);
    if (!selected) return;

    setLoading(true);
    try {
      const buffer = await readArrayBuffer(selected);
      const result = await validateZip(buffer, { concurrency: 4 });
      setSummary(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  const handleReset = useCallback(() => {
    setFile(null);
    setError(null);
    setSummary(null);
  }, []);

  if (error) {
    return (
      <Box component="section" className="p-4">
        <Paper className="p-4">
          <Typography color="error" variant="body2">
            Failed to validate archive: {error}
          </Typography>
          <Button variant="outlined" onClick={handleReset} size="small">
            Try another archive
          </Button>
        </Paper>
      </Box>
    );
  }

  if (loading) {
    return (
      <Box component="section" className="p-4">
        <Paper className="p-4 flex flex-col items-center justify-center">
          <CircularProgress size={40} />
          <Typography variant="body2" className="mt-2 text-gray-400">
            Validating archive…
          </Typography>
        </Paper>
      </Box>
    );
  }

  return (
    <Box component="section" className="p-4">
      <Paper className="p-4">
        <Typography variant="h6" className="mb-4">
          Batch Validator
        </Typography>

        <Box className="mb-4">
          <label className="block text-sm text-gray-400 mb-2">
            Drag and drop a ZIP of stellar.toml files, or click to select
          </label>
          <input
            accept=".zip"
            className="block w-full text-sm text-gray-300 file:mr-4 file:py-2 file:px-4 file:rounded file:border-0 file:text-sm file:font-semibold file:bg-blue-500 file:text-white hover:file:bg-blue-600"
            id="zip-file"
            onChange={handleFileChange}
            type="file"
          />
          {file && (
            <Typography variant="caption" className="mt-1 text-gray-500">
              {file.name} ({(file.size / 1024).toFixed(1)} KB)
            </Typography>
          )}
        </Box>

        <Button disabled={loading || !file} onClick={handleReset} variant="outlined" size="small">
          Reset
        </Button>

        {summary !== null && (
          <Box className="mt-6">
            <Typography variant="subtitle2" className="mb-2 text-gray-400">
              Results
            </Typography>
            <TableContainer component={Paper} className="bg-gray-800 border border-gray-700">
              <Table size="small">
                <TableHead>
                  <TableRow className="bg-gray-800">
                    <TableCell className="text-gray-400">Files</TableCell>
                    <TableCell className="text-gray-400">Passed</TableCell>
                    <TableCell className="text-gray-400">Failed</TableCell>
                    <TableCell className="text-gray-400">Pass Rate</TableCell>
                    <TableCell className="text-gray-400">Errors</TableCell>
                    <TableCell className="text-gray-400">Warnings</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  <TableRow>
                    <TableCell className="text-gray-200">{summary.totalFiles}</TableCell>
                    <TableCell className="text-green-400">{summary.passed}</TableCell>
                    <TableCell className="text-red-400">{summary.failed}</TableCell>
                    <TableCell className="text-gray-200">{summary.passRate}%</TableCell>
                    <TableCell className="text-gray-200">{summary.totalErrors}</TableCell>
                    <TableCell className="text-gray-200">{summary.totalWarnings}</TableCell>
                  </TableRow>
                </TableBody>
              </Table>
            </TableContainer>

            {summary.commonErrors.length > 0 && (
              <Box className="mt-4">
                <Typography variant="subtitle2" className="mb-2 text-gray-400">
                  Common error patterns
                </Typography>
                <TableContainer component={Paper} className="bg-gray-800 border border-gray-700">
                  <Table size="small">
                    <TableHead>
                      <TableRow className="bg-gray-800">
                        <TableCell className="text-gray-400">Rule</TableCell>
                        <TableCell className="text-gray-400">Occurrences</TableCell>
                        <TableCell className="text-gray-400">Files affected</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {summary.commonErrors.map((entry) => (
                        <TableRow key={entry.rule} hover>
                          <TableCell>
                            <Typography variant="body2" className="text-gray-300">
                              {entry.rule}
                            </Typography>
                          </TableCell>
                          <TableCell className="text-gray-200">{entry.count}</TableCell>
                          <TableCell className="text-gray-400">{entry.files.length}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Box>
            )}

            <Box className="mt-4">
              <Typography variant="subtitle2" className="mb-2 text-gray-400">
                Per-file results
              </Typography>
              <TableContainer component={Paper} className="bg-gray-800 border border-gray-700">
                <Table size="small">
                  <TableHead>
                    <TableRow className="bg-gray-800">
                      <TableCell className="text-gray-400">File</TableCell>
                      <TableCell className="text-gray-400">Status</TableCell>
                      <TableCell className="text-gray-400">Errors</TableCell>
                      <TableCell className="text-gray-400">Warnings</TableCell>
                      <TableCell className="text-gray-400">Infos</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {summary.results.map((entry) => (
                      <TableRow key={entry.path} hover>
                        <TableCell>
                          <Typography variant="body2" className="text-gray-300 truncate">
                            {entry.name}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={entry.result.ok ? 'Pass' : 'Fail'}
                            color={entry.result.ok ? 'success' : 'error'}
                            size="small"
                            variant="outlined"
                          />
                        </TableCell>
                        <TableCell className="text-gray-200">
                          {entry.result.counts['error']}
                        </TableCell>
                        <TableCell className="text-gray-200">
                          {entry.result.counts['warning']}
                        </TableCell>
                        <TableCell className="text-gray-200">
                          {entry.result.counts['info']}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>
          </Box>
        )}
      </Paper>
    </Box>
  );
}

function readArrayBuffer(file: File): Promise<ArrayBuffer> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result as ArrayBuffer);
    reader.onerror = () => reject(reader.error ?? new Error('Failed to read archive'));
    reader.readAsArrayBuffer(file);
  });
}
