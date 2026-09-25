import { useState } from 'react';
import {
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  Typography,
} from '@mui/material';
import type { Diagnostic } from '../types';

interface DiagnosticsProps {
  diagnostics: Diagnostic[];
}

export default function Diagnostics({ diagnostics }: DiagnosticsProps) {
  const [selectedRow, setSelectedRow] = useState<number | null>(null);

  if (diagnostics.length === 0) {
    return (
      <Typography variant="body1" className="text-gray-400">
        No diagnostics. Start typing in the editor to lint.
      </Typography>
    );
  }

  const severityColor = (severity: string) => {
    switch (severity) {
      case 'error':
        return 'error';
      case 'warning':
        return 'warning';
      case 'info':
        return 'info';
      default:
        return 'default';
    }
  };

  return (
    <TableContainer component={Paper} className="bg-gray-800 border border-gray-700">
      <Table size="small">
        <TableHead>
          <TableRow className="bg-gray-800">
            <TableCell className="text-gray-400">Severity</TableCell>
            <TableCell className="text-gray-400">Rule</TableCell>
            <TableCell className="text-gray-400">Message</TableCell>
            <TableCell className="text-gray-400">Line</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {diagnostics.map((diag, index) => (
            <TableRow
              key={index}
              hover
              selected={selectedRow === index}
              onClick={() => setSelectedRow(selectedRow === index ? null : index)}
              className="cursor-pointer hover:bg-gray-800/80"
            >
              <TableCell>
                <Chip
                  label={diag.severity}
                  color={severityColor(diag.severity)}
                  size="small"
                  variant="outlined"
                />
              </TableCell>
              <TableCell>
                <Typography variant="body2" className="text-gray-300">
                  {diag.rule}
                </Typography>
              </TableCell>
              <TableCell>
                <Typography variant="body2" className="text-gray-200">
                  {diag.message}
                </Typography>
              </TableCell>
              <TableCell>
                <Typography variant="body2" className="text-gray-400">
                  {diag.position?.line}
                </Typography>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );
}
