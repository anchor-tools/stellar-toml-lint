import { useState } from 'react';
import {
  Button,
  Paper,
  Typography,
  List,
  ListItem,
  ListItemText,
  Chip,
  Box,
  Icon,
} from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import WrenchIcon from '@mui/icons-material/Build';
import WarningIcon from '@mui/icons-material/Warning';

interface FixAction {
  rule: string;
  severity: string;
  message: string;
  suggestion: string;
  applied: boolean;
}

const sampleFixes: FixAction[] = [
  {
    rule: 'currencies/issuance-exclusive',
    severity: 'error',
    message: 'CURRENCIES[0] sets fixed_number and is_unlimited',
    suggestion: 'Remove is_unlimited or fixed_number to satisfy exactly-one issuance policy',
    applied: false,
  },
  {
    rule: 'network/passphrase',
    severity: 'error',
    message: 'NETWORK_PASSPHRASE has stray whitespace',
    suggestion: 'Replace with exactly: Public Global Stellar Network ; September 2015',
    applied: false,
  },
  {
    rule: 'documentation/phone-e164',
    severity: 'warning',
    message: 'ORG_PHONE_NUMBER is not in E.164 format',
    suggestion: 'Use leading + and digits only, e.g. "+14155552671"',
    applied: false,
  },
];

export default function FixActions() {
  const [fixes, setFixes] = useState<FixAction[]>(sampleFixes);
  const [applying, setApplying] = useState(false);

  const applyAutofix = () => {
    setApplying(true);
    setTimeout(() => {
      setFixes(fixes.map((f) => ({ ...f, applied: true })));
      setApplying(false);
    }, 500);
  };

  return (
    <Box className="w-full">
      <Typography variant="h6" className="text-white mb-4">
        Fix Actions
      </Typography>
      <Paper className="bg-gray-800 border border-gray-700 p-4 mb-4">
        <Typography variant="body2" className="text-gray-400 mb-3">
          The following fixes can be applied automatically:
        </Typography>
        <List>
          {fixes.map((fix, index) => (
            <ListItem key={index} className="px-0" divider>
              <ListItemText
                primary={
                  <Box className="flex items-center gap-2">
                    <Typography variant="body2" className="text-gray-200">
                      {fix.suggestion}
                    </Typography>
                    <Chip
                      label={fix.severity}
                      size="small"
                      color={fix.severity === 'error' ? 'error' : 'warning'}
                      variant="outlined"
                    />
                  </Box>
                }
                secondary={
                  <Typography variant="caption" className="text-gray-500">
                    {fix.rule}
                  </Typography>
                }
              />
              {fix.applied ? (
                <Icon className="text-green-500">
                  <CheckCircleIcon />
                </Icon>
              ) : (
                <Icon className="text-gray-500">
                  <WarningIcon />
                </Icon>
              )}
            </ListItem>
          ))}
        </List>
      </Paper>
      <Button
        variant="contained"
        color="primary"
        onClick={applyAutofix}
        disabled={applying || fixes.every((f) => f.applied)}
        startIcon={<WrenchIcon />}
        className="bg-blue-600 hover:bg-blue-700"
      >
        {applying
          ? 'Applying...'
          : fixes.every((f) => f.applied)
            ? 'All Fixes Applied'
            : 'Apply Autofix'}
      </Button>
    </Box>
  );
}
