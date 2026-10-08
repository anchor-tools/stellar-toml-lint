import { lint } from './lint.js';
import { getHoverInfo } from './lsp/hover.js';

interface LspMessage {
  jsonrpc: string;
  method?: string;
  params?: Record<string, unknown>;
  id?: number | string;
  result?: unknown;
  error?: { code: number; message: string };
}

interface Position {
  line: number;
  character: number;
}

interface Range {
  start: Position;
  end: Position;
}

interface DiagnosticPayload {
  range: Range;
  severity: number;
  code: string;
  message: string;
  source: string;
}

const SEVERITY_MAP = { error: 1, warning: 2, info: 3 };

let documentUri = '';
let documentSource = '';

export function lspMain(): void {
  process.stdin.on('data', (chunk) => {
    const data = chunk.toString();
    for (const line of data.split('\n')) {
      if (line.trim() === '') continue;
      try {
        const msg: LspMessage = JSON.parse(line);
        handleMessage(msg).then((response) => {
          if (response) {
            const payload = JSON.stringify(response);
            process.stdout.write(`Content-Length: ${payload.length}\r\n\r\n${payload}`);
          }
        });
      } catch {
        // skip non-JSON lines
      }
    }
  });
}

async function handleMessage(msg: LspMessage): Promise<LspMessage | null> {
  switch (msg.method) {
    case 'initialize': {
      return {
        jsonrpc: '2.0',
        id: msg.id,
        result: {
          capabilities: {
            textDocumentSync: {
              openClose: true,
              change: 2,
            },
            diagnosticProvider: {
              interFileDependencies: false,
              workspaceDiagnostics: false,
            },
            completionProvider: {
              resolveProvider: false,
              triggerCharacters: ['.', '-'],
            },
            hoverProvider: true,
          },
        },
      };
    }
    case 'initialized': {
      return null;
    }
    case 'textDocument/didOpen': {
      const params = msg.params as { textDocument: { uri: string; text: string } };
      documentUri = params.textDocument.uri;
      documentSource = params.textDocument.text;
      return await sendDiagnostics();
    }
    case 'textDocument/didChange': {
      const params = msg.params as { contentChanges?: { text: string }[] };
      documentSource = params.contentChanges?.[0]?.text ?? '';
      return await sendDiagnostics();
    }
    case 'textDocument/completion': {
      const params = msg.params as {
        textDocument: { uri: string };
        position: Position;
        context?: unknown;
      };
      return {
        jsonrpc: '2.0',
        id: msg.id,
        result: {
          isIncomplete: false,
          items: getCompletions(documentSource, params.position),
        },
      };
    }
    case 'textDocument/hover': {
      const params = msg.params as {
        textDocument: { uri: string };
        position: Position;
      };
      return {
        jsonrpc: '2.0',
        id: msg.id,
        result: getHoverInfo(documentSource, params.position),
      };
    }
    default:
      return null;
  }
}

async function sendDiagnostics(): Promise<LspMessage | null> {
  const diagnostics = lint(documentSource, {});
  const params = {
    uri: documentUri,
    diagnostics: diagnostics.diagnostics.map((d) => ({
      range: positionToRange(d.position),
      severity: SEVERITY_MAP[d.severity],
      code: d.rule,
      message: d.message,
      source: 'stellar-toml-lint',
    })),
  } as { uri: string; diagnostics: DiagnosticPayload[] };

  return {
    jsonrpc: '2.0',
    method: 'textDocument/publishDiagnostics',
    params,
  };
}

function positionToRange(pos?: { line: number; column: number }): Range {
  if (!pos) {
    return { start: { line: 0, character: 0 }, end: { line: 0, character: 0 } };
  }
  return {
    start: { line: pos.line - 1, character: pos.column - 1 },
    end: { line: pos.line - 1, character: pos.column - 1 },
  };
}

function getCompletions(
  _source: string,
  _position: Position,
): Array<{
  label: string;
  kind: number;
  detail: string;
}> {
  const topKeys = [
    'VERSION',
    'NETWORK_PASSPHRASE',
    'DOMAIN',
    'SIGNING_KEY',
    'CURRENCIES',
    'VALIDATORS',
    'DOCUMENTATION',
    'PRINCIPALS',
    'ORG_NAME',
    'ORG_URL',
    'ORG_EMAIL',
    'ORG_GITHUB',
    'TRANSFER_SERVER',
    'WEB_AUTH_ENDPOINT',
    'KYC_SERVER',
    'HORIZON_URL',
    'ANCHOR_QUOTE_SERVER',
  ];
  return topKeys.map((key) => ({
    label: key,
    kind: 6,
    detail: 'stellar.toml',
  }));
}
