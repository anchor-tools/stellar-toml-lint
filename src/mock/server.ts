/**
 * A local mock anchor, built from a `stellar.toml` on disk.
 *
 * Wallet and frontend developers need something that answers like an anchor
 * before one is deployed. This serves the file itself plus SEP-10, SEP-24, and
 * SEP-38 discovery endpoints generated from its contents, on nothing but
 * `node:http`, so the linter's dependency tree does not grow a web framework.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { StrKey } from '@stellar/stellar-base';
import { isString } from '../predicates.js';
import { mockAssetsOf } from './assets.js';
import { buildChallenge, resolveSep10Signer, type Sep10Signer } from './sep10.js';
import { sep24Info } from './sep24.js';
import { sep38Info, sep38Prices } from './sep38.js';

export const DEFAULT_MOCK_PORT = 8080;

export interface MockServerOptions {
  /** The raw file, served byte for byte at `/.well-known/stellar.toml`. */
  source: string;
  /** The parsed file the generated endpoints are built from. */
  doc: Record<string, unknown>;
  /** The secret for `SIGNING_KEY`, so challenges verify against the published key. */
  signingSecret?: string;
}

export interface MockRoute {
  method: 'GET';
  path: string;
  description: string;
}

export const MOCK_ROUTES: readonly MockRoute[] = [
  { method: 'GET', path: '/.well-known/stellar.toml', description: 'The linted stellar.toml' },
  { method: 'GET', path: '/auth', description: 'SEP-10 challenge transaction (?account=G...)' },
  { method: 'GET', path: '/sep24/info', description: 'SEP-24 assets from [[CURRENCIES]]' },
  { method: 'GET', path: '/sep38/info', description: 'SEP-38 assets from [[CURRENCIES]]' },
  { method: 'GET', path: '/sep38/prices', description: 'SEP-38 indicative prices' },
];

export interface MockServer {
  server: Server;
  signer: Sep10Signer;
}

const CORS_HEADERS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, OPTIONS',
  'access-control-allow-headers': '*',
};

function send(
  res: ServerResponse,
  status: number,
  body: string,
  contentType = 'application/json; charset=utf-8',
): void {
  res.writeHead(status, { ...CORS_HEADERS, 'content-type': contentType });
  res.end(body);
}

const json = (res: ServerResponse, status: number, body: unknown): void =>
  send(res, status, `${JSON.stringify(body, null, 2)}\n`);

/** The request's host without the port, the domain SEP-10 names in `web_auth_domain`. */
function hostOf(req: IncomingMessage): string {
  return (req.headers.host ?? 'localhost').replace(/:\d+$/, '');
}

/** Builds the mock server without listening, so callers choose the port. */
export function createMockServer(options: MockServerOptions): MockServer {
  const { source, doc } = options;
  const assets = mockAssetsOf(doc);
  const signer = resolveSep10Signer(doc.SIGNING_KEY, options.signingSecret);
  const networkPassphrase = isString(doc.NETWORK_PASSPHRASE) ? doc.NETWORK_PASSPHRASE : undefined;

  const server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost');

    if (req.method === 'OPTIONS') {
      res.writeHead(204, CORS_HEADERS);
      res.end();
      return;
    }
    if (req.method !== 'GET') {
      json(res, 405, { error: `${req.method} is not supported by the mock server` });
      return;
    }

    switch (url.pathname) {
      case '/.well-known/stellar.toml':
        send(res, 200, source, 'text/plain; charset=utf-8');
        return;

      case '/auth': {
        const account = url.searchParams.get('account');
        if (account === null || !StrKey.isValidEd25519PublicKey(account)) {
          json(res, 400, { error: 'account must be a valid Stellar account ID (G...)' });
          return;
        }
        const host = hostOf(req);
        json(
          res,
          200,
          buildChallenge(signer.keypair, {
            account,
            homeDomain: url.searchParams.get('home_domain') ?? host,
            webAuthDomain: host,
            ...(networkPassphrase !== undefined ? { networkPassphrase } : {}),
          }),
        );
        return;
      }

      case '/sep24/info':
        json(res, 200, sep24Info(assets));
        return;

      case '/sep38/info':
        json(res, 200, sep38Info(assets));
        return;

      case '/sep38/prices': {
        const result = sep38Prices(assets, url.searchParams);
        json(res, result.status, result.body);
        return;
      }

      default:
        json(res, 404, { error: `No mock endpoint at ${url.pathname}` });
    }
  });

  return { server, signer };
}

/** The boot banner: every route, and whether challenges verify against `SIGNING_KEY`. */
export function formatRoutingTable(baseUrl: string, signer: Sep10Signer): string {
  const width = Math.max(...MOCK_ROUTES.map((route) => (baseUrl + route.path).length));
  const lines = [
    `stellar-toml-lint mock server listening on ${baseUrl}`,
    '',
    ...MOCK_ROUTES.map(
      (route) => `  ${route.method}  ${(baseUrl + route.path).padEnd(width)}  ${route.description}`,
    ),
    '',
  ];
  if (signer.matchesSigningKey) {
    lines.push(`SEP-10 challenges are signed by SIGNING_KEY ${signer.keypair.publicKey()}.`);
  } else {
    lines.push(
      `SEP-10 challenges are signed by an ephemeral key ${signer.keypair.publicKey()},`,
      'not SIGNING_KEY. Set STELLAR_TOML_MOCK_SIGNING_SECRET to its secret to sign with it.',
    );
  }
  lines.push('Press Ctrl+C to stop.', '');
  return lines.join('\n');
}
