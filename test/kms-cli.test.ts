import { afterEach, describe, expect, it } from 'vitest';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import {
  Account,
  Asset,
  Keypair,
  Networks,
  Operation,
  TransactionBuilder,
} from '@stellar/stellar-base';

const run = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, '..', 'dist', 'cli.js');

async function cli(
  args: string[],
  env: NodeJS.ProcessEnv = {},
): Promise<{ code: number; stdout: string; stderr: string }> {
  try {
    const { stdout, stderr } = await run('node', [CLI, ...args], {
      env: { ...process.env, NO_COLOR: '1', ...env },
      maxBuffer: 4 * 1024 * 1024,
    });
    return { code: 0, stdout, stderr };
  } catch (error) {
    const failure = error as { code?: number; stdout?: string; stderr?: string };
    return {
      code: failure.code ?? 1,
      stdout: failure.stdout ?? '',
      stderr: failure.stderr ?? '',
    };
  }
}

function envelope(): string {
  const account = new Account(Keypair.random().publicKey(), '1');
  return new TransactionBuilder(account, {
    fee: '100',
    networkPassphrase: Networks.TESTNET,
  })
    .addOperation(
      Operation.payment({
        destination: Keypair.random().publicKey(),
        asset: Asset.native(),
        amount: '1',
      }),
    )
    .setTimeout(30)
    .build()
    .toXDR();
}

async function readBody(request: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString('utf8');
}

function send(response: ServerResponse, body: unknown, status = 200): void {
  response.writeHead(status, { 'content-type': 'application/json' });
  response.end(JSON.stringify(body));
}

const servers: ReturnType<typeof createServer>[] = [];

afterEach(() => {
  for (const server of servers.splice(0)) server.close();
});

describe('test-kms-signer command', () => {
  it('documents the subcommand in --help', async () => {
    const { code, stdout } = await cli(['test-kms-signer', '--help']);
    expect(code).toBe(0);
    expect(stdout).toContain('test-kms-signer');
    expect(stdout).toContain('--key-id');
    expect(stdout).toContain('--envelope');
    expect(stdout).toContain('--no-quorum');
  }, 20000);

  it('exits 2 without the required arguments', async () => {
    const { code, stderr } = await cli(['test-kms-signer']);
    expect(code).toBe(2);
    expect(stderr).toContain('requires --key-id <arn> and --envelope <xdr>');
  }, 20000);

  it('exits 2 for an unrecognised key identifier', async () => {
    const { code, stderr } = await cli([
      'test-kms-signer',
      '--key-id',
      'not-a-cloud-key',
      '--envelope',
      envelope(),
      '--no-quorum',
    ]);
    expect(code).toBe(2);
    expect(stderr).toContain('Unrecognised KMS key identifier');
  }, 20000);

  it('signs through a mock AWS KMS endpoint and verifies the envelope', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const publicKeyDer = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
    const keyArn = 'arn:aws:kms:us-east-1:111122223333:key/mock-signer';

    const server = createServer((request, response) => {
      void (async () => {
        const body = JSON.parse(await readBody(request)) as Record<string, unknown>;
        const target = String(request.headers['x-amz-target'] ?? '');
        if (target.endsWith('DescribeKey')) {
          send(response, {
            KeyMetadata: {
              KeyId: 'mock-signer',
              Arn: keyArn,
              KeyUsage: 'SIGN_VERIFY',
              KeyState: 'Enabled',
              KeySpec: 'ECC_NIST_ED25519',
              SigningAlgorithms: ['ECC_NIST_ED25519'],
            },
          });
          return;
        }
        if (target.endsWith('GetPublicKey')) {
          send(response, { PublicKey: publicKeyDer });
          return;
        }
        if (target.endsWith('Sign')) {
          const message = Buffer.from(String(body.Message), 'base64');
          send(response, {
            KeyId: keyArn,
            SigningAlgorithm: 'ECC_NIST_ED25519',
            Signature: cryptoSign(null, message, privateKey).toString('base64'),
          });
          return;
        }
        send(response, { __type: 'InvalidActionException', message: target }, 400);
      })();
    });
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    if (address === null || typeof address === 'string') throw new Error('no server address');

    const { code, stdout, stderr } = await cli(
      [
        'test-kms-signer',
        '--key-id',
        keyArn,
        '--envelope',
        envelope(),
        '--network',
        Networks.TESTNET,
        '--no-quorum',
      ],
      {
        AWS_ACCESS_KEY_ID: 'AKIAMOCK',
        AWS_SECRET_ACCESS_KEY: 'mock-secret',
        AWS_REGION: 'us-east-1',
        AWS_ENDPOINT_URL_KMS: `http://127.0.0.1:${address.port}`,
      },
    );

    expect(stderr).toBe('');
    expect(code).toBe(0);
    expect(stdout).toContain('Cloud KMS signer check — AWS KMS');
    expect(stdout).toContain('verified');
    expect(stdout).toContain('Result: PASS');
    expect(stdout).not.toContain('mock-secret');
  }, 20000);
});
