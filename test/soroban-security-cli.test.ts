import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { Account, Address, Operation, TransactionBuilder, xdr } from '@stellar/stellar-base';
import { OP, buildWasm, funcType, u32 } from './fixtures/wasm-build.js';

const run = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, '..', 'dist', 'cli.js');
const NETWORK = 'Test SDF Network ; September 2015';
const CONTRACT = 'CABQ4GJEF45EKUC3MZYXZB4STWULHPWJ2TP6V5IABMLCCLBXIJGVQKFK';
const SIGNING_KEY = 'GDVEU3DD4KOFECV66VIHWEZOYX4ZKR3WV27L464SIIPOU2IUI3JCZA57';

let directory: string;

async function cli(args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  try {
    const { stdout, stderr } = await run('node', [CLI, ...args], {
      env: { ...process.env, NO_COLOR: '1' },
      maxBuffer: 8 * 1024 * 1024,
    });
    return { code: 0, stdout, stderr };
  } catch (error) {
    const e = error as { code?: number; stdout?: string; stderr?: string };
    return { code: e.code ?? 1, stdout: e.stdout ?? '', stderr: e.stderr ?? '' };
  }
}

/** A module with two mutually recursive functions. */
function recursiveWasm(): Uint8Array {
  return buildWasm({
    types: [funcType([], [])],
    memoryPages: 1,
    memoryMaxPages: 4,
    functions: [
      { type: 0, code: [OP.CALL, ...u32(1)] },
      { type: 0, code: [OP.CALL, ...u32(0)] },
    ],
    exports: [
      { name: 'f0', kind: 0x00, index: 0 },
      { name: 'f1', kind: 0x00, index: 1 },
    ],
  });
}

/** A module that verifies ed25519 signatures with no replay protection. */
function insecureSignatureWasm(): Uint8Array {
  return buildWasm({
    types: [funcType([], [])],
    imports: [{ module: 'env', name: 'ed25519_verify', type: 0 }],
    functions: [{ type: 0, code: [OP.CALL, ...u32(0)] }],
    exports: [{ name: 'verify', kind: 0x00, index: 1 }],
    functionNames: ['verify'],
  });
}

function authEntry(nonce: string): xdr.SorobanAuthorizationEntry {
  return new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(
      new xdr.SorobanAddressCredentials({
        address: new Address(SIGNING_KEY).toScAddress(),
        nonce: xdr.Int64.fromString(nonce),
        signatureExpirationLedger: 1000,
        signature: xdr.ScVal.scvVec([xdr.ScVal.scvBytes(Buffer.alloc(64, 1))]),
      }),
    ),
    rootInvocation: new xdr.SorobanAuthorizedInvocation({
      function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
        new xdr.InvokeContractArgs({
          contractAddress: new Address(CONTRACT).toScAddress(),
          functionName: 'mint',
          args: [],
        }),
      ),
      subInvocations: [],
    }),
  });
}

function envelope(entry: xdr.SorobanAuthorizationEntry): string {
  const hostFunction = xdr.HostFunction.hostFunctionTypeInvokeContract(
    new xdr.InvokeContractArgs({
      contractAddress: new Address(CONTRACT).toScAddress(),
      functionName: 'mint',
      args: [],
    }),
  );
  return new TransactionBuilder(new Account(SIGNING_KEY, '0'), {
    fee: '100',
    networkPassphrase: NETWORK,
  })
    .addOperation(Operation.invokeHostFunction({ func: hostFunction, auth: [entry] }))
    .setTimeout(30)
    .build()
    .toEnvelope()
    .toXDR('base64');
}

describe('soroban security audit CLI commands', () => {
  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), 'soroban-audit-'));
    await writeFile(join(directory, 'recursive.wasm'), recursiveWasm());
    await writeFile(join(directory, 'signature.wasm'), insecureSignatureWasm());
  });

  afterAll(async () => {
    await rm(directory, { recursive: true, force: true });
  });

  it('audit-wasm-memory exits 1 on a recursive contract', async () => {
    const { code, stdout } = await cli([
      'audit-wasm-memory',
      '--file',
      join(directory, 'recursive.wasm'),
    ]);
    expect(code).toBe(1);
    expect(stdout).toContain('WASM memory audit');
    expect(stdout).toContain('soroban/wasm-recursive-call');
  });

  it('audit-wasm-memory emits machine-readable JSON', async () => {
    const { code, stdout } = await cli([
      'audit-wasm-memory',
      '--file',
      join(directory, 'recursive.wasm'),
      '--format',
      'json',
    ]);
    expect(code).toBe(1);
    const report = JSON.parse(stdout) as { valid: boolean; recursion: unknown[] };
    expect(report.valid).toBe(true);
    expect(report.recursion).toHaveLength(1);
  });

  it('audit-wasm-memory exits 2 without a file', async () => {
    const { code, stderr } = await cli(['audit-wasm-memory']);
    expect(code).toBe(2);
    expect(stderr).toContain('Usage: stellar-toml-lint audit-wasm-memory');
  });

  it('auth-tree renders the authorization hierarchy', async () => {
    const { code, stdout } = await cli([
      'auth-tree',
      '--xdr',
      envelope(authEntry('7')),
      '--latest-ledger',
      '900',
    ]);
    expect(code).toBe(0);
    expect(stdout).toContain('Auth tree: 1 entry');
    expect(stdout).toContain(CONTRACT);
    expect(stdout).toContain('nonce 7');
  });

  it('auth-tree exits 1 on a zero nonce', async () => {
    const { code, stdout } = await cli([
      'auth-tree',
      '--xdr',
      envelope(authEntry('0')),
      '--latest-ledger',
      '900',
    ]);
    expect(code).toBe(1);
    expect(stdout).toContain('soroban/auth-entry-nonce-reused');
  });

  it('auth-tree rejects a value that is not an envelope', async () => {
    const { code, stdout } = await cli(['auth-tree', '--xdr', 'nope']);
    expect(code).toBe(1);
    expect(stdout).toContain('INVALID');
  });

  it('audit-signature-replay exits 1 for ed25519 verification without a nonce', async () => {
    const { code, stdout } = await cli([
      'audit-signature-replay',
      '--file',
      join(directory, 'signature.wasm'),
    ]);
    expect(code).toBe(1);
    expect(stdout).toContain('soroban/signature-verification-without-nonce');
    expect(stdout).toContain('soroban/signature-verification-without-domain-separation');
  });

  it('--audit-signature-replay is the flag form of the same command', async () => {
    const { code, stdout } = await cli([
      '--audit-signature-replay',
      '--file',
      join(directory, 'signature.wasm'),
    ]);
    expect(code).toBe(1);
    expect(stdout).toContain('Signature replay audit');
  });

  it('lists the new rules for --list-rules', async () => {
    const { stdout } = await cli(['--list-rules']);
    expect(stdout).toContain('soroban/wasm-recursive-call');
    expect(stdout).toContain('soroban/auth-entry-nonce-reused');
    expect(stdout).toContain('soroban/signature-verification-without-nonce');
  });
});
