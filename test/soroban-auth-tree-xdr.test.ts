import { describe, expect, it } from 'vitest';
import {
  Account,
  Address,
  Asset,
  Operation,
  StrKey,
  type Transaction,
  TransactionBuilder,
  xdr,
} from '@stellar/stellar-base';
import {
  AUTH_EXPIRATION_UNBOUNDED_RULE,
  AUTH_NONCE_REUSED_RULE,
  AUTH_CREDENTIAL_UNBOUND_RULE,
  AUTH_SIGNATURE_EXPIRED_RULE,
  AUTH_SIGNATURE_MISSING_RULE,
  AuthTreeSimulator,
  DEFAULT_MAX_AUTH_LIFETIME_LEDGERS,
  authTreeRuleIds,
  renderAuthTreeDiagram,
  renderAuthTreeReport,
} from '../src/soroban/authTreeSimulator.js';
import { UNAUTHORIZED_CROSS_CONTRACT_RULE } from '../src/soroban/auth-tree-simulator.js';

const CONTRACT = 'CABQ4GJEF45EKUC3MZYXZB4STWULHPWJ2TP6V5IABMLCCLBXIJGVQKFK';
const OTHER_CONTRACT = 'CAUDGPSJKRPWU5MAROLKDLFXYLG5RY7O7ECA6GRFGA5UMUK4M5ZH2B33';
const SIGNING_KEY = 'GDVEU3DD4KOFECV66VIHWEZOYX4ZKR3WV27L464SIIPOU2IUI3JCZA57';
const NETWORK = 'Test SDF Network ; September 2015';

function contractFn(
  contract: string,
  fn: string,
  args: xdr.ScVal[] = [],
): xdr.SorobanAuthorizedFunction {
  return xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
    new xdr.InvokeContractArgs({
      contractAddress: new Address(contract).toScAddress(),
      functionName: fn,
      args,
    }),
  );
}

function invocation(
  fn: xdr.SorobanAuthorizedFunction,
  children: xdr.SorobanAuthorizedInvocation[] = [],
): xdr.SorobanAuthorizedInvocation {
  return new xdr.SorobanAuthorizedInvocation({ function: fn, subInvocations: children });
}

function authBoundary(contract: string, address?: string): xdr.SorobanAuthorizedInvocation {
  const args: xdr.ScVal[] = [xdr.ScVal.scvVec([])];
  if (address !== undefined) args.unshift(new Address(address).toScVal());
  return invocation(contractFn(contract, '__require_auth', args));
}

function entry(
  options: {
    nonce?: string;
    expiration?: number;
    signed?: boolean;
    address?: string;
    children?: xdr.SorobanAuthorizedInvocation[];
  } = {},
): xdr.SorobanAuthorizationEntry {
  const signature =
    options.signed === false
      ? xdr.ScVal.scvVoid()
      : xdr.ScVal.scvVec([xdr.ScVal.scvBytes(Buffer.alloc(64, 1))]);
  return new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(
      new xdr.SorobanAddressCredentials({
        address: new Address(options.address ?? SIGNING_KEY).toScAddress(),
        nonce: xdr.Int64.fromString(options.nonce ?? '7'),
        signatureExpirationLedger: options.expiration ?? 1000,
        signature,
      }),
    ),
    rootInvocation: invocation(
      contractFn(CONTRACT, 'mint', [new Address(SIGNING_KEY).toScVal()]),
      options.children ?? [authBoundary(CONTRACT, SIGNING_KEY)],
    ),
  });
}

function envelope(entries: xdr.SorobanAuthorizationEntry[]): string {
  const hostFunction = xdr.HostFunction.hostFunctionTypeInvokeContract(
    new xdr.InvokeContractArgs({
      contractAddress: new Address(CONTRACT).toScAddress(),
      functionName: 'mint',
      args: [new Address(SIGNING_KEY).toScVal()],
    }),
  );
  return new TransactionBuilder(new Account(SIGNING_KEY, '0'), {
    fee: '100',
    networkPassphrase: NETWORK,
  })
    .addOperation(Operation.invokeHostFunction({ func: hostFunction, auth: entries }))
    .setTimeout(30)
    .build()
    .toEnvelope()
    .toXDR('base64');
}

describe('soroban XDR authorization tree simulator', () => {
  it('parses every invoke operation and its auth entries', () => {
    const simulator = new AuthTreeSimulator();
    const parsed = simulator.parseEnvelope(envelope([entry()]));
    expect(parsed?.operations).toHaveLength(1);
    expect(parsed?.operations[0]?.contract).toBe(CONTRACT);
    expect(parsed?.operations[0]?.function).toBe('mint');
    expect(parsed?.operations[0]?.auth).toHaveLength(1);
    expect(parsed?.entries[0]).toMatchObject({
      credentialAddress: SIGNING_KEY,
      credentialNonce: '7',
      signatureExpirationLedger: 1000,
      hasSignature: true,
    });
  });

  it('accepts a fully bound, signed, unexpired entry', async () => {
    const report = await new AuthTreeSimulator({ latestLedger: 900 }).simulate(envelope([entry()]));
    expect(report.valid).toBe(true);
    expect(report.ok).toBe(true);
    expect(report.findings).toEqual([]);
    expect(report.diagram).toContain('require_auth(');
    expect(report.diagram).toContain(SIGNING_KEY);
  });

  it('flags a zero nonce as replayable', async () => {
    const report = await new AuthTreeSimulator({ latestLedger: 900 }).simulate(
      envelope([entry({ nonce: '0' })]),
    );
    expect(report.findings).toContainEqual(
      expect.objectContaining({ rule: AUTH_NONCE_REUSED_RULE, severity: 'error' }),
    );
    expect(report.ok).toBe(false);
  });

  it('flags an already expired signature', async () => {
    const report = await new AuthTreeSimulator({ latestLedger: 1000 }).simulate(
      envelope([entry({ expiration: 1000 })]),
    );
    expect(report.findings).toContainEqual(
      expect.objectContaining({ rule: AUTH_SIGNATURE_EXPIRED_RULE, severity: 'error' }),
    );
  });

  it('flags an expiration far beyond the current ledger', async () => {
    const report = await new AuthTreeSimulator({ latestLedger: 100 }).simulate(
      envelope([entry({ expiration: 100 + DEFAULT_MAX_AUTH_LIFETIME_LEDGERS + 1 })]),
    );
    expect(report.findings).toContainEqual(
      expect.objectContaining({ rule: AUTH_EXPIRATION_UNBOUNDED_RULE, severity: 'warning' }),
    );
    expect(report.ok).toBe(true);
  });

  it('warns about an unsigned entry and omits expiration checks without a ledger', async () => {
    const report = await new AuthTreeSimulator().simulate(
      envelope([entry({ signed: false, expiration: 1 })]),
    );
    expect(report.findings).toContainEqual(
      expect.objectContaining({ rule: AUTH_SIGNATURE_MISSING_RULE, severity: 'warning' }),
    );
    expect(report.findings.map((finding) => finding.rule)).not.toContain(
      AUTH_SIGNATURE_EXPIRED_RULE,
    );
  });

  it('reports a cross-contract delegation outside the invoked contract', async () => {
    const report = await new AuthTreeSimulator({ latestLedger: 900 }).simulate(
      envelope([
        entry({
          children: [invocation(contractFn(OTHER_CONTRACT, 'transfer'))],
        }),
      ]),
    );
    expect(report.findings).toContainEqual(
      expect.objectContaining({ rule: UNAUTHORIZED_CROSS_CONTRACT_RULE, severity: 'error' }),
    );
  });

  it('allows a cross-contract call the caller explicitly approves', async () => {
    const report = await new AuthTreeSimulator({
      latestLedger: 900,
      allowedContracts: [OTHER_CONTRACT],
    }).simulate(
      envelope([entry({ children: [invocation(contractFn(OTHER_CONTRACT, 'transfer'))] })]),
    );
    expect(report.findings.map((finding) => finding.rule)).not.toContain(
      UNAUTHORIZED_CROSS_CONTRACT_RULE,
    );
  });

  it('records missing authorizations through Soroban RPC', async () => {
    const recorded = entry();
    const fetchImpl = (async (_url: string | URL | Request, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as { method: string };
      expect(body.method).toBe('simulateTransaction');
      return new Response(
        JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          result: {
            latestLedger: 900,
            results: [{ auth: [recorded.toXDR('base64')] }],
          },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }) as unknown as typeof fetch;

    const report = await new AuthTreeSimulator({
      rpcUrl: 'https://rpc.test',
      fetchImpl,
    }).simulate(envelope([]));
    expect(report.valid).toBe(true);
    expect(report.latestLedger).toBe(900);
    expect(report.entries).toHaveLength(1);
    expect(report.findings).toEqual([]);
  });

  it('reports an unreadable envelope without throwing', async () => {
    const report = await new AuthTreeSimulator().simulate('not-an-envelope');
    expect(report.valid).toBe(false);
    expect(report.error).toContain('not a base64 TransactionEnvelope');
    expect(report.ok).toBe(false);
  });

  it('renders an ASCII/Unicode tree with nested require_auth boundaries', () => {
    const simulator = new AuthTreeSimulator();
    const parsed = simulator.parseEnvelope(envelope([entry(), entry({ nonce: '8' })]));
    const diagram = renderAuthTreeDiagram(parsed?.entries ?? []);
    expect(diagram).toContain('├─');
    expect(diagram).toContain('└─');
    expect(diagram).toContain('nonce 7');
    expect(diagram).toContain('mint');
  });

  it('renders a text report and registers its rules', async () => {
    const report = await new AuthTreeSimulator({ latestLedger: 900 }).simulate(envelope([entry()]));
    const text = renderAuthTreeReport(report);
    expect(text).toContain('Auth tree: 1 entry');
    expect(text).toContain('No authorization problems found.');
    expect(authTreeRuleIds).toContain(AUTH_NONCE_REUSED_RULE);
    expect(authTreeRuleIds).toContain(UNAUTHORIZED_CROSS_CONTRACT_RULE);
  });

  it('parses a v0 transaction envelope', () => {
    const transaction = xdr.TransactionEnvelope.fromXDR(envelope([entry()]), 'base64')
      .v1()
      .tx();
    const v0 = new xdr.TransactionV0({
      sourceAccountEd25519: Buffer.from(StrKey.decodeEd25519PublicKey(SIGNING_KEY)),
      fee: transaction.fee(),
      seqNum: transaction.seqNum(),
      timeBounds: transaction.cond().timeBounds(),
      memo: transaction.memo(),
      operations: transaction.operations(),
      ext: xdr.TransactionV0Ext.fromXDR(Buffer.alloc(4), 'raw'),
    });
    const v0Envelope = xdr.TransactionEnvelope.envelopeTypeTxV0(
      new xdr.TransactionV0Envelope({ tx: v0, signatures: [] }),
    ).toXDR('base64');
    const parsed = new AuthTreeSimulator().parseEnvelope(v0Envelope);
    expect(parsed?.operations[0]?.function).toBe('mint');
    expect(parsed?.entries).toHaveLength(1);
  });

  it('parses a fee-bump envelope by reading its inner transaction', () => {
    const inner = TransactionBuilder.fromXDR(envelope([entry()]), NETWORK) as Transaction;
    const feeBump = TransactionBuilder.buildFeeBumpTransaction(SIGNING_KEY, '200', inner, NETWORK);
    const parsed = new AuthTreeSimulator().parseEnvelope(feeBump.toEnvelope().toXDR('base64'));
    expect(parsed?.operations[0]?.function).toBe('mint');
    expect(parsed?.entries).toHaveLength(1);
  });

  it('fetches the latest ledger when the envelope carries no auth', async () => {
    const fetchImpl = (async (_url: string | URL | Request, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as { method: string };
      const result =
        body.method === 'getLatestLedger' ? { sequence: 1234 } : { results: [{ auth: [] }] };
      return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as unknown as typeof fetch;

    const report = await new AuthTreeSimulator({
      rpcUrl: 'https://rpc.test',
      fetchImpl,
    }).simulate(envelope([]));
    expect(report.valid).toBe(true);
    expect(report.entries).toEqual([]);
    expect(report.latestLedger).toBe(1234);
    expect(report.diagram).toContain('(no authorization entries)');
  });

  it('stays valid when the RPC refuses or returns undecodable auth', async () => {
    const failing = (async () => new Response('nope', { status: 500 })) as unknown as typeof fetch;
    const failed = await new AuthTreeSimulator({
      rpcUrl: 'https://rpc.test',
      fetchImpl: failing,
    }).simulate(envelope([]));
    expect(failed.valid).toBe(true);
    expect(failed.entries).toEqual([]);

    const throwing = (async () => {
      throw new Error('offline');
    }) as unknown as typeof fetch;
    const offline = await new AuthTreeSimulator({
      rpcUrl: 'https://rpc.test',
      fetchImpl: throwing,
    }).simulate(envelope([]));
    expect(offline.valid).toBe(true);

    const garbage = (async (_url: string | URL | Request, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as { method: string };
      const result =
        body.method === 'getLatestLedger' ? {} : { results: [{ auth: [42, 'not-xdr'] }] };
      return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as unknown as typeof fetch;
    const undecodable = await new AuthTreeSimulator({
      rpcUrl: 'https://rpc.test',
      fetchImpl: garbage,
    }).simulate(envelope([]));
    expect(undecodable.valid).toBe(true);
    expect(undecodable.entries).toEqual([]);
  });

  it('renders an invalid report with an error and a network label', async () => {
    const report = await new AuthTreeSimulator({ networkPassphrase: NETWORK }).simulate('nope');
    const text = renderAuthTreeReport(report);
    expect(text).toContain('Auth tree: INVALID');
    expect(text).toContain(`Network: ${NETWORK}`);
    expect(text).toContain('Error:');
    expect(renderAuthTreeDiagram([])).toContain('(no authorization entries)');
  });

  it('renders a source-account entry without credential details', () => {
    const sourceEntry = new xdr.SorobanAuthorizationEntry({
      credentials: xdr.SorobanCredentials.sorobanCredentialsSourceAccount(),
      rootInvocation: invocation(contractFn(CONTRACT, 'mint')),
    });
    const diagram = renderAuthTreeDiagram([
      {
        sourceAccount: true,
        hasSignature: false,
        root: {
          contract: CONTRACT,
          function: 'mint',
          addresses: [],
          authBoundary: false,
          children: [],
        },
        requiredAddresses: [],
      },
    ]);
    expect(diagram).toContain('transaction source account');
    expect(sourceEntry.toXDR('base64')).toBeTypeOf('string');
  });

  it('labels a non-contract invocation as a plain call', () => {
    const diagram = renderAuthTreeDiagram([
      {
        sourceAccount: true,
        hasSignature: false,
        root: { addresses: [], authBoundary: false, children: [] },
        requiredAddresses: [],
      },
    ]);
    expect(diagram).toContain('call');
  });

  it('skips non-invoke operations and still reads the invoke operation', () => {
    const hostFunction = xdr.HostFunction.hostFunctionTypeInvokeContract(
      new xdr.InvokeContractArgs({
        contractAddress: new Address(CONTRACT).toScAddress(),
        functionName: 'mint',
        args: [],
      }),
    );
    const encoded = new TransactionBuilder(new Account(SIGNING_KEY, '0'), {
      fee: '100',
      networkPassphrase: NETWORK,
    })
      .addOperation(
        Operation.payment({ destination: SIGNING_KEY, asset: Asset.native(), amount: '1' }),
      )
      .addOperation(Operation.invokeHostFunction({ func: hostFunction, auth: [entry()] }))
      .setTimeout(30)
      .build()
      .toEnvelope()
      .toXDR('base64');
    const parsed = new AuthTreeSimulator().parseEnvelope(encoded);
    expect(parsed?.operations).toHaveLength(1);
    expect(parsed?.operations[0]?.index).toBe(1);
  });

  it('flags address credentials with no readable address', () => {
    const findings = new AuthTreeSimulator().auditCredentials(
      [
        {
          sourceAccount: false,
          hasSignature: false,
          root: { addresses: [], authBoundary: false, children: [] },
          requiredAddresses: [],
        },
      ],
      100,
    );
    expect(findings.map((finding) => finding.rule)).toContain(AUTH_CREDENTIAL_UNBOUND_RULE);
    expect(findings.map((finding) => finding.rule)).toContain(AUTH_SIGNATURE_MISSING_RULE);
  });

  it('renders findings with their fixes', async () => {
    const report = await new AuthTreeSimulator({ latestLedger: 900 }).simulate(
      envelope([entry({ nonce: '0' })]),
    );
    const text = renderAuthTreeReport(report);
    expect(text).toContain('Findings (1)');
    expect(text).toContain('Fix:');
  });

  it('accepts a multi-hop swap and liquidity route the caller approves', async () => {
    const report = await new AuthTreeSimulator({
      latestLedger: 900,
      allowedContracts: [OTHER_CONTRACT],
    }).simulate(
      envelope([
        entry({
          children: [
            invocation(contractFn(OTHER_CONTRACT, 'transfer')),
            invocation(contractFn(OTHER_CONTRACT, 'swap')),
          ],
        }),
      ]),
    );
    expect(report.findings).toEqual([]);
    expect(report.diagram).toContain(OTHER_CONTRACT);
  });

  it('reports an unapproved liquidity hop', async () => {
    const report = await new AuthTreeSimulator({ latestLedger: 900 }).simulate(
      envelope([
        entry({
          children: [invocation(contractFn(OTHER_CONTRACT, 'swap'))],
        }),
      ]),
    );
    expect(report.findings).toEqual(
      expect.arrayContaining([expect.objectContaining({ rule: UNAUTHORIZED_CROSS_CONTRACT_RULE })]),
    );
  });

  it('handles an RPC result with no auth or ledger fields', async () => {
    const fetchImpl = (async (_url: string | URL | Request, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as { method: string };
      return new Response(
        JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          result: body.method === 'getLatestLedger' ? {} : {},
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }) as unknown as typeof fetch;
    const report = await new AuthTreeSimulator({
      rpcUrl: 'https://rpc.test',
      fetchImpl,
    }).simulate(envelope([]));
    expect(report.valid).toBe(true);
    expect(report.entries).toEqual([]);
    expect(report.latestLedger).toBeUndefined();
  });

  it('handles source-account credentials without credential findings', async () => {
    const sourceEntry = new xdr.SorobanAuthorizationEntry({
      credentials: xdr.SorobanCredentials.sorobanCredentialsSourceAccount(),
      rootInvocation: invocation(contractFn(CONTRACT, 'mint')),
    });
    const report = await new AuthTreeSimulator({ latestLedger: 900 }).simulate(
      envelope([sourceEntry]),
    );
    expect(report.entries[0]?.sourceAccount).toBe(true);
    expect(report.findings).toEqual([]);
  });
});
