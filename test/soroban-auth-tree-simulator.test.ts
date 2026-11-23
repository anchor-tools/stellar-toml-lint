import { describe, expect, it } from 'vitest';
import { Address, xdr } from '@stellar/stellar-base';
import {
  UNAUTHORIZED_CROSS_CONTRACT_RULE,
  UNBOUNDED_AUTH_GRANT_RULE,
  analyzeAuthTree,
  auditTomlAuthTree,
  authTreeSimulatorRules,
  buildAuthTreeTransaction,
  parseAuthEntries,
  parseAuthEntry,
  simulateAuthTree,
} from '../src/soroban/auth-tree-simulator.js';

/** The token contract the file declares. */
const CONTRACT = 'CABQ4GJEF45EKUC3MZYXZB4STWULHPWJ2TP6V5IABMLCCLBXIJGVQKFK';
/** A contract the file does not declare. */
const OTHER_CONTRACT = 'CAUDGPSJKRPWU5MAROLKDLFXYLG5RY7O7ECA6GRFGA5UMUK4M5ZH2B33';
/** The anchor's published signing key. */
const SIGNING_KEY = 'GDVEU3DD4KOFECV66VIHWEZOYX4ZKR3WV27L464SIIPOU2IUI3JCZA57';
/** The issuer the file designates for the asset. */
const ISSUER = 'GB6KZ5DBZM7QWSCF2ROC5HH7T7X5WC365K73ILLRTZY5EA2PHVIIED2J';
/** An account the anchor does not control. */
const STRANGER = 'GAADCTOBLRGGI3V24MCVLH7U4B4DTZS3F2QBV6AXGJ7LD4M3BLQCE2DS';

const RPC = 'https://rpc.test';

/** The contract call a node of the tree names. */
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

/** One invocation of the tree, with the sub-invocations it carries. */
function invocation(
  fn: xdr.SorobanAuthorizedFunction,
  children: xdr.SorobanAuthorizedInvocation[] = [],
): xdr.SorobanAuthorizedInvocation {
  return new xdr.SorobanAuthorizedInvocation({ function: fn, subInvocations: children });
}

/** Credentials that name the identity that authorized the root invocation. */
function addressCredential(address: string): xdr.SorobanCredentials {
  return xdr.SorobanCredentials.sorobanCredentialsAddress(
    new xdr.SorobanAddressCredentials({
      address: new Address(address).toScAddress(),
      nonce: xdr.Int64.fromString('0'),
      signatureExpirationLedger: 100,
      signature: xdr.ScVal.scvVec([]),
    }),
  );
}

/** Credentials that leave the authorization to the transaction source account. */
function sourceAccountCredential(): xdr.SorobanCredentials {
  return xdr.SorobanCredentials.sorobanCredentialsSourceAccount();
}

/** The `require_auth` boundary a contract records when it asks to be authorized. */
function authBoundary(contract: string, address?: string): xdr.SorobanAuthorizedInvocation {
  const args: xdr.ScVal[] = [];
  if (address !== undefined) args.push(new Address(address).toScVal());
  args.push(xdr.ScVal.scvVec([]));
  return invocation(contractFn(contract, '__require_auth', args));
}

/**
 * The tree a well-configured SAC mint produces: the mint call at the root,
 * authorized by the account the file publishes.
 */
function validMintTree(): xdr.SorobanAuthorizationEntry {
  return new xdr.SorobanAuthorizationEntry({
    credentials: addressCredential(SIGNING_KEY),
    rootInvocation: invocation(contractFn(CONTRACT, 'mint', [new Address(SIGNING_KEY).toScVal()])),
  });
}

/** A tree the transaction source account authorizes on its own. */
function sourceAuthorizedTree(): xdr.SorobanAuthorizationEntry {
  return new xdr.SorobanAuthorizationEntry({
    credentials: sourceAccountCredential(),
    rootInvocation: invocation(contractFn(CONTRACT, 'mint', [new Address(SIGNING_KEY).toScVal()])),
  });
}

/** A tree that also authorizes an unrelated contract. */
function delegatingTree(): xdr.SorobanAuthorizationEntry {
  return new xdr.SorobanAuthorizationEntry({
    credentials: addressCredential(SIGNING_KEY),
    rootInvocation: invocation(contractFn(CONTRACT, 'mint', [new Address(SIGNING_KEY).toScVal()]), [
      invocation(contractFn(OTHER_CONTRACT, 'swap')),
    ]),
  });
}

/** A tree that widens the mint into a transfer on the same contract. */
function wideningTree(): xdr.SorobanAuthorizationEntry {
  return new xdr.SorobanAuthorizationEntry({
    credentials: addressCredential(SIGNING_KEY),
    rootInvocation: invocation(contractFn(CONTRACT, 'mint', [new Address(SIGNING_KEY).toScVal()]), [
      invocation(contractFn(CONTRACT, 'transfer')),
    ]),
  });
}

/** A tree authorized by an account the anchor does not control. */
function strangerTree(): xdr.SorobanAuthorizationEntry {
  return new xdr.SorobanAuthorizationEntry({
    credentials: addressCredential(STRANGER),
    rootInvocation: invocation(contractFn(CONTRACT, 'mint', [new Address(SIGNING_KEY).toScVal()])),
  });
}

/** A tree whose nested authorization boundary names no address at all. */
function unboundedTree(): xdr.SorobanAuthorizationEntry {
  return new xdr.SorobanAuthorizationEntry({
    credentials: addressCredential(SIGNING_KEY),
    rootInvocation: invocation(contractFn(CONTRACT, 'mint', [new Address(SIGNING_KEY).toScVal()]), [
      authBoundary(CONTRACT),
    ]),
  });
}

/** A tree the token contract authorizes itself. */
function selfAuthorizedTree(): xdr.SorobanAuthorizationEntry {
  return new xdr.SorobanAuthorizationEntry({
    credentials: addressCredential(CONTRACT),
    rootInvocation: invocation(contractFn(CONTRACT, 'mint', [new Address(SIGNING_KEY).toScVal()])),
  });
}

/**
 * An RPC stub that answers every `simulateTransaction` with `entries`.
 *
 * The RPC keeps the recorded authorizations under the host function result,
 * which is where the simulator reads them.
 */
function authRpcFetch(entries: xdr.SorobanAuthorizationEntry[]): typeof fetch {
  return (async (_url: string | URL | Request, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body)) as {
      method: string;
      params: { transaction: string; authMode?: string };
    };
    expect(body.method).toBe('simulateTransaction');
    expect(typeof body.params.transaction).toBe('string');
    expect(body.params.authMode).toBe('record');
    return new Response(
      JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        result: {
          latestLedger: 1000,
          minResourceFee: '1',
          results: [{ auth: entries.map((entry) => entry.toXDR('base64')), xdr: '' }],
        },
      }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );
  }) as unknown as typeof fetch;
}

/** The analysis context a well-configured anchor produces. */
const CONTEXT = {
  authorizedIdentities: [SIGNING_KEY, ISSUER],
  allowedContracts: [CONTRACT],
};

/** The options every simulation in this suite shares. */
const OPTIONS = {
  authorizedIdentities: CONTEXT.authorizedIdentities,
  allowedContracts: CONTEXT.allowedContracts,
  sourceAccount: SIGNING_KEY,
};

describe('soroban SEP-42 authorization call-tree simulator', () => {
  it('builds an InvokeHostFunction envelope for mint', () => {
    const envelope = buildAuthTreeTransaction(CONTRACT, 'mint', SIGNING_KEY);
    const parsed = xdr.TransactionEnvelope.fromXDR(envelope, 'base64');
    const op = parsed.v1().tx().operations()[0]!;
    expect(op.body().switch().name).toBe('invokeHostFunction');

    const invoke = op.body().invokeHostFunctionOp().hostFunction().invokeContract();
    expect(invoke.functionName().toString()).toBe('mint');
    expect(Address.fromScAddress(invoke.contractAddress()).toString()).toBe(CONTRACT);
    expect(invoke.args().map((arg) => arg.switch().name)).toEqual(['scvAddress', 'scvI128']);
  });

  it('builds an InvokeHostFunction envelope for clawback', () => {
    const envelope = buildAuthTreeTransaction(CONTRACT, 'clawback', SIGNING_KEY);
    const parsed = xdr.TransactionEnvelope.fromXDR(envelope, 'base64');
    const op = parsed.v1().tx().operations()[0]!;
    const invoke = op.body().invokeHostFunctionOp().hostFunction().invokeContract();
    expect(invoke.functionName().toString()).toBe('clawback');
  });

  it('passes a valid auth tree matching SIGNING_KEY', async () => {
    const diagnostics = await simulateAuthTree(
      CONTRACT,
      'mint',
      SIGNING_KEY,
      RPC,
      authRpcFetch([validMintTree()]),
      OPTIONS,
    );
    expect(diagnostics).toEqual([]);
  });

  it('passes a valid auth tree matching the designated issuer', async () => {
    const tree = new xdr.SorobanAuthorizationEntry({
      credentials: addressCredential(ISSUER),
      rootInvocation: invocation(contractFn(CONTRACT, 'clawback', [new Address(ISSUER).toScVal()])),
    });

    const diagnostics = await simulateAuthTree(
      CONTRACT,
      'clawback',
      ISSUER,
      RPC,
      authRpcFetch([tree]),
      OPTIONS,
    );
    expect(diagnostics).toEqual([]);
  });

  it('passes a valid auth tree the transaction source account authorizes', async () => {
    const diagnostics = await simulateAuthTree(
      CONTRACT,
      'mint',
      SIGNING_KEY,
      RPC,
      authRpcFetch([sourceAuthorizedTree()]),
      OPTIONS,
    );
    expect(diagnostics).toEqual([]);
  });

  it('asserts soroban/unauthorized-cross-contract-call on an unauthorized sub-invocation', async () => {
    const diagnostics = await simulateAuthTree(
      CONTRACT,
      'mint',
      SIGNING_KEY,
      RPC,
      authRpcFetch([delegatingTree()]),
      OPTIONS,
    );
    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: UNAUTHORIZED_CROSS_CONTRACT_RULE,
        severity: 'error',
        message: expect.stringContaining(OTHER_CONTRACT),
      }),
    );
  });

  it('asserts soroban/unauthorized-cross-contract-call when the tree widens the operation', async () => {
    const diagnostics = await simulateAuthTree(
      CONTRACT,
      'mint',
      SIGNING_KEY,
      RPC,
      authRpcFetch([wideningTree()]),
      OPTIONS,
    );
    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: UNAUTHORIZED_CROSS_CONTRACT_RULE,
        severity: 'error',
        message: expect.stringContaining('transfer'),
      }),
    );
  });

  it('asserts soroban/unauthorized-cross-contract-call when a stranger authorizes the tree', async () => {
    const diagnostics = await simulateAuthTree(
      CONTRACT,
      'mint',
      SIGNING_KEY,
      RPC,
      authRpcFetch([strangerTree()]),
      OPTIONS,
    );
    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: UNAUTHORIZED_CROSS_CONTRACT_RULE,
        severity: 'error',
        message: expect.stringContaining(STRANGER),
      }),
    );
  });

  it('asserts soroban/unbounded-auth-grant when a boundary names no address', async () => {
    const diagnostics = await simulateAuthTree(
      CONTRACT,
      'mint',
      SIGNING_KEY,
      RPC,
      authRpcFetch([unboundedTree()]),
      OPTIONS,
    );
    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: UNBOUNDED_AUTH_GRANT_RULE,
        severity: 'warning',
      }),
    );
  });

  it('asserts soroban/unbounded-auth-grant when the contract authorizes itself', async () => {
    const diagnostics = await simulateAuthTree(
      CONTRACT,
      'mint',
      SIGNING_KEY,
      RPC,
      authRpcFetch([selfAuthorizedTree()]),
      OPTIONS,
    );
    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: UNBOUNDED_AUTH_GRANT_RULE,
        severity: 'warning',
      }),
    );
  });

  it('reads the tree the RPC returns', () => {
    const entries = parseAuthEntries([validMintTree().toXDR('base64')]);
    expect(entries).toHaveLength(1);
    const [entry] = entries;
    expect(entry?.root.function).toBe('mint');
    expect(entry?.root.contract).toBe(CONTRACT);
    expect(entry?.credentialAddress).toBe(SIGNING_KEY);
    expect(entry?.sourceAccount).toBe(false);
    expect(entry?.requiredAddresses).toEqual([]);
  });

  it('reads a nested authorization boundary', () => {
    const entry = parseAuthEntry(
      new xdr.SorobanAuthorizationEntry({
        credentials: addressCredential(SIGNING_KEY),
        rootInvocation: invocation(
          contractFn(CONTRACT, 'mint', [new Address(SIGNING_KEY).toScVal()]),
          [authBoundary(CONTRACT, ISSUER)],
        ),
      }),
    );
    expect(entry.requiredAddresses).toEqual([ISSUER]);
    expect(entry.root.children[0]?.authBoundary).toBe(true);
    expect(entry.root.children[0]?.addresses).toEqual([ISSUER]);
  });

  it('skips an auth entry it cannot decode', () => {
    expect(parseAuthEntries(['not-base64-xdr', 42])).toEqual([]);
    expect(parseAuthEntries(undefined)).toEqual([]);
  });

  it('finds nothing in a tree the anchor does not publish any identity for', () => {
    const findings = analyzeAuthTree([parseAuthEntry(strangerTree())], {
      authorizedIdentities: [],
      allowedContracts: [],
    });
    expect(findings).toEqual([]);
  });

  it('audits the contracts a stellar.toml document declares', async () => {
    const doc = {
      NETWORK_PASSPHRASE: 'Test SDF Network ; September 2015',
      SIGNING_KEY,
      CURRENCIES: [{ code: 'TEST', contract: CONTRACT, issuer: ISSUER }],
    };

    const diagnostics = await auditTomlAuthTree(doc, authRpcFetch([validMintTree()]), {
      rpcUrl: RPC,
    });
    expect(diagnostics).toEqual([]);
  });

  it('reports an unauthorized tree for a stellar.toml document', async () => {
    const doc = {
      NETWORK_PASSPHRASE: 'Test SDF Network ; September 2015',
      SIGNING_KEY,
      CURRENCIES: [{ code: 'TEST', contract: CONTRACT, issuer: ISSUER }],
    };

    const diagnostics = await auditTomlAuthTree(doc, authRpcFetch([delegatingTree()]), {
      rpcUrl: RPC,
    });
    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: UNAUTHORIZED_CROSS_CONTRACT_RULE,
        severity: 'error',
      }),
    );
  });

  it('stays silent when the RPC does not answer', async () => {
    const failing = (async () => new Response('nope', { status: 500 })) as unknown as typeof fetch;

    const diagnostics = await simulateAuthTree(
      CONTRACT,
      'mint',
      SIGNING_KEY,
      RPC,
      failing,
      OPTIONS,
    );
    expect(diagnostics).toEqual([]);
  });

  it('builds no envelope for a contract id that is not an address', () => {
    expect(buildAuthTreeTransaction('not-a-contract', 'mint', SIGNING_KEY)).toBe('');
  });

  it('stays silent for a contract id that is not an address', async () => {
    const diagnostics = await simulateAuthTree(
      'not-a-contract',
      'mint',
      SIGNING_KEY,
      RPC,
      authRpcFetch([validMintTree()]),
      OPTIONS,
    );
    expect(diagnostics).toEqual([]);
  });

  it('asserts soroban/unauthorized-cross-contract-call for a nested boundary naming a stranger', async () => {
    const tree = new xdr.SorobanAuthorizationEntry({
      credentials: addressCredential(SIGNING_KEY),
      rootInvocation: invocation(
        contractFn(CONTRACT, 'mint', [new Address(SIGNING_KEY).toScVal()]),
        [authBoundary(CONTRACT, STRANGER)],
      ),
    });

    const diagnostics = await simulateAuthTree(
      CONTRACT,
      'mint',
      SIGNING_KEY,
      RPC,
      authRpcFetch([tree]),
      OPTIONS,
    );
    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: UNAUTHORIZED_CROSS_CONTRACT_RULE,
        severity: 'error',
        message: expect.stringContaining(STRANGER),
      }),
    );
  });

  it('registers both rule definitions', () => {
    expect(
      authTreeSimulatorRules.map((rule) => ({ id: rule.id, severity: rule.severity })),
    ).toEqual([
      { id: UNAUTHORIZED_CROSS_CONTRACT_RULE, severity: 'error' },
      { id: UNBOUNDED_AUTH_GRANT_RULE, severity: 'warning' },
    ]);
  });
});
