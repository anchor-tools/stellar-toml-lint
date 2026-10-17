import { describe, expect, it } from 'vitest';
import { Address, Keypair, StrKey, xdr } from '@stellar/stellar-base';
import {
  SEP45_ERROR_CODES,
  SEP45_WEB_AUTH_FUNCTION,
  Sep45AuthEngine,
  decodeSep45Args,
  operationsOf,
  parseSep45Challenge,
  sep45Rules,
  simulateSep45Challenge,
  validateSep45Challenge,
  verifySep45Challenge,
} from '../../src/soroban/sep45.js';

const WEB_AUTH_CONTRACT = 'CACTZSQPCQSSZ5YG3PI3N7WO6JEERKEUHTPILKB4MBANF2K4D2UHKDDU';
const OTHER_CONTRACT = StrKey.encodeContract(Buffer.alloc(32, 2));
const ACCOUNT = Keypair.random().publicKey();
const RPC = 'https://soroban-testnet.stellar.org';

const contractAddress = (contract = WEB_AUTH_CONTRACT): xdr.ScAddress =>
  new Address(contract).toScAddress();

const ACCOUNT_ADDRESS = (): xdr.ScAddress =>
  xdr.ScAddress.scAddressTypeAccount(
    xdr.PublicKey.publicKeyTypeEd25519(StrKey.decodeEd25519PublicKey(ACCOUNT)),
  );

const NONCE = Buffer.alloc(32, 9);

interface ArgOverrides {
  account?: xdr.ScVal;
  homeDomain?: xdr.ScVal;
  webAuthDomain?: xdr.ScVal;
  nonce?: xdr.ScVal;
  clientDomain?: xdr.ScVal;
  extra?: xdr.ScVal[];
}

/** The five `web_auth_verify` arguments, each overridable by type. */
function webAuthArgs(overrides: ArgOverrides = {}): xdr.ScVal[] {
  return [
    overrides.account ?? xdr.ScVal.scvAddress(contractAddress()),
    overrides.homeDomain ?? xdr.ScVal.scvString('anchor.example.com'),
    overrides.webAuthDomain ?? xdr.ScVal.scvString('auth.anchor.example.com'),
    overrides.nonce ?? xdr.ScVal.scvBytes(NONCE),
    overrides.clientDomain ?? xdr.ScVal.scvString('wallet.example.com'),
    ...(overrides.extra ?? []),
  ];
}

interface AuthOverrides {
  credentials?: 'address' | 'source';
  address?: xdr.ScAddress;
  nonce?: string;
  expiration?: number;
  signature?: xdr.ScVal;
  rootContract?: string;
  rootFunctionName?: string;
  rootFunction?: 'contract' | 'create';
  subInvocations?: xdr.SorobanAuthorizedInvocation[];
}

function authorizedContractFn(
  name = SEP45_WEB_AUTH_FUNCTION,
  contract = WEB_AUTH_CONTRACT,
): xdr.SorobanAuthorizedFunction {
  return xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
    new xdr.InvokeContractArgs({
      contractAddress: contractAddress(contract),
      functionName: name,
      args: [],
    }),
  );
}

function authorizedCreateFn(): xdr.SorobanAuthorizedFunction {
  return xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeCreateContractHostFn(
    new xdr.CreateContractArgs({
      contractIdPreimage: xdr.ContractIdPreimage.contractIdPreimageFromAddress(
        new xdr.ContractIdPreimageFromAddress({
          address: contractAddress(),
          salt: Buffer.alloc(32),
        }),
      ),
      executable: xdr.ContractExecutable.contractExecutableWasm(Buffer.alloc(32)),
    }),
  );
}

function authEntry(overrides: AuthOverrides = {}): xdr.SorobanAuthorizationEntry {
  const credentials =
    overrides.credentials === 'source'
      ? xdr.SorobanCredentials.sorobanCredentialsSourceAccount()
      : xdr.SorobanCredentials.sorobanCredentialsAddress(
          new xdr.SorobanAddressCredentials({
            address: overrides.address ?? contractAddress(),
            nonce: xdr.Int64.fromString(overrides.nonce ?? '1'),
            signatureExpirationLedger: overrides.expiration ?? 5_000,
            signature: overrides.signature ?? xdr.ScVal.scvBytes(Buffer.alloc(64, 7)),
          }),
        );

  const fn =
    overrides.rootFunction === 'create'
      ? authorizedCreateFn()
      : authorizedContractFn(overrides.rootFunctionName, overrides.rootContract);

  return new xdr.SorobanAuthorizationEntry({
    credentials,
    rootInvocation: new xdr.SorobanAuthorizedInvocation({
      function: fn,
      subInvocations: overrides.subInvocations ?? [],
    }),
  });
}

const muxedSource = (): xdr.MuxedAccount =>
  xdr.MuxedAccount.keyTypeEd25519(StrKey.decodeEd25519PublicKey(ACCOUNT));

interface ChallengeOverrides {
  hostFunction?: xdr.HostFunction;
  auth?: xdr.SorobanAuthorizationEntry[];
  operations?: xdr.Operation[];
  kind?: 'tx' | 'v0' | 'feeBump';
}

/** A full SEP-45 challenge transaction, base64 encoded. */
function challengeXdr(overrides: ChallengeOverrides = {}): string {
  const operations = overrides.operations ?? [
    new xdr.Operation({
      sourceAccount: null,
      body: xdr.OperationBody.invokeHostFunction(
        new xdr.InvokeHostFunctionOp({
          hostFunction:
            overrides.hostFunction ??
            xdr.HostFunction.hostFunctionTypeInvokeContract(
              new xdr.InvokeContractArgs({
                contractAddress: contractAddress(),
                functionName: SEP45_WEB_AUTH_FUNCTION,
                args: webAuthArgs(),
              }),
            ),
          auth: overrides.auth ?? [authEntry()],
        }),
      ),
    }),
  ];
  const tx = new xdr.Transaction({
    sourceAccount: muxedSource(),
    fee: 100,
    seqNum: xdr.Int64.fromString('1'),
    cond: xdr.Preconditions.precondNone(),
    memo: xdr.Memo.memoNone(),
    operations,
    ext: xdr.TransactionExt.fromXDR(Buffer.alloc(4), 'raw'),
  });

  if (overrides.kind === 'feeBump') {
    const feeBump = new xdr.FeeBumpTransaction({
      feeSource: muxedSource(),
      fee: xdr.Int64.fromString('200'),
      innerTx: xdr.FeeBumpTransactionInnerTx.envelopeTypeTx(
        new xdr.TransactionV1Envelope({ tx, signatures: [] }),
      ),
      ext: xdr.FeeBumpTransactionExt.fromXDR(Buffer.alloc(4), 'raw'),
    });
    return xdr.TransactionEnvelope.envelopeTypeTxFeeBump(
      new xdr.FeeBumpTransactionEnvelope({ tx: feeBump, signatures: [] }),
    ).toXDR('base64');
  }

  if (overrides.kind === 'v0') {
    const v0 = new xdr.TransactionV0({
      sourceAccountEd25519: StrKey.decodeEd25519PublicKey(ACCOUNT),
      fee: 100,
      seqNum: xdr.Int64.fromString('1'),
      timeBounds: null,
      memo: xdr.Memo.memoNone(),
      operations,
      ext: xdr.TransactionV0Ext.fromXDR(Buffer.alloc(4), 'raw'),
    });
    return xdr.TransactionEnvelope.envelopeTypeTxV0(
      new xdr.TransactionV0Envelope({ tx: v0, signatures: [] }),
    ).toXDR('base64');
  }

  return xdr.TransactionEnvelope.envelopeTypeTx(
    new xdr.TransactionV1Envelope({ tx, signatures: [] }),
  ).toXDR('base64');
}

const codes = (diagnostics: { rule: string }[]): string[] => diagnostics.map((d) => d.rule);

function challengeWith(auth: xdr.SorobanAuthorizationEntry[]) {
  const parsed = parseSep45Challenge(challengeXdr({ auth }));
  if (parsed.challenge === undefined) throw new Error('challenge did not parse');
  return parsed.challenge;
}

describe('parseSep45Challenge', () => {
  it('decodes the contract, function, arguments, and authorization entries', () => {
    const parsed = parseSep45Challenge(challengeXdr());
    expect(parsed.challenge).toBeDefined();
    const challenge = parsed.challenge;
    if (challenge === undefined) return;

    expect(challenge.operationCount).toBe(1);
    expect(challenge.operationType).toBe('invokeHostFunction');
    expect(challenge.hostFunctionType).toBe('hostFunctionTypeInvokeContract');
    expect(challenge.contractId).toBe(WEB_AUTH_CONTRACT);
    expect(challenge.functionName).toBe(SEP45_WEB_AUTH_FUNCTION);
    expect(challenge.args.account).toBe(WEB_AUTH_CONTRACT);
    expect(challenge.args.homeDomain).toBe('anchor.example.com');
    expect(challenge.args.webAuthDomain).toBe('auth.anchor.example.com');
    expect(challenge.args.clientDomain).toBe('wallet.example.com');
    expect(Buffer.from(challenge.args.nonce ?? []).toString('hex')).toBe(NONCE.toString('hex'));
    expect(challenge.auth).toHaveLength(1);
  });

  it('reads a challenge given as hex', () => {
    const base64 = challengeXdr();
    const hex = Buffer.from(base64, 'base64').toString('hex');
    const parsed = parseSep45Challenge(hex);
    expect(parsed.challenge?.functionName).toBe(SEP45_WEB_AUTH_FUNCTION);
  });

  it('unwraps a fee-bump envelope and a v0 envelope', () => {
    expect(parseSep45Challenge(challengeXdr({ kind: 'feeBump' })).challenge?.contractId).toBe(
      WEB_AUTH_CONTRACT,
    );
    expect(parseSep45Challenge(challengeXdr({ kind: 'v0' })).challenge?.contractId).toBe(
      WEB_AUTH_CONTRACT,
    );
  });

  it('rejects an empty or undecodable challenge', () => {
    expect(parseSep45Challenge('').diagnostic?.rule).toBe(SEP45_ERROR_CODES.MALFORMED_CHALLENGE);
    expect(parseSep45Challenge('   ').diagnostic?.rule).toBe(SEP45_ERROR_CODES.MALFORMED_CHALLENGE);
    expect(parseSep45Challenge('zzzz').diagnostic?.rule).toBe(
      SEP45_ERROR_CODES.MALFORMED_CHALLENGE,
    );
  });

  it('records a multi-operation transaction without reading its host function', () => {
    const manageData = new xdr.Operation({
      sourceAccount: null,
      body: xdr.OperationBody.manageData(new xdr.ManageDataOp({ dataName: 'x', dataValue: null })),
    });
    const parsed = parseSep45Challenge(challengeXdr({ operations: [manageData, manageData] }));
    expect(parsed.challenge?.operationCount).toBe(2);
    expect(parsed.challenge?.operationType).toBeUndefined();
  });

  it('reports a transaction with no operations as a non-invoke challenge', () => {
    const parsed = parseSep45Challenge(challengeXdr({ operations: [] }));
    expect(parsed.challenge?.operationCount).toBe(0);
    if (parsed.challenge === undefined) return;
    expect(codes(validateSep45Challenge(parsed.challenge))).toEqual([
      SEP45_ERROR_CODES.NOT_INVOKE_HOST_FUNCTION,
    ]);
  });

  it('ignores an envelope type it does not know how to unwrap', () => {
    const unknown = {
      switch: () => ({ name: 'envelopeTypeSomethingElse' }),
    } as unknown as xdr.TransactionEnvelope;
    expect(operationsOf(unknown)).toEqual([]);
  });

  it('records an invoke whose host function is not a contract call', () => {
    const hostFunction = xdr.HostFunction.hostFunctionTypeCreateContract(
      new xdr.CreateContractArgs({
        contractIdPreimage: xdr.ContractIdPreimage.contractIdPreimageFromAddress(
          new xdr.ContractIdPreimageFromAddress({
            address: contractAddress(),
            salt: Buffer.alloc(32),
          }),
        ),
        executable: xdr.ContractExecutable.contractExecutableWasm(Buffer.alloc(32)),
      }),
    );
    const challenge = parseSep45Challenge(challengeXdr({ hostFunction })).challenge;
    expect(challenge?.hostFunctionType).toBe('hostFunctionTypeCreateContract');
    expect(challenge?.contractId).toBeUndefined();
  });
});

describe('decodeSep45Args', () => {
  it('returns an empty object for an empty argument list', () => {
    expect(decodeSep45Args([])).toEqual({});
  });

  it('ignores arguments of the wrong type', () => {
    const args = decodeSep45Args([
      xdr.ScVal.scvU32(1),
      xdr.ScVal.scvU32(2),
      xdr.ScVal.scvU32(3),
      xdr.ScVal.scvU32(4),
      xdr.ScVal.scvU32(5),
    ]);
    expect(args).toEqual({});
  });

  it('ignores an address shape the contract layer cannot render', () => {
    // A muxed-address slot holding a plain ed25519 key is not a shape
    // `Address.fromScAddress` can render, and the decoder must not throw on it.
    const odd = xdr.ScAddress.scAddressTypeMuxedAccount(
      xdr.MuxedAccount.keyTypeEd25519(Buffer.alloc(32)) as unknown as xdr.MuxedEd25519Account,
    );
    const args = decodeSep45Args([
      xdr.ScVal.scvAddress(odd),
      xdr.ScVal.scvString('home'),
      xdr.ScVal.scvString('auth'),
      xdr.ScVal.scvBytes(NONCE),
    ]);
    expect(args.account).toBeUndefined();
    expect(args.homeDomain).toBe('home');
  });

  it('renders a claimable-balance address as its B... form', () => {
    const args = decodeSep45Args([
      xdr.ScVal.scvAddress(
        xdr.ScAddress.scAddressTypeClaimableBalance(
          xdr.ClaimableBalanceId.claimableBalanceIdTypeV0(Buffer.alloc(32)),
        ),
      ),
    ]);
    expect(args.account?.startsWith('B')).toBe(true);
  });

  it('reads an account address as a classic G... key', () => {
    const args = decodeSep45Args([
      xdr.ScVal.scvAddress(ACCOUNT_ADDRESS()),
      xdr.ScVal.scvString('home'),
      xdr.ScVal.scvString('auth'),
      xdr.ScVal.scvBytes(NONCE),
    ]);
    expect(args.account).toBe(ACCOUNT);
    expect(args.clientDomain).toBeUndefined();
  });
});

describe('validateSep45Challenge', () => {
  it('accepts a well-formed challenge', () => {
    const parsed = parseSep45Challenge(challengeXdr());
    if (parsed.challenge === undefined) throw new Error('parsing failed');
    expect(validateSep45Challenge(parsed.challenge)).toEqual([]);
  });

  it('accepts a signature wrapped in a vector of bytes', () => {
    const challenge = challengeWith([
      authEntry({ signature: xdr.ScVal.scvVec([xdr.ScVal.scvBytes(Buffer.alloc(8, 3))]) }),
    ]);
    expect(validateSep45Challenge(challenge)).toEqual([]);
  });

  it('rejects a transaction that is not a single invoke', () => {
    const parsed = parseSep45Challenge(
      challengeXdr({
        operations: [
          new xdr.Operation({
            sourceAccount: null,
            body: xdr.OperationBody.manageData(
              new xdr.ManageDataOp({ dataName: 'x', dataValue: null }),
            ),
          }),
        ],
      }),
    );
    if (parsed.challenge === undefined) throw new Error('parsing failed');
    expect(codes(validateSep45Challenge(parsed.challenge))).toEqual([
      SEP45_ERROR_CODES.NOT_INVOKE_HOST_FUNCTION,
    ]);
  });

  it('rejects an invokeHostFunction that does not call a contract', () => {
    const hostFunction = xdr.HostFunction.hostFunctionTypeCreateContract(
      new xdr.CreateContractArgs({
        contractIdPreimage: xdr.ContractIdPreimage.contractIdPreimageFromAddress(
          new xdr.ContractIdPreimageFromAddress({
            address: contractAddress(),
            salt: Buffer.alloc(32),
          }),
        ),
        executable: xdr.ContractExecutable.contractExecutableWasm(Buffer.alloc(32)),
      }),
    );
    const parsed = parseSep45Challenge(challengeXdr({ hostFunction }));
    if (parsed.challenge === undefined) throw new Error('parsing failed');
    expect(codes(validateSep45Challenge(parsed.challenge))).toEqual([
      SEP45_ERROR_CODES.UNSUPPORTED_HOST_FUNCTION,
    ]);
  });

  it('rejects an unexpected function name', () => {
    const parsed = parseSep45Challenge(
      challengeXdr({
        hostFunction: xdr.HostFunction.hostFunctionTypeInvokeContract(
          new xdr.InvokeContractArgs({
            contractAddress: contractAddress(),
            functionName: 'transfer',
            args: webAuthArgs(),
          }),
        ),
      }),
    );
    if (parsed.challenge === undefined) throw new Error('parsing failed');
    expect(codes(validateSep45Challenge(parsed.challenge))).toContain(
      SEP45_ERROR_CODES.UNEXPECTED_AUTH_FUNCTION,
    );
  });

  it('rejects a challenge aimed at a different contract', () => {
    const parsed = parseSep45Challenge(challengeXdr());
    if (parsed.challenge === undefined) throw new Error('parsing failed');
    const diagnostics = validateSep45Challenge(parsed.challenge, {
      webAuthContractId: OTHER_CONTRACT,
    });
    expect(codes(diagnostics)).toContain(SEP45_ERROR_CODES.UNEXPECTED_AUTH_CONTRACT);
  });

  it('rejects malformed web_auth_verify arguments', () => {
    const parsed = parseSep45Challenge(
      challengeXdr({
        hostFunction: xdr.HostFunction.hostFunctionTypeInvokeContract(
          new xdr.InvokeContractArgs({
            contractAddress: contractAddress(),
            functionName: SEP45_WEB_AUTH_FUNCTION,
            args: webAuthArgs({
              account: xdr.ScVal.scvU32(1),
              homeDomain: xdr.ScVal.scvU32(2),
              webAuthDomain: xdr.ScVal.scvU32(3),
              nonce: xdr.ScVal.scvBytes(Buffer.alloc(8, 1)),
            }),
          }),
        ),
      }),
    );
    if (parsed.challenge === undefined) throw new Error('parsing failed');
    const diagnostics = validateSep45Challenge(parsed.challenge);
    expect(codes(diagnostics)).toContain(SEP45_ERROR_CODES.MALFORMED_ARGUMENTS);
    expect(
      diagnostics.filter((d) => d.rule === SEP45_ERROR_CODES.MALFORMED_ARGUMENTS),
    ).toHaveLength(4);
  });

  it('rejects a challenge that carries no authorization entry', () => {
    expect(codes(validateSep45Challenge(challengeWith([])))).toContain(
      SEP45_ERROR_CODES.MISSING_AUTHORIZATION,
    );
  });

  it('rejects source-account credentials', () => {
    const challenge = challengeWith([authEntry({ credentials: 'source' })]);
    expect(codes(validateSep45Challenge(challenge))).toContain(
      SEP45_ERROR_CODES.MALFORMED_AUTHORIZATION_ENTRY,
    );
  });

  it('rejects an expired signature expiration ledger', () => {
    const challenge = challengeWith([authEntry({ expiration: 100 })]);
    expect(codes(validateSep45Challenge(challenge, { latestLedger: 100 }))).toContain(
      SEP45_ERROR_CODES.EXPIRED_SUB_INVOCATION,
    );
    // A comfortably future expiration is fine.
    expect(validateSep45Challenge(challenge, { latestLedger: 99 })).not.toContainEqual(
      expect.objectContaining({ rule: SEP45_ERROR_CODES.EXPIRED_SUB_INVOCATION }),
    );
  });

  it('rejects zero and repeated nonces', () => {
    const zero = validateSep45Challenge(challengeWith([authEntry({ nonce: '0' })]));
    expect(codes(zero)).toContain(SEP45_ERROR_CODES.INVALID_NONCE_SEQUENCE);

    const repeated = validateSep45Challenge(
      challengeWith([authEntry({ nonce: '7' }), authEntry({ nonce: '7' })]),
    );
    expect(codes(repeated)).toContain(SEP45_ERROR_CODES.INVALID_NONCE_SEQUENCE);
  });

  it('rejects a malformed signature payload', () => {
    const challenge = challengeWith([authEntry({ signature: xdr.ScVal.scvU32(1) })]);
    expect(codes(validateSep45Challenge(challenge))).toContain(
      SEP45_ERROR_CODES.INVALID_SIGNATURE_STRUCTURE,
    );

    const emptyVector = challengeWith([authEntry({ signature: xdr.ScVal.scvVec([]) })]);
    expect(codes(validateSep45Challenge(emptyVector))).toContain(
      SEP45_ERROR_CODES.INVALID_SIGNATURE_STRUCTURE,
    );

    const nonBytesVector = challengeWith([
      authEntry({ signature: xdr.ScVal.scvVec([xdr.ScVal.scvU32(1)]) }),
    ]);
    expect(codes(validateSep45Challenge(nonBytesVector))).toContain(
      SEP45_ERROR_CODES.INVALID_SIGNATURE_STRUCTURE,
    );
  });

  it('rejects a root invocation that is not a contract function', () => {
    const challenge = challengeWith([authEntry({ rootFunction: 'create' })]);
    expect(codes(validateSep45Challenge(challenge))).toContain(
      SEP45_ERROR_CODES.MALFORMED_AUTHORIZATION_ENTRY,
    );
  });

  it('rejects a root invocation of the wrong function or contract', () => {
    const wrongFunction = challengeWith([authEntry({ rootFunctionName: 'transfer' })]);
    expect(codes(validateSep45Challenge(wrongFunction))).toContain(
      SEP45_ERROR_CODES.MALFORMED_AUTHORIZATION_ENTRY,
    );

    const wrongContract = challengeWith([authEntry({ rootContract: OTHER_CONTRACT })]);
    expect(codes(validateSep45Challenge(wrongContract))).toContain(
      SEP45_ERROR_CODES.MALFORMED_AUTHORIZATION_ENTRY,
    );
  });

  it('rejects a non-contract sub-invocation', () => {
    const sub = new xdr.SorobanAuthorizedInvocation({
      function: authorizedCreateFn(),
      subInvocations: [],
    });
    const challenge = challengeWith([authEntry({ subInvocations: [sub] })]);
    const diagnostics = validateSep45Challenge(challenge);
    expect(codes(diagnostics)).toContain(SEP45_ERROR_CODES.MALFORMED_AUTHORIZATION_ENTRY);
    expect(diagnostics.some((d) => d.message.includes('subInvocations'))).toBe(true);
  });

  it('accepts a contract-function sub-invocation', () => {
    const sub = new xdr.SorobanAuthorizedInvocation({
      function: authorizedContractFn('transfer'),
      subInvocations: [],
    });
    expect(validateSep45Challenge(challengeWith([authEntry({ subInvocations: [sub] })]))).toEqual(
      [],
    );
  });

  it('honours --off and severity overrides', () => {
    const challenge = challengeWith([]);
    expect(
      validateSep45Challenge(challenge, {
        rules: { [SEP45_ERROR_CODES.MISSING_AUTHORIZATION]: 'off' },
      }),
    ).toEqual([]);

    const raised = challengeWith([authEntry({ nonce: '0' })]);
    const diagnostics = validateSep45Challenge(raised, {
      rules: { [SEP45_ERROR_CODES.INVALID_NONCE_SEQUENCE]: 'warning' },
    });
    expect(diagnostics[0]?.severity).toBe('warning');
  });
});

// ── simulation ──────────────────────────────────────────────────────────────

function rpcReturning(body: unknown, status = 200): typeof fetch {
  return (async () =>
    new Response(typeof body === 'string' ? body : JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' },
    })) as unknown as typeof fetch;
}

describe('simulateSep45Challenge', () => {
  it('is clean when the RPC simulates the invocation', async () => {
    const fetchImpl = rpcReturning({
      jsonrpc: '2.0',
      id: 1,
      result: { latestLedger: 100, results: [] },
    });
    const outcome = await simulateSep45Challenge(challengeXdr(), RPC, fetchImpl);
    expect(outcome.diagnostics).toEqual([]);
    expect(outcome.result).toBeDefined();
  });

  it('reports a simulation the network rejected, at the JSON-RPC level and in the result', async () => {
    const rpcLevel = await simulateSep45Challenge(
      challengeXdr(),
      RPC,
      rpcReturning({ jsonrpc: '2.0', id: 1, error: { code: -32602, message: 'invalid params' } }),
    );
    expect(codes(rpcLevel.diagnostics)).toEqual([SEP45_ERROR_CODES.SIMULATION_FAILED]);

    // An error object without a message still has to be reported, not ignored.
    const messageLess = await simulateSep45Challenge(
      challengeXdr(),
      RPC,
      rpcReturning({ jsonrpc: '2.0', id: 1, error: { code: -32600 } }),
    );
    expect(codes(messageLess.diagnostics)).toEqual([SEP45_ERROR_CODES.SIMULATION_FAILED]);

    // A success answer with no `result` is still a successful simulation.
    const noResult = await simulateSep45Challenge(
      challengeXdr(),
      RPC,
      rpcReturning({ jsonrpc: '2.0', id: 1 }),
    );
    expect(noResult.diagnostics).toEqual([]);
    expect(noResult.result).toBeUndefined();

    const stringError = await simulateSep45Challenge(
      challengeXdr(),
      RPC,
      rpcReturning({ jsonrpc: '2.0', id: 1, error: 'bad request' }),
    );
    expect(codes(stringError.diagnostics)).toEqual([SEP45_ERROR_CODES.SIMULATION_FAILED]);

    const resultLevel = await simulateSep45Challenge(
      challengeXdr(),
      RPC,
      rpcReturning({ jsonrpc: '2.0', id: 1, result: { error: 'HostError: auth failed' } }),
    );
    expect(codes(resultLevel.diagnostics)).toEqual([SEP45_ERROR_CODES.SIMULATION_FAILED]);
    expect(resultLevel.result).toBeDefined();
  });

  it('degrades an unreachable or malformed RPC to a warning', async () => {
    const offline = (async () => {
      throw new Error('connect ECONNREFUSED');
    }) as unknown as typeof fetch;
    expect(codes((await simulateSep45Challenge(challengeXdr(), RPC, offline)).diagnostics)).toEqual(
      [SEP45_ERROR_CODES.SIMULATION_UNAVAILABLE],
    );

    const httpError = await simulateSep45Challenge(
      challengeXdr(),
      RPC,
      rpcReturning({ error: 'nope' }, 502),
    );
    expect(codes(httpError.diagnostics)).toEqual([SEP45_ERROR_CODES.SIMULATION_UNAVAILABLE]);

    const notJson = await simulateSep45Challenge(
      challengeXdr(),
      RPC,
      rpcReturning('<html>oops</html>'),
    );
    expect(codes(notJson.diagnostics)).toEqual([SEP45_ERROR_CODES.SIMULATION_UNAVAILABLE]);

    const arrayBody = await simulateSep45Challenge(challengeXdr(), RPC, rpcReturning([1, 2, 3]));
    expect(codes(arrayBody.diagnostics)).toEqual([SEP45_ERROR_CODES.SIMULATION_UNAVAILABLE]);
  });

  it('posts a simulateTransaction request for the challenge', async () => {
    let request: { method?: string; body?: unknown } = {};
    const fetchImpl = (async (_url: string, init?: RequestInit) => {
      request = { method: init?.method, body: JSON.parse(String(init?.body)) };
      return new Response(JSON.stringify({ result: {} }), { status: 200 });
    }) as unknown as typeof fetch;

    await simulateSep45Challenge(challengeXdr(), RPC, fetchImpl);
    expect(request.method).toBe('POST');
    expect(request.body).toMatchObject({ method: 'simulateTransaction' });
  });

  it('honours the SIMULATION_UNAVAILABLE severity override', async () => {
    const offline = (async () => {
      throw new Error('offline');
    }) as unknown as typeof fetch;
    const diagnostics = await simulateSep45Challenge(challengeXdr(), RPC, offline, {
      rules: { [SEP45_ERROR_CODES.SIMULATION_UNAVAILABLE]: 'off' },
    });
    expect(diagnostics.diagnostics).toEqual([]);
  });
});

describe('verifySep45Challenge', () => {
  it('fails on an undecodable challenge without touching the network', async () => {
    const verification = await verifySep45Challenge('zzzz');
    expect(verification.valid).toBe(false);
    expect(codes(verification.diagnostics)).toEqual([SEP45_ERROR_CODES.MALFORMED_CHALLENGE]);
    expect(verification.challenge).toBeUndefined();
  });

  it('verifies a well-formed challenge offline', async () => {
    const verification = await verifySep45Challenge(challengeXdr());
    expect(verification.valid).toBe(true);
    expect(verification.diagnostics).toEqual([]);
    expect(verification.challenge?.contractId).toBe(WEB_AUTH_CONTRACT);
  });

  it('adds a successful simulation when an RPC is configured', async () => {
    const verification = await verifySep45Challenge(challengeXdr(), {
      rpcUrl: RPC,
      fetchImpl: rpcReturning({ result: { latestLedger: 1 } }),
    });
    expect(verification.valid).toBe(true);
    expect(verification.simulation).toEqual({ latestLedger: 1 });
  });

  it('stays valid when only the RPC is unavailable', async () => {
    const offline = (async () => {
      throw new Error('offline');
    }) as unknown as typeof fetch;
    const verification = await verifySep45Challenge(challengeXdr(), {
      rpcUrl: RPC,
      fetchImpl: offline,
    });
    expect(verification.valid).toBe(true);
    expect(codes(verification.diagnostics)).toEqual([SEP45_ERROR_CODES.SIMULATION_UNAVAILABLE]);
  });

  it('is invalid when the RPC rejects the simulation', async () => {
    const verification = await verifySep45Challenge(challengeXdr(), {
      rpcUrl: RPC,
      fetchImpl: rpcReturning({ result: { error: 'auth failed' } }),
    });
    expect(verification.valid).toBe(false);
  });
});

describe('Sep45AuthEngine', () => {
  it('exposes parse, validate, verify, and simulate', async () => {
    const engine = new Sep45AuthEngine({
      webAuthContractId: WEB_AUTH_CONTRACT,
      latestLedger: 10,
    });

    const parsed = engine.parse(challengeXdr());
    expect(parsed.challenge).toBeDefined();
    if (parsed.challenge === undefined) return;

    expect(engine.validate(parsed.challenge)).toEqual([]);
    expect((await engine.verify(challengeXdr())).valid).toBe(true);
    // No RPC configured, so simulate is a no-op.
    expect(await engine.simulate(challengeXdr())).toEqual([]);
  });

  it('simulates through the configured RPC', async () => {
    const engine = new Sep45AuthEngine({
      rpcUrl: RPC,
      fetchImpl: rpcReturning({ result: {} }),
    });
    expect(await engine.simulate(challengeXdr())).toEqual([]);
    expect((await engine.verify(challengeXdr())).valid).toBe(true);
  });

  it('reports the contract mismatch through the engine', () => {
    const engine = new Sep45AuthEngine({ webAuthContractId: OTHER_CONTRACT });
    const parsed = engine.parse(challengeXdr());
    if (parsed.challenge === undefined) throw new Error('parsing failed');
    expect(codes(engine.validate(parsed.challenge))).toContain(
      SEP45_ERROR_CODES.UNEXPECTED_AUTH_CONTRACT,
    );
  });
});

describe('sep45Rules', () => {
  it('registers every error code', () => {
    expect(sep45Rules.map((rule) => rule.id).sort()).toEqual(
      Object.values(SEP45_ERROR_CODES).sort(),
    );
    const simulatedUnavailable = sep45Rules.find(
      (rule) => rule.id === SEP45_ERROR_CODES.SIMULATION_UNAVAILABLE,
    );
    expect(simulatedUnavailable?.severity).toBe('warning');
  });
});
