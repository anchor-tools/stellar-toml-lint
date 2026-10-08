/**
 * Soroban RPC real-time simulation sandbox for SEP-41 operations.
 *
 * A contract can exist on the ledger and still revert the moment a wallet calls
 * it: a missing function, a panicking `initialize`, a footprint the host
 * rejects. This audit builds `InvokeHostFunctionOp` envelopes for the standard
 * SEP-41 read functions — `decimals()`, `name()`, `symbol()`, and a zero-value
 * `balance(dummy)` — and asks the Soroban RPC to `simulateTransaction` them.
 * Nothing is submitted and no fees are spent; the RPC dry-runs the call and
 * reports whether it would succeed. The CPU instruction and memory metrics the
 * simulation returns are also checked, so a contract that only just fits inside
 * the ledger limits is flagged before it fails in the field.
 *
 * Runs under the opt-in `--check-network --simulate-soroban` flags like the
 * other on-chain audits, never throws on an RPC outage, and registers rule
 * objects so `--list-rules` and `--off`/`--warn`/`--error` know its ids.
 *
 * Diagnostics:
 * - `soroban/simulation-failed` (error)
 * - `soroban/excessive-resource-consumption` (warning)
 */
import { Account, Address, Operation, TransactionBuilder, xdr } from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { rpcUrlFor } from '../rules/display-decimals-audit.js';
import { contractCurrenciesOf } from '../rules/currencies.js';
import { RPC_TIMEOUT_MS, severityFor } from './rpc.js';

export const SIMULATION_FAILED_RULE = 'soroban/simulation-failed';
export const EXCESSIVE_RESOURCE_RULE = 'soroban/excessive-resource-consumption';

/** A valid account used as the transaction source when the caller has none. */
export const DEFAULT_SOURCE_ACCOUNT = 'GDVEU3DD4KOFECV66VIHWEZOYX4ZKR3WV27L464SIIPOU2IUI3JCZA57';

const NETWORK_PASSPHRASE = 'Test SDF Network ; September 2015';

/** Default ceilings before a simulation is considered resource-heavy. */
export const DEFAULT_MAX_INSTRUCTIONS = 100_000_000;
export const DEFAULT_MAX_MEMORY_BYTES = 40 * 1024 * 1024;

/** The zero-argument SEP-41 getters, simulated against every contract. */
const READ_FUNCTIONS = ['decimals', 'name', 'symbol'] as const;

export interface SimulationOptions {
  rules?: RuleOverrides;
  /** The file path that named the contract, attached to every diagnostic. */
  path?: string;
  /** Soroban RPC endpoint, overriding the one derived from the passphrase. */
  rpcUrl?: string;
  /** Network passphrase used to build the invocation envelope. */
  networkPassphrase?: string;
  /** Source account for the simulation envelope. */
  sourceAccount?: string;
  /** Address passed to `balance`, defaulting to the source account. */
  dummyAddress?: string;
  /** CPU instruction ceiling before `excessive-resource-consumption` fires. */
  maxInstructions?: number;
  /** Memory ceiling in bytes before `excessive-resource-consumption` fires. */
  maxMemoryBytes?: number;
}

/** Arguments for one simulated SEP-41 call. */
function invocationArgs(fnName: string, dummyAddress: string): xdr.ScVal[] {
  if (fnName === 'balance') return [new Address(dummyAddress).toScVal()];
  return [];
}

/**
 * Builds the base64 `TransactionEnvelope` for an `InvokeHostFunctionOp` calling
 * `fnName` on `contractId`. The transaction is never signed or submitted; it is
 * only an envelope for `simulateTransaction` to dry-run.
 */
export function buildInvokeTransaction(
  contractId: string,
  fnName: string,
  dummyAddress: string,
  options: SimulationOptions = {},
): string {
  const source = options.sourceAccount ?? DEFAULT_SOURCE_ACCOUNT;
  const hostFunction = xdr.HostFunction.hostFunctionTypeInvokeContract(
    new xdr.InvokeContractArgs({
      contractAddress: new Address(contractId).toScAddress(),
      functionName: fnName,
      args: invocationArgs(fnName, dummyAddress),
    }),
  );

  const transaction = new TransactionBuilder(new Account(source, '0'), {
    fee: '100',
    networkPassphrase: options.networkPassphrase ?? NETWORK_PASSPHRASE,
  })
    .addOperation(Operation.invokeHostFunction({ func: hostFunction, auth: [] }))
    .setTimeout(30)
    .build();

  return transaction.toEnvelope().toXDR('base64');
}

interface SimulationResponse {
  error?: unknown;
  result?: Record<string, unknown>;
}

/** The resource usage a successful simulation reports. */
interface ResourceUsage {
  instructions?: number;
  memoryBytes?: number;
}

function usageOf(result: Record<string, unknown>): ResourceUsage {
  const usage: ResourceUsage = {};

  const transactionData = result.transactionData;
  if (typeof transactionData === 'string') {
    try {
      const data = xdr.SorobanTransactionData.fromXDR(transactionData, 'base64');
      usage.instructions = data.resources().instructions();
    } catch {
      // A transactionData we cannot parse simply yields no metric.
    }
  }

  const cost = result.cost;
  if (typeof cost === 'object' && cost !== null) {
    const c = cost as Record<string, unknown>;
    const instructions = Number(c.cpuInsns);
    if (Number.isFinite(instructions)) usage.instructions = instructions;
    const memory = Number(c.memBytes);
    if (Number.isFinite(memory)) usage.memoryBytes = memory;
  }

  return usage;
}

/** POSTs one `simulateTransaction`. `undefined` means the RPC could not answer. */
async function simulateCall(
  rpcUrl: string,
  envelope: string,
  fetchImpl: typeof fetch,
): Promise<SimulationResponse | undefined> {
  try {
    const response = await fetchImpl(rpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'simulateTransaction',
        params: { transaction: envelope },
      }),
      signal: AbortSignal.timeout(RPC_TIMEOUT_MS),
    });
    if (!response.ok) return undefined;
    const body = (await response.json()) as SimulationResponse;
    return typeof body === 'object' && body !== null ? body : undefined;
  } catch {
    return undefined;
  }
}

/** The reason a simulation did not produce a usable result, or `undefined`. */
function failureReason(response: SimulationResponse): string | undefined {
  if (response.error !== undefined && response.error !== null) {
    if (typeof response.error === 'string') return response.error;
    const message = (response.error as Record<string, unknown>).message;
    return typeof message === 'string' ? message : 'the RPC returned an error';
  }
  const result = response.result;
  if (result === undefined) return 'the RPC returned no simulation result';
  if (typeof result.error === 'string') return result.error;
  if (!('transactionData' in result) && !Array.isArray(result.results)) {
    return 'the RPC returned no simulation result';
  }
  return undefined;
}

function simulationFinding(
  contractId: string,
  options: SimulationOptions,
): (
  rule: string,
  fallback: 'error' | 'warning',
  detail: string,
  suggestion?: string,
) => Diagnostic[] {
  return (rule, fallback, detail, suggestion) => {
    const severity = severityFor(rule, fallback, options.rules);
    if (severity === undefined) return [];
    return [
      {
        rule,
        severity,
        category: 'network',
        message: `Contract ${contractId} ${detail}`,
        ...(options.path !== undefined ? { path: options.path } : {}),
        ...(suggestion !== undefined ? { suggestion } : {}),
      },
    ];
  };
}

/**
 * Dry-runs the SEP-41 read functions against one contract and reports the call
 * that reverted, plus any that consume more CPU or memory than expected.
 */
export async function simulateContract(
  contractId: string,
  rpcUrl: string,
  fetchImpl: typeof fetch = fetch,
  options: SimulationOptions = {},
): Promise<Diagnostic[]> {
  const dummyAddress = options.dummyAddress ?? options.sourceAccount ?? DEFAULT_SOURCE_ACCOUNT;
  const maxInstructions = options.maxInstructions ?? DEFAULT_MAX_INSTRUCTIONS;
  const maxMemoryBytes = options.maxMemoryBytes ?? DEFAULT_MAX_MEMORY_BYTES;
  const finding = simulationFinding(contractId, options);
  const diagnostics: Diagnostic[] = [];

  for (const fnName of [...READ_FUNCTIONS, 'balance'] as string[]) {
    const envelope = buildInvokeTransaction(contractId, fnName, dummyAddress, options);
    const response = await simulateCall(rpcUrl, envelope, fetchImpl);
    if (response === undefined) continue;

    const reason = failureReason(response);
    if (reason !== undefined) {
      diagnostics.push(
        ...finding(
          SIMULATION_FAILED_RULE,
          'error',
          `reverted when simulating ${fnName}(): ${reason}`,
          `Fix ${fnName}() so the call succeeds on the target network.`,
        ),
      );
      continue;
    }

    const usage = usageOf(response.result!);
    if (usage.instructions !== undefined && usage.instructions > maxInstructions) {
      diagnostics.push(
        ...finding(
          EXCESSIVE_RESOURCE_RULE,
          'warning',
          `${fnName}() consumes ${usage.instructions} CPU instructions, over the ${maxInstructions} budget`,
          `Reduce ${fnName}()'s work, or raise the resource ceiling for callers.`,
        ),
      );
    }
    if (usage.memoryBytes !== undefined && usage.memoryBytes > maxMemoryBytes) {
      diagnostics.push(
        ...finding(
          EXCESSIVE_RESOURCE_RULE,
          'warning',
          `${fnName}() allocates ${usage.memoryBytes} bytes of memory, over the ${maxMemoryBytes} budget`,
          `Reduce ${fnName}()'s memory use, or raise the resource ceiling for callers.`,
        ),
      );
    }
  }

  return diagnostics;
}

/**
 * Simulates every contract the file declares under `[[CURRENCIES]]`. Silent
 * when no RPC URL can be derived.
 */
export async function auditTomlContractSimulation(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: SimulationOptions = {},
): Promise<Diagnostic[]> {
  const passphrase =
    typeof doc.NETWORK_PASSPHRASE === 'string' ? doc.NETWORK_PASSPHRASE : undefined;
  const rpcUrl = options.rpcUrl ?? rpcUrlFor(passphrase);
  if (!rpcUrl) return [];

  const diagnostics: Diagnostic[] = [];
  for (const currency of contractCurrenciesOf(doc)) {
    diagnostics.push(
      ...(await simulateContract(currency.id, rpcUrl, fetchImpl, {
        ...options,
        networkPassphrase: options.networkPassphrase ?? passphrase,
        path: currency.path,
      })),
    );
  }
  return diagnostics;
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const simulationRules: Rule[] = [
  {
    id: SIMULATION_FAILED_RULE,
    category: 'network',
    severity: 'error',
    description: 'A simulated SEP-41 contract call reverted on the Soroban RPC',
    run() {},
  },
  {
    id: EXCESSIVE_RESOURCE_RULE,
    category: 'network',
    severity: 'warning',
    description: 'A Soroban contract call consumes excessive CPU or memory',
    run() {},
  },
];

/** Rule ids emitted by {@link auditTomlContractSimulation}. */
export const simulationRuleIds: readonly string[] = simulationRules.map((rule) => rule.id);
