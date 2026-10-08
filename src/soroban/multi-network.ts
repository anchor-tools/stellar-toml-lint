/**
 * The same contract, checked on every public network at once.
 *
 * Anchors run a testnet deployment side by side with mainnet, and a
 * `stellar.toml` is trivially copy-pasted between the two — swap the
 * passphrase, keep the `C...` addresses. A wallet that resolves such a file
 * asks mainnet for a token that only ever existed on testnet, and gets "not
 * found" with nothing to explain it.
 *
 * So this audit asks each network's Soroban RPC the same question — is there a
 * live contract instance at this address? — and compares the answers. Only a
 * positive answer elsewhere counts: absence from the declared network on its
 * own is already `soroban/contract-not-found` under `--check-contracts`, and
 * re-reporting an unknown as a mismatch would turn an RPC outage into a false
 * error. Consistent with the rest of the network-bound checks, an endpoint that
 * cannot be reached diagnoses nothing.
 */
import { Networks } from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';
import { isString, isUrl } from '../predicates.js';
import { rpcUrlFor } from '../rules/display-decimals-audit.js';
import { contractCurrenciesOf } from '../rules/currencies.js';
import { webAuthContractIdOf } from '../rules/general.js';
import { contractDataInstanceKey, queryLedgerEntry } from '../soroban.js';

const CONTRACT_ONLY_ON_TESTNET_RULE = 'soroban/contract-only-on-testnet';
const NETWORK_MISMATCH_RULE = 'soroban/network-mismatch';

const NETWORKS_HELP_URI = 'https://developers.stellar.org/docs/networks';

/** One of the networks a contract can be live on. */
export interface NetworkTarget {
  name: 'mainnet' | 'testnet' | 'futurenet';
  passphrase: string;
  rpcUrl: string;
}

/** What a probe learned about one network. */
export type ContractPresence = 'deployed' | 'absent' | 'unknown';

const NETWORK_PASSPHRASES = {
  mainnet: Networks.PUBLIC,
  testnet: Networks.TESTNET,
  futurenet: Networks.FUTURENET,
} as const;

/**
 * The networks worth comparing. Only those with a public Soroban RPC URL are
 * listed, so a network whose endpoint this package does not know is simply not
 * part of the comparison rather than being guessed at.
 */
export const NETWORK_TARGETS: readonly NetworkTarget[] = (
  Object.entries(NETWORK_PASSPHRASES) as [NetworkTarget['name'], string][]
).flatMap(([name, passphrase]): NetworkTarget[] => {
  const rpcUrl = rpcUrlFor(passphrase);
  return rpcUrl === undefined ? [] : [{ name, passphrase, rpcUrl }];
});

/** The network a file's own `NETWORK_PASSPHRASE` names, when we know it. */
export function networkTargetFor(passphrase: unknown): NetworkTarget | undefined {
  if (!isString(passphrase)) return undefined;
  return NETWORK_TARGETS.find((target) => target.passphrase === passphrase);
}

interface MultiNetworkOptions {
  rules?: RuleOverrides;
  /** Compare against these networks; defaults to every known public network. */
  targets?: readonly NetworkTarget[];
}

function severityFor(
  rule: string,
  fallback: Severity,
  rules?: RuleOverrides,
): Severity | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' || override === 'info'
    ? override
    : fallback;
}

/**
 * Asks one network's Soroban RPC whether a contract instance is live there.
 * `unknown` means the RPC did not answer usefully — outage, timeout, malformed
 * reply — which is deliberately distinct from `absent`.
 */
export async function probeContractPresence(
  contractId: string,
  target: NetworkTarget,
  fetchImpl: typeof fetch = fetch,
): Promise<ContractPresence> {
  const entry = await queryLedgerEntry(
    target.rpcUrl,
    contractDataInstanceKey(contractId),
    fetchImpl,
  );
  if (entry === undefined) return 'unknown';
  return entry.liveUntil === undefined ? 'absent' : 'deployed';
}

/** Every contract a file declares, with the path that named it. */
function declaredContracts(doc: Record<string, unknown>): { id: string; path: string }[] {
  const auth = webAuthContractIdOf(doc);
  return [
    ...contractCurrenciesOf(doc).map(({ id, path }) => ({ id, path })),
    ...(auth === undefined ? [] : [auth]),
  ];
}

function finding(
  rule: string,
  fallback: Severity,
  message: string,
  path: string,
  suggestion: string,
  rules?: RuleOverrides,
): Diagnostic[] {
  const severity = severityFor(rule, fallback, rules);
  if (severity === undefined) return [];
  return [
    {
      rule,
      severity,
      category: 'network',
      message,
      path,
      helpUri: NETWORKS_HELP_URI,
      suggestion,
    },
  ];
}

/**
 * Cross-checks the contract IDs a file declares against every public network.
 *
 * `deployments` maps contract id → network name → presence, so a caller that
 * has already probed can pass the answers in. Supplying an entry for a contract
 * ends the probing for that contract: networks it does not name are treated as
 * `unknown`, so a caller's partial cache is never silently completed with live
 * requests the caller did not expect.
 */
export async function checkMultiNetworkDeployments(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: MultiNetworkOptions & {
    deployments?: Record<string, Partial<Record<NetworkTarget['name'], ContractPresence>>>;
  } = {},
): Promise<Diagnostic[]> {
  const declared = networkTargetFor(doc.NETWORK_PASSPHRASE);
  if (declared === undefined) return [];

  const targets = options.targets ?? NETWORK_TARGETS;
  const contracts = declaredContracts(doc);
  const diagnostics: Diagnostic[] = [];

  for (const contract of contracts) {
    const cached = options.deployments?.[contract.id];
    const onNetwork = (target: NetworkTarget): Promise<ContractPresence> => {
      if (cached === undefined) return probeContractPresence(contract.id, target, fetchImpl);
      return Promise.resolve(cached[target.name] ?? 'unknown');
    };

    const here = await onNetwork(declared);
    if (here !== 'absent') continue;

    const elsewhere: NetworkTarget[] = [];
    for (const target of targets) {
      if (target.name === declared.name) continue;
      if ((await onNetwork(target)) === 'deployed') elsewhere.push(target);
    }
    if (elsewhere.length === 0) continue;

    const found = elsewhere.map((target) => target.name).join(', ');
    if (declared.name === 'mainnet' && elsewhere.some((t) => t.name === 'testnet')) {
      diagnostics.push(
        ...finding(
          CONTRACT_ONLY_ON_TESTNET_RULE,
          'error',
          `Contract ${contract.id} is deployed on Testnet but not on the Mainnet this file describes`,
          contract.path,
          `Publish the Mainnet deployment, or point ${contract.path} at the contract that is live on Mainnet. Found on: ${found}.`,
          options.rules,
        ),
      );
      continue;
    }

    diagnostics.push(
      ...finding(
        NETWORK_MISMATCH_RULE,
        'error',
        `Contract ${contract.id} is absent from ${declared.name}, the network this file declares, but live on ${found}`,
        contract.path,
        `A wallet resolves ${contract.path} on ${declared.name} only. Deploy it there, or set NETWORK_PASSPHRASE to the network that has it.`,
        options.rules,
      ),
    );
  }

  return diagnostics;
}

/**
 * Flags a file whose `HORIZON_URL` serves a different network from its
 * `NETWORK_PASSPHRASE`.
 *
 * The two are read by different clients — Horizon by indexers and browsers, the
 * passphrase by everyone signing — so a mixed pair sends half the integrators
 * to the other network's ledgers, where none of the declared contracts exist.
 * Runs offline: it is a comparison of two strings already in the file.
 */
export function horizonPassphraseMismatch(doc: Record<string, unknown>): Diagnostic[] {
  const declared = networkTargetFor(doc.NETWORK_PASSPHRASE);
  const horizon = doc.HORIZON_URL;
  if (declared === undefined || !isString(horizon) || !isUrl(horizon)) return [];

  let served: NetworkTarget | undefined;
  try {
    const host = new URL(horizon).hostname;
    if (host.includes('horizon-testnet')) served = networkTargetFor(Networks.TESTNET);
    else if (host.includes('futurenet')) served = networkTargetFor(Networks.FUTURENET);
    else if (host === 'horizon.stellar.org') served = networkTargetFor(Networks.PUBLIC);
  } catch {
    return [];
  }

  if (served === undefined || served.name === declared.name) return [];

  return finding(
    NETWORK_MISMATCH_RULE,
    'error',
    `HORIZON_URL serves ${served.name} but NETWORK_PASSPHRASE is ${declared.name}`,
    'HORIZON_URL',
    'Point both at the same network — clients that follow one but not the other resolve contracts that are not there.',
    undefined,
  );
}

/**
 * The `--check-network` entry point: contract cross-network comparison plus the
 * file's own Horizon/passphrase agreement.
 */
export async function checkNetworkConsistency(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: MultiNetworkOptions = {},
): Promise<Diagnostic[]> {
  return [
    ...horizonPassphraseMismatch(doc),
    ...(await checkMultiNetworkDeployments(doc, fetchImpl, options)),
  ];
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const multiNetworkRules: Rule[] = [
  {
    id: CONTRACT_ONLY_ON_TESTNET_RULE,
    category: 'network',
    severity: 'error',
    description: 'A declared Soroban contract exists only on Testnet while the file is Mainnet',
    run() {},
  },
  {
    id: NETWORK_MISMATCH_RULE,
    category: 'network',
    severity: 'error',
    description: 'A contract or endpoint is on a different network than NETWORK_PASSPHRASE',
    run() {},
  },
];

/** Rule ids emitted by {@link checkNetworkConsistency}. */
export const multiNetworkRuleIds: readonly string[] = multiNetworkRules.map((rule) => rule.id);
