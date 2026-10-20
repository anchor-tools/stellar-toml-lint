import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isAccountId } from '../predicates.js';
import { horizonUrlFor } from '../network-checks.js';

export const SECURITY_INSUFFICIENT_MPC_THRESHOLD = 'security/insufficient-mpc-threshold';

interface MpcGovernanceOptions {
  rules?: RuleOverrides;
  fetchImpl?: typeof fetch;
}

interface MpcDisclosure {
  provider: string;
  certificationUrl: string;
  threshold: number;
  participants: number;
  signerKeys: string[];
}

function severityFor(rules?: RuleOverrides): 'warning' | 'error' | undefined {
  const override = rules?.[SECURITY_INSUFFICIENT_MPC_THRESHOLD];
  if (override === 'off') return undefined;
  return override === 'error' ? 'error' : 'warning';
}

function finding(message: string, rules?: RuleOverrides): Diagnostic[] {
  const severity = severityFor(rules);
  return severity === undefined
    ? []
    : [
        {
          rule: SECURITY_INSUFFICIENT_MPC_THRESHOLD,
          severity,
          category: 'network',
          message,
          path: 'MPC_GOVERNANCE',
          suggestion:
            'Publish an independently verifiable provider certification and a threshold of at least 2-of-n with matching on-chain signer weights.',
        },
      ];
}

function parseDisclosure(
  doc: Record<string, unknown>,
  rules?: RuleOverrides,
): {
  disclosure?: MpcDisclosure;
  diagnostics: Diagnostic[];
} {
  const value = doc.MPC_GOVERNANCE;
  if (value === undefined) return { diagnostics: [] };
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return { diagnostics: finding('MPC_GOVERNANCE must be a table', rules) };
  }

  const table = value as Record<string, unknown>;
  const provider = table.PROVIDER;
  const certificationUrl = table.CERTIFICATION_URL;
  const threshold = table.THRESHOLD;
  const participants = table.PARTICIPANTS;
  const signerKeys = table.SIGNER_KEYS;
  const diagnostics: Diagnostic[] = [];

  if (typeof provider !== 'string' || provider.trim() === '') {
    diagnostics.push(...finding('MPC provider name is missing', rules));
  }
  let validCertificationUrl = false;
  if (typeof certificationUrl === 'string') {
    try {
      validCertificationUrl = new URL(certificationUrl).protocol === 'https:';
    } catch {
      validCertificationUrl = false;
    }
  }
  if (!validCertificationUrl) {
    diagnostics.push(...finding('MPC provider certification URL must use HTTPS', rules));
  }

  if (
    !Number.isInteger(threshold) ||
    !Number.isInteger(participants) ||
    (threshold as number) < 2 ||
    (participants as number) < (threshold as number)
  ) {
    diagnostics.push(
      ...finding(
        'MPC threshold must be at least 2 and no greater than its participant count',
        rules,
      ),
    );
  }

  if (
    !Array.isArray(signerKeys) ||
    signerKeys.length !== participants ||
    !signerKeys.every(isAccountId) ||
    new Set(signerKeys).size !== signerKeys.length
  ) {
    diagnostics.push(
      ...finding(
        'MPC SIGNER_KEYS must contain one unique Stellar account ID per participant',
        rules,
      ),
    );
  }

  if (
    diagnostics.length > 0 ||
    typeof provider !== 'string' ||
    typeof certificationUrl !== 'string' ||
    !Number.isInteger(threshold) ||
    !Number.isInteger(participants) ||
    !Array.isArray(signerKeys)
  ) {
    return { diagnostics };
  }

  return {
    disclosure: {
      provider,
      certificationUrl,
      threshold: threshold as number,
      participants: participants as number,
      signerKeys,
    },
    diagnostics,
  };
}

/** Audits an advertised MPC custody declaration under `--check-network`. */
export async function checkMpcGovernance(
  doc: Record<string, unknown>,
  options: MpcGovernanceOptions = {},
): Promise<Diagnostic[]> {
  const { disclosure, diagnostics } = parseDisclosure(doc, options.rules);
  if (!disclosure || severityFor(options.rules) === undefined) return diagnostics;

  const fetchImpl = options.fetchImpl ?? fetch;
  try {
    const certification = await fetchImpl(disclosure.certificationUrl, { redirect: 'follow' });
    if (!certification.ok) {
      diagnostics.push(
        ...finding(
          `MPC provider certification returned HTTP ${certification.status}`,
          options.rules,
        ),
      );
      await certification.body?.cancel();
    } else {
      const attestation = (await certification.json()) as {
        provider?: unknown;
        threshold?: unknown;
        participants?: unknown;
      };
      if (
        attestation.provider !== disclosure.provider ||
        !Number.isInteger(attestation.threshold) ||
        (attestation.threshold as number) < disclosure.threshold ||
        !Number.isInteger(attestation.participants) ||
        (attestation.participants as number) < disclosure.participants
      ) {
        diagnostics.push(
          ...finding(
            'MPC provider certification does not cover the declared provider and threshold',
            options.rules,
          ),
        );
      }
    }
  } catch {
    diagnostics.push(...finding('MPC provider certification could not be reached', options.rules));
  }

  const signingKey = doc.SIGNING_KEY;
  if (typeof signingKey !== 'string' || !isAccountId(signingKey)) {
    diagnostics.push(
      ...finding('SIGNING_KEY is unavailable for the MPC on-chain signer check', options.rules),
    );
    return diagnostics;
  }

  const passphrase =
    typeof doc.NETWORK_PASSPHRASE === 'string' ? doc.NETWORK_PASSPHRASE : undefined;
  try {
    const response = await fetchImpl(
      `${horizonUrlFor(passphrase)}/accounts/${encodeURIComponent(signingKey)}`,
    );
    if (!response.ok) {
      diagnostics.push(
        ...finding(`MPC signer account returned HTTP ${response.status}`, options.rules),
      );
      return diagnostics;
    }

    const account = (await response.json()) as {
      thresholds?: { med_threshold?: unknown; high_threshold?: unknown };
      signers?: { key?: unknown; weight?: unknown }[];
    };
    const signers = account.signers;
    const med = account.thresholds?.med_threshold;
    const high = account.thresholds?.high_threshold;
    if (!Array.isArray(signers) || !Number.isInteger(med) || !Number.isInteger(high)) {
      diagnostics.push(
        ...finding(
          'Horizon returned incomplete signer thresholds for the MPC account',
          options.rules,
        ),
      );
      return diagnostics;
    }

    let declaredWeight = 0;
    for (const signerKey of disclosure.signerKeys) {
      const signer = signers.find((candidate) => candidate.key === signerKey);
      if (
        signer === undefined ||
        !Number.isInteger(signer.weight) ||
        (signer.weight as number) <= 0
      ) {
        diagnostics.push(
          ...finding(
            `Declared MPC signer ${signerKey} is not an active on-chain signer`,
            options.rules,
          ),
        );
        continue;
      }
      declaredWeight += signer.weight as number;
    }
    if (declaredWeight < (med as number) || declaredWeight < (high as number)) {
      diagnostics.push(
        ...finding(
          'Declared MPC signer weight cannot meet the on-chain medium and high thresholds',
          options.rules,
        ),
      );
    }
  } catch {
    diagnostics.push(
      ...finding('MPC signer thresholds could not be verified on Horizon', options.rules),
    );
  }

  return diagnostics;
}

export const mpcGovernanceRules: Rule[] = [
  {
    id: SECURITY_INSUFFICIENT_MPC_THRESHOLD,
    category: 'network',
    severity: 'warning',
    description: 'MPC custody disclosure must meet threshold and on-chain signer requirements',
    run() {},
  },
];
