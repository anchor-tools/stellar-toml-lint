export const CURRENCIES_UNDISCLOSED_CLAWBACK_ENABLED = 'currencies/undisclosed-clawback-enabled';
export const CURRENCIES_MISMATCHED_AUTH_REVOCABLE_FLAG =
  'currencies/mismatched-auth-revocable-flag';

/** Regulatory account flags as reported by Horizon. */
export interface IssuerAccountFlags {
  auth_clawback_enabled?: boolean;
  auth_revocable?: boolean;
  auth_required?: boolean;
}

/** Asset entry from stellar.toml `[CURRENCIES]` documentation. */
export interface AssetClawbackDocumentation {
  clawback_enabled?: boolean;
  auth_revocable?: boolean;
  auth_required?: boolean;
}

/**
 * Compares the issuer's on-chain regulatory flags with what the stellar.toml
 * asset entry documents and emits diagnostics for undisclosed or mismatched
 * clawback / revocability controls (CAP-35).
 */
export function auditClawbackAndFreeze(
  asset: AssetClawbackDocumentation,
  horizonAccountFlags: IssuerAccountFlags,
): string[] {
  const diagnostics: string[] = [];
  const onChainClawback = horizonAccountFlags.auth_clawback_enabled ?? false;
  if (onChainClawback && !asset.clawback_enabled) {
    diagnostics.push(CURRENCIES_UNDISCLOSED_CLAWBACK_ENABLED);
  }
  const onChainRevocable = horizonAccountFlags.auth_revocable ?? false;
  if (onChainRevocable !== (asset.auth_revocable ?? false)) {
    diagnostics.push(CURRENCIES_MISMATCHED_AUTH_REVOCABLE_FLAG);
  }
  return diagnostics;
}
