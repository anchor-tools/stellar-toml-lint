import { describe, expect, it } from 'vitest';
import { lint } from '../src/lint.js';
import type { Diagnostic } from '../src/types.js';

const NETWORK_PASSPHRASE = 'Public Global Stellar Network ; September 2015';

const MODERN_TOML = `
VERSION = "2.7.0"
NETWORK_PASSPHRASE = "${NETWORK_PASSPHRASE}"
FEDERATION_SERVER = "https://api.example.com/federation"

[DOCUMENTATION]
ORG_NAME = "Example"
ORG_URL = "https://example.com"
ORG_DESCRIPTION = "Example organization"
ORG_LOGO = "https://example.com/logo.png"
ORG_OFFICIAL_EMAIL = "ops@example.com"
`;

const LEGACY_TOML = `
VERSION = "2.7.0"
NETWORK_PASSPHRASE = "${NETWORK_PASSPHRASE}"
FEDERATION_SERVER = "http://api.example.com/federation"
AUTH_SERVER = "https://api.example.com/auth"
DEPOSIT_SERVER = "https://api.example.com"
ORG_NAME = "Example"
`;

function deprecations(diagnostics: Diagnostic[]): Diagnostic[] {
  return diagnostics.filter((diagnostic) => diagnostic.rule === 'general/deprecated-field');
}

describe('deprecated SEP-1 fields', () => {
  it('accepts modern federation and documentation configuration', () => {
    const result = lint(MODERN_TOML, { strict: true });

    expect(result.diagnostics).toEqual([]);
    expect(result.ok).toBe(true);
  });

  it('warns with replacement syntax for legacy configuration', () => {
    const result = lint(LEGACY_TOML);
    const diagnostics = deprecations(result.diagnostics);

    expect(diagnostics).toHaveLength(4);
    expect(diagnostics.map((diagnostic) => diagnostic.path)).toEqual([
      'FEDERATION_SERVER',
      'AUTH_SERVER',
      'DEPOSIT_SERVER',
      'ORG_NAME',
    ]);
    expect(diagnostics.every((diagnostic) => diagnostic.severity === 'warning')).toBe(true);
    expect(diagnostics[0]?.suggestion).toContain('FEDERATION_SERVER = "https://');
    expect(diagnostics[1]?.suggestion).toContain('WEB_AUTH_ENDPOINT');
    expect(diagnostics[1]?.suggestion).toContain('KYC_SERVER');
    expect(diagnostics[2]?.suggestion).toContain('TRANSFER_SERVER');
    expect(diagnostics[3]?.suggestion).toContain('[DOCUMENTATION]');
  });
});
