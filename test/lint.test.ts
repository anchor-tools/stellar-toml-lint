import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { lint } from '../src/lint.js';
import { allRules } from '../src/rules/index.js';
import type { Diagnostic, LintResult, Severity } from '../src/types.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string): string => readFileSync(join(here, 'fixtures', name), 'utf8');

/** Rule ids reported at or above `severity`. */
function rules(result: LintResult, severity?: Severity): string[] {
  return result.diagnostics
    .filter((d) => severity === undefined || d.severity === severity)
    .map((d) => d.rule);
}

function find(result: LintResult, rule: string): Diagnostic[] {
  return result.diagnostics.filter((d) => d.rule === rule);
}

/**
 * Wraps a document body so rules that need context are satisfied.
 *
 * The body is emitted *before* `[DOCUMENTATION]`: TOML captures every key
 * under the preceding table header, so a global field placed after the
 * section would silently become `DOCUMENTATION.<field>`.
 */
function withValidBase(body: string): string {
  return [
    'VERSION="2.7.0"',
    'NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"',
    body,
    '',
    '[DOCUMENTATION]',
    'ORG_NAME="Example"',
    'ORG_URL="https://example.com"',
    'ORG_DESCRIPTION="Example"',
    'ORG_LOGO="https://example.com/logo.png"',
    'ORG_OFFICIAL_EMAIL="ops@example.com"',
  ].join('\n');
}

const ACCOUNT_A = 'GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS';
const ACCOUNT_B = 'GC7T6T56DX23PT7Q6WGCTIJT5O6TP6SJ47RP73JCA3ISLVCCVMGHNSDI';
const CONTRACT_A = 'CACTZSQPCQSSZ5YG3PI3N7WO6JEERKEUHTPILKB4MBANF2K4D2UHKDDU';

describe('valid fixture', () => {
  const result = lint(fixture('valid.toml'), { domain: 'example.com' });

  it('reports no diagnostics at all', () => {
    // Printed on failure so a new false positive is immediately identifiable.
    expect(result.diagnostics.map((d) => `${d.severity} ${d.rule}: ${d.message}`)).toEqual([]);
  });

  it('passes in strict mode', () => {
    expect(result.ok).toBe(true);
  });

  it('exposes the parsed document', () => {
    expect(result.parsed?.VERSION).toBe('2.7.0');
  });
});

describe('broken fixture', () => {
  const result = lint(fixture('broken.toml'), { domain: 'example.com' });

  it('fails overall', () => {
    expect(result.ok).toBe(false);
    expect(result.counts.error).toBeGreaterThan(0);
  });

  it.each([
    'general/version',
    'network/passphrase',
    'general/https-endpoints',
    'general/trailing-slash-in-endpoint',
    'general/signing-keys',
    'general/accounts',
    'general/sep31-requires-kyc',
    'general/auth-requires-signing-key',
    'general/deprecated-field',
    'general/unknown-field',
    'documentation/urls',
    'documentation/emails',
    'documentation/phone-e164',
    'documentation/social-handles',
    'documentation/attestation-domain',
    'documentation/org-url-matches-domain',
    'principals/required-fields',
    'principals/photo-hashes',
    'principals/social-handles',
    'currencies/code',
    'currencies/issuer-or-contract',
    'currencies/issuance-exclusive',
    'currencies/enums',
    'currencies/display-decimals',
    'currencies/name-length',
    'currencies/regulated-needs-approval-server',
    'currencies/regulated-invalid-target',
    'currencies/collateral-consistency',
    'validators/alias',
    'validators/public-key',
    'validators/host',
    'validators/invalid-history-url',
  ])('detects %s', (rule) => {
    expect(rules(result)).toContain(rule);
  });

  it('gives every diagnostic a message and a rule id', () => {
    for (const d of result.diagnostics) {
      expect(d.message.length).toBeGreaterThan(0);
      expect(d.rule).toMatch(/^[a-z]+\/[a-z0-9-]+$/);
    }
  });

  it('sorts errors before warnings before info', () => {
    const order = { error: 0, warning: 1, info: 2 } as const;
    const ranks = result.diagnostics.map((d) => order[d.severity]);
    expect(ranks).toEqual([...ranks].sort((a, b) => a - b));
  });
});

describe('parse failures', () => {
  it('reports a positioned syntax error', () => {
    const result = lint('VERSION="1.0.0"\nthis is not toml\n');
    expect(rules(result)).toEqual(['file/parse']);
    expect(result.diagnostics[0]?.position?.line).toBe(2);
  });

  it('does not run semantic rules when parsing fails', () => {
    const result = lint('[[[bad');
    expect(result.diagnostics).toHaveLength(1);
    expect(result.parsed).toBeUndefined();
  });

  it('accepts an empty file without crashing', () => {
    const result = lint('');
    expect(result.parsed).toEqual({});
    expect(rules(result, 'error')).toEqual([]);
  });

  it('flags a byte order mark but still lints the rest', () => {
    // U+FEFF written as an escape so it stays visible in review.
    const result = lint(`\uFEFF${fixture('valid.toml')}`, { domain: 'example.com' });
    expect(rules(result)).toEqual(['file/encoding']);
  });
});

describe('network/passphrase', () => {
  it('accepts the three documented networks', () => {
    for (const passphrase of [
      'Public Global Stellar Network ; September 2015',
      'Test SDF Network ; September 2015',
      'Test SDF Future Network ; October 2022',
    ]) {
      const result = lint(`NETWORK_PASSPHRASE="${passphrase}"`);
      expect(find(result, 'network/passphrase')).toEqual([]);
    }
  });

  it('calls out stray whitespace with the exact replacement', () => {
    const result = lint('NETWORK_PASSPHRASE="Public Global Stellar Network;September 2015"');
    const [d] = find(result, 'network/passphrase');
    expect(d?.message).toContain('stray whitespace');
    expect(d?.suggestion).toContain('Public Global Stellar Network ; September 2015');
  });

  it('rejects an unrecognised passphrase', () => {
    const result = lint('NETWORK_PASSPHRASE="My Private Chain"');
    expect(find(result, 'network/passphrase')[0]?.severity).toBe('error');
  });
});

describe('checksum validation', () => {
  it('rejects a G-key whose checksum has been altered', () => {
    const broken = `${ACCOUNT_A.slice(0, -1)}X`;
    const result = lint(`SIGNING_KEY="${broken}"`);
    expect(find(result, 'general/signing-keys')).toHaveLength(1);
  });

  it('tells you when a contract ID was used as an account ID', () => {
    const result = lint(`SIGNING_KEY="${CONTRACT_A}"`);
    expect(find(result, 'general/signing-keys')[0]?.message).toContain('contract');
  });

  it('accepts a correct key', () => {
    const result = lint(`SIGNING_KEY="${ACCOUNT_A}"`);
    expect(find(result, 'general/signing-keys')).toEqual([]);
  });
});

describe('currencies/issuance-exclusive', () => {
  it('rejects two issuance policies at once', () => {
    const result = lint(
      withValidBase(
        `[[CURRENCIES]]\ncode="AAA"\nissuer="${ACCOUNT_A}"\nfixed_number=10\nis_unlimited=true`,
      ),
    );
    const [d] = find(result, 'currencies/issuance-exclusive');
    expect(d?.severity).toBe('error');
    expect(d?.message).toContain('mutually exclusive');
  });

  it('warns when no issuance policy is declared', () => {
    const result = lint(withValidBase(`[[CURRENCIES]]\ncode="AAA"\nissuer="${ACCOUNT_A}"`));
    expect(find(result, 'currencies/issuance-exclusive')[0]?.severity).toBe('warning');
  });

  it('accepts exactly one', () => {
    const result = lint(
      withValidBase(`[[CURRENCIES]]\ncode="AAA"\nissuer="${ACCOUNT_A}"\nis_unlimited=true`),
    );
    expect(find(result, 'currencies/issuance-exclusive')).toEqual([]);
  });
});

describe('currencies/issuer-or-contract', () => {
  it('rejects an entry with neither', () => {
    const result = lint(withValidBase('[[CURRENCIES]]\ncode="AAA"\nis_unlimited=true'));
    expect(find(result, 'currencies/issuer-or-contract')[0]?.message).toContain('neither');
  });

  it('rejects an entry with both', () => {
    const result = lint(
      withValidBase(
        `[[CURRENCIES]]\ncode="AAA"\nissuer="${ACCOUNT_A}"\ncontract="${CONTRACT_A}"\nis_unlimited=true`,
      ),
    );
    expect(find(result, 'currencies/issuer-or-contract')[0]?.message).toContain(
      'mutually exclusive',
    );
  });

  it('accepts a SEP-41 contract token', () => {
    const result = lint(
      withValidBase(`[[CURRENCIES]]\ncode="AAA"\ncontract="${CONTRACT_A}"\nis_unlimited=true`),
    );
    expect(find(result, 'currencies/issuer-or-contract')).toEqual([]);
  });
});

describe('the native asset', () => {
  // XLM has no issuing account, so requiring one is a false positive. The SDF's
  // own reference anchor publishes `code = "native"` with no issuer.
  const native = '[[CURRENCIES]]\ncode="native"\nstatus="live"\nis_asset_anchored=false';

  it('does not demand an issuer or contract', () => {
    const result = lint(withValidBase(native));
    expect(find(result, 'currencies/issuer-or-contract')).toEqual([]);
  });

  it('does not demand an issuance policy', () => {
    const result = lint(withValidBase(native));
    expect(find(result, 'currencies/issuance-exclusive')).toEqual([]);
  });

  it('flags an issuer wrongly attached to the native asset', () => {
    const result = lint(withValidBase(`[[CURRENCIES]]\ncode="native"\nissuer="${ACCOUNT_A}"`));
    expect(find(result, 'currencies/issuer-or-contract')[0]?.message).toContain('native asset');
  });

  it('treats bare XLM with no issuer as native', () => {
    const result = lint(withValidBase('[[CURRENCIES]]\ncode="XLM"'));
    expect(find(result, 'currencies/issuer-or-contract')).toEqual([]);
  });

  it('still requires an issuer for a non-native code', () => {
    const result = lint(withValidBase('[[CURRENCIES]]\ncode="USDC"'));
    expect(find(result, 'currencies/issuer-or-contract')).toHaveLength(1);
  });

  it('flags display_decimals on the native asset as info', () => {
    const result = lint(withValidBase('[[CURRENCIES]]\ncode="native"\ndisplay_decimals=2'));
    const [d] = find(result, 'currencies/display-decimals');
    expect(d?.severity).toBe('info');
    expect(d?.message).toContain('native asset');
    expect(d?.path).toBe('CURRENCIES[0].display_decimals');
  });

  it('flags display_decimals on bare XLM with no issuer', () => {
    const result = lint(withValidBase('[[CURRENCIES]]\ncode="XLM"\ndisplay_decimals=2'));
    expect(find(result, 'currencies/display-decimals')).toHaveLength(1);
  });

  it('stays silent when the native entry omits display_decimals', () => {
    const result = lint(withValidBase('[[CURRENCIES]]\ncode="native"'));
    expect(find(result, 'currencies/display-decimals')).toEqual([]);
  });

  it('stays silent when a non-native entry sets display_decimals', () => {
    const result = lint(
      withValidBase(
        `[[CURRENCIES]]\ncode="USDC"\nissuer="${ACCOUNT_A}"\ndisplay_decimals=2\nis_unlimited=true`,
      ),
    );
    expect(find(result, 'currencies/display-decimals')).toEqual([]);
  });
});

describe('currencies/toml-pointer', () => {
  it('accepts a pointer-only entry', () => {
    const result = lint(
      withValidBase('[[CURRENCIES]]\ntoml="https://example.com/.well-known/USD.toml"'),
    );
    expect(find(result, 'currencies/toml-pointer')).toEqual([]);
    // Field rules must not fire on a pointer entry.
    expect(find(result, 'currencies/code')).toEqual([]);
    expect(find(result, 'currencies/issuer-or-contract')).toEqual([]);
  });

  it('rejects a pointer entry with extra fields', () => {
    const result = lint(
      withValidBase('[[CURRENCIES]]\ntoml="https://example.com/USD.toml"\ncode="USD"'),
    );
    expect(find(result, 'currencies/toml-pointer')[0]?.message).toContain('code');
  });
});

describe('currencies/duplicate-asset', () => {
  it('flags the same code and issuer twice', () => {
    const entry = `[[CURRENCIES]]\ncode="AAA"\nissuer="${ACCOUNT_A}"\nis_unlimited=true`;
    const result = lint(withValidBase(`${entry}\n\n${entry}`));
    expect(find(result, 'currencies/duplicate-asset')).toHaveLength(1);
  });

  it('allows the same code from different issuers', () => {
    const result = lint(
      withValidBase(
        `[[CURRENCIES]]\ncode="AAA"\nissuer="${ACCOUNT_A}"\nis_unlimited=true\n\n` +
          `[[CURRENCIES]]\ncode="AAA"\nissuer="${ACCOUNT_B}"\nis_unlimited=true`,
      ),
    );
    expect(find(result, 'currencies/duplicate-asset')).toEqual([]);
  });
});

describe('source positions', () => {
  it('points at the right line inside an array of tables', () => {
    const source = [
      'VERSION="2.7.0"',
      '',
      '[[CURRENCIES]]',
      'code="AAA"',
      `issuer="${ACCOUNT_A}"`,
      'is_unlimited=true',
      '',
      '[[CURRENCIES]]',
      'code="BBB"',
      'issuer="not-a-key"',
      'is_unlimited=true',
    ].join('\n');

    const [d] = find(lint(source), 'currencies/issuer-or-contract');
    expect(d?.path).toBe('CURRENCIES[1].issuer');
    expect(d?.position?.line).toBe(10);
  });

  it('ignores a # inside a quoted value', () => {
    const source = 'VERSION="2.7.0"\nHORIZON_URL="https://h.example.com/#/nope"\n';
    expect(find(lint(source), 'file/parse')).toEqual([]);
  });

  it('locates a key inside [DOCUMENTATION]', () => {
    const source = 'VERSION="2.7.0"\n\n[DOCUMENTATION]\nORG_URL="http://example.com"\n';
    const [d] = find(lint(source), 'documentation/urls');
    expect(d?.position?.line).toBe(4);
  });
});

describe('validators/alias-reserved-keyword', () => {
  const validator = (alias: string): string =>
    withValidBase(
      `[[VALIDATORS]]\nALIAS="${alias}"\nPUBLIC_KEY="${ACCOUNT_A}"\nHOST="core.example.com:11625"`,
    );

  it.each(['self', 'all', 'default', 'none', 'quorum', 'peers', 'manual', 'auto'])(
    'flags "%s" as a reserved stellar-core keyword',
    (alias) => {
      const result = lint(validator(alias));
      expect(find(result, 'validators/alias-reserved-keyword')[0]?.message).toContain('reserved');
    },
  );

  it('suggests a node-indexed alias', () => {
    const [d] = find(lint(validator('self')), 'validators/alias-reserved-keyword');
    expect(d?.suggestion).toContain('self-0');
  });

  it('leaves an ordinary alias clean', () => {
    const result = lint(validator('core-1'));
    expect(find(result, 'validators/alias-reserved-keyword')).toEqual([]);
  });
});

describe('cross-SEP structural consistency', () => {
  const NEW_RULES = [
    'general/sep24-requires-auth',
    'general/kyc-requires-auth',
    'general/sep38-requires-auth',
    'general/transfer-server-needs-currencies',
    'currencies/anchored-fiat-needs-transfer-server',
    'currencies/regulated-invalid-target',
  ];

  const AUTH = 'WEB_AUTH_ENDPOINT="https://api.example.com/auth"';
  const SEP6 = 'TRANSFER_SERVER="https://api.example.com/sep6"';
  const SEP24 = 'TRANSFER_SERVER_SEP0024="https://api.example.com/sep24"';

  it('flags TRANSFER_SERVER_SEP0024 without WEB_AUTH_ENDPOINT', () => {
    const [d] = find(lint(withValidBase(SEP24)), 'general/sep24-requires-auth');
    expect(d?.severity).toBe('error');
    expect(d?.path).toBe('TRANSFER_SERVER_SEP0024');
    expect(d?.position?.line).toBe(3);
    expect(d?.helpUri).toBeTruthy();
    expect(d?.suggestion).toContain('SEP-10');
  });

  it('flags KYC_SERVER without WEB_AUTH_ENDPOINT', () => {
    const [d] = find(
      lint(withValidBase('KYC_SERVER="https://api.example.com/kyc"')),
      'general/kyc-requires-auth',
    );
    expect(d?.severity).toBe('error');
    expect(d?.path).toBe('KYC_SERVER');
    expect(d?.position?.line).toBe(3);
    expect(d?.suggestion).toBeTruthy();
  });

  it('flags ANCHOR_QUOTE_SERVER without WEB_AUTH_ENDPOINT', () => {
    const [d] = find(
      lint(withValidBase('ANCHOR_QUOTE_SERVER="https://api.example.com/sep38"')),
      'general/sep38-requires-auth',
    );
    expect(d?.severity).toBe('error');
    expect(d?.path).toBe('ANCHOR_QUOTE_SERVER');
    expect(d?.position?.line).toBe(3);
    expect(d?.suggestion).toBeTruthy();
  });

  it('stays silent on the auth pairing once WEB_AUTH_ENDPOINT is present', () => {
    const result = lint(
      withValidBase(
        `${SEP24}\nKYC_SERVER="https://api.example.com/kyc"\nANCHOR_QUOTE_SERVER="https://api.example.com/sep38"\n${AUTH}`,
      ),
    );
    expect(rules(result)).not.toContain('general/sep24-requires-auth');
    expect(rules(result)).not.toContain('general/kyc-requires-auth');
    expect(rules(result)).not.toContain('general/sep38-requires-auth');
  });

  it('flags a transfer server with no [[CURRENCIES]]', () => {
    const [d] = find(lint(withValidBase(SEP6)), 'general/transfer-server-needs-currencies');
    expect(d?.severity).toBe('warning');
    expect(d?.path).toBe('TRANSFER_SERVER');
    expect(d?.position?.line).toBe(3);
    expect(d?.suggestion).toContain('[[CURRENCIES]]');
  });

  it('flags TRANSFER_SERVER_SEP0024 alone when [[CURRENCIES]] is absent', () => {
    const [d] = find(lint(withValidBase(SEP24)), 'general/transfer-server-needs-currencies');
    expect(d?.path).toBe('TRANSFER_SERVER_SEP0024');
  });

  it('reports once, anchored at TRANSFER_SERVER, when both servers are declared', () => {
    const result = lint(withValidBase(`${SEP6}\n${SEP24}`));
    const found = find(result, 'general/transfer-server-needs-currencies');
    expect(found).toHaveLength(1);
    expect(found[0]?.path).toBe('TRANSFER_SERVER');
  });

  it('flags an explicitly empty [[CURRENCIES]] array', () => {
    const result = lint(withValidBase(`${SEP6}\nCURRENCIES=[]`));
    expect(find(result, 'general/transfer-server-needs-currencies')).toHaveLength(1);
  });

  it('stays silent when the transfer server has currencies', () => {
    const source = withValidBase(
      `${SEP6}\n\n[[CURRENCIES]]\ncode="AAA"\nissuer="${ACCOUNT_A}"\nis_unlimited=true`,
    );
    expect(rules(lint(source))).not.toContain('general/transfer-server-needs-currencies');
  });

  it('stays silent with no transfer server declared', () => {
    expect(rules(lint(withValidBase('')))).not.toContain(
      'general/transfer-server-needs-currencies',
    );
  });

  it('flags anchored fiat with no transfer server', () => {
    const source = withValidBase(
      `[[CURRENCIES]]\ncode="USDX"\nissuer="${ACCOUNT_A}"\nis_unlimited=true\nis_asset_anchored=true\nanchor_asset_type="fiat"\nanchor_asset="USD"`,
    );
    const [d] = find(lint(source), 'currencies/anchored-fiat-needs-transfer-server');
    expect(d?.severity).toBe('warning');
    expect(d?.path).toBe('CURRENCIES[0]');
    expect(d?.position?.line).toBe(3);
    expect(d?.suggestion).toContain('TRANSFER_SERVER');
  });

  it('stays silent on anchored fiat once a transfer server is declared', () => {
    const source = withValidBase(
      `${SEP6}\n\n[[CURRENCIES]]\ncode="USDX"\nissuer="${ACCOUNT_A}"\nis_unlimited=true\nis_asset_anchored=true\nanchor_asset_type="fiat"\nanchor_asset="USD"`,
    );
    expect(rules(lint(source))).not.toContain('currencies/anchored-fiat-needs-transfer-server');
  });

  it('ignores non-fiat anchored assets without a transfer server', () => {
    const source = withValidBase(
      `[[CURRENCIES]]\ncode="BTC"\nissuer="${ACCOUNT_A}"\nis_unlimited=true\nis_asset_anchored=true\nanchor_asset_type="crypto"\nanchor_asset="BTC"`,
    );
    expect(rules(lint(source))).not.toContain('currencies/anchored-fiat-needs-transfer-server');
  });

  it('flags regulated = true on a Soroban contract token', () => {
    const source = withValidBase(
      `[[CURRENCIES]]\ncode="TKN"\ncontract="${CONTRACT_A}"\nis_unlimited=true\nregulated=true\napproval_server="https://api.example.com/approve"`,
    );
    const [d] = find(lint(source), 'currencies/regulated-invalid-target');
    expect(d?.severity).toBe('error');
    expect(d?.message).toContain('contract');
    expect(d?.path).toBe('CURRENCIES[0].regulated');
    expect(d?.position?.line).toBe(7);
    expect(d?.helpUri).toBeTruthy();
    expect(d?.suggestion).toBeTruthy();
  });

  it('flags regulated = true on the native XLM asset', () => {
    const source = withValidBase('[[CURRENCIES]]\ncode="native"\nregulated=true');
    const [d] = find(lint(source), 'currencies/regulated-invalid-target');
    expect(d?.severity).toBe('error');
    expect(d?.message).toContain('native');
    expect(d?.path).toBe('CURRENCIES[0].regulated');
  });

  it('flags regulated = true on bare XLM with no issuer', () => {
    const source = withValidBase('[[CURRENCIES]]\ncode="XLM"\nregulated=true');
    expect(find(lint(source), 'currencies/regulated-invalid-target')).toHaveLength(1);
  });

  it('accepts regulated = true on a classic issued asset', () => {
    const source = withValidBase(
      `[[CURRENCIES]]\ncode="AAA"\nissuer="${ACCOUNT_A}"\nis_unlimited=true\nregulated=true\napproval_server="https://api.example.com/approve"`,
    );
    expect(rules(lint(source))).not.toContain('currencies/regulated-invalid-target');
  });

  it('stays silent on a fully compliant file', () => {
    // valid.toml pairs every auth-requiring endpoint with WEB_AUTH_ENDPOINT,
    // gives its transfer server currencies, and backs its anchored fiat with
    // a transfer server.
    const result = lint(fixture('valid.toml'), { domain: 'example.com' });
    for (const rule of NEW_RULES) {
      expect(rules(result)).not.toContain(rule);
    }
  });

  it('registers every new rule so --list-rules and --off know it', () => {
    const ids = allRules.map((r) => r.id);
    for (const rule of NEW_RULES) {
      expect(ids).toContain(rule);
    }
  });
});

describe('rule configuration', () => {
  it('disables a rule with off', () => {
    const result = lint(fixture('broken.toml'), { rules: { 'general/version': 'off' } });
    expect(rules(result)).not.toContain('general/version');
  });

  it('raises severity', () => {
    const result = lint(fixture('broken.toml'), {
      rules: { 'general/unknown-field': 'error' },
    });
    expect(find(result, 'general/unknown-field')[0]?.severity).toBe('error');
  });

  it('treats warnings as errors in strict mode', () => {
    const source = withValidBase(`[[CURRENCIES]]\ncode="AAA"\nissuer="${ACCOUNT_A}"`);
    expect(lint(source).ok).toBe(true);
    expect(lint(source, { strict: true }).ok).toBe(false);
  });
});

describe('rule registry', () => {
  it('has unique ids', () => {
    const ids = allRules.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('gives every rule a description and a namespaced id', () => {
    for (const rule of allRules) {
      expect(rule.description.length).toBeGreaterThan(0);
      // Categories are lowercase; digits are allowed so `sep38/...` matches.
      expect(rule.id).toMatch(/^[a-z][a-z0-9]*\/[a-z0-9-]+$/);
    }
  });

  it('survives a rule that throws', () => {
    // Feed structurally hostile input: correct types in the wrong shapes.
    const hostile = [
      'ACCOUNTS="not-an-array"',
      'DOCUMENTATION="not-a-table"',
      'CURRENCIES="not-a-list"',
      'PRINCIPALS=42',
      'VALIDATORS=[1,2,3]',
    ].join('\n');
    const result = lint(hostile);
    expect(find(result, 'internal/rule-error')).toEqual([]);
  });
});
