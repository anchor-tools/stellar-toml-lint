import { strict as assert } from 'node:assert';
import { describe, it, vi } from 'vitest';
import { emailMxRule } from '../src/rules/email-mx.js';
import type { RuleContext } from '../src/types.js';
import { resolveMx } from 'node:dns/promises';

// Mock dns.promises.resolveMx
vi.mock('node:dns/promises', async () => ({
  resolveMx: vi.fn(),
}));

function makeContext(doc: Record<string, unknown>): RuleContext {
  const source = `VERSION="2.7.0"\nNETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"\n[DOCUMENTATION]\nORG_NAME="Example"\nORG_URL="https://example.com"\nORG_DESCRIPTION="Example"\nORG_OFFICIAL_EMAIL="ops@example.com"\n`;
  const pathToLine: Record<string, number> = {};
  let lineNum = 1;
  for (const line of source.split('\n')) {
    const lower = line.toLowerCase();
    if (lower.startsWith('version="')) pathToLine['version'] = lineNum;
    if (lower.startsWith('network_passphrase="')) pathToLine['network_passphrase'] = lineNum;
    if (lower.startsWith('[documentation]')) pathToLine['documentation'] = lineNum;
    if (lower.startsWith('org_name="')) pathToLine['org_name'] = lineNum;
    if (lower.startsWith('org_url="')) pathToLine['org_url'] = lineNum;
    if (lower.startsWith('org_description="')) pathToLine['org_description'] = lineNum;
    if (lower.startsWith('org_official_email="')) pathToLine['org_official_email'] = lineNum;
    lineNum++;
  }

  return {
    doc,
    source,
    options: { rules: {}, strict: false, checkNetwork: true },
    locate: (path: string): { line: number; column: number } | undefined => {
      const line = pathToLine[path];
      if (line === undefined) return undefined;
      const lineContent = source.split('\n')[line - 1] ?? '';
      const column = lineContent.indexOf(path.split('.').pop() ?? '') + 1;
      return { line, column };
    },
    report: () => {},
  } as RuleContext;
}

describe('email-mx', () => {
  it('passes when MX records resolve', async () => {
    vi.mocked(resolveMx).mockResolvedValue([
      { exchange: 'alt1.aspmx.l.google.com', priority: 1 },
      { exchange: 'alt2.aspmx.l.google.com', priority: 5 },
    ]);

    const doc = {
      VERSION: '2.7.0',
      NETWORK_PASSPHRASE: 'Public Global Stellar Network ; September 2015',
      DOCUMENTATION: {
        ORG_NAME: 'Example',
        ORG_URL: 'https://example.com',
        ORG_DESCRIPTION: 'Example',
        ORG_OFFICIAL_EMAIL: 'ops@example.com',
      },
    };

    const reported: any[] = [];
    const ctx = makeContext(doc) as RuleContext & { reported: typeof reported };
    ctx.reported = reported;
    ctx.report = (d: any) => {
      reported.push(d);
    };

    await emailMxRule.run(ctx);

    // A domain with working MX records is not a finding.
    assert.equal(reported.length, 0);
  });

  it('asserts general/email-domain-no-mx when DNS lookup fails with ENOENT', async () => {
    vi.mocked(resolveMx).mockRejectedValue(new Error('ENOENT'));

    const doc = {
      VERSION: '2.7.0',
      NETWORK_PASSPHRASE: 'Public Global Stellar Network ; September 2015',
      DOCUMENTATION: {
        ORG_NAME: 'Example',
        ORG_URL: 'https://example.com',
        ORG_DESCRIPTION: 'Example',
        ORG_OFFICIAL_EMAIL: 'ops@example.com',
      },
    };

    const reported: any[] = [];
    const ctx = makeContext(doc) as RuleContext & { reported: typeof reported };
    ctx.reported = reported;
    ctx.report = (d: any) => {
      reported.push(d);
    };

    await emailMxRule.run(ctx);

    assert.equal(reported.length, 1);
    assert.equal(reported[0]!.rule, 'general/email-domain-no-mx');
    assert.equal(reported[0]!.severity, 'warning');
    assert(reported[0]!.message.includes('Could not resolve MX records'));
  });

  it('asserts general/email-domain-no-mx when DNS lookup fails with NETWORK', async () => {
    vi.mocked(resolveMx).mockRejectedValue(new Error('NETWORK'));

    const doc = {
      VERSION: '2.7.0',
      NETWORK_PASSPHRASE: 'Public Global Stellar Network ; September 2015',
      DOCUMENTATION: {
        ORG_NAME: 'Example',
        ORG_URL: 'https://example.com',
        ORG_DESCRIPTION: 'Example',
        ORG_OFFICIAL_EMAIL: 'ops@example.com',
      },
    };

    const reported: any[] = [];
    const ctx = makeContext(doc) as RuleContext & { reported: typeof reported };
    ctx.reported = reported;
    ctx.report = (d: any) => {
      reported.push(d);
    };

    await emailMxRule.run(ctx);

    assert.equal(reported.length, 1);
    assert.equal(reported[0]!.rule, 'general/email-domain-no-mx');
    assert.equal(reported[0]!.severity, 'warning');
  });

  it('is silent when ORG_OFFICIAL_EMAIL is absent', () => {
    const doc = {
      VERSION: '2.7.0',
      NETWORK_PASSPHRASE: 'Public Global Stellar Network ; September 2015',
      DOCUMENTATION: {
        ORG_NAME: 'Example',
        ORG_URL: 'https://example.com',
        ORG_DESCRIPTION: 'Example',
      },
    };

    const ctx = makeContext(doc) as RuleContext & { reported: any[] };
    const reported: any[] = [];
    ctx.reported = reported;
    ctx.report = (d: any) => {
      reported.push(d);
    };

    emailMxRule.run(ctx);

    assert.equal(reported.length, 0);
  });

  it('is silent when ORG_OFFICIAL_EMAIL has no @ sign', async () => {
    vi.mocked(resolveMx).mockResolvedValue([]);

    const doc = {
      VERSION: '2.7.0',
      NETWORK_PASSPHRASE: 'Public Global Stellar Network ; September 2015',
      DOCUMENTATION: {
        ORG_NAME: 'Example',
        ORG_URL: 'https://example.com',
        ORG_DESCRIPTION: 'Example',
        ORG_OFFICIAL_EMAIL: 'no-email',
      },
    };

    const ctx = makeContext(doc) as RuleContext & { reported: any[] };
    const reported: any[] = [];
    ctx.reported = reported;
    ctx.report = (d: any) => {
      reported.push(d);
    };

    await emailMxRule.run(ctx);

    assert.equal(reported.length, 0);
  });
});
