import { describe, expect, it } from 'vitest';
import { DnsRecord, MockChain, Question, RrSet, SecurityStatus } from '@relaycorp/dnssec';
import { BROKEN_DNSSEC_CHAIN_RULE, EXPIRED_RRSIG_RULE } from '../../src/security/dnssec-chain.js';
import { verifyDnssecDomain } from '../../src/security/dnssec-chain-node.js';

async function chainFixture(status = SecurityStatus.SECURE, signatureEnd?: Date) {
  const question = new Question('anchor.example.com.', 'A');
  const answer = new DnsRecord(question.name, 'A', 'IN', 300, '192.0.2.15');
  const rrset = RrSet.init(question, [answer]);
  const chain = await MockChain.generate(question.name);
  const fixture = chain.generateFixture(
    rrset,
    status,
    signatureEnd === undefined
      ? undefined
      : { start: new Date(signatureEnd.getTime() - 60_000), end: signatureEnd },
  );
  return { fixture, question };
}

describe('DNSSEC chain verification', () => {
  it('accepts authenticated delegation and key-signature records', async () => {
    const { fixture } = await chainFixture();
    const diagnostics = await verifyDnssecDomain('anchor.example.com', {
      resolver: fixture.resolver,
      trustAnchors: fixture.trustAnchors,
    });
    expect(diagnostics).toEqual([]);
  });

  it('reports an unauthenticated chain and expired signatures distinctly', async () => {
    const brokenFixture = await chainFixture(SecurityStatus.BOGUS);
    const broken = await verifyDnssecDomain('anchor.example.com', {
      resolver: brokenFixture.fixture.resolver,
      trustAnchors: brokenFixture.fixture.trustAnchors,
    });
    expect(broken[0]?.rule).toBe(BROKEN_DNSSEC_CHAIN_RULE);

    const expiredFixture = await chainFixture(SecurityStatus.SECURE, new Date(Date.now() - 60_000));
    const expired = await verifyDnssecDomain('anchor.example.com', {
      resolver: expiredFixture.fixture.resolver,
      trustAnchors: expiredFixture.fixture.trustAnchors,
    });
    expect(expired[0]?.rule).toBe(EXPIRED_RRSIG_RULE);
  });

  it('reports DNS transport failures without throwing', async () => {
    const diagnostics = await verifyDnssecDomain('anchor.example.com', {
      resolver: async () => {
        throw new Error('resolver unavailable');
      },
    });
    expect(diagnostics[0]?.rule).toBe(BROKEN_DNSSEC_CHAIN_RULE);
    expect(diagnostics[0]?.message).toContain('resolver unavailable');
  });
});
