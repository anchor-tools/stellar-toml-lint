import {
  dnssecLookUp,
  Message,
  Question,
  SecurityStatus,
  type Resolver,
  type TrustAnchor,
} from '@relaycorp/dnssec';
import { DNSoverHTTPS } from 'dohdec';
import type { Diagnostic, RuleOverrides } from '../types.js';
import { hostOf } from '../predicates.js';
import { BROKEN_DNSSEC_CHAIN_RULE, EXPIRED_RRSIG_RULE } from './dnssec-chain.js';

export interface DnssecChainOptions {
  domain?: string;
  rules?: RuleOverrides;
  fetchImpl?: typeof fetch;
  resolverUrl?: string;
  resolver?: Resolver;
  trustAnchors?: readonly TrustAnchor[];
}

function rootDomain(doc: Record<string, unknown>, explicit?: string): string | undefined {
  const candidate =
    explicit ??
    hostOf(
      typeof doc.DOCUMENTATION === 'object' && doc.DOCUMENTATION !== null
        ? (doc.DOCUMENTATION as Record<string, unknown>).ORG_URL
        : undefined,
    );
  if (typeof candidate !== 'string' || candidate === '') return undefined;
  try {
    return new URL(
      candidate.includes('://') ? candidate : `https://${candidate}`,
    ).hostname.toLowerCase();
  } catch {
    return undefined;
  }
}

function dnsOverHttpsResolver(options: DnssecChainOptions): Resolver {
  const doh = new DNSoverHTTPS({
    ...(options.resolverUrl === undefined ? {} : { url: options.resolverUrl }),
    ...(options.fetchImpl === undefined ? {} : { customFetch: options.fetchImpl }),
    http2: false,
  });
  return async (question) => {
    const result = await doh.lookup(question.name, {
      rrtype: question.getTypeName(),
      json: false,
      decode: false,
      dnssec: true,
      dnssecCheckingDisabled: true,
      signal: AbortSignal.timeout(5000),
    });
    if (!Buffer.isBuffer(result)) throw new Error('DNS-over-HTTPS returned no DNS wire response');
    return result;
  };
}

function failureDiagnostic(
  rule: string,
  domain: string,
  detail: string,
  rules: RuleOverrides | undefined,
): Diagnostic[] {
  const override = rules?.[rule];
  if (override === 'off') return [];
  return [
    {
      rule,
      severity: override === 'warning' || override === 'info' ? override : 'error',
      category: 'network',
      message: `DNSSEC validation for ${domain} failed: ${detail}`,
    },
  ];
}

/** Cryptographically verifies the requested answer and its complete chain to the root. */
export async function verifyDnssecDomain(
  domain: string,
  options: DnssecChainOptions = {},
): Promise<Diagnostic[]> {
  const resolver = options.resolver ?? dnsOverHttpsResolver(options);
  const question = new Question(`${domain.replace(/\.$/, '')}.`, 'A');
  const responses: Message[] = [];
  const recordingResolver: Resolver = async (lookupQuestion) => {
    const response = await resolver(lookupQuestion);
    responses.push(response instanceof Message ? response : Message.deserialise(response));
    return response;
  };
  let result;
  try {
    result = await dnssecLookUp(question, recordingResolver, {
      ...(options.trustAnchors === undefined ? {} : { trustAnchors: options.trustAnchors }),
    });
  } catch (error) {
    const detail = error instanceof Error ? error.message : 'DNS resolver failed';
    return failureDiagnostic(BROKEN_DNSSEC_CHAIN_RULE, domain, detail, options.rules);
  }
  if (result.status === SecurityStatus.SECURE) return [];
  const details = result.reasonChain.join('; ') || result.status.toLowerCase();
  const now = Date.now();
  const hasExpiredSignature = responses.some((response) =>
    response.answers.some((record) => {
      if (record.typeId !== 46) return false;
      const expiration = (record.dataFields as { expiration?: unknown }).expiration;
      return typeof expiration === 'number' && expiration * 1000 < now;
    }),
  );
  const rule =
    hasExpiredSignature || /signature.*expired|expired.*signature|rrsig.*expired/i.test(details)
      ? EXPIRED_RRSIG_RULE
      : BROKEN_DNSSEC_CHAIN_RULE;
  return failureDiagnostic(rule, domain, details, options.rules);
}

/** Resolve and cryptographically verify the DNSSEC chain for a document's domain. */
export async function verifyDnssecChain(
  doc: Record<string, unknown>,
  options: DnssecChainOptions = {},
): Promise<Diagnostic[]> {
  const domain = rootDomain(doc, options.domain);
  return domain === undefined ? [] : verifyDnssecDomain(domain, options);
}
