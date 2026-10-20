import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { HTTPS_ENDPOINT_FIELDS } from '../spec.js';
import { hostOf, isString } from '../predicates.js';

export const SECURITY_LACKS_FORWARD_SECRECY_RULE = 'security/lacks-forward-secrecy';
export const SECURITY_SESSION_RESUMPTION_RULE = 'security/session-resumption-insecure';
export const DEFAULT_TLS_SESSION_OBSERVATION_WINDOW_MS = 10 * 60 * 1000;

export interface TlsHandshakeObservation {
  cipher: string;
  protocol: string;
  ephemeral: boolean;
  sessionReused: boolean;
}

export type TlsProbe = (
  hostname: string,
  sessionObservationWindowMs: number,
) => Promise<TlsHandshakeObservation | undefined>;

export interface TlsPfsAuditorOptions {
  rules?: RuleOverrides;
  domain?: string;
  probe?: TlsProbe;
  sessionObservationWindowMs?: number;
}

export const tlsPfsAuditorRules: Rule[] = [
  {
    id: SECURITY_LACKS_FORWARD_SECRECY_RULE,
    category: 'network',
    severity: 'error',
    description: 'TLS endpoints should use ephemeral Diffie-Hellman key exchange',
    run() {},
  },
  {
    id: SECURITY_SESSION_RESUMPTION_RULE,
    category: 'network',
    severity: 'warning',
    description: 'TLS session resumption should use regularly rotated ticket keys',
    run() {},
  },
];

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules: RuleOverrides | undefined,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

function targetsOf(doc: Record<string, unknown>, domain?: string): string[] {
  const targets = new Set<string>();
  const domainValue = domain ?? doc.DOMAIN;
  if (typeof domainValue === 'string') {
    try {
      targets.add(
        new URL(domainValue.includes('://') ? domainValue : `https://${domainValue}`).hostname,
      );
    } catch {
      // Invalid document domains are handled by the normal lint rules.
    }
  }
  const documentation = doc.DOCUMENTATION;
  if (
    typeof documentation === 'object' &&
    documentation !== null &&
    !Array.isArray(documentation)
  ) {
    const organizationHost = hostOf((documentation as Record<string, unknown>).ORG_URL);
    if (organizationHost !== undefined) targets.add(organizationHost);
  }
  for (const field of HTTPS_ENDPOINT_FIELDS) {
    const value = doc[field];
    if (!isString(value)) continue;
    const host = hostOf(value);
    if (host !== undefined) targets.add(host);
  }
  return [...targets];
}

async function systemTlsProbe(
  hostname: string,
  sessionObservationWindowMs: number,
): Promise<TlsHandshakeObservation | undefined> {
  const tls = await import('node:tls').catch(() => null);
  if (tls === null) return undefined;

  interface HandshakeResult {
    observation: TlsHandshakeObservation;
    session?: Buffer;
  }

  const handshake = (session?: Buffer): Promise<HandshakeResult | undefined> =>
    new Promise<HandshakeResult | undefined>((resolve) => {
      let settled = false;
      let connected = false;
      let observation: TlsHandshakeObservation | undefined;
      let capturedSession: Buffer | undefined;
      let ticketTimer: NodeJS.Timeout | undefined;
      const socket = tls.connect({
        host: hostname,
        port: 443,
        servername: hostname,
        ...(session === undefined ? {} : { session }),
      });
      const finish = () => {
        if (settled) return;
        settled = true;
        if (ticketTimer !== undefined) clearTimeout(ticketTimer);
        socket.destroy();
        resolve(
          observation === undefined
            ? undefined
            : {
                observation,
                ...(capturedSession === undefined ? {} : { session: capturedSession }),
              },
        );
      };
      socket.setTimeout(5_000);
      socket.on('session', (newSession) => {
        capturedSession = newSession;
        if (connected && session === undefined) finish();
      });
      socket.once('secureConnect', () => {
        connected = true;
        const cipher = socket.getCipher().name;
        const protocol = socket.getProtocol() ?? '';
        const ephemeralKey = socket.getEphemeralKeyInfo();
        const ephemeralKeyType =
          typeof ephemeralKey === 'object' && ephemeralKey !== null && 'type' in ephemeralKey
            ? ephemeralKey.type
            : undefined;
        const ephemeral =
          protocol === 'TLSv1.3' ||
          /(?:ECDHE|DHE)/i.test(cipher) ||
          ephemeralKeyType === 'ECDH' ||
          ephemeralKeyType === 'DH';
        observation = {
          cipher,
          protocol,
          ephemeral,
          sessionReused: socket.isSessionReused(),
        };
        const currentSession = socket.getSession();
        if (currentSession !== undefined && currentSession.length > 0) {
          capturedSession = currentSession;
        }
        if (session !== undefined || capturedSession !== undefined) {
          finish();
        } else {
          ticketTimer = setTimeout(finish, 2_000);
        }
      });
      socket.once('timeout', finish);
      socket.once('error', finish);
    });

  const first = await handshake();
  if (first === undefined) return undefined;
  if (first.session === undefined) return first.observation;
  await new Promise((resolve) => setTimeout(resolve, sessionObservationWindowMs));
  const second = await handshake(first.session);
  return second === undefined ? first.observation : second.observation;
}

export async function auditTlsForwardSecrecy(
  doc: Record<string, unknown>,
  options: TlsPfsAuditorOptions = {},
): Promise<Diagnostic[]> {
  const diagnostics: Diagnostic[] = [];
  const targets = targetsOf(doc, options.domain);
  const observationWindow =
    options.sessionObservationWindowMs ?? DEFAULT_TLS_SESSION_OBSERVATION_WINDOW_MS;
  const observationMinutes = Math.round(observationWindow / 60_000);
  const results = await Promise.all(
    targets.map(async (host) => ({
      host,
      observation: options.probe
        ? await options.probe(host, observationWindow)
        : await systemTlsProbe(host, observationWindow),
    })),
  );
  for (const { host, observation } of results) {
    if (observation === undefined) continue;
    if (!observation.ephemeral) {
      const severity = severityFor(SECURITY_LACKS_FORWARD_SECRECY_RULE, 'error', options.rules);
      if (severity !== undefined) {
        diagnostics.push({
          rule: SECURITY_LACKS_FORWARD_SECRECY_RULE,
          severity,
          category: 'network',
          message: `${host} negotiated ${observation.protocol || 'TLS'} cipher ${observation.cipher} without ephemeral key exchange`,
          suggestion: 'Disable static RSA key exchange and enable ECDHE or DHE cipher suites.',
        });
      }
    }
    if (observation.sessionReused) {
      const severity = severityFor(SECURITY_SESSION_RESUMPTION_RULE, 'warning', options.rules);
      if (severity !== undefined) {
        diagnostics.push({
          rule: SECURITY_SESSION_RESUMPTION_RULE,
          severity,
          category: 'network',
          message: `${host} accepted a TLS session after a ${observationMinutes}-minute observation interval`,
          suggestion:
            'Rotate TLS session ticket keys more frequently or reduce the maximum session lifetime.',
        });
      }
    }
  }
  return diagnostics;
}
