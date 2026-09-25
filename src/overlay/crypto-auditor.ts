import type { Diagnostic, Rule, RuleOverrides } from '../types.js';

export const OVERLAY_INVALID_CRYPTO_FRAMING = 'overlay/invalid-crypto-framing';
export const OVERLAY_MAC_AUTHENTICATION_FAILURE = 'overlay/mac-authentication-failure';
export const INVALID_CRYPTO_FRAMING_RULE = OVERLAY_INVALID_CRYPTO_FRAMING;
export const MAC_AUTHENTICATION_FAILURE_RULE = OVERLAY_MAC_AUTHENTICATION_FAILURE;

const HASH_LENGTH = 32;
const DEFAULT_MAX_FRAME_BYTES = 16 * 1024 * 1024;

export type BinaryValue = Uint8Array | ArrayBuffer | string;

export interface OverlayFrame {
  payload: BinaryValue;
  length?: number;
  tag?: BinaryValue;
  expectedTag?: BinaryValue;
  expectedMac?: BinaryValue;
  mac?: BinaryValue;
  macTag?: BinaryValue;
  validMac?: boolean;
  sequence?: number;
  nonce?: BinaryValue;
  aad?: BinaryValue;
}

export interface CryptoSessionInput {
  stream?: Uint8Array | ArrayBuffer;
  frames?: readonly OverlayFrame[];
  messages?: readonly OverlayFrame[];
  sequenceNumbers?: readonly number[];
  expectedSequence?: number;
  initialSequence?: number;
  lastSequence?: number;
  replayDetected?: boolean;
  sequence?: number;
  ikm?: BinaryValue;
  salt?: BinaryValue;
  info?: BinaryValue;
  outputLength?: number;
  derivedKey?: BinaryValue;
  expectedKey?: BinaryValue;
  sessionKey?: BinaryValue;
  key?: BinaryValue;
  macKey?: BinaryValue;
  nonce?: BinaryValue;
  aad?: BinaryValue;
  tagLength?: number;
  streamIncludesTags?: boolean;
}

export interface CryptoAuditOptions {
  rules?: RuleOverrides;
  maxFrameBytes?: number;
  expectedSequence?: number;
  initialSequence?: number;
  tagLength?: number;
  streamIncludesTags?: boolean;
}

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules: RuleOverrides | undefined,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

function diagnostic(rule: string, message: string, options: CryptoAuditOptions): Diagnostic[] {
  const severity = severityFor(rule, 'error', options.rules);
  if (severity === undefined) return [];
  return [{ rule, severity, category: 'network', message }];
}

function toBytes(value: BinaryValue): Uint8Array<ArrayBuffer> {
  if (value instanceof Uint8Array) return new Uint8Array(value);
  if (value instanceof ArrayBuffer) return new Uint8Array(value.slice(0));
  const trimmed = value.trim();
  if (/^(?:0x)?[0-9a-f]+$/i.test(trimmed) && trimmed.replace(/^0x/i, '').length % 2 === 0) {
    const hex = trimmed.replace(/^0x/i, '');
    const bytes = new Uint8Array(hex.length / 2);
    for (let index = 0; index < bytes.length; index++) {
      bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
    }
    return bytes;
  }
  return new TextEncoder().encode(value);
}

function frameBytes(value: BinaryValue): Uint8Array {
  return toBytes(value);
}

function view(bytes: Uint8Array): DataView {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

function rawFrames(
  stream: Uint8Array,
  maxFrameBytes: number,
  tagLength: number | undefined,
  includesTags: boolean,
): { frames: OverlayFrame[]; problems: string[] } {
  const frames: OverlayFrame[] = [];
  const problems: string[] = [];
  const data = view(stream);
  let offset = 0;
  let index = 0;
  while (offset < stream.length) {
    if (stream.length - offset < 4) {
      problems.push(`frame ${index} has a truncated 4-byte length prefix`);
      break;
    }
    const length = data.getUint32(offset);
    if (length === 0 || length > maxFrameBytes) {
      problems.push(`frame ${index} declares an invalid length of ${length} bytes`);
      break;
    }
    const total = 4 + length;
    if (offset + total > stream.length) {
      problems.push(`frame ${index} declares ${length} bytes but the stream is truncated`);
      break;
    }
    const end = offset + total;
    const bodyStart = offset + 4;
    const bodyLength = includesTags ? length - (tagLength ?? 0) : length;
    if (bodyLength < 0 || (includesTags && (tagLength ?? 0) > length)) {
      problems.push(`frame ${index} is shorter than its authentication tag`);
      offset = end;
      index++;
      continue;
    }
    const payload = stream.slice(bodyStart, bodyStart + bodyLength);
    const tag = includesTags ? stream.slice(bodyStart + bodyLength, end) : undefined;
    frames.push({
      payload,
      ...(tag === undefined ? {} : { tag }),
    });
    offset = end;
    index++;
  }
  return { frames, problems };
}

function framePayload(frame: OverlayFrame): Uint8Array {
  return frameBytes(frame.payload);
}

function frameTag(frame: OverlayFrame): Uint8Array | undefined {
  const value = frame.tag ?? frame.mac ?? frame.macTag;
  return value === undefined ? undefined : toBytes(value);
}

function auditFrameObjects(
  frames: readonly OverlayFrame[],
  maxFrameBytes: number,
  tagLength: number | undefined,
): string[] {
  const problems: string[] = [];
  for (const [index, frame] of frames.entries()) {
    let payloadLength: number;
    try {
      payloadLength = framePayload(frame).length;
    } catch {
      problems.push(`frame ${index} has an unreadable payload`);
      continue;
    }
    if (frame.length !== undefined) {
      const expectedLength = payloadLength + (frameTag(frame)?.length ?? 0);
      if (frame.length !== payloadLength && frame.length !== expectedLength) {
        problems.push(
          `frame ${index} declares ${frame.length} bytes but contains ${payloadLength}`,
        );
      }
    }
    if (payloadLength + (frameTag(frame)?.length ?? 0) > maxFrameBytes) {
      problems.push(`frame ${index} exceeds the ${maxFrameBytes}-byte frame limit`);
    }
    const tag = frameTag(frame);
    if (tagLength !== undefined && tag !== undefined && tag.length !== tagLength) {
      problems.push(`frame ${index} has a ${tag.length}-byte tag instead of ${tagLength} bytes`);
    }
  }
  return problems;
}

export function auditCryptoFraming(
  input: Uint8Array | ArrayBuffer | readonly OverlayFrame[],
  options: CryptoAuditOptions = {},
): Diagnostic[] {
  const maxFrameBytes = options.maxFrameBytes ?? DEFAULT_MAX_FRAME_BYTES;
  const tagLength = options.tagLength;
  if (Array.isArray(input)) {
    return auditFrameObjects(input as readonly OverlayFrame[], maxFrameBytes, tagLength).flatMap(
      (problem) =>
        diagnostic(
          OVERLAY_INVALID_CRYPTO_FRAMING,
          `Overlay frame audit failed: ${problem}`,
          options,
        ),
    );
  }
  const binaryInput = input as Uint8Array | ArrayBuffer;
  const problems = rawFrames(
    binaryInput instanceof Uint8Array ? binaryInput : new Uint8Array(binaryInput),
    maxFrameBytes,
    tagLength,
    options.streamIncludesTags ?? false,
  ).problems;
  return problems.flatMap((problem) =>
    diagnostic(OVERLAY_INVALID_CRYPTO_FRAMING, `Overlay frame audit failed: ${problem}`, options),
  );
}

function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++)
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  return difference === 0;
}

async function hmacSha256(
  key: Uint8Array<ArrayBuffer>,
  data: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  const subtle = globalThis.crypto?.subtle;
  if (subtle === undefined) throw new Error('Web Crypto is unavailable');
  const cryptoKey = await subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
  ]);
  return new Uint8Array(await subtle.sign('HMAC', cryptoKey, data));
}

export async function deriveHkdf(
  ikmValue: BinaryValue,
  saltValue: BinaryValue = new Uint8Array(HASH_LENGTH),
  infoValue: BinaryValue = new Uint8Array(),
  outputLength = HASH_LENGTH,
): Promise<Uint8Array<ArrayBuffer>> {
  if (!Number.isInteger(outputLength) || outputLength < 1 || outputLength > 255 * HASH_LENGTH) {
    throw new Error('HKDF output length must be between 1 and 8160 bytes');
  }
  const ikm = toBytes(ikmValue);
  const salt = toBytes(saltValue);
  const info = toBytes(infoValue);
  const prk = await hmacSha256(salt, ikm);
  const output = new Uint8Array(outputLength);
  let previous = new Uint8Array();
  let offset = 0;
  for (let counter = 1; offset < outputLength; counter++) {
    const input = new Uint8Array(previous.length + info.length + 1);
    input.set(previous, 0);
    input.set(info, previous.length);
    input[input.length - 1] = counter;
    previous = await hmacSha256(prk, input);
    const length = Math.min(previous.length, outputLength - offset);
    output.set(previous.subarray(0, length), offset);
    offset += length;
  }
  return output;
}

export const deriveHkdfKey = deriveHkdf;

export async function computeOverlayMac(
  keyValue: BinaryValue,
  payloadValue: BinaryValue,
  aadValue?: BinaryValue,
  nonceValue?: BinaryValue,
): Promise<Uint8Array<ArrayBuffer>> {
  const payload = toBytes(payloadValue);
  const aad = aadValue === undefined ? new Uint8Array() : toBytes(aadValue);
  const nonce = nonceValue === undefined ? new Uint8Array() : toBytes(nonceValue);
  const input = new Uint8Array(nonce.length + aad.length + payload.length);
  input.set(nonce, 0);
  input.set(aad, nonce.length);
  input.set(payload, nonce.length + aad.length);
  return hmacSha256(toBytes(keyValue), input);
}

function frameList(
  session: CryptoSessionInput,
  additionalFrames?: readonly OverlayFrame[],
): readonly OverlayFrame[] {
  return additionalFrames ?? session.frames ?? session.messages ?? [];
}

async function auditHkdf(
  session: CryptoSessionInput,
  options: CryptoAuditOptions,
): Promise<Diagnostic[]> {
  const expected = session.expectedKey ?? session.derivedKey ?? session.sessionKey ?? session.key;
  if (session.ikm === undefined || expected === undefined) return [];
  try {
    const derived = await deriveHkdf(
      session.ikm,
      session.salt,
      session.info,
      session.outputLength ?? toBytes(expected).length,
    );
    if (!constantTimeEqual(derived, toBytes(expected))) {
      return diagnostic(
        OVERLAY_INVALID_CRYPTO_FRAMING,
        'HKDF session key derivation does not match the authenticated session key',
        options,
      );
    }
    return [];
  } catch (error) {
    return diagnostic(
      OVERLAY_INVALID_CRYPTO_FRAMING,
      `HKDF session key derivation failed: ${error instanceof Error ? error.message : String(error)}`,
      options,
    );
  }
}

async function auditMac(
  session: CryptoSessionInput,
  options: CryptoAuditOptions,
  additionalFrames?: readonly OverlayFrame[],
): Promise<Diagnostic[]> {
  const diagnostics: Diagnostic[] = [];
  for (const [index, frame] of frameList(session, additionalFrames).entries()) {
    const tag = frameTag(frame);
    const expectedValue = frame.expectedTag ?? frame.expectedMac;
    const expected = expectedValue === undefined ? undefined : toBytes(expectedValue);
    if (frame.validMac === false) {
      diagnostics.push(
        ...diagnostic(
          OVERLAY_MAC_AUTHENTICATION_FAILURE,
          `Overlay frame ${index} was marked as failing MAC authentication`,
          options,
        ),
      );
      continue;
    }
    if (expected !== undefined && tag !== undefined && !constantTimeEqual(expected, tag)) {
      diagnostics.push(
        ...diagnostic(
          OVERLAY_MAC_AUTHENTICATION_FAILURE,
          `Overlay frame ${index} MAC tag does not match its expected value`,
          options,
        ),
      );
      continue;
    }
    if (session.macKey !== undefined && tag !== undefined) {
      try {
        const calculated = await computeOverlayMac(
          session.macKey,
          frame.payload,
          frame.aad ?? session.aad,
          frame.nonce ?? session.nonce,
        );
        const expectedLength = session.tagLength ?? options.tagLength ?? tag.length;
        if (
          calculated.length < expectedLength ||
          !constantTimeEqual(calculated.subarray(0, expectedLength), tag)
        ) {
          diagnostics.push(
            ...diagnostic(
              OVERLAY_MAC_AUTHENTICATION_FAILURE,
              `Overlay frame ${index} MAC authentication failed`,
              options,
            ),
          );
        }
      } catch (error) {
        diagnostics.push(
          ...diagnostic(
            OVERLAY_MAC_AUTHENTICATION_FAILURE,
            `Overlay frame ${index} MAC could not be verified: ${error instanceof Error ? error.message : String(error)}`,
            options,
          ),
        );
      }
    }
  }
  return diagnostics;
}

function auditSequences(
  session: CryptoSessionInput,
  options: CryptoAuditOptions,
  additionalFrames?: readonly OverlayFrame[],
): Diagnostic[] {
  const values =
    session.sequenceNumbers ??
    (session.sequence === undefined
      ? frameList(session, additionalFrames).flatMap((frame) =>
          frame.sequence === undefined ? [] : [frame.sequence],
        )
      : [session.sequence]);
  const expected =
    options.expectedSequence ??
    session.expectedSequence ??
    session.initialSequence ??
    options.initialSequence;
  let previous = session.lastSequence;
  if (session.replayDetected === true) {
    return diagnostic(
      OVERLAY_INVALID_CRYPTO_FRAMING,
      'Overlay session reported a replayed or reused message sequence',
      options,
    );
  }
  for (const [index, value] of values.entries()) {
    if (!Number.isInteger(value) || value < 0) {
      return diagnostic(
        OVERLAY_INVALID_CRYPTO_FRAMING,
        `Overlay message ${index} has an invalid sequence number`,
        options,
      );
    }
    const required = previous === undefined ? expected : previous + 1;
    if (required !== undefined && value !== required) {
      return diagnostic(
        OVERLAY_INVALID_CRYPTO_FRAMING,
        `Overlay message ${index} has sequence ${value}; expected ${required}`,
        options,
      );
    }
    previous = value;
  }
  return [];
}

export async function auditOverlayCrypto(
  session: CryptoSessionInput,
  options: CryptoAuditOptions = {},
): Promise<Diagnostic[]> {
  const framingInput = session.stream ?? session.frames ?? session.messages ?? new Uint8Array();
  const parsedStreamFrames =
    session.stream === undefined
      ? undefined
      : rawFrames(
          session.stream instanceof Uint8Array ? session.stream : new Uint8Array(session.stream),
          options.maxFrameBytes ?? DEFAULT_MAX_FRAME_BYTES,
          session.tagLength ?? options.tagLength,
          options.streamIncludesTags ?? session.streamIncludesTags ?? false,
        ).frames;
  const diagnostics = [
    ...auditCryptoFraming(
      framingInput as Uint8Array | ArrayBuffer | readonly OverlayFrame[],
      options,
    ),
    ...(await auditHkdf(session, options)),
    ...(await auditMac(session, options, parsedStreamFrames)),
    ...auditSequences(session, options, parsedStreamFrames),
  ];
  return diagnostics;
}

export const auditCryptoSession = auditOverlayCrypto;
export const auditOverlayCryptoSession = auditOverlayCrypto;

export class CryptoAuditor {
  constructor(private readonly options: CryptoAuditOptions = {}) {}

  audit(session: CryptoSessionInput): Promise<Diagnostic[]> {
    return auditOverlayCrypto(session, this.options);
  }
}

export const cryptoAuditorRules: Rule[] = [
  {
    id: OVERLAY_INVALID_CRYPTO_FRAMING,
    category: 'network',
    severity: 'error',
    description:
      'Overlay messages must use valid big-endian framing and monotonic session sequences',
    run() {},
  },
  {
    id: OVERLAY_MAC_AUTHENTICATION_FAILURE,
    category: 'network',
    severity: 'error',
    description: 'Overlay message authentication tags must verify against their session keys',
    run() {},
  },
];

export const cryptoRuleIds: readonly string[] = cryptoAuditorRules.map((rule) => rule.id);
export const overlayCryptoRuleIds = cryptoRuleIds;
