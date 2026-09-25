import { describe, expect, it } from 'vitest';
import { Keypair } from '@stellar/stellar-base';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha2';
import { keccak_256 } from '@noble/hashes/sha3';
import { verifyCollateralSignature } from '../src/crypto/collateral.js';
import { lint } from '../src/lint.js';

const MESSAGE = 'Reserve attestation for USDC, 2026-09-25';

const stellarKey = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 7));

/** Private key 1: every address family below has a well-known address for it. */
const SECP_KEY = new Uint8Array(32);
SECP_KEY[31] = 1;

/** Addresses published for private key 1, so address derivation is checked independently. */
const BTC_P2PKH_COMPRESSED = '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH';
const BTC_P2PKH_UNCOMPRESSED = '1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm';
const BTC_P2SH_P2WPKH = '3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN';
const BTC_P2WPKH = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4';
const ETH_ADDRESS = '0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf';

const encoder = new TextEncoder();

function stellarSignature(message: string): string {
  return stellarKey.sign(Buffer.from(message, 'utf8')).toString('base64');
}

/** BIP-137: a compact signature over the double-SHA256 `Bitcoin Signed Message` digest. */
function bitcoinSignature(message: string, headerBase: number): string {
  const body = encoder.encode(message);
  const prefix = encoder.encode('\x18Bitcoin Signed Message:\n');
  const digest = sha256(sha256(new Uint8Array([...prefix, body.length, ...body])));
  const sig = secp256k1.sign(digest, SECP_KEY);
  const header = headerBase + sig.recovery;
  return Buffer.from([header, ...sig.toCompactRawBytes()]).toString('base64');
}

/** EIP-191 `personal_sign`, printed the way wallets print it. */
function ethereumSignature(message: string): string {
  const body = encoder.encode(message);
  const digest = keccak_256(
    new Uint8Array([...encoder.encode(`\x19Ethereum Signed Message:\n${body.length}`), ...body]),
  );
  const sig = secp256k1.sign(digest, SECP_KEY);
  return `0x${Buffer.from([...sig.toCompactRawBytes(), 27 + sig.recovery]).toString('hex')}`;
}

describe('verifyCollateralSignature — Stellar', () => {
  it('accepts an Ed25519 signature over the raw message', () => {
    expect(
      verifyCollateralSignature(stellarKey.publicKey(), MESSAGE, stellarSignature(MESSAGE)),
    ).toBe('valid');
  });

  it('accepts an Ed25519 signature over the SEP-53 digest', () => {
    const digest = sha256(encoder.encode(`Stellar Signed Message:\n${MESSAGE}`));
    const signature = stellarKey.sign(Buffer.from(digest)).toString('base64');
    expect(verifyCollateralSignature(stellarKey.publicKey(), MESSAGE, signature)).toBe('valid');
  });

  it('rejects a signature over a tampered message', () => {
    expect(
      verifyCollateralSignature(stellarKey.publicKey(), `${MESSAGE}!`, stellarSignature(MESSAGE)),
    ).toBe('invalid');
  });

  it("rejects another key's signature", () => {
    const other = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 8));
    expect(verifyCollateralSignature(other.publicKey(), MESSAGE, stellarSignature(MESSAGE))).toBe(
      'invalid',
    );
  });

  it('reports non-base64 and wrong-length signatures as malformed', () => {
    const address = stellarKey.publicKey();
    expect(verifyCollateralSignature(address, MESSAGE, 'not base64!!')).toBe('malformed');
    expect(verifyCollateralSignature(address, MESSAGE, '')).toBe('malformed');
    expect(verifyCollateralSignature(address, MESSAGE, 'AAAA')).toBe('malformed');
  });
});

describe('verifyCollateralSignature — Bitcoin', () => {
  it('verifies a compressed P2PKH (1...) signature', () => {
    expect(
      verifyCollateralSignature(BTC_P2PKH_COMPRESSED, MESSAGE, bitcoinSignature(MESSAGE, 31)),
    ).toBe('valid');
  });

  it('verifies an uncompressed P2PKH signature', () => {
    expect(
      verifyCollateralSignature(BTC_P2PKH_UNCOMPRESSED, MESSAGE, bitcoinSignature(MESSAGE, 27)),
    ).toBe('valid');
  });

  it('verifies a P2SH-P2WPKH (3...) signature', () => {
    expect(verifyCollateralSignature(BTC_P2SH_P2WPKH, MESSAGE, bitcoinSignature(MESSAGE, 35))).toBe(
      'valid',
    );
  });

  it('verifies a native segwit (bc1q...) signature, BIP-137 or Electrum header', () => {
    expect(verifyCollateralSignature(BTC_P2WPKH, MESSAGE, bitcoinSignature(MESSAGE, 39))).toBe(
      'valid',
    );
    expect(verifyCollateralSignature(BTC_P2WPKH, MESSAGE, bitcoinSignature(MESSAGE, 31))).toBe(
      'valid',
    );
  });

  it('rejects a signature for a different address or message', () => {
    const signature = bitcoinSignature(MESSAGE, 31);
    expect(
      verifyCollateralSignature('1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2', MESSAGE, signature),
    ).toBe('invalid');
    expect(verifyCollateralSignature(BTC_P2PKH_COMPRESSED, 'other', signature)).toBe('invalid');
  });

  it('reports a DER or truncated signature as malformed', () => {
    expect(
      verifyCollateralSignature(
        BTC_P2PKH_COMPRESSED,
        MESSAGE,
        '304502206e21798a42fae0e854281abd38bacd1aeed3ee3738d9e1446618c4571d10',
      ),
    ).toBe('malformed');
  });

  it('leaves an address with a bad checksum or taproot as unsupported', () => {
    const signature = bitcoinSignature(MESSAGE, 31);
    expect(
      verifyCollateralSignature('1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMJ', MESSAGE, signature),
    ).toBe('unsupported');
    expect(
      verifyCollateralSignature(
        'bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297',
        MESSAGE,
        signature,
      ),
    ).toBe('unsupported');
  });
});

describe('verifyCollateralSignature — Ethereum', () => {
  it('verifies an EIP-191 personal_sign signature in 0x hex', () => {
    expect(verifyCollateralSignature(ETH_ADDRESS, MESSAGE, ethereumSignature(MESSAGE))).toBe(
      'valid',
    );
  });

  it('accepts the same signature base64-encoded, and v as 0/1', () => {
    const bytes = Buffer.from(ethereumSignature(MESSAGE).slice(2), 'hex');
    expect(verifyCollateralSignature(ETH_ADDRESS, MESSAGE, bytes.toString('base64'))).toBe('valid');

    bytes[64] = (bytes[64] as number) - 27;
    expect(verifyCollateralSignature(ETH_ADDRESS, MESSAGE, `0x${bytes.toString('hex')}`)).toBe(
      'valid',
    );
  });

  it('matches the address case-insensitively', () => {
    expect(
      verifyCollateralSignature(ETH_ADDRESS.toLowerCase(), MESSAGE, ethereumSignature(MESSAGE)),
    ).toBe('valid');
  });

  it('rejects a signature from a different key', () => {
    expect(
      verifyCollateralSignature(
        '0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF',
        MESSAGE,
        ethereumSignature(MESSAGE),
      ),
    ).toBe('invalid');
  });

  it('reports a short or non-hex signature as malformed', () => {
    expect(verifyCollateralSignature(ETH_ADDRESS, MESSAGE, '0x1234')).toBe('malformed');
    expect(verifyCollateralSignature(ETH_ADDRESS, MESSAGE, '0xzz')).toBe('malformed');
  });
});

describe('verifyCollateralSignature — other addresses', () => {
  it('leaves unknown address families unsupported', () => {
    expect(verifyCollateralSignature('rN7n7otQDd6FczFgLdSqtcsAUxDkw6fzRH', MESSAGE, 'AAAA')).toBe(
      'unsupported',
    );
  });
});

function currencyWith(address: string, message: string, signature: string): string {
  return [
    '[[CURRENCIES]]',
    'code="USDC"',
    `issuer="${stellarKey.publicKey()}"`,
    'is_unlimited=true',
    `collateral_addresses=["${address}"]`,
    `collateral_address_messages=["${message}"]`,
    `collateral_address_signatures=["${signature}"]`,
  ].join('\n');
}

const rulesOf = (source: string): string[] =>
  lint(source)
    .diagnostics.map((d) => d.rule)
    .filter((rule) => rule.startsWith('currencies/collateral-signature'));

describe('currencies/collateral-signature-* rules', () => {
  it('passes a valid Stellar signature cleanly', () => {
    expect(
      rulesOf(currencyWith(stellarKey.publicKey(), MESSAGE, stellarSignature(MESSAGE))),
    ).toEqual([]);
  });

  it('reports a tampered message as currencies/collateral-signature-invalid', () => {
    const result = lint(
      currencyWith(stellarKey.publicKey(), 'tampered', stellarSignature(MESSAGE)),
    );
    const diagnostic = result.diagnostics.find(
      (d) => d.rule === 'currencies/collateral-signature-invalid',
    );
    expect(diagnostic).toMatchObject({
      severity: 'error',
      category: 'currencies',
      path: 'CURRENCIES[0].collateral_address_signatures',
    });
    expect(diagnostic?.message).toContain('CURRENCIES[0].collateral_address_signatures[0]');
    expect(diagnostic?.position?.line).toBe(7);
  });

  it('reports a non-base64 signature as currencies/collateral-signature-malformed', () => {
    expect(rulesOf(currencyWith(stellarKey.publicKey(), MESSAGE, '%%%not-base64%%%'))).toEqual([
      'currencies/collateral-signature-malformed',
    ]);
  });

  it('verifies an Ethereum reserve address', () => {
    expect(rulesOf(currencyWith(ETH_ADDRESS, MESSAGE, ethereumSignature(MESSAGE)))).toEqual([]);
  });

  it('checks each aligned position independently', () => {
    const source = [
      '[[CURRENCIES]]',
      'code="USDC"',
      `issuer="${stellarKey.publicKey()}"`,
      'is_unlimited=true',
      `collateral_addresses=["${stellarKey.publicKey()}", "${ETH_ADDRESS}"]`,
      `collateral_address_messages=["${MESSAGE}", "${MESSAGE}"]`,
      `collateral_address_signatures=["${stellarSignature(MESSAGE)}", "${ethereumSignature('x')}"]`,
    ].join('\n');
    const diagnostics = lint(source).diagnostics.filter((d) =>
      d.rule.startsWith('currencies/collateral-signature'),
    );
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.message).toContain('collateral_address_signatures[1]');
  });

  it('stays silent when messages are missing (collateral-consistency covers it)', () => {
    const source = [
      '[[CURRENCIES]]',
      'code="USDC"',
      `issuer="${stellarKey.publicKey()}"`,
      'is_unlimited=true',
      `collateral_addresses=["${stellarKey.publicKey()}"]`,
      `collateral_address_signatures=["garbage"]`,
    ].join('\n');
    expect(rulesOf(source)).toEqual([]);
  });

  it('can be switched off', () => {
    const source = currencyWith(stellarKey.publicKey(), 'tampered', stellarSignature(MESSAGE));
    const result = lint(source, { rules: { 'currencies/collateral-signature-invalid': 'off' } });
    expect(result.diagnostics.map((d) => d.rule)).not.toContain(
      'currencies/collateral-signature-invalid',
    );
  });
});
