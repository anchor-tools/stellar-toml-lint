/**
 * SEP-10 challenge transactions for the local mock server.
 *
 * The challenge follows the SEP-10 shape a wallet validates: sequence number
 * 0, a 15-minute time bound, a `<home_domain> auth` ManageData operation
 * sourced from the client account carrying a 48-byte random nonce, a
 * `web_auth_domain` operation sourced from the server account, and the
 * server's signature.
 *
 * `stellar.toml` publishes only the public `SIGNING_KEY`. The challenge is
 * signed with the matching secret when one is supplied; otherwise with an
 * ephemeral key, which the server reports so nobody mistakes the result for a
 * challenge their wallet can verify against the published key.
 */
import {
  Account,
  Keypair,
  Networks,
  Operation,
  StrKey,
  TransactionBuilder,
} from '@stellar/stellar-base';

/** SEP-10 recommends a challenge be valid for 15 minutes. */
const CHALLENGE_TTL_SECONDS = 900;

export interface Sep10Signer {
  keypair: Keypair;
  /** True when `keypair` is the file's `SIGNING_KEY`, false for an ephemeral key. */
  matchesSigningKey: boolean;
}

/**
 * The key challenges are signed with: `secret` when it is the secret for
 * `signingKey`, an ephemeral random key otherwise.
 */
export function resolveSep10Signer(signingKey: unknown, secret: string | undefined): Sep10Signer {
  if (secret !== undefined && StrKey.isValidEd25519SecretSeed(secret)) {
    const keypair = Keypair.fromSecret(secret);
    if (keypair.publicKey() === signingKey) return { keypair, matchesSigningKey: true };
  }
  return { keypair: Keypair.random(), matchesSigningKey: false };
}

export interface ChallengeRequest {
  /** The client account (`G...`) being authenticated. */
  account: string;
  homeDomain: string;
  webAuthDomain: string;
  networkPassphrase?: string;
}

export interface ChallengeResponse {
  transaction: string;
  network_passphrase: string;
}

/** Builds and signs a SEP-10 challenge for `request.account`. */
export function buildChallenge(signer: Keypair, request: ChallengeRequest): ChallengeResponse {
  const networkPassphrase = request.networkPassphrase ?? Networks.TESTNET;
  // Sequence -1 so the built transaction carries sequence number 0, which no
  // real account can submit — the property that makes a challenge harmless.
  const server = new Account(signer.publicKey(), '-1');
  const now = Math.floor(Date.now() / 1000);

  const nonce = new Uint8Array(48);
  crypto.getRandomValues(nonce);

  const transaction = new TransactionBuilder(server, {
    fee: '100',
    networkPassphrase,
    timebounds: { minTime: now, maxTime: now + CHALLENGE_TTL_SECONDS },
  })
    .addOperation(
      Operation.manageData({
        name: `${request.homeDomain} auth`,
        // 48 random bytes base64-encode to the 64-byte value SEP-10 specifies.
        value: Buffer.from(nonce).toString('base64'),
        source: request.account,
      }),
    )
    .addOperation(
      Operation.manageData({
        name: 'web_auth_domain',
        value: request.webAuthDomain,
        source: signer.publicKey(),
      }),
    )
    .build();

  transaction.sign(signer);
  return { transaction: transaction.toXDR(), network_passphrase: networkPassphrase };
}
