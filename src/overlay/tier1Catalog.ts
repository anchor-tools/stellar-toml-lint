/**
 * Catalog of Stellar Tier-1 validator organizations.
 *
 * Tier-1 organizations run at least three independent, high-uptime validators
 * that publish history archives, and together form the consensus core of the
 * public network. Quorum slices that do not lean on them can agree on values
 * the rest of the network rejects.
 *
 * The list changes as organizations join or leave Tier 1, so it is plain data:
 * {@link DEFAULT_TIER1_CATALOG} is the bundled snapshot, and operators can pass
 * their own file (`--tier1-catalog <file.json>`) in the format described by
 * `docs/schemas/tier1-catalog.schema.json`, validated by
 * {@link parseTier1Catalog}. Always confirm membership against
 * https://developers.stellar.org/docs/validators/tier-1-orgs before relying on
 * the snapshot.
 */

import { StrKey } from '@stellar/stellar-base';

/** Current catalog format version. */
export const TIER1_CATALOG_VERSION = 1;

/** One validator run by a Tier-1 organization. */
export interface Tier1Validator {
  /** Operator-facing node name, e.g. `sdf_1`. */
  name: string;
  /** StrKey-encoded Ed25519 node id (`G...`). */
  publicKey: string;
  /** ISO-8601 date the node joined the catalog; informational. */
  since?: string;
}

/** A Tier-1 organization and the validators it runs. */
export interface Tier1Organization {
  name: string;
  /** Home domain that publishes the organization's `stellar.toml`. */
  homeDomain: string;
  validators: Tier1Validator[];
}

/** Versioned Tier-1 catalog. */
export interface Tier1Catalog {
  version: number;
  /** ISO-8601 date the snapshot was last reviewed. */
  updated: string;
  /** Where the snapshot was taken from. */
  source?: string;
  organizations: Tier1Organization[];
}

/** Largest catalog accepted; keeps the subset search bounded. */
export const MAX_TIER1_ORGANIZATIONS = 16;

/**
 * Bundled snapshot of the Tier-1 organizations on the public network.
 * Every key passes the StrKey checksum; membership must still be confirmed
 * against the source before it is relied on.
 */
export const DEFAULT_TIER1_CATALOG: Tier1Catalog = {
  version: TIER1_CATALOG_VERSION,
  updated: '2026-11-23',
  source: 'https://developers.stellar.org/docs/validators/tier-1-orgs',
  organizations: [
    {
      name: 'Stellar Development Foundation',
      homeDomain: 'stellar.org',
      validators: [
        { name: 'sdf_1', publicKey: 'GCGB2S2KGYARPVIA37HYZXVRM2YZUEXA6S33ZU5BUDC6THSB62LZSTYH' },
        { name: 'sdf_2', publicKey: 'GCM6QMP3DLRPTAZW2UZPCPX2LF3SXWXKPMP3GKFZBDSF3QZGV2G5QSTK' },
        { name: 'sdf_3', publicKey: 'GABMKJM6I25XI4K7U6XWMULOUQIQ27BCTMLS6BYYSOWKTBUXVRJSXHYQ' },
      ],
    },
    {
      name: 'SatoshiPay',
      homeDomain: 'satoshipay.io',
      validators: [
        {
          name: 'satoshipay_frankfurt',
          publicKey: 'GC5SXLNAM3C4NMGK2PXK4R34B5GNZ47FYQ24ZIBFDFOCU6D4KBN4POAE',
        },
        {
          name: 'satoshipay_singapore',
          publicKey: 'GBJQUIXUO4XSNPAUT6ODLZUJRV2NPXYASKUBY4G5MYP3M47PCVI55MNT',
        },
        {
          name: 'satoshipay_iowa',
          publicKey: 'GAK6Z5UVGUVSEK6PEOCAYJISTT5EJBB34PN3NOLEQG2SUKXRVV2F6HZY',
        },
      ],
    },
    {
      name: 'LOBSTR',
      homeDomain: 'lobstr.co',
      validators: [
        { name: 'lobstr_1', publicKey: 'GCFONE23AB7Y6C5YZOMKUKGETPIAJA4QOYLS5VNS4JHBGKRZCPYHDLW7' },
        { name: 'lobstr_2', publicKey: 'GDXQB3OMMQ6MGG43PWFBZWBFKBBDUZIVSUDAZZTRAWQZKES2CDSE5HKJ' },
        { name: 'lobstr_3', publicKey: 'GD5QWEVV4GZZTQP46BRXV5CUMMMLP4JTGFD7FWYJJWRL54CELY6JGQ63' },
        { name: 'lobstr_4', publicKey: 'GA7TEPCBDQKI7JQLQ34ZURRMK44DVYCIGVXQQWNSWAEQR6KB4FMCBT7J' },
        { name: 'lobstr_5', publicKey: 'GA5STBMV6QDXFDGD62MEHLLHZTPDI77U3PFOD2SELU5RJDHQWBR5NNK7' },
      ],
    },
    {
      name: 'PublicNode',
      homeDomain: 'publicnode.org',
      validators: [
        {
          name: 'publicnode_bootes',
          publicKey: 'GDKWELGJURRKXECG3HHFHXMRX64YWQPUHKCVRESOX3E5PM6DM4YXLZJM',
        },
        {
          name: 'publicnode_lyra',
          publicKey: 'GBLJNN3AVZZPG2FYAYTYQKECNWTQYYUUY2KVFN2OUKZKBULXIXBZ4FCT',
        },
        {
          name: 'publicnode_hercules',
          publicKey: 'GCVJ4Z6TI6Z2SOGENSPXDQ2U4RKH3CNQKYUHNSSPYFPNWTLGS6EBH7I2',
        },
      ],
    },
    {
      name: 'Blockdaemon',
      homeDomain: 'stellar.blockdaemon.com',
      validators: [
        {
          name: 'blockdaemon_1',
          publicKey: 'GAAV2GCVFLNN522ORUYFV33E76VPC22E72S75AQ6MBR5V45Z5DWVPWEU',
        },
        {
          name: 'blockdaemon_2',
          publicKey: 'GAVXB7SBJRYHSG6KSQHY74N7JAFRL4PFVZCNWW2ARI6ZEKNBJSMSKW7C',
        },
        {
          name: 'blockdaemon_3',
          publicKey: 'GAYXZ4PZ7P6QOX7EBHPIZXNWY4KCOBYWJCA4WKWRKC7XIUS3UJPT6EZ4',
        },
      ],
    },
    {
      name: 'Franklin Templeton',
      homeDomain: 'stellar.franklintempleton.com',
      validators: [
        {
          name: 'franklin_templeton_1',
          publicKey: 'GARYGQ5F2IJEBCZJCBNPWNWVDOFK7IBOHLJKKSG2TMHDQKEEC6P4PE4V',
        },
        {
          name: 'franklin_templeton_2',
          publicKey: 'GCMSM2VFZGRPTZKPH5OABHGH4F3AVS6XTNJXDGCZ3MKCOSUBH3FL6DOB',
        },
        {
          name: 'franklin_templeton_3',
          publicKey: 'GA7DV63PBUUWNUFAF4GAZVXU2OZMYRATDLKTC7VTCG7AU4XUPN5VRX4A',
        },
      ],
    },
  ],
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function requireString(value: unknown, path: string, errors: string[]): string {
  if (typeof value !== 'string' || value.trim() === '') {
    errors.push(`${path} must be a non-empty string`);
    return '';
  }
  return value.trim();
}

/**
 * Validates an untrusted catalog (for example `JSON.parse` of a file) and
 * returns it in normalized form. Throws one error that lists every problem.
 */
export function parseTier1Catalog(input: unknown): Tier1Catalog {
  const errors: string[] = [];
  if (!isRecord(input)) throw new Error('Tier-1 catalog must be a JSON object');

  if (input.version !== TIER1_CATALOG_VERSION) {
    errors.push(`version must be ${TIER1_CATALOG_VERSION}`);
  }
  const updated = requireString(input.updated, 'updated', errors);
  if (updated !== '' && Number.isNaN(Date.parse(updated))) {
    errors.push('updated must be an ISO-8601 date');
  }
  const source =
    input.source === undefined ? undefined : requireString(input.source, 'source', errors);

  const organizations: Tier1Organization[] = [];
  const seenKeys = new Map<string, string>();
  const seenNames = new Set<string>();
  if (!Array.isArray(input.organizations) || input.organizations.length === 0) {
    errors.push('organizations must be a non-empty array');
  } else if (input.organizations.length > MAX_TIER1_ORGANIZATIONS) {
    errors.push(`organizations must list at most ${MAX_TIER1_ORGANIZATIONS} entries`);
  } else {
    input.organizations.forEach((raw: unknown, orgIndex) => {
      const orgPath = `organizations[${orgIndex}]`;
      if (!isRecord(raw)) {
        errors.push(`${orgPath} must be an object`);
        return;
      }
      const name = requireString(raw.name, `${orgPath}.name`, errors);
      if (name !== '' && seenNames.has(name.toLowerCase())) {
        errors.push(`${orgPath}.name duplicates another organization`);
      }
      seenNames.add(name.toLowerCase());
      const homeDomain = requireString(raw.homeDomain, `${orgPath}.homeDomain`, errors);
      const validators: Tier1Validator[] = [];
      if (!Array.isArray(raw.validators) || raw.validators.length === 0) {
        errors.push(`${orgPath}.validators must be a non-empty array`);
      } else {
        raw.validators.forEach((node: unknown, nodeIndex) => {
          const nodePath = `${orgPath}.validators[${nodeIndex}]`;
          if (!isRecord(node)) {
            errors.push(`${nodePath} must be an object`);
            return;
          }
          const nodeName = requireString(node.name, `${nodePath}.name`, errors);
          const publicKey = requireString(node.publicKey, `${nodePath}.publicKey`, errors);
          if (publicKey !== '' && !StrKey.isValidEd25519PublicKey(publicKey)) {
            errors.push(`${nodePath}.publicKey is not a valid G... public key`);
          } else if (publicKey !== '') {
            const owner = seenKeys.get(publicKey);
            if (owner !== undefined) {
              errors.push(`${nodePath}.publicKey is already listed under ${owner}`);
            }
            seenKeys.set(publicKey, name);
          }
          let since: string | undefined;
          if (node.since !== undefined) {
            since = requireString(node.since, `${nodePath}.since`, errors);
            if (since !== '' && Number.isNaN(Date.parse(since))) {
              errors.push(`${nodePath}.since must be an ISO-8601 date`);
            }
          }
          validators.push({
            name: nodeName,
            publicKey,
            ...(since === undefined ? {} : { since }),
          });
        });
      }
      organizations.push({ name, homeDomain: homeDomain.toLowerCase(), validators });
    });
  }

  if (errors.length > 0) {
    throw new Error(`Invalid Tier-1 catalog:\n  - ${errors.join('\n  - ')}`);
  }
  return {
    version: TIER1_CATALOG_VERSION,
    updated,
    ...(source === undefined ? {} : { source }),
    organizations,
  };
}
