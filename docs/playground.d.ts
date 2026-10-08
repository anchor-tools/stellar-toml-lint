export const SAMPLES: {
  readonly 'Minimal Issuer': string;
  readonly 'SEP-24 Anchor': string;
  readonly 'Validator Node': string;
  readonly 'Broken TOML': string;
};

export function sourceFromHash(hash: string): string | undefined;
export function hashForSource(source: string): string;
