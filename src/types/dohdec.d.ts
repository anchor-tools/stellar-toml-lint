declare module 'dohdec' {
  export class DNSoverHTTPS {
    constructor(options?: { url?: string; customFetch?: typeof fetch; http2?: boolean });
    lookup(
      name: string,
      options: {
        rrtype: string;
        json: false;
        decode: false;
        dnssec: true;
        dnssecCheckingDisabled: true;
        signal: AbortSignal;
      },
    ): Promise<Buffer | unknown>;
  }
}
