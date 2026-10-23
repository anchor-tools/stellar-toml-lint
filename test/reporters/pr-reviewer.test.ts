import { describe, expect, it } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  buildPullRequestReviewPayload,
  submitPullRequestReview,
} from '../../src/reporters/pr-reviewer.js';

describe('pull request review suggestions', () => {
  it('creates an inline suggestion from a diagnostic safe fix', () => {
    const payload = buildPullRequestReviewPayload(
      {
        repository: { name: 'stellar-toml-lint', owner: { login: 'anchor-tools' } },
        pull_request: { number: 42 },
      },
      [
        {
          filename: 'stellar.toml',
          source: 'ORG_URL = "http://example.com"\n',
          diagnostics: [
            {
              rule: 'general/https-required',
              severity: 'error',
              category: 'general',
              message: 'ORG_URL should use HTTPS',
              path: 'ORG_URL',
              position: { line: 1, column: 1 },
              fix: { value: 'https://example.com' },
            },
          ],
        },
      ],
    );

    expect(payload?.comments[0]).toMatchObject({
      path: 'stellar.toml',
      line: 1,
      side: 'RIGHT',
    });
    expect(payload?.comments[0]?.body).toContain(
      '```suggestion\nORG_URL = "https://example.com"\n```',
    );
    expect(payload?.comments[0]?.body).toContain('<!-- stellar-toml-lint:');
  });

  it('skips events without a pull request and diagnostics without safe fixes', () => {
    expect(
      buildPullRequestReviewPayload({ repository: { name: 'repo', owner: { login: 'org' } } }, []),
    ).toBeUndefined();
  });

  it('removes stale comments authored by the token user only', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'stellar-pr-review-'));
    const eventPath = join(directory, 'event.json');
    await writeFile(
      eventPath,
      JSON.stringify({
        repository: { name: 'repo', owner: { login: 'org' } },
        pull_request: { number: 12 },
      }),
    );
    const calls: string[] = [];
    try {
      const result = await submitPullRequestReview(
        [{ filename: 'stellar.toml', source: '', diagnostics: [] }],
        {
          eventPath,
          token: 'test-token',
          fetchImpl: async (input, init) => {
            const url = String(input);
            calls.push(`${init?.method ?? 'GET'} ${url}`);
            if (url.includes('/comments?'))
              return Response.json([
                { id: 7, user: { type: 'Bot' }, body: '<!-- stellar-toml-lint:stale -->' },
                { id: 8, user: { type: 'User' }, body: '<!-- stellar-toml-lint:stale -->' },
              ]);
            return new Response(null, { status: 204 });
          },
        },
      );
      expect(result.ok).toBe(true);
      expect(calls.some((call) => call.includes('/pulls/comments/7'))).toBe(true);
      expect(calls.some((call) => call.includes('/pulls/comments/8'))).toBe(false);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it('does not call GitHub for non-pull-request events', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'stellar-pr-review-'));
    const eventPath = join(directory, 'event.json');
    await writeFile(
      eventPath,
      JSON.stringify({ repository: { name: 'repo', owner: { login: 'org' } } }),
    );
    let requested = false;
    try {
      const result = await submitPullRequestReview([], {
        eventPath,
        token: 'test-token',
        fetchImpl: async () => {
          requested = true;
          return Response.json([]);
        },
      });
      expect(result.reason).toBe('Event is not a pull request');
      expect(requested).toBe(false);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
