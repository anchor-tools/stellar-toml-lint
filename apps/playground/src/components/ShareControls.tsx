import { useCallback, useState } from 'react';
import {
  encodeShareLink,
  shareLinkNotice,
  toMarkdownLink,
  type ShareState,
} from 'stellar-toml-lint/browser';

interface ShareControlsProps {
  /** Reads the buffer at click time, so typing never re-renders this. */
  getSource: () => string;
  /** Domain the loaded file was fetched from, when the session has one. */
  domain?: string;
  /** Severity overrides in force, carried so the recipient sees the same run. */
  rules?: ShareState['rules'];
  /** Whether the session is in strict mode. */
  strict?: boolean;
}

/**
 * One-click share link for the session in the buffer (issue #372).
 *
 * The link is built on click rather than on every keystroke: encoding is an
 * async compress and a digest, and doing that per character would make the
 * editor lag for no benefit — nobody shares a buffer they are still typing.
 */
export function ShareControls({ getSource, domain, rules, strict }: ShareControlsProps) {
  const [summary, setSummary] = useState('');
  const [markdown, setMarkdown] = useState('');
  const [copied, setCopied] = useState('');

  const build = useCallback(async () => {
    const state: ShareState = {
      source: getSource(),
      ...(domain === undefined ? {} : { domain }),
      ...(rules === undefined ? {} : { rules }),
      ...(strict === true ? { strict: true } : {}),
    };
    const link = await encodeShareLink(state, { pageUrl: window.location.href });
    setMarkdown(toMarkdownLink(link));
    setSummary(`${link.chars} characters. ${shareLinkNotice(link)}`);
    setCopied('');
    return link;
  }, [getSource, domain, rules, strict]);

  const copy = useCallback(
    async (kind: 'url' | 'markdown') => {
      const link = await build();
      const text = kind === 'url' ? link.url : toMarkdownLink(link);
      // A clipboard is a secure-context API: over plain HTTP it is simply
      // absent, and claiming "copied" then would be a lie. The generated text
      // stays on screen to select by hand instead of failing silently.
      const clipboard = navigator.clipboard;
      if (clipboard === undefined) {
        setCopied('No clipboard in this context — copy the text below.');
        return;
      }
      try {
        await clipboard.writeText(text);
        setCopied(kind === 'url' ? 'Link copied.' : 'Markdown copied.');
      } catch {
        setCopied('Your browser blocked the clipboard — copy the text below.');
      }
    },
    [build],
  );

  const button =
    'px-2 py-1 text-xs rounded bg-gray-800 text-gray-300 hover:bg-gray-700 transition-colors';

  return (
    <div className="border-t border-gray-800 bg-gray-900 px-4 py-2 text-xs">
      <div className="flex items-center gap-2">
        <span className="font-medium text-gray-400">Share</span>
        <button className={button} onClick={() => void copy('url')} type="button">
          Copy link
        </button>
        <button className={button} onClick={() => void copy('markdown')} type="button">
          Copy markdown
        </button>
        {copied && <span className="text-green-400">{copied}</span>}
        {summary && <span className="text-gray-400">{summary}</span>}
      </div>
      {markdown && (
        <pre className="mt-2 max-h-24 overflow-auto whitespace-pre-wrap break-all rounded bg-gray-950 p-2 text-gray-500">
          {markdown}
        </pre>
      )}
    </div>
  );
}
