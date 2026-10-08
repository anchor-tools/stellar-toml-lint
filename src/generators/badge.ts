import type { LintResult } from '../types.js';

export interface BadgeSvgOptions {
  label?: string;
}

interface ShieldsEndpoint {
  schemaVersion: 1;
  label: string;
  message: string;
  color: string;
}

function scoreColor(score: number): string {
  if (score >= 100) return 'brightgreen';
  if (score >= 80) return 'yellow';
  return 'red';
}

export function computeScore(result: LintResult): number {
  const total = result.counts.error + result.counts.warning + result.counts.info;
  if (total === 0) return 100;
  const deductions = result.counts.error * 10 + result.counts.warning * 3 + result.counts.info;
  return Math.max(0, Math.round(100 - deductions));
}

export function generateShieldsEndpoint(
  result: LintResult,
  label = 'stellar.toml',
): ShieldsEndpoint {
  const score = computeScore(result);
  return {
    schemaVersion: 1,
    label,
    message:
      result.counts.error > 0
        ? `${result.counts.error} error${result.counts.error === 1 ? '' : 's'}`
        : `${score}%`,
    color: scoreColor(score),
  };
}

export function generateBadgeSvg(result: LintResult, options: BadgeSvgOptions = {}): string {
  const label = options.label ?? 'stellar.toml';
  const endpoint = generateShieldsEndpoint(result, label);
  const message = endpoint.message;

  const colorMap: Record<string, string> = {
    brightgreen: '#4c1',
    yellow: '#dfb317',
    red: '#e05d44',
  };
  const fill = colorMap[endpoint.color] ?? '#9f9f9f';

  const labelWidth = label.length * 7 + 10;
  const messageWidth = message.length * 7 + 10;
  const totalWidth = labelWidth + messageWidth;

  return [
    `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="20">`,
    `  <linearGradient id="b" x2="0" y2="100%">`,
    `    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>`,
    `    <stop offset="1" stop-opacity=".1"/>`,
    `  </linearGradient>`,
    `  <mask id="a">`,
    `    <rect width="${totalWidth}" height="20" rx="3" fill="#fff"/>`,
    `  </mask>`,
    `  <g mask="url(#a)">`,
    `    <rect width="${labelWidth}" height="20" fill="#555"/>`,
    `    <rect x="${labelWidth}" width="${messageWidth}" height="20" fill="${fill}"/>`,
    `    <rect width="${totalWidth}" height="20" fill="url(#b)"/>`,
    `  </g>`,
    `  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">`,
    `    <text x="${labelWidth / 2}" y="15" fill="#010101" fill-opacity=".3">${escapeXml(label)}</text>`,
    `    <text x="${labelWidth / 2}" y="14">${escapeXml(label)}</text>`,
    `    <text x="${labelWidth + messageWidth / 2}" y="15" fill="#010101" fill-opacity=".3">${escapeXml(message)}</text>`,
    `    <text x="${labelWidth + messageWidth / 2}" y="14">${escapeXml(message)}</text>`,
    `  </g>`,
    `</svg>`,
  ].join('\n');
}

function escapeXml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
