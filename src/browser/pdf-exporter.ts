/**
 * Browser-based Offline PDF Compliance Report Generator
 *
 * Generates multi-page PDF audit reports with executive summary,
 * asset breakdown, validator quorum graph, and cryptographic checksums
 * using pdfmake. Works completely offline in the browser.
 */

import { createPdf, addVirtualFileSystem, type Content, type Style } from 'pdfmake';
import pdfFonts from 'pdfmake/build/vfs_fonts.js';

// Type definitions not exported by pdfmake, define locally
interface TVirtualFileSystem {
  [filePath: string]: string;
}

interface TDocumentDefinitions {
  content: Content[];
  pageSize?: 'A4' | 'A3' | 'LETTER';
  pageOrientation?: 'portrait' | 'landscape';
  pageMargins?: [number, number, number, number];
  watermark?: { text: string; color: string; opacity: number; bold: boolean; fontSize: number };
  styles?: Record<string, Style>;
  defaultStyle?: Style;
  footer?: (currentPage: number, pageCount: number) => Content;
}

addVirtualFileSystem(pdfFonts as TVirtualFileSystem);

export interface ComplianceReportData {
  document: Record<string, unknown>;
  diagnostics: Array<{
    rule: string;
    severity: 'error' | 'warning' | 'info';
    category: string;
    message: string;
    path?: string;
    position?: { line: number; column: number };
    helpUri?: string;
    suggestion?: string;
  }>;
  metadata: {
    linterVersion: string;
    timestamp: string;
    domain?: string;
    networkPassphrase?: string;
  };
}

export interface PDFExportOptions {
  title?: string;
  includeExecutiveSummary?: boolean;
  includeAssetBreakdown?: boolean;
  includeValidatorDetails?: boolean;
  includeDiagnostics?: boolean;
  includeQuorumGraph?: boolean;
  includeChecksum?: boolean;
  watermark?: string;
  pageSize?: 'A4' | 'A3' | 'LETTER';
  pageOrientation?: 'portrait' | 'landscape';
  margins?: [number, number, number, number];
}

const DEFAULT_OPTIONS: Required<PDFExportOptions> = {
  title: 'Stellar TOML Compliance Audit Certificate',
  includeExecutiveSummary: true,
  includeAssetBreakdown: true,
  includeValidatorDetails: true,
  includeDiagnostics: true,
  includeQuorumGraph: false,
  includeChecksum: true,
  watermark: 'CONFIDENTIAL',
  pageSize: 'A4',
  pageOrientation: 'portrait',
  margins: [40, 60, 40, 60],
};

function calculateSHA256(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  return crypto.subtle.digest('SHA-256', dataBuffer).then((hashBuffer) => {
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  });
}

function getSeverityLabel(severity: string): string {
  return severity.charAt(0).toUpperCase() + severity.slice(1);
}

function computeComplianceScore(diagnostics: ComplianceReportData['diagnostics']): number {
  const total = diagnostics.length;
  if (total === 0) return 100;

  const weights = { error: 10, warning: 3, info: 1 };
  let penalty = 0;

  for (const diag of diagnostics) {
    penalty += weights[diag.severity] ?? 1;
  }

  const maxPenalty = total * weights.error;
  const score = Math.max(0, Math.round(100 - (penalty / maxPenalty) * 100));
  return score;
}

function formatDate(date: Date): string {
  return date.toISOString().replace('T', ' ').split('.')[0] + ' UTC';
}

function createExecutiveSummary(data: ComplianceReportData, options: Required<PDFExportOptions>): Content[] {
  const score = computeComplianceScore(data.diagnostics);
  const errorCount = data.diagnostics.filter((d) => d.severity === 'error').length;
  const warningCount = data.diagnostics.filter((d) => d.severity === 'warning').length;
  const infoCount = data.diagnostics.filter((d) => d.severity === 'info').length;

  const rating = score >= 90 ? 'EXCELLENT' : score >= 75 ? 'GOOD' : score >= 60 ? 'FAIR' : 'POOR';

  return [
    { text: 'Executive Summary', style: 'sectionHeader', margin: [0, 0, 0, 10] },
    {
      style: 'table',
      table: {
        widths: ['30%', '70%'],
        body: [
          [{ text: 'Report Title', style: 'tableHeader' }, { text: options.title, style: 'tableCell' }],
          [{ text: 'Generated', style: 'tableHeader' }, { text: formatDate(new Date(data.metadata.timestamp)), style: 'tableCell' }],
          [{ text: 'Linter Version', style: 'tableHeader' }, { text: data.metadata.linterVersion, style: 'tableCell' }],
          [{ text: 'Domain', style: 'tableHeader' }, { text: data.metadata.domain ?? 'Local File', style: 'tableCell' }],
          [{ text: 'Network', style: 'tableHeader' }, { text: data.metadata.networkPassphrase ?? 'Public Global Stellar Network', style: 'tableCell' }],
          [{ text: 'Compliance Score', style: 'tableHeader' }, { text: `${score}% (${rating})`, style: { ...styles.tableCell, color: score >= 75 ? '#10B981' : score >= 50 ? '#F59E0B' : '#EF4444', bold: true } }],
          [{ text: 'Total Findings', style: 'tableHeader' }, { text: `${data.diagnostics.length} (${errorCount} errors, ${warningCount} warnings, ${infoCount} info)`, style: 'tableCell' }],
        ],
      },
      layout: 'lightHorizontalLines',
      margin: [0, 0, 0, 20],
    },
  ];
}

function createAssetBreakdown(data: ComplianceReportData): Content[] {
  const doc = data.document;
  interface CurrencyEntry {
    code?: string;
    issuer?: string;
    anchor_asset_type?: string;
    anchor_asset?: string;
    is_unlimited?: boolean;
    fixed_number?: string | number;
    max_number?: string | number;
  }
  const currencies = (doc.CURRENCIES as Array<CurrencyEntry>) ?? [];

  if (currencies.length === 0) {
    return [
      { text: 'Asset Breakdown', style: 'sectionHeader', margin: [0, 0, 0, 10] },
      { text: 'No assets declared in CURRENCIES.', style: 'body', margin: [0, 0, 0, 20] },
    ];
  }

  const rows = [
    [{ text: 'Code', style: 'tableHeader' }, { text: 'Issuer', style: 'tableHeader' }, { text: 'Type', style: 'tableHeader' }, { text: 'Anchor Asset', style: 'tableHeader' }, { text: 'Status', style: 'tableHeader' }],
  ];

  for (const curr of currencies) {
    const code = curr.code ?? '—';
    const issuer = curr.issuer ?? '—';
    const type = curr.anchor_asset_type ?? 'stellar';
    const anchorAsset = curr.anchor_asset ?? '—';
    const status = curr.is_unlimited ? 'Unlimited' : curr.fixed_number ? `Fixed: ${curr.fixed_number}` : curr.max_number ? `Max: ${curr.max_number}` : '—';

    rows.push([
      { text: code, style: 'tableCell' },
      { text: issuer.length > 30 ? issuer.slice(0, 30) + '…' : issuer, style: 'tableCell' },
      { text: type, style: 'tableCell' },
      { text: anchorAsset, style: 'tableCell' },
      { text: status, style: 'tableCell' },
    ]);
  }

  return [
    { text: 'Asset Breakdown', style: 'sectionHeader', margin: [0, 0, 0, 10] },
    {
      style: 'table',
      table: {
        headerRows: 1,
        widths: ['15%', '30%', '12%', '20%', '23%'],
        body: rows,
      },
      layout: 'lightHorizontalLines',
      margin: [0, 0, 0, 20],
    },
  ];
}

function createValidatorDetails(data: ComplianceReportData): Content[] {
  const doc = data.document;
  interface ValidatorEntry {
    ALIAS?: string;
    PUBLIC_KEY?: string;
    HOST?: string;
    HISTORY?: string;
  }
  const validators = (doc.VALIDATORS as Array<ValidatorEntry>) ?? [];

  if (validators.length === 0) {
    return [
      { text: 'Validator Quorum Set', style: 'sectionHeader', margin: [0, 0, 0, 10] },
      { text: 'No validators declared.', style: 'body', margin: [0, 0, 0, 20] },
    ];
  }

  const rows = [
    [{ text: 'Alias', style: 'tableHeader' }, { text: 'Public Key', style: 'tableHeader' }, { text: 'Host', style: 'tableHeader' }, { text: 'History', style: 'tableHeader' }],
  ];

  for (const val of validators) {
    const alias = val.ALIAS ?? '—';
    const pubKey = val.PUBLIC_KEY ?? '—';
    const host = val.HOST ?? '—';
    const history = val.HISTORY ?? '—';

    rows.push([
      { text: alias, style: 'tableCell' },
      { text: pubKey.length > 30 ? pubKey.slice(0, 30) + '…' : pubKey, style: 'tableCell' },
      { text: host, style: 'tableCell' },
      { text: history, style: 'tableCell' },
    ]);
  }

  return [
    { text: 'Validator Quorum Set', style: 'sectionHeader', margin: [0, 0, 0, 10] },
    {
      style: 'table',
      table: {
        headerRows: 1,
        widths: ['20%', '30%', '25%', '25%'],
        body: rows,
      },
      layout: 'lightHorizontalLines',
      margin: [0, 0, 0, 20],
    },
  ];
}

function createDiagnostics(data: ComplianceReportData): Content[] {
  const diagnostics = data.diagnostics;

  if (diagnostics.length === 0) {
    return [
      { text: 'Diagnostic Findings', style: 'sectionHeader', margin: [0, 0, 0, 10] },
      { text: 'No issues found. The stellar.toml file passes all validation rules.', style: 'body', margin: [0, 0, 0, 20] },
    ];
  }

  const grouped = diagnostics.reduce((acc, diag) => {
    const cat = acc[diag.category] ?? [];
    cat.push(diag);
    acc[diag.category] = cat;
    return acc;
  }, {} as Record<string, typeof diagnostics>);

  const content: Content[] = [
    { text: 'Diagnostic Findings', style: 'sectionHeader', margin: [0, 0, 0, 10] },
  ];

  for (const [category, diags] of Object.entries(grouped)) {
    content.push({ text: category, style: 'subSectionHeader', margin: [0, 10, 0, 5] });

    const rows = [
      [{ text: 'Rule', style: 'tableHeader' }, { text: 'Severity', style: 'tableHeader' }, { text: 'Message', style: 'tableHeader' }, { text: 'Location', style: 'tableHeader' }, { text: 'Suggestion', style: 'tableHeader' }],
    ];

    for (const diag of diags) {
      rows.push([
        { text: diag.rule, style: 'tableCellSmall' },
        {
          text: getSeverityLabel(diag.severity),
          style: 'tableCellSmallSeverity',
        },
        { text: diag.message, style: 'tableCellSmall' },
        {
          text: diag.path ?? (diag.position ? `L${diag.position.line}:C${diag.position.column}` : '—'),
          style: 'tableCellSmall',
        },
        { text: diag.suggestion ?? '—', style: 'tableCellSmall' },
      ]);
    }

    content.push({
      style: 'table',
      table: {
        headerRows: 1,
        widths: ['18%', '10%', '32%', '15%', '25%'],
        body: rows,
      },
      layout: 'lightHorizontalLines',
      margin: [0, 0, 0, 15],
    });
  }

  return content;
}

function createChecksumPage(data: ComplianceReportData, checksum: string): Content[] {
  const canonicalContent = JSON.stringify(data.document, null, 2);

  return [
    { text: 'Cryptographic Verification', style: 'sectionHeader', margin: [0, 0, 0, 10] },
    {
      style: 'table',
      table: {
        widths: ['30%', '70%'],
        body: [
          [{ text: 'Document SHA-256', style: 'tableHeader' }, { text: checksum, style: 'tableCellMonospace' }],
          [{ text: 'Linter Version', style: 'tableHeader' }, { text: data.metadata.linterVersion, style: 'tableCell' }],
          [{ text: 'Timestamp', style: 'tableHeader' }, { text: formatDate(new Date(data.metadata.timestamp)), style: 'tableCell' }],
          [{ text: 'Canonical Document Length', style: 'tableHeader' }, { text: `${canonicalContent.length} bytes`, style: 'tableCell' }],
        ],
      },
      layout: 'lightHorizontalLines',
      margin: [0, 0, 0, 20],
    },
    { text: 'Verification', style: 'subSectionHeader', margin: [0, 10, 0, 5] },
    {
      text: 'To verify this certificate, compute SHA-256 of the canonical JSON representation of the stellar.toml document and compare with the checksum above. This certificate was generated offline in the browser with no server-side processing.',
      style: 'body',
      margin: [0, 0, 0, 20],
    },
    { text: 'End of Certificate', style: 'sectionHeader', margin: [0, 30, 0, 0], alignment: 'center' },
  ];
}

const styles: Record<string, Record<string, unknown>> = {
  header: { fontSize: 22, bold: true, color: '#1E3A8A', margin: [0, 0, 0, 5] },
  subHeader: { fontSize: 14, color: '#6B7280', margin: [0, 0, 0, 20] },
  sectionHeader: { fontSize: 16, bold: true, color: '#1F2937', margin: [0, 15, 0, 5] },
  subSectionHeader: { fontSize: 12, bold: true, color: '#374151', margin: [0, 10, 0, 5] },
  body: { fontSize: 10, color: '#374151', lineHeight: 1.4 },
  tableHeader: { fontSize: 9, bold: true, color: '#FFFFFF', fillColor: '#1E3A8A', alignment: 'center' },
  tableCell: { fontSize: 9, color: '#374151', alignment: 'left' },
  tableCellSmall: { fontSize: 8, color: '#374151', alignment: 'left' },
  tableCellSmallSeverity: { fontSize: 8, color: '#374151', alignment: 'left', bold: true },
  tableCellMonospace: { fontSize: 9, color: '#374151', alignment: 'left', fontFamily: 'Courier' },
  footer: { fontSize: 8, color: '#9CA3AF', alignment: 'center', margin: [0, 20, 0, 0] },
};

export async function generateCompliancePDF(
  data: ComplianceReportData,
  options: PDFExportOptions = {}
): Promise<Blob> {
  const opts = { ...DEFAULT_OPTIONS, ...options };

  const canonicalContent = JSON.stringify(data.document, null, 2);
  const checksum = await calculateSHA256(canonicalContent);

  const docDefinition: TDocumentDefinitions = {
    pageSize: opts.pageSize,
    pageOrientation: opts.pageOrientation,
    pageMargins: opts.margins,
    watermark: { text: opts.watermark, color: 'gray', opacity: 0.05, bold: true, fontSize: 80 },
    styles,
    defaultStyle: { font: 'Roboto' },
    content: [
      { text: opts.title, style: 'header' },
      { text: `Generated by stellar-toml-lint v${data.metadata.linterVersion}`, style: 'subHeader' },
      { canvas: [{ type: 'line', x1: 0, y1: 0, x2: 515, y2: 0, lineWidth: 1, lineColor: '#E5E7EB' }], margin: [0, 0, 0, 20] },
    ],
    footer: (currentPage: number, pageCount: number) => ({
      text: `Page ${currentPage} of ${pageCount} | stellar-toml-lint v${data.metadata.linterVersion} | ${formatDate(new Date())}`,
      style: 'footer',
    }),
  };

  if (opts.includeExecutiveSummary) {
    docDefinition.content.push(...createExecutiveSummary(data, opts));
  }

  if (opts.includeAssetBreakdown) {
    docDefinition.content.push(...createAssetBreakdown(data));
  }

  if (opts.includeValidatorDetails) {
    docDefinition.content.push(...createValidatorDetails(data));
  }

  if (opts.includeDiagnostics) {
    docDefinition.content.push(...createDiagnostics(data));
  }

  if (opts.includeChecksum) {
    docDefinition.content.push({ pageBreak: 'before' } as Content);
    docDefinition.content.push(...createChecksumPage(data, checksum));
  }

  return new Promise((resolve, reject) => {
    try {
      const pdfDoc = createPdf(docDefinition);
      pdfDoc.getBlob().then((blob: Blob) => resolve(blob)).catch(reject);
    } catch (error) {
      reject(error);
    }
  });
}

export async function downloadCompliancePDF(
  data: ComplianceReportData,
  filename?: string,
  options: PDFExportOptions = {}
): Promise<void> {
  const blob = await generateCompliancePDF(data, options);
  const url = URL.createObjectURL(blob);
  if (typeof document !== 'undefined') {
    const link = document.createElement('a');
    link.href = url;
    link.download = filename ?? `stellar-toml-audit-${new Date().toISOString().split('T')[0]}.pdf`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }
  URL.revokeObjectURL(url);
}