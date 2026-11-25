/**
 * Human-readable rendering of a Cloud KMS signer check.
 *
 * Credentials are never part of the report, so this formatter has nothing to
 * redact; it only prints key metadata, the signature shape, and the quorum
 * verdict an operator needs to attach to an audit trail.
 */
import type { CloudKmsSignerReport } from './kmsSignerCoordinator.js';

/** Formats a coordinator report as a terminal block. */
export function formatKmsSignerReport(report: CloudKmsSignerReport): string {
  const lines: string[] = [
    `Cloud KMS signer check — ${report.key.provider.toUpperCase()} KMS`,
    '',
    `  Key          ${report.key.resourceName}`,
    `  Algorithm    ${report.key.algorithm}`,
  ];

  if (report.key.stellarAddress !== undefined) {
    lines.push(`  Stellar key  ${report.key.stellarAddress}`);
  }
  lines.push(`  Hint         ${report.key.hint}`);
  if (report.key.keyState !== undefined) {
    lines.push(`  Key state    ${report.key.keyState}`);
  }
  lines.push(`  Network      ${report.transaction.networkPassphrase}`);
  lines.push(`  Transaction  ${report.transaction.type} ${report.transaction.hash}`);
  lines.push(`  Image        ${report.transaction.source}`);

  if (report.signature !== undefined) {
    lines.push(
      `  Signature    ${report.signature.length} bytes, ${report.signature.format}, ` +
        `${report.signature.verified ? 'verified' : 'not verified'} ` +
        `(${report.signature.attempts} attempt${report.signature.attempts === 1 ? '' : 's'})`,
    );
    lines.push(`  Decorated    ${report.signature.decoratedXdr}`);
  }

  if (report.quorum.checked) {
    lines.push(
      `  Quorum       ${report.quorum.signerKey ?? '(unknown signer)'} weight ` +
        `${report.quorum.signerWeight ?? 0} of ${report.quorum.thresholdName} ` +
        `threshold ${report.quorum.threshold ?? '?'} — ${report.quorum.met ? 'met' : 'NOT met'}`,
    );
  } else {
    lines.push(`  Quorum       not checked${reasonSuffix(report.quorum.reason)}`);
  }

  lines.push('', '  Checks');
  for (const check of report.checks) {
    lines.push(`    ${check.ok ? '[✓]' : '[✗]'} ${check.id.padEnd(22)} ${check.message}`);
  }

  if (report.warnings.length > 0) {
    lines.push('', '  Warnings');
    for (const warning of report.warnings) lines.push(`    - ${warning}`);
  }

  lines.push('', `  Result: ${report.ok ? 'PASS' : 'FAIL'}`);
  return `${lines.join('\n')}\n`;
}

function reasonSuffix(reason: string | undefined): string {
  return reason === undefined ? '' : ` (${reason})`;
}
