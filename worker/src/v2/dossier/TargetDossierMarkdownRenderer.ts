/**
 * R3 (P3) — Target Dossier Markdown rendering.
 *
 * Pure formatting of an already-built TargetDossier into a human-readable
 * Markdown file — the companion to the JSON export, meant to be legible
 * on its own when carried into manual tooling (Parrot). No new data, no
 * claims beyond what the dossier itself already states.
 */

import type { TargetDossier } from './TargetDossierContracts.js';

function escapeMd(value: string): string {
  return value.replace(/\|/g, '\\|');
}

export function renderTargetDossierMarkdown(dossier: TargetDossier): string {
  const lines: string[] = [];

  lines.push(`# Target Dossier — ${dossier.targetDomain}`);
  lines.push('');
  lines.push(`- **Assessment**: \`${dossier.assessmentId}\` (scan \`${dossier.scanId}\`)`);
  lines.push(`- **Generated**: ${dossier.generatedAt}`);
  lines.push(`- **Actor**: \`${dossier.lineage.actorId}\``);
  lines.push('');
  lines.push(
    '> Recon + classification + advisory hypotheses only. No new probing was performed to build this file, ' +
      'nothing here is auto-confirmed, and hypotheses marked "deferred to manual validation" require operator ' +
      'action (e.g. Parrot) before they mean anything more than a lead worth investigating.'
  );
  lines.push('');

  lines.push('## Surface Summary');
  lines.push('');
  lines.push(`Total discovered endpoints: **${dossier.surfaceSummary.totalEndpoints}**`);
  lines.push('');
  lines.push('| Classification | Count |');
  lines.push('|---|---|');
  for (const [kind, count] of Object.entries(dossier.surfaceSummary.byClassification)) {
    lines.push(`| ${kind} | ${count} |`);
  }
  lines.push('');
  if (dossier.surfaceSummary.unclassifiedEndpointUrls.length > 0) {
    lines.push(
      `**Unclassified endpoints**${dossier.surfaceSummary.unclassifiedEndpointUrlsTruncated ? ' (sample)' : ''}:`
    );
    lines.push('');
    for (const url of dossier.surfaceSummary.unclassifiedEndpointUrls) {
      lines.push(`- ${escapeMd(url)}`);
    }
    lines.push('');
  }

  lines.push('## Hypotheses');
  lines.push('');
  if (dossier.hypotheses.length === 0) {
    lines.push('_No hypotheses generated._');
    lines.push('');
  } else {
    if (dossier.hypothesesTruncated) {
      lines.push('_List truncated — see the full JSON export for the complete set._');
      lines.push('');
    }
    lines.push('| Score | Kind | Deferred to manual validation | Title | Blocked |');
    lines.push('|---|---|---|---|---|');
    for (const h of dossier.hypotheses) {
      lines.push(
        `| ${h.score} | ${h.hypothesisKind} | ${h.deferredToManualValidation ? 'yes' : 'no'} | ${escapeMd(h.title)} | ${h.blocked ? `yes (${h.blockReason})` : 'no'} |`
      );
    }
    lines.push('');
  }

  lines.push('## Findings (human-approved)');
  lines.push('');
  if (dossier.findings.length === 0) {
    lines.push('_No approved findings yet._');
    lines.push('');
  } else {
    lines.push('| Severity | Type | Title | Target | Verification State |');
    lines.push('|---|---|---|---|---|');
    for (const f of dossier.findings) {
      lines.push(
        `| ${f.severity} | ${f.type} | ${escapeMd(f.title)} | ${escapeMd(f.target)} | ${f.verificationState} |`
      );
    }
    lines.push('');
  }

  lines.push('## Non-Claims');
  lines.push('');
  lines.push('- No new probing was performed to build this file.');
  lines.push('- No autonomous exploitation occurred.');
  lines.push('- Hypotheses are advisory only — never auto-executed.');
  lines.push('- Hypotheses marked deferred-to-manual-validation require operator action before they mean anything confirmed.');
  lines.push('');

  return lines.join('\n');
}
