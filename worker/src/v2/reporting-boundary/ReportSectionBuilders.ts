/**
 * FixGuard V2 — HTML Report Section Builders (Milestone P2-6)
 *
 * Implements self-contained, dependency-free HTML and CSS generation for
 * authoritative defensive assessment reports:
 * - Header & Assessment Lineage Metadata
 * - Executive Summary with Severity Breakdown
 * - Mandatory Audit Limitations & Defensive Scope Constraints
 * - Confirmed Findings (HITL Promoted only) with Evidence & Lineage
 * - Advisory Recommendations
 * - Signed Operator Attestation Statement
 */

import type { OrchestratedAssessmentRecord } from '../application/OrchestratedAssessmentContracts.js';
import type { Finding } from '../core/Evidence.js';
import type { TargetRecommendation } from '../intelligence/IntelligenceContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import { sanitizeEvidenceFragment } from '../core/EvidenceSanitizer.js';
import type { AttackChain } from '../attack-chain/AttackChainContracts.js';
import type { AttackPlan } from '../attack-planning/AttackPlanContracts.js';
import type {
  CredentialReference,
  PostExploitationState,
} from '../post-exploitation/PostExploitationContracts.js';
import type { ImpactAssessment } from './ImpactAssessmentContracts.js';
import { formatEpistemicBadge } from './ImpactAssessmentContracts.js';

export function escapeHtml(str: string): string {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

export function buildReportStyles(): string {
  return `
    :root {
      --bg: #09090b;
      --card-bg: #121215;
      --card-border: #27272a;
      --text: #f4f4f5;
      --text-muted: #a1a1aa;
      --text-dim: #71717a;
      --accent: #3b82f6;
      --severity-crit: #ef4444;
      --severity-high: #f97316;
      --severity-med: #eab308;
      --severity-low: #3b82f6;
      --severity-info: #10b981;
    }
    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 2.5rem 1.5rem;
    }
    .report-container {
      max-width: 960px;
      margin: 0 auto;
      display: flex;
      flex-direction: column;
      gap: 2rem;
    }
    .card {
      background-color: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 1.5rem;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
    }
    .header-badge {
      display: inline-block;
      font-size: 0.75rem;
      font-family: monospace;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      padding: 0.25rem 0.6rem;
      border-radius: 6px;
      background: rgba(59, 130, 246, 0.15);
      border: 1px solid rgba(59, 130, 246, 0.3);
      color: #60a5fa;
      margin-bottom: 0.75rem;
    }
    h1 {
      font-size: 1.75rem;
      font-weight: 700;
      letter-spacing: -0.02em;
      margin-bottom: 0.5rem;
      color: #ffffff;
    }
    h2 {
      font-size: 1.25rem;
      font-weight: 600;
      margin-bottom: 1rem;
      border-bottom: 1px solid var(--card-border);
      padding-bottom: 0.5rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    h3 {
      font-size: 1rem;
      font-weight: 600;
      margin-bottom: 0.5rem;
    }
    .meta-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
      margin-top: 1rem;
    }
    .meta-item {
      display: flex;
      flex-direction: column;
      gap: 0.2rem;
    }
    .meta-label {
      font-size: 0.75rem;
      color: var(--text-dim);
      text-transform: uppercase;
      font-family: monospace;
    }
    .meta-value {
      font-size: 0.875rem;
      font-family: monospace;
      color: var(--text);
      word-break: break-all;
    }
    .summary-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 1rem;
      margin-top: 1rem;
    }
    .summary-card {
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 1rem;
      text-align: center;
    }
    .summary-count {
      font-size: 1.75rem;
      font-weight: 700;
      font-family: monospace;
    }
    .summary-label {
      font-size: 0.75rem;
      color: var(--text-muted);
      text-transform: uppercase;
      margin-top: 0.25rem;
    }
    .badge {
      display: inline-block;
      font-size: 0.7rem;
      font-family: monospace;
      font-weight: 700;
      text-transform: uppercase;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
    }
    .badge-critical { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }
    .badge-high { background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.4); }
    .badge-medium { background: rgba(234, 179, 8, 0.2); color: #facc15; border: 1px solid rgba(234, 179, 8, 0.4); }
    .badge-low { background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.4); }
    .badge-info { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }
    .finding-card {
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 1.25rem;
      margin-bottom: 1rem;
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
    }
    .finding-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 1rem;
      flex-wrap: wrap;
    }
    .finding-title {
      font-size: 1rem;
      font-weight: 600;
      color: #ffffff;
    }
    .finding-desc {
      font-size: 0.875rem;
      color: var(--text-muted);
    }
    .code-box {
      background: #000000;
      border: 1px solid #1f1f23;
      border-radius: 6px;
      padding: 0.75rem;
      font-family: monospace;
      font-size: 0.8rem;
      color: #d4d4d8;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }
    .limitations-list {
      list-style-type: none;
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
      font-size: 0.875rem;
      color: var(--text-muted);
    }
    .limitations-list li {
      padding-left: 1.5rem;
      position: relative;
    }
    .limitations-list li::before {
      content: "•";
      position: absolute;
      left: 0.5rem;
      color: #f59e0b;
      font-weight: bold;
    }
    .attestation-box {
      background: rgba(16, 185, 129, 0.05);
      border: 1px solid rgba(16, 185, 129, 0.3);
      border-radius: 8px;
      padding: 1.25rem;
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
    }
    .attestation-statement {
      font-style: italic;
      font-size: 0.95rem;
      color: #e4e4e7;
    }
    .attestation-meta {
      display: flex;
      flex-wrap: wrap;
      gap: 1.5rem;
      font-size: 0.8rem;
      font-family: monospace;
      color: #a1a1aa;
      border-top: 1px solid rgba(16, 185, 129, 0.2);
      padding-top: 0.75rem;
    }
    .footer {
      text-align: center;
      font-size: 0.75rem;
      font-family: monospace;
      color: var(--text-dim);
      padding: 1rem 0;
    }
    .epistemic-badge {
      display: inline-block;
      font-size: 0.7rem;
      font-family: monospace;
      font-weight: 700;
      letter-spacing: 0.02em;
      padding: 0.2rem 0.55rem;
      border-radius: 4px;
      white-space: nowrap;
    }
    .epistemic-verified {
      background: rgba(16, 185, 129, 0.15);
      color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.4);
    }
    .epistemic-inferred {
      background: rgba(234, 179, 8, 0.12);
      color: #facc15;
      border: 1px solid rgba(234, 179, 8, 0.35);
    }
    .epistemic-refuted {
      background: rgba(239, 68, 68, 0.12);
      color: #f87171;
      border: 1px solid rgba(239, 68, 68, 0.35);
    }
    .epistemic-observed {
      background: rgba(59, 130, 246, 0.12);
      color: #60a5fa;
      border: 1px solid rgba(59, 130, 246, 0.35);
    }
    .adversarial-item {
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 1rem;
      margin-bottom: 0.75rem;
    }
  `;
}

function epistemicBadgeClass(status: string): string {
  switch (status) {
    case 'VERIFIED':
      return 'epistemic-verified';
    case 'INFERRED':
      return 'epistemic-inferred';
    case 'REFUTED':
      return 'epistemic-refuted';
    case 'OBSERVED':
      return 'epistemic-observed';
    default:
      return 'epistemic-inferred';
  }
}

function renderEpistemicBadgeHtml(status: 'OBSERVED' | 'INFERRED' | 'VERIFIED' | 'REFUTED'): string {
  const badge = formatEpistemicBadge(status);
  return `<span class="epistemic-badge ${epistemicBadgeClass(status)}">${escapeHtml(badge)}</span>`;
}

export function buildHeaderSection(record: OrchestratedAssessmentRecord): string {
  const target = escapeHtml(record.targetDomain);
  const assessmentId = escapeHtml(record.assessmentId);
  const scanId = escapeHtml(record.scanId);
  const grantId = escapeHtml(record.lineage.authorizationGrantId);
  const decisionId = escapeHtml(record.lineage.authorizationDecisionId);
  const actorId = escapeHtml(record.lineage.actorId);
  const startedAt = escapeHtml(record.timing.startedAt);
  const completedAt = escapeHtml(record.timing.completedAt ?? 'In Progress');
  const duration = record.timing.durationMs ? `${(record.timing.durationMs / 1000).toFixed(2)}s` : 'N/A';

  return `
    <header class="card">
      <div class="header-badge">FixGuard V2 Defensive Security Assessment</div>
      <h1>Defensive Assessment Report</h1>
      <p style="color: var(--text-muted); font-size: 0.95rem;">
        Authorized target assessment for <strong style="color: #ffffff;">https://${target}</strong>
      </p>

      <div class="meta-grid">
        <div class="meta-item">
          <span class="meta-label">Assessment ID</span>
          <span class="meta-value">${assessmentId}</span>
        </div>
        <div class="meta-item">
          <span class="meta-label">Scan ID</span>
          <span class="meta-value">${scanId}</span>
        </div>
        <div class="meta-item">
          <span class="meta-label">Authorization Grant</span>
          <span class="meta-value">${grantId}</span>
        </div>
        <div class="meta-item">
          <span class="meta-label">Decision ID</span>
          <span class="meta-value">${decisionId}</span>
        </div>
        <div class="meta-item">
          <span class="meta-label">Authorized Actor</span>
          <span class="meta-value">${actorId}</span>
        </div>
        <div class="meta-item">
          <span class="meta-label">Started At</span>
          <span class="meta-value">${startedAt}</span>
        </div>
        <div class="meta-item">
          <span class="meta-label">Completed At</span>
          <span class="meta-value">${completedAt}</span>
        </div>
        <div class="meta-item">
          <span class="meta-label">Duration</span>
          <span class="meta-value">${duration}</span>
        </div>
      </div>
    </header>
  `;
}

export function buildExecutiveSummarySection(record: OrchestratedAssessmentRecord): string {
  const findings = record.findings || [];
  const critCount = findings.filter((f) => f.severity === 'critical').length;
  const highCount = findings.filter((f) => f.severity === 'high').length;
  const medCount = findings.filter((f) => f.severity === 'medium').length;
  const lowCount = findings.filter((f) => f.severity === 'low').length;
  const infoCount = findings.filter((f) => f.severity === 'info').length;

  return `
    <section class="card">
      <h2>Executive Summary</h2>
      <p style="color: var(--text-muted); font-size: 0.9rem;">
        This document reflects the verified findings resulting from authorized defensive scanning, composite active reconnaissance, and differential HTTP evidence inspection approved by a certified operator.
      </p>

      <div class="summary-grid">
        <div class="summary-card">
          <div class="summary-count" style="color: #ffffff;">${findings.length}</div>
          <div class="summary-label">Total Confirmed</div>
        </div>
        <div class="summary-card">
          <div class="summary-count" style="color: var(--severity-crit);">${critCount}</div>
          <div class="summary-label">Critical</div>
        </div>
        <div class="summary-card">
          <div class="summary-count" style="color: var(--severity-high);">${highCount}</div>
          <div class="summary-label">High</div>
        </div>
        <div class="summary-card">
          <div class="summary-count" style="color: var(--severity-med);">${medCount}</div>
          <div class="summary-label">Medium</div>
        </div>
        <div class="summary-card">
          <div class="summary-count" style="color: var(--severity-low);">${lowCount}</div>
          <div class="summary-label">Low</div>
        </div>
        <div class="summary-card">
          <div class="summary-count" style="color: var(--severity-info);">${infoCount}</div>
          <div class="summary-label">Info</div>
        </div>
      </div>
    </section>
  `;
}

export function buildAuditLimitationsSection(): string {
  return `
    <section class="card">
      <h2>Mandatory Audit Limitations & Scope Boundaries</h2>
      <ul class="limitations-list">
        <li><strong>Point-in-Time Assessment</strong>: This assessment reflects the security posture and configuration of the authorized target strictly at the time of execution. Dynamic cloud environments, DNS records, or subsequent code releases may introduce alterations.</li>
        <li><strong>Defensive Execution Discipline</strong>: Probing is strictly non-destructive and non-exploitative. Testing did not employ denial-of-service, destructive database modifications, or brute-force data harvesting.</li>
        <li><strong>Unassessed Threat Vectors</strong>: Out-of-scope assets, third-party vendor integrations, payment gateways, physical security, and social engineering vectors were explicitly excluded.</li>
        <li><strong>Abstention & Non-Claim Guarantee</strong>: Areas marked as abstained (secure) indicate that no indicators of vulnerability were observed under tested parameters, not formal mathematical proof of absolute absence of flaws.</li>
        <li><strong>Human Authorization Boundary</strong>: Only evidence items reviewed and authorized by an authenticated human operator are elevated to formal findings.</li>
      </ul>
    </section>
  `;
}

export function buildConfirmedFindingsSection(
  findings: readonly Finding[],
  lineage: AuthorizedActiveReconRequestLineage
): string {
  if (!findings || findings.length === 0) {
    return `
      <section class="card">
        <h2>Confirmed Findings (0)</h2>
        <div style="background: rgba(16, 185, 129, 0.05); border: 1px solid rgba(16, 185, 129, 0.2); border-radius: 8px; padding: 1.5rem; text-align: center; color: #a1a1aa; font-size: 0.9rem;">
          <strong style="color: #34d399; display: block; margin-bottom: 0.25rem;">Zero Confirmed Findings</strong>
          All inspected surfaces cleanly abstained or satisfied defensive security controls under tested parameters.
        </div>
      </section>
    `;
  }

  const findingsHtml = findings
    .map((f, idx) => {
      const badgeClass = `badge-${f.severity.toLowerCase()}`;
      const title = escapeHtml(f.title);
      const desc = escapeHtml(f.description);
      const target = escapeHtml(f.target);
      const type = escapeHtml(f.type);
      const evidence = escapeHtml(sanitizeEvidenceFragment(f.evidence));
      const meta = escapeHtml(sanitizeEvidenceFragment(JSON.stringify(f.metadata, null, 2)));

      return `
        <div class="finding-card">
          <div class="finding-header">
            <div>
              <span class="badge ${badgeClass}">${escapeHtml(f.severity)}</span>
              <span style="font-family: monospace; font-size: 0.75rem; color: var(--text-dim); margin-left: 0.5rem;">#${idx + 1} • ${escapeHtml(f.id)}</span>
              <h3 class="finding-title" style="margin-top: 0.35rem;">${title}</h3>
            </div>
            <span style="font-family: monospace; font-size: 0.75rem; color: #a1a1aa; background: #1c1c21; padding: 0.2rem 0.5rem; border-radius: 4px; border: 1px solid #2e2e36;">${type}</span>
          </div>

          <p class="finding-desc">${desc}</p>

          <div style="font-size: 0.8rem; font-family: monospace; color: var(--text-muted);">
            Target: <span style="color: #ffffff;">${target}</span>
          </div>

          <div>
            <div style="font-size: 0.75rem; font-family: monospace; text-transform: uppercase; color: var(--text-dim); margin-bottom: 0.25rem;">Proof of Evidence (Human Verified)</div>
            <div class="code-box">${evidence}</div>
          </div>

          <div>
            <div style="font-size: 0.75rem; font-family: monospace; text-transform: uppercase; color: var(--text-dim); margin-bottom: 0.25rem;">Typed Finding Metadata</div>
            <div class="code-box">${meta}</div>
          </div>

          <div style="font-size: 0.75rem; font-family: monospace; color: var(--text-dim); border-top: 1px solid #1f1f24; padding-top: 0.5rem; display: flex; gap: 1rem; flex-wrap: wrap;">
            <span>Scan: ${escapeHtml(lineage.scanId)}</span>
            <span>Grant: ${escapeHtml(lineage.authorizationGrantId)}</span>
            <span>Decision: ${escapeHtml(lineage.authorizationDecisionId)}</span>
          </div>
        </div>
      `;
    })
    .join('\n');

  return `
    <section class="card">
      <h2>Confirmed Findings (${findings.length})</h2>
      <div style="margin-top: 1rem;">
        ${findingsHtml}
      </div>
    </section>
  `;
}

export function buildRecommendationsSection(recommendations: readonly TargetRecommendation[]): string {
  if (!recommendations || recommendations.length === 0) {
    return '';
  }

  const itemsHtml = recommendations
    .map((r) => {
      const title = escapeHtml(r.title);
      const reasoning = escapeHtml(r.reasoning);
      const category = escapeHtml(r.category);
      const cap = escapeHtml(r.suggestedCapability);
      const perms = r.requiredPermissions.map((p) => escapeHtml(p)).join(', ');

      return `
        <div style="background: rgba(255, 255, 255, 0.02); border: 1px solid var(--card-border); border-radius: 8px; padding: 1rem; margin-bottom: 0.75rem;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.25rem;">
            <strong style="color: #ffffff; font-size: 0.9rem;">${title}</strong>
            <span style="font-size: 0.75rem; font-family: monospace; color: #60a5fa; background: rgba(59, 130, 246, 0.1); padding: 0.15rem 0.4rem; border-radius: 4px;">${category}</span>
          </div>
          <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 0.5rem;">${reasoning}</p>
          <div style="font-size: 0.75rem; font-family: monospace; color: var(--text-dim);">
            Suggested Action: <span style="color: #e4e4e7;">${cap}</span> • Permissions: <span style="color: #a1a1aa;">${perms || 'none'}</span>
          </div>
        </div>
      `;
    })
    .join('\n');

  return `
    <section class="card">
      <h2>Advisory Recommendations</h2>
      <p style="color: var(--text-muted); font-size: 0.85rem; margin-bottom: 1rem;">
        Synthesized next-step guidance generated by the defensive intelligence engine for human authorization.
      </p>
      ${itemsHtml}
    </section>
  `;
}

export function buildOperatorAttestationSection(attestation: {
  operatorId: string;
  verifiedAt: string;
  attestationText: string;
}): string {
  const operatorId = escapeHtml(attestation.operatorId);
  const verifiedAt = escapeHtml(attestation.verifiedAt);
  const text = escapeHtml(attestation.attestationText);

  return `
    <section class="card">
      <h2>Operator Attestation & Formal Sign-Off</h2>
      <div class="attestation-box">
        <p class="attestation-statement">"${text}"</p>
        <div class="attestation-meta">
          <div>Verified By: <strong style="color: #ffffff;">${operatorId}</strong></div>
          <div>Attested At: <strong style="color: #ffffff;">${verifiedAt}</strong></div>
          <div>Attestation Status: <strong style="color: #34d399;">SIGNED &amp; RATIFIED</strong></div>
        </div>
      </div>
    </section>
  `;
}

/**
 * Section 4 — Attack Execution Record
 * Timeline of authorized plans and chain-step execution outcomes (no secrets).
 */
export function buildAttackExecutionRecordSection(params: {
  readonly attackPlans?: readonly AttackPlan[];
  readonly attackChains?: readonly AttackChain[];
}): string {
  const plans = params.attackPlans ?? [];
  const chains = params.attackChains ?? [];

  const planItems =
    plans.length === 0
      ? `<p style="color: var(--text-muted); font-size: 0.85rem;">No authorized attack plans were recorded for this assessment.</p>`
      : plans
          .map((p) => {
            const completedSteps = p.steps.filter((s) => s.status === 'completed').length;
            return `
          <div class="adversarial-item">
            <div style="display:flex;justify-content:space-between;gap:1rem;flex-wrap:wrap;">
              <strong style="color:#ffffff;">${escapeHtml(p.title)}</strong>
              <span style="font-family:monospace;font-size:0.75rem;color:#a1a1aa;">${escapeHtml(p.status)}</span>
            </div>
            <div style="font-size:0.8rem;font-family:monospace;color:var(--text-muted);margin-top:0.35rem;">
              Plan: ${escapeHtml(p.planId)} • Capability: ${escapeHtml(p.capability)} • Steps completed: ${completedSteps}/${p.steps.length}
            </div>
            <p style="font-size:0.85rem;color:var(--text-muted);margin-top:0.5rem;">${escapeHtml(p.reasoning)}</p>
          </div>`;
          })
          .join('\n');

  const stepRows: string[] = [];
  for (const chain of chains) {
    for (const step of chain.steps) {
      stepRows.push(`
        <div class="adversarial-item">
          <div style="display:flex;justify-content:space-between;gap:1rem;flex-wrap:wrap;align-items:center;">
            <strong style="color:#ffffff;">Chain ${escapeHtml(chain.chainId)} · Step ${step.sequence}</strong>
            ${renderEpistemicBadgeHtml(step.epistemicStatus)}
          </div>
          <div style="font-size:0.8rem;font-family:monospace;color:var(--text-muted);margin-top:0.35rem;">
            Capability: ${escapeHtml(step.capabilityKind)} • Outcome: ${escapeHtml(step.outcome)} • Recorded: ${escapeHtml(step.evidence.recordedAt)}
          </div>
          <p style="font-size:0.85rem;color:var(--text-muted);margin-top:0.4rem;">${escapeHtml(step.evidence.safeMessage)}</p>
        </div>`);
    }
  }

  const executionHtml =
    stepRows.length === 0
      ? `<p style="color: var(--text-muted); font-size: 0.85rem;">No executed attack-chain steps were recorded.</p>`
      : stepRows.join('\n');

  return `
    <section class="card" id="section-attack-execution-record">
      <h2>Attack Execution Record</h2>
      <p style="color: var(--text-muted); font-size: 0.85rem; margin-bottom: 1rem;">
        Authorized plans and recorded validation-step outcomes. Duration is derived from recorded step timestamps when available.
      </p>
      <h3 style="margin-top:0.5rem;">Authorized Plans</h3>
      ${planItems}
      <h3 style="margin-top:1rem;">Execution Outcomes</h3>
      ${executionHtml}
    </section>
  `;
}

/**
 * Section 5 — Attack Chains & Impact (epistemic badges mandatory)
 */
export function buildAttackChainsAndImpactSection(params: {
  readonly attackChains?: readonly AttackChain[];
  readonly impactAssessments?: readonly ImpactAssessment[];
}): string {
  const chains = params.attackChains ?? [];
  const impacts = params.impactAssessments ?? [];
  const impactByChain = new Map(impacts.map((i) => [i.chainId, i]));

  if (chains.length === 0) {
    return `
      <section class="card" id="section-attack-chains-impact">
        <h2>Attack Chains &amp; Impact</h2>
        <p style="color: var(--text-muted); font-size: 0.85rem;">No attack chains were recorded for this assessment.</p>
      </section>
    `;
  }

  const items = chains
    .map((chain) => {
      const impact = impactByChain.get(chain.chainId);
      const impactBlock = impact
        ? `
          <div style="margin-top:0.75rem;padding-top:0.75rem;border-top:1px solid var(--card-border);">
            <div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap;margin-bottom:0.35rem;">
              <span style="font-size:0.75rem;font-family:monospace;color:var(--text-dim);text-transform:uppercase;">Impact Assessment</span>
              ${renderEpistemicBadgeHtml(impact.epistemicStatus)}
              <span style="font-family:monospace;font-size:0.75rem;color:#a1a1aa;">${escapeHtml(impact.impactLevel)}</span>
            </div>
            <p style="font-size:0.85rem;color:var(--text-muted);">${escapeHtml(impact.impactDescription)}</p>
            <div style="font-size:0.75rem;font-family:monospace;color:var(--text-dim);margin-top:0.35rem;">
              Evidence basis: ${
                impact.evidenceBasis.length === 0
                  ? 'none'
                  : impact.evidenceBasis.map((id) => escapeHtml(id)).join(', ')
              }
            </div>
          </div>`
        : `<p style="font-size:0.8rem;color:var(--text-dim);margin-top:0.5rem;">No terminal impact assessment derived (chain not completed).</p>`;

      const stepsHtml = chain.steps
        .map(
          (s) => `
          <li style="margin-bottom:0.35rem;">
            ${renderEpistemicBadgeHtml(s.epistemicStatus)}
            <span style="font-family:monospace;font-size:0.8rem;color:#e4e4e7;">#${s.sequence} ${escapeHtml(s.capabilityKind)}</span>
            <span style="font-size:0.8rem;color:var(--text-muted);"> — ${escapeHtml(s.outcome)}: ${escapeHtml(s.evidence.safeMessage)}</span>
          </li>`
        )
        .join('\n');

      return `
        <div class="adversarial-item">
          <div style="display:flex;justify-content:space-between;gap:1rem;flex-wrap:wrap;align-items:center;">
            <strong style="color:#ffffff;">${escapeHtml(chain.hypothesis)}</strong>
            ${renderEpistemicBadgeHtml(chain.overallEpistemicStatus)}
          </div>
          <div style="font-size:0.8rem;font-family:monospace;color:var(--text-muted);margin-top:0.35rem;">
            Chain: ${escapeHtml(chain.chainId)} • Status: ${escapeHtml(chain.status)} • Objective: ${escapeHtml(chain.objectiveKind)} • ImpactLevel: ${escapeHtml(chain.impactLevel)}
          </div>
          <ul style="list-style:none;margin-top:0.75rem;padding:0;">${stepsHtml || '<li style="color:var(--text-dim);font-size:0.85rem;">No steps recorded.</li>'}</ul>
          ${impactBlock}
        </div>`;
    })
    .join('\n');

  return `
    <section class="card" id="section-attack-chains-impact">
      <h2>Attack Chains &amp; Impact</h2>
      <p style="color: var(--text-muted); font-size: 0.85rem; margin-bottom: 1rem;">
        Chain progression with mandatory epistemic badges. Impact assessments never exceed chain overall epistemic status.
      </p>
      ${items}
    </section>
  `;
}

/**
 * Section 6 — Acquired Access & Credentials (CredentialReference fields only)
 */
export function buildAcquiredAccessAndCredentialsSection(params: {
  readonly postExploitationState?: PostExploitationState | null;
  readonly credentialReferences?: readonly CredentialReference[];
}): string {
  const state = params.postExploitationState ?? null;
  const refs = params.credentialReferences ?? [];

  const accessHtml =
    !state || state.acquiredAccess.length === 0
      ? `<p style="color: var(--text-muted); font-size: 0.85rem;">No acquired access records.</p>`
      : state.acquiredAccess
          .map((a) => {
            return `
          <div class="adversarial-item">
            <div style="display:flex;justify-content:space-between;gap:1rem;flex-wrap:wrap;align-items:center;">
              <strong style="color:#ffffff;">${escapeHtml(a.accessKind)}</strong>
              ${renderEpistemicBadgeHtml(a.epistemicStatus)}
            </div>
            <p style="font-size:0.85rem;color:var(--text-muted);margin-top:0.35rem;">${escapeHtml(a.description)}</p>
            <div style="font-size:0.75rem;font-family:monospace;color:var(--text-dim);margin-top:0.35rem;">
              Access: ${escapeHtml(a.accessId)} • Chain: ${escapeHtml(a.sourceChainId)} • Step: ${escapeHtml(a.sourceStepId)}
              ${a.credentialRefId ? ` • CredentialRef: ${escapeHtml(a.credentialRefId)}` : ''}
              ${a.identityContext ? ` • Identity: ${escapeHtml(a.identityContext)}` : ''}
            </div>
          </div>`;
          })
          .join('\n');

  const credHtml =
    refs.length === 0
      ? `<p style="color: var(--text-muted); font-size: 0.85rem;">No credential references recorded.</p>`
      : refs
          .map((r) => {
            // Render ONLY CredentialReference fields — never vault secrets.
            return `
          <div class="adversarial-item">
            <strong style="color:#ffffff;font-family:monospace;">${escapeHtml(r.credentialId)}</strong>
            <div style="font-size:0.8rem;font-family:monospace;color:var(--text-muted);margin-top:0.35rem;">
              Kind: ${escapeHtml(r.credentialKind)} • Source: ${escapeHtml(r.source)}
              ${r.associatedHostname ? ` • Host: ${escapeHtml(r.associatedHostname)}` : ''}
              • Discovered: ${escapeHtml(r.discoveredAt)}
              ${r.expiresAt ? ` • Expires: ${escapeHtml(r.expiresAt)}` : ''}
            </div>
          </div>`;
          })
          .join('\n');

  const lateralHtml =
    !state || state.lateralMovementHypotheses.length === 0
      ? ''
      : `
      <h3 style="margin-top:1rem;">Lateral Movement Hypotheses</h3>
      ${state.lateralMovementHypotheses
        .map(
          (h) => `
        <div class="adversarial-item">
          <div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap;">
            <strong style="color:#ffffff;">${escapeHtml(h.targetHost)}</strong>
            ${renderEpistemicBadgeHtml(h.epistemicStatus)}
          </div>
          <div style="font-size:0.8rem;font-family:monospace;color:var(--text-muted);margin-top:0.35rem;">
            Mechanism: ${escapeHtml(h.mechanism)} • Hypothesis: ${escapeHtml(h.hypothesisId)}
            ${h.credentialRefId ? ` • CredentialRef: ${escapeHtml(h.credentialRefId)}` : ''}
          </div>
        </div>`
        )
        .join('\n')}`;

  return `
    <section class="card" id="section-acquired-access-credentials">
      <h2>Acquired Access &amp; Credentials</h2>
      <p style="color: var(--text-muted); font-size: 0.85rem; margin-bottom: 1rem;">
        Privilege indicators and discovered credential references only. Raw vault secrets are never rendered.
      </p>
      <h3>Acquired Access</h3>
      ${accessHtml}
      <h3 style="margin-top:1rem;">Credential References</h3>
      ${credHtml}
      ${lateralHtml}
    </section>
  `;
}

/**
 * Section 7 — Target Defenses (What Failed & Resisted)
 */
export function buildTargetDefensesSection(params: {
  readonly attackChains?: readonly AttackChain[];
}): string {
  const chains = params.attackChains ?? [];
  const resisted: Array<{
    chainId: string;
    stepId: string;
    capabilityKind: string;
    safeMessage: string;
    epistemicStatus: 'OBSERVED' | 'INFERRED' | 'VERIFIED' | 'REFUTED';
    outcome: string;
  }> = [];

  for (const chain of chains) {
    for (const step of chain.steps) {
      if (step.outcome === 'refuted' || step.outcome === 'failed' || step.epistemicStatus === 'REFUTED') {
        resisted.push({
          chainId: chain.chainId,
          stepId: step.stepId,
          capabilityKind: step.capabilityKind,
          safeMessage: step.evidence.safeMessage,
          epistemicStatus: step.epistemicStatus,
          outcome: step.outcome,
        });
      }
    }
    if (chain.status === 'refuted' && resisted.every((r) => r.chainId !== chain.chainId)) {
      resisted.push({
        chainId: chain.chainId,
        stepId: 'chain',
        capabilityKind: chain.objectiveKind,
        safeMessage: `Chain ${chain.chainId} marked refuted — target resisted the hypothesized path.`,
        epistemicStatus: chain.overallEpistemicStatus,
        outcome: 'refuted',
      });
    }
  }

  const items =
    resisted.length === 0
      ? `<p style="color: var(--text-muted); font-size: 0.85rem;">No refuted or failed validation steps were recorded. Absence of resistance records is not proof of weakness.</p>`
      : resisted
          .map(
            (r) => `
        <div class="adversarial-item">
          <div style="display:flex;justify-content:space-between;gap:1rem;flex-wrap:wrap;align-items:center;">
            <strong style="color:#ffffff;">${escapeHtml(r.capabilityKind)}</strong>
            ${renderEpistemicBadgeHtml(r.epistemicStatus === 'REFUTED' ? 'REFUTED' : r.epistemicStatus)}
          </div>
          <div style="font-size:0.8rem;font-family:monospace;color:var(--text-muted);margin-top:0.35rem;">
            Chain: ${escapeHtml(r.chainId)} • Step: ${escapeHtml(r.stepId)} • Outcome: ${escapeHtml(r.outcome)}
          </div>
          <p style="font-size:0.85rem;color:var(--text-muted);margin-top:0.4rem;">${escapeHtml(r.safeMessage)}</p>
        </div>`
          )
          .join('\n');

  return `
    <section class="card" id="section-target-defenses">
      <h2>Target Defenses (What Failed &amp; Resisted)</h2>
      <p style="color: var(--text-muted); font-size: 0.85rem; margin-bottom: 1rem;">
        Documented where the target blocked or refuted an authorized validation attempt — defensive signal, not speculative severity.
      </p>
      ${items}
    </section>
  `;
}

/**
 * Section 8 — Assessment Limitations (What Was Not Attempted)
 */
export function buildAssessmentLimitationsAdversarialSection(): string {
  return `
    <section class="card" id="section-assessment-limitations-adversarial">
      <h2>Assessment Limitations (What Was Not Attempted)</h2>
      <ul class="limitations-list">
        <li><strong>No Destructive Operations</strong>: Denial-of-service, destructive writes, and data destruction were prohibited and not attempted.</li>
        <li><strong>No Brute-Force Credential Harvesting</strong>: Password spraying, credential stuffing, and bulk account enumeration were out of scope.</li>
        <li><strong>No Autonomous Exploitation</strong>: Attack plans require human authorization; the engine does not self-authorize or auto-escalate blast radius.</li>
        <li><strong>No Out-of-Scope Assets</strong>: Third-party hosts, payment gateways, and assets outside the authorized scope grant were not targeted.</li>
        <li><strong>No Speculative Impact Inflation</strong>: Impact assessments never exceed the epistemic status of their source attack chain. INFERRED chains cannot produce VERIFIED impact.</li>
        <li><strong>Credential Vault Isolation</strong>: Raw secrets remain in the process-local vault and are never serialized into this report — only CredentialReference metadata appears.</li>
        <li><strong>Point-in-Time Boundary</strong>: Findings and chain outcomes reflect the target state during the authorized assessment window only.</li>
      </ul>
    </section>
  `;
}
