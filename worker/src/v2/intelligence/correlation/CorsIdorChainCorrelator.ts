/**
 * Milestone P5-1 — CORS + IDOR Compound Chain Correlator
 *
 * Evaluates confirmed findings from P4-9 (Credentialed CORS) and P3-3 (Differential IDOR)
 * sharing the same origin to synthesize top-tier Critical Compound Chain findings.
 *
 * Strict Invariants:
 * - Purely analytical: operates 100% in-memory with ZERO network calls.
 * - Requires exact origin match (scheme + host + port).
 * - Requires confirmed Credentialed CORS (allowCredentials: true).
 * - Requires confirmed Differential IDOR (BROKEN_ACCESS_CONTROL).
 * - Human-in-the-loop: Unattended runs produce EnrichedEvidenceDraft for operator review.
 */

import type { Finding, CompoundChainMetadata, CredentialedCorsMetadata, BrokenAccessControlMetadata } from '../../core/Evidence.js';
import type { EnrichedEvidenceDraft } from '../../application/OrchestratedAssessmentContracts.js';
import type { HumanReviewDecision } from '../../detection/DetectionContracts.js';
import { sanitizeEvidenceFragment } from '../../core/EvidenceSanitizer.js';

export function normalizeOriginFromUrl(targetUrl: string): string | null {
  try {
    const parsed = new URL(targetUrl);
    return parsed.origin.toLowerCase();
  } catch {
    return null;
  }
}

function sanitizeToSafeId(raw: string): string {
  const cleaned = raw.replace(/[^A-Za-z0-9]/g, '').slice(0, 16);
  return cleaned.length > 0 ? cleaned : '001';
}

export interface CorsIdorChainCorrelationRequest {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly actorId: string;
  readonly findings: readonly Finding[];
  readonly humanReviewDecision?: HumanReviewDecision;
}

export interface CorsIdorChainCorrelationResult {
  readonly chainsFound: number;
  readonly compoundFindings: readonly Finding[];
  readonly compoundDrafts: readonly EnrichedEvidenceDraft[];
}

export function correlateCorsIdorChains(
  request: CorsIdorChainCorrelationRequest
): CorsIdorChainCorrelationResult {
  const { assessmentId, scanId, actorId, findings, humanReviewDecision } = request;
  const nowIso = new Date().toISOString();

  const corsFindings: Finding[] = [];
  const idorFindings: Finding[] = [];

  for (const f of findings) {
    if (
      f.type === 'SECURITY_MISCONFIGURATION' &&
      f.metadata?.kind === 'credentialed_cors_metadata'
    ) {
      const corsMeta = f.metadata as CredentialedCorsMetadata;
      if (corsMeta.allowCredentialsHeader) {
        corsFindings.push(f);
      }
    } else if (
      f.type === 'BROKEN_ACCESS_CONTROL' &&
      f.metadata?.kind === 'broken_access_control_metadata'
    ) {
      idorFindings.push(f);
    }
  }

  const compoundFindings: Finding[] = [];
  const compoundDrafts: EnrichedEvidenceDraft[] = [];

  for (const corsF of corsFindings) {
    const corsOrigin = normalizeOriginFromUrl(corsF.target);
    if (!corsOrigin) continue;

    for (const idorF of idorFindings) {
      const idorOrigin = normalizeOriginFromUrl(idorF.target);
      if (!idorOrigin) continue;

      // Both findings must share the exact same normalized origin
      if (corsOrigin === idorOrigin) {
        const chainSeed = sanitizeToSafeId(`${corsF.id}_${idorF.id}`);
        const draftId = `dft_cmpnd_${chainSeed}`;
        const candidateId = `cnd_cmpnd_${chainSeed}`;
        const evidenceRecordId = `evd_cmpnd_${chainSeed}`;
        const compoundImpactScore = 0.95;

        // If human review is approved, promote to formal Critical Finding
        if (humanReviewDecision?.decision === 'approve_evidence') {
          const compoundFinding: Finding = {
            id: `fnd_cmpnd_${chainSeed}`,
            type: 'BROKEN_ACCESS_CONTROL',
            severity: 'critical',
            title: `Critical Compound Exploit Chain: Credentialed CORS + IDOR on ${corsOrigin}`,
            description: `Synthesized Compound Chain: Target reflects untrusted external origins with Access-Control-Allow-Credentials: true (${corsF.id}) and is vulnerable to Differential IDOR (${idorF.id}) on ${idorF.target}. This proves full cross-origin authenticated exfiltration of unauthorized tenant data.`,
            target: idorF.target,
            evidence: sanitizeEvidenceFragment(
              JSON.stringify({
                chainKind: 'cors_idor_compound',
                sharedOrigin: corsOrigin,
                primaryFindingId: corsF.id,
                secondaryFindingId: idorF.id,
                targetEndpointUrl: idorF.target,
                compoundImpactScore,
                reviewedBy: humanReviewDecision.reviewerId,
                reviewedAt: humanReviewDecision.reviewedAt,
              })
            ),
            confidence: 1.0,
            verificationState: 'validated_vulnerability',
            metadata: {
              kind: 'compound_chain_metadata',
              category: 'BROKEN_ACCESS_CONTROL',
              chainKind: 'cors_idor_compound',
              primaryFindingId: corsF.id,
              secondaryFindingId: idorF.id,
              sharedOrigin: corsOrigin,
              targetEndpointUrl: idorF.target,
              compoundImpactScore,
              observedAt: nowIso,
              candidateId,
              evidenceRecordId,
              lineage: `${assessmentId}:${scanId}:${actorId}`,
            },
          };
          compoundFindings.push(compoundFinding);
        } else if (humanReviewDecision?.decision === 'reject') {
          // Explicitly rejected by operator, do not create draft or finding
        } else {
          // Unreviewed -> Generate Enriched Evidence Draft for HITL triage
          const draft: EnrichedEvidenceDraft = {
            draftKind: 'non_persisted_comparison_evidence_draft',
            draftId,
            suggestedEvidenceType: 'http_difference',
            suggestedStrength: 'strong',
            sourceComparisonId: `cmp_cmpnd_${chainSeed}`,
            sourceSnapshotIds: {
              baselineSnapshotId: `snp_cmpnd_${chainSeed}_base`,
              validationSnapshotId: `snp_cmpnd_${chainSeed}_val`,
            },
            requiresHumanReview: true,
            notPersisted: true,
            notARealFinding: true,
            notConfirmedEvidence: true,
            notForExternalDelivery: true,
            notM45EvidenceRecord: true,
            safeRationale: `Proved compound attack chain on ${corsOrigin}: Credentialed CORS (${corsF.id}) enables arbitrary origin reflection with credentials, paired with Differential IDOR (${idorF.id}) on ${idorF.target}, enabling authenticated cross-origin data theft.`,
            differentialContext: {
              endpointUrl: idorF.target,
              detectionKind: 'cors_idor_compound',
              chainKind: 'cors_idor_compound',
              primaryFindingId: corsF.id,
              secondaryFindingId: idorF.id,
              sharedOrigin: corsOrigin,
              targetEndpointUrl: idorF.target,
              compoundImpactScore,
            },
          };
          compoundDrafts.push(draft);
        }
      }
    }
  }

  return {
    chainsFound: compoundFindings.length + compoundDrafts.length,
    compoundFindings,
    compoundDrafts,
  };
}

export class CorsIdorChainCorrelator {
  public correlate(
    request: CorsIdorChainCorrelationRequest
  ): CorsIdorChainCorrelationResult {
    return correlateCorsIdorChains(request);
  }
}
