/**
 * Milestone A12 — Impact Assessment Service
 *
 * Derives formal ImpactAssessment records from completed AttackChain evidence
 * and optional PostExploitationState. Never invents steps, never inflates
 * epistemic status above the chain overall, and never embeds vault secrets.
 */

import type { AttackChain } from '../attack-chain/AttackChainContracts.js';
import type { PostExploitationState } from '../post-exploitation/PostExploitationContracts.js';
import {
  IMPACT_ASSESSMENT_CONTRACT_VERSION,
  type ImpactAssessment,
  isHighImpactLevel,
  permitsVerifiedHighImpact,
} from './ImpactAssessmentContracts.js';

export interface DeriveImpactAssessmentsInput {
  readonly chains: readonly AttackChain[];
  readonly postExploitationState?: PostExploitationState | null;
  readonly assessedAt?: string;
}

/**
 * A chain is "completed" for impact assessment when it reached a terminal
 * status (fully_validated / refuted / abandoned) or has completedAt set.
 * Incomplete hypotheses without terminal evidence produce no assessment.
 */
export function isCompletedAttackChain(chain: AttackChain): boolean {
  if (typeof chain.completedAt === 'string' && chain.completedAt.length > 0) {
    return true;
  }
  return (
    chain.status === 'fully_validated' ||
    chain.status === 'refuted' ||
    chain.status === 'abandoned'
  );
}

function collectEvidenceIds(chain: AttackChain): readonly string[] {
  const ids: string[] = [];
  for (const step of chain.steps) {
    if (typeof step.evidence.evidenceId === 'string' && step.evidence.evidenceId.length > 0) {
      ids.push(step.evidence.evidenceId);
    }
  }
  return Object.freeze([...ids]);
}

function relatedAccessSummaries(
  chain: AttackChain,
  state: PostExploitationState | null | undefined
): readonly string[] {
  if (!state) return [];
  const lines: string[] = [];
  for (const access of state.acquiredAccess) {
    if (access.sourceChainId !== chain.chainId) continue;
    // Metadata only — never secrets.
    const cred =
      typeof access.credentialRefId === 'string'
        ? `; credentialRefId=${access.credentialRefId}`
        : '';
    lines.push(
      `Acquired access ${access.accessId} (${access.accessKind}, epistemic=${access.epistemicStatus}${cred})`
    );
  }
  return lines;
}

function buildFactualDescription(
  chain: AttackChain,
  postExploitationState: PostExploitationState | null | undefined
): string {
  const stepCount = chain.steps.length;
  const succeeded = chain.steps.filter((s) => s.outcome === 'succeeded').length;
  const refutedOrFailed = chain.steps.filter(
    (s) => s.outcome === 'refuted' || s.outcome === 'failed'
  ).length;

  const parts: string[] = [
    `Chain ${chain.chainId} objective=${chain.objectiveKind} status=${chain.status} impactLevel=${chain.impactLevel}.`,
    `Recorded ${stepCount} step(s): ${succeeded} succeeded, ${refutedOrFailed} refuted/failed.`,
    `Overall epistemic status from chain evidence: ${chain.overallEpistemicStatus}.`,
  ];

  if (chain.status === 'refuted') {
    parts.push(
      'Target resisted or refuted one or more authorized validation steps; impact is not confirmed.'
    );
  } else if (chain.status === 'abandoned') {
    parts.push('Chain was abandoned; no confirmed impact claim is made.');
  } else if (
    chain.status === 'fully_validated' &&
    chain.overallEpistemicStatus === 'VERIFIED' &&
    permitsVerifiedHighImpact(chain.overallEpistemicStatus)
  ) {
    parts.push(
      `Validated chain evidence supports the recorded impact class "${chain.impactLevel}" under human-authorized assessment.`
    );
  } else if (chain.overallEpistemicStatus === 'INFERRED') {
    parts.push(
      'Impact remains inferred from incomplete or mixed epistemic evidence; not verified.'
    );
  } else if (chain.overallEpistemicStatus === 'OBSERVED') {
    parts.push(
      'Impact indicators were observed in responses; verification to confirmed impact was not established at VERIFIED.'
    );
  } else {
    parts.push(
      `Impact description limited to chain status=${chain.status} and epistemic=${chain.overallEpistemicStatus}.`
    );
  }

  // High-impact honesty gate: never phrase as impact_confirmed unless VERIFIED.
  if (isHighImpactLevel(chain.impactLevel) && !permitsVerifiedHighImpact(chain.overallEpistemicStatus)) {
    parts.push(
      `High-impact class "${chain.impactLevel}" cannot be claimed as impact_confirmed while chain epistemic is ${chain.overallEpistemicStatus}.`
    );
  }

  const accessLines = relatedAccessSummaries(chain, postExploitationState);
  if (accessLines.length > 0) {
    parts.push(`Related post-exploitation records: ${accessLines.join('; ')}.`);
  }

  return parts.join(' ');
}

export class ImpactAssessmentService {
  /**
   * Derive ImpactAssessment[] from completed chains without epistemic inflation.
   */
  public deriveImpactAssessments(input: DeriveImpactAssessmentsInput): readonly ImpactAssessment[] {
    const assessedAt = input.assessedAt ?? new Date().toISOString();
    const results: ImpactAssessment[] = [];

    for (const chain of input.chains) {
      if (!isCompletedAttackChain(chain)) {
        continue;
      }

      // Epistemic status MUST equal (never exceed) chain overall.
      const epistemicStatus = chain.overallEpistemicStatus;

      const assessment: ImpactAssessment = Object.freeze({
        contractVersion: IMPACT_ASSESSMENT_CONTRACT_VERSION,
        kind: 'impact_assessment',
        assessmentId: chain.assessmentId,
        chainId: chain.chainId,
        impactLevel: chain.impactLevel,
        impactDescription: buildFactualDescription(chain, input.postExploitationState),
        evidenceBasis: collectEvidenceIds(chain),
        epistemicStatus,
        assessedAt,
      });

      results.push(assessment);
    }

    return Object.freeze(results);
  }
}
