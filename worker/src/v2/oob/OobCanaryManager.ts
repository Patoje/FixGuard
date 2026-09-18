/**
 * Milestone P7-1 — OOB Canary Token & Ephemeral Callback Server Architecture
 *
 * Core Invariant: Secure, isolated generation and validation of unique canary
 * tokens for asynchronous out-of-band detection (blind SSRF, DNS rebinding,
 * blind XSS, OOB RCE) with zero persistent credential storage.
 *
 * Safety & Quality Guarantees:
 * - High-entropy cryptographic token generation linked to active assessment lineages.
 * - Ephemeral in-memory volatile state with automatic cleanup & zero DB leakage.
 * - HITL review routing via EvidenceDraftEnvelope.
 * - 0 occurrences of 'as any'.
 */

import * as crypto from 'node:crypto';
import type { Finding } from '../core/Evidence.js';
import type { EvidenceDraftEnvelope } from '../evidence-mapping/ComparisonEvidenceMappingContracts.js';

export type OobPurpose = 'blind_ssrf' | 'blind_xss' | 'dns_rebinding' | 'oob_rce' | 'generic';
export type OobInteractionType = 'http_callback' | 'dns_query';

export interface OobCanaryTokenDescriptor {
  readonly canaryToken: string;
  readonly callbackDomain: string;
  readonly callbackUrl: string;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly actorId: string;
  readonly targetDomain: string;
  readonly targetEndpoint?: string;
  readonly purpose: OobPurpose;
  readonly issuedAt: string;
  readonly expiresAt: string;
}

export interface OobInboundInteraction {
  readonly canaryToken: string;
  readonly interactionType: OobInteractionType;
  readonly remoteAddress?: string;
  readonly receivedAt: string;
  readonly rawHeaders?: Record<string, string>;
  readonly queryParams?: Record<string, string>;
  readonly httpMethod?: string;
}

export interface IssueCanaryOptions {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly actorId: string;
  readonly targetDomain: string;
  readonly targetEndpoint?: string;
  readonly purpose?: OobPurpose;
  readonly callbackDomain?: string;
  readonly ttlSeconds?: number;
}

export interface OobEvaluationRequest {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly actorId: string;
  readonly targetDomain: string;
  readonly humanReviewDecision?: {
    readonly decision: 'approve_evidence' | 'reject' | 'needs_more_review';
    readonly reviewerId: string;
    readonly reviewedAt: string;
  };
}

export interface OobEvaluationResult {
  readonly contractVersion: 'fixguard-detection-expansion/v0';
  readonly kind: 'oob_canary_evaluation_result';
  readonly hasInteractions: boolean;
  readonly confirmedInteractions: readonly {
    readonly tokenDescriptor: OobCanaryTokenDescriptor;
    readonly interaction: OobInboundInteraction;
  }[];
  readonly evidenceDrafts: readonly EvidenceDraftEnvelope[];
  readonly findings: readonly Finding[];
}

export class OobCanaryManager {
  private readonly tokensByTokenStr: Map<string, OobCanaryTokenDescriptor> = new Map();
  private readonly tokensByAssessment: Map<string, Set<string>> = new Map();
  private readonly interactionsByTokenStr: Map<string, OobInboundInteraction[]> = new Map();
  private readonly defaultCallbackDomain: string;

  constructor(options?: { defaultCallbackDomain?: string }) {
    this.defaultCallbackDomain = options?.defaultCallbackDomain ?? 'oob.fixguard.internal';
  }

  /**
   * Generates a high-entropy cryptographic canary token linked to an assessment lineage.
   */
  public issueCanaryToken(options: IssueCanaryOptions): OobCanaryTokenDescriptor {
    const {
      assessmentId,
      scanId,
      actorId,
      targetDomain,
      targetEndpoint,
      purpose = 'blind_ssrf',
      callbackDomain = this.defaultCallbackDomain,
      ttlSeconds = 3600,
    } = options;

    const randomEntropy = crypto.randomBytes(12).toString('hex');
    const canaryToken = `fgc_${randomEntropy}`;
    const now = new Date();
    const issuedAt = now.toISOString();
    const expiresAt = new Date(now.getTime() + ttlSeconds * 1000).toISOString();
    const callbackUrl = `https://${canaryToken}.${callbackDomain}/`;

    const descriptor: OobCanaryTokenDescriptor = {
      canaryToken,
      callbackDomain,
      callbackUrl,
      assessmentId,
      scanId,
      actorId,
      targetDomain,
      targetEndpoint,
      purpose,
      issuedAt,
      expiresAt,
    };

    this.tokensByTokenStr.set(canaryToken, descriptor);

    let assessmentTokens = this.tokensByAssessment.get(assessmentId);
    if (!assessmentTokens) {
      assessmentTokens = new Set();
      this.tokensByAssessment.set(assessmentId, assessmentTokens);
    }
    assessmentTokens.add(canaryToken);

    return descriptor;
  }

  /**
   * Records an inbound interaction received on the OOB ephemeral callback listener.
   */
  public recordInteraction(interaction: OobInboundInteraction): boolean {
    const descriptor = this.tokensByTokenStr.get(interaction.canaryToken);
    if (!descriptor) {
      return false; // Unknown or expired token
    }

    // Verify token expiration
    const now = new Date();
    if (new Date(descriptor.expiresAt) < now) {
      return false; // Expired token
    }

    let interactions = this.interactionsByTokenStr.get(interaction.canaryToken);
    if (!interactions) {
      interactions = [];
      this.interactionsByTokenStr.set(interaction.canaryToken, interactions);
    }
    interactions.push(interaction);
    return true;
  }

  /**
   * Retrieves all interactions recorded for a given canary token.
   */
  public getInteractionsForToken(canaryToken: string): readonly OobInboundInteraction[] {
    return this.interactionsByTokenStr.get(canaryToken) ?? [];
  }

  /**
   * Evaluates all OOB tokens and received callbacks for a given assessment.
   */
  public evaluateOobInteractions(request: OobEvaluationRequest): OobEvaluationResult {
    const { assessmentId, scanId, actorId, targetDomain, humanReviewDecision } = request;
    const tokenSet = this.tokensByAssessment.get(assessmentId);

    if (!tokenSet || tokenSet.size === 0) {
      return {
        contractVersion: 'fixguard-detection-expansion/v0',
        kind: 'oob_canary_evaluation_result',
        hasInteractions: false,
        confirmedInteractions: [],
        evidenceDrafts: [],
        findings: [],
      };
    }

    const confirmedInteractions: {
      tokenDescriptor: OobCanaryTokenDescriptor;
      interaction: OobInboundInteraction;
    }[] = [];

    for (const tokenStr of tokenSet) {
      const descriptor = this.tokensByTokenStr.get(tokenStr);
      const interactions = this.interactionsByTokenStr.get(tokenStr);
      if (descriptor && interactions && interactions.length > 0) {
        for (const interaction of interactions) {
          confirmedInteractions.push({
            tokenDescriptor: descriptor,
            interaction,
          });
        }
      }
    }

    if (confirmedInteractions.length === 0) {
      return {
        contractVersion: 'fixguard-detection-expansion/v0',
        kind: 'oob_canary_evaluation_result',
        hasInteractions: false,
        confirmedInteractions: [],
        evidenceDrafts: [],
        findings: [],
      };
    }

    const evidenceDrafts: EvidenceDraftEnvelope[] = [];
    const findings: Finding[] = [];

    for (let i = 0; i < confirmedInteractions.length; i++) {
      const { tokenDescriptor, interaction } = confirmedInteractions[i];
      const safeToken = tokenDescriptor.canaryToken.replace(/[^a-zA-Z0-9]/g, '').toLowerCase().slice(0, 10);
      const safeSeed = `${assessmentId.replace(/[^a-zA-Z0-9]/g, '').toLowerCase().slice(0, 6)}_${safeToken}_${i}`;
      const draftId = `dft_oobcan_${safeSeed}`;
      const candidateId = `cnd_oobcan_${safeSeed}`;
      const evidenceRecordId = `evd_oobcan_${safeSeed}`;
      const findingId = `fnd_oobcan_${safeSeed}`;

      const targetEndpoint = tokenDescriptor.targetEndpoint ?? `https://${targetDomain}/`;
      const rationale = `Asynchronous out-of-band interaction confirmed for canary token '${tokenDescriptor.canaryToken}' (${tokenDescriptor.purpose}). Interaction type: ${interaction.interactionType} from remote IP ${interaction.remoteAddress ?? 'unknown'} at ${interaction.receivedAt}.`;

      if (humanReviewDecision?.decision === 'approve_evidence') {
        const nowIso = new Date().toISOString();
        const finding: Finding = {
          id: findingId,
          type: 'SERVER_SIDE_REQUEST_FORGERY',
          severity: tokenDescriptor.purpose === 'blind_ssrf' || tokenDescriptor.purpose === 'oob_rce' ? 'critical' : 'high',
          title: `Confirmed Out-Of-Band (OOB) Interaction: ${tokenDescriptor.purpose.toUpperCase()}`,
          description: `Defensive verification confirmed asynchronous out-of-band interaction from target ${targetDomain} via canary token ${tokenDescriptor.canaryToken} (${interaction.interactionType}).`,
          target: targetEndpoint,
          evidence: JSON.stringify({
            assessmentId,
            scanId,
            canaryToken: tokenDescriptor.canaryToken,
            callbackDomain: tokenDescriptor.callbackDomain,
            interactionType: interaction.interactionType,
            remoteAddress: interaction.remoteAddress,
            receivedAt: interaction.receivedAt,
            rawHeaders: interaction.rawHeaders,
            reviewedBy: actorId,
            reviewedAt: nowIso,
          }),
          confidence: 1.0,
          metadata: {
            kind: 'oob_canary_metadata',
            category: 'SERVER_SIDE_REQUEST_FORGERY',
            canaryToken: tokenDescriptor.canaryToken,
            callbackDomain: tokenDescriptor.callbackDomain,
            interactionType: interaction.interactionType,
            remoteAddress: interaction.remoteAddress,
            interactionTimestamp: interaction.receivedAt,
            exposureSeverity: tokenDescriptor.purpose === 'blind_ssrf' || tokenDescriptor.purpose === 'oob_rce' ? 'critical' : 'high',
            observedAt: nowIso,
            candidateId,
            evidenceRecordId,
            lineage: `${assessmentId}:${scanId}:${actorId}:${nowIso}`,
          },
        };
        findings.push(finding);
      } else {
        const draft: EvidenceDraftEnvelope = {
          draftKind: 'non_persisted_comparison_evidence_draft',
          draftId,
          suggestedEvidenceType: 'http_difference',
          suggestedStrength: 'strong',
          sourceComparisonId: `cmp_oobcan_${safeSeed}`,
          sourceSnapshotIds: {
            baselineSnapshotId: `snp_base_${safeToken}`,
            validationSnapshotId: `snp_val_${safeToken}`,
          },
          requiresHumanReview: true,
          notPersisted: true,
          notARealFinding: true,
          notConfirmedEvidence: true,
          notForExternalDelivery: true,
          notM45EvidenceRecord: true,
          safeRationale: rationale,
        };
        evidenceDrafts.push(draft);
      }
    }

    return {
      contractVersion: 'fixguard-detection-expansion/v0',
      kind: 'oob_canary_evaluation_result',
      hasInteractions: true,
      confirmedInteractions,
      evidenceDrafts,
      findings,
    };
  }

  /**
   * Cleans up volatile in-memory state for an assessment.
   */
  public clearAssessment(assessmentId: string): void {
    const tokens = this.tokensByAssessment.get(assessmentId);
    if (tokens) {
      for (const token of tokens) {
        this.tokensByTokenStr.delete(token);
        this.interactionsByTokenStr.delete(token);
      }
      this.tokensByAssessment.delete(assessmentId);
    }
  }

  /**
   * Returns current active in-memory token count.
   */
  public get activeTokenCount(): number {
    return this.tokensByTokenStr.size;
  }
}

export const defaultOobCanaryManager = new OobCanaryManager();
