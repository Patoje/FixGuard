/**
 * Native multi-identity authz matrix (Hadrian-equivalent thin slice).
 *
 * Expands dual-identity IDOR into pairwise comparisons:
 * - identity A vs B
 * - unauthenticated vs A (when A has credentials)
 * - unauthenticated vs B (when B has credentials)
 *
 * Write pairs (Fase 4 / A4 thin) are built separately via
 * buildAuthzMatrixWritePairs and executed by SupabaseBolaBflaWriteExpansionService.
 *
 * Never auto-executes attack plans; detection-only differential probes.
 */

import type {
  IdorDifferentialDetectionRequest,
  IdorDifferentialDetectionResult,
  ProbeAuthContext,
} from './DetectionContracts.js';
import { runIdorDifferentialDetection } from './IdorDifferentialDetectionService.js';
import { probeAuthContextHasCredentials } from './DetectionTargetBridge.js';

export type AuthzMatrixPairKind =
  | 'identity_a_vs_b'
  | 'unauth_vs_a'
  | 'unauth_vs_b';

/** Write-side matrix pairs (BOLA/BFLA) — gated behind allowStateChangingRequests. */
export type AuthzMatrixWritePairKind =
  | 'identity_a_vs_b_write'
  | 'unauth_vs_a_write'
  | 'unauth_vs_b_write';

export interface AuthzMatrixPair {
  readonly pairKind: AuthzMatrixPairKind;
  readonly left: ProbeAuthContext;
  readonly right: ProbeAuthContext;
}

export interface AuthzMatrixWritePair {
  readonly pairKind: AuthzMatrixWritePairKind;
  readonly left: ProbeAuthContext;
  readonly right: ProbeAuthContext;
}

export interface MultiIdentityAuthzMatrixRequest {
  readonly contractVersion: IdorDifferentialDetectionRequest['contractVersion'];
  readonly detectionIdPrefix: string;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly verifiedAuthorizationDecision: IdorDifferentialDetectionRequest['verifiedAuthorizationDecision'];
  readonly scopeGrant: IdorDifferentialDetectionRequest['scopeGrant'];
  readonly endpointUrl: string;
  readonly method?: IdorDifferentialDetectionRequest['method'];
  readonly resourceParamName: string;
  readonly baselineResourceId: string;
  readonly identityA: ProbeAuthContext;
  readonly identityB: ProbeAuthContext;
  readonly reviewerPolicy?: IdorDifferentialDetectionRequest['reviewerPolicy'];
  readonly humanReviewDecision?: IdorDifferentialDetectionRequest['humanReviewDecision'];
  readonly triageDecision?: IdorDifferentialDetectionRequest['triageDecision'];
  readonly transport?: IdorDifferentialDetectionRequest['transport'];
  readonly dnsResolver?: IdorDifferentialDetectionRequest['dnsResolver'];
  /** Cap pairwise runs per candidate (default: all built pairs). */
  readonly maxPairs?: number;
}

export interface MultiIdentityAuthzMatrixResult {
  readonly contractVersion: 'fixguard-authz-matrix/v0';
  readonly kind: 'multi_identity_authz_matrix_result';
  readonly pairsExecuted: number;
  readonly pairResults: readonly {
    readonly pairKind: AuthzMatrixPairKind;
    readonly result: IdorDifferentialDetectionResult;
  }[];
}

const UNAUTH_IDENTITY: ProbeAuthContext = Object.freeze({
  identityId: 'identity_unauth',
});

/**
 * Build pairwise probe sets. Always includes A vs B when both identities exist.
 */
export function buildAuthzMatrixPairs(
  identityA: ProbeAuthContext,
  identityB: ProbeAuthContext
): readonly AuthzMatrixPair[] {
  const pairs: AuthzMatrixPair[] = [
    {
      pairKind: 'identity_a_vs_b',
      left: identityA,
      right: identityB,
    },
  ];

  if (probeAuthContextHasCredentials(identityA)) {
    pairs.push({
      pairKind: 'unauth_vs_a',
      left: UNAUTH_IDENTITY,
      right: identityA,
    });
  }

  if (probeAuthContextHasCredentials(identityB)) {
    pairs.push({
      pairKind: 'unauth_vs_b',
      left: UNAUTH_IDENTITY,
      right: identityB,
    });
  }

  return Object.freeze(pairs);
}

/**
 * Build write-side pairwise probe sets (A↔B and unauth vs credentialed).
 * Execution requires allowStateChangingRequests — builder itself is pure.
 */
export function buildAuthzMatrixWritePairs(
  identityA: ProbeAuthContext,
  identityB: ProbeAuthContext
): readonly AuthzMatrixWritePair[] {
  const pairs: AuthzMatrixWritePair[] = [
    {
      pairKind: 'identity_a_vs_b_write',
      left: identityA,
      right: identityB,
    },
  ];

  if (probeAuthContextHasCredentials(identityA)) {
    pairs.push({
      pairKind: 'unauth_vs_a_write',
      left: UNAUTH_IDENTITY,
      right: identityA,
    });
  }

  if (probeAuthContextHasCredentials(identityB)) {
    pairs.push({
      pairKind: 'unauth_vs_b_write',
      left: UNAUTH_IDENTITY,
      right: identityB,
    });
  }

  return Object.freeze(pairs);
}

/**
 * Run IDOR differential across authz matrix pairs for one endpoint candidate.
 */
export async function runMultiIdentityAuthzMatrix(
  request: MultiIdentityAuthzMatrixRequest
): Promise<MultiIdentityAuthzMatrixResult> {
  const pairs = buildAuthzMatrixPairs(request.identityA, request.identityB);
  const maxPairs =
    typeof request.maxPairs === 'number' && request.maxPairs > 0
      ? Math.min(request.maxPairs, pairs.length)
      : pairs.length;

  const pairResults: {
    readonly pairKind: AuthzMatrixPairKind;
    readonly result: IdorDifferentialDetectionResult;
  }[] = [];

  for (const pair of pairs.slice(0, maxPairs)) {
    const result = await runIdorDifferentialDetection({
      contractVersion: request.contractVersion,
      kind: 'idor_differential_detection_request',
      detectionId: `${request.detectionIdPrefix}_${pair.pairKind}`.slice(0, 96),
      assessmentId: request.assessmentId,
      scanId: request.scanId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
      scopeGrant: request.scopeGrant,
      endpointUrl: request.endpointUrl,
      ...(request.method ? { method: request.method } : {}),
      resourceParamName: request.resourceParamName,
      baselineResourceId: request.baselineResourceId,
      identityA: pair.left,
      identityB: pair.right,
      ...(request.reviewerPolicy ? { reviewerPolicy: request.reviewerPolicy } : {}),
      ...(request.humanReviewDecision
        ? { humanReviewDecision: request.humanReviewDecision }
        : {}),
      ...(request.triageDecision ? { triageDecision: request.triageDecision } : {}),
      ...(request.transport ? { transport: request.transport } : {}),
      ...(request.dnsResolver ? { dnsResolver: request.dnsResolver } : {}),
    });

    pairResults.push({ pairKind: pair.pairKind, result });
  }

  return {
    contractVersion: 'fixguard-authz-matrix/v0',
    kind: 'multi_identity_authz_matrix_result',
    pairsExecuted: pairResults.length,
    pairResults: Object.freeze(pairResults),
  };
}
