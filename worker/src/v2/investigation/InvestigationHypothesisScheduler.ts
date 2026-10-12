/**
 * Block B — Investigation Hypothesis Scheduler & State Machine
 *
 * Pure, deterministic intelligence domain logic (NO network I/O, NO async).
 *
 * Responsibilities:
 * 1. Structural Route Normalization & Hypothesis Deduplication:
 *    Groups parameterized endpoints (e.g. /api/orders/123, /api/orders/124)
 *    into a single structural boundary hypothesis (/api/orders/{id}).
 * 2. Hypothesis Generation from Real Observations:
 *    Derives candidates from probe inventory, differential matrix records,
 *    discovered parameters, and verified findings.
 * 3. Deterministic Scoring & Priority Ranking:
 *    Calculates explainable scores based on evidence strength, novelty,
 *    attempt count, and information gain.
 * 4. Investigation Plan Generation:
 *    Translates the top hypothesis into an explicit, bounded, read-only plan.
 * 5. Closed-Loop Feedback & State Transitions:
 *    Applies observation results to update hypothesis state (supported, refuted,
 *    weakened, inconclusive, exhausted) and adjust scores for the next decision.
 */

import type { AttackCapabilityKind } from '../attack-planning/AttackPlanContracts.js';
import {
  isPublicStaticAssetUrl,
  isVercelSecurityChallengeUrl,
} from '../detection/PublicStaticAsset.js';
import { isJsluiceFragmentPath } from './InventoryRouteClass.js';
import type { Finding } from '../core/Evidence.js';
import {
  HYPOTHESIS_SCHEDULER_CONTRACT_VERSION,
  type HypothesisBlockReason,
  type HypothesisEpistemicStatus,
  type HypothesisLifecycleState,
  type HypothesisPriorityBand,
  type SecurityHypothesis,
  type SecurityHypothesisKind,
} from '../hypothesis-scheduler/HypothesisSchedulerContracts.js';
import type { ProbeInventory } from './ProbeInventoryContracts.js';
import {
  INVESTIGATION_FEEDBACK_CONTRACT_VERSION,
  type DiscoveredSurface,
  type InvestigationContextKind,
  type InvestigationExecutionResult,
  type InvestigationFeedbackStepRecord,
  type InvestigationPlan,
} from './InvestigationFeedbackContracts.js';

export interface RouteNormalizationResult {
  readonly normalizedPattern: string;
  readonly isParameterized: boolean;
  readonly objectId?: string;
  readonly parameterNames: readonly string[];
}

/**
 * Normalizes URL path structures to deduplicate dynamic endpoints.
 * E.g. /api/orders/1234 -> /api/orders/{id}
 *      /users/550e8400-e29b-41d4-a716-446655440000 -> /users/{uuid}
 */
export function normalizeStructuralRoute(rawUrl: string): RouteNormalizationResult {
  try {
    const isAbsolute = rawUrl.startsWith('http://') || rawUrl.startsWith('https://');
    const parsed = isAbsolute ? new URL(rawUrl) : new URL(rawUrl, 'https://dummy.local');
    const pathname = parsed.pathname;
    const segments = pathname.split('/').filter((s) => s.length > 0);
    const parameterNames: string[] = [];
    let isParameterized = false;
    let objectId: string | undefined;

    const normalizedSegments = segments.map((seg) => {
      // UUID check
      if (/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(seg)) {
        isParameterized = true;
        objectId = seg;
        return '{uuid}';
      }
      // Pure integer ID
      if (/^\d+$/.test(seg)) {
        isParameterized = true;
        objectId = seg;
        return '{id}';
      }
      // Common prefixed ID (ord_123, usr_abc, item-456, step1, step_1, ord123)
      if (/^(ord|usr|user|item|doc|inv|acc|tx|step|job)([_\-][a-zA-Z0-9]+|\d+[a-zA-Z0-9]*)$/i.test(seg)) {
        isParameterized = true;
        objectId = seg;
        return '{id}';
      }
      return seg;
    });

    for (const [key] of parsed.searchParams.entries()) {
      parameterNames.push(key);
      isParameterized = true;
    }

    const normalizedPath = `/${normalizedSegments.join('/')}`;
    const queryPart = parameterNames.length > 0 ? `?{${parameterNames.join(',')}}` : '';
    const normalizedPattern = isAbsolute
      ? `${parsed.origin}${normalizedPath}${queryPart}`
      : `${normalizedPath}${queryPart}`;

    return {
      normalizedPattern,
      isParameterized,
      ...(objectId ? { objectId } : {}),
      parameterNames: Object.freeze(parameterNames),
    };
  } catch {
    return {
      normalizedPattern: rawUrl,
      isParameterized: false,
      parameterNames: Object.freeze([]),
    };
  }
}

export interface HypothesisGenerationInput {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly targetDomain: string;
  readonly probeInventory?: ProbeInventory;
  readonly findings?: readonly Finding[];
  readonly differentialRecords?: readonly {
    readonly url: string;
    readonly outcome: string;
    readonly reasonCode: string;
  }[];
  readonly sessionContext: {
    readonly hasAuthenticatedContext: boolean;
    readonly hasSecondaryAuthenticatedContext: boolean;
    readonly hasJwt: boolean;
  };
  readonly nowIso?: string;
}

export function stableHypothesisId(kind: string, target: string): string {
  let h = 0;
  const s = `${kind}|${target}`;
  for (let i = 0; i < s.length; i++) {
    h = (h * 31 + s.charCodeAt(i)) >>> 0;
  }
  return `hyp_${kind.slice(0, 4)}_${h.toString(16).padStart(8, '0')}`;
}

/**
 * Pure generator creating candidate hypotheses from real observations.
 */
export function generateHypothesesFromObservations(
  input: HypothesisGenerationInput
): readonly SecurityHypothesis[] {
  const generated: SecurityHypothesis[] = [];
  const seenPatterns = new Set<string>();
  const now = input.nowIso ?? new Date().toISOString();

  // 1. Hypotheses from Differential Matrix observations (Highest value)
  for (const diff of input.differentialRecords ?? []) {
    const norm = normalizeStructuralRoute(diff.url);
    const key = `auth_diff|${norm.normalizedPattern}`;
    if (seenPatterns.has(key)) continue;
    seenPatterns.add(key);

    const isBroken = diff.outcome === 'potential_authorization_boundary' || diff.outcome === 'auth_boundary_broken_anon_parity';
    const hypId = stableHypothesisId('auth_boundary_differential', norm.normalizedPattern);

    generated.push({
      contractVersion: HYPOTHESIS_SCHEDULER_CONTRACT_VERSION,
      kind: 'security_hypothesis',
      hypothesisId: hypId,
      hypothesisKind: 'auth_boundary_differential',
      title: `Authorization boundary differential on ${norm.normalizedPattern}`,
      epistemicStatus: 'OBSERVED',
      state: isBroken ? 'supported' : 'candidate',
      score: isBroken ? 90 : 80,
      priorityBand: 'critical',
      rationale: `Differential matrix observed response discrepancy across authentication contexts on ${diff.url}`,
      explanation: Object.freeze([
        'Differential matrix observed significant response divergence',
        isBroken ? 'Unprotected application data observed anonymously' : 'Protected route requires authorization boundary validation',
      ]),
      sourceFindingIds: Object.freeze([]),
      targetUrl: diff.url,
      normalizedRoutePattern: norm.normalizedPattern,
      suggestedCapability: 'auth_boundary_differential',
      supportingEvidence: isBroken ? Object.freeze([`Differential outcome: ${diff.outcome} (${diff.reasonCode})`]) : Object.freeze([]),
      contradictingEvidence: Object.freeze([]),
      blocked: !input.sessionContext.hasAuthenticatedContext,
      blockReason: input.sessionContext.hasAuthenticatedContext ? 'none' : 'missing_byot_identities',
      ...(input.sessionContext.hasAuthenticatedContext
        ? {}
        : { blockDetail: 'Authorization differential requires at least one authenticated identity' }),
      dependencies: {
        requiresAuth: true,
        requiresSecondaryAuth: false,
        requiresParameter: false,
        satisfied: input.sessionContext.hasAuthenticatedContext,
        blockReason: input.sessionContext.hasAuthenticatedContext ? 'none' : 'missing_byot_identities',
      },
      investigationCount: 0,
      originatingObservation: {
        sourceKind: 'differential_matrix',
        summary: `Differential record ${diff.outcome} on ${diff.url}`,
      },
    });
  }

  // 2. Hypotheses from Parameterized & API Probe Inventory entries
  for (const entry of input.probeInventory?.entries ?? []) {
    const entryUrl = `${entry.origin}${entry.path}`;
    const norm = normalizeStructuralRoute(entryUrl);

    // Skip public static asset noise
    if (/\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot)(\?.*)?$/i.test(entryUrl)) {
      continue;
    }

    // GraphQL Surface Hypothesis
    if (entryUrl.includes('/graphql') || entryUrl.includes('/query')) {
      const gqlKey = `graphql|${entryUrl}`;
      if (!seenPatterns.has(gqlKey)) {
        seenPatterns.add(gqlKey);
        const hypId = stableHypothesisId('graphql_surface', entryUrl);
        generated.push({
          contractVersion: HYPOTHESIS_SCHEDULER_CONTRACT_VERSION,
          kind: 'security_hypothesis',
          hypothesisId: hypId,
          hypothesisKind: 'graphql_surface_probe',
          title: `GraphQL surface exposure on ${entryUrl}`,
          epistemicStatus: 'OBSERVED',
          state: 'candidate',
          score: 65,
          priorityBand: 'high',
          rationale: `Observed GraphQL endpoint at ${entryUrl}`,
          explanation: Object.freeze(['Discovered GraphQL endpoint in recon inventory', 'Requires schema introspection test']),
          sourceFindingIds: Object.freeze([]),
          targetUrl: entryUrl,
          normalizedRoutePattern: entryUrl,
          suggestedCapability: 'graphql_surface_probe',
          supportingEvidence: Object.freeze([`Discovered GraphQL surface at ${entryUrl}`]),
          contradictingEvidence: Object.freeze([]),
          blocked: false,
          blockReason: 'none',
          dependencies: {
            requiresAuth: false,
            requiresSecondaryAuth: false,
            requiresParameter: false,
            satisfied: true,
            blockReason: 'none',
          },
          investigationCount: 0,
          originatingObservation: {
            sourceKind: 'probe_inventory',
            summary: `GraphQL endpoint observed at ${entryUrl}`,
          },
        });
      }
    }

    // Parameterized Route -> IDOR & Access Control Hypothesis
    if (norm.isParameterized) {
      const hasDualAuth = input.sessionContext.hasSecondaryAuthenticatedContext;
      const hasSingleAuth = input.sessionContext.hasAuthenticatedContext;
      const kind: SecurityHypothesisKind = hasDualAuth ? 'idor_differential' : 'auth_boundary_differential';
      const capability: AttackCapabilityKind = hasDualAuth ? 'idor_read_differential' : 'auth_boundary_differential';
      const idorKey = `${kind}|${norm.normalizedPattern}`;
      if (!seenPatterns.has(idorKey)) {
        seenPatterns.add(idorKey);
        const hypId = stableHypothesisId(kind, norm.normalizedPattern);
        const observedObjectIds = norm.objectId ? [norm.objectId] : [];
        const candidateTargetUrls = [entryUrl];

        generated.push({
          contractVersion: HYPOTHESIS_SCHEDULER_CONTRACT_VERSION,
          kind: 'security_hypothesis',
          hypothesisId: hypId,
          hypothesisKind: kind,
          title: hasDualAuth
            ? `Object access boundary on ${norm.normalizedPattern}`
            : `Authorization boundary differential on ${norm.normalizedPattern}`,
          epistemicStatus: 'INFERRED',
          state: 'candidate',
          score: hasDualAuth ? 85 : hasSingleAuth ? 80 : 45,
          priorityBand: hasDualAuth || hasSingleAuth ? 'critical' : 'medium',
          rationale: `Parameterized object route discovered: ${norm.normalizedPattern}`,
          explanation: Object.freeze([
            'Parameterized object route represents candidate authorization boundary',
            hasDualAuth
              ? 'Dual BYOT identities available for cross-tenant testing'
              : hasSingleAuth
              ? 'Single identity available for authentication boundary differential testing'
              : 'Awaiting authenticated identity for differential verification',
          ]),
          sourceFindingIds: Object.freeze([]),
          targetUrl: entryUrl,
          normalizedRoutePattern: norm.normalizedPattern,
          suggestedCapability: capability,
          supportingEvidence: Object.freeze([`Discovered parameterized target ${entryUrl}`]),
          contradictingEvidence: Object.freeze([]),
          blocked: !hasSingleAuth,
          blockReason: hasSingleAuth ? 'none' : 'missing_byot_identities',
          ...(hasSingleAuth ? {} : { blockDetail: 'Authorization differential requires at least one authenticated identity' }),
          dependencies: {
            requiresAuth: true,
            requiresSecondaryAuth: hasDualAuth,
            requiresParameter: true,
            satisfied: hasDualAuth || hasSingleAuth,
            blockReason: hasSingleAuth ? 'none' : 'missing_byot_identities',
          },
          investigationCount: 0,
          observedObjectIds: Object.freeze(observedObjectIds),
          candidateTargetUrls: Object.freeze(candidateTargetUrls),
          originatingObservation: {
            sourceKind: 'probe_inventory',
            summary: `Parameterized route ${norm.normalizedPattern} with parameter ${norm.parameterNames.join(',') || norm.objectId || 'id'}`,
          },
        });
      } else {
        // Block B.1 — Retain subsequent object IDs and target URLs on the structural hypothesis
        const hypId = stableHypothesisId(kind, norm.normalizedPattern);
        const existing = generated.find((h) => h.hypothesisId === hypId);
        if (existing) {
          const updatedObjectIds = norm.objectId && !existing.observedObjectIds?.includes(norm.objectId)
            ? [...(existing.observedObjectIds ?? []), norm.objectId]
            : (existing.observedObjectIds ?? []);
          const updatedTargetUrls = !existing.candidateTargetUrls?.includes(entryUrl)
            ? [...(existing.candidateTargetUrls ?? []), entryUrl]
            : (existing.candidateTargetUrls ?? []);
          const updatedSupporting = !existing.supportingEvidence?.includes(`Discovered parameterized target ${entryUrl}`)
            ? [...(existing.supportingEvidence ?? []), `Discovered parameterized target ${entryUrl}`]
            : (existing.supportingEvidence ?? []);

          const idx = generated.indexOf(existing);
          generated[idx] = {
            ...existing,
            observedObjectIds: Object.freeze(updatedObjectIds),
            candidateTargetUrls: Object.freeze(updatedTargetUrls),
            supportingEvidence: Object.freeze(updatedSupporting),
          };
        }
      }
    }
  }

  // 3. Hypotheses from Findings
  for (const finding of input.findings ?? []) {
    let kind: SecurityHypothesisKind | null = null;
    let capability: AttackCapabilityKind = 'security_header_probe';
    let baseScore = 50;

    if (finding.type === 'BROKEN_ACCESS_CONTROL') {
      const hasSecondary = input.sessionContext.hasSecondaryAuthenticatedContext;
      kind = hasSecondary ? 'idor_differential' : 'auth_boundary_differential';
      capability = hasSecondary ? 'idor_read_differential' : 'auth_boundary_differential';
      baseScore = 85;
    } else if (finding.type === 'AUTHENTICATION_BYPASS') {
      kind = 'auth_bypass';
      capability = 'auth_bypass_probe';
      baseScore = 80;
    } else if (finding.type === 'CORS_MISCONFIGURATION' || finding.type === 'CROSS_ORIGIN_RESOURCE_SHARING') {
      kind = 'credentialed_cors';
      capability = 'cors_misconfiguration_probe';
      baseScore = 60;
    } else if (finding.type === 'OPEN_REDIRECT') {
      kind = 'parameter_reflection';
      capability = 'open_redirect_probe';
      baseScore = 55;
    } else if (finding.type === 'INFORMATION_DISCLOSURE') {
      kind = 'header_hardening_gap';
      capability = 'information_disclosure_probe';
      baseScore = 50;
    } else if (finding.type === 'DISCOVERY') {
      const hasSecondary = input.sessionContext.hasSecondaryAuthenticatedContext;
      const hasSingle = input.sessionContext.hasAuthenticatedContext;
      kind = hasSecondary ? 'idor_differential' : 'auth_boundary_differential';
      capability = hasSecondary ? 'idor_read_differential' : 'auth_boundary_differential';
      baseScore = hasSecondary ? 85 : hasSingle ? 80 : 50;
    }

    if (!kind) continue;
    const metadataEndpoint =
      finding.metadata && typeof finding.metadata === 'object' && 'endpointUrl' in finding.metadata
        ? (finding.metadata as { endpointUrl?: string }).endpointUrl
        : undefined;
    const targetUrl =
      metadataEndpoint ??
      (finding.target.startsWith('http') ? finding.target : `https://${input.targetDomain}/`);
    const norm = normalizeStructuralRoute(targetUrl);
    const key = `finding|${kind}|${norm.normalizedPattern}`;
    if (seenPatterns.has(key)) continue;
    seenPatterns.add(key);

    const hypId = stableHypothesisId(kind, norm.normalizedPattern);
    generated.push({
      contractVersion: HYPOTHESIS_SCHEDULER_CONTRACT_VERSION,
      kind: 'security_hypothesis',
      hypothesisId: hypId,
      hypothesisKind: kind,
      title: `${finding.type} hypothesis on ${norm.normalizedPattern}`,
      epistemicStatus: 'OBSERVED',
      state: 'candidate',
      score: baseScore,
      priorityBand: baseScore >= 80 ? 'critical' : baseScore >= 60 ? 'high' : 'medium',
      rationale: `Formed from finding ${finding.id} (${finding.type})`,
      explanation: Object.freeze([`Originating finding ${finding.id}`, `Target: ${norm.normalizedPattern}`]),
      sourceFindingIds: Object.freeze([finding.id]),
      targetUrl,
      normalizedRoutePattern: norm.normalizedPattern,
      suggestedCapability: capability,
      supportingEvidence: Object.freeze([`Derived from observation ${finding.id}`]),
      contradictingEvidence: Object.freeze([]),
      blocked: false,
      blockReason: 'none',
      dependencies: {
        requiresAuth:
          kind === 'auth_bypass' ||
          kind === 'idor_differential' ||
          kind === 'auth_boundary_differential',
        requiresSecondaryAuth: kind === 'idor_differential',
        requiresParameter: false,
        satisfied: true,
        blockReason: 'none',
      },
      investigationCount: 0,
      originatingObservation: {
        sourceKind: 'finding',
        observationId: finding.id,
        summary: `Finding ${finding.id}: ${finding.type}`,
      },
    });
  }

  return Object.freeze(generated);
}

export interface ScoreEvaluation {
  readonly score: number;
  readonly priorityBand: HypothesisPriorityBand;
  readonly explanation: readonly string[];
  readonly blocked: boolean;
  readonly blockReason: HypothesisBlockReason;
  readonly blockDetail?: string;
}

/**
 * Deterministic scoring pure function.
 */
export function scoreHypothesis(
  hyp: SecurityHypothesis,
  context: {
    readonly identityCount: number;
    readonly hasJwt: boolean;
  }
): ScoreEvaluation {
  const reasons: string[] = [];
  let score = 50;

  // 1. Base score by hypothesis kind
  switch (hyp.hypothesisKind) {
    case 'supabase_rls_read_confirm':
      score = 95;
      reasons.push('High security relevance: database Row Level Security read confirmation');
      break;
    case 'idor_differential':
    case 'auth_boundary_differential':
      score = 85;
      reasons.push('High security relevance: authorization boundary / access control');
      break;
    case 'auth_bypass':
      score = 80;
      reasons.push('High security relevance: authentication bypass');
      break;
    case 'jwt_confusion':
      score = 75;
      reasons.push('Elevated security relevance: JWT signature verification');
      break;
    case 'security_header_probe' as unknown as SecurityHypothesisKind:
      score = 70;
      reasons.push('Baseline application route read observation');
      break;
    case 'graphql_surface_probe':
      score = 65;
      reasons.push('API surface discovery: GraphQL introspection');
      break;
    case 'parameter_reflection':
    case 'credentialed_cors':
      score = 60;
      reasons.push('Medium security relevance: parameter or CORS boundary');
      break;
    case 'header_hardening_gap':
      score = 25;
      reasons.push('Low information gain: header hardening gap');
      break;
    default:
      score = 50;
      reasons.push('Default baseline security score');
  }

  if (hyp.suggestedCapability === 'security_header_probe' && score < 70) {
    score = 70;
    reasons.push('Baseline application route read observation');
  }

  // 2. State adjustments
  const state = hyp.state ?? 'candidate';
  switch (state) {
    case 'refuted':
      score = 0;
      reasons.push('Negative evidence: hypothesis refuted by target response (score set to 0)');
      return {
        score: 0,
        priorityBand: 'low',
        explanation: Object.freeze(reasons),
        blocked: false,
        blockReason: 'none',
      };
    case 'exhausted':
      score = 0;
      reasons.push('Budget exhausted: maximum requests reached without confirmation');
      return {
        score: 0,
        priorityBand: 'low',
        explanation: Object.freeze(reasons),
        blocked: false,
        blockReason: 'none',
      };
    case 'candidate':
      score += 10;
      reasons.push('Fresh untested candidate (+10)');
      break;
    case 'supported':
      score += 15;
      reasons.push('Corroborated by prior test: high verification priority (+15)');
      break;
    case 'weakened':
      score -= 25;
      reasons.push('Weakened by equivocal observation (-25)');
      break;
    case 'inconclusive':
      score -= 10;
      reasons.push('Prior probe interfered or inconclusive (-10)');
      break;
    case 'validated':
    case 'confirmed':
      score -= 30;
      reasons.push('Already validated: deprioritized in favor of unresolved surfaces (-30)');
      break;
  }

  // 3. Information Gain & Parameter Bonuses
  if (hyp.normalizedRoutePattern?.includes('{id}') || hyp.normalizedRoutePattern?.includes('{uuid}')) {
    score += 15;
    reasons.push('Parameterized object route detected (+15)');
  }
  if (hyp.originatingObservation?.sourceKind === 'differential_matrix') {
    score += 15;
    reasons.push('Directly backed by differential matrix observation (+15)');
  }

  // 4. Investigation Attempt Penalty (Negative feedback on repeated attempts)
  const count = hyp.investigationCount ?? 0;
  if (count > 0) {
    const penalty = count * 15;
    score -= penalty;
    reasons.push(`Attempt penalty for ${count} prior probe(s) (-${penalty})`);
  }

  // 5. Dependency & Block Resolution
  let blocked = false;
  let blockReason: HypothesisBlockReason = 'none';
  let blockDetail: string | undefined;

  if (hyp.dependencies?.requiresSecondaryAuth && context.identityCount < 2) {
    blocked = true;
    blockReason = 'missing_byot_identities';
    blockDetail = 'Requires dual session identities (Identity A and B)';
    score = 0;
    reasons.push('BLOCKED: Missing secondary BYOT identity for cross-tenant verification');
  } else if (hyp.dependencies?.requiresAuth && context.identityCount < 1) {
    blocked = true;
    blockReason = 'missing_byot_identities';
    blockDetail = 'Requires authenticated session identity';
    score = 0;
    reasons.push('BLOCKED: Missing authenticated BYOT identity');
  } else if (hyp.hypothesisKind === 'jwt_confusion' && !context.hasJwt) {
    blocked = true;
    blockReason = 'missing_jwt_identity';
    blockDetail = 'Requires Bearer JWT identity';
    score = 0;
    reasons.push('BLOCKED: Identity lacks Bearer JWT');
  }

  if (hyp.targetUrl) {
    if (isVercelSecurityChallengeUrl(hyp.targetUrl)) {
      blocked = true;
      blockReason = 'none';
      score = 0;
      reasons.push('BLOCKED: Platform challenge asset is not a valid route');
    } else {
      let targetPath = '';
      try {
        targetPath = new URL(hyp.targetUrl).pathname;
      } catch {
        targetPath = hyp.targetUrl;
      }
      if (isJsluiceFragmentPath(targetPath)) {
        blocked = true;
        blockReason = 'none';
        score = 0;
        reasons.push('BLOCKED: Jsluice fragment is noise and not a valid route');
      } else if (isPublicStaticAssetUrl(hyp.targetUrl)) {
        if (
          hyp.hypothesisKind === 'auth_bypass' ||
          hyp.hypothesisKind === 'auth_boundary_differential'
        ) {
          blocked = true;
          blockReason = 'none';
          score = 0;
          reasons.push('BLOCKED: Public static asset is not an authentication boundary');
        } else {
          score -= 30;
          reasons.push('Public static asset: deprioritized in favor of application routes (-30)');
        }
      }
    }
  }

  // Clamp 0 to 100
  score = Math.max(0, Math.min(100, Math.round(score)));

  const priorityBand: HypothesisPriorityBand =
    score >= 80 ? 'critical' : score >= 60 ? 'high' : score >= 40 ? 'medium' : 'low';

  return {
    score,
    priorityBand,
    explanation: Object.freeze(reasons),
    blocked,
    blockReason,
    ...(blockDetail ? { blockDetail } : {}),
  };
}

export interface NextInvestigationSelection {
  readonly selectedHypothesis: SecurityHypothesis;
  readonly plan: InvestigationPlan;
}

/**
 * Pure scheduler: ranks all hypotheses and selects the top actionable plan.
 */
export function scheduleNextInvestigation(
  hypotheses: readonly SecurityHypothesis[],
  context: {
    readonly identityCount: number;
    readonly hasJwt: boolean;
    readonly nowIso?: string;
  }
): NextInvestigationSelection | null {
  const now = context.nowIso ?? new Date().toISOString();

  // Evaluate & score all hypotheses
  const scored = hypotheses.map((hyp) => {
    const evaluation = scoreHypothesis(hyp, context);
    return {
      hypothesis: {
        ...hyp,
        score: evaluation.score,
        priorityBand: evaluation.priorityBand,
        explanation: evaluation.explanation,
        blocked: evaluation.blocked,
        blockReason: evaluation.blockReason,
        ...(evaluation.blockDetail ? { blockDetail: evaluation.blockDetail } : {}),
      },
      evaluation,
    };
  });

  // Filter to runnable hypotheses: score > 0, unblocked, not refuted, not exhausted,
  // and having unexamined candidate targets or secondary authentication contexts
  const runnable = scored.filter((item) => {
    if (item.evaluation.blocked) return false;
    if (item.evaluation.score <= 0) return false;
    if (item.hypothesis.state === 'refuted' || item.hypothesis.state === 'exhausted') return false;
    const count = item.hypothesis.investigationCount ?? 0;
    if (count === 0) return true;
    if (Array.isArray(item.hypothesis.candidateTargetUrls) && count < item.hypothesis.candidateTargetUrls.length) {
      return true;
    }
    if (item.hypothesis.dependencies?.requiresSecondaryAuth && context.identityCount >= 2 && count < 2) {
      return true;
    }
    return false;
  });

  if (runnable.length === 0) {
    return null;
  }

  // Sort deterministically:
  // 1. Score descending
  // 2. Investigation count ascending (favor fresher)
  // 3. Hypothesis ID ascending (tiebreak)
  runnable.sort((left, right) => {
    if (right.evaluation.score !== left.evaluation.score) {
      return right.evaluation.score - left.evaluation.score;
    }
    const leftCount = left.hypothesis.investigationCount ?? 0;
    const rightCount = right.hypothesis.investigationCount ?? 0;
    if (leftCount !== rightCount) {
      return leftCount - rightCount;
    }
    if (
      left.hypothesis.createdAt &&
      right.hypothesis.createdAt &&
      left.hypothesis.createdAt !== right.hypothesis.createdAt
    ) {
      return left.hypothesis.createdAt.localeCompare(right.hypothesis.createdAt);
    }
    return left.hypothesis.hypothesisId.localeCompare(right.hypothesis.hypothesisId);
  });

  const winner = runnable[0].hypothesis;

  // Determine context kind based on requirements
  let contextKind: InvestigationContextKind = 'anonymous';
  if (winner.dependencies?.requiresSecondaryAuth) {
    contextKind = 'authenticated_secondary';
  } else if (winner.dependencies?.requiresAuth) {
    contextKind = 'authenticated';
  }

  // Determine capability
  const capability: AttackCapabilityKind =
    (winner.suggestedCapability as AttackCapabilityKind) ??
    (winner.hypothesisKind === 'idor_differential'
      ? 'idor_read_differential'
      : winner.hypothesisKind === 'auth_boundary_differential'
      ? 'auth_boundary_differential'
      : winner.hypothesisKind === 'graphql_surface_probe'
      ? 'graphql_surface_probe'
      : 'security_header_probe');

  const targetUrl = winner.targetUrl ?? `https://app.example.com/`;
  const planId = `inv_plan_${winner.hypothesisId.slice(4)}_${(winner.investigationCount ?? 0) + 1}`;

  const plan: InvestigationPlan = {
    contractVersion: INVESTIGATION_FEEDBACK_CONTRACT_VERSION,
    kind: 'investigation_plan',
    planId,
    hypothesisId: winner.hypothesisId,
    capability,
    targetUrl,
    method: 'GET',
    contextKind,
    requestPurpose: `Controlled read verification for ${winner.title}`,
    expectedObservation: `Differential verification outcome for ${winner.hypothesisKind}`,
    safetyLevel: 'read_only',
    requestCost: 1,
    dependenciesReady: true,
    createdAt: now,
  };

  return {
    selectedHypothesis: winner,
    plan,
  };
}

/**
 * Pure state machine: applies investigation result to update hypothesis state.
 */
export function applyInvestigationFeedback(
  hypothesis: SecurityHypothesis,
  result: InvestigationExecutionResult,
  maxRequestsPerHypothesis = 2
): {
  readonly updatedHypothesis: SecurityHypothesis;
  readonly stepRecord: InvestigationFeedbackStepRecord;
} {
  const fromState = hypothesis.state ?? 'candidate';
  let toState: HypothesisLifecycleState = fromState;
  const supporting = [...(hypothesis.supportingEvidence ?? [])];
  const contradicting = [...(hypothesis.contradictingEvidence ?? [])];
  const count = (hypothesis.investigationCount ?? 0) + 1;

  switch (result.outcome) {
    case 'supported':
      toState = fromState === 'supported' ? 'validated' : 'supported';
      supporting.push(result.safeEvidenceMessage);
      break;
    case 'refuted':
      toState = 'refuted';
      contradicting.push(result.safeEvidenceMessage);
      break;
    case 'weakened':
      toState = 'weakened';
      contradicting.push(result.safeEvidenceMessage);
      break;
    case 'inconclusive':
      toState = 'inconclusive';
      contradicting.push(result.safeEvidenceMessage);
      break;
  }

  // Exhaustion bound
  if (count >= maxRequestsPerHypothesis && toState !== 'validated' && toState !== 'refuted') {
    toState = 'exhausted';
    contradicting.push(`Investigation budget ceiling reached (${count}/${maxRequestsPerHypothesis} attempts)`);
  }

  const updatedHypothesis: SecurityHypothesis = {
    ...hypothesis,
    state: toState,
    investigationCount: count,
    lastTestedAt: result.executedAt,
    supportingEvidence: Object.freeze(supporting),
    contradictingEvidence: Object.freeze(contradicting),
  };

  const oldScore = hypothesis.score ?? 50;
  const newScore = toState === 'refuted' || toState === 'exhausted' ? 0 : Math.max(0, oldScore + (result.outcome === 'supported' ? 15 : -25));

  const stepRecord: InvestigationFeedbackStepRecord = {
    stepIndex: count,
    hypothesisId: hypothesis.hypothesisId,
    planId: result.planId,
    capability: (hypothesis.suggestedCapability as AttackCapabilityKind) ?? 'security_header_probe',
    targetUrl: result.targetUrl,
    contextKind: result.statusCode ? 'authenticated' : 'anonymous',
    testValidityVerdict: result.testValidityVerdict,
    outcome: result.outcome,
    stateTransition: {
      from: fromState,
      to: toState,
    },
    scoreDelta: newScore - oldScore,
    reasonCode: result.reasonCode,
    safeEvidenceMessage: result.safeEvidenceMessage,
    executedAt: result.executedAt,
  };

  return {
    updatedHypothesis,
    stepRecord,
  };
}
