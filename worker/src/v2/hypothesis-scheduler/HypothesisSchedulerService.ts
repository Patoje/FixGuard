/**
 * Etapa 2 · F2 — HypothesisSchedulerService + PreconditionResolver stub.
 * Deterministic ranking. No auto-execute.
 */

import {
  HYPOTHESIS_SCHEDULER_CONTRACT_VERSION,
  type HypothesisBlockReason,
  type HypothesisSchedulerInput,
  type HypothesisSchedulerResult,
  type SecurityHypothesis,
  type SecurityHypothesisKind,
} from './HypothesisSchedulerContracts.js';

export interface PreconditionResolution {
  readonly satisfied: boolean;
  readonly blockReason: HypothesisBlockReason;
  readonly detail?: string;
  readonly subHypothesisTitle?: string;
  readonly subHypothesisRationale?: string;
}

/**
 * Stub resolver: maps hypothesis kinds to identity/param preconditions.
 * Missing BYOT → blocked with obtain_byot_identities sub-hypothesis.
 */
export function resolveHypothesisPreconditions(args: {
  readonly hypothesisKind: SecurityHypothesisKind;
  readonly identityCount: number;
  readonly hasJwtIdentity: boolean;
  readonly hasObservedParameter?: boolean;
}): PreconditionResolution {
  const { hypothesisKind, identityCount, hasJwtIdentity, hasObservedParameter } = args;

  if (hypothesisKind === 'idor_differential') {
    if (identityCount >= 2) {
      return { satisfied: true, blockReason: 'none' };
    }
    return {
      satisfied: false,
      blockReason: 'missing_byot_identities',
      detail: 'IDOR differential requires BYOT identity A+B',
      subHypothesisTitle: 'Obtain dual BYOT identities',
      subHypothesisRationale:
        'Provide two authorized session identities at assessment launch before dual-identity differential execution',
    };
  }

  if (hypothesisKind === 'auth_boundary_differential') {
    // A+anon is enough for auth-boundary GET differential; dual BYOT preferred for A↔B notes.
    if (identityCount >= 1) {
      return { satisfied: true, blockReason: 'none' };
    }
    return {
      satisfied: false,
      blockReason: 'missing_byot_identities',
      detail: 'Account/order auth-boundary differential requires at least Identity A (anon probe is empty headers)',
      subHypothesisTitle: 'Obtain authenticated BYOT identity',
      subHypothesisRationale:
        'Provide at least one authorized session identity; anonymous contrast is probed with empty headers',
    };
  }

  if (hypothesisKind === 'auth_bypass') {
    if (identityCount >= 1) {
      return { satisfied: true, blockReason: 'none' };
    }
    return {
      satisfied: false,
      blockReason: 'missing_byot_identities',
      detail: 'Authentication bypass hypothesis requires at least Identity A',
      subHypothesisTitle: 'Obtain authenticated BYOT identity',
      subHypothesisRationale:
        'Provide one authorized session identity before an auth-bypass execute',
    };
  }

  if (hypothesisKind === 'jwt_confusion') {
    if (hasJwtIdentity) {
      return { satisfied: true, blockReason: 'none' };
    }
    return {
      satisfied: false,
      blockReason: 'missing_jwt_identity',
      detail: 'JWT confusion probe requires a Bearer JWT identity',
    };
  }

  if (hypothesisKind === 'parameter_reflection' || hypothesisKind === 'sql_oracle') {
    if (hasObservedParameter === false) {
      return {
        satisfied: false,
        blockReason: 'missing_parameter',
        detail: 'No observed parameter available for this hypothesis',
      };
    }
  }

  if (hypothesisKind === 'header_hardening_gap') {
    return {
      satisfied: false,
      blockReason: 'stack_policy_deprioritized',
      detail: 'Missing security headers remain low-info; not Attack Mode primary',
    };
  }

  return { satisfied: true, blockReason: 'none' };
}

function shaId(parts: readonly string[]): string {
  let h = 0;
  const s = parts.join('|');
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
  return `hyp_${h.toString(16).padStart(8, '0')}`;
}

export class HypothesisSchedulerService {
  public schedule(input: HypothesisSchedulerInput): HypothesisSchedulerResult {
    const rulesApplied: string[] = [];
    const raw: SecurityHypothesis[] = [];
    const max =
      typeof input.maxHypotheses === 'number' && input.maxHypotheses > 0
        ? Math.floor(input.maxHypotheses)
        : 12;
    const stack = input.stackHints ?? {};
    const tech = (stack.technologyNames ?? []).map((t) => t.toLowerCase());
    const hasSpa =
      stack.hasSpa === true ||
      stack.hasNextJs === true ||
      tech.some((t) => /next|react|vue|spa/.test(t));
    const vercelNext =
      (stack.hasVercel === true || tech.some((t) => /vercel/.test(t))) &&
      (stack.hasNextJs === true || tech.some((t) => /next/.test(t)));

    const pushFindingHypotheses = (): void => {
      for (const f of input.findings) {
        const meta = f.metadataKind ?? '';
        let kind: SecurityHypothesisKind | null = null;
        let title = '';
        let capability = '';
        let score = 50;
        let epistemic: SecurityHypothesis['epistemicStatus'] = 'OBSERVED';

        if (
          f.type === 'BROKEN_ACCESS_CONTROL' ||
          meta === 'broken_access_control_metadata'
        ) {
          kind = 'idor_differential';
          title = 'IDOR / BOLA differential hypothesis';
          capability = 'idor_read_differential';
          score = 95;
        } else if (meta === 'auth_bypass_metadata') {
          kind = 'auth_bypass';
          title = 'Authentication bypass hypothesis';
          capability = 'auth_bypass_probe';
          score = 90;
        } else if (
          meta === 'credentialed_cors_metadata' ||
          (f.type === 'CORS_MISCONFIGURATION' && meta.includes('cors'))
        ) {
          kind = 'credentialed_cors';
          title = 'Credentialed CORS chain hypothesis';
          capability = 'cors_chain_exploit';
          score = 88;
        } else if (meta === 'jwt_algorithm_confusion_metadata') {
          kind = 'jwt_confusion';
          title = 'JWT alg confusion hypothesis';
          capability = 'jwt_alg_none_probe';
          score = 85;
        } else if (meta === 'sql_error_oracle_metadata') {
          kind = 'sql_oracle';
          title = 'SQL error-oracle hypothesis';
          capability = '';
          score = 70;
        } else if (
          f.type === 'PARAMETER_REFLECTION' ||
          meta === 'blind_xss_detection_metadata'
        ) {
          kind = 'parameter_reflection';
          title = 'Parameter reflection / XSS hypothesis';
          capability = 'parameter_reflection_probe';
          score = 65;
        } else if (meta === 'missing_security_headers_metadata') {
          kind = 'header_hardening_gap';
          title = 'Missing security headers (low-info)';
          score = 15;
          epistemic = 'INFERRED';
        }

        if (!kind) continue;
        rulesApplied.push(`rule_finding_${kind}`);
        const pre = resolveHypothesisPreconditions({
          hypothesisKind: kind,
          identityCount: input.identityCount,
          hasJwtIdentity: input.hasJwtIdentity,
          hasObservedParameter: true,
        });
        raw.push(
          Object.freeze({
            contractVersion: HYPOTHESIS_SCHEDULER_CONTRACT_VERSION,
            kind: 'security_hypothesis',
            hypothesisId: shaId([input.assessmentId, kind, f.id]),
            hypothesisKind: kind,
            title,
            epistemicStatus: epistemic,
            score: pre.satisfied ? score : Math.min(score, 40),
            rationale: `Derived from finding ${f.id} (${f.type})`,
            sourceFindingIds: Object.freeze([f.id]),
            ...(capability ? { suggestedCapability: capability } : {}),
            blocked: !pre.satisfied,
            blockReason: pre.blockReason,
            ...(pre.detail ? { blockDetail: pre.detail } : {}),
            ...(pre.subHypothesisTitle
              ? {
                  subHypothesis: Object.freeze({
                    hypothesisKind: 'obtain_byot_identities' as const,
                    title: pre.subHypothesisTitle,
                    rationale: pre.subHypothesisRationale ?? pre.detail ?? '',
                  }),
                }
              : {}),
          })
        );
      }
    };

    pushFindingHypotheses();

    if (hasSpa && !raw.some((h) => h.hypothesisKind === 'spa_surface_probe')) {
      rulesApplied.push('rule_asg_spa_surface');
      const score = vercelNext ? 35 : 45;
      raw.push(
        Object.freeze({
          contractVersion: HYPOTHESIS_SCHEDULER_CONTRACT_VERSION,
          kind: 'security_hypothesis',
          hypothesisId: shaId([input.assessmentId, 'spa_surface']),
          hypothesisKind: 'spa_surface_probe',
          title: 'SPA / JS surface expansion',
          epistemicStatus: 'INFERRED',
          score: vercelNext ? Math.max(20, score - 10) : score,
          rationale: vercelNext
            ? 'Vercel+Next stack — soft-deprioritize spray; prefer observed endpoints from JS mining'
            : 'SPA signals present — expand JS/endpoint surface before spray',
          sourceFindingIds: Object.freeze([]),
          suggestedCapability: 'parameter_reflection_probe',
          blocked: vercelNext,
          blockReason: vercelNext ? 'stack_policy_deprioritized' : 'none',
          ...(vercelNext
            ? {
                blockDetail:
                  'Soft deprioritization vs Vercel bot challenges — wait for OBSERVED JS endpoints',
              }
            : {}),
        })
      );
    }

    if (
      (input.asgNodeKinds ?? []).includes('endpoint') &&
      input.identityCount < 2 &&
      !raw.some((h) => h.hypothesisKind === 'idor_differential')
    ) {
      rulesApplied.push('rule_asg_idor_needs_byot');
      const pre = resolveHypothesisPreconditions({
        hypothesisKind: 'idor_differential',
        identityCount: input.identityCount,
        hasJwtIdentity: input.hasJwtIdentity,
      });
      raw.push(
        Object.freeze({
          contractVersion: HYPOTHESIS_SCHEDULER_CONTRACT_VERSION,
          kind: 'security_hypothesis',
          hypothesisId: shaId([input.assessmentId, 'asg_idor']),
          hypothesisKind: 'idor_differential',
          title: 'ASG endpoint IDOR candidate (needs BYOT)',
          epistemicStatus: 'INFERRED',
          score: 40,
          rationale: 'ASG contains endpoints but dual identities are not present',
          sourceFindingIds: Object.freeze([]),
          suggestedCapability: 'idor_read_differential',
          blocked: true,
          blockReason: pre.blockReason,
          blockDetail: pre.detail,
          subHypothesis: Object.freeze({
            hypothesisKind: 'obtain_byot_identities' as const,
            title: pre.subHypothesisTitle ?? 'Obtain dual BYOT identities',
            rationale: pre.subHypothesisRationale ?? '',
          }),
        })
      );
    }

    const hasEndpoint = (input.asgNodeKinds ?? []).includes('endpoint');
    const pushSurface = (
      hypothesisKind: SecurityHypothesisKind,
      title: string,
      rationale: string,
      score: number,
      suggestedCapability: string | undefined,
      rule: string
    ): void => {
      if (raw.some((h) => h.hypothesisKind === hypothesisKind)) return;
      rulesApplied.push(rule);
      const pre = resolveHypothesisPreconditions({
        hypothesisKind,
        identityCount: input.identityCount,
        hasJwtIdentity: input.hasJwtIdentity,
        hasObservedParameter: input.hasObservedParameter === true,
      });
      raw.push(
        Object.freeze({
          contractVersion: HYPOTHESIS_SCHEDULER_CONTRACT_VERSION,
          kind: 'security_hypothesis',
          hypothesisId: shaId([input.assessmentId, hypothesisKind, 'surface']),
          hypothesisKind,
          title,
          epistemicStatus: 'INFERRED',
          score: pre.satisfied ? score : Math.min(score, 40),
          rationale,
          sourceFindingIds: Object.freeze([]),
          ...(suggestedCapability ? { suggestedCapability } : {}),
          blocked: !pre.satisfied,
          blockReason: pre.blockReason,
          ...(pre.detail ? { blockDetail: pre.detail } : {}),
          ...(pre.subHypothesisTitle
            ? {
                subHypothesis: Object.freeze({
                  hypothesisKind: 'obtain_byot_identities' as const,
                  title: pre.subHypothesisTitle,
                  rationale: pre.subHypothesisRationale ?? pre.detail ?? '',
                }),
              }
            : {}),
        })
      );
    };

    if (hasEndpoint) {
      pushSurface(
        'auth_boundary_differential',
        'Account/order auth-boundary differential (A+anon)',
        'OBSERVED endpoint surface with one identity is enough for an A versus anonymous GET hypothesis',
        80,
        'auth_boundary_differential',
        'rule_asg_auth_boundary'
      );
      pushSurface(
        'auth_bypass',
        'Authentication bypass hypothesis',
        'Auth-bypass stays a hypothesis until a later authorized execute',
        72,
        'auth_bypass_probe',
        'rule_asg_auth_bypass'
      );
      pushSurface(
        'jwt_confusion',
        'JWT alg confusion hypothesis',
        'JWT confusion stays a hypothesis until a later authorized execute',
        68,
        'jwt_alg_none_probe',
        'rule_asg_jwt'
      );
      pushSurface(
        'sql_oracle',
        'SQL error-oracle hypothesis',
        'SQL error-oracle stays a hypothesis. No automatic finding and no unregistered probe plan',
        60,
        undefined,
        'rule_asg_sql'
      );
    }

    const ranked = [...raw].sort((a, b) => {
      if (b.score !== a.score) return b.score - a.score;
      return a.hypothesisId.localeCompare(b.hypothesisId);
    });

    return Object.freeze({
      contractVersion: HYPOTHESIS_SCHEDULER_CONTRACT_VERSION,
      assessmentId: input.assessmentId,
      scanId: input.scanId,
      hypotheses: Object.freeze(ranked.slice(0, max)),
      rulesApplied: Object.freeze([...new Set(rulesApplied)]),
      generatedAt: new Date().toISOString(),
    });
  }
}
