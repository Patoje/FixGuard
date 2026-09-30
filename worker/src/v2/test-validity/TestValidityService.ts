/**
 * TestValidity evaluator — valid | interfered | inconclusive.
 *
 * Rule: verdict !== 'valid' → allowsVerificationMutation = false
 * (cannot advance or refute VerificationState).
 */

import {
  TEST_VALIDITY_CONTRACT_VERSION,
  type DefenseObservation,
  type HttpResponseDefenseSignals,
  type TestValidityEvaluation,
  type TestValidityEvaluationInput,
  type TestValidityVerdict,
} from './TestValidityContracts.js';
import {
  isBlockingDefense,
  observeDefensesFromHttpResponse,
} from './DefenseObservationService.js';

function looksSuccessful(signals: HttpResponseDefenseSignals): boolean {
  const status = signals.statusCode;
  if (typeof status !== 'number') return false;
  return status >= 200 && status < 400 && status !== 429;
}

function looksBlocked(signals: HttpResponseDefenseSignals): boolean {
  const status = signals.statusCode;
  if (status === 403 || status === 429 || status === 503) return true;
  const body = signals.bodyExcerpt ?? '';
  return /vercel\s*security\s*checkpoint|attention\s+required|captcha|just\s+a\s+moment|cf-browser-verification/i.test(
    body
  );
}

function mergeDefenses(
  ...groups: readonly (readonly DefenseObservation[])[]
): readonly DefenseObservation[] {
  const byReason = new Map<string, DefenseObservation>();
  for (const group of groups) {
    for (const obs of group) {
      if (!byReason.has(obs.reasonCode)) {
        byReason.set(obs.reasonCode, obs);
      }
    }
  }
  return Object.freeze([...byReason.values()]);
}

function buildEvaluation(args: {
  readonly verdict: TestValidityVerdict;
  readonly reasonCode: string;
  readonly defenses: readonly DefenseObservation[];
  readonly evaluatedAt: string;
}): TestValidityEvaluation {
  return Object.freeze({
    contractVersion: TEST_VALIDITY_CONTRACT_VERSION,
    kind: 'test_validity_evaluation' as const,
    verdict: args.verdict,
    reasonCode: args.reasonCode,
    defenses: args.defenses,
    evaluatedAt: args.evaluatedAt,
    allowsVerificationMutation: args.verdict === 'valid',
  });
}

/**
 * Evaluate whether a probe result is a valid measurement, interfered by a
 * defense, or inconclusive.
 */
export function evaluateTestValidity(
  input: TestValidityEvaluationInput
): TestValidityEvaluation {
  const evaluatedAt = input.observedAt ?? new Date().toISOString();
  const prefix = input.observationIdPrefix ?? 'tv';

  const probeDefenses = observeDefensesFromHttpResponse(input.probe, {
    observedAt: evaluatedAt,
    observationIdPrefix: `${prefix}_probe`,
  });

  const controlDefenses = input.control
    ? observeDefensesFromHttpResponse(input.control, {
        observedAt: evaluatedAt,
        observationIdPrefix: `${prefix}_control`,
      })
    : Object.freeze([] as DefenseObservation[]);

  const defenses = mergeDefenses(probeDefenses, controlDefenses);
  const blockingProbe = probeDefenses.filter(isBlockingDefense);
  const blockingControl = controlDefenses.filter(isBlockingDefense);

  // interference_check: suspicious blocked, benign control passes → interfered
  if (input.control) {
    const probeBlocked = looksBlocked(input.probe) || blockingProbe.length > 0;
    const controlOk =
      looksSuccessful(input.control) && blockingControl.length === 0;

    if (probeBlocked && controlOk) {
      const differential: DefenseObservation = Object.freeze({
        contractVersion: TEST_VALIDITY_CONTRACT_VERSION,
        kind: 'defense_observation' as const,
        observationId: `def_ctrl_${prefix}`,
        controlKind: blockingProbe[0]?.controlKind ?? 'waf',
        signalSource: 'control_differential' as const,
        reasonCode: 'probe_blocked_control_passed',
        observedAt: evaluatedAt,
        ...(input.probe.targetHost
          ? { targetHost: input.probe.targetHost }
          : {}),
      });
      return buildEvaluation({
        verdict: 'interfered',
        reasonCode: 'interference_check_probe_blocked_control_ok',
        defenses: mergeDefenses(defenses, [differential]),
        evaluatedAt,
      });
    }

    // Both blocked → cannot tell vuln absence from defense
    if (probeBlocked && (looksBlocked(input.control) || blockingControl.length > 0)) {
      return buildEvaluation({
        verdict: 'inconclusive',
        reasonCode: 'both_probe_and_control_blocked',
        defenses,
        evaluatedAt,
      });
    }
  }

  if (blockingProbe.length > 0 || looksBlocked(input.probe)) {
    return buildEvaluation({
      verdict: 'interfered',
      reasonCode: blockingProbe[0]?.reasonCode ?? 'probe_blocked_without_control',
      defenses,
      evaluatedAt,
    });
  }

  if (
    typeof input.probe.statusCode !== 'number' &&
    !(input.probe.bodyExcerpt && input.probe.bodyExcerpt.length > 0) &&
    defenses.length === 0
  ) {
    return buildEvaluation({
      verdict: 'inconclusive',
      reasonCode: 'insufficient_response_signal',
      defenses,
      evaluatedAt,
    });
  }

  return buildEvaluation({
    verdict: 'valid',
    reasonCode: 'measurement_not_interfered',
    defenses,
    evaluatedAt,
  });
}

/**
 * Gate for VerificationStateService.advanceState / refuteState callers.
 * interfered / inconclusive → mutation denied (finding stays put).
 */
export function canMutateVerificationState(
  evaluation: TestValidityEvaluation
): boolean {
  return evaluation.allowsVerificationMutation === true && evaluation.verdict === 'valid';
}

/**
 * Derive validity from capability-style reason codes when HTTP facets are absent.
 * Used as a thin bridge until capabilities emit full DefenseObservation payloads.
 */
export function evaluateTestValidityFromReasonCode(
  reasonCode: string,
  options?: { readonly evaluatedAt?: string; readonly targetHost?: string }
): TestValidityEvaluation {
  const evaluatedAt = options?.evaluatedAt ?? new Date().toISOString();
  const code = reasonCode.toLowerCase();

  // Soft-404 / both-404 / expired session / insufficient signal → inconclusive
  // (MUST NOT advance or refute VerificationState as if the test were valid).
  // Checked before interference so codes like both_404_inconclusive are not
  // misclassified by substring matches (e.g. "bot" inside "both").
  const inconclusive =
    /inconclusive|soft.?404|html.?shell|both.?404|session.?expired|insufficient.?signal|baseline_not_authenticated|spa_html|unauthenticated_baseline/.test(
      code
    );
  if (inconclusive) {
    return buildEvaluation({
      verdict: 'inconclusive',
      reasonCode: 'capability_reason_indicates_inconclusive',
      defenses: [],
      evaluatedAt,
    });
  }

  const interfered =
    /waf|challenge|rate[_ ]?limit|\bbot\b|cloudflare|vercel.?security|interfered|captcha|403_blocked|blocked_by_defense/.test(
      code
    );

  if (interfered) {
    const defense: DefenseObservation = Object.freeze({
      contractVersion: TEST_VALIDITY_CONTRACT_VERSION,
      kind: 'defense_observation' as const,
      observationId: `def_rc_${code.slice(0, 24)}`,
      controlKind: /rate/.test(code)
        ? ('rate_limit' as const)
        : /\bbot\b|captcha|challenge/.test(code)
          ? ('bot' as const)
          : ('waf' as const),
      signalSource: 'error_signal' as const,
      reasonCode: code.slice(0, 80),
      observedAt: evaluatedAt,
      ...(options?.targetHost ? { targetHost: options.targetHost } : {}),
    });
    return buildEvaluation({
      verdict: 'interfered',
      reasonCode: 'capability_reason_indicates_interference',
      defenses: [defense],
      evaluatedAt,
    });
  }

  return buildEvaluation({
    verdict: 'valid',
    reasonCode: 'capability_reason_no_interference',
    defenses: [],
    evaluatedAt,
  });
}
