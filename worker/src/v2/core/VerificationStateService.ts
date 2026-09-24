/**
 * VerificationStateService.ts
 * FixGuard V2 - Verification State Machine Service
 * Enforces strict ordered forward transitions and state immutability.
 */

import type { Finding } from './Evidence';
import type { VerificationState, VerificationStateTransition } from './VerificationStateContracts';
import {
  IllegalVerificationStateTransitionError,
  verificationStateIndex,
} from './VerificationStateContracts';

function applyTransition(
  finding: Finding,
  targetState: VerificationState,
  transition: {
    readonly evidenceId?: string;
    readonly reviewerId?: string;
    readonly reasonCode: string;
  }
): { updatedFinding: Finding; transitionRecord: VerificationStateTransition } {
  if (!transition.evidenceId && !transition.reviewerId) {
    throw new Error(
      'Verification state transition invariant violated: Must specify either evidenceId or reviewerId.'
    );
  }

  if (!transition.reasonCode || transition.reasonCode.trim().length === 0) {
    throw new Error('Verification state transition invariant violated: Reason code is required.');
  }

  const currentState = finding.verificationState;

  const transitionRecord: VerificationStateTransition = {
    fromState: currentState,
    toState: targetState,
    transitionedAt: new Date().toISOString(),
    ...(transition.evidenceId ? { evidenceId: transition.evidenceId } : {}),
    ...(transition.reviewerId ? { reviewerId: transition.reviewerId } : {}),
    reasonCode: transition.reasonCode,
  };

  const updatedFinding: Finding = Object.freeze({
    ...finding,
    verificationState: targetState,
  });

  return { updatedFinding, transitionRecord };
}

export class VerificationStateService {
  /**
   * Advances verification state by at most ONE ordered step forward (or same-state no-op).
   * Skipping ahead or moving backward throws IllegalVerificationStateTransitionError.
   * Invariant: A transition MUST carry either an evidenceId or a reviewerId.
   */
  public static advanceState(
    finding: Finding,
    targetState: VerificationState,
    transition: {
      readonly evidenceId?: string;
      readonly reviewerId?: string;
      readonly reasonCode: string;
    }
  ): { updatedFinding: Finding; transitionRecord: VerificationStateTransition } {
    const fromIdx = verificationStateIndex(finding.verificationState);
    const toIdx = verificationStateIndex(targetState);

    if (fromIdx < 0 || toIdx < 0 || toIdx - fromIdx > 1 || toIdx < fromIdx) {
      throw new IllegalVerificationStateTransitionError(finding.verificationState, targetState);
    }

    return applyTransition(finding, targetState, transition);
  }

  /**
   * Refutes or resets verification state with evidence or human reviewer authorization.
   * May downgrade or stay at the same state — never upgrade (toIdx > fromIdx throws).
   */
  public static refuteState(
    finding: Finding,
    targetState: VerificationState,
    transition: {
      readonly evidenceId?: string;
      readonly reviewerId?: string;
      readonly reasonCode: string;
    }
  ): { updatedFinding: Finding; transitionRecord: VerificationStateTransition } {
    const fromIdx = verificationStateIndex(finding.verificationState);
    const toIdx = verificationStateIndex(targetState);

    if (fromIdx < 0 || toIdx < 0 || toIdx > fromIdx) {
      throw new IllegalVerificationStateTransitionError(finding.verificationState, targetState);
    }

    return applyTransition(finding, targetState, transition);
  }
}
