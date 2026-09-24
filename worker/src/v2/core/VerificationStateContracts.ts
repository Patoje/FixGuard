/**
 * VerificationStateContracts.ts
 * FixGuard V2 - 5-State Verification Lifecycle Contracts
 */

export type VerificationState =
  | 'observed_anomaly'
  | 'suspected_vulnerability'
  | 'validated_vulnerability'
  | 'exploitability_confirmed'
  | 'impact_confirmed';

/**
 * Strict forward order for advanceState().
 * advanceState may move at most ONE step forward (or stay put).
 * refuteState may reset/downgrade or stay — never upgrade (toIdx > fromIdx).
 */
export const VERIFICATION_STATE_ORDER: readonly VerificationState[] = [
  'observed_anomaly',
  'suspected_vulnerability',
  'validated_vulnerability',
  'exploitability_confirmed',
  'impact_confirmed',
] as const;

export function verificationStateIndex(state: VerificationState): number {
  return VERIFICATION_STATE_ORDER.indexOf(state);
}

export function nextVerificationState(state: VerificationState): VerificationState | null {
  const idx = verificationStateIndex(state);
  if (idx < 0 || idx >= VERIFICATION_STATE_ORDER.length - 1) {
    return null;
  }
  return VERIFICATION_STATE_ORDER[idx + 1]!;
}

export class IllegalVerificationStateTransitionError extends Error {
  readonly code = 'illegal_verification_state_transition' as const;
  readonly fromState: VerificationState;
  readonly toState: VerificationState;

  constructor(fromState: VerificationState, toState: VerificationState) {
    super(
      `Illegal verification state transition: cannot advance from "${fromState}" to "${toState}" (ordered forward by at most one step)`
    );
    this.name = 'IllegalVerificationStateTransitionError';
    this.fromState = fromState;
    this.toState = toState;
  }
}

export interface VerificationStateTransition {
  readonly fromState: VerificationState;
  readonly toState: VerificationState;
  readonly transitionedAt: string;
  readonly evidenceId?: string;
  readonly reviewerId?: string;
  readonly reasonCode: string;
}
