/**
 * Milestone A11 — LateralMovementService
 *
 * Manages the four disjoint lateral-movement structural types.
 * DiscoveredReachableHost always has inScope: false; discovery never
 * authorizes network probes. Credential reuse is evaluated only against
 * AuthorizedLateralTarget hosts after vault + brand + SSRF/DNS gates.
 *
 * A10 LateralMovementHypothesis remains INFERRED; this service promotes
 * discovery into DiscoveredReachableHost and requires explicit scope grants
 * for AuthorizedLateralTarget.
 */

import { isStrictSafeId } from '../reporting-boundary/DefensiveReportContracts.js';
import { sanitizeEvidenceFragment } from '../core/EvidenceSanitizer.js';
import { isScopeAllowed } from '../attack-execution/AttackExecutionContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AttackAuthorizationToken } from '../attack-authorization/AttackAuthorizationContracts.js';
import type { AuthorizedExecutionLineageTuple } from '../detection/DetectionContracts.js';
import type { IdorHttpProbeTransport } from '../detection/DetectionContracts.js';
import type { PreSpawnDnsResolver } from '../recon/adapters/AdapterPreflightPipeline.js';
import type { CredentialReference } from '../post-exploitation/PostExploitationContracts.js';
import type { PostExploitationState } from '../post-exploitation/PostExploitationContracts.js';
import type { CredentialVaultService } from '../post-exploitation/CredentialVaultService.js';
import type { CapabilityGained } from './AttackPlanContracts.js';
import {
  LATERAL_MOVEMENT_CONTRACT_VERSION,
  isLateralMovementMechanism,
  type ActuallyAccessedTarget,
  type AttackEvidence,
  type AuthorizedLateralTarget,
  type DiscoveredReachableHost,
  type LateralMovementMechanism,
  type LateralMovementRecord,
  type LateralMovementSnapshot,
  type SuccessfullyPivotedTarget,
} from './LateralMovementContracts.js';
import {
  attemptCredentialReuse,
  type CredentialReuseAttemptResult,
} from '../attack-execution/capabilities/CredentialReuseCapability.js';

export class LateralMovementValidationError extends Error {
  readonly reasonCode = 'lateral_movement_validation_error' as const;

  constructor(message: string) {
    super(message);
    this.name = 'LateralMovementValidationError';
  }
}

export class LateralMovementUnauthorizedError extends Error {
  readonly reasonCode = 'lateral_movement_unauthorized' as const;

  constructor(message: string) {
    super(message);
    this.name = 'LateralMovementUnauthorizedError';
  }
}

interface AssessmentLateralState {
  readonly assessmentId: string;
  readonly scanId: string;
  discoveredHosts: DiscoveredReachableHost[];
  authorizedTargets: AuthorizedLateralTarget[];
  accessedTargets: ActuallyAccessedTarget[];
  pivotedTargets: SuccessfullyPivotedTarget[];
  records: LateralMovementRecord[];
  updatedAt: string;
}

export interface RegisterDiscoveredHostInput {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly hostname: string;
  readonly discoveredInStepId: string;
  readonly discoveredAt?: string;
}

export interface PromoteToAuthorizedTargetInput {
  readonly assessmentId: string;
  readonly hostname: string;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly authorizedBy: string;
  readonly authorizedAt?: string;
}

export interface EvaluateCredentialReuseInput {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly sourceHost: string;
  readonly destinationHost: string;
  readonly mechanism: LateralMovementMechanism;
  readonly credentialRef: CredentialReference;
  readonly vault: CredentialVaultService;
  readonly token: AttackAuthorizationToken;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly targetUrl?: string;
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
  readonly capabilityGained?: CapabilityGained;
  readonly recordedAt?: string;
}

export type EvaluateCredentialReuseResult =
  | {
      readonly status: 'access_confirmed';
      readonly accessed: ActuallyAccessedTarget;
      readonly pivoted?: SuccessfullyPivotedTarget;
      readonly record: LateralMovementRecord;
      readonly reuse: CredentialReuseAttemptResult;
    }
  | {
      readonly status: 'access_denied' | 'unauthorized';
      readonly record: LateralMovementRecord;
      readonly reuse: CredentialReuseAttemptResult;
      readonly networkDispatched: false;
    };

function assertStrictId(field: string, value: string): void {
  if (!value || typeof value !== 'string' || !isStrictSafeId(value)) {
    throw new LateralMovementValidationError(
      `Field ${field} must satisfy strict identifier format`
    );
  }
}

function normalizeHostname(hostname: string): string {
  if (typeof hostname !== 'string' || hostname.trim().length === 0) {
    throw new LateralMovementValidationError('hostname must be a non-empty string');
  }
  return sanitizeEvidenceFragment(hostname.trim().toLowerCase(), 256);
}

/**
 * Process-local lateral-movement state. Discovery ≠ authorization.
 */
export class LateralMovementService {
  private readonly byAssessment = new Map<string, AssessmentLateralState>();

  private ensureState(
    assessmentId: string,
    scanId: string,
    updatedAt: string
  ): AssessmentLateralState {
    assertStrictId('assessmentId', assessmentId);
    assertStrictId('scanId', scanId);
    const existing = this.byAssessment.get(assessmentId);
    if (existing) {
      if (existing.scanId !== scanId) {
        throw new LateralMovementValidationError(
          'Lateral movement state scanId isolation violation'
        );
      }
      return existing;
    }
    const created: AssessmentLateralState = {
      assessmentId,
      scanId,
      discoveredHosts: [],
      authorizedTargets: [],
      accessedTargets: [],
      pivotedTargets: [],
      records: [],
      updatedAt,
    };
    this.byAssessment.set(assessmentId, created);
    return created;
  }

  public getSnapshot(assessmentId: string): LateralMovementSnapshot | null {
    if (!assessmentId || typeof assessmentId !== 'string' || !isStrictSafeId(assessmentId)) {
      throw new LateralMovementValidationError(
        'Field assessmentId must satisfy strict identifier format'
      );
    }
    const state = this.byAssessment.get(assessmentId);
    if (!state) return null;
    return Object.freeze({
      contractVersion: LATERAL_MOVEMENT_CONTRACT_VERSION,
      kind: 'lateral_movement_snapshot' as const,
      assessmentId: state.assessmentId,
      scanId: state.scanId,
      discoveredHosts: Object.freeze([...state.discoveredHosts]),
      authorizedTargets: Object.freeze([...state.authorizedTargets]),
      accessedTargets: Object.freeze([...state.accessedTargets]),
      pivotedTargets: Object.freeze([...state.pivotedTargets]),
      records: Object.freeze([...state.records]),
      updatedAt: state.updatedAt,
    });
  }

  /**
   * Register a discovery-only host. inScope is forced to false.
   * This NEVER authorizes network probes.
   */
  public registerDiscoveredHost(input: RegisterDiscoveredHostInput): DiscoveredReachableHost {
    assertStrictId('discoveredInStepId', input.discoveredInStepId);
    const hostname = normalizeHostname(input.hostname);
    const discoveredAt = input.discoveredAt ?? new Date().toISOString();
    const state = this.ensureState(input.assessmentId, input.scanId, discoveredAt);

    const existing = state.discoveredHosts.find((h) => h.hostname === hostname);
    if (existing) {
      return existing;
    }

    const host: DiscoveredReachableHost = Object.freeze({
      contractVersion: LATERAL_MOVEMENT_CONTRACT_VERSION,
      kind: 'discovered_reachable_host',
      hostname,
      discoveredInStepId: input.discoveredInStepId,
      inScope: false,
      discoveredAt,
    });

    state.discoveredHosts.push(host);
    state.updatedAt = discoveredAt;
    return host;
  }

  /**
   * Promote A10 hypotheses into DiscoveredReachableHost entries.
   * Hypotheses stay INFERRED; this does not authorize them.
   */
  public evaluateHypothesesFromState(
    postExploitationState: PostExploitationState
  ): readonly DiscoveredReachableHost[] {
    const registered: DiscoveredReachableHost[] = [];
    for (const hypothesis of postExploitationState.lateralMovementHypotheses) {
      const host = this.registerDiscoveredHost({
        assessmentId: postExploitationState.assessmentId,
        scanId: postExploitationState.scanId,
        hostname: hypothesis.targetHost,
        discoveredInStepId: hypothesis.discoveredInStepId,
        discoveredAt: hypothesis.discoveredAt,
      });
      registered.push(host);
    }
    return Object.freeze(registered);
  }

  /**
   * Promote a discovered (or known) host to AuthorizedLateralTarget.
   * Requires an explicit AuthorizedScopeGrant that permits the hostname.
   */
  public promoteToAuthorizedTarget(
    input: PromoteToAuthorizedTargetInput
  ): AuthorizedLateralTarget {
    assertStrictId('assessmentId', input.assessmentId);
    assertStrictId('authorizedBy', input.authorizedBy);

    const hostname = normalizeHostname(input.hostname);
    const scopeGrant = input.scopeGrant;
    if (!scopeGrant || typeof scopeGrant !== 'object' || Array.isArray(scopeGrant)) {
      throw new LateralMovementUnauthorizedError(
        'AuthorizedScopeGrant is required to promote a lateral target'
      );
    }
    if (typeof scopeGrant.grantId !== 'string' || !isStrictSafeId(scopeGrant.grantId)) {
      throw new LateralMovementUnauthorizedError(
        'AuthorizedScopeGrant.grantId must satisfy strict identifier format'
      );
    }
    if (!isScopeAllowed(hostname, scopeGrant)) {
      throw new LateralMovementUnauthorizedError(
        'hostname is not permitted under the provided AuthorizedScopeGrant'
      );
    }

    const authorizedAt = input.authorizedAt ?? new Date().toISOString();
    const scanId =
      this.byAssessment.get(input.assessmentId)?.scanId ??
      (typeof scopeGrant.scanId === 'string' ? scopeGrant.scanId : '');
    if (!scanId || !isStrictSafeId(scanId)) {
      throw new LateralMovementValidationError(
        'scanId must be established before promoting a lateral target'
      );
    }

    const state = this.ensureState(input.assessmentId, scanId, authorizedAt);
    const existing = state.authorizedTargets.find((t) => t.hostname === hostname);
    if (existing) {
      return existing;
    }

    const target: AuthorizedLateralTarget = Object.freeze({
      contractVersion: LATERAL_MOVEMENT_CONTRACT_VERSION,
      kind: 'authorized_lateral_target',
      hostname,
      scopeGrantId: scopeGrant.grantId,
      authorizedAt,
      authorizedBy: input.authorizedBy,
    });

    state.authorizedTargets.push(target);
    state.updatedAt = authorizedAt;
    return target;
  }

  /**
   * Fail-closed: discovery-only hosts MUST NOT trigger network probes.
   */
  public assertNetworkProbeAllowed(assessmentId: string, hostname: string): void {
    assertStrictId('assessmentId', assessmentId);
    const normalized = normalizeHostname(hostname);
    const state = this.byAssessment.get(assessmentId);
    if (!state) {
      throw new LateralMovementUnauthorizedError(
        'No lateral-movement state; network probe denied (fail-closed)'
      );
    }

    const authorized = state.authorizedTargets.some((t) => t.hostname === normalized);
    if (!authorized) {
      const discovered = state.discoveredHosts.find((h) => h.hostname === normalized);
      if (discovered) {
        throw new LateralMovementUnauthorizedError(
          `DiscoveredReachableHost "${normalized}" has inScope=false; network probe denied`
        );
      }
      throw new LateralMovementUnauthorizedError(
        `Host "${normalized}" is not an AuthorizedLateralTarget; network probe denied`
      );
    }
  }

  /**
   * Evaluate credential reuse against an authorized lateral target only.
   * Unauthorized / discovery-only destinations fail closed with zero network dispatch.
   */
  public async evaluateCredentialReuse(
    input: EvaluateCredentialReuseInput
  ): Promise<EvaluateCredentialReuseResult> {
    assertStrictId('assessmentId', input.assessmentId);
    assertStrictId('scanId', input.scanId);
    if (!isLateralMovementMechanism(input.mechanism)) {
      throw new LateralMovementValidationError('Invalid LateralMovementMechanism');
    }

    const sourceHost = normalizeHostname(input.sourceHost);
    const destinationHost = normalizeHostname(input.destinationHost);
    const recordedAt = input.recordedAt ?? new Date().toISOString();
    const state = this.ensureState(input.assessmentId, input.scanId, recordedAt);

    const isAuthorized = state.authorizedTargets.some(
      (t) => t.hostname === destinationHost
    );

    if (!isAuthorized) {
      const evidence: AttackEvidence = Object.freeze({
        evidenceId: `ev_lat_unauth_${recordedAt.replace(/[^0-9A-Za-z]/g, '').slice(0, 24)}`,
        reasonCode: 'destination_not_authorized_lateral_target',
        safeMessage:
          'Credential reuse denied: destination is not an AuthorizedLateralTarget (zero network)',
        recordedAt,
      });
      const record = this.appendRecord(state, {
        recordId: `lmr_${recordedAt.replace(/[^0-9A-Za-z]/g, '').slice(0, 20)}_${destinationHost.slice(0, 12)}`,
        assessmentId: input.assessmentId,
        scanId: input.scanId,
        mechanism: input.mechanism,
        sourceHost,
        destinationHost,
        credentialRefId: input.credentialRef.credentialId,
        status: 'unauthorized',
        lineage: input.lineage,
        evidence: [evidence],
        recordedAt,
      });
      return {
        status: 'unauthorized',
        record,
        networkDispatched: false,
        reuse: {
          outcome: 'denied',
          reasonCode: 'destination_not_authorized_lateral_target',
          safeMessage: evidence.safeMessage,
          networkDispatched: false,
        },
      };
    }

    // Authorized path: still enforce vault + brand + SSRF/DNS before network.
    const reuse = await attemptCredentialReuse({
      vault: input.vault,
      credentialRef: input.credentialRef,
      targetHost: destinationHost,
      targetUrl: input.targetUrl ?? `https://${destinationHost}/`,
      token: input.token,
      scopeGrant: input.scopeGrant,
      transport: input.transport,
      dnsResolver: input.dnsResolver,
    });

    if (reuse.outcome === 'denied' || reuse.outcome === 'preflight_denied') {
      const evidence: AttackEvidence = Object.freeze({
        evidenceId: `ev_lat_denied_${recordedAt.replace(/[^0-9A-Za-z]/g, '').slice(0, 24)}`,
        reasonCode: reuse.reasonCode,
        safeMessage: reuse.safeMessage,
        recordedAt,
      });
      const record = this.appendRecord(state, {
        recordId: `lmr_denied_${recordedAt.replace(/[^0-9A-Za-z]/g, '').slice(0, 20)}`,
        assessmentId: input.assessmentId,
        scanId: input.scanId,
        mechanism: input.mechanism,
        sourceHost,
        destinationHost,
        credentialRefId: input.credentialRef.credentialId,
        status: reuse.networkDispatched ? 'access_denied' : 'unauthorized',
        lineage: input.lineage,
        evidence: [evidence],
        recordedAt,
      });
      return {
        status: reuse.networkDispatched ? 'access_denied' : 'unauthorized',
        record,
        networkDispatched: false,
        reuse,
      };
    }

    if (reuse.outcome === 'access_denied') {
      const evidenceId =
        reuse.evidenceId ??
        `ev_lat_access_denied_${recordedAt.replace(/[^0-9A-Za-z]/g, '').slice(0, 20)}`;
      const evidence: AttackEvidence = Object.freeze({
        evidenceId,
        reasonCode: reuse.reasonCode,
        safeMessage: reuse.safeMessage,
        recordedAt,
      });
      const record = this.appendRecord(state, {
        recordId: `lmr_access_denied_${recordedAt.replace(/[^0-9A-Za-z]/g, '').slice(0, 16)}`,
        assessmentId: input.assessmentId,
        scanId: input.scanId,
        mechanism: input.mechanism,
        sourceHost,
        destinationHost,
        credentialRefId: input.credentialRef.credentialId,
        status: 'access_denied',
        lineage: input.lineage,
        evidence: [evidence],
        recordedAt,
      });
      return {
        status: 'access_denied',
        record,
        networkDispatched: false,
        reuse,
      };
    }

    // access_confirmed — real evidence required for VERIFIED
    if (reuse.outcome !== 'access_confirmed' || typeof reuse.evidenceId !== 'string') {
      throw new LateralMovementValidationError(
        'Credential reuse confirmation requires VERIFIED evidenceId (fail-closed)'
      );
    }
    const evidenceId = reuse.evidenceId;
    const evidence: AttackEvidence = Object.freeze({
      evidenceId,
      reasonCode: reuse.reasonCode,
      safeMessage: reuse.safeMessage,
      recordedAt,
    });

    const accessed: ActuallyAccessedTarget = Object.freeze({
      contractVersion: LATERAL_MOVEMENT_CONTRACT_VERSION,
      kind: 'actually_accessed_target',
      hostname: destinationHost,
      evidenceId,
      epistemicStatus: 'VERIFIED' as const,
      accessedAt: recordedAt,
    });
    if (!state.accessedTargets.some((t) => t.hostname === destinationHost)) {
      state.accessedTargets.push(accessed);
    }

    const capabilityGained: CapabilityGained = input.capabilityGained ?? 'read_authenticated';
    let pivoted: SuccessfullyPivotedTarget | undefined;
    if (capabilityGained !== 'none') {
      pivoted = Object.freeze({
        contractVersion: LATERAL_MOVEMENT_CONTRACT_VERSION,
        kind: 'successfully_pivoted_target',
        hostname: destinationHost,
        capabilityGained,
        epistemicStatus: 'VERIFIED',
        pivotedAt: recordedAt,
      });
      if (!state.pivotedTargets.some((t) => t.hostname === destinationHost)) {
        state.pivotedTargets.push(pivoted);
      }
    }

    const record = this.appendRecord(state, {
      recordId: `lmr_ok_${recordedAt.replace(/[^0-9A-Za-z]/g, '').slice(0, 20)}`,
      assessmentId: input.assessmentId,
      scanId: input.scanId,
      mechanism: input.mechanism,
      sourceHost,
      destinationHost,
      credentialRefId: input.credentialRef.credentialId,
      status: pivoted ? 'pivot_complete' : 'access_confirmed',
      lineage: input.lineage,
      evidence: [evidence],
      recordedAt,
    });

    state.updatedAt = recordedAt;

    return {
      status: 'access_confirmed',
      accessed,
      ...(pivoted ? { pivoted } : {}),
      record,
      reuse,
    };
  }

  private appendRecord(
    state: AssessmentLateralState,
    record: Omit<LateralMovementRecord, 'contractVersion' | 'kind'>
  ): LateralMovementRecord {
    const frozen: LateralMovementRecord = Object.freeze({
      contractVersion: LATERAL_MOVEMENT_CONTRACT_VERSION,
      kind: 'lateral_movement_record' as const,
      recordId: record.recordId,
      assessmentId: record.assessmentId,
      scanId: record.scanId,
      mechanism: record.mechanism,
      sourceHost: record.sourceHost,
      destinationHost: record.destinationHost,
      ...(record.credentialRefId !== undefined
        ? { credentialRefId: record.credentialRefId }
        : {}),
      status: record.status,
      lineage: record.lineage,
      evidence: Object.freeze([...record.evidence]),
      recordedAt: record.recordedAt,
    });
    state.records.push(frozen);
    state.updatedAt = record.recordedAt;
    return frozen;
  }
}
