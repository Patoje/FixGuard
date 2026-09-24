/**
 * FixGuard V2 — Attack Mode API Client (Milestone A13)
 *
 * Typed Bearer-authenticated client for Attack Mode workbench routes under
 * GET/POST /api/v2/assessments/:assessmentId/...
 *
 * Uses /assessments prefix (authorize/execute only exist there; GETs mirror).
 * Never accepts or displays raw secrets. Runtime WeakSet brands stay server-side.
 */

import type { LineageTuple } from './v2Api';
import { V2ApiError, type V2ApiClientConfig } from './v2Api';

// ---------------------------------------------------------------------------
// Shared / epistemic
// ---------------------------------------------------------------------------

export type EpistemicStatus = 'OBSERVED' | 'INFERRED' | 'VERIFIED' | 'REFUTED';

export type AttackPlanScopeClass =
  | 'single_parameter'
  | 'single_endpoint'
  | 'single_resource'
  | 'user_scoped'
  | 'role_scoped'
  | 'tenant_scoped'
  | 'application_wide'
  | 'origin_wide'
  | 'domain_wide'
  | 'cross_origin_third_party';

export type AuthorizableBlastRadiusClass =
  | 'read_public'
  | 'read_authenticated'
  | 'read_escalated'
  | 'sensitive_data_access'
  | 'credential_use'
  | 'privilege_escalation'
  | 'lateral_movement'
  | 'state_change_benign'
  | 'state_change_impact';

export type BlastRadiusClass = AuthorizableBlastRadiusClass | 'persistence' | 'destructive';

export type AttackCapabilityKind =
  | 'idor_read_differential'
  | 'cors_chain_exploit'
  | 'auth_bypass_probe'
  | 'jwt_alg_none_probe'
  | 'sql_error_oracle_probe'
  | 'parameter_reflection_probe'
  | 'session_fixation_probe'
  | 'method_manipulation_probe'
  | 'lfi_path_traversal'
  | 'sql_oracle_advancement'
  | 'nuclei_xss_scan'
  | 'sql_injection_verification'
  | 'credential_reuse';

export type CapabilityGained =
  | 'read_escalated'
  | 'read_authenticated'
  | 'active_validation'
  | 'none';

export type AttackPlanStatus =
  | 'ready_for_authorization'
  | 'prerequisite_missing'
  | 'authorized'
  | 'rejected'
  | 'superseded';

export type AttackStepStatus =
  | 'pending'
  | 'blocked'
  | 'ready'
  | 'skipped'
  | 'completed';

export type AttackPrerequisiteKind =
  | 'identity_count_at_least_2'
  | 'identity_present'
  | 'identity_with_jwt'
  | 'parameter_present'
  | 'credentialed_cors'
  | 'finding_present'
  | 'host_in_scope'
  | 'credential_reference_present';

export interface AttackPrerequisite {
  readonly kind: AttackPrerequisiteKind;
  readonly description: string;
  readonly satisfied: boolean;
  readonly detail?: string;
}

export interface AttackStep {
  readonly stepId: string;
  readonly ordinal: number;
  readonly title: string;
  readonly description: string;
  readonly status: AttackStepStatus;
  readonly requiredPermissions: readonly string[];
}

export interface AttackPlan {
  readonly contractVersion: 'fixguard-attack-planning/v0';
  readonly kind: 'attack_plan';
  readonly planId: string;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly capability: AttackCapabilityKind;
  readonly title: string;
  readonly reasoning: string;
  readonly status: AttackPlanStatus;
  readonly blastRadius: AttackPlanScopeClass;
  readonly capabilityGained: CapabilityGained;
  readonly sourceFindingIds: readonly string[];
  readonly sourceFindingTypes: readonly string[];
  readonly prerequisites: readonly AttackPrerequisite[];
  readonly steps: readonly AttackStep[];
  readonly targetUrl?: string;
  readonly parameterName?: string;
  readonly planOrigin?: 'validated_finding' | 'pending_draft' | 'observed_surface';
  readonly sourceDraftIds?: readonly string[];
  readonly lineage: LineageTuple;
  readonly createdAt: string;
  readonly executable: false;
}

export interface GetAttackPlansResponse {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly planCount: number;
  readonly plans: readonly AttackPlan[];
  readonly lineage: LineageTuple;
}

export type AttackAuthorizationLevel =
  | 'assessment_authorization'
  | 'hitl_plan_approval'
  | 'explicit_per_step_approval';

/** Safe token DTO — brand is process-local WeakSet on the worker, never in JSON. */
export interface AttackAuthorizationTokenDto {
  readonly planId: string;
  readonly assessmentId: string;
  readonly blastRadiusClass: AuthorizableBlastRadiusClass;
  readonly authorizationLevel: AttackAuthorizationLevel;
  readonly authorizedBy: string;
  readonly authorizedAt: string;
}

export interface AuthorizeAttackPlanParams {
  readonly operatorId: string;
  readonly blastRadiusClass: BlastRadiusClass;
  readonly authorizedAt?: string;
}

export interface AuthorizeAttackPlanResponse {
  readonly status: 'established';
  readonly reasonCode: string;
  readonly token: AttackAuthorizationTokenDto;
}

export type AttackStepExecutionOutcome =
  | 'succeeded'
  | 'observed'
  | 'refuted'
  | 'failed'
  | 'preflight_denied'
  | 'capability_not_implemented';

export interface AttackStepExecutionDto {
  readonly stepId: string;
  readonly outcome: AttackStepExecutionOutcome;
  readonly reasonCode: string;
  readonly gatesPassed: true | string;
  readonly verificationStateBefore?: string;
  readonly verificationStateAfter?: string;
  readonly evidenceId?: string;
}

export interface AttackExecutionRecordDto {
  readonly executionId: string;
  readonly planId: string;
  readonly assessmentId: string;
  readonly capability: AttackCapabilityKind;
  readonly status: 'completed' | 'preflight_denied' | 'failed';
  readonly stepRecords: readonly AttackStepExecutionDto[];
  readonly updatedFindingStates: readonly {
    readonly id: string;
    readonly verificationState: string;
  }[];
}

export type ImpactLevel =
  | 'information_exposure'
  | 'authentication_bypass'
  | 'authorization_bypass'
  | 'data_access'
  | 'privilege_escalation'
  | 'lateral_movement'
  | 'rce_demonstrated';

export type ChainObjectiveKind =
  | 'data_access'
  | 'authentication_bypass'
  | 'privilege_escalation'
  | 'lateral_movement'
  | 'information_disclosure';

export type AttackChainStatus =
  | 'hypothesis'
  | 'partially_validated'
  | 'fully_validated'
  | 'refuted'
  | 'abandoned';

export type AttackChainStepOutcome = 'succeeded' | 'refuted' | 'failed';

export interface AttackChainStepEvidence {
  readonly evidenceId?: string;
  readonly reasonCode: string;
  readonly safeMessage: string;
  readonly recordedAt: string;
}

export interface AttackChainStep {
  readonly stepId: string;
  readonly sequence: number;
  readonly capabilityKind: AttackCapabilityKind;
  readonly epistemicStatus: EpistemicStatus;
  readonly evidence: AttackChainStepEvidence;
  readonly capabilityGained: CapabilityGained;
  readonly outcome: AttackChainStepOutcome;
  readonly sourceStepId?: string;
}

export interface AttackChain {
  readonly contractVersion: 'fixguard-attack-chain/v0';
  readonly kind: 'attack_chain';
  readonly chainId: string;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly hypothesis: string;
  readonly objectiveKind: ChainObjectiveKind;
  readonly steps: readonly AttackChainStep[];
  readonly overallEpistemicStatus: EpistemicStatus;
  readonly status: AttackChainStatus;
  readonly impactLevel: ImpactLevel;
  readonly declaredImpactLevel: ImpactLevel;
  readonly lineage: LineageTuple;
  readonly createdAt: string;
  readonly completedAt?: string;
}

export interface GetAttackChainsResponse {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly chainCount: number;
  readonly chains: readonly AttackChain[];
  readonly lineage: LineageTuple;
}

export type AcquiredAccessKind =
  | 'authenticated_session'
  | 'elevated_identity'
  | 'discovered_credential'
  | 'service_trust'
  | 'network_reachability';

export type CredentialKind =
  | 'session_cookie'
  | 'bearer_token'
  | 'api_key'
  | 'basic_auth'
  | 'oauth_refresh_token';

/** Opaque credential handle — MUST NEVER contain raw secret values. */
export interface CredentialReference {
  readonly contractVersion: 'fixguard-post-exploitation/v0';
  readonly kind: 'credential_reference';
  readonly credentialId: string;
  readonly credentialKind: CredentialKind;
  readonly source: string;
  readonly associatedHostname?: string;
  readonly discoveredAt: string;
  readonly expiresAt?: string;
}

export interface AcquiredAccess {
  readonly contractVersion: 'fixguard-post-exploitation/v0';
  readonly kind: 'acquired_access';
  readonly accessId: string;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly accessKind: AcquiredAccessKind;
  readonly description: string;
  readonly epistemicStatus: EpistemicStatus;
  readonly sourceStepId: string;
  readonly sourceChainId: string;
  readonly credentialRefId?: string;
  readonly identityContext?: string;
  readonly newlyReachableTargets: readonly string[];
  readonly acquiredAt: string;
}

export interface LateralMovementHypothesis {
  readonly contractVersion: 'fixguard-post-exploitation/v0';
  readonly kind: 'lateral_movement_hypothesis';
  readonly hypothesisId: string;
  readonly mechanism: string;
  readonly targetHost: string;
  readonly credentialRefId?: string;
  readonly epistemicStatus: 'INFERRED';
  readonly discoveredInStepId: string;
  readonly discoveredAt: string;
}

export interface PostExploitationState {
  readonly contractVersion: 'fixguard-post-exploitation/v0';
  readonly kind: 'post_exploitation_state';
  readonly assessmentId: string;
  readonly scanId: string;
  readonly acquiredAccess: readonly AcquiredAccess[];
  readonly lateralMovementHypotheses: readonly LateralMovementHypothesis[];
  readonly updatedAt: string;
}

export interface GetPostExploitationResponse {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly state: PostExploitationState | null;
  readonly lineage: LineageTuple;
}

export type LateralMovementMechanism =
  | 'credential_reuse'
  | 'session_token_reuse'
  | 'api_key_reuse'
  | 'oauth_token_scope'
  | 'shared_auth_backend'
  | 'cors_credential_relay'
  | 'trust_relationship'
  | 'subdomain_session_share';

export interface DiscoveredReachableHost {
  readonly contractVersion: 'fixguard-lateral-movement/v0';
  readonly kind: 'discovered_reachable_host';
  readonly hostname: string;
  readonly discoveredInStepId: string;
  readonly inScope: false;
  readonly discoveredAt: string;
}

export interface AuthorizedLateralTarget {
  readonly contractVersion: 'fixguard-lateral-movement/v0';
  readonly kind: 'authorized_lateral_target';
  readonly hostname: string;
  readonly scopeGrantId: string;
  readonly authorizedAt: string;
  readonly authorizedBy: string;
}

export interface ActuallyAccessedTarget {
  readonly contractVersion: 'fixguard-lateral-movement/v0';
  readonly kind: 'actually_accessed_target';
  readonly hostname: string;
  readonly evidenceId: string;
  readonly epistemicStatus: 'VERIFIED';
  readonly accessedAt: string;
}

export interface SuccessfullyPivotedTarget {
  readonly contractVersion: 'fixguard-lateral-movement/v0';
  readonly kind: 'successfully_pivoted_target';
  readonly hostname: string;
  readonly capabilityGained: CapabilityGained;
  readonly epistemicStatus: 'VERIFIED';
  readonly pivotedAt: string;
}

export interface AttackEvidence {
  readonly evidenceId: string;
  readonly reasonCode: string;
  readonly safeMessage: string;
  readonly recordedAt: string;
}

export type LateralMovementRecordStatus =
  | 'pivot_complete'
  | 'access_confirmed'
  | 'access_denied'
  | 'unauthorized';

export interface LateralMovementRecord {
  readonly contractVersion: 'fixguard-lateral-movement/v0';
  readonly kind: 'lateral_movement_record';
  readonly recordId: string;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly mechanism: LateralMovementMechanism;
  readonly sourceHost: string;
  readonly destinationHost: string;
  readonly credentialRefId?: string;
  readonly status: LateralMovementRecordStatus;
  readonly lineage: LineageTuple;
  readonly evidence: readonly AttackEvidence[];
  readonly recordedAt: string;
}

export interface LateralMovementSnapshot {
  readonly contractVersion: 'fixguard-lateral-movement/v0';
  readonly kind: 'lateral_movement_snapshot';
  readonly assessmentId: string;
  readonly scanId: string;
  readonly discoveredHosts: readonly DiscoveredReachableHost[];
  readonly authorizedTargets: readonly AuthorizedLateralTarget[];
  readonly accessedTargets: readonly ActuallyAccessedTarget[];
  readonly pivotedTargets: readonly SuccessfullyPivotedTarget[];
  readonly records: readonly LateralMovementRecord[];
  readonly updatedAt: string;
}

export interface GetLateralMovementResponse {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly snapshot: LateralMovementSnapshot | null;
  readonly lineage: LineageTuple;
}

export interface ImpactAssessment {
  readonly contractVersion: 'fixguard-impact-assessment/v0';
  readonly kind: 'impact_assessment';
  readonly assessmentId: string;
  readonly chainId: string;
  readonly impactLevel: ImpactLevel;
  readonly impactDescription: string;
  readonly evidenceBasis: readonly string[];
  readonly epistemicStatus: EpistemicStatus;
  readonly assessedAt: string;
}

export interface GetImpactAssessmentsResponse {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly impactCount: number;
  readonly impactAssessments: readonly ImpactAssessment[];
  readonly lineage: LineageTuple;
}

export interface AttackModeRefreshDto {
  readonly attackChains: readonly AttackChain[];
  readonly postExploitationState: PostExploitationState | null;
  readonly lateralMovementSnapshot: LateralMovementSnapshot | null;
  readonly impactAssessments: readonly ImpactAssessment[];
}

export interface ExecuteAttackPlanParams {
  readonly operatorId: string;
  readonly scopeGrant: AuthorizedScopeGrantDto;
  readonly findings?: readonly { readonly id: string; readonly verificationState: string }[];
  readonly dnsAnswers?: readonly string[];
  readonly primaryIdentity?: { readonly identityId: string; readonly headers?: Record<string, string> };
  readonly secondaryIdentity?: { readonly identityId: string; readonly headers?: Record<string, string> };
}

export interface ExecuteAttackPlanResponse {
  readonly status: 'completed' | 'preflight_denied' | 'failed';
  readonly reasonCode: string;
  readonly record: AttackExecutionRecordDto;
  readonly refresh?: AttackModeRefreshDto;
}

/** Minimal closed-world scope grant DTO for execute / lateral writes. */
export interface AuthorizedScopeGrantDto {
  readonly contractVersion: 'fixguard-authorized-scope-policy/v0';
  readonly kind: 'authorized_scope_grant';
  readonly grantId: string;
  readonly scanId: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly subject: {
    readonly targetKind: 'origin' | 'host' | 'domain';
    readonly normalizedOrigin?: string;
    readonly host?: string;
    readonly domain?: string;
  };
  readonly authorizationBasis: {
    readonly basisKind:
      | 'user_attestation'
      | 'contract_reference'
      | 'internal_asset_record'
      | 'external_verification_record';
    readonly referenceId?: string;
    readonly recordedBy: 'human_user' | 'system_import';
    readonly authorizationText: string;
  };
  readonly permissionSet: {
    readonly passiveRecon: boolean;
    readonly technologyFingerprinting: boolean;
    readonly endpointDiscovery: boolean;
    readonly activeCrawling: boolean;
    readonly authenticatedTesting: boolean;
    readonly lightValidation: boolean;
    readonly activeValidation: boolean;
    readonly aggressiveValidation: boolean;
    readonly oobTesting: boolean;
    readonly destructiveOperations: false;
  };
  readonly boundaries: {
    readonly allowedOrigins?: readonly string[];
    readonly allowedHosts?: readonly string[];
    readonly allowedDomains?: readonly string[];
    readonly allowedPathPatterns?: readonly { readonly match: 'exact' | 'prefix'; readonly pathTemplate: string }[];
    readonly deniedPathPatterns?: readonly { readonly match: 'exact' | 'prefix'; readonly pathTemplate: string }[];
    readonly allowedMethods?: readonly string[];
    readonly deniedMethods?: readonly string[];
  };
  readonly constraints: {
    readonly maxRequestsPerMinute?: number;
    readonly maxDepth?: number;
    readonly maxRuntimeSeconds?: number;
    readonly allowLoginRequiredAreas: boolean;
    readonly allowStateChangingRequests: boolean;
    readonly allowCredentialUse: boolean;
    readonly allowOobCallbacks: boolean;
    readonly allowThirdPartyTargets: false;
    readonly notes?: string;
  };
  readonly classification: {
    readonly createsRealFindings: false;
    readonly createsPersistedEvidence: false;
    readonly confirmsVulnerabilities: false;
    readonly makesRiskClaims: false;
    readonly makesSeverityClaims: false;
    readonly makesImpactClaims: false;
    readonly executesNetwork: false;
    readonly executesTools: false;
    readonly persistsData: false;
  };
}

export interface PromoteLateralTargetParams {
  readonly hostname: string;
  readonly operatorId: string;
  readonly scopeGrant: AuthorizedScopeGrantDto;
  readonly authorizedAt?: string;
}

export interface PromoteLateralTargetResponse {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly target: AuthorizedLateralTarget;
  readonly snapshot: LateralMovementSnapshot;
  readonly lineage: LineageTuple;
}

export interface EvaluateCredentialReuseParams {
  readonly planId: string;
  readonly sourceHost: string;
  readonly destinationHost: string;
  readonly mechanism: LateralMovementMechanism;
  readonly credentialRefId: string;
  readonly operatorId: string;
  readonly scopeGrant: AuthorizedScopeGrantDto;
  readonly targetUrl?: string;
  readonly recordedAt?: string;
}

export interface EvaluateCredentialReuseResponse {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly status: 'access_confirmed' | 'access_denied' | 'unauthorized';
  readonly networkDispatched: boolean;
  readonly record: LateralMovementRecord;
  readonly snapshot: LateralMovementSnapshot;
  readonly lineage: LineageTuple;
}

export type { LineageTuple } from './v2Api';
export { V2ApiError };

export const AUTHORIZABLE_BLAST_RADIUS_CLASSES: readonly AuthorizableBlastRadiusClass[] = [
  'read_public',
  'read_authenticated',
  'read_escalated',
  'sensitive_data_access',
  'credential_use',
  'privilege_escalation',
  'lateral_movement',
  'state_change_benign',
  'state_change_impact',
] as const;

/**
 * Suggest an authorizable blast-radius class from plan capability.
 * Operator must still confirm — never auto-seals a brand.
 */
export function suggestBlastRadiusForCapability(
  capability: AttackCapabilityKind
): AuthorizableBlastRadiusClass {
  switch (capability) {
    case 'parameter_reflection_probe':
    case 'nuclei_xss_scan':
      return 'read_public';
    case 'session_fixation_probe':
    case 'method_manipulation_probe':
      return 'read_authenticated';
    case 'idor_read_differential':
    case 'cors_chain_exploit':
      return 'read_escalated';
    case 'sql_error_oracle_probe':
    case 'sql_oracle_advancement':
    case 'sql_injection_verification':
    case 'lfi_path_traversal':
      return 'sensitive_data_access';
    case 'credential_reuse':
      return 'credential_use';
    case 'auth_bypass_probe':
    case 'jwt_alg_none_probe':
      return 'privilege_escalation';
    default: {
      const _exhaustive: never = capability;
      return _exhaustive;
    }
  }
}

export function formatEpistemicBadge(status: EpistemicStatus): string {
  switch (status) {
    case 'VERIFIED':
      return '[VERIFIED]';
    case 'INFERRED':
      return '[INFERRED - NOT VERIFIED]';
    case 'REFUTED':
      return '[REFUTED - TARGET RESISTED]';
    case 'OBSERVED':
      return '[OBSERVED]';
    default: {
      const _exhaustive: never = status;
      return _exhaustive;
    }
  }
}

/**
 * Build a workbench AuthorizedScopeGrant from assessment lineage + target domain.
 * Single-operator convenience — never invents secrets.
 */
export function buildWorkbenchScopeGrant(params: {
  readonly grantId: string;
  readonly scanId: string;
  readonly targetDomain: string;
  readonly extraHosts?: readonly string[];
  readonly allowCredentialUse?: boolean;
}): AuthorizedScopeGrantDto {
  const now = new Date();
  const expires = new Date(now.getTime() + 3600_000);
  const domain = params.targetDomain.trim().toLowerCase();
  const hosts = Array.from(
    new Set([domain, ...(params.extraHosts ?? []).map((h) => h.trim().toLowerCase()).filter(Boolean)])
  );

  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: params.grantId,
    scanId: params.scanId,
    issuedAt: now.toISOString(),
    expiresAt: expires.toISOString(),
    subject: {
      targetKind: 'domain',
      domain,
    },
    authorizationBasis: {
      basisKind: 'user_attestation',
      recordedBy: 'human_user',
      authorizationText: `Operator-attested Attack Mode scope for ${domain}`,
    },
    permissionSet: {
      passiveRecon: true,
      technologyFingerprinting: true,
      endpointDiscovery: true,
      activeCrawling: true,
      authenticatedTesting: true,
      lightValidation: true,
      activeValidation: true,
      aggressiveValidation: false,
      oobTesting: false,
      destructiveOperations: false,
    },
    boundaries: {
      allowedDomains: [domain],
      allowedHosts: hosts,
      allowedOrigins: [`https://${domain}`, `http://${domain}`],
      allowedMethods: ['GET', 'HEAD', 'OPTIONS'],
    },
    constraints: {
      allowLoginRequiredAreas: true,
      allowStateChangingRequests: false,
      allowCredentialUse: params.allowCredentialUse ?? true,
      allowOobCallbacks: false,
      allowThirdPartyTargets: false,
    },
    classification: {
      createsRealFindings: false,
      createsPersistedEvidence: false,
      confirmsVulnerabilities: false,
      makesRiskClaims: false,
      makesSeverityClaims: false,
      makesImpactClaims: false,
      executesNetwork: false,
      executesTools: false,
      persistsData: false,
    },
  };
}

export class V2AttackApiClient {
  private readonly baseUrl: string;
  private readonly apiSecret?: string;

  constructor(config?: V2ApiClientConfig) {
    this.baseUrl = config?.baseUrl ?? process.env.NEXT_PUBLIC_V2_API_URL ?? '/api/v2';
    this.apiSecret = config?.apiSecret ?? process.env.FIXGUARD_API_SECRET;
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const url = `${this.baseUrl}${path.startsWith('/') ? path : `/${path}`}`;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    };

    if (this.apiSecret) {
      headers['Authorization'] = `Bearer ${this.apiSecret}`;
    }

    if (options.headers) {
      const customHeaders = options.headers as Record<string, string>;
      for (const [key, value] of Object.entries(customHeaders)) {
        headers[key] = value;
      }
    }

    const res = await fetch(url, { ...options, headers });
    if (!res.ok) {
      let errorType = 'HttpError';
      let message = `HTTP ${res.status} ${res.statusText}`;
      let reasonCode: string | undefined;

      try {
        const body = (await res.json()) as Record<string, unknown>;
        if (typeof body.error === 'string') errorType = body.error;
        if (typeof body.message === 'string') message = body.message;
        if (typeof body.reasonCode === 'string') reasonCode = body.reasonCode;
      } catch {
        // Non-JSON response
      }

      throw new V2ApiError(res.status, errorType, message, reasonCode);
    }

    return (await res.json()) as T;
  }

  /** GET /api/v2/assessments/:assessmentId/attack-plans */
  public async getAttackPlans(assessmentId: string): Promise<GetAttackPlansResponse> {
    return this.request<GetAttackPlansResponse>(
      `/assessments/${encodeURIComponent(assessmentId)}/attack-plans`
    );
  }

  /**
   * POST /api/v2/assessments/:assessmentId/attack-plans/:planId/authorize
   * Seals a server-side WeakSet-branded token. Response token DTO is safe metadata only.
   */
  public async authorizeAttackPlan(
    assessmentId: string,
    planId: string,
    params: AuthorizeAttackPlanParams
  ): Promise<AuthorizeAttackPlanResponse> {
    const body: Record<string, string> = {
      operatorId: params.operatorId,
      blastRadiusClass: params.blastRadiusClass,
    };
    if (params.authorizedAt) {
      body.authorizedAt = params.authorizedAt;
    }

    return this.request<AuthorizeAttackPlanResponse>(
      `/assessments/${encodeURIComponent(assessmentId)}/attack-plans/${encodeURIComponent(planId)}/authorize`,
      {
        method: 'POST',
        body: JSON.stringify(body),
      }
    );
  }

  /**
   * POST /api/v2/assessments/:assessmentId/attack-plans/:planId/execute
   * Requires prior in-process authorize (WeakSet brand). Token never sent from client.
   */
  public async executeAttackPlan(
    assessmentId: string,
    planId: string,
    params: ExecuteAttackPlanParams
  ): Promise<ExecuteAttackPlanResponse> {
    const body: Record<string, unknown> = {
      operatorId: params.operatorId,
      scopeGrant: params.scopeGrant,
    };
    if (params.findings !== undefined) body.findings = params.findings;
    if (params.dnsAnswers !== undefined) body.dnsAnswers = params.dnsAnswers;
    if (params.primaryIdentity !== undefined) body.primaryIdentity = params.primaryIdentity;
    if (params.secondaryIdentity !== undefined) body.secondaryIdentity = params.secondaryIdentity;

    return this.request<ExecuteAttackPlanResponse>(
      `/assessments/${encodeURIComponent(assessmentId)}/attack-plans/${encodeURIComponent(planId)}/execute`,
      {
        method: 'POST',
        body: JSON.stringify(body),
      }
    );
  }

  /** GET /api/v2/assessments/:assessmentId/attack-chains */
  public async getAttackChains(assessmentId: string): Promise<GetAttackChainsResponse> {
    return this.request<GetAttackChainsResponse>(
      `/assessments/${encodeURIComponent(assessmentId)}/attack-chains`
    );
  }

  /** GET /api/v2/assessments/:assessmentId/post-exploitation */
  public async getPostExploitation(assessmentId: string): Promise<GetPostExploitationResponse> {
    return this.request<GetPostExploitationResponse>(
      `/assessments/${encodeURIComponent(assessmentId)}/post-exploitation`
    );
  }

  /** GET /api/v2/assessments/:assessmentId/lateral-movement */
  public async getLateralMovement(assessmentId: string): Promise<GetLateralMovementResponse> {
    return this.request<GetLateralMovementResponse>(
      `/assessments/${encodeURIComponent(assessmentId)}/lateral-movement`
    );
  }

  /** GET /api/v2/assessments/:assessmentId/impact */
  public async getImpactAssessments(assessmentId: string): Promise<GetImpactAssessmentsResponse> {
    return this.request<GetImpactAssessmentsResponse>(
      `/assessments/${encodeURIComponent(assessmentId)}/impact`
    );
  }

  /** POST /api/v2/assessments/:assessmentId/lateral-movement/promote-to-authorized-target */
  public async promoteLateralTarget(
    assessmentId: string,
    params: PromoteLateralTargetParams
  ): Promise<PromoteLateralTargetResponse> {
    const body: Record<string, unknown> = {
      hostname: params.hostname,
      operatorId: params.operatorId,
      scopeGrant: params.scopeGrant,
    };
    if (params.authorizedAt) body.authorizedAt = params.authorizedAt;

    return this.request<PromoteLateralTargetResponse>(
      `/assessments/${encodeURIComponent(assessmentId)}/lateral-movement/promote-to-authorized-target`,
      {
        method: 'POST',
        body: JSON.stringify(body),
      }
    );
  }

  /**
   * POST /api/v2/assessments/:assessmentId/lateral-movement/evaluate-credential-reuse
   * credentialRefId only — never raw secrets. Requires prior authorize on planId.
   */
  public async evaluateCredentialReuse(
    assessmentId: string,
    params: EvaluateCredentialReuseParams
  ): Promise<EvaluateCredentialReuseResponse> {
    const body: Record<string, unknown> = {
      planId: params.planId,
      sourceHost: params.sourceHost,
      destinationHost: params.destinationHost,
      mechanism: params.mechanism,
      credentialRefId: params.credentialRefId,
      operatorId: params.operatorId,
      scopeGrant: params.scopeGrant,
    };
    if (params.targetUrl) body.targetUrl = params.targetUrl;
    if (params.recordedAt) body.recordedAt = params.recordedAt;

    return this.request<EvaluateCredentialReuseResponse>(
      `/assessments/${encodeURIComponent(assessmentId)}/lateral-movement/evaluate-credential-reuse`,
      {
        method: 'POST',
        body: JSON.stringify(body),
      }
    );
  }
}

export const v2AttackApi = new V2AttackApiClient();
