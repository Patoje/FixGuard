/**
 * FixGuard V2 — Web Frontend API Client (Orchestrated Assessments)
 *
 * Provides typed, Bearer-authenticated client functions for invoking the
 * FixGuard V2 Orchestrated Assessment Gateway from Next.js.
 *
 * Strictly adheres to zero type bypass policy and strict closed typing.
 */

export interface LineageTuple {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
}

export interface StageResultDto {
  readonly stage: string;
  readonly status: 'success' | 'partial_failure' | 'failed' | 'skipped';
  readonly observationsCount: number;
  readonly durationMs: number;
  readonly warnings: readonly string[];
  readonly error?: string;
}

export interface FindingDto {
  readonly id: string;
  readonly type: string;
  readonly severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  readonly title: string;
  readonly target: string;
  readonly evidence: string;
  readonly line: number;
  readonly timestamp: string;
  readonly hash: string;
}

export interface RecommendationDto {
  readonly id: string;
  readonly category: string;
  readonly title: string;
  readonly reasoning: string;
  readonly suggestedCapability: string;
  readonly requiredPermissions: readonly string[];
  readonly confidence: number;
  readonly severity: string;
}

export interface ProfileEndpointDto {
  readonly url: string;
  readonly method: string;
  readonly path: string;
  readonly parameters: readonly string[];
  readonly authRequirement: 'none' | 'session' | 'token' | 'unknown';
}

export interface FlawContextDto {
  readonly endpoint: string;
  readonly flawType: string;
  readonly parameter?: string;
  readonly severity: string;
}

export interface TargetProfileDto {
  readonly targetHost: string;
  readonly normalizedOrigin: string;
  readonly updatedAt: string;
  readonly technologies: readonly string[];
  readonly endpoints: readonly ProfileEndpointDto[];
  readonly findings: readonly FindingDto[];
  readonly flawContexts: readonly FlawContextDto[];
  readonly lineage: LineageTuple;
}

export interface TimingDto {
  readonly startedAt: string;
  readonly completedAt?: string;
  readonly durationMs?: number;
}

export interface StartOrchestratedAssessmentParams {
  readonly targetDomain: string;
  readonly actorId?: string;
  readonly config?: {
    readonly skipStages?: readonly string[];
    readonly timeoutPerStageMs?: number;
  };
}

export interface StartOrchestratedAssessmentResponse {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly status: 'running';
  readonly lineage: LineageTuple;
}

export interface OrchestratedAssessmentStatusResponse {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly targetDomain: string;
  readonly status: 'pending' | 'running' | 'completed' | 'failed' | 'preflight_denied' | 'circuit_broken';
  readonly stages: readonly StageResultDto[];
  readonly timing: TimingDto;
  readonly errorCount: number;
  readonly warningCount: number;
  readonly lineage: LineageTuple;
  readonly pendingEvidenceDraftCount?: number;
  readonly error?: string;
}

export interface DifferentialEvidenceContextDto {
  readonly endpointUrl: string;
  readonly detectionKind: 'cors_misconfiguration' | 'parameter_reflection' | 'idor_access_control' | 'missing_security_headers' | 'open_redirect' | 'custom_difference';
  readonly baselineStatusCode?: number;
  readonly baselineBodyHash?: string;
  readonly validationStatusCode?: number;
  readonly validationBodyHash?: string;
  readonly reflectedOrigin?: string;
  readonly allowCredentials?: boolean;
  readonly parameterName?: string;
  readonly reflectedCanary?: string;
  readonly resourceParamName?: string;
  readonly baselineResourceId?: string;
  readonly missingHeaders?: readonly string[];
  readonly presentHeaders?: readonly string[];
  readonly injectedCanary?: string;
  readonly finalDestination?: string;
  readonly redirectChain?: readonly string[];
}

export interface EvidenceDraftDto {
  readonly draftKind: string;
  readonly draftId: string;
  readonly suggestedEvidenceType: string;
  readonly suggestedStrength: string;
  readonly sourceComparisonId: string;
  readonly sourceSnapshotIds: {
    readonly baselineSnapshotId: string;
    readonly validationSnapshotId: string;
  };
  readonly requiresHumanReview: true;
  readonly safeRationale: string;
  readonly differentialContext?: DifferentialEvidenceContextDto;
}

export interface GetEvidenceDraftsResponse {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly draftCount: number;
  readonly drafts: readonly EvidenceDraftDto[];
}

export interface ReviewEvidenceDraftParams {
  readonly decision: 'approve_evidence' | 'reject_evidence';
  readonly reviewerId: string;
  readonly reviewedAt: string;
  readonly notes?: string;
}

export interface ReviewEvidenceDraftResponse {
  readonly assessmentId: string;
  readonly draftId: string;
  readonly decision: 'approve_evidence' | 'reject_evidence';
  readonly reviewerId: string;
  readonly reviewedAt: string;
  readonly findingCreated?: FindingDto;
  readonly remainingDraftCount: number;
}

export interface OrchestratedAssessmentSummaryResponse {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly targetDomain: string;
  readonly status: 'pending' | 'running' | 'completed' | 'failed' | 'preflight_denied' | 'circuit_broken';
  readonly profile?: TargetProfileDto;
  readonly findings: readonly FindingDto[];
  readonly pendingEvidenceDrafts?: readonly EvidenceDraftDto[];
  readonly recommendations: readonly RecommendationDto[];
  readonly lineage: LineageTuple;
  readonly timing: TimingDto;
  readonly error?: string;
}

export interface V2ApiClientConfig {
  readonly baseUrl?: string;
  readonly apiSecret?: string;
}

export class V2ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly errorType: string,
    message: string,
    public readonly reasonCode?: string
  ) {
    super(message);
    this.name = 'V2ApiError';
  }
}

export class V2OrchestratedApiClient {
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

  /**
   * Dispatches an authenticated orchestrated assessment.
   * POST /api/v2/orchestrated/assessments/start
   */
  public async startAssessment(
    params: StartOrchestratedAssessmentParams
  ): Promise<StartOrchestratedAssessmentResponse> {
    return this.request<StartOrchestratedAssessmentResponse>('/orchestrated/assessments/start', {
      method: 'POST',
      body: JSON.stringify(params),
    });
  }

  /**
   * Retrieves status, stage results, and error counts for an orchestrated assessment.
   * GET /api/v2/orchestrated/assessments/:assessmentId/status
   */
  public async getStatus(
    assessmentId: string
  ): Promise<OrchestratedAssessmentStatusResponse> {
    return this.request<OrchestratedAssessmentStatusResponse>(
      `/orchestrated/assessments/${encodeURIComponent(assessmentId)}/status`
    );
  }

  /**
   * Retrieves summary, profile, findings, and recommendations for an orchestrated assessment.
   * GET /api/v2/orchestrated/assessments/:assessmentId/summary
   */
  public async getSummary(
    assessmentId: string
  ): Promise<OrchestratedAssessmentSummaryResponse> {
    return this.request<OrchestratedAssessmentSummaryResponse>(
      `/orchestrated/assessments/${encodeURIComponent(assessmentId)}/summary`
    );
  }

  /**
   * Retrieves pending evidence drafts with differential context for human triage.
   * GET /api/v2/orchestrated/assessments/:assessmentId/evidence-drafts
   */
  public async getEvidenceDrafts(
    assessmentId: string
  ): Promise<GetEvidenceDraftsResponse> {
    return this.request<GetEvidenceDraftsResponse>(
      `/orchestrated/assessments/${encodeURIComponent(assessmentId)}/evidence-drafts`
    );
  }

  /**
   * Submits a formal human review decision for an evidence draft.
   * POST /api/v2/orchestrated/assessments/:assessmentId/evidence/:draftId/review
   */
  public async reviewEvidenceDraft(
    assessmentId: string,
    draftId: string,
    params: ReviewEvidenceDraftParams
  ): Promise<ReviewEvidenceDraftResponse> {
    return this.request<ReviewEvidenceDraftResponse>(
      `/orchestrated/assessments/${encodeURIComponent(assessmentId)}/evidence/${encodeURIComponent(draftId)}/review`,
      {
        method: 'POST',
        body: JSON.stringify(params),
      }
    );
  }
}

export const v2OrchestratedApi = new V2OrchestratedApiClient();

export async function startOrchestratedAssessment(
  params: StartOrchestratedAssessmentParams,
  config?: V2ApiClientConfig
): Promise<StartOrchestratedAssessmentResponse> {
  const client = config ? new V2OrchestratedApiClient(config) : v2OrchestratedApi;
  return client.startAssessment(params);
}

export async function getOrchestratedAssessmentStatus(
  assessmentId: string,
  config?: V2ApiClientConfig
): Promise<OrchestratedAssessmentStatusResponse> {
  const client = config ? new V2OrchestratedApiClient(config) : v2OrchestratedApi;
  return client.getStatus(assessmentId);
}

export async function getOrchestratedAssessmentSummary(
  assessmentId: string,
  config?: V2ApiClientConfig
): Promise<OrchestratedAssessmentSummaryResponse> {
  const client = config ? new V2OrchestratedApiClient(config) : v2OrchestratedApi;
  return client.getSummary(assessmentId);
}

export async function getEvidenceDrafts(
  assessmentId: string,
  config?: V2ApiClientConfig
): Promise<GetEvidenceDraftsResponse> {
  const client = config ? new V2OrchestratedApiClient(config) : v2OrchestratedApi;
  return client.getEvidenceDrafts(assessmentId);
}

export async function reviewEvidenceDraft(
  assessmentId: string,
  draftId: string,
  params: ReviewEvidenceDraftParams,
  config?: V2ApiClientConfig
): Promise<ReviewEvidenceDraftResponse> {
  const client = config ? new V2OrchestratedApiClient(config) : v2OrchestratedApi;
  return client.reviewEvidenceDraft(assessmentId, draftId, params);
}

