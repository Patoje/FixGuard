/**
 * FixGuard V2 API Gateway HTTP Client
 *
 * Consumes the dedicated V2 Express 5 Gateway (/api/v2).
 * Strictly communicates via HTTP without referencing any V1 monolith code or database layers.
 */

import type {
  AssessmentSummaryDto,
  AssessmentDetailsDto,
  ListEvidenceDraftsResponse,
  PromoteCandidateParams,
  PromoteCandidateResponse,
  GenerateReportParams,
  DefensiveAssessmentReportDto,
  SafeErrorResponseBody
} from './types';
import { isStrictSafeId, isValidTargetUri } from './idGenerator';

export class V2ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly errorType: string,
    message: string,
    public readonly conflictKey?: string,
    public readonly sessionId?: string,
    public readonly recordId?: string
  ) {
    super(message);
    this.name = 'V2ApiError';
  }
}

export class FixGuardV2ApiClient {
  private readonly baseUrl: string;

  constructor(baseUrl?: string) {
    // Default to /api/v2 (proxied by Next.js rewrites) or explicit env variable
    this.baseUrl = baseUrl || process.env.NEXT_PUBLIC_V2_API_URL || '/api/v2';
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const url = `${this.baseUrl}${path.startsWith('/') ? path : `/${path}`}`;
    const headers = {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      ...options.headers
    };

    let response: Response;
    try {
      response = await fetch(url, { ...options, headers });
    } catch (networkErr) {
      throw new V2ApiError(
        0,
        'NetworkError',
        `Failed to communicate with V2 API Gateway: ${(networkErr as Error).message}`
      );
    }

    if (!response.ok) {
      let safeError: SafeErrorResponseBody = {
        error: 'HttpError',
        message: `HTTP ${response.status} ${response.statusText}`
      };

      try {
        const errorJson = (await response.json()) as SafeErrorResponseBody;
        if (errorJson && typeof errorJson.error === 'string') {
          safeError = errorJson;
        }
      } catch {
        // Response was not JSON
      }

      throw new V2ApiError(
        response.status,
        safeError.error,
        safeError.message,
        safeError.conflictKey,
        safeError.sessionId,
        safeError.recordId
      );
    }

    return (await response.json()) as T;
  }

  /**
   * Stage 1: Create a new defensive assessment session
   * POST /api/v2/assessments
   */
  async createAssessment(targetUri: string): Promise<AssessmentSummaryDto> {
    if (!isValidTargetUri(targetUri)) {
      throw new V2ApiError(400, 'ValidationError', 'Target URI must be a valid http: or https: URL');
    }

    return this.request<AssessmentSummaryDto>('/assessments', {
      method: 'POST',
      body: JSON.stringify({ targetUri })
    });
  }

  /**
   * Stage 2: Retrieve full assessment details by sessionId
   * GET /api/v2/assessments/:sessionId
   */
  async getAssessment(sessionId: string): Promise<AssessmentDetailsDto> {
    if (!isStrictSafeId(sessionId)) {
      throw new V2ApiError(400, 'ValidationError', 'Invalid sessionId format');
    }

    return this.request<AssessmentDetailsDto>(`/assessments/${sessionId}`);
  }

  /**
   * Stage 2: Trigger initial active reconnaissance
   * POST /api/v2/assessments/:sessionId/recon
   */
  async triggerRecon(sessionId: string): Promise<AssessmentDetailsDto> {
    if (!isStrictSafeId(sessionId)) {
      throw new V2ApiError(400, 'ValidationError', 'Invalid sessionId format');
    }

    return this.request<AssessmentDetailsDto>(`/assessments/${sessionId}/recon`, {
      method: 'POST'
    });
  }

  /**
   * Stage 3: Fetch authentic unreviewed evidence drafts by scanId
   * GET /api/v2/scans/:scanId/evidence-drafts
   */
  async listEvidenceDrafts(scanId: string): Promise<ListEvidenceDraftsResponse> {
    if (!isStrictSafeId(scanId)) {
      throw new V2ApiError(400, 'ValidationError', 'Invalid scanId format');
    }

    return this.request<ListEvidenceDraftsResponse>(`/scans/${scanId}/evidence-drafts`);
  }

  /**
   * Stage 3: Promote reviewed evidence draft to formal finding candidate (HITL)
   * POST /api/v2/candidates/promote
   *
   * ANTI-FABRICATION INVARIANT:
   * Only identifier and human reviewer metadata are sent.
   * Client NEVER sends draft body.
   */
  async promoteCandidate(payload: PromoteCandidateParams): Promise<PromoteCandidateResponse> {
    if (!isStrictSafeId(payload.candidateId)) {
      throw new V2ApiError(400, 'ValidationError', 'Invalid candidateId format');
    }
    if (!isStrictSafeId(payload.scanId)) {
      throw new V2ApiError(400, 'ValidationError', 'Invalid scanId format');
    }
    if (!isStrictSafeId(payload.draftId)) {
      throw new V2ApiError(400, 'ValidationError', 'Invalid draftId format');
    }
    if (!isStrictSafeId(payload.reviewerId)) {
      throw new V2ApiError(400, 'ValidationError', 'Invalid reviewerId format');
    }
    if (!isStrictSafeId(payload.triageDecisionId)) {
      throw new V2ApiError(400, 'ValidationError', 'Invalid triageDecisionId format');
    }

    // Exact closed-world payload construction
    const exactBody = {
      candidateId: payload.candidateId,
      scanId: payload.scanId,
      draftId: payload.draftId,
      reviewerId: payload.reviewerId,
      triageDecisionId: payload.triageDecisionId
    };

    return this.request<PromoteCandidateResponse>('/candidates/promote', {
      method: 'POST',
      body: JSON.stringify(exactBody)
    });
  }

  /**
   * Stage 4: Compile signed Defensive Assessment Report
   * POST /api/v2/reports
   */
  async generateReport(payload: GenerateReportParams): Promise<DefensiveAssessmentReportDto> {
    if (!isStrictSafeId(payload.reportId)) {
      throw new V2ApiError(400, 'ValidationError', 'Invalid reportId format');
    }
    if (!isStrictSafeId(payload.sessionId)) {
      throw new V2ApiError(400, 'ValidationError', 'Invalid sessionId format');
    }
    if (!isStrictSafeId(payload.scanId)) {
      throw new V2ApiError(400, 'ValidationError', 'Invalid scanId format');
    }
    if (!isStrictSafeId(payload.operatorSignatureId)) {
      throw new V2ApiError(400, 'ValidationError', 'Invalid operatorSignatureId format');
    }
    if (!payload.operatorAttestationText || payload.operatorAttestationText.trim().length < 10) {
      throw new V2ApiError(
        400,
        'ValidationError',
        'Operator attestation text must be at least 10 characters'
      );
    }

    const exactBody = {
      reportId: payload.reportId,
      sessionId: payload.sessionId,
      scanId: payload.scanId,
      requestedAt: payload.requestedAt,
      operatorSignatureId: payload.operatorSignatureId,
      operatorVerifiedAt: payload.operatorVerifiedAt,
      operatorAttestationText: payload.operatorAttestationText.trim()
    };

    return this.request<DefensiveAssessmentReportDto>('/reports', {
      method: 'POST',
      body: JSON.stringify(exactBody)
    });
  }
}

// Singleton default client
export const v2ApiClient = new FixGuardV2ApiClient();
