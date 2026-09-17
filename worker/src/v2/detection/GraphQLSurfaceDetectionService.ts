/**
 * Milestone P4-6 — GraphQL Surface Detection Engine
 *
 * Safe verification of modern GraphQL API interfaces:
 * - Probes candidate endpoints (/graphql, /api/graphql, /v1/graphql, /query, or custom paths).
 * - Probe 1: Schema Introspection (query { __schema { types { name } } }) -> extracts up to 20 root types.
 * - Probe 2: Field Suggestion Leakage (query { fixguard_invalid_probe }) -> extracts "Did you mean" suggestion excerpts.
 * - Probe 3: Query Batching Capability ([{query: "{ __typename }"}, {query: "{ __typename }"}]) -> checks array responses.
 *
 * Strict Invariants:
 * - Strictly read-only schema inspection (zero mutations or state-altering queries).
 * - 7-pass SSRF preflight protection.
 * - Sanitizes suggestion leaks with sanitizeEvidenceFragment() (max 128 chars).
 * - Clean abstention (secure_target_abstained) when GraphQL is absent, disabled, or hardened.
 * - HITL Routing: Unattended runs produce pending_human_review with EvidenceDraftEnvelope.
 */

import type {
  GraphQLSurfaceDetectionRequest,
  GraphQLSurfaceDetectionResult,
  IdorHttpProbeTransport,
  HttpProbeRequest,
  HttpProbeResponse,
} from './DetectionContracts.js';
import { DETECTION_CONTRACT_VERSION } from './DetectionContracts.js';
import { runAdapterPreflight } from '../recon/adapters/AdapterPreflightPipeline.js';
import type { Finding } from '../core/Evidence.js';
import type { EvidenceDraftEnvelope } from '../evidence-mapping/ComparisonEvidenceMappingContracts.js';
import { defaultHttpProbeTransport } from './IdorDifferentialDetectionService.js';
import { sanitizeEvidenceFragment } from '../core/EvidenceSanitizer.js';

function sanitizeToSafeId(raw: string): string {
  const cleaned = raw.replace(/[^A-Za-z0-9]/g, '').slice(0, 16);
  return cleaned.length > 0 ? cleaned : '001';
}

const DEFAULT_GRAPHQL_PATHS = ['/graphql', '/api/graphql', '/v1/graphql', '/query'] as const;

const SUGGESTION_PATTERNS = [
  /Did you mean ["']?([^"'?]+)["']?/i,
  /Cannot query field ["']?([^"']+)["']?/i,
  /Unknown field ["']?([^"']+)["']?/i,
  /Field '.*' doesn't exist on type/i,
];

function extractSuggestionLeak(bodyText: string): string | undefined {
  for (const pattern of SUGGESTION_PATTERNS) {
    const match = pattern.exec(bodyText);
    if (match) {
      const startIdx = Math.max(0, match.index - 5);
      const endIdx = Math.min(bodyText.length, match.index + match[0].length + 60);
      const rawExcerpt = bodyText.substring(startIdx, endIdx).replace(/\s+/g, ' ').trim();
      const sanitized = sanitizeEvidenceFragment(rawExcerpt);
      return sanitized.length > 128 ? `${sanitized.slice(0, 125)}...` : sanitized;
    }
  }
  return undefined;
}

export async function runGraphQLSurfaceDetection(
  request: GraphQLSurfaceDetectionRequest
): Promise<GraphQLSurfaceDetectionResult> {
  const lineage = {
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
  };

  const safeSeed = sanitizeToSafeId(request.detectionId);
  const nowIso = new Date().toISOString();
  const transport = request.transport ?? defaultHttpProbeTransport;

  // Determine candidate URLs to probe
  let candidateUrls: string[] = [];
  try {
    const parsed = new URL(request.endpointUrl);
    if (parsed.pathname.includes('/graphql') || parsed.pathname.includes('/query')) {
      candidateUrls = [request.endpointUrl];
    } else {
      const customPaths = request.customPaths && request.customPaths.length > 0
        ? request.customPaths
        : DEFAULT_GRAPHQL_PATHS;
      candidateUrls = customPaths.map((p) => {
        const urlObj = new URL(request.endpointUrl);
        urlObj.pathname = p.startsWith('/') ? p : `/${p}`;
        urlObj.search = '';
        return urlObj.toString();
      });
    }
  } catch {
    candidateUrls = [request.endpointUrl];
  }

  for (const candidateUrl of candidateUrls) {
    // 1. SSRF Preflight
    const preflight = await runAdapterPreflight({
      target: candidateUrl,
      targetKind: 'url',
      verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
      authorizedScopeGrant: request.scopeGrant,
      lineage,
      permissionCheck: (ps) => Boolean(ps.endpointDiscovery || ps.lightValidation || ps.activeValidation),
      dnsResolver: request.dnsResolver,
    });

    if (!preflight.ok) {
      return {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'graphql_surface_detection_result',
        detectionId: request.detectionId,
        scanId: request.scanId,
        assessmentId: request.assessmentId,
        authorizationGrantId: request.authorizationGrantId,
        authorizationDecisionId: request.authorizationDecisionId,
        actorId: request.actorId,
        status: 'preflight_denied',
        reasonCode: preflight.reasonCode,
        lineage,
        endpointUrl: candidateUrl,
        introspectionEnabled: false,
        batchingEnabled: false,
        fieldSuggestionsEnabled: false,
        error: {
          code: preflight.reasonCode,
          safeMessage: `Preflight denied for GraphQL Surface: ${preflight.reasonCode}`,
        },
      };
    }

    let introspectionEnabled = false;
    let batchingEnabled = false;
    let fieldSuggestionsEnabled = false;
    let discoveredRootTypes: string[] | undefined;
    let suggestionLeak: string | undefined;

    // 2. Probe 1 — Schema Introspection
    const introspectionReq: HttpProbeRequest = {
      url: candidateUrl,
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json, text/plain, */*',
        'user-agent': 'Mozilla/5.0 (FixGuard Defensive Auditor)',
      },
      body: JSON.stringify({ query: '{ __schema { types { name } } }' }),
      timeoutMs: 5000,
    };

    try {
      const resp = await transport(introspectionReq);
      if (resp.statusCode === 200 && resp.bodyText) {
        try {
          const parsed = JSON.parse(resp.bodyText) as {
            data?: { __schema?: { types?: readonly { name?: string }[] } };
          };
          if (parsed.data?.__schema?.types && Array.isArray(parsed.data.__schema.types)) {
            introspectionEnabled = true;
            const allTypes = parsed.data.__schema.types
              .map((t) => t.name)
              .filter((n): n is string => typeof n === 'string' && n.length > 0);
            
            const userTypes = allTypes.filter((n) => !n.startsWith('__'));
            discoveredRootTypes = userTypes.length > 0
              ? userTypes.slice(0, 20)
              : allTypes.slice(0, 20);
          }
        } catch {
          // not valid JSON
        }
      }
    } catch {
      // transport error or network error
    }

    // 3. Probe 2 — Field Suggestion Leakage
    const suggestionReq: HttpProbeRequest = {
      url: candidateUrl,
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json, text/plain, */*',
        'user-agent': 'Mozilla/5.0 (FixGuard Defensive Auditor)',
      },
      body: JSON.stringify({ query: '{ fixguard_invalid_probe }' }),
      timeoutMs: 5000,
    };

    try {
      const resp = await transport(suggestionReq);
      if (resp.bodyText) {
        const leak = extractSuggestionLeak(resp.bodyText);
        if (leak) {
          fieldSuggestionsEnabled = true;
          suggestionLeak = leak;
        }
      }
    } catch {
      // ignore
    }

    // 4. Probe 3 — Query Batching Capability
    const batchingReq: HttpProbeRequest = {
      url: candidateUrl,
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json, text/plain, */*',
        'user-agent': 'Mozilla/5.0 (FixGuard Defensive Auditor)',
      },
      body: JSON.stringify([{ query: '{ __typename }' }, { query: '{ __typename }' }]),
      timeoutMs: 5000,
    };

    try {
      const resp = await transport(batchingReq);
      if (resp.statusCode === 200 && resp.bodyText) {
        try {
          const parsed = JSON.parse(resp.bodyText);
          if (Array.isArray(parsed) && parsed.length === 2 && parsed.every((item) => typeof item === 'object' && item !== null)) {
            batchingEnabled = true;
          }
        } catch {
          // not JSON array
        }
      }
    } catch {
      // ignore
    }

    // If any GraphQL capability is detected, process finding or draft
    if (introspectionEnabled || fieldSuggestionsEnabled || batchingEnabled) {
      const category = introspectionEnabled ? 'INFORMATION_DISCLOSURE' : 'SECURITY_MISCONFIGURATION';
      const draftId = `dft_gql_${safeSeed}`;
      const candidateId = `cnd_gql_${safeSeed}`;
      const evidenceRecordId = `evd_gql_${safeSeed}`;

      let parsedPath = '/graphql';
      try {
        parsedPath = new URL(candidateUrl).pathname;
      } catch {
        // fallback
      }

      // 5. Human Review Routing & Finding Construction
      if (request.humanReviewDecision) {
        if (request.humanReviewDecision.decision === 'approve_evidence') {
          const title = introspectionEnabled
            ? `GraphQL Schema Introspection Enabled on ${parsedPath}`
            : `GraphQL Endpoint Misconfiguration on ${parsedPath}`;

          const details: string[] = [];
          if (introspectionEnabled) {
            details.push(`Full schema introspection enabled (${(discoveredRootTypes ?? []).length} root types identified).`);
          }
          if (fieldSuggestionsEnabled && suggestionLeak) {
            details.push(`Field suggestions enabled disclosing schema fields ("${suggestionLeak}").`);
          }
          if (batchingEnabled) {
            details.push('Array query batching enabled (potential amplification risk).');
          }

          const finding: Finding = {
            id: `fnd_gql_${safeSeed}`,
            type: category,
            severity: introspectionEnabled ? 'medium' : 'low',
            title,
            description: `Target application exposes active GraphQL capabilities at ${parsedPath}. ${details.join(' ')}`,
            target: candidateUrl,
            evidence: sanitizeEvidenceFragment(
              JSON.stringify({
                endpointUrl: candidateUrl,
                introspectionEnabled,
                batchingEnabled,
                fieldSuggestionsEnabled,
                discoveredRootTypes: discoveredRootTypes ?? [],
                suggestionLeak,
                reviewedBy: request.humanReviewDecision.reviewerId,
                reviewedAt: request.humanReviewDecision.reviewedAt,
              })
            ),
            confidence: 0.95,
            metadata: {
              kind: 'graphql_surface_metadata',
              category,
              endpointUrl: candidateUrl,
              introspectionEnabled,
              batchingEnabled,
              fieldSuggestionsEnabled,
              discoveredRootTypes: discoveredRootTypes ?? [],
              suggestionLeak,
              observedAt: nowIso,
              candidateId,
              evidenceRecordId,
              lineage: `${request.assessmentId}:${request.scanId}:${request.actorId}`,
            },
          };

          return {
            contractVersion: DETECTION_CONTRACT_VERSION,
            kind: 'graphql_surface_detection_result',
            detectionId: request.detectionId,
            scanId: request.scanId,
            assessmentId: request.assessmentId,
            authorizationGrantId: request.authorizationGrantId,
            authorizationDecisionId: request.authorizationDecisionId,
            actorId: request.actorId,
            status: 'graphql_surface_detected',
            reasonCode: 'graphql_surface_confirmed',
            lineage,
            endpointUrl: candidateUrl,
            introspectionEnabled,
            batchingEnabled,
            fieldSuggestionsEnabled,
            discoveredRootTypes,
            suggestionLeak,
            finding,
          };
        }

        if (request.humanReviewDecision.decision === 'reject') {
          return {
            contractVersion: DETECTION_CONTRACT_VERSION,
            kind: 'graphql_surface_detection_result',
            detectionId: request.detectionId,
            scanId: request.scanId,
            assessmentId: request.assessmentId,
            authorizationGrantId: request.authorizationGrantId,
            authorizationDecisionId: request.authorizationDecisionId,
            actorId: request.actorId,
            status: 'secure_target_abstained',
            reasonCode: 'human_review_rejected',
            lineage,
            endpointUrl: candidateUrl,
            introspectionEnabled,
            batchingEnabled,
            fieldSuggestionsEnabled,
          };
        }
      }

      // 6. Unreviewed -> Produce Draft for HITL Triage
      const rationaleParts: string[] = [];
      if (introspectionEnabled) rationaleParts.push('Schema Introspection enabled');
      if (fieldSuggestionsEnabled) rationaleParts.push('Field Suggestions leakage');
      if (batchingEnabled) rationaleParts.push('Query Batching enabled');

      const evidenceDraft: EvidenceDraftEnvelope = {
        draftKind: 'non_persisted_comparison_evidence_draft',
        draftId,
        suggestedEvidenceType: 'http_difference',
        suggestedStrength: introspectionEnabled ? 'strong' : 'moderate',
        sourceComparisonId: `cmp_gql_${safeSeed}`,
        sourceSnapshotIds: {
          baselineSnapshotId: `snp_gql_${safeSeed}_base`,
          validationSnapshotId: `snp_gql_${safeSeed}_val`,
        },
        requiresHumanReview: true,
        notPersisted: true,
        notARealFinding: true,
        notConfirmedEvidence: true,
        notForExternalDelivery: true,
        notM45EvidenceRecord: true,
        safeRationale: `GraphQL endpoint detected at ${parsedPath} with: ${rationaleParts.join(', ')}`,
      };

      return {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'graphql_surface_detection_result',
        detectionId: request.detectionId,
        scanId: request.scanId,
        assessmentId: request.assessmentId,
        authorizationGrantId: request.authorizationGrantId,
        authorizationDecisionId: request.authorizationDecisionId,
        actorId: request.actorId,
        status: 'pending_human_review',
        reasonCode: 'graphql_surface_observed',
        lineage,
        endpointUrl: candidateUrl,
        introspectionEnabled,
        batchingEnabled,
        fieldSuggestionsEnabled,
        discoveredRootTypes,
        suggestionLeak,
        evidenceDraft,
      };
    }
  }

  // If no GraphQL surface found across candidate paths
  return {
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'graphql_surface_detection_result',
    detectionId: request.detectionId,
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
    status: 'secure_target_abstained',
    reasonCode: 'no_graphql_surface_detected',
    lineage,
    endpointUrl: request.endpointUrl,
    introspectionEnabled: false,
    batchingEnabled: false,
    fieldSuggestionsEnabled: false,
  };
}

export class GraphQLSurfaceDetectionService {
  public async execute(
    request: GraphQLSurfaceDetectionRequest
  ): Promise<GraphQLSurfaceDetectionResult> {
    return runGraphQLSurfaceDetection(request);
  }
}
