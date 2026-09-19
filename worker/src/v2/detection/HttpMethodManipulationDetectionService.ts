/**
 * Milestone P5-3 — HTTP Method Manipulation Detection Engine
 *
 * Probes whether endpoints with authorization gates accept alternative HTTP verbs
 * or override headers (X-HTTP-Method-Override, _method, TRACE) to bypass restrictions.
 *
 * Strict Invariants:
 * - Read-only inspection bounded to response status and body.
 * - 7-pass SSRF preflight protection blocking internal IP and metadata probing.
 * - Anti-leak evidence sanitization via sanitizeEvidenceFragment().
 * - Clean abstention (secure_target_abstained) when target blocks overrides or returns 405.
 * - HITL Routing: Unattended runs produce pending_human_review with EvidenceDraftEnvelope.
 * - 0 occurrences of 'as any'.
 */

import type {
  HttpMethodManipulationDetectionRequest,
  HttpMethodManipulationDetectionResult,
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

export async function runHttpMethodManipulationDetection(
  request: HttpMethodManipulationDetectionRequest
): Promise<HttpMethodManipulationDetectionResult> {
  const transport = request.transport ?? defaultHttpProbeTransport;
  const endpointUrl = request.endpointUrl ?? request.targetEndpointUrl ?? '';
  const safeSeed = sanitizeToSafeId(request.detectionId);
  const lineage = {
    assessmentId: request.assessmentId,
    scanId: request.scanId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
  };

  const targetOperation = request.targetOperation ?? 'api_operation';
  const baselineMethod = request.baselineMethod ?? 'PUT';

  // 1. 7-Pass SSRF Preflight Protection
  const preflight = await runAdapterPreflight({
    target: endpointUrl,
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
      kind: 'http_method_manipulation_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'preflight_denied',
      reasonCode: preflight.reasonCode,
      lineage,
      endpointUrl: endpointUrl,
      targetOperation,
      baselineMethod,
      bypassMethodOrHeader: '',
      baselineStatusCode: 0,
      manipulatedStatusCode: 0,
      bypassType: 'method_override_header',
      error: {
        code: preflight.reasonCode,
        safeMessage: preflight.reason ?? 'Preflight denied for HTTP method manipulation probe',
      },
    };
  }

  // Prepare standard headers
  const baseHeaders: Record<string, string> = {
    Accept: 'application/json, text/plain, */*',
  };
  if (request.identityAContext?.headers) {
    for (const [k, v] of Object.entries(request.identityAContext.headers)) {
      if (typeof v === 'string') {
        baseHeaders[k] = v;
      }
    }
  }

  // 2. Baseline Probe: Direct restricted method
  let baselineStatusCode = 0;
  let baselineBody = '';
  try {
    const baselineResp = await transport({
      url: endpointUrl,
      method: (baselineMethod === 'DELETE' || baselineMethod === 'PUT' || baselineMethod === 'POST' || baselineMethod === 'HEAD' || baselineMethod === 'OPTIONS' || baselineMethod === 'TRACE') ? baselineMethod : 'PUT',
      headers: baseHeaders,
      timeoutMs: 5000,
    });
    baselineStatusCode = baselineResp.statusCode;
    baselineBody = baselineResp.bodyText ?? '';
  } catch (err) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'http_method_manipulation_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'unexpected_failure',
      reasonCode: 'baseline_method_probe_failed',
      lineage,
      endpointUrl: endpointUrl,
      targetOperation,
      baselineMethod,
      bypassMethodOrHeader: '',
      baselineStatusCode: 0,
      manipulatedStatusCode: 0,
      bypassType: 'method_override_header',
      error: {
        code: 'baseline_method_probe_failed',
        safeMessage: err instanceof Error ? err.message : 'Baseline HTTP method probe failed',
      },
    };
  }

  // 3. Override Probe A: X-HTTP-Method-Override Header
  const altMethod = baselineMethod.toUpperCase() === 'GET' ? 'POST' : 'GET';
  let overrideAStatusCode = 0;
  let overrideABody = '';
  try {
    const overrideAResp = await transport({
      url: endpointUrl,
      method: 'POST',
      headers: {
        ...baseHeaders,
        'X-HTTP-Method-Override': altMethod,
      },
      timeoutMs: 5000,
    });
    overrideAStatusCode = overrideAResp.statusCode;
    overrideABody = overrideAResp.bodyText ?? '';
  } catch {
    // Ignore individual probe failures
  }

  // 4. Override Probe B: Query Parameter _method override
  let overrideBStatusCode = 0;
  let overrideBBody = '';
  try {
    const parsedUrl = new URL(endpointUrl);
    parsedUrl.searchParams.set('_method', altMethod);
    const overrideBResp = await transport({
      url: parsedUrl.toString(),
      method: 'POST',
      headers: baseHeaders,
      timeoutMs: 5000,
    });
    overrideBStatusCode = overrideBResp.statusCode;
    overrideBBody = overrideBResp.bodyText ?? '';
  } catch {
    // Ignore individual probe failures
  }

  // 5. TRACE Method Probe: Cross-Site Tracing (XST) Reflection
  const canaryToken = `fixguard_xst_${safeSeed}`;
  let traceStatusCode = 0;
  let traceBody = '';
  try {
    const traceResp = await transport({
      url: endpointUrl,
      method: 'TRACE',
      headers: {
        ...baseHeaders,
        'X-Fixguard-Canary': canaryToken,
      },
      timeoutMs: 5000,
    });
    traceStatusCode = traceResp.statusCode;
    traceBody = traceResp.bodyText ?? '';
  } catch {
    // Ignore trace probe failure
  }

  const traceCanaryReflected =
    traceStatusCode >= 200 &&
    traceStatusCode < 300 &&
    (traceBody.includes(canaryToken) || traceBody.toLowerCase().includes('x-fixguard-canary'));

  // Disparity Evaluation
  const isBaselineRestricted = baselineStatusCode === 401 || baselineStatusCode === 403 || baselineStatusCode === 405;
  const isOverrideABypass = overrideAStatusCode >= 200 && overrideAStatusCode < 300 && overrideABody.trim().length > 0 && isBaselineRestricted;
  const isOverrideBBypass = overrideBStatusCode >= 200 && overrideBStatusCode < 300 && overrideBBody.trim().length > 0 && isBaselineRestricted;

  if (isOverrideABypass || isOverrideBBypass) {
    const bypassType: 'method_override_header' | 'query_param_override' = isOverrideABypass
      ? 'method_override_header'
      : 'query_param_override';
    const bypassMethodOrHeader = isOverrideABypass
      ? `X-HTTP-Method-Override: ${altMethod}`
      : `_method=${altMethod}`;
    const manipulatedStatusCode = isOverrideABypass ? overrideAStatusCode : overrideBStatusCode;
    const responseBodySample = isOverrideABypass ? overrideABody : overrideBBody;

    const draftId = `dft_hmeth_${safeSeed}`;
    const candidateId = `cnd_hmeth_${safeSeed}`;
    const evidenceRecordId = `evd_hmeth_${safeSeed}`;
    const sanitizedUrl = sanitizeEvidenceFragment(endpointUrl);

    // HITL Decision Handling
    if (request.humanReviewDecision) {
      if (request.humanReviewDecision.decision === 'approve_evidence') {
        const finding: Finding = {
          id: `fnd_hmeth_${safeSeed}`,
          type: 'BROKEN_ACCESS_CONTROL',
          severity: 'high',
          title: `Approved HTTP Verb Tampering Bypass (${bypassMethodOrHeader}) on ${sanitizedUrl}`,
          description: `Target application restricts direct HTTP ${baselineMethod} (status ${baselineStatusCode}) but accepts verb manipulation via '${bypassMethodOrHeader}' on ${sanitizedUrl}, returning HTTP ${manipulatedStatusCode} OK and bypassing authorization controls.`,
          target: endpointUrl,
          evidence: JSON.stringify({
            endpointUrl: sanitizedUrl,
            targetOperation,
            baselineMethod,
            bypassMethodOrHeader,
            baselineStatusCode,
            manipulatedStatusCode,
            bypassType,
            bodySampleSnippet: sanitizeEvidenceFragment(responseBodySample.slice(0, 200)),
          }),
          confidence: 0.95,
          verificationState: 'validated_vulnerability',
          metadata: {
            kind: 'http_method_manipulation_metadata',
            category: 'BROKEN_ACCESS_CONTROL',
            endpointUrl: endpointUrl,
            targetOperation,
            baselineMethod,
            bypassMethodOrHeader,
            baselineStatusCode,
            manipulatedStatusCode,
            bypassType,
            observedAt: new Date().toISOString(),
            candidateId,
            evidenceRecordId,
            lineage,
          },
        };

        return {
          contractVersion: DETECTION_CONTRACT_VERSION,
          kind: 'http_method_manipulation_detection_result',
          detectionId: request.detectionId,
          scanId: request.scanId,
          assessmentId: request.assessmentId,
          authorizationGrantId: request.authorizationGrantId,
          authorizationDecisionId: request.authorizationDecisionId,
          actorId: request.actorId,
          status: 'vulnerability_detected',
          reasonCode: 'http_method_override_bypass_confirmed',
          lineage,
          endpointUrl: endpointUrl,
          targetOperation,
          baselineMethod,
          bypassMethodOrHeader,
          baselineStatusCode,
          manipulatedStatusCode,
          bypassType,
          finding,
        };
      }

      return {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'http_method_manipulation_detection_result',
        detectionId: request.detectionId,
        scanId: request.scanId,
        assessmentId: request.assessmentId,
        authorizationGrantId: request.authorizationGrantId,
        authorizationDecisionId: request.authorizationDecisionId,
        actorId: request.actorId,
        status: 'secure_target_abstained',
        reasonCode: 'human_operator_rejected_method_override_draft',
        lineage,
        endpointUrl: endpointUrl,
        targetOperation,
        baselineMethod,
        bypassMethodOrHeader,
        baselineStatusCode,
        manipulatedStatusCode,
        bypassType,
      };
    }

    // Unattended Run -> Evidence Draft
    const evidenceDraft: EvidenceDraftEnvelope = {
      draftKind: 'non_persisted_comparison_evidence_draft',
      draftId,
      suggestedEvidenceType: 'http_difference',
      suggestedStrength: 'strong',
      sourceComparisonId: `cmp_hmeth_${safeSeed}`,
      sourceSnapshotIds: {
        baselineSnapshotId: `snp_base_${safeSeed}`,
        validationSnapshotId: `snp_val_${safeSeed}`,
      },
      requiresHumanReview: true,
      notPersisted: true,
      notARealFinding: true,
      notConfirmedEvidence: true,
      notForExternalDelivery: true,
      notM45EvidenceRecord: true,
      safeRationale: `Target blocked direct ${baselineMethod} (${baselineStatusCode}) but accepted override '${bypassMethodOrHeader}' returning ${manipulatedStatusCode} OK.`,
      differentialContext: {
        endpointUrl: sanitizedUrl,
        detectionKind: 'http_method_manipulation',
        targetOperation,
        baselineMethod,
        bypassMethodOrHeader,
        baselineStatusCode,
        manipulatedStatusCode,
        bypassType,
      },
    };

    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'http_method_manipulation_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'pending_human_review',
      reasonCode: 'http_method_override_bypass_pending_review',
      lineage,
      endpointUrl: endpointUrl,
      targetOperation,
      baselineMethod,
      bypassMethodOrHeader,
      baselineStatusCode,
      manipulatedStatusCode,
      bypassType,
      evidenceDraft,
    };
  }

  // TRACE Reflection Evaluation
  if (traceCanaryReflected) {
    const draftId = `dft_hmeth_${safeSeed}`;
    const candidateId = `cnd_hmeth_${safeSeed}`;
    const evidenceRecordId = `evd_hmeth_${safeSeed}`;
    const sanitizedUrl = sanitizeEvidenceFragment(endpointUrl);

    if (request.humanReviewDecision) {
      if (request.humanReviewDecision.decision === 'approve_evidence') {
        const finding: Finding = {
          id: `fnd_hmeth_${safeSeed}`,
          type: 'SECURITY_MISCONFIGURATION',
          severity: 'medium',
          title: `Approved HTTP TRACE Method Enabled (Cross-Site Tracing) on ${sanitizedUrl}`,
          description: `Target application responds with HTTP 200 OK to TRACE requests and echoes back custom request headers (${canaryToken}), creating Cross-Site Tracing (XST) and credential exposure risks.`,
          target: endpointUrl,
          evidence: JSON.stringify({
            endpointUrl: sanitizedUrl,
            targetOperation: 'trace_debugging',
            baselineMethod: 'TRACE',
            bypassMethodOrHeader: 'HTTP TRACE with Canary Header',
            baselineStatusCode,
            manipulatedStatusCode: traceStatusCode,
            bypassType: 'trace_enabled',
            bodySampleSnippet: sanitizeEvidenceFragment(traceBody.slice(0, 200)),
          }),
          confidence: 0.9,
          verificationState: 'observed_anomaly',
          metadata: {
            kind: 'http_method_manipulation_metadata',
            category: 'SECURITY_MISCONFIGURATION',
            endpointUrl: endpointUrl,
            targetOperation: 'trace_debugging',
            baselineMethod: 'TRACE',
            bypassMethodOrHeader: 'HTTP TRACE',
            baselineStatusCode,
            manipulatedStatusCode: traceStatusCode,
            bypassType: 'trace_enabled',
            observedAt: new Date().toISOString(),
            candidateId,
            evidenceRecordId,
            lineage,
          },
        };

        return {
          contractVersion: DETECTION_CONTRACT_VERSION,
          kind: 'http_method_manipulation_detection_result',
          detectionId: request.detectionId,
          scanId: request.scanId,
          assessmentId: request.assessmentId,
          authorizationGrantId: request.authorizationGrantId,
          authorizationDecisionId: request.authorizationDecisionId,
          actorId: request.actorId,
          status: 'potential_weakness',
          reasonCode: 'http_trace_xst_enabled_confirmed',
          lineage,
          endpointUrl: endpointUrl,
          targetOperation: 'trace_debugging',
          baselineMethod: 'TRACE',
          bypassMethodOrHeader: 'HTTP TRACE',
          baselineStatusCode,
          manipulatedStatusCode: traceStatusCode,
          bypassType: 'trace_enabled',
          finding,
        };
      }

      return {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'http_method_manipulation_detection_result',
        detectionId: request.detectionId,
        scanId: request.scanId,
        assessmentId: request.assessmentId,
        authorizationGrantId: request.authorizationGrantId,
        authorizationDecisionId: request.authorizationDecisionId,
        actorId: request.actorId,
        status: 'secure_target_abstained',
        reasonCode: 'human_operator_rejected_trace_draft',
        lineage,
        endpointUrl: endpointUrl,
        targetOperation: 'trace_debugging',
        baselineMethod: 'TRACE',
        bypassMethodOrHeader: 'HTTP TRACE',
        baselineStatusCode,
        manipulatedStatusCode: traceStatusCode,
        bypassType: 'trace_enabled',
      };
    }

    const evidenceDraft: EvidenceDraftEnvelope = {
      draftKind: 'non_persisted_comparison_evidence_draft',
      draftId,
      suggestedEvidenceType: 'http_difference',
      suggestedStrength: 'moderate',
      sourceComparisonId: `cmp_hmeth_${safeSeed}`,
      sourceSnapshotIds: {
        baselineSnapshotId: `snp_base_${safeSeed}`,
        validationSnapshotId: `snp_val_${safeSeed}`,
      },
      requiresHumanReview: true,
      notPersisted: true,
      notARealFinding: true,
      notConfirmedEvidence: true,
      notForExternalDelivery: true,
      notM45EvidenceRecord: true,
      safeRationale: `Target application responds 200 OK to TRACE requests reflecting canary header '${canaryToken}'.`,
      differentialContext: {
        endpointUrl: sanitizedUrl,
        detectionKind: 'http_method_manipulation',
        targetOperation: 'trace_debugging',
        baselineMethod: 'TRACE',
        bypassMethodOrHeader: 'HTTP TRACE',
        baselineStatusCode,
        manipulatedStatusCode: traceStatusCode,
        bypassType: 'trace_enabled',
      },
    };

    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'http_method_manipulation_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'pending_human_review',
      reasonCode: 'http_trace_enabled_pending_review',
      lineage,
      endpointUrl: endpointUrl,
      targetOperation: 'trace_debugging',
      baselineMethod: 'TRACE',
      bypassMethodOrHeader: 'HTTP TRACE',
      baselineStatusCode,
      manipulatedStatusCode: traceStatusCode,
      bypassType: 'trace_enabled',
      evidenceDraft,
    };
  }

  // 6. Clean Abstention
  return {
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'http_method_manipulation_detection_result',
    detectionId: request.detectionId,
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
    status: 'secure_target_abstained',
    reasonCode: 'http_method_overrides_and_trace_blocked',
    lineage,
    endpointUrl: endpointUrl,
    targetOperation,
    baselineMethod,
    bypassMethodOrHeader: '',
    baselineStatusCode,
    manipulatedStatusCode: 0,
    bypassType: 'method_override_header',
  };
}
