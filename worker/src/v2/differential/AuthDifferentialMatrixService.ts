/**
 * FixGuard V2 — Auth Differential Matrix Service.
 *
 * Evaluates discovered application endpoints under both anonymous and authenticated
 * contexts to map authorization boundaries and access control differentials.
 *
 * Epistemic Rules:
 * 1. An observed delta is recorded as an `anon_session_get_delta` fact only.
 * 2. Never claims a vulnerability (no auto-promoted IDOR or severity).
 * 3. Never mutates session state in-place.
 * 4. Respects target execution pacing and budget ceilings.
 */

import { createHash } from 'node:crypto';
import {
  AUTH_DIFFERENTIAL_CONTRACT_VERSION,
  type AuthDifferentialClassification,
  type AuthDifferentialEndpointResult,
  type AuthDifferentialMatrixRequest,
  type AuthDifferentialMatrixResult,
} from './AuthDifferentialContracts.js';
import { observeDefensesFromHttpResponse } from '../test-validity/DefenseObservationService.js';
import { defaultHttpProbeTransport } from '../detection/IdorDifferentialDetectionService.js';
import {
  formatAnonSessionGetDeltaValue,
  type ObservedFact,
} from '../observation/ObservedFactContracts.js';
import { tryBuildObservedFact } from '../observation/ObservedFactCatalogService.js';
import { runAdapterPreflight } from '../recon/adapters/AdapterPreflightPipeline.js';

function sha256Hex(content: string): string {
  return createHash('sha256').update(content).digest('hex').slice(0, 16);
}

function detectShapeKind(
  body: string
): 'empty' | 'json_object' | 'json_array' | 'html' | 'text' {
  const trimmed = body.trim();
  if (trimmed.length === 0) return 'empty';
  if (trimmed.startsWith('{') && trimmed.endsWith('}')) return 'json_object';
  if (trimmed.startsWith('[') && trimmed.endsWith(']')) return 'json_array';
  if (/<(?:!doctype|html|head|body|div)\b/i.test(trimmed)) return 'html';
  return 'text';
}

const SENSITIVE_PATH_PATTERN =
  /\/(?:api|rpc|rest|user|users|account|admin|dashboard|profile|settings|tenants|orders|invoices)\b/i;

export async function runAuthDifferentialMatrix(
  request: AuthDifferentialMatrixRequest
): Promise<AuthDifferentialMatrixResult> {
  const evaluatedAt = request.observedAt ?? new Date().toISOString();
  const transport = request.transport ?? defaultHttpProbeTransport;
  const maxEndpoints = request.maxEndpoints ?? 15;

  const summaryCounts: Record<AuthDifferentialClassification, number> = {
    expected_auth_difference: 0,
    protected: 0,
    authentication_required: 0,
    application_behavior_differs: 0,
    potential_authorization_boundary: 0,
    interfered: 0,
    inconclusive: 0,
  };

  const results: AuthDifferentialEndpointResult[] = [];
  const generatedFacts: ObservedFact[] = [];

  const hasAuth = request.sessionSanctuary.hasAuthenticatedContext();
  const endpointsToEvaluate = request.endpointUrls.slice(0, maxEndpoints);

  for (const endpointUrl of endpointsToEvaluate) {
    if (!hasAuth) {
      summaryCounts.inconclusive++;
      results.push({
        endpointUrl,
        method: 'GET',
        classification: 'inconclusive',
        reasonCode: 'missing_authenticated_context',
        explanation: 'No authenticated context available in session sanctuary for differential comparison',
        anonStatusCode: 0,
        authStatusCode: 0,
        anonBodyHash: '',
        authBodyHash: '',
        interfered: false,
        observedFact: null,
      });
      continue;
    }

    // Safety preflight check for network egress on this endpoint
    const preflight = await runAdapterPreflight({
      target: endpointUrl,
      targetKind: 'url',
      verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
      authorizedScopeGrant: request.scopeGrant,
      lineage: request.lineage,
      requiredPermissions: ['authenticatedTesting', 'activeCrawling'],
      dnsResolver: request.dnsResolver,
    });

    if (!preflight.ok) {
      summaryCounts.inconclusive++;
      results.push({
        endpointUrl,
        method: 'GET',
        classification: 'inconclusive',
        reasonCode: preflight.reasonCode,
        explanation: `Preflight denied for endpoint: ${preflight.reason}`,
        anonStatusCode: 0,
        authStatusCode: 0,
        anonBodyHash: '',
        authBodyHash: '',
        interfered: false,
        observedFact: null,
      });
      continue;
    }

    try {
      // 1. Anonymous request (isolated context)
      const anonHeaders = request.sessionSanctuary.createProbeHeaders('anonymous');
      const anonRes = await transport({
        url: endpointUrl,
        method: 'GET',
        headers: Object.freeze(anonHeaders),
        timeoutMs: 6000,
      });

      // 2. Authenticated request (sanctuary context)
      const authHeaders = request.sessionSanctuary.createProbeHeaders('authenticated');
      const authRes = await transport({
        url: endpointUrl,
        method: 'GET',
        headers: Object.freeze(authHeaders),
        timeoutMs: 6000,
      });

      // 3. Defense observation checks
      const anonDefenses = observeDefensesFromHttpResponse({
        statusCode: anonRes.statusCode,
        headerValues: anonRes.headers,
        bodyExcerpt: anonRes.bodyText.slice(0, 300),
        targetHost: request.targetDomain,
      });

      const authDefenses = observeDefensesFromHttpResponse({
        statusCode: authRes.statusCode,
        headerValues: authRes.headers,
        bodyExcerpt: authRes.bodyText.slice(0, 300),
        targetHost: request.targetDomain,
      });

      const isInterfered =
        anonDefenses.some((d) => d.controlKind === 'bot' || d.reasonCode.includes('challenge')) ||
        authDefenses.some((d) => d.controlKind === 'bot' || d.reasonCode.includes('challenge'));

      const anonHash = sha256Hex(anonRes.bodyText);
      const authHash = sha256Hex(authRes.bodyText);
      const anonShape = detectShapeKind(anonRes.bodyText);
      const authShape = detectShapeKind(authRes.bodyText);

      let classification: AuthDifferentialClassification;
      let reasonCode: string;
      let explanation: string;

      if (isInterfered) {
        classification = 'interfered';
        reasonCode = 'edge_challenge_interfered';
        explanation = 'One or both probes encountered an edge WAF or bot challenge';
      } else if (anonRes.statusCode >= 500 || authRes.statusCode >= 500) {
        classification = 'inconclusive';
        reasonCode = 'server_error_response';
        explanation = `Server returned error status (anon=${anonRes.statusCode}, auth=${authRes.statusCode})`;
      } else if (
        (anonRes.statusCode === 401 || anonRes.statusCode === 403) &&
        authRes.statusCode === 200
      ) {
        classification = 'authentication_required';
        reasonCode = 'authentication_enforced';
        explanation = 'Anonymous access was rejected; authenticated access succeeded with HTTP 200';
      } else if (
        (anonRes.statusCode === 401 || anonRes.statusCode === 403) &&
        (authRes.statusCode === 401 || authRes.statusCode === 403)
      ) {
        classification = 'protected';
        reasonCode = 'both_contexts_denied';
        explanation = 'Both anonymous and authenticated requests received denial (401/403)';
      } else if (anonRes.statusCode === 200 && authRes.statusCode === 200) {
        if (anonHash === authHash) {
          if (SENSITIVE_PATH_PATTERN.test(endpointUrl)) {
            classification = 'potential_authorization_boundary';
            reasonCode = 'sensitive_endpoint_identical_response';
            explanation = 'Sensitive route returned identical HTTP 200 response to both anonymous and authenticated callers';
          } else {
            classification = 'expected_auth_difference';
            reasonCode = 'public_surface_identical_response';
            explanation = 'Public endpoint returned identical HTTP 200 response';
          }
        } else {
          classification = 'application_behavior_differs';
          reasonCode = 'response_body_hash_divergence';
          explanation = 'Both returned HTTP 200, but authenticated response differed in body hash/structure';
        }
      } else {
        classification = 'inconclusive';
        reasonCode = 'asymmetric_status_unclassified';
        explanation = `Status code pairing (${anonRes.statusCode} vs ${authRes.statusCode}) did not match closed categories`;
      }

      summaryCounts[classification]++;

      // Format observed fact
      const deltaValue = formatAnonSessionGetDeltaValue({
        anonStatus: anonRes.statusCode,
        sessionStatus: authRes.statusCode,
        anonBodyHash: anonHash,
        sessionBodyHash: authHash,
        anonBodyShape: anonShape,
        sessionBodyShape: authShape,
        interfered: isInterfered,
      });

      const observedFact = tryBuildObservedFact({
        factKind: 'anon_session_get_delta',
        value: deltaValue,
        observationText: `${endpointUrl} ${deltaValue}`,
        sourceUrl: endpointUrl,
        observationKind: 'differential_get',
        lineage: request.lineage,
        observedAt: evaluatedAt,
        sourceLabel: 'auth_differential_matrix',
      });

      if (observedFact) {
        generatedFacts.push(observedFact);
      }

      results.push({
        endpointUrl,
        method: 'GET',
        classification,
        reasonCode,
        explanation,
        anonStatusCode: anonRes.statusCode,
        authStatusCode: authRes.statusCode,
        anonBodyHash: anonHash,
        authBodyHash: authHash,
        anonBodyShape: anonShape,
        authBodyShape: authShape,
        interfered: isInterfered,
        observedFact,
      });
    } catch (probeErr: unknown) {
      summaryCounts.inconclusive++;
      results.push({
        endpointUrl,
        method: 'GET',
        classification: 'inconclusive',
        reasonCode: 'transport_error',
        explanation: `Differential probe error: ${probeErr instanceof Error ? probeErr.message : String(probeErr)}`,
        anonStatusCode: 0,
        authStatusCode: 0,
        anonBodyHash: '',
        authBodyHash: '',
        interfered: false,
        observedFact: null,
      });
    }
  }

  return Object.freeze({
    contractVersion: AUTH_DIFFERENTIAL_CONTRACT_VERSION,
    targetDomain: request.targetDomain,
    evaluatedAt,
    totalEvaluated: results.length,
    results: Object.freeze(results),
    generatedFacts: Object.freeze(generatedFacts),
    summaryCounts: Object.freeze(summaryCounts),
  });
}
