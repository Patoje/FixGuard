/**
 * F1.6 — Anon vs session GET observation.
 * Reuses AuthBoundaryDifferentialDetectionService. Records an OBSERVED
 * `anon_session_get_delta` fact only. Never creates a Finding.
 */

import { DETECTION_CONTRACT_VERSION } from '../detection/DetectionContracts.js';
import type {
  AuthorizedExecutionLineageTuple,
  IdorHttpProbeTransport,
  ProbeAuthContext,
} from '../detection/DetectionContracts.js';
import type { VerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { PreSpawnDnsResolver } from '../recon/adapters/AdapterPreflightPipeline.js';
import { runAuthBoundaryDifferentialDetection } from '../detection/AuthBoundaryDifferentialDetectionService.js';
import type { AuthBoundaryProbeFacet } from '../detection/AuthBoundaryDifferentialContracts.js';
import {
  formatAnonSessionGetDeltaValue,
  type ObservedFact,
} from './ObservedFactContracts.js';
import { tryBuildObservedFact } from './ObservedFactCatalogService.js';

export interface AnonSessionGetDeltaObservation {
  readonly fact: ObservedFact | null;
  readonly reasonCode: string;
  readonly interfered: boolean;
  readonly createsFinding: false;
}

function facetFor(
  facets: readonly AuthBoundaryProbeFacet[],
  role: AuthBoundaryProbeFacet['identityRole']
): AuthBoundaryProbeFacet | undefined {
  return facets.find((facet) => facet.identityRole === role);
}

export async function observeAnonSessionGetDelta(input: {
  readonly detectionId: string;
  readonly endpointUrl: string;
  readonly identityA: ProbeAuthContext;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
  readonly observedAt: string;
}): Promise<AnonSessionGetDeltaObservation> {
  const measured = await runAuthBoundaryDifferentialDetection({
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'auth_boundary_differential_detection_request',
    detectionId: input.detectionId,
    assessmentId: input.lineage.assessmentId,
    scanId: input.lineage.scanId,
    authorizationGrantId: input.lineage.authorizationGrantId,
    authorizationDecisionId: input.lineage.authorizationDecisionId,
    actorId: input.lineage.actorId,
    verifiedAuthorizationDecision: input.verifiedAuthorizationDecision,
    scopeGrant: input.scopeGrant,
    endpointUrl: input.endpointUrl,
    identityA: input.identityA,
    ...(input.transport ? { transport: input.transport } : {}),
    ...(input.dnsResolver ? { dnsResolver: input.dnsResolver } : {}),
  });

  const interfered = measured.investigationOutcome === 'interfered';
  const facets = measured.facets ?? [];
  const session = facetFor(facets, 'authenticated_a');
  const anon = facetFor(facets, 'anonymous');
  if (!session || !anon) {
    return {
      fact: null,
      reasonCode: measured.reasonCode,
      interfered,
      createsFinding: false,
    };
  }

  const value = formatAnonSessionGetDeltaValue({
    anonStatus: anon.statusCode,
    sessionStatus: session.statusCode,
    anonBodyHash: anon.bodyHash,
    sessionBodyHash: session.bodyHash,
    anonBodyShape: anon.bodyShapeKind,
    sessionBodyShape: session.bodyShapeKind,
    interfered,
  });
  const fact = tryBuildObservedFact({
    factKind: 'anon_session_get_delta',
    value,
    observationText: `${input.endpointUrl} ${value}`,
    sourceUrl: input.endpointUrl,
    observationKind: 'differential_get',
    lineage: input.lineage,
    observedAt: input.observedAt,
    sourceLabel: 'auth_boundary_differential',
  });
  return {
    fact,
    reasonCode: measured.reasonCode,
    interfered,
    createsFinding: false,
  };
}
