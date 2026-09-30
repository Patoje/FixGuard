/**
 * Phase 2 — read-only detection over an already stored probe inventory.
 * Calls existing detector entrypoints. Does not mint authorization, invent
 * identities, or execute attack plans.
 */

import type { Finding } from '../core/Evidence.js';
import type {
  DifferentialEvidenceContext,
  EnrichedEvidenceDraft,
} from '../application/OrchestratedAssessmentContracts.js';
import type { EvidenceDraftEnvelope } from '../evidence-mapping/ComparisonEvidenceMappingContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { VerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import type { AggregatedReconObservations } from '../recon/orchestration/ActiveReconOrchestrationContracts.js';
import type { PreSpawnDnsResolver } from '../recon/adapters/AdapterPreflightPipeline.js';
import type { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';
import {
  DETECTION_CONTRACT_VERSION,
  type IdorHttpProbeTransport,
  type ProbeAuthContext,
  type SourcemapExposureDetectionResult,
} from '../detection/DetectionContracts.js';
import { parseProbeInventory } from './ProbeInventory.js';
import type { ProbeInventoryEntry } from './ProbeInventoryContracts.js';
import { runSecurityHeaderDetection } from '../detection/SecurityHeaderDetectionService.js';
import { runOpenRedirectDetection } from '../detection/OpenRedirectDetectionService.js';
import { runInformationDisclosureDetection } from '../detection/InformationDisclosureDetectionService.js';
import { runCorsMisconfigurationDetection } from '../detection/CorsMisconfigurationDetectionService.js';
import { runParameterReflectionDetection } from '../detection/ParameterReflectionDetectionService.js';
import { runGraphQLSurfaceDetection } from '../detection/GraphQLSurfaceDetectionService.js';
import { runAuthBypassDetection } from '../detection/AuthBypassDetectionService.js';
import { runAuthBoundaryDifferentialDetection } from '../detection/AuthBoundaryDifferentialDetectionService.js';
import { runIdorDifferentialDetection } from '../detection/IdorDifferentialDetectionService.js';

export type ReadDetectionDetectorName =
  | 'security_header'
  | 'open_redirect'
  | 'information_disclosure'
  | 'cors_misconfiguration'
  | 'parameter_reflection'
  | 'graphql_surface'
  | 'auth_bypass'
  | 'auth_boundary_differential'
  | 'idor_differential';

export interface ReadDetectionSkip {
  readonly detector: ReadDetectionDetectorName;
  readonly reasonCode: string;
}

export interface ReadDetectionPassResult {
  readonly status: 'completed' | 'rejected';
  readonly reasonCode?: string;
  readonly findings: readonly Finding[];
  readonly pendingEvidenceDrafts: readonly EnrichedEvidenceDraft[];
  readonly detectorCallCount: number;
  readonly invokedDetectors: readonly ReadDetectionDetectorName[];
  readonly skipped: readonly ReadDetectionSkip[];
}

export interface RunReadDetectionPassInput {
  readonly probeInventory: unknown;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly transport: IdorHttpProbeTransport;
  readonly dnsResolver: PreSpawnDnsResolver;
  readonly coordinator?: TargetExecutionCoordinator;
  readonly circuitHost?: string;
  readonly identityA?: ProbeAuthContext;
  readonly identityB?: ProbeAuthContext;
  readonly observedGraphqlUrls?: readonly string[];
}

interface DetectorOutcome {
  readonly finding?: Finding;
  readonly status: string;
  readonly evidenceDraft?: EvidenceDraftEnvelope;
  readonly context: DifferentialEvidenceContext;
}

function endpointUrlForEntry(entry: ProbeInventoryEntry): string | null {
  try {
    const url = new URL(entry.path, entry.origin);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      return null;
    }
    return url.toString();
  } catch {
    return null;
  }
}

function readMethod(method: string): 'GET' | 'HEAD' {
  return method.trim().toUpperCase() === 'HEAD' ? 'HEAD' : 'GET';
}

function sameOriginPath(left: string, right: string): boolean {
  try {
    const a = new URL(left);
    const b = new URL(right);
    return a.origin === b.origin && a.pathname === b.pathname;
  } catch {
    return false;
  }
}

function pathnameOf(url: string): string | null {
  try {
    return new URL(url).pathname;
  } catch {
    return null;
  }
}

/**
 * GraphQL detector fans out to default paths unless the URL already
 * contains /graphql or /query, or customPaths pins the observed path.
 */
function graphqlInvocation(
  endpointUrl: string,
  observedGraphqlUrls: readonly string[]
): { readonly customPaths?: readonly string[] } | null {
  const pathname = pathnameOf(endpointUrl);
  if (pathname === null) {
    return null;
  }
  const singleObservedPath =
    pathname.includes('/graphql') || pathname.includes('/query');
  const priorObservation = observedGraphqlUrls.some((candidate) =>
    sameOriginPath(candidate, endpointUrl)
  );
  if (!singleObservedPath && !priorObservation) {
    return null;
  }
  if (singleObservedPath) {
    return {};
  }
  return { customPaths: [pathname] };
}

function keepDetectorOutcome(
  findings: Finding[],
  drafts: EnrichedEvidenceDraft[],
  outcome: DetectorOutcome
): void {
  if (outcome.finding) {
    findings.push(outcome.finding);
    return;
  }
  if (outcome.status === 'pending_human_review' && outcome.evidenceDraft) {
    drafts.push({
      ...outcome.evidenceDraft,
      differentialContext: outcome.context,
    });
  }
}

function observedResourceId(
  entry: ProbeInventoryEntry
): { readonly resourceParamName: string; readonly baselineResourceId: string } | null {
  const parts = entry.path.split('/').filter((part) => part.length > 0);
  if (parts.length < 2) return null;
  const baselineResourceId = parts[parts.length - 1];
  const resourceParamName = parts[parts.length - 2];
  if (!baselineResourceId || !resourceParamName) return null;
  if (!/\d/.test(baselineResourceId)) return null;
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(baselineResourceId)) return null;
  if (!/^[A-Za-z][A-Za-z0-9_-]{0,32}$/.test(resourceParamName)) return null;
  return { resourceParamName, baselineResourceId };
}

function skipList(
  identityA: ProbeAuthContext | undefined,
  identityB: ProbeAuthContext | undefined
): readonly ReadDetectionSkip[] {
  const skipped: ReadDetectionSkip[] = [];
  if (!identityA) {
    skipped.push({
      detector: 'auth_bypass',
      reasonCode: 'identity_a_absent',
    });
    skipped.push({
      detector: 'auth_boundary_differential',
      reasonCode: 'identity_a_absent',
    });
  }
  if (!identityA || !identityB) {
    skipped.push({
      detector: 'idor_differential',
      reasonCode: 'no_single_unauthenticated_read',
    });
    skipped.push({
      detector: 'idor_differential',
      reasonCode: 'two_identity_differential_inconclusive',
    });
  }
  return Object.freeze(skipped);
}

function emptyCompleted(
  skipped: readonly ReadDetectionSkip[],
  reasonCode?: string
): ReadDetectionPassResult {
  return {
    status: 'completed',
    ...(reasonCode ? { reasonCode } : {}),
    findings: Object.freeze([]),
    pendingEvidenceDrafts: Object.freeze([]),
    detectorCallCount: 0,
    invokedDetectors: Object.freeze([]),
    skipped,
  };
}

function circuitOpen(input: RunReadDetectionPassInput): boolean {
  if (!input.coordinator || !input.circuitHost) {
    return false;
  }
  return input.coordinator.isCircuitOpen(input.circuitHost);
}

function sourcemapContext(
  result: SourcemapExposureDetectionResult,
  endpointUrl: string
): DifferentialEvidenceContext {
  return {
    endpointUrl,
    detectionKind: 'sourcemap_exposure',
    sourceJsUrl: result.sourceJsUrl,
    ...(result.exposedMapUrl ? { exposedMapUrl: result.exposedMapUrl } : {}),
    ...(result.sampleSourcesCount !== undefined
      ? { sampleSourcesCount: result.sampleSourcesCount }
      : {}),
    ...(result.mapFileSizeBytes !== undefined
      ? { mapFileSizeBytes: result.mapFileSizeBytes }
      : {}),
  };
}

function observedSourcemapDraft(
  result: SourcemapExposureDetectionResult
): EnrichedEvidenceDraft | null {
  if (result.status !== 'observed' || !result.exposedMapUrl) {
    return null;
  }
  const endpointUrl = result.exposedMapUrl;
  return {
    draftKind: 'non_persisted_comparison_evidence_draft',
    draftId: `dft_smap_${result.detectionId.replace(/[^A-Za-z0-9]/g, '').slice(0, 24)}`,
    suggestedEvidenceType: 'http_difference',
    suggestedStrength: 'moderate',
    sourceComparisonId: `cmp_smap_${result.detectionId.replace(/[^A-Za-z0-9]/g, '').slice(0, 24)}`,
    sourceSnapshotIds: {
      baselineSnapshotId: `snp_smap_${result.detectionId.replace(/[^A-Za-z0-9]/g, '').slice(0, 16)}_base`,
      validationSnapshotId: `snp_smap_${result.detectionId.replace(/[^A-Za-z0-9]/g, '').slice(0, 16)}_val`,
    },
    requiresHumanReview: true,
    notPersisted: true,
    notARealFinding: true,
    notConfirmedEvidence: true,
    notForExternalDelivery: true,
    notM45EvidenceRecord: true,
    safeRationale: `Reachable sourcemap JSON observed for ${result.sourceJsUrl} at ${result.exposedMapUrl}`,
    differentialContext: sourcemapContext(result, endpointUrl),
  };
}

/**
 * Keeps a sourcemap detector result. A Finding or evidence draft already
 * on the result is copied through. An observed map is kept as a draft and
 * is not promoted by this function.
 */
export function retainSourcemapDetectionResult(
  result: SourcemapExposureDetectionResult
): {
  readonly findings: readonly Finding[];
  readonly pendingEvidenceDrafts: readonly EnrichedEvidenceDraft[];
} {
  if (result.finding) {
    return {
      findings: Object.freeze([result.finding]),
      pendingEvidenceDrafts: Object.freeze([]),
    };
  }
  if (result.status === 'pending_human_review' && result.evidenceDraft) {
    const endpointUrl = result.exposedMapUrl ?? result.sourceJsUrl;
    return {
      findings: Object.freeze([]),
      pendingEvidenceDrafts: Object.freeze([
        {
          ...result.evidenceDraft,
          differentialContext: sourcemapContext(result, endpointUrl),
        },
      ]),
    };
  }
  const observed = observedSourcemapDraft(result);
  return {
    findings: Object.freeze([]),
    pendingEvidenceDrafts: observed ? Object.freeze([observed]) : Object.freeze([]),
  };
}

export function graphqlEndpointsFromRecon(
  observations: AggregatedReconObservations
): readonly string[] {
  const found: string[] = [];
  for (const item of observations.urls) {
    found.push(item.url);
  }
  for (const item of observations.webObservations) {
    found.push(item.url);
  }
  for (const item of observations.schemaObservations ?? []) {
    if (item.surfaceKind === 'graphql_type' || item.surfaceKind === 'graphql_query_field') {
      found.push(item.sourceUrl);
    }
  }
  return Object.freeze(found);
}

export async function runReadDetectionPass(
  input: RunReadDetectionPassInput
): Promise<ReadDetectionPassResult> {
  const inventory = parseProbeInventory(input.probeInventory);
  if (!inventory) {
    return {
      status: 'rejected',
      reasonCode: 'malformed_probe_inventory',
      findings: Object.freeze([]),
      pendingEvidenceDrafts: Object.freeze([]),
      detectorCallCount: 0,
      invokedDetectors: Object.freeze([]),
      skipped: Object.freeze([]),
    };
  }

  const skipped = [...skipList(input.identityA, input.identityB)];
  if (inventory.entries.length === 0 || circuitOpen(input)) {
    return emptyCompleted(
      skipped,
      inventory.entries.length === 0 ? 'empty_probe_inventory' : 'circuit_open'
    );
  }

  const findings: Finding[] = [];
  const drafts: EnrichedEvidenceDraft[] = [];
  const invoked: ReadDetectionDetectorName[] = [];
  let detectorCallCount = 0;
  let idorInvoked = false;
  const observedGraphqlUrls = input.observedGraphqlUrls ?? [];
  const lineageFields = {
    assessmentId: input.lineage.assessmentId,
    scanId: input.lineage.scanId,
    authorizationGrantId: input.lineage.authorizationGrantId,
    authorizationDecisionId: input.lineage.authorizationDecisionId,
    actorId: input.lineage.actorId,
  };

  const note = (name: ReadDetectionDetectorName): void => {
    detectorCallCount += 1;
    invoked.push(name);
  };

  for (let index = 0; index < inventory.entries.length; index += 1) {
    if (circuitOpen(input)) {
      break;
    }
    const entry = inventory.entries[index];
    if (!entry) {
      continue;
    }
    const endpointUrl = endpointUrlForEntry(entry);
    if (!endpointUrl) {
      continue;
    }
    const method = readMethod(entry.method);
    const auth = input.identityA ? { authContext: input.identityA } : {};
    const shared = {
      contractVersion: DETECTION_CONTRACT_VERSION,
      detectionId: '',
      ...lineageFields,
      verifiedAuthorizationDecision: input.verifiedAuthorizationDecision,
      scopeGrant: input.scopeGrant,
      transport: input.transport,
      dnsResolver: input.dnsResolver,
      ...(input.coordinator ? { coordinator: input.coordinator } : {}),
    };

    try {
      note('security_header');
      const headerResult = await runSecurityHeaderDetection({
        ...shared,
        kind: 'security_header_detection_request',
        detectionId: `det_rd_hdr_${index}`,
        endpointUrl,
        method,
        ...auth,
      });
      keepDetectorOutcome(findings, drafts, {
        ...(headerResult.finding ? { finding: headerResult.finding } : {}),
        status: headerResult.status,
        ...(headerResult.evidenceDraft ? { evidenceDraft: headerResult.evidenceDraft } : {}),
        context: {
          endpointUrl,
          detectionKind: 'missing_security_headers',
          missingHeaders: headerResult.missingHeaders,
          presentHeaders: headerResult.presentHeaders,
        },
      });
    } catch {
      // Detector failure must not invent a finding.
    }

    if (circuitOpen(input)) break;

    try {
      note('open_redirect');
      const redirectResult = await runOpenRedirectDetection({
        ...shared,
        kind: 'open_redirect_detection_request',
        detectionId: `det_rd_redir_${index}`,
        endpointUrl,
        method,
        ...auth,
      });
      keepDetectorOutcome(findings, drafts, {
        ...(redirectResult.finding ? { finding: redirectResult.finding } : {}),
        status: redirectResult.status,
        ...(redirectResult.evidenceDraft ? { evidenceDraft: redirectResult.evidenceDraft } : {}),
        context: {
          endpointUrl,
          detectionKind: 'open_redirect',
          ...(redirectResult.parameterName ? { parameterName: redirectResult.parameterName } : {}),
          ...(redirectResult.injectedCanary ? { injectedCanary: redirectResult.injectedCanary } : {}),
          ...(redirectResult.finalDestination
            ? { finalDestination: redirectResult.finalDestination }
            : {}),
          ...(redirectResult.redirectChain ? { redirectChain: redirectResult.redirectChain } : {}),
        },
      });
    } catch {
      // Detector failure must not invent a finding.
    }

    if (circuitOpen(input)) break;

    try {
      note('information_disclosure');
      const disclosureResult = await runInformationDisclosureDetection({
        ...shared,
        kind: 'information_disclosure_detection_request',
        detectionId: `det_rd_info_${index}`,
        endpointUrl,
        method,
        ...auth,
      });
      const primary = disclosureResult.disclosures[0];
      keepDetectorOutcome(findings, drafts, {
        ...(disclosureResult.finding ? { finding: disclosureResult.finding } : {}),
        status: disclosureResult.status,
        ...(disclosureResult.evidenceDraft
          ? { evidenceDraft: disclosureResult.evidenceDraft }
          : {}),
        context: {
          endpointUrl,
          detectionKind: 'information_disclosure',
          ...(primary
            ? {
                disclosureKind: primary.disclosureKind,
                disclosedFragment: primary.disclosedFragment,
                trigger: primary.trigger,
              }
            : {}),
        },
      });
    } catch {
      // Detector failure must not invent a finding.
    }

    if (circuitOpen(input)) break;

    try {
      note('cors_misconfiguration');
      const corsResult = await runCorsMisconfigurationDetection({
        ...shared,
        kind: 'cors_misconfiguration_detection_request',
        detectionId: `det_rd_cors_${index}`,
        endpointUrl,
        method,
        ...auth,
      });
      keepDetectorOutcome(findings, drafts, {
        ...(corsResult.finding ? { finding: corsResult.finding } : {}),
        status: corsResult.status,
        ...(corsResult.evidenceDraft ? { evidenceDraft: corsResult.evidenceDraft } : {}),
        context: {
          endpointUrl,
          detectionKind: 'cors_misconfiguration',
          ...(corsResult.reflectedOrigin ? { reflectedOrigin: corsResult.reflectedOrigin } : {}),
          ...(corsResult.allowCredentials !== undefined
            ? { allowCredentials: corsResult.allowCredentials }
            : {}),
        },
      });
    } catch {
      // Detector failure must not invent a finding.
    }

    if (circuitOpen(input)) break;

    for (let paramIndex = 0; paramIndex < entry.parameters.length; paramIndex += 1) {
      const parameterName = entry.parameters[paramIndex];
      if (typeof parameterName !== 'string' || parameterName.length === 0) {
        continue;
      }
      if (circuitOpen(input)) break;
      try {
        note('parameter_reflection');
        const reflectionResult = await runParameterReflectionDetection({
          ...shared,
          kind: 'parameter_reflection_detection_request',
          detectionId: `det_rd_refl_${index}_${paramIndex}`,
          endpointUrl,
          parameterName,
          method,
          ...auth,
        });
        keepDetectorOutcome(findings, drafts, {
          ...(reflectionResult.finding ? { finding: reflectionResult.finding } : {}),
          status: reflectionResult.status,
          ...(reflectionResult.evidenceDraft
            ? { evidenceDraft: reflectionResult.evidenceDraft }
            : {}),
          context: {
            endpointUrl,
            detectionKind: 'parameter_reflection',
            parameterName,
            ...(reflectionResult.reflectedCanary
              ? { reflectedCanary: reflectionResult.reflectedCanary }
              : {}),
          },
        });
      } catch {
        // Detector failure must not invent a finding.
      }
    }

    if (circuitOpen(input)) break;

    const graphql = graphqlInvocation(endpointUrl, observedGraphqlUrls);
    if (graphql) {
      try {
        note('graphql_surface');
        const graphqlResult = await runGraphQLSurfaceDetection({
          ...shared,
          kind: 'graphql_surface_detection_request',
          detectionId: `det_rd_gql_${index}`,
          endpointUrl,
          ...(graphql.customPaths ? { customPaths: graphql.customPaths } : {}),
        });
        keepDetectorOutcome(findings, drafts, {
          ...(graphqlResult.finding ? { finding: graphqlResult.finding } : {}),
          status: graphqlResult.status,
          ...(graphqlResult.evidenceDraft ? { evidenceDraft: graphqlResult.evidenceDraft } : {}),
          context: {
            endpointUrl: graphqlResult.endpointUrl,
            detectionKind: 'graphql_surface',
            introspectionEnabled: graphqlResult.introspectionEnabled,
            batchingEnabled: graphqlResult.batchingEnabled,
            fieldSuggestionsEnabled: graphqlResult.fieldSuggestionsEnabled,
            ...(graphqlResult.discoveredRootTypes
              ? { discoveredRootTypes: graphqlResult.discoveredRootTypes }
              : {}),
            ...(graphqlResult.suggestionLeak ? { suggestionLeak: graphqlResult.suggestionLeak } : {}),
          },
        });
      } catch {
        // Detector failure must not invent a finding.
      }
    }

    if (input.identityA && !circuitOpen(input)) {
      try {
        note('auth_bypass');
        const authResult = await runAuthBypassDetection({
          contractVersion: DETECTION_CONTRACT_VERSION,
          kind: 'auth_bypass_detection_request',
          detectionId: `det_rd_auth_${index}`,
          ...lineageFields,
          verifiedAuthorizationDecision: input.verifiedAuthorizationDecision,
          scopeGrant: input.scopeGrant,
          endpointUrl,
          method,
          identityA: input.identityA,
          transport: input.transport,
          dnsResolver: input.dnsResolver,
        });
        keepDetectorOutcome(findings, drafts, {
          ...(authResult.finding ? { finding: authResult.finding } : {}),
          status: authResult.status,
          ...(authResult.evidenceDraft ? { evidenceDraft: authResult.evidenceDraft } : {}),
          context: {
            endpointUrl: authResult.endpointUrl,
            detectionKind: 'auth_bypass',
            bypassMechanism: authResult.bypassMechanism,
            ...(authResult.similarityRatio !== undefined
              ? { bodySimilarityRatio: authResult.similarityRatio }
              : {}),
          },
        });
      } catch {
        // Detector failure must not invent a finding.
      }
    }

    if (input.identityA && !circuitOpen(input)) {
      try {
        note('auth_boundary_differential');
        await runAuthBoundaryDifferentialDetection({
          contractVersion: DETECTION_CONTRACT_VERSION,
          kind: 'auth_boundary_differential_detection_request',
          detectionId: `det_rd_abnd_${index}`,
          ...lineageFields,
          verifiedAuthorizationDecision: input.verifiedAuthorizationDecision,
          scopeGrant: input.scopeGrant,
          endpointUrl,
          identityA: input.identityA,
          ...(input.identityB ? { identityB: input.identityB } : {}),
          transport: input.transport,
          dnsResolver: input.dnsResolver,
        });
      } catch {
        // Detector failure must not invent a finding.
      }
    }

    if (
      !idorInvoked &&
      input.identityA &&
      input.identityB &&
      !circuitOpen(input)
    ) {
      const resource = observedResourceId(entry);
      if (resource) {
        idorInvoked = true;
        try {
          note('idor_differential');
          const idorResult = await runIdorDifferentialDetection({
            contractVersion: DETECTION_CONTRACT_VERSION,
            kind: 'idor_differential_detection_request',
            detectionId: `det_rd_idor_${index}`,
            ...lineageFields,
            verifiedAuthorizationDecision: input.verifiedAuthorizationDecision,
            scopeGrant: input.scopeGrant,
            endpointUrl,
            method,
            resourceParamName: resource.resourceParamName,
            baselineResourceId: resource.baselineResourceId,
            identityA: input.identityA,
            identityB: input.identityB,
            transport: input.transport,
            dnsResolver: input.dnsResolver,
          });
          keepDetectorOutcome(findings, drafts, {
            ...(idorResult.finding ? { finding: idorResult.finding } : {}),
            status: idorResult.status,
            ...(idorResult.evidenceDraft ? { evidenceDraft: idorResult.evidenceDraft } : {}),
            context: {
              endpointUrl,
              detectionKind: 'idor_access_control',
              resourceParamName: resource.resourceParamName,
              baselineResourceId: resource.baselineResourceId,
            },
          });
        } catch {
          // Detector failure must not invent a finding.
        }
      }
    }
  }

  if (input.identityA && input.identityB && !idorInvoked) {
    skipped.push({
      detector: 'idor_differential',
      reasonCode: 'resource_id_not_observed',
    });
  }

  return {
    status: 'completed',
    findings: Object.freeze([...findings]),
    pendingEvidenceDrafts: Object.freeze([...drafts]),
    detectorCallCount,
    invokedDetectors: Object.freeze([...invoked]),
    skipped: Object.freeze(skipped),
  };
}
