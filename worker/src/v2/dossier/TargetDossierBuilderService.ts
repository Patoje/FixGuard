/**
 * R3 — Target Dossier Builder (recon-first pivot).
 *
 * Pure, read-only assembly of a TargetDossier from already-computed
 * assessment state (AttackSurfaceGraph, hypotheses, findings). Never
 * dispatches a network call, never mints authorization, never invents a
 * claim — it only reorganizes what the assessment already produced into a
 * single artifact an operator can hand off to manual tooling (Parrot).
 */

import type { Finding } from '../core/Evidence.js';
import type { AttackSurfaceGraph } from '../attack-surface/AttackSurfaceContracts.js';
import { AttackSurfaceQueryService } from '../attack-surface/AttackSurfaceQueryService.js';
import type { SecurityHypothesis } from '../hypothesis-scheduler/HypothesisSchedulerContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import {
  TARGET_DOSSIER_CONTRACT_VERSION,
  type TargetDossier,
  type TargetDossierFindingEntry,
  type TargetDossierHypothesisEntry,
  type TargetDossierSurfaceSummary,
} from './TargetDossierContracts.js';

const DEFAULT_MAX_HYPOTHESES = 50;
const DEFAULT_MAX_UNCLASSIFIED_ENDPOINTS = 50;

export interface BuildTargetDossierInput {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly targetDomain: string;
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly attackSurfaceGraph: AttackSurfaceGraph | null;
  readonly hypotheses: readonly SecurityHypothesis[];
  readonly findings: readonly Finding[];
  readonly maxHypotheses?: number;
  readonly maxUnclassifiedEndpoints?: number;
  readonly generatedAt?: string;
}

function buildSurfaceSummary(
  graph: AttackSurfaceGraph | null,
  maxUnclassified: number
): TargetDossierSurfaceSummary {
  if (!graph) {
    return {
      totalEndpoints: 0,
      byClassification: {
        rest_api: 0,
        graphql_api: 0,
        static_asset: 0,
        auth_boundary: 0,
        admin_or_internal: 0,
        spa_client_route: 0,
        unknown: 0,
      },
      unclassifiedEndpointUrls: Object.freeze([]),
      unclassifiedEndpointUrlsTruncated: false,
    };
  }

  const query = new AttackSurfaceQueryService(graph);
  const byClassification = query.summarizeEndpointSurfaceClassification();
  const totalEndpoints = graph.nodes.filter((n) => n.kind === 'endpoint').length;
  const unclassified = query.findUnclassifiedEndpoints();
  const sampled = unclassified.slice(0, maxUnclassified).map((m) => m.node.metadata.url);

  return {
    totalEndpoints,
    byClassification,
    unclassifiedEndpointUrls: Object.freeze(sampled),
    unclassifiedEndpointUrlsTruncated: unclassified.length > maxUnclassified,
  };
}

function toHypothesisEntry(h: SecurityHypothesis): TargetDossierHypothesisEntry {
  return {
    hypothesisId: h.hypothesisId,
    hypothesisKind: h.hypothesisKind,
    title: h.title,
    epistemicStatus: h.epistemicStatus,
    score: h.score,
    rationale: h.rationale,
    blocked: h.blocked,
    blockReason: h.blockReason,
    deferredToManualValidation: h.deferredToManualValidation === true,
    ...(h.suggestedCapability ? { suggestedCapability: h.suggestedCapability } : {}),
    ...(h.targetUrl ? { targetUrl: h.targetUrl } : {}),
  };
}

function toFindingEntry(f: Finding): TargetDossierFindingEntry {
  return {
    findingId: f.id,
    type: f.type,
    severity: f.severity,
    title: f.title,
    target: f.target,
    confidence: f.confidence,
    verificationState: f.verificationState,
  };
}

/**
 * Assembles a TargetDossier from already-computed assessment state.
 * Deterministic: same input always produces the same ranked output
 * (hypotheses sorted by score desc, tie-broken by hypothesisId).
 */
export function buildTargetDossier(input: BuildTargetDossierInput): TargetDossier {
  const maxHypotheses =
    typeof input.maxHypotheses === 'number' && input.maxHypotheses > 0
      ? Math.floor(input.maxHypotheses)
      : DEFAULT_MAX_HYPOTHESES;
  const maxUnclassified =
    typeof input.maxUnclassifiedEndpoints === 'number' && input.maxUnclassifiedEndpoints > 0
      ? Math.floor(input.maxUnclassifiedEndpoints)
      : DEFAULT_MAX_UNCLASSIFIED_ENDPOINTS;

  const rankedHypotheses = [...input.hypotheses].sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    return a.hypothesisId.localeCompare(b.hypothesisId);
  });

  return Object.freeze({
    contractVersion: TARGET_DOSSIER_CONTRACT_VERSION,
    kind: 'target_dossier' as const,
    dossierId: `dossier_${input.assessmentId}`.slice(0, 64),
    assessmentId: input.assessmentId,
    scanId: input.scanId,
    targetDomain: input.targetDomain,
    generatedAt: input.generatedAt ?? new Date().toISOString(),
    lineage: input.lineage,
    surfaceSummary: buildSurfaceSummary(input.attackSurfaceGraph, maxUnclassified),
    hypotheses: Object.freeze(
      rankedHypotheses.slice(0, maxHypotheses).map(toHypothesisEntry)
    ),
    hypothesesTruncated: rankedHypotheses.length > maxHypotheses,
    findings: Object.freeze(input.findings.map(toFindingEntry)),
    nonClaims: {
      noNewProbingPerformed: true as const,
      noAutonomousExploitation: true as const,
      hypothesesAreAdvisoryOnly: true as const,
      deferredHypothesesRequireManualValidation: true as const,
    },
  });
}
