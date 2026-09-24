/**
 * Phase D2 — persistence-boundary validation for OrchestratedAssessment + ASG.
 *
 * Fail-closed on forbidden executable/secret keys, missing lineage continuity,
 * and ASG epistemic honesty (OBSERVED vs INFERRED must persist distinctly).
 */

import {
  ATTACK_SURFACE_CONTRACT_VERSION,
  type AttackSurfaceGraph,
  type AsgEdge,
  type AsgNode,
  type EpistemicStatus,
} from '../attack-surface/AttackSurfaceContracts.js';
import {
  ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION,
  type OrchestratedAssessmentRecord,
  type OrchestratedAssessmentStatus,
} from '../application/OrchestratedAssessmentContracts.js';

const FORBIDDEN_PERSISTENCE_KEYS = new Set([
  'binary',
  'args',
  'env',
  'command',
  'shell',
  'stdin',
  'executionRequest',
  'capabilityRequest',
  'execution_request',
  'capability_request',
  'password',
  'rawSecret',
  'rawToken',
  'rawPassword',
  'cookieValue',
  'authorizationHeader',
  'privateKey',
  'sessionToken',
  'apiKey',
  'clientSecret',
]);

const EPISTEMIC_STATUSES = new Set<EpistemicStatus>([
  'OBSERVED',
  'INFERRED',
  'VERIFIED',
  'REFUTED',
]);

const ASSESSMENT_STATUSES = new Set<OrchestratedAssessmentStatus>([
  'pending',
  'running',
  'completed',
  'failed',
  'preflight_denied',
  'circuit_broken',
]);

const ORCHESTRATED_REQUIRED_KEYS = [
  'contractVersion',
  'assessmentId',
  'scanId',
  'targetDomain',
  'status',
  'lineage',
  'stages',
  'timing',
  'errorCount',
  'warningCount',
  'findings',
  'recommendations',
] as const;

const ASG_REQUIRED_KEYS = [
  'contractVersion',
  'kind',
  'graphId',
  'assessmentId',
  'scanId',
  'targetHost',
  'builtAt',
  'lineage',
  'nodes',
  'edges',
] as const;

export function assertNoForbiddenPersistenceKeys(value: unknown, path = 'root'): void {
  if (value === null || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i += 1) {
      assertNoForbiddenPersistenceKeys(value[i], `${path}[${i}]`);
    }
    return;
  }
  const record = value as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (FORBIDDEN_PERSISTENCE_KEYS.has(key)) {
      throw new Error(
        `Persistence validation failed: forbidden key '${key}' at ${path}`
      );
    }
    assertNoForbiddenPersistenceKeys(record[key], `${path}.${key}`);
  }
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

function isExactKeyObject(
  value: unknown,
  requiredKeys: readonly string[],
  optionalKeys: readonly string[] = []
): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const keys = Object.keys(value);
  const allowed = new Set([...requiredKeys, ...optionalKeys]);
  for (const key of keys) {
    if (!allowed.has(key)) {
      return false;
    }
  }
  for (const required of requiredKeys) {
    if (!Object.prototype.hasOwnProperty.call(value, required)) {
      return false;
    }
  }
  return true;
}

function validateLineageTuple(
  lineage: unknown,
  assessmentId: string,
  scanId: string
): boolean {
  if (
    !isExactKeyObject(lineage, [
      'assessmentId',
      'scanId',
      'authorizationGrantId',
      'authorizationDecisionId',
      'actorId',
    ])
  ) {
    return false;
  }
  return (
    lineage.assessmentId === assessmentId &&
    lineage.scanId === scanId &&
    isNonEmptyString(lineage.authorizationGrantId) &&
    isNonEmptyString(lineage.authorizationDecisionId) &&
    isNonEmptyString(lineage.actorId)
  );
}

function validateAsgProvenance(
  provenance: unknown,
  assessmentId: string,
  scanId: string
): boolean {
  if (
    !isExactKeyObject(
      provenance,
      ['assessmentId', 'scanId', 'sourceKind'],
      [
        'actorId',
        'authorizationGrantId',
        'authorizationDecisionId',
        'sourceId',
        'observedAt',
        'verificationState',
      ]
    )
  ) {
    return false;
  }
  return provenance.assessmentId === assessmentId && provenance.scanId === scanId;
}

function validateAsgNode(node: unknown, assessmentId: string, scanId: string): node is AsgNode {
  if (node === null || typeof node !== 'object' || Array.isArray(node)) {
    return false;
  }
  const candidate = node as Record<string, unknown>;
  if (
    !isNonEmptyString(candidate.id) ||
    !isNonEmptyString(candidate.kind) ||
    !isNonEmptyString(candidate.label) ||
    typeof candidate.epistemicStatus !== 'string' ||
    !EPISTEMIC_STATUSES.has(candidate.epistemicStatus as EpistemicStatus)
  ) {
    return false;
  }
  if (!validateAsgProvenance(candidate.provenance, assessmentId, scanId)) {
    return false;
  }
  if (candidate.metadata === null || typeof candidate.metadata !== 'object') {
    return false;
  }
  return true;
}

function validateAsgEdge(edge: unknown, assessmentId: string, scanId: string): edge is AsgEdge {
  if (
    !isExactKeyObject(
      edge,
      ['id', 'kind', 'fromNodeId', 'toNodeId', 'epistemicStatus', 'provenance'],
      ['label']
    )
  ) {
    return false;
  }
  if (
    !isNonEmptyString(edge.id) ||
    !isNonEmptyString(edge.kind) ||
    !isNonEmptyString(edge.fromNodeId) ||
    !isNonEmptyString(edge.toNodeId) ||
    typeof edge.epistemicStatus !== 'string' ||
    !EPISTEMIC_STATUSES.has(edge.epistemicStatus as EpistemicStatus)
  ) {
    return false;
  }
  return validateAsgProvenance(edge.provenance, assessmentId, scanId);
}

export function validateAttackSurfaceGraph(value: unknown): value is AttackSurfaceGraph {
  if (!isExactKeyObject(value, ASG_REQUIRED_KEYS)) {
    return false;
  }
  if (
    value.contractVersion !== ATTACK_SURFACE_CONTRACT_VERSION ||
    value.kind !== 'attack_surface_graph' ||
    !isNonEmptyString(value.graphId) ||
    !isNonEmptyString(value.assessmentId) ||
    !isNonEmptyString(value.scanId) ||
    !isNonEmptyString(value.targetHost) ||
    !isNonEmptyString(value.builtAt) ||
    !Array.isArray(value.nodes) ||
    !Array.isArray(value.edges)
  ) {
    return false;
  }
  if (
    !validateLineageTuple(
      value.lineage,
      value.assessmentId as string,
      value.scanId as string
    )
  ) {
    return false;
  }
  for (const node of value.nodes) {
    if (!validateAsgNode(node, value.assessmentId as string, value.scanId as string)) {
      return false;
    }
  }
  for (const edge of value.edges) {
    if (!validateAsgEdge(edge, value.assessmentId as string, value.scanId as string)) {
      return false;
    }
  }
  return true;
}

export function validateOrchestratedAssessmentRecord(
  value: unknown
): value is OrchestratedAssessmentRecord {
  if (
    !isExactKeyObject(value, ORCHESTRATED_REQUIRED_KEYS, [
      'profile',
      'pendingEvidenceDrafts',
      'attackSurfaceGraph',
      'degradedCapabilities',
      'error',
      'reasonCode',
    ])
  ) {
    return false;
  }
  if (
    value.contractVersion !== ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION ||
    !isNonEmptyString(value.assessmentId) ||
    !isNonEmptyString(value.scanId) ||
    !isNonEmptyString(value.targetDomain) ||
    typeof value.status !== 'string' ||
    !ASSESSMENT_STATUSES.has(value.status as OrchestratedAssessmentStatus) ||
    !Array.isArray(value.stages) ||
    !Array.isArray(value.findings) ||
    !Array.isArray(value.recommendations) ||
    typeof value.errorCount !== 'number' ||
    typeof value.warningCount !== 'number'
  ) {
    return false;
  }
  if (
    !validateLineageTuple(
      value.lineage,
      value.assessmentId as string,
      value.scanId as string
    )
  ) {
    return false;
  }
  if (
    value.timing === null ||
    typeof value.timing !== 'object' ||
    Array.isArray(value.timing) ||
    !isNonEmptyString((value.timing as Record<string, unknown>).startedAt)
  ) {
    return false;
  }
  if (value.attackSurfaceGraph !== undefined) {
    if (!validateAttackSurfaceGraph(value.attackSurfaceGraph)) {
      return false;
    }
    const graph = value.attackSurfaceGraph;
    if (
      graph.assessmentId !== value.assessmentId ||
      graph.scanId !== value.scanId
    ) {
      return false;
    }
  }
  try {
    assertNoForbiddenPersistenceKeys(value);
  } catch {
    return false;
  }
  return true;
}

export function countEpistemicByStatus(
  graph: AttackSurfaceGraph
): Readonly<{
  observed: number;
  inferred: number;
  verified: number;
  refuted: number;
}> {
  let observed = 0;
  let inferred = 0;
  let verified = 0;
  let refuted = 0;
  for (const node of graph.nodes) {
    switch (node.epistemicStatus) {
      case 'OBSERVED':
        observed += 1;
        break;
      case 'INFERRED':
        inferred += 1;
        break;
      case 'VERIFIED':
        verified += 1;
        break;
      case 'REFUTED':
        refuted += 1;
        break;
    }
  }
  return { observed, inferred, verified, refuted };
}

export function cloneForPersistence<T>(value: T): T {
  assertNoForbiddenPersistenceKeys(value);
  return JSON.parse(JSON.stringify(value)) as T;
}
