/**
 * Milestone A2 — Attack Surface Graph (ASG) Contracts
 * Contract version: fixguard-attack-surface/v0
 *
 * Typed, immutable graph model for authorized assessment attack surface.
 * Every edge carries mandatory EpistemicStatus. No fabricated severities.
 */

import type { AuthorizedExecutionLineageTuple } from '../detection/DetectionContracts.js';
import type { VerificationState } from '../core/VerificationStateContracts.js';

export type AttackSurfaceContractVersion = 'fixguard-attack-surface/v0';
export const ATTACK_SURFACE_CONTRACT_VERSION: AttackSurfaceContractVersion =
  'fixguard-attack-surface/v0';

/**
 * Epistemic honesty for ASG claims.
 * OBSERVED  — directly recorded from target/recon response
 * INFERRED  — derived relationship without direct confirmation
 * VERIFIED  — corroborated via verified finding / validation lifecycle
 * REFUTED   — previously claimed relationship rejected by evidence
 */
export type EpistemicStatus = 'OBSERVED' | 'INFERRED' | 'VERIFIED' | 'REFUTED' | 'INCONCLUSIVE';

export type AsgNodeKind =
  | 'domain'
  | 'subdomain'
  | 'ip_address'
  | 'port'
  | 'service'
  | 'application'
  | 'endpoint'
  | 'parameter'
  | 'identity'
  | 'session'
  | 'vulnerability'
  | 'data_api_table'
  | 'data_api_rpc'
  | 'auth_boundary'
  /** P2 — a structural grouping of endpoints sharing a path prefix.
   * Purely derived from already-built graph data (graph_derivation
   * provenance), never a confirmed architectural claim — hence always
   * INFERRED. */
  | 'service_boundary';

export type AsgEdgeKind =
  | 'resolves_to'
  | 'hosts'
  | 'serves'
  | 'exposes'
  | 'accepts'
  | 'has_vulnerability'
  | 'requires_auth'
  | 'authenticated_by'
  | 'observed_as_accessible_by'
  | 'reachable_from'
  | 'enables_attack'
  | 'exposes_rest'
  | 'readable_as'
  | 'writable_as'
  /** P2 — service_boundary node to the endpoints it structurally groups. */
  | 'groups';

export type AsgProvenanceSourceKind =
  | 'target_profile'
  | 'recon_observation'
  | 'finding'
  | 'graph_derivation'
  /** P2 — statically extracted from source/bundle code (StaticRouteExtractionService),
   * never a live confirmation. Nodes from this source are always `INFERRED`. */
  | 'static_analysis';

export interface AsgProvenance {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly actorId?: string;
  readonly authorizationGrantId?: string;
  readonly authorizationDecisionId?: string;
  readonly sourceKind: AsgProvenanceSourceKind;
  readonly sourceId?: string;
  readonly observedAt?: string;
  readonly verificationState?: VerificationState;
}

export interface AsgNodeBase {
  readonly id: string;
  readonly kind: AsgNodeKind;
  readonly epistemicStatus: EpistemicStatus;
  readonly provenance: AsgProvenance;
  readonly label: string;
}

export interface DomainNode extends AsgNodeBase {
  readonly kind: 'domain';
  readonly metadata: {
    readonly hostname: string;
  };
}

export interface SubdomainNode extends AsgNodeBase {
  readonly kind: 'subdomain';
  readonly metadata: {
    readonly hostname: string;
    readonly parentDomain: string;
  };
}

export interface IpAddressNode extends AsgNodeBase {
  readonly kind: 'ip_address';
  readonly metadata: {
    readonly address: string;
  };
}

export interface PortNode extends AsgNodeBase {
  readonly kind: 'port';
  readonly metadata: {
    readonly host: string;
    readonly ip: string;
    readonly port: number;
    readonly protocol: 'tcp' | 'udp';
    readonly state: 'open' | 'filtered' | 'closed' | 'unknown';
  };
}

export interface ServiceNode extends AsgNodeBase {
  readonly kind: 'service';
  readonly metadata: {
    readonly name: string;
    readonly host: string;
    readonly port?: number;
  };
}

export interface ApplicationNode extends AsgNodeBase {
  readonly kind: 'application';
  readonly metadata: {
    readonly name: string;
    readonly technologies: readonly string[];
  };
}

/**
 * R2 — Endpoint surface classification (recon-first pivot, read-only).
 * Deterministic, pattern-based classification of what kind of surface an
 * endpoint is, derived only from its path/method — never from a guessed
 * severity or exploitability claim. 'unknown' is the honest default when no
 * pattern matches; this is a descriptive tag, not a finding.
 */
export type EndpointSurfaceKind =
  | 'rest_api'
  | 'graphql_api'
  | 'static_asset'
  | 'auth_boundary'
  | 'admin_or_internal'
  | 'spa_client_route'
  | 'unknown';

export interface EndpointNode extends AsgNodeBase {
  readonly kind: 'endpoint';
  readonly metadata: {
    readonly url: string;
    readonly path: string;
    readonly method: string;
    readonly authRequirement: 'unknown' | 'none' | 'authenticated';
    readonly flawCategories: readonly string[];
    readonly surfaceClassification?: EndpointSurfaceKind;
  };
}

export interface ParameterNode extends AsgNodeBase {
  readonly kind: 'parameter';
  readonly metadata: {
    readonly name: string;
    readonly endpointUrl: string;
    readonly method?: string;
  };
}

export interface IdentityNode extends AsgNodeBase {
  readonly kind: 'identity';
  readonly metadata: {
    readonly identityKind: 'anonymous' | 'authenticated_session' | 'role' | 'unknown';
    readonly label: string;
  };
}

/**
 * Session node — authorized session bound to an identity.
 * Token material is referenced only (sessionTokenRef / vaultRef); never embedded.
 * Populated by AttackSurfaceGraphBuilder when authContexts are supplied.
 */
export interface SessionNode extends AsgNodeBase {
  readonly kind: 'session';
  readonly metadata: {
    readonly identityId: string;
    readonly sessionTokenRef?: string;
    readonly vaultRef?: string;
    readonly createdAt: string;
  };
}

export interface VulnerabilityNode extends AsgNodeBase {
  readonly kind: 'vulnerability';
  readonly metadata: {
    readonly findingId: string;
    readonly findingType: string;
    readonly title: string;
    readonly target: string;
    readonly verificationState: VerificationState;
  };
}

export interface DataApiTableNode extends AsgNodeBase {
  readonly kind: 'data_api_table';
  readonly metadata: {
    readonly tableName: string;
    readonly restBaseUrl: string;
    readonly projectRef?: string;
  };
}

export interface DataApiRpcNode extends AsgNodeBase {
  readonly kind: 'data_api_rpc';
  readonly metadata: {
    readonly rpcName: string;
    readonly restBaseUrl: string;
    readonly projectRef?: string;
  };
}

export interface AuthBoundaryNode extends AsgNodeBase {
  readonly kind: 'auth_boundary';
  readonly metadata: {
    readonly boundaryUrl: string;
    readonly boundaryKind: 'supabase_auth' | 'api' | 'unknown';
  };
}

/**
 * P2 — a structural grouping of endpoints sharing a path prefix (e.g. all
 * `/api/orders/*`). Deterministic, purely from path structure already in
 * the graph — not a claim about actual service/microservice architecture.
 */
export interface ServiceBoundaryNode extends AsgNodeBase {
  readonly kind: 'service_boundary';
  readonly metadata: {
    readonly pathPrefix: string;
    readonly endpointCount: number;
  };
}

export type AsgNode =
  | DomainNode
  | SubdomainNode
  | IpAddressNode
  | PortNode
  | ServiceNode
  | ApplicationNode
  | EndpointNode
  | ParameterNode
  | IdentityNode
  | SessionNode
  | VulnerabilityNode
  | DataApiTableNode
  | DataApiRpcNode
  | AuthBoundaryNode
  | ServiceBoundaryNode;

export interface AsgEdge {
  readonly id: string;
  readonly kind: AsgEdgeKind;
  readonly fromNodeId: string;
  readonly toNodeId: string;
  readonly epistemicStatus: EpistemicStatus;
  readonly provenance: AsgProvenance;
  readonly label?: string;
}

export interface AttackSurfaceGraph {
  readonly contractVersion: AttackSurfaceContractVersion;
  readonly kind: 'attack_surface_graph';
  readonly graphId: string;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly targetHost: string;
  readonly builtAt: string;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly nodes: readonly AsgNode[];
  readonly edges: readonly AsgEdge[];
}

export interface AttackSurfaceGraphQueryMatch<T extends AsgNode = AsgNode> {
  readonly node: T;
  readonly epistemicStatus: EpistemicStatus;
  readonly relatedEdges: readonly AsgEdge[];
}
