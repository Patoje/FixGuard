/**
 * Milestone A2 — Attack Surface Graph Query Service
 *
 * Read-only queries over an immutable AttackSurfaceGraph.
 * All results preserve epistemic status from source nodes/edges.
 */

import type {
  AttackSurfaceGraph,
  AttackSurfaceGraphQueryMatch,
  AsgEdge,
  EndpointNode,
  IdentityNode,
  IpAddressNode,
  EpistemicStatus,
} from './AttackSurfaceContracts.js';

function edgesForNode(graph: AttackSurfaceGraph, nodeId: string): readonly AsgEdge[] {
  return graph.edges.filter((e) => e.fromNodeId === nodeId || e.toNodeId === nodeId);
}

function strongestEpistemic(
  nodeStatus: EpistemicStatus,
  related: readonly AsgEdge[]
): EpistemicStatus {
  const rank: Record<EpistemicStatus, number> = {
    REFUTED: 0,
    INFERRED: 1,
    OBSERVED: 2,
    VERIFIED: 3,
  };
  let best: EpistemicStatus = nodeStatus;
  for (const edge of related) {
    if (rank[edge.epistemicStatus] > rank[best]) {
      best = edge.epistemicStatus;
    }
  }
  return best;
}

export class AttackSurfaceQueryService {
  constructor(private readonly graph: AttackSurfaceGraph) {}

  /**
   * Endpoints that have a linked vulnerability of the given finding type.
   */
  findEndpointsWithFinding(findingType: string): readonly AttackSurfaceGraphQueryMatch<EndpointNode>[] {
    const matches: AttackSurfaceGraphQueryMatch<EndpointNode>[] = [];
    const seenEndpointIds = new Set<string>();
    const vulns = this.graph.nodes.filter(
      (n) => n.kind === 'vulnerability' && n.metadata.findingType === findingType
    );

    for (const vuln of vulns) {
      const linkingEdges = this.graph.edges.filter(
        (e) => e.toNodeId === vuln.id && e.kind === 'has_vulnerability'
      );
      for (const edge of linkingEdges) {
        const endpoint = this.graph.nodes.find(
          (n) => n.id === edge.fromNodeId && n.kind === 'endpoint'
        );
        if (!endpoint || endpoint.kind !== 'endpoint') {
          continue;
        }
        if (seenEndpointIds.has(endpoint.id)) {
          continue;
        }
        seenEndpointIds.add(endpoint.id);
        const related = edgesForNode(this.graph, endpoint.id);
        matches.push({
          node: endpoint,
          epistemicStatus: strongestEpistemic(endpoint.epistemicStatus, [
            edge,
            ...related.filter((e) => e.toNodeId === vuln.id),
          ]),
          relatedEdges: Object.freeze([edge]),
        });
      }
    }

    return Object.freeze(matches);
  }

  /**
   * Identity nodes linked to an endpoint URL via requires_auth / authenticated_by.
   */
  findIdentitiesForEndpoint(url: string): readonly AttackSurfaceGraphQueryMatch<IdentityNode>[] {
    const endpoint = this.graph.nodes.find(
      (n) => n.kind === 'endpoint' && n.metadata.url === url
    );
    if (!endpoint || endpoint.kind !== 'endpoint') {
      return Object.freeze([]);
    }

    const identityEdges = this.graph.edges.filter(
      (e) =>
        e.fromNodeId === endpoint.id &&
        (e.kind === 'requires_auth' || e.kind === 'authenticated_by')
    );

    const matches: AttackSurfaceGraphQueryMatch<IdentityNode>[] = [];
    for (const edge of identityEdges) {
      const identity = this.graph.nodes.find(
        (n) => n.id === edge.toNodeId && n.kind === 'identity'
      );
      if (!identity || identity.kind !== 'identity') {
        continue;
      }
      matches.push({
        node: identity,
        epistemicStatus: strongestEpistemic(identity.epistemicStatus, [edge]),
        relatedEdges: Object.freeze([edge]),
      });
    }

    return Object.freeze(matches);
  }

  /**
   * Endpoints with no has_vulnerability edge (uncovered by findings).
   */
  findUncoveredEndpoints(): readonly AttackSurfaceGraphQueryMatch<EndpointNode>[] {
    const coveredEndpointIds = new Set(
      this.graph.edges
        .filter((e) => e.kind === 'has_vulnerability')
        .map((e) => e.fromNodeId)
    );

    const matches: AttackSurfaceGraphQueryMatch<EndpointNode>[] = [];
    for (const node of this.graph.nodes) {
      if (node.kind !== 'endpoint') {
        continue;
      }
      if (coveredEndpointIds.has(node.id)) {
        continue;
      }
      const related = edgesForNode(this.graph, node.id);
      matches.push({
        node,
        epistemicStatus: strongestEpistemic(node.epistemicStatus, related),
        relatedEdges: related,
      });
    }

    return Object.freeze(matches);
  }

  /**
   * IP hosts reachable from the assessment root via reachable_from / resolves_to.
   */
  findReachableHosts(): readonly AttackSurfaceGraphQueryMatch<IpAddressNode>[] {
    const reachableIpIds = new Set(
      this.graph.edges
        .filter((e) => e.kind === 'reachable_from' || e.kind === 'resolves_to')
        .map((e) => e.toNodeId)
    );

    const matches: AttackSurfaceGraphQueryMatch<IpAddressNode>[] = [];
    for (const node of this.graph.nodes) {
      if (node.kind !== 'ip_address') {
        continue;
      }
      if (!reachableIpIds.has(node.id)) {
        continue;
      }
      const related = edgesForNode(this.graph, node.id).filter(
        (e) => e.kind === 'reachable_from' || e.kind === 'resolves_to'
      );
      matches.push({
        node,
        epistemicStatus: strongestEpistemic(node.epistemicStatus, related),
        relatedEdges: related,
      });
    }

    return Object.freeze(matches);
  }
}
