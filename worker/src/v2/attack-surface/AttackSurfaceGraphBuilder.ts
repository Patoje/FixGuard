/**
 * Milestone A2 — Attack Surface Graph Builder
 *
 * Pure function: maps TargetProfile + recon observations + Findings into an
 * immutable AttackSurfaceGraph. Zero side effects, zero network calls.
 *
 * Epistemic discipline:
 * - Recon-backed entities → OBSERVED
 * - Derived relationships without direct observation → INFERRED
 * - Finding edges use verificationState mapping; never overclaim VERIFIED
 */

import { createHash } from 'node:crypto';
import type { Finding } from '../core/Evidence.js';
import type { VerificationState } from '../core/VerificationStateContracts.js';
import type { TargetProfile } from '../intelligence/IntelligenceContracts.js';
import type { AggregatedReconObservations } from '../recon/orchestration/ActiveReconOrchestrationContracts.js';
import type {
  AsgEdge,
  AsgEdgeKind,
  AsgNode,
  AsgProvenance,
  AsgProvenanceSourceKind,
  AttackSurfaceGraph,
  EpistemicStatus,
} from './AttackSurfaceContracts.js';
import { ATTACK_SURFACE_CONTRACT_VERSION } from './AttackSurfaceContracts.js';

export interface AsgSessionAuthContext {
  /** Stable identity id only — never embed session token material. */
  readonly identityId: string;
  /** Opaque vault/session reference (id/ref only). */
  readonly sessionTokenRef?: string;
  readonly vaultRef?: string;
  readonly createdAt?: string;
}

export interface AttackSurfaceGraphBuilderInput {
  readonly profile: TargetProfile;
  readonly findings: readonly Finding[];
  readonly observations?: Partial<AggregatedReconObservations>;
  readonly builtAt?: string;
  /**
   * Operator-supplied auth/session contexts (BYOT). When present, SessionNode(s)
   * are created and linked to authenticated endpoints via observed_as_accessible_by.
   * Refs/ids only — never embed live tokens.
   */
  readonly authContexts?: readonly AsgSessionAuthContext[];
}

function sha256Short(content: string): string {
  return createHash('sha256').update(content).digest('hex').slice(0, 16);
}

function stableId(prefix: string, parts: readonly string[]): string {
  return `${prefix}_${sha256Short(parts.join('|'))}`;
}

function isIpv4(value: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(value);
}

function mapVerificationToEpistemic(state: VerificationState): EpistemicStatus {
  switch (state) {
    case 'validated_vulnerability':
    case 'exploitability_confirmed':
    case 'impact_confirmed':
      return 'VERIFIED';
    case 'suspected_vulnerability':
      return 'INFERRED';
    case 'observed_anomaly':
      return 'OBSERVED';
    default: {
      const _exhaustive: never = state;
      return _exhaustive;
    }
  }
}

function freshnessToEpistemic(
  freshness: 'live' | 'historical' | 'unknown' | undefined,
  sourceReliability: 'direct_observation' | 'historical_archive' | 'inferred_relationship' | undefined
): EpistemicStatus {
  if (sourceReliability === 'inferred_relationship') {
    return 'INFERRED';
  }
  if (freshness === 'historical' || sourceReliability === 'historical_archive') {
    return 'INFERRED';
  }
  return 'OBSERVED';
}

function baseProvenance(
  profile: TargetProfile,
  sourceKind: AsgProvenanceSourceKind,
  extras?: {
    readonly sourceId?: string;
    readonly observedAt?: string;
    readonly verificationState?: VerificationState;
  }
): AsgProvenance {
  return {
    assessmentId: profile.lineage.assessmentId,
    scanId: profile.lineage.scanId,
    actorId: profile.lineage.actorId,
    authorizationGrantId: profile.lineage.authorizationGrantId,
    authorizationDecisionId: profile.lineage.authorizationDecisionId,
    sourceKind,
    ...(extras?.sourceId ? { sourceId: extras.sourceId } : {}),
    ...(extras?.observedAt ? { observedAt: extras.observedAt } : {}),
    ...(extras?.verificationState ? { verificationState: extras.verificationState } : {}),
  };
}

function extractHostname(urlOrHost: string): string | null {
  try {
    if (urlOrHost.includes('://')) {
      return new URL(urlOrHost).hostname.toLowerCase();
    }
    return urlOrHost.toLowerCase().split('/')[0] ?? null;
  } catch {
    return null;
  }
}

class GraphAccumulator {
  private readonly nodes = new Map<string, AsgNode>();
  private readonly edges = new Map<string, AsgEdge>();

  hasNode(id: string): boolean {
    return this.nodes.has(id);
  }

  addNode(node: AsgNode): AsgNode {
    const existing = this.nodes.get(node.id);
    if (existing) {
      return existing;
    }
    this.nodes.set(node.id, Object.freeze(node));
    return node;
  }

  addEdge(edge: AsgEdge): void {
    if (!edge.epistemicStatus) {
      throw new Error('AsgEdge must carry EpistemicStatus');
    }
    if (this.edges.has(edge.id)) {
      return;
    }
    if (!this.nodes.has(edge.fromNodeId) || !this.nodes.has(edge.toNodeId)) {
      return;
    }
    this.edges.set(edge.id, Object.freeze(edge));
  }

  link(
    kind: AsgEdgeKind,
    fromId: string,
    toId: string,
    epistemicStatus: EpistemicStatus,
    provenance: AsgProvenance,
    label?: string
  ): void {
    const id = stableId('edge', [kind, fromId, toId]);
    this.addEdge({
      id,
      kind,
      fromNodeId: fromId,
      toNodeId: toId,
      epistemicStatus,
      provenance,
      ...(label ? { label } : {}),
    });
  }

  snapshot(): { nodes: readonly AsgNode[]; edges: readonly AsgEdge[] } {
    return {
      nodes: Object.freeze([...this.nodes.values()]),
      edges: Object.freeze([...this.edges.values()]),
    };
  }
}

export const AttackSurfaceGraphBuilder = {
  /**
   * Pure builder: TargetProfile + observations + findings → immutable ASG.
   */
  buildFromAssessmentResults(input: AttackSurfaceGraphBuilderInput): AttackSurfaceGraph {
    const { profile, findings } = input;
    const observations = input.observations ?? {};
    const builtAt = input.builtAt ?? new Date().toISOString();
    const acc = new GraphAccumulator();

    const rootHostname = profile.targetHost.toLowerCase();
    const domainProvenance = baseProvenance(profile, 'target_profile', {
      sourceId: profile.profileId,
      observedAt: profile.updatedAt,
    });

    const domainNode = acc.addNode({
      id: stableId('domain', [rootHostname]),
      kind: 'domain',
      epistemicStatus: 'OBSERVED',
      provenance: domainProvenance,
      label: rootHostname,
      metadata: { hostname: rootHostname },
    });

    const applicationNode = acc.addNode({
      id: stableId('app', [rootHostname, profile.technologies.join(',')]),
      kind: 'application',
      epistemicStatus: 'INFERRED',
      provenance: baseProvenance(profile, 'target_profile', {
        sourceId: profile.profileId,
        observedAt: profile.updatedAt,
      }),
      label: rootHostname,
      metadata: {
        name: rootHostname,
        technologies: [...profile.technologies],
      },
    });

    acc.link(
      'hosts',
      domainNode.id,
      applicationNode.id,
      'INFERRED',
      baseProvenance(profile, 'graph_derivation'),
      'hosts_application'
    );

    // Subdomains
    for (const sub of observations.subdomains ?? []) {
      const hostname = sub.subdomain.toLowerCase();
      const status = freshnessToEpistemic(sub.freshness, sub.sourceReliability);
      const prov = baseProvenance(profile, 'recon_observation', {
        sourceId: hostname,
        observedAt: sub.collectedAt ?? sub.discoveredAt,
      });
      const subNode = acc.addNode({
        id: stableId('subdomain', [hostname]),
        kind: 'subdomain',
        epistemicStatus: status,
        provenance: prov,
        label: hostname,
        metadata: {
          hostname,
          parentDomain: sub.parentDomain.toLowerCase(),
        },
      });
      acc.link('hosts', domainNode.id, subNode.id, status, prov);

      for (const ip of sub.ipAddresses ?? []) {
        const ipNode = acc.addNode({
          id: stableId('ip', [ip]),
          kind: 'ip_address',
          epistemicStatus: status,
          provenance: prov,
          label: ip,
          metadata: { address: ip },
        });
        acc.link('resolves_to', subNode.id, ipNode.id, status, prov);
        acc.link('reachable_from', domainNode.id, ipNode.id, 'INFERRED', prov);
      }
    }

    // DNS A/AAAA → resolves_to
    for (const dns of observations.dnsRecords ?? []) {
      const hostname = dns.domain.toLowerCase();
      const status = freshnessToEpistemic(dns.freshness, dns.sourceReliability);
      const prov = baseProvenance(profile, 'recon_observation', {
        sourceId: `${hostname}:${dns.recordType}`,
        observedAt: dns.collectedAt ?? dns.discoveredAt,
      });

      const hostNode =
        hostname === rootHostname
          ? domainNode
          : acc.addNode({
              id: stableId('subdomain', [hostname]),
              kind: 'subdomain',
              epistemicStatus: status,
              provenance: prov,
              label: hostname,
              metadata: {
                hostname,
                parentDomain: rootHostname,
              },
            });

      if (dns.recordType === 'A' || dns.recordType === 'AAAA') {
        for (const value of dns.values) {
          if (!isIpv4(value) && dns.recordType === 'A') {
            continue;
          }
          const ipNode = acc.addNode({
            id: stableId('ip', [value]),
            kind: 'ip_address',
            epistemicStatus: status,
            provenance: prov,
            label: value,
            metadata: { address: value },
          });
          acc.link('resolves_to', hostNode.id, ipNode.id, status, prov);
          acc.link('reachable_from', domainNode.id, ipNode.id, status, prov);
        }
      }
    }

    // Ports → PortNode + ServiceNode
    for (const portObs of observations.ports ?? []) {
      const status = freshnessToEpistemic(portObs.freshness, portObs.sourceReliability);
      const prov = baseProvenance(profile, 'recon_observation', {
        sourceId: `${portObs.ip}:${portObs.port}`,
        observedAt: portObs.collectedAt ?? portObs.discoveredAt,
      });

      const ipNode = acc.addNode({
        id: stableId('ip', [portObs.ip]),
        kind: 'ip_address',
        epistemicStatus: status,
        provenance: prov,
        label: portObs.ip,
        metadata: { address: portObs.ip },
      });

      const portNode = acc.addNode({
        id: stableId('port', [portObs.ip, String(portObs.port), portObs.protocol]),
        kind: 'port',
        epistemicStatus: status,
        provenance: prov,
        label: `${portObs.ip}:${portObs.port}`,
        metadata: {
          host: portObs.host,
          ip: portObs.ip,
          port: portObs.port,
          protocol: portObs.protocol,
          state: portObs.state,
        },
      });

      acc.link('exposes', ipNode.id, portNode.id, status, prov);

      const serviceName =
        portObs.port === 443 || portObs.port === 80
          ? 'http'
          : `tcp/${portObs.port}`;
      const serviceNode = acc.addNode({
        id: stableId('service', [portObs.ip, String(portObs.port), serviceName]),
        kind: 'service',
        epistemicStatus: 'INFERRED',
        provenance: prov,
        label: serviceName,
        metadata: {
          name: serviceName,
          host: portObs.host,
          port: portObs.port,
        },
      });
      acc.link('serves', portNode.id, serviceNode.id, 'INFERRED', prov);
      acc.link('reachable_from', domainNode.id, ipNode.id, status, prov);
    }

    // Web observations → endpoints + optional service labels
    for (const web of observations.webObservations ?? []) {
      const status = freshnessToEpistemic(web.freshness, web.sourceReliability);
      const prov = baseProvenance(profile, 'recon_observation', {
        sourceId: web.url,
        observedAt: web.collectedAt ?? web.discoveredAt,
      });

      let path = '/';
      try {
        path = new URL(web.url).pathname || '/';
      } catch {
        path = '/';
      }

      const endpointNode = acc.addNode({
        id: stableId('endpoint', [web.method.toUpperCase(), web.url]),
        kind: 'endpoint',
        epistemicStatus: status,
        provenance: prov,
        label: `${web.method.toUpperCase()} ${path}`,
        metadata: {
          url: web.url,
          path,
          method: web.method.toUpperCase(),
          authRequirement: 'unknown',
          flawCategories: [],
        },
      });
      acc.link('exposes', applicationNode.id, endpointNode.id, status, prov);

      if (web.webServer) {
        const serviceNode = acc.addNode({
          id: stableId('service', [rootHostname, web.webServer]),
          kind: 'service',
          epistemicStatus: status,
          provenance: prov,
          label: web.webServer,
          metadata: {
            name: web.webServer,
            host: rootHostname,
          },
        });
        acc.link('serves', applicationNode.id, serviceNode.id, status, prov);
      }

      if (web.resolvedIp) {
        const ipNode = acc.addNode({
          id: stableId('ip', [web.resolvedIp]),
          kind: 'ip_address',
          epistemicStatus: status,
          provenance: prov,
          label: web.resolvedIp,
          metadata: { address: web.resolvedIp },
        });
        acc.link('resolves_to', domainNode.id, ipNode.id, status, prov);
        acc.link('reachable_from', domainNode.id, ipNode.id, status, prov);
      }
    }

    // URL observations → endpoints (may be historical → INFERRED)
    for (const urlObs of observations.urls ?? []) {
      const status = freshnessToEpistemic(urlObs.freshness, urlObs.sourceReliability);
      const prov = baseProvenance(profile, 'recon_observation', {
        sourceId: urlObs.url,
        observedAt: urlObs.collectedAt ?? urlObs.discoveredAt,
      });
      const endpointNode = acc.addNode({
        id: stableId('endpoint', ['GET', urlObs.url]),
        kind: 'endpoint',
        epistemicStatus: status,
        provenance: prov,
        label: `GET ${urlObs.path || '/'}`,
        metadata: {
          url: urlObs.url,
          path: urlObs.path || '/',
          method: 'GET',
          authRequirement: 'unknown',
          flawCategories: [],
        },
      });
      acc.link('exposes', applicationNode.id, endpointNode.id, status, prov);
    }

    // Profile endpoints (authoritative consolidation)
    for (const ep of profile.endpoints) {
      const prov = baseProvenance(profile, 'target_profile', {
        sourceId: ep.url,
        observedAt: profile.updatedAt,
      });
      const endpointNode = acc.addNode({
        id: stableId('endpoint', [ep.method.toUpperCase(), ep.url]),
        kind: 'endpoint',
        epistemicStatus: 'OBSERVED',
        provenance: prov,
        label: `${ep.method.toUpperCase()} ${ep.path}`,
        metadata: {
          url: ep.url,
          path: ep.path,
          method: ep.method.toUpperCase(),
          authRequirement: ep.authRequirement,
          flawCategories: [...ep.flawCategories],
        },
      });
      acc.link('exposes', applicationNode.id, endpointNode.id, 'OBSERVED', prov);

      for (const paramName of ep.parameters) {
        const paramNode = acc.addNode({
          id: stableId('param', [ep.url, ep.method, paramName]),
          kind: 'parameter',
          epistemicStatus: 'OBSERVED',
          provenance: prov,
          label: paramName,
          metadata: {
            name: paramName,
            endpointUrl: ep.url,
            method: ep.method.toUpperCase(),
          },
        });
        acc.link('accepts', endpointNode.id, paramNode.id, 'OBSERVED', prov);
      }

      if (ep.authRequirement === 'authenticated') {
        const identityNode = acc.addNode({
          id: stableId('identity', [ep.url, 'authenticated_session']),
          kind: 'identity',
          epistemicStatus: 'INFERRED',
          provenance: baseProvenance(profile, 'graph_derivation', { sourceId: ep.url }),
          label: `auth:${ep.path}`,
          metadata: {
            identityKind: 'authenticated_session',
            label: `authenticated session for ${ep.path}`,
          },
        });
        acc.link(
          'requires_auth',
          endpointNode.id,
          identityNode.id,
          'INFERRED',
          baseProvenance(profile, 'graph_derivation', { sourceId: ep.url })
        );
        acc.link(
          'authenticated_by',
          endpointNode.id,
          identityNode.id,
          'INFERRED',
          baseProvenance(profile, 'graph_derivation', { sourceId: ep.url })
        );
      }
    }

    // Parameter discovery observations
    for (const paramObs of observations.parameters ?? []) {
      const status = freshnessToEpistemic(paramObs.freshness, paramObs.sourceReliability);
      const prov = baseProvenance(profile, 'recon_observation', {
        sourceId: `${paramObs.url}:${paramObs.parameterName}`,
        observedAt: paramObs.collectedAt ?? paramObs.discoveredAt,
      });
      const endpointId = stableId('endpoint', [paramObs.method.toUpperCase(), paramObs.url]);
      if (!acc.hasNode(endpointId)) {
        let path = '/';
        try {
          path = new URL(paramObs.url).pathname || '/';
        } catch {
          path = '/';
        }
        acc.addNode({
          id: endpointId,
          kind: 'endpoint',
          epistemicStatus: status,
          provenance: prov,
          label: `${paramObs.method.toUpperCase()} ${path}`,
          metadata: {
            url: paramObs.url,
            path,
            method: paramObs.method.toUpperCase(),
            authRequirement: 'unknown',
            flawCategories: [],
          },
        });
        acc.link('exposes', applicationNode.id, endpointId, status, prov);
      }
      const paramNode = acc.addNode({
        id: stableId('param', [paramObs.url, paramObs.method, paramObs.parameterName]),
        kind: 'parameter',
        epistemicStatus: status,
        provenance: prov,
        label: paramObs.parameterName,
        metadata: {
          name: paramObs.parameterName,
          endpointUrl: paramObs.url,
          method: paramObs.method.toUpperCase(),
        },
      });
      acc.link('accepts', endpointId, paramNode.id, status, prov);
    }

    // Findings → VulnerabilityNode + has_vulnerability / enables_attack
    for (const finding of findings) {
      const epistemic = mapVerificationToEpistemic(finding.verificationState);
      const prov = baseProvenance(profile, 'finding', {
        sourceId: finding.id,
        verificationState: finding.verificationState,
      });

      const vulnNode = acc.addNode({
        id: stableId('vuln', [finding.id]),
        kind: 'vulnerability',
        epistemicStatus: epistemic,
        provenance: prov,
        label: finding.title,
        metadata: {
          findingId: finding.id,
          findingType: finding.type,
          title: finding.title,
          target: finding.target,
          verificationState: finding.verificationState,
        },
      });

      const endpointMatch =
        profile.endpoints.find((ep) => ep.url === finding.target) ??
        profile.endpoints.find((ep) => {
          try {
            const findingUrl = new URL(
              finding.target.includes('://') ? finding.target : `https://${finding.target}`
            );
            const epUrl = new URL(ep.url);
            return (
              findingUrl.hostname === epUrl.hostname &&
              findingUrl.pathname === epUrl.pathname
            );
          } catch {
            return false;
          }
        });

      if (endpointMatch) {
        const endpointId = stableId('endpoint', [
          endpointMatch.method.toUpperCase(),
          endpointMatch.url,
        ]);
        // Ensure endpoint exists before linking
        if (!acc.hasNode(endpointId)) {
          const provEp = baseProvenance(profile, 'finding', {
            sourceId: finding.id,
            verificationState: finding.verificationState,
          });
          acc.addNode({
            id: endpointId,
            kind: 'endpoint',
            epistemicStatus: epistemic,
            provenance: provEp,
            label: `${endpointMatch.method.toUpperCase()} ${endpointMatch.path}`,
            metadata: {
              url: endpointMatch.url,
              path: endpointMatch.path,
              method: endpointMatch.method.toUpperCase(),
              authRequirement: endpointMatch.authRequirement,
              flawCategories: [...endpointMatch.flawCategories],
            },
          });
        }
        acc.link('has_vulnerability', endpointId, vulnNode.id, epistemic, prov);
        acc.link('enables_attack', endpointId, vulnNode.id, 'INFERRED', prov);
      } else {
        acc.link('has_vulnerability', applicationNode.id, vulnNode.id, epistemic, prov);
        acc.link('enables_attack', applicationNode.id, vulnNode.id, 'INFERRED', prov);
      }
    }

    // Session nodes from operator-supplied auth contexts (refs/ids only)
    const authContexts = input.authContexts ?? [];
    for (const authCtx of authContexts) {
      if (typeof authCtx.identityId !== 'string' || authCtx.identityId.trim().length === 0) {
        continue;
      }
      const identityId = authCtx.identityId.trim();
      const sessionCreatedAt = authCtx.createdAt ?? profile.updatedAt;
      const sessionProv = baseProvenance(profile, 'target_profile', {
        sourceId: identityId,
        observedAt: sessionCreatedAt,
      });
      const sessionNode = acc.addNode({
        id: stableId('session', [identityId]),
        kind: 'session',
        epistemicStatus: 'OBSERVED',
        provenance: sessionProv,
        label: `session:${identityId}`,
        metadata: {
          identityId,
          ...(authCtx.sessionTokenRef ? { sessionTokenRef: authCtx.sessionTokenRef } : {}),
          ...(authCtx.vaultRef ? { vaultRef: authCtx.vaultRef } : {}),
          createdAt: sessionCreatedAt,
        },
      });

      for (const ep of profile.endpoints) {
        if (ep.authRequirement !== 'authenticated') {
          continue;
        }
        const endpointId = stableId('endpoint', [ep.method.toUpperCase(), ep.url]);
        if (!acc.hasNode(endpointId)) {
          continue;
        }
        // OBSERVED: operator supplied the session for authorized testing of these endpoints.
        // Does not claim successful access was proven — only that the session was bound for testing.
        acc.link(
          'observed_as_accessible_by',
          endpointId,
          sessionNode.id,
          'OBSERVED',
          sessionProv,
          'session_bound_for_auth_testing'
        );
      }
    }

    const { nodes, edges } = acc.snapshot();
    const graphId = stableId('asg', [
      profile.lineage.assessmentId,
      profile.lineage.scanId,
      String(nodes.length),
      String(edges.length),
    ]);

    return Object.freeze({
      contractVersion: ATTACK_SURFACE_CONTRACT_VERSION,
      kind: 'attack_surface_graph' as const,
      graphId,
      assessmentId: profile.lineage.assessmentId,
      scanId: profile.lineage.scanId,
      targetHost: rootHostname,
      builtAt,
      lineage: { ...profile.lineage },
      nodes,
      edges,
    });
  },
};
