/**
 * Milestone F5 — Real Intelligence Layer: TargetProfileBuilder
 *
 * Consolidates factual Findings and infrastructure Observations into an immutable,
 * structured TargetProfile capturing technologies, endpoints, auth boundaries,
 * and observed flaws.
 */

import { createHash } from 'node:crypto';
import type {
  TargetProfile,
  TargetProfileBuilderInput,
  TargetProfileEndpoint,
  CorsProfileConfiguration,
  AuthRequirementKind,
} from './IntelligenceContracts.js';
import { INTELLIGENCE_CONTRACT_VERSION } from './IntelligenceContracts.js';
import type { Finding } from '../core/Evidence.js';

function sha256(content: string): string {
  return createHash('sha256').update(content).digest('hex');
}

function sanitizeToSafeId(raw: string): string {
  const cleaned = raw.replace(/[^A-Za-z0-9]/g, '').slice(0, 16);
  return cleaned.length > 0 ? cleaned : '001';
}

function extractPathAndParams(targetUrl: string): { path: string; params: string[] } {
  try {
    const parsed = new URL(targetUrl);
    const params: string[] = [];
    parsed.searchParams.forEach((_, key) => {
      if (!params.includes(key)) {
        params.push(key);
      }
    });
    return { path: parsed.pathname || '/', params };
  } catch {
    return { path: '/', params: [] };
  }
}

interface MutableEndpoint {
  url: string;
  path: string;
  method: string;
  parameters: Set<string>;
  authRequirement: AuthRequirementKind;
  corsConfiguration?: CorsProfileConfiguration;
  flawCategories: Set<string>;
}

export function buildTargetProfile(input: TargetProfileBuilderInput): TargetProfile {
  const nowIso = input.buildTimestamp ?? new Date().toISOString();
  const safeSeed = sanitizeToSafeId(input.targetHost);
  const profileId = input.profileId ?? `prof_${safeSeed}_${Date.now().toString(36)}`;

  const findings: readonly Finding[] = input.findings ?? [];
  const rawObservations: readonly unknown[] = input.observations ?? [];

  // 1. Extract and deduplicate technologies
  const technologySet = new Set<string>();

  for (const obs of rawObservations) {
    if (typeof obs === 'object' && obs !== null) {
      const rec = obs as Record<string, unknown>;
      if (Array.isArray(rec.technologies)) {
        for (const t of rec.technologies) {
          if (typeof t === 'string' && t.trim().length > 0) {
            technologySet.add(t.trim());
          }
        }
      }
      if (typeof rec.webServer === 'string' && rec.webServer.trim().length > 0) {
        technologySet.add(rec.webServer.trim());
      }
      if (typeof rec.server === 'string' && rec.server.trim().length > 0) {
        technologySet.add(rec.server.trim());
      }
    }
  }

  // 2. Synthesize and consolidate endpoints
  const endpointMap = new Map<string, MutableEndpoint>();

  function getOrCreateEndpoint(url: string, method: string): MutableEndpoint {
    const { path, params } = extractPathAndParams(url);
    const key = `${method.toUpperCase()}:${path}`;
    let existing = endpointMap.get(key);
    if (!existing) {
      existing = {
        url,
        path,
        method: method.toUpperCase(),
        parameters: new Set(params),
        authRequirement: 'unknown',
        flawCategories: new Set(),
      };
      endpointMap.set(key, existing);
    } else {
      for (const p of params) {
        existing.parameters.add(p);
      }
    }
    return existing;
  }

  // 2a. Ingest endpoints from raw observations
  for (const obs of rawObservations) {
    if (typeof obs === 'object' && obs !== null) {
      const rec = obs as Record<string, unknown>;
      if (typeof rec.url === 'string') {
        const method = typeof rec.method === 'string' ? rec.method : 'GET';
        getOrCreateEndpoint(rec.url, method);
      }
    }
  }

  // 2b. Ingest endpoints and flaw context from canonical Findings
  for (const finding of findings) {
    const ep = getOrCreateEndpoint(finding.target, 'GET');
    const category = typeof finding.metadata?.category === 'string' ? finding.metadata.category : finding.type;
    ep.flawCategories.add(category);

    // Contextual extraction for CORS
    if (category === 'CORS_MISCONFIGURATION' || category === 'SECURITY_MISCONFIGURATION') {
      const allowOrigin = typeof finding.metadata?.reflectedOrigin === 'string'
        ? finding.metadata.reflectedOrigin
        : undefined;
      const allowCredentials = finding.metadata?.allowCredentials === true;
      ep.corsConfiguration = {
        allowOrigin,
        allowCredentials,
      };
    }

    // Contextual extraction for Parameter Reflection
    if (category === 'INPUT_VALIDATION_FLAW' || category === 'PARAMETER_REFLECTION') {
      if (typeof finding.metadata?.parameterName === 'string') {
        ep.parameters.add(finding.metadata.parameterName);
      }
    }

    // Contextual extraction for Broken Access Control
    if (category === 'BROKEN_ACCESS_CONTROL') {
      ep.authRequirement = 'authenticated';
      if (typeof finding.metadata?.resourceParamName === 'string') {
        ep.parameters.add(finding.metadata.resourceParamName);
      }
    }
  }

  // 3. Build immutable endpoint array
  const endpoints: TargetProfileEndpoint[] = Array.from(endpointMap.values())
    .map(e => ({
      url: e.url,
      path: e.path,
      method: e.method,
      parameters: Array.from(e.parameters).sort(),
      authRequirement: e.authRequirement,
      corsConfiguration: e.corsConfiguration,
      flawCategories: Array.from(e.flawCategories).sort(),
    }))
    .sort((a, b) => a.path.localeCompare(b.path));

  const sortedTechnologies = Array.from(technologySet).sort();

  return {
    contractVersion: INTELLIGENCE_CONTRACT_VERSION,
    kind: 'target_profile',
    profileId,
    targetHost: input.targetHost,
    normalizedOrigin: input.normalizedOrigin,
    updatedAt: nowIso,
    technologies: sortedTechnologies,
    endpoints,
    knownFindings: [...findings],
    rawObservations: [...rawObservations],
    lineage: { ...input.lineage },
  };
}

export class TargetProfileBuilder {
  public build(input: TargetProfileBuilderInput): TargetProfile {
    return buildTargetProfile(input);
  }
}

import type { CorrelatedFinding } from './CorrelatedFinding.js';
import type { TargetProfile as LegacyTargetProfile } from './TargetProfile.js';
import type { ProfilerRule } from './ProfilerRule.js';

export interface LegacyTargetProfileBuilder {
  build(correlated: CorrelatedFinding[], targetUri: string): LegacyTargetProfile;
}

export class LocalTargetProfileBuilder implements LegacyTargetProfileBuilder {
  constructor(private rules: ProfilerRule[]) {}

  build(correlated: CorrelatedFinding[], targetUri: string): LegacyTargetProfile {
    let profile: LegacyTargetProfile = {
      targetUri,
      technologies: [],
      discoveredSubdomains: [],
      exposedCapabilities: [],
      sourceFindingIds: [],
      metadata: {
        version: 1,
        lastUpdated: Date.now()
      }
    };

    for (const rule of this.rules) {
      if (rule.applies(correlated)) {
        profile = rule.enrich(profile, correlated);

        // Bump version automatically after a successful rule enrichment
        profile = {
          ...profile,
          metadata: {
            ...profile.metadata,
            version: (profile.metadata.version as number) + 1,
            lastUpdated: Date.now()
          }
        };
      }
    }

    return profile;
  }
}

