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
  DiscoveredHostRecord,
  DiscoveredHostPortRecord,
  AuthSurfaceMap,
  AuthSurfacePathRecord,
  HistoricalAssetRecord,
  ExternalDependency,
  InferredHostingProvider,
} from './IntelligenceContracts.js';
import { INTELLIGENCE_CONTRACT_VERSION } from './IntelligenceContracts.js';
import type { Finding } from '../core/Evidence.js';
import { TechnologyFingerprintService } from '../recon/analysis/TechnologyFingerprintService.js';
import {
  classifyAuthPath,
  extractHeaderValue,
  inferHostingProviderFromCname,
  isInferredCdnProvider,
  parseCspHeader,
} from './TargetProfileInference.js';

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

  // 1. Analytical Technology Fingerprinting
  const fingerprintService = new TechnologyFingerprintService();
  const fingerprintResult = fingerprintService.analyze({
    url: input.normalizedOrigin,
    rawObservations,
  });

  const technologySet = new Set<string>();
  for (const t of fingerprintResult.technologies) {
    technologySet.add(t.name);
  }

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

  // 2a-bis. Phase D1 — ingest aggregated URL observations (includes assessment seeds)
  if (input.aggregatedObservations?.urls) {
    for (const urlObs of input.aggregatedObservations.urls) {
      if (typeof urlObs.url === 'string' && urlObs.url.length > 0) {
        getOrCreateEndpoint(urlObs.url, 'GET');
      }
    }
  }

  // 2b. Ingest endpoints and flaw context from canonical Findings
  for (const finding of findings) {
    const ep = getOrCreateEndpoint(finding.target, 'GET');
    const category = typeof finding.metadata?.category === 'string' ? finding.metadata.category : finding.type;
    ep.flawCategories.add(category);

    const meta = finding.metadata;

    // Contextual extraction for CORS
    if (category === 'CORS_MISCONFIGURATION' || category === 'SECURITY_MISCONFIGURATION') {
      const allowOrigin = meta?.kind === 'security_misconfiguration_metadata' && typeof meta.reflectedOrigin === 'string'
        ? meta.reflectedOrigin
        : undefined;
      const allowCredentials = meta?.kind === 'security_misconfiguration_metadata' && meta.allowCredentials === true;
      ep.corsConfiguration = {
        allowOrigin,
        allowCredentials,
      };
    }

    // Contextual extraction for Parameter Reflection
    if (category === 'INPUT_VALIDATION_FLAW' || category === 'PARAMETER_REFLECTION') {
      if (meta?.kind === 'input_validation_flaw_metadata' && typeof meta.parameterName === 'string') {
        ep.parameters.add(meta.parameterName);
      }
    }

    // Contextual extraction for Broken Access Control
    if (category === 'BROKEN_ACCESS_CONTROL') {
      ep.authRequirement = 'authenticated';
      if (meta?.kind === 'broken_access_control_metadata' && typeof meta.resourceParamName === 'string') {
        ep.parameters.add(meta.resourceParamName);
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

  // 4. Milestone A3 — TargetProfile v2 additive enrichment (analytical only, zero network)
  const aggregated = input.aggregatedObservations;
  const discoveredHosts = buildDiscoveredHosts(input.targetHost, aggregated, rawObservations);
  const authSurface = buildAuthSurface(endpoints, aggregated, rawObservations);
  const historicalAssets = buildHistoricalAssets(aggregated);
  const externalDependencies = buildExternalDependencies(aggregated, rawObservations, discoveredHosts);

  return {
    contractVersion: INTELLIGENCE_CONTRACT_VERSION,
    kind: 'target_profile',
    profileId,
    targetHost: input.targetHost,
    normalizedOrigin: input.normalizedOrigin,
    updatedAt: nowIso,
    technologies: sortedTechnologies,
    detectedTechnologies: fingerprintResult.technologies,
    ecosystemProfile: fingerprintResult.ecosystemProfile,
    endpoints,
    knownFindings: [...findings],
    rawObservations: [...rawObservations],
    lineage: { ...input.lineage },
    discoveredHosts,
    authSurface,
    historicalAssets,
    externalDependencies,
  };
}

function buildDiscoveredHosts(
  rootHost: string,
  aggregated: TargetProfileBuilderInput['aggregatedObservations'],
  rawObservations: readonly unknown[]
): readonly DiscoveredHostRecord[] {
  type MutableHost = {
    fqdn: string;
    ips: Set<string>;
    ports: Map<string, DiscoveredHostPortRecord>;
    cnames: Set<string>;
    providers: Set<InferredHostingProvider>;
    asn?: string;
    epistemicStatus: 'OBSERVED' | 'INFERRED';
  };

  const hosts = new Map<string, MutableHost>();

  function ensure(fqdn: string, status: 'OBSERVED' | 'INFERRED'): MutableHost {
    const key = fqdn.toLowerCase();
    let existing = hosts.get(key);
    if (!existing) {
      existing = {
        fqdn: key,
        ips: new Set(),
        ports: new Map(),
        cnames: new Set(),
        providers: new Set(),
        epistemicStatus: status,
      };
      hosts.set(key, existing);
    } else if (status === 'OBSERVED') {
      existing.epistemicStatus = 'OBSERVED';
    }
    return existing;
  }

  ensure(rootHost.toLowerCase(), 'OBSERVED');

  for (const sub of aggregated?.subdomains ?? []) {
    const host = ensure(sub.subdomain, 'OBSERVED');
    for (const ip of sub.ipAddresses ?? []) {
      host.ips.add(ip);
    }
  }

  for (const dns of aggregated?.dnsRecords ?? []) {
    const host = ensure(dns.domain, 'OBSERVED');
    if (dns.recordType === 'A' || dns.recordType === 'AAAA') {
      for (const value of dns.values) {
        host.ips.add(value);
      }
    }
    if (dns.recordType === 'CNAME') {
      for (const value of dns.values) {
        const cleaned = value.replace(/\.$/, '').toLowerCase();
        host.cnames.add(cleaned);
        const provider = inferHostingProviderFromCname(cleaned);
        if (provider !== 'unknown') {
          host.providers.add(provider);
        }
      }
    }
  }

  for (const port of aggregated?.ports ?? []) {
    const host = ensure(port.host || rootHost, 'OBSERVED');
    host.ips.add(port.ip);
    const portKey = `${port.protocol}:${port.port}`;
    host.ports.set(portKey, {
      port: port.port,
      protocol: port.protocol,
      state: port.state,
    });
  }

  for (const obs of rawObservations) {
    if (typeof obs !== 'object' || obs === null) continue;
    const rec = obs as Record<string, unknown>;
    if (typeof rec.domain === 'string' && rec.recordType === 'CNAME' && Array.isArray(rec.values)) {
      const host = ensure(rec.domain, 'OBSERVED');
      for (const value of rec.values) {
        if (typeof value !== 'string') continue;
        const cleaned = value.replace(/\.$/, '').toLowerCase();
        host.cnames.add(cleaned);
        const provider = inferHostingProviderFromCname(cleaned);
        if (provider !== 'unknown') {
          host.providers.add(provider);
        }
      }
    }
    if (typeof rec.subdomain === 'string') {
      const host = ensure(rec.subdomain, 'OBSERVED');
      if (Array.isArray(rec.ipAddresses)) {
        for (const ip of rec.ipAddresses) {
          if (typeof ip === 'string') host.ips.add(ip);
        }
      }
    }
  }

  return Array.from(hosts.values())
    .map((h) => {
      let provider: InferredHostingProvider | undefined;
      for (const p of h.providers) {
        provider = p;
        break;
      }
      return {
        fqdn: h.fqdn,
        ipAddresses: Array.from(h.ips).sort(),
        ports: Array.from(h.ports.values()).sort((a, b) => a.port - b.port),
        cnameTargets: Array.from(h.cnames).sort(),
        ...(provider ? { inferredHostingProvider: provider } : {}),
        ...(provider && isInferredCdnProvider(provider) ? { inferredCdn: true } : {}),
        ...(h.asn ? { asn: h.asn } : {}),
        epistemicStatus: h.epistemicStatus,
      };
    })
    .sort((a, b) => a.fqdn.localeCompare(b.fqdn));
}

function buildAuthSurface(
  endpoints: readonly TargetProfileEndpoint[],
  aggregated: TargetProfileBuilderInput['aggregatedObservations'],
  rawObservations: readonly unknown[]
): AuthSurfaceMap {
  const buckets: {
    loginPaths: AuthSurfacePathRecord[];
    oauthPaths: AuthSurfacePathRecord[];
    ssoPaths: AuthSurfacePathRecord[];
    registrationPaths: AuthSurfacePathRecord[];
    passwordResetPaths: AuthSurfacePathRecord[];
    otherAuthPaths: AuthSurfacePathRecord[];
  } = {
    loginPaths: [],
    oauthPaths: [],
    ssoPaths: [],
    registrationPaths: [],
    passwordResetPaths: [],
    otherAuthPaths: [],
  };

  const seen = new Set<string>();

  function addPath(
    path: string,
    url: string | undefined,
    source: AuthSurfacePathRecord['source'],
    formHints: readonly string[] = []
  ): void {
    const bucket = classifyAuthPath(path);
    if (!bucket) return;
    const key = `${bucket}:${path}`;
    if (seen.has(key)) return;
    seen.add(key);
    buckets[bucket].push({
      path,
      ...(url ? { url } : {}),
      source,
      formHints: [...formHints],
    });
  }

  for (const ep of endpoints) {
    addPath(ep.path, ep.url, 'endpoint_observation');
  }

  for (const urlObs of aggregated?.urls ?? []) {
    addPath(urlObs.path, urlObs.url, 'url_observation');
  }

  for (const obs of rawObservations) {
    if (typeof obs !== 'object' || obs === null) continue;
    const rec = obs as Record<string, unknown>;
    if (typeof rec.path === 'string') {
      const url = typeof rec.url === 'string' ? rec.url : undefined;
      addPath(rec.path, url, 'url_observation');
    } else if (typeof rec.url === 'string') {
      try {
        const parsed = new URL(rec.url);
        addPath(parsed.pathname || '/', rec.url, 'url_observation');
      } catch {
        // ignore malformed
      }
    }
  }

  if (
    buckets.loginPaths.length === 0 &&
    buckets.oauthPaths.length === 0 &&
    buckets.ssoPaths.length === 0 &&
    buckets.registrationPaths.length === 0 &&
    buckets.passwordResetPaths.length === 0 &&
    buckets.otherAuthPaths.length === 0
  ) {
    for (const wellKnown of ['/login', '/oauth/authorize', '/sso', '/register', '/password/reset']) {
      addPath(wellKnown, undefined, 'well_known_heuristic');
    }
  }

  return {
    loginPaths: buckets.loginPaths.sort((a, b) => a.path.localeCompare(b.path)),
    oauthPaths: buckets.oauthPaths.sort((a, b) => a.path.localeCompare(b.path)),
    ssoPaths: buckets.ssoPaths.sort((a, b) => a.path.localeCompare(b.path)),
    registrationPaths: buckets.registrationPaths.sort((a, b) => a.path.localeCompare(b.path)),
    passwordResetPaths: buckets.passwordResetPaths.sort((a, b) => a.path.localeCompare(b.path)),
    otherAuthPaths: buckets.otherAuthPaths.sort((a, b) => a.path.localeCompare(b.path)),
  };
}

function buildHistoricalAssets(
  aggregated: TargetProfileBuilderInput['aggregatedObservations']
): readonly HistoricalAssetRecord[] {
  const assets: HistoricalAssetRecord[] = [];
  for (const urlObs of aggregated?.urls ?? []) {
    const freshness = urlObs.freshness ?? 'unknown';
    const sourceReliability =
      urlObs.sourceReliability ??
      (freshness === 'historical' ? 'historical_archive' : 'direct_observation');
    if (freshness !== 'historical' && sourceReliability !== 'historical_archive') {
      continue;
    }
    assets.push({
      url: urlObs.url,
      host: urlObs.host,
      path: urlObs.path,
      ...(urlObs.query ? { query: urlObs.query } : {}),
      sources: [...urlObs.sources],
      freshness,
      sourceReliability,
      discoveredAt: urlObs.discoveredAt,
      ...(urlObs.collectedAt ? { collectedAt: urlObs.collectedAt } : {}),
    });
  }
  return assets.sort((a, b) => a.url.localeCompare(b.url));
}

function cspKindForDirective(directive: string): ExternalDependency['kind'] {
  switch (directive) {
    case 'script-src':
      return 'csp_script_src';
    case 'connect-src':
      return 'csp_connect_src';
    case 'frame-src':
      return 'csp_frame_src';
    case 'img-src':
      return 'csp_img_src';
    default:
      return 'csp_other';
  }
}

function buildExternalDependencies(
  aggregated: TargetProfileBuilderInput['aggregatedObservations'],
  rawObservations: readonly unknown[],
  discoveredHosts: readonly DiscoveredHostRecord[]
): readonly ExternalDependency[] {
  const deps: ExternalDependency[] = [];
  const seen = new Set<string>();

  function add(dep: ExternalDependency): void {
    const key = `${dep.kind}|${dep.value}|${dep.sourceHost ?? ''}`;
    if (seen.has(key)) return;
    seen.add(key);
    deps.push(dep);
  }

  function ingestHeaders(
    headers: Readonly<Record<string, string | string[] | undefined>> | undefined,
    sourceHost?: string
  ): void {
    const csp = extractHeaderValue(headers, 'content-security-policy');
    if (!csp) return;
    const parsed = parseCspHeader(csp);
    for (const [directive, sources] of parsed.entries()) {
      for (const source of sources) {
        if (source.startsWith("'") || source === '*' || source === 'data:' || source === 'blob:') {
          continue;
        }
        let hostValue = source;
        try {
          if (source.includes('://')) {
            hostValue = new URL(source).hostname;
          }
        } catch {
          hostValue = source;
        }
        const provider = inferHostingProviderFromCname(hostValue);
        add({
          kind: cspKindForDirective(directive),
          value: hostValue,
          epistemicStatus: 'OBSERVED',
          ...(sourceHost ? { sourceHost } : {}),
          ...(provider !== 'unknown' ? { inferredProvider: provider } : {}),
        });
      }
    }
  }

  for (const web of aggregated?.webObservations ?? []) {
    let host: string | undefined;
    try {
      host = new URL(web.url).hostname;
    } catch {
      host = undefined;
    }
    ingestHeaders(web.headers, host);
  }

  for (const obs of rawObservations) {
    if (typeof obs !== 'object' || obs === null) continue;
    const rec = obs as Record<string, unknown>;
    if (rec.headers && typeof rec.headers === 'object' && !Array.isArray(rec.headers)) {
      let host: string | undefined;
      if (typeof rec.url === 'string') {
        try {
          host = new URL(rec.url).hostname;
        } catch {
          host = undefined;
        }
      }
      const headerEntries: Record<string, string | string[] | undefined> = {};
      for (const [k, v] of Object.entries(rec.headers)) {
        if (typeof v === 'string' || Array.isArray(v) || v === undefined) {
          headerEntries[k] = v;
        }
      }
      ingestHeaders(headerEntries, host);
    }
  }

  for (const host of discoveredHosts) {
    for (const cname of host.cnameTargets) {
      const provider = inferHostingProviderFromCname(cname);
      add({
        kind: 'cname_cloud',
        value: cname,
        ...(provider !== 'unknown' ? { inferredProvider: provider } : {}),
        sourceHost: host.fqdn,
        epistemicStatus: 'INFERRED',
      });
    }
  }

  return deps.sort((a, b) => `${a.kind}:${a.value}`.localeCompare(`${b.kind}:${b.value}`));
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

