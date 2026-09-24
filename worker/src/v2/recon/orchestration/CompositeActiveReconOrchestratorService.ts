/**
 * Milestone 73 — Composite Active Reconnaissance Orchestrator Application Service
 *
 * Chains the 9 Layer 6 tool adapters across 5 staged discovery phases:
 * Stage 1: Domain & Zone Enumeration (Subfinder + Dnsx)
 * Stage 2: Port & Service Discovery (Naabu)
 * Stage 3: HTTP & TLS Inspection (Httpx + Tlsx)
 * Stage 4: Surface Crawling & Parameter Discovery (Composite URL + Ffuf + Arjun)
 * Stage 5: Secret & Credential Inspection (Trufflehog)
 *
 * Enforces atomic preflight (F1), concurrency & rate-limiting (F3), session lifecycle (F3),
 * graceful stage containment, and unbroken lineage preservation.
 */

import { runAdapterPreflight, FQDN_REGEX, extractHost } from '../adapters/AdapterPreflightPipeline.js';
import { isInternalOrSsrfTarget } from '../policy/PassiveEgressPolicy.js';
import { validateSessionHealth } from '../../core/SessionLifecycleService.js';
import { TargetExecutionCoordinator } from '../../runtime/TargetExecutionCoordinator.js';
import {
  CIRCUIT_OPEN_REASON_CODE,
  TargetInstabilityError,
} from '../../runtime/CircuitBreakerContracts.js';

import type {
  ActiveReconOrchestrationRequest,
  ActiveReconOrchestrationResult,
  ReconToolAdapters,
  ReconStageExecutionResult,
  OrchestratedReconEvidenceDraft,
  AggregatedReconObservations,
  ReconStageName,
} from './ActiveReconOrchestrationContracts.js';
import {
  ACTIVE_RECON_ORCHESTRATION_CONTRACT_VERSION,
  RECON_ORCHESTRATION_NON_CLAIMS,
} from './ActiveReconOrchestrationContracts.js';

import type {
  SubdomainDiscoveryResult,
  DiscoveredSubdomainObservation,
} from '../adapters/SubdomainDiscoveryContracts.js';
import type {
  DnsResolutionResult,
  DiscoveredDnsObservation,
} from '../adapters/DnsResolutionContracts.js';
import type {
  PortDiscoveryResult,
  DiscoveredPortObservation,
} from '../adapters/PortDiscoveryContracts.js';
import type {
  WebInspectionResult,
  DiscoveredWebObservation,
} from '../adapters/WebInspectionContracts.js';
import type {
  TlsInspectionResult,
  DiscoveredTlsObservation,
} from '../adapters/TlsInspectionContracts.js';
import type {
  UrlDiscoveryResult,
  DiscoveredUrlObservation,
} from '../adapters/UrlDiscoveryContracts.js';
import type {
  ContentDiscoveryResult,
  DiscoveredContentObservation,
} from '../adapters/ContentDiscoveryContracts.js';
import type {
  ParameterDiscoveryResult,
  DiscoveredParameterObservation,
} from '../adapters/ParameterDiscoveryContracts.js';
import type {
  SecretDiscoveryResult,
  DiscoveredSecretObservation,
} from '../adapters/SecretDiscoveryContracts.js';
import type {
  BrowserAutomationResult,
  DiscoveredSpaObservation,
} from '../adapters/BrowserAutomationContracts.js';
import {
  PLAYWRIGHT_SPA_SOURCE,
  RSC_DISCOVERY_SOURCE,
  SPA_DISCOVERY_MAX_PAGES,
} from '../adapters/BrowserAutomationContracts.js';
import type { AuthorizedScopeGrant } from '../../scope/AuthorizedScopeContracts.js';
import {
  HTML_LINK_EXTRACTION_SOURCE,
  HTML_ROUTE_EXTRACTION_MAX_HOP2,
  HTML_ROUTE_EXTRACTION_MAX_PER_STAGE,
  HtmlRouteExtractionService,
  isHtmlStaticBundlePath,
} from '../analysis/HtmlRouteExtractionService.js';
import { isBrowserUrlAllowed } from '../adapters/PlaywrightSpaAdapter.js';

function sanitizeToSafeId(raw: string): string {
  const cleaned = raw.replace(/[^A-Za-z0-9]/g, '').slice(0, 16);
  return cleaned.length > 0 ? cleaned : 'target';
}

/** Heuristic Next.js / RSC signals from Stage 3 web observations (pre-fingerprint). */
function webObservationHasNextSignals(obs: DiscoveredWebObservation): boolean {
  const headers = obs.headers ?? {};
  const poweredBy = headers['x-powered-by'] ?? '';
  if (/next\.?js/i.test(poweredBy)) return true;
  if (headers['x-nextjs-cache'] !== undefined || headers['x-nextjs-matched-path'] !== undefined) {
    return true;
  }
  const vary = headers['vary'] ?? '';
  if (/rsc|next-router/i.test(vary)) return true;
  if ((obs.technologies ?? []).some((t) => /next\.?js/i.test(t))) return true;
  const body = obs.bodyText ?? '';
  if (body.includes('__NEXT_DATA__') || body.includes('/_next/static/') || body.includes('self.__next_f')) {
    return true;
  }
  return false;
}

function shouldEnableSpaDiscovery(
  request: {
    readonly seedUrls?: readonly string[];
    readonly config?: { readonly enableSpaDiscovery?: boolean };
  },
  webObservations: readonly DiscoveredWebObservation[]
): boolean {
  if (request.config?.enableSpaDiscovery === false) return false;
  if (request.config?.enableSpaDiscovery === true) return true;
  if (request.seedUrls && request.seedUrls.length > 0) return true;
  return webObservations.some(webObservationHasNextSignals);
}

/**
 * Select capped Playwright navigation targets: seeds first, then in-scope app
 * endpoints (never /_next/static). Fail-closed via isBrowserUrlAllowed.
 */
function selectSpaDiscoveryPages(input: {
  readonly seedUrls: readonly string[];
  readonly inventoryUrls: readonly { readonly url: string; readonly path?: string }[];
  readonly rootUrls: readonly string[];
  readonly authorizedScopeGrant: AuthorizedScopeGrant;
  readonly maxPages: number;
}): readonly string[] {
  const selected: string[] = [];
  const seen = new Set<string>();

  const tryAdd = (url: string): void => {
    if (selected.length >= input.maxPages) return;
    if (seen.has(url)) return;
    if (!isBrowserUrlAllowed(url, input.authorizedScopeGrant)) return;
    try {
      const parsed = new URL(url);
      if (isHtmlStaticBundlePath(parsed.pathname)) return;
    } catch {
      return;
    }
    seen.add(url);
    selected.push(url);
  };

  for (const seed of input.seedUrls) {
    tryAdd(seed);
  }
  for (const entry of input.inventoryUrls) {
    tryAdd(entry.url);
  }
  // Fallback: roots when no seeds/inventory yet (Next.js signal-only enable).
  if (selected.length === 0) {
    for (const root of input.rootUrls) {
      tryAdd(root);
    }
  }

  return Object.freeze(selected);
}

function normalizeHostname(raw: string): string | null {
  let cleaned = raw.trim().toLowerCase();
  if (cleaned.startsWith('*.')) cleaned = cleaned.slice(2);
  cleaned = cleaned.replace(/\.$/, '');
  if (!cleaned || !FQDN_REGEX.test(cleaned)) return null;
  if (isInternalOrSsrfTarget(cleaned)) return null;
  return cleaned;
}

function isHostnameInAuthorizedScope(host: string, grant: AuthorizedScopeGrant): boolean {
  const allowedDomains = (grant.boundaries.allowedDomains ?? []).map((d) =>
    d.trim().toLowerCase().replace(/\.$/, '')
  );
  const allowedHosts = (grant.boundaries.allowedHosts ?? []).map((h) =>
    h.trim().toLowerCase().replace(/\.$/, '')
  );
  const subjectDomain = grant.subject.domain?.trim().toLowerCase().replace(/\.$/, '');
  const subjectHost = grant.subject.host?.trim().toLowerCase().replace(/\.$/, '');

  const originHosts: string[] = [];
  for (const origin of grant.boundaries.allowedOrigins ?? []) {
    const h = extractHost(origin);
    if (h) originHosts.push(h);
  }

  return (
    allowedDomains.includes(host) ||
    allowedDomains.some((d) => host === d || host.endsWith('.' + d)) ||
    allowedHosts.includes(host) ||
    subjectDomain === host ||
    (subjectDomain !== undefined && host.endsWith('.' + subjectDomain)) ||
    subjectHost === host ||
    originHosts.includes(host) ||
    originHosts.some((h) => host === h || host.endsWith('.' + h))
  );
}

function mergeSubdomainObservation(
  bucket: DiscoveredSubdomainObservation[],
  index: Map<string, number>,
  obs: DiscoveredSubdomainObservation
): void {
  const existingIdx = index.get(obs.subdomain);
  if (existingIdx === undefined) {
    index.set(obs.subdomain, bucket.length);
    bucket.push(obs);
    return;
  }
  const existing = bucket[existingIdx]!;
  const mergedSources = new Set<string>([...(existing.sources ?? []), ...(obs.sources ?? [])]);
  const mergedIps = new Set<string>([...(existing.ipAddresses ?? []), ...(obs.ipAddresses ?? [])]);
  bucket[existingIdx] = {
    ...existing,
    sources: mergedSources.size > 0 ? Array.from(mergedSources).sort() : existing.sources,
    ipAddresses: mergedIps.size > 0 ? Array.from(mergedIps).sort() : existing.ipAddresses,
    confidence: Math.max(existing.confidence, obs.confidence),
  };
}

/**
 * Phase D1 Step 2 — binaries whose absence / stub substitution must be surfaced
 * per stage (includes katana which is not in the P0-3 allowlist but is used by URL discovery).
 */
const STAGE_DEGRADED_BINARIES: Readonly<Record<ReconStageName, readonly string[]>> = {
  stage_1_domain_zone: ['subfinder', 'dnsx'],
  stage_2_port_service: ['naabu'],
  stage_3_web_tls: ['httpx', 'tlsx'],
  stage_4_crawling_parameters: ['gau', 'katana', 'ffuf', 'arjun'],
  stage_5_secret_inspection: ['trufflehog'],
};

export class CompositeActiveReconOrchestratorService {
  constructor(private readonly tools: ReconToolAdapters) {}

  public async orchestrate(
    request: ActiveReconOrchestrationRequest
  ): Promise<ActiveReconOrchestrationResult> {
    const startTime = Date.now();
    const safeSeed = sanitizeToSafeId(request.targetDomain);

    // -------------------------------------------------------------------------
    // Safety Gateway 1: Atomic Root Preflight Check
    // -------------------------------------------------------------------------
    const preflight = await runAdapterPreflight({
      target: request.targetDomain,
      targetKind: 'fqdn',
      verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
      authorizedScopeGrant: request.authorizedScopeGrant,
      lineage: request.lineage,
      requiredPermissions: [
        'passiveRecon',
        'endpointDiscovery',
        'activeCrawling',
        'technologyFingerprinting',
        'lightValidation',
      ],
      missingPermissionReason: 'Scope grant does not permit active reconnaissance operations',
      dnsResolver: request.dnsResolver,
    });

    if (!preflight.ok) {
      return {
        status: 'preflight_denied',
        contractVersion: ACTIVE_RECON_ORCHESTRATION_CONTRACT_VERSION,
        targetDomain: request.targetDomain,
        reasonCode: preflight.reasonCode,
        reason: preflight.reason,
        explicitNonClaims: RECON_ORCHESTRATION_NON_CLAIMS,
        lineage: { ...request.lineage },
        durationMs: Date.now() - startTime,
      };
    }

    // -------------------------------------------------------------------------
    // Safety Gateway 2: Session Lifecycle Health Validation (if authenticated)
    // -------------------------------------------------------------------------
    if (request.authContext?.sessionState) {
      const sessionHealth = await validateSessionHealth(
        request.authContext.sessionState
      );
      if (!sessionHealth.ok) {
        return {
          status: 'preflight_denied',
          contractVersion: ACTIVE_RECON_ORCHESTRATION_CONTRACT_VERSION,
          targetDomain: request.targetDomain,
          reasonCode: sessionHealth.reasonCode ?? 'session_expired',
          reason: 'Configured authentication session is expired or invalid',
          explicitNonClaims: RECON_ORCHESTRATION_NON_CLAIMS,
          lineage: { ...request.lineage },
          durationMs: Date.now() - startTime,
        };
      }
    }

    // -------------------------------------------------------------------------
    // Safety Gateway 3: Target Execution Coordinator (Rate-Limiting & Concurrency)
    // -------------------------------------------------------------------------
    const coordinator = request.coordinator ?? new TargetExecutionCoordinator();
    const skipStages = new Set(request.config?.skipStages ?? []);

    const stageResults: ReconStageExecutionResult[] = [];
    const drafts: OrchestratedReconEvidenceDraft[] = [];
    let draftCounter = 0;

    const subdomains: DiscoveredSubdomainObservation[] = [];
    const subdomainIndex = new Map<string, number>();
    const dnsRecords: DiscoveredDnsObservation[] = [];
    const ports: DiscoveredPortObservation[] = [];
    const webObservations: DiscoveredWebObservation[] = [];
    const tlsCertificates: DiscoveredTlsObservation[] = [];
    const urls: DiscoveredUrlObservation[] = [];
    const content: DiscoveredContentObservation[] = [];
    const parameters: DiscoveredParameterObservation[] = [];
    const secrets: DiscoveredSecretObservation[] = [];
    const spaObservations: DiscoveredSpaObservation[] = [];

    // Phase D1 — inject pre-validated assessment seeds as live OBSERVED URL inventory.
    if (request.seedUrls && request.seedUrls.length > 0) {
      const seedObservedAt = new Date().toISOString();
      for (const seedUrl of request.seedUrls) {
        try {
          const parsed = new URL(seedUrl);
          urls.push({
            url: seedUrl,
            host: parsed.hostname.toLowerCase(),
            path: parsed.pathname || '/',
            ...(parsed.search.length > 1
              ? { query: parsed.search.slice(1) }
              : {}),
            sources: Object.freeze(['assessment_seed']),
            discoveredAt: seedObservedAt,
            collectedAt: seedObservedAt,
            freshness: 'live',
            sourceReliability: 'direct_observation',
          });
        } catch {
          // Seeds are pre-validated; skip any residual parse failure fail-closed without aborting recon.
        }
      }
    }

    /** Hosts already submitted to DNS resolution (idempotent across stages / SAN feedback). */
    const dnsResolvedHosts = new Set<string>();
    /** Hosts already submitted to HTTP inspection (idempotent across stages / SAN feedback). */
    const httpInspectedHosts = new Set<string>();
    /** Exact URLs already HTTP-probed (seed paths must not be collapsed to hostname). */
    const httpInspectedUrls = new Set<string>();
    /** Hosts already TLS-inspected (avoid re-probing TLS per seed path). */
    const tlsInspectedHosts = new Set<string>();

    /** Phase D1 Step 2 — accumulate loud degradation notices across stages. */
    const degradedCapabilityNotices = new Set<string>();
    const degradedBinarySet = new Set(
      (request.degradedBinaries ?? []).map((b) => b.trim().toLowerCase()).filter((b) => b.length > 0)
    );

    function degradedNotice(binary: string): string {
      return `degraded_mode_missing_binary: ${binary}`;
    }

    function collectStageDegradation(
      stage: ReconStageName,
      intoWarnings: string[]
    ): void {
      const stageTools = STAGE_DEGRADED_BINARIES[stage] ?? [];
      for (const binary of stageTools) {
        if (degradedBinarySet.has(binary)) {
          const notice = degradedNotice(binary);
          degradedCapabilityNotices.add(notice);
          if (!intoWarnings.includes(notice)) {
            intoWarnings.push(notice);
          }
        }
      }
    }

    function createDraft(
      stage: ReconStageName,
      targetHost: string,
      observationType: string,
      count: number
    ): void {
      if (count <= 0) return;
      draftCounter += 1;
      drafts.push({
        draftId: `drf_${stage}_${safeSeed}_${draftCounter}`,
        stage,
        targetHost,
        observationType,
        observationsCount: count,
        explicitNonClaims: RECON_ORCHESTRATION_NON_CLAIMS,
        lineage: { ...request.lineage },
        createdAt: new Date().toISOString(),
      });
    }

    async function recordStageResult(res: ReconStageExecutionResult): Promise<void> {
      stageResults.push(res);
      if (request.onStageComplete) {
        try {
          await request.onStageComplete(res);
        } catch {
          // Non-blocking containment
        }
      }
    }

    const buildCircuitBrokenResult = (host: string): ActiveReconOrchestrationResult => ({
      status: 'circuit_broken',
      contractVersion: ACTIVE_RECON_ORCHESTRATION_CONTRACT_VERSION,
      targetDomain: request.targetDomain,
      reasonCode: CIRCUIT_OPEN_REASON_CODE,
      reason: `Target circuit breaker tripped to OPEN on '${host}' to protect target availability. Orchestration safely paused.`,
      stages: stageResults,
      drafts,
      aggregatedObservations: {
        subdomains,
        dnsRecords,
        ports,
        webObservations,
        tlsCertificates,
        urls,
        content,
        parameters,
        secrets,
        spaObservations,
      },
      explicitNonClaims: RECON_ORCHESTRATION_NON_CLAIMS,
      lineage: { ...request.lineage },
      durationMs: Date.now() - startTime,
      ...(degradedCapabilityNotices.size > 0
        ? { degradedCapabilities: Object.freeze(Array.from(degradedCapabilityNotices).sort()) }
        : {}),
    });

    // =========================================================================
    // Stage 1: Domain & Zone Enumeration (Subfinder + Dnsx)
    // =========================================================================
    if (coordinator.isCircuitOpen(request.targetDomain)) {
      return buildCircuitBrokenResult(request.targetDomain);
    }

    const stage1Start = Date.now();
    if (skipStages.has('stage_1_domain_zone')) {
      await recordStageResult({
        stage: 'stage_1_domain_zone',
        status: 'skipped',
        durationMs: 0,
        observationsCount: 0,
      });
    } else {
      const stage1Warnings: string[] = [];

      try {
        const subResult: SubdomainDiscoveryResult = await coordinator.execute(
          request.targetDomain,
          () =>
            this.tools.subdomainTool.discoverSubdomains({
              targetDomain: request.targetDomain,
              verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
              authorizedScopeGrant: request.authorizedScopeGrant,
              lineage: request.lineage,
              timeoutMs: request.config?.timeoutMs,
            })
        );

        if (subResult.status === 'success') {
          for (const obs of subResult.observations) {
            mergeSubdomainObservation(subdomains, subdomainIndex, obs);
          }
        } else {
          stage1Warnings.push(`Subdomain discovery denied: ${subResult.reasonCode}`);
        }
      } catch (err) {
        if (err instanceof TargetInstabilityError || coordinator.isCircuitOpen(request.targetDomain)) {
          await recordStageResult({
            stage: 'stage_1_domain_zone',
            status: 'partial_failure',
            durationMs: Date.now() - stage1Start,
            observationsCount: subdomains.length,
            warnings: [`Circuit breaker tripped on ${request.targetDomain}`],
          });
          return buildCircuitBrokenResult(request.targetDomain);
        }
        stage1Warnings.push(`Subdomain tool error: ${err instanceof Error ? err.message : String(err)}`);
      }

      // Passive CT-log (crt.sh) — historical hostname candidates; merged + deduped with Subfinder
      if (this.tools.passiveCtTool) {
        try {
          const ctResult: SubdomainDiscoveryResult = await coordinator.execute(
            request.targetDomain,
            () =>
              this.tools.passiveCtTool!.discoverSubdomains({
                targetDomain: request.targetDomain,
                verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
                authorizedScopeGrant: request.authorizedScopeGrant,
                lineage: request.lineage,
                timeoutMs: request.config?.timeoutMs,
              })
          );

          if (ctResult.status === 'success') {
            for (const obs of ctResult.observations) {
              mergeSubdomainObservation(subdomains, subdomainIndex, obs);
            }
          } else {
            stage1Warnings.push(`Passive CT discovery denied: ${ctResult.reasonCode}`);
          }
        } catch (err) {
          if (err instanceof TargetInstabilityError || coordinator.isCircuitOpen(request.targetDomain)) {
            await recordStageResult({
              stage: 'stage_1_domain_zone',
              status: 'partial_failure',
              durationMs: Date.now() - stage1Start,
              observationsCount: subdomains.length,
              warnings: [`Circuit breaker tripped on ${request.targetDomain}`],
            });
            return buildCircuitBrokenResult(request.targetDomain);
          }
          stage1Warnings.push(
            `Passive CT tool error: ${err instanceof Error ? err.message : String(err)}`
          );
        }
      }

      // Collect hosts to resolve with Dnsx
      const hostsToResolve = new Set<string>();
      hostsToResolve.add(request.targetDomain);
      for (const sub of subdomains) {
        hostsToResolve.add(sub.subdomain);
      }

      for (const host of hostsToResolve) {
        if (dnsResolvedHosts.has(host)) continue;
        dnsResolvedHosts.add(host);
        try {
          const dnsResult: DnsResolutionResult = await coordinator.execute(
            host,
            () =>
              this.tools.dnsTool.resolveDns({
                targetDomain: host,
                verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
                authorizedScopeGrant: request.authorizedScopeGrant,
                lineage: request.lineage,
                timeoutMs: request.config?.timeoutMs,
              })
          );

          if (dnsResult.status === 'success') {
            for (const obs of dnsResult.observations) {
              dnsRecords.push(obs);
            }
          }
        } catch (err) {
          if (err instanceof TargetInstabilityError || coordinator.isCircuitOpen(host)) {
            createDraft('stage_1_domain_zone', request.targetDomain, 'subdomains', subdomains.length);
            createDraft('stage_1_domain_zone', request.targetDomain, 'dns_records', dnsRecords.length);
            await recordStageResult({
              stage: 'stage_1_domain_zone',
              status: 'partial_failure',
              durationMs: Date.now() - stage1Start,
              observationsCount: subdomains.length + dnsRecords.length,
              warnings: [`Circuit breaker tripped on ${host}`],
            });
            return buildCircuitBrokenResult(host);
          }
          stage1Warnings.push(`DNS resolution error on ${host}: ${err instanceof Error ? err.message : String(err)}`);
        }
      }

      createDraft('stage_1_domain_zone', request.targetDomain, 'subdomains', subdomains.length);
      createDraft('stage_1_domain_zone', request.targetDomain, 'dns_records', dnsRecords.length);

      collectStageDegradation('stage_1_domain_zone', stage1Warnings);

      await recordStageResult({
        stage: 'stage_1_domain_zone',
        status: stage1Warnings.length > 0 && subdomains.length === 0 ? 'partial_failure' : 'completed',
        durationMs: Date.now() - stage1Start,
        observationsCount: subdomains.length + dnsRecords.length,
        warnings: stage1Warnings.length > 0 ? stage1Warnings : undefined,
      });
    }


    // =========================================================================
    // Stage 2: Port & Service Discovery (Naabu)
    // =========================================================================
    if (coordinator.isCircuitOpen(request.targetDomain)) {
      return buildCircuitBrokenResult(request.targetDomain);
    }

    const stage2Start = Date.now();
    if (skipStages.has('stage_2_port_service')) {
      await recordStageResult({
        stage: 'stage_2_port_service',
        status: 'skipped',
        durationMs: 0,
        observationsCount: 0,
      });
    } else {
      const stage2Warnings: string[] = [];

      // Collect target hosts/IPs from Stage 1 or root domain
      const hostsToScan = new Set<string>();
      hostsToScan.add(request.targetDomain);
      for (const s of subdomains) {
        hostsToScan.add(s.subdomain);
      }

      for (const host of hostsToScan) {
        try {
          const portResult: PortDiscoveryResult = await coordinator.execute(
            host,
            () =>
              this.tools.portTool.discoverPorts({
                targetHostOrIp: host,
                targetPorts: request.config?.targetPorts,
                verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
                authorizedScopeGrant: request.authorizedScopeGrant,
                lineage: request.lineage,
                timeoutMs: request.config?.timeoutMs,
              })
          );

          if (portResult.status === 'success') {
            for (const obs of portResult.observations) {
              ports.push(obs);
            }
          }
        } catch (err) {
          if (err instanceof TargetInstabilityError || coordinator.isCircuitOpen(host)) {
            createDraft('stage_2_port_service', request.targetDomain, 'open_ports', ports.length);
            await recordStageResult({
              stage: 'stage_2_port_service',
              status: 'partial_failure',
              durationMs: Date.now() - stage2Start,
              observationsCount: ports.length,
              warnings: [`Circuit breaker tripped on ${host}`],
            });
            return buildCircuitBrokenResult(host);
          }
          stage2Warnings.push(`Port tool error on ${host}: ${err instanceof Error ? err.message : String(err)}`);
        }
      }

      createDraft('stage_2_port_service', request.targetDomain, 'open_ports', ports.length);

      collectStageDegradation('stage_2_port_service', stage2Warnings);

      await recordStageResult({
        stage: 'stage_2_port_service',
        status: stage2Warnings.length > 0 && ports.length === 0 ? 'partial_failure' : 'completed',
        durationMs: Date.now() - stage2Start,
        observationsCount: ports.length,
        warnings: stage2Warnings.length > 0 ? stage2Warnings : undefined,
      });
    }

    // =========================================================================
    // Stage 3: HTTP & TLS Inspection (Httpx + Tlsx)
    // =========================================================================
    if (coordinator.isCircuitOpen(request.targetDomain)) {
      return buildCircuitBrokenResult(request.targetDomain);
    }

    const stage3Start = Date.now();
    if (skipStages.has('stage_3_web_tls')) {
      await recordStageResult({
        stage: 'stage_3_web_tls',
        status: 'skipped',
        durationMs: 0,
        observationsCount: 0,
      });
    } else {
      const stage3Warnings: string[] = [];

      // Build target URLs from discovered open ports or standard defaults
      const urlsToInspect = new Set<string>();
      if (ports.length > 0) {
        for (const p of ports) {
          if (p.port === 443 || p.port === 8443) {
            urlsToInspect.add(`https://${p.host}:${p.port}`);
          } else if (p.port === 80 || p.port === 8080) {
            urlsToInspect.add(`http://${p.host}:${p.port}`);
          } else {
            urlsToInspect.add(`https://${p.host}:${p.port}`);
            urlsToInspect.add(`http://${p.host}:${p.port}`);
          }
        }
      } else {
        urlsToInspect.add(`https://${request.targetDomain}`);
        urlsToInspect.add(`http://${request.targetDomain}`);
      }

      // Phase D1 Step 2 — probe each validated seed URL alongside root (URL-level, not host-collapsed).
      if (request.seedUrls && request.seedUrls.length > 0) {
        for (const seedUrl of request.seedUrls) {
          urlsToInspect.add(seedUrl);
        }
      }

      // Phase D1 Steps 3–4 — snapshot primary inspect set (seeds + roots).
      // Hop-1 mines these bodies; hop-2 re-mines only hop-1 app_endpoint bodies (no third hop).
      const stage3PrimaryInspectUrls = new Set<string>(urlsToInspect);

      for (const targetUrl of urlsToInspect) {
        let currentHost = request.targetDomain;
        try {
          const parsed = new URL(targetUrl);
          currentHost = parsed.hostname;

          if (!httpInspectedUrls.has(targetUrl)) {
            httpInspectedUrls.add(targetUrl);
            httpInspectedHosts.add(parsed.hostname);
            const webResult: WebInspectionResult = await coordinator.execute(
              parsed.hostname,
              () =>
                this.tools.webTool.inspectWeb({
                  targetUrl,
                  verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
                  authorizedScopeGrant: request.authorizedScopeGrant,
                  lineage: request.lineage,
                  timeoutMs: request.config?.timeoutMs,
                })
            );

            if (webResult.status === 'success') {
              for (const obs of webResult.observations) {
                webObservations.push(obs);
              }
            } else if (webResult.status === 'preflight_denied' || webResult.status === 'execution_failed') {
              stage3Warnings.push(
                `Web inspection ${webResult.status} on ${targetUrl}: ${webResult.reasonCode}`
              );
            }
          }

          if (targetUrl.startsWith('https://') && !tlsInspectedHosts.has(parsed.hostname)) {
            tlsInspectedHosts.add(parsed.hostname);
            const tlsPort = parsed.port ? parseInt(parsed.port, 10) : 443;
            const tlsResult: TlsInspectionResult = await coordinator.execute(
              parsed.hostname,
              () =>
                this.tools.tlsTool.inspectTls({
                  targetHostOrUrl: parsed.hostname,
                  targetPorts: [tlsPort],
                  verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
                  authorizedScopeGrant: request.authorizedScopeGrant,
                  lineage: request.lineage,
                  timeoutMs: request.config?.timeoutMs,
                })
            );

            if (tlsResult.status === 'success') {
              for (const obs of tlsResult.observations) {
                tlsCertificates.push(obs);
              }
            } else if (tlsResult.status === 'preflight_denied' || tlsResult.status === 'execution_failed') {
              stage3Warnings.push(
                `TLS inspection ${tlsResult.status} on ${parsed.hostname}: ${tlsResult.reasonCode}`
              );
            }
          }
        } catch (err) {
          if (err instanceof TargetInstabilityError || coordinator.isCircuitOpen(currentHost)) {
            createDraft('stage_3_web_tls', request.targetDomain, 'web_technologies', webObservations.length);
            createDraft('stage_3_web_tls', request.targetDomain, 'tls_certificates', tlsCertificates.length);
            await recordStageResult({
              stage: 'stage_3_web_tls',
              status: 'partial_failure',
              durationMs: Date.now() - stage3Start,
              observationsCount: webObservations.length + tlsCertificates.length,
              warnings: [`Circuit breaker tripped on ${currentHost}`],
            });
            return buildCircuitBrokenResult(currentHost);
          }
          const errMsg = err instanceof Error ? err.message : String(err);
          stage3Warnings.push(`Web/TLS inspection error on ${targetUrl}: ${errMsg}`);
          // Loud degraded mode when CLI spawn fails with missing binary.
          for (const binary of ['httpx', 'tlsx'] as const) {
            if (/command not found|ENOENT/i.test(errMsg) && errMsg.toLowerCase().includes(binary)) {
              const notice = degradedNotice(binary);
              degradedCapabilityNotices.add(notice);
              degradedBinarySet.add(binary);
              if (!stage3Warnings.includes(notice)) {
                stage3Warnings.push(notice);
              }
            }
          }
        }
      }

      // -----------------------------------------------------------------
      // Phase D1 Step 3 — Passive HTML link & route extraction (hop-1, max 25)
      // Hermetic: only bodies from stage3PrimaryInspectUrls. Scope+egress already
      // enforced inside HtmlRouteExtractionService (fail-closed OOS drop).
      // -----------------------------------------------------------------
      const htmlExtractor = new HtmlRouteExtractionService();
      const knownUrlInventory = new Set<string>(urls.map((u) => u.url));
      for (const primary of stage3PrimaryInspectUrls) {
        knownUrlInventory.add(primary);
      }
      const hop1ExtractedUrls: string[] = [];
      const hop1AppEndpointUrls: string[] = [];
      const htmlExtractedAt = new Date().toISOString();

      for (const webObs of webObservations) {
        if (hop1ExtractedUrls.length >= HTML_ROUTE_EXTRACTION_MAX_PER_STAGE) {
          break;
        }
        if (!stage3PrimaryInspectUrls.has(webObs.url)) {
          continue;
        }
        if (typeof webObs.bodyText !== 'string' || webObs.bodyText.length === 0) {
          continue;
        }

        const remaining = HTML_ROUTE_EXTRACTION_MAX_PER_STAGE - hop1ExtractedUrls.length;
        const extracted = htmlExtractor.extract({
          bodyText: webObs.bodyText,
          baseUrl: webObs.url,
          targetDomain: request.targetDomain,
          authorizedScopeGrant: request.authorizedScopeGrant,
          maxResults: remaining,
        });

        for (const candidate of extracted.accepted) {
          if (hop1ExtractedUrls.length >= HTML_ROUTE_EXTRACTION_MAX_PER_STAGE) {
            break;
          }
          if (knownUrlInventory.has(candidate.url)) {
            continue;
          }
          knownUrlInventory.add(candidate.url);
          hop1ExtractedUrls.push(candidate.url);
          if (candidate.kind === 'app_endpoint') {
            hop1AppEndpointUrls.push(candidate.url);
          }

          urls.push({
            url: candidate.url,
            host: candidate.host,
            path: candidate.path,
            ...(candidate.query !== undefined ? { query: candidate.query } : {}),
            sources: Object.freeze([HTML_LINK_EXTRACTION_SOURCE]),
            discoveredAt: htmlExtractedAt,
            collectedAt: htmlExtractedAt,
            freshness: 'live',
            sourceReliability: 'direct_observation',
          });

          // Enqueue for hop-1 HTTP probe (hop-2 mining follows after probe).
          urlsToInspect.add(candidate.url);
        }
      }

      // Hop-1 probe of HTML-extracted URLs (inventory already registered above).
      for (const extractedUrl of hop1ExtractedUrls) {
        if (httpInspectedUrls.has(extractedUrl)) {
          continue;
        }
        let currentHost = request.targetDomain;
        try {
          const parsed = new URL(extractedUrl);
          currentHost = parsed.hostname;
          httpInspectedUrls.add(extractedUrl);
          httpInspectedHosts.add(parsed.hostname);

          const webResult: WebInspectionResult = await coordinator.execute(
            parsed.hostname,
            () =>
              this.tools.webTool.inspectWeb({
                targetUrl: extractedUrl,
                verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
                authorizedScopeGrant: request.authorizedScopeGrant,
                lineage: request.lineage,
                timeoutMs: request.config?.timeoutMs,
              })
          );

          if (webResult.status === 'success') {
            for (const obs of webResult.observations) {
              webObservations.push(obs);
            }
          } else if (webResult.status === 'preflight_denied' || webResult.status === 'execution_failed') {
            stage3Warnings.push(
              `HTML-extracted URL inspection ${webResult.status} on ${extractedUrl}: ${webResult.reasonCode}`
            );
          }
        } catch (err) {
          if (err instanceof TargetInstabilityError || coordinator.isCircuitOpen(currentHost)) {
            createDraft('stage_3_web_tls', request.targetDomain, 'web_technologies', webObservations.length);
            createDraft('stage_3_web_tls', request.targetDomain, 'tls_certificates', tlsCertificates.length);
            await recordStageResult({
              stage: 'stage_3_web_tls',
              status: 'partial_failure',
              durationMs: Date.now() - stage3Start,
              observationsCount: webObservations.length + tlsCertificates.length,
              warnings: [`Circuit breaker tripped on ${currentHost}`],
            });
            return buildCircuitBrokenResult(currentHost);
          }
          stage3Warnings.push(
            `HTML-extracted URL inspection error on ${extractedUrl}: ${err instanceof Error ? err.message : String(err)}`
          );
        }
      }

      // -----------------------------------------------------------------
      // Phase D1 Step 4 — Hop-2 HTML extraction from app_endpoint bodies only
      // (never /_next/static). Cap additional URLs; no third hop.
      // -----------------------------------------------------------------
      const hop1AppEndpointSet = new Set<string>(hop1AppEndpointUrls);
      const hop2ExtractedUrls: string[] = [];
      const hop2ExtractedAt = new Date().toISOString();

      for (const webObs of webObservations) {
        if (hop2ExtractedUrls.length >= HTML_ROUTE_EXTRACTION_MAX_HOP2) {
          break;
        }
        if (!hop1AppEndpointSet.has(webObs.url)) {
          continue;
        }
        if (typeof webObs.bodyText !== 'string' || webObs.bodyText.length === 0) {
          continue;
        }

        const remaining = HTML_ROUTE_EXTRACTION_MAX_HOP2 - hop2ExtractedUrls.length;
        const extracted = htmlExtractor.extract({
          bodyText: webObs.bodyText,
          baseUrl: webObs.url,
          targetDomain: request.targetDomain,
          authorizedScopeGrant: request.authorizedScopeGrant,
          maxResults: remaining,
        });

        for (const candidate of extracted.accepted) {
          if (hop2ExtractedUrls.length >= HTML_ROUTE_EXTRACTION_MAX_HOP2) {
            break;
          }
          // Prefer useful surface: skip static bundles on hop-2 inventory budget.
          if (candidate.kind === 'static_bundle') {
            continue;
          }
          if (knownUrlInventory.has(candidate.url)) {
            continue;
          }
          knownUrlInventory.add(candidate.url);
          hop2ExtractedUrls.push(candidate.url);

          urls.push({
            url: candidate.url,
            host: candidate.host,
            path: candidate.path,
            ...(candidate.query !== undefined ? { query: candidate.query } : {}),
            sources: Object.freeze([HTML_LINK_EXTRACTION_SOURCE]),
            discoveredAt: hop2ExtractedAt,
            collectedAt: hop2ExtractedAt,
            freshness: 'live',
            sourceReliability: 'direct_observation',
          });
        }
      }

      // One-shot probe of hop-2 URLs (register + observe; bodies are never re-mined).
      for (const extractedUrl of hop2ExtractedUrls) {
        if (httpInspectedUrls.has(extractedUrl)) {
          continue;
        }
        let currentHost = request.targetDomain;
        try {
          const parsed = new URL(extractedUrl);
          currentHost = parsed.hostname;
          httpInspectedUrls.add(extractedUrl);
          httpInspectedHosts.add(parsed.hostname);

          const webResult: WebInspectionResult = await coordinator.execute(
            parsed.hostname,
            () =>
              this.tools.webTool.inspectWeb({
                targetUrl: extractedUrl,
                verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
                authorizedScopeGrant: request.authorizedScopeGrant,
                lineage: request.lineage,
                timeoutMs: request.config?.timeoutMs,
              })
          );

          if (webResult.status === 'success') {
            for (const obs of webResult.observations) {
              webObservations.push(obs);
            }
          } else if (webResult.status === 'preflight_denied' || webResult.status === 'execution_failed') {
            stage3Warnings.push(
              `HTML hop-2 URL inspection ${webResult.status} on ${extractedUrl}: ${webResult.reasonCode}`
            );
          }
        } catch (err) {
          if (err instanceof TargetInstabilityError || coordinator.isCircuitOpen(currentHost)) {
            createDraft('stage_3_web_tls', request.targetDomain, 'web_technologies', webObservations.length);
            createDraft('stage_3_web_tls', request.targetDomain, 'tls_certificates', tlsCertificates.length);
            await recordStageResult({
              stage: 'stage_3_web_tls',
              status: 'partial_failure',
              durationMs: Date.now() - stage3Start,
              observationsCount: webObservations.length + tlsCertificates.length,
              warnings: [`Circuit breaker tripped on ${currentHost}`],
            });
            return buildCircuitBrokenResult(currentHost);
          }
          stage3Warnings.push(
            `HTML hop-2 URL inspection error on ${extractedUrl}: ${err instanceof Error ? err.message : String(err)}`
          );
        }
      }

      // -----------------------------------------------------------------
      // R1d — TLS SAN → subdomain feedback (one-shot, non-recursive)
      // SAN ≠ live. Discovery ≠ authorization. Scope-check + dedupe only.
      // -----------------------------------------------------------------
      const knownHosts = new Set<string>();
      knownHosts.add(request.targetDomain.toLowerCase().replace(/\.$/, ''));
      for (const s of subdomains) {
        knownHosts.add(s.subdomain);
      }

      const sanFeedbackHosts: string[] = [];
      const sanSeen = new Set<string>();
      const nowIso = new Date().toISOString();

      for (const tlsObs of tlsCertificates) {
        for (const rawSan of tlsObs.subjectAlternativeNames) {
          const host = normalizeHostname(rawSan);
          if (!host) continue;
          if (sanSeen.has(host) || knownHosts.has(host)) continue;
          if (!isHostnameInAuthorizedScope(host, request.authorizedScopeGrant)) continue;

          sanSeen.add(host);
          knownHosts.add(host);
          sanFeedbackHosts.push(host);

          mergeSubdomainObservation(subdomains, subdomainIndex, {
            subdomain: host,
            parentDomain: request.targetDomain,
            sources: ['tls_san'],
            discoveredAt: nowIso,
            collectedAt: nowIso,
            freshness: 'unknown',
            sourceReliability: 'inferred_relationship',
            confidence: 0.7,
          });
        }
      }

      // One-shot DNS + HTTP follow-up for newly discovered in-scope SAN hosts (no TLS recursion)
      for (const host of sanFeedbackHosts) {
        if (!dnsResolvedHosts.has(host)) {
          dnsResolvedHosts.add(host);
          try {
            const dnsResult: DnsResolutionResult = await coordinator.execute(
              host,
              () =>
                this.tools.dnsTool.resolveDns({
                  targetDomain: host,
                  verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
                  authorizedScopeGrant: request.authorizedScopeGrant,
                  lineage: request.lineage,
                  timeoutMs: request.config?.timeoutMs,
                })
            );
            if (dnsResult.status === 'success') {
              for (const obs of dnsResult.observations) {
                dnsRecords.push(obs);
              }
            }
          } catch (err) {
            if (err instanceof TargetInstabilityError || coordinator.isCircuitOpen(host)) {
              createDraft('stage_3_web_tls', request.targetDomain, 'web_technologies', webObservations.length);
              createDraft('stage_3_web_tls', request.targetDomain, 'tls_certificates', tlsCertificates.length);
              await recordStageResult({
                stage: 'stage_3_web_tls',
                status: 'partial_failure',
                durationMs: Date.now() - stage3Start,
                observationsCount: webObservations.length + tlsCertificates.length,
                warnings: [`Circuit breaker tripped on SAN feedback host ${host}`],
              });
              return buildCircuitBrokenResult(host);
            }
            stage3Warnings.push(
              `SAN DNS follow-up error on ${host}: ${err instanceof Error ? err.message : String(err)}`
            );
          }
        }

        if (!httpInspectedHosts.has(host)) {
          httpInspectedHosts.add(host);
          const sanUrl = `https://${host}`;
          if (!httpInspectedUrls.has(sanUrl)) {
            httpInspectedUrls.add(sanUrl);
          }
          try {
            const webResult: WebInspectionResult = await coordinator.execute(
              host,
              () =>
                this.tools.webTool.inspectWeb({
                  targetUrl: sanUrl,
                  verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
                  authorizedScopeGrant: request.authorizedScopeGrant,
                  lineage: request.lineage,
                  timeoutMs: request.config?.timeoutMs,
                })
            );
            if (webResult.status === 'success') {
              for (const obs of webResult.observations) {
                webObservations.push(obs);
              }
            } else if (webResult.status === 'preflight_denied' || webResult.status === 'execution_failed') {
              stage3Warnings.push(
                `SAN HTTP follow-up ${webResult.status} on ${host}: ${webResult.reasonCode}`
              );
            }
          } catch (err) {
            if (err instanceof TargetInstabilityError || coordinator.isCircuitOpen(host)) {
              createDraft('stage_3_web_tls', request.targetDomain, 'web_technologies', webObservations.length);
              createDraft('stage_3_web_tls', request.targetDomain, 'tls_certificates', tlsCertificates.length);
              await recordStageResult({
                stage: 'stage_3_web_tls',
                status: 'partial_failure',
                durationMs: Date.now() - stage3Start,
                observationsCount: webObservations.length + tlsCertificates.length,
                warnings: [`Circuit breaker tripped on SAN feedback host ${host}`],
              });
              return buildCircuitBrokenResult(host);
            }
            stage3Warnings.push(
              `SAN HTTP follow-up error on ${host}: ${err instanceof Error ? err.message : String(err)}`
            );
          }
        }
      }

      createDraft('stage_3_web_tls', request.targetDomain, 'web_technologies', webObservations.length);
      createDraft('stage_3_web_tls', request.targetDomain, 'tls_certificates', tlsCertificates.length);

      collectStageDegradation('stage_3_web_tls', stage3Warnings);

      await recordStageResult({
        stage: 'stage_3_web_tls',
        status: stage3Warnings.length > 0 && webObservations.length === 0 ? 'partial_failure' : 'completed',
        durationMs: Date.now() - stage3Start,
        observationsCount: webObservations.length + tlsCertificates.length,
        warnings: stage3Warnings.length > 0 ? stage3Warnings : undefined,
      });
    }

    // =========================================================================
    // Stage 4: Surface Crawling & Parameter Discovery (Composite URL + Ffuf + Arjun)
    // =========================================================================
    if (coordinator.isCircuitOpen(request.targetDomain)) {
      return buildCircuitBrokenResult(request.targetDomain);
    }

    const stage4Start = Date.now();
    if (skipStages.has('stage_4_crawling_parameters')) {
      await recordStageResult({
        stage: 'stage_4_crawling_parameters',
        status: 'skipped',
        durationMs: 0,
        observationsCount: 0,
      });
    } else {
      const stage4Warnings: string[] = [];

      // Collect root URLs from Stage 3 web discoveries or default
      const rootUrls: string[] = [];
      if (request.seedUrls && request.seedUrls.length > 0) {
        for (const seedUrl of request.seedUrls) {
          rootUrls.push(seedUrl);
        }
      }
      if (webObservations.length > 0) {
        for (const w of webObservations) {
          if (!rootUrls.includes(w.url)) {
            rootUrls.push(w.url);
          }
        }
      } else if (rootUrls.length === 0) {
        rootUrls.push(`https://${request.targetDomain}`);
      }

      for (const rootUrl of rootUrls) {
        let currentHost = request.targetDomain;
        try {
          const parsed = new URL(rootUrl);
          currentHost = parsed.hostname;

          // 1. Composite URL crawling (Katana + Gau)
          const urlResult: UrlDiscoveryResult = await coordinator.execute(
            parsed.hostname,
            () =>
              this.tools.urlTool.discoverUrls({
                targetUrlOrDomain: rootUrl,
                verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
                authorizedScopeGrant: request.authorizedScopeGrant,
                lineage: request.lineage,
                timeoutMs: request.config?.timeoutMs,
              })
          );

          if (urlResult.status === 'success') {
            for (const obs of urlResult.observations) {
              urls.push(obs);
            }
          }

          // 2. Content discovery via Ffuf (if wordlist provided)
          if (request.config?.wordlistPath) {
            const contentResult: ContentDiscoveryResult = await coordinator.execute(
              parsed.hostname,
              () =>
                this.tools.contentTool.discoverContent({
                  targetUrl: rootUrl,
                  wordlistPath: request.config!.wordlistPath!,
                  verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
                  authorizedScopeGrant: request.authorizedScopeGrant,
                  lineage: request.lineage,
                  timeoutMs: request.config?.timeoutMs,
                })
            );

            if (contentResult.status === 'success') {
              for (const obs of contentResult.observations) {
                content.push(obs);
              }
            }
          }

          // 3. Parameter discovery via Arjun
          const paramResult: ParameterDiscoveryResult = await coordinator.execute(
            parsed.hostname,
            () =>
              this.tools.parameterTool.discoverParameters({
                targetUrl: rootUrl,
                verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
                authorizedScopeGrant: request.authorizedScopeGrant,
                lineage: request.lineage,
                timeoutMs: request.config?.timeoutMs,
              })
          );

          if (paramResult.status === 'success') {
            for (const obs of paramResult.observations) {
              parameters.push(obs);
            }
          }
        } catch (err) {
          if (err instanceof TargetInstabilityError || coordinator.isCircuitOpen(currentHost)) {
            createDraft('stage_4_crawling_parameters', request.targetDomain, 'discovered_urls', urls.length);
            createDraft('stage_4_crawling_parameters', request.targetDomain, 'discovered_content', content.length);
            createDraft('stage_4_crawling_parameters', request.targetDomain, 'discovered_parameters', parameters.length);
            createDraft('stage_4_crawling_parameters', request.targetDomain, 'discovered_spa_observations', spaObservations.length);
            await recordStageResult({
              stage: 'stage_4_crawling_parameters',
              status: 'partial_failure',
              durationMs: Date.now() - stage4Start,
              observationsCount: urls.length + content.length + parameters.length + spaObservations.length,
              warnings: [`Circuit breaker tripped on ${currentHost}`],
            });
            return buildCircuitBrokenResult(currentHost);
          }
          stage4Warnings.push(`Crawling/parameter error on ${rootUrl}: ${err instanceof Error ? err.message : String(err)}`);
        }
      }

      // -----------------------------------------------------------------
      // Phase D1 — Opt-in Playwright SPA / RSC mining (egress-gated)
      // Enable when: config.enableSpaDiscovery===true OR seeds present OR
      // Next.js/RSC signals in Stage 3. Caps: seeds + ≤N app endpoints.
      // Loud degrade on browser_unavailable (missing Chromium/Playwright).
      // -----------------------------------------------------------------
      const spaEnabled = shouldEnableSpaDiscovery(request, webObservations);
      if (spaEnabled && this.tools.spaDiscoveryTool) {
        const maxPages =
          typeof request.config?.spaDiscoveryMaxPages === 'number' &&
          request.config.spaDiscoveryMaxPages > 0
            ? Math.floor(request.config.spaDiscoveryMaxPages)
            : SPA_DISCOVERY_MAX_PAGES;

        const spaTargets = selectSpaDiscoveryPages({
          seedUrls: request.seedUrls ?? [],
          inventoryUrls: urls,
          rootUrls,
          authorizedScopeGrant: request.authorizedScopeGrant,
          maxPages,
        });

        for (const spaUrl of spaTargets) {
          let currentHost = request.targetDomain;
          try {
            const parsedSpa = new URL(spaUrl);
            currentHost = parsedSpa.hostname;

            const spaResult: BrowserAutomationResult = await coordinator.execute(
              parsedSpa.hostname,
              () =>
                this.tools.spaDiscoveryTool!.discoverSpa({
                  targetUrlOrDomain: spaUrl,
                  verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
                  authorizedScopeGrant: request.authorizedScopeGrant,
                  lineage: request.lineage,
                  coordinator,
                  timeoutMs: request.config?.timeoutMs,
                })
            );

            if (spaResult.status === 'success') {
              for (const obs of spaResult.observations) {
                spaObservations.push(obs);
                for (const route of obs.routes) {
                  try {
                    if (!isBrowserUrlAllowed(route.url, request.authorizedScopeGrant)) {
                      continue;
                    }
                    const parsedRoute = new URL(route.url);
                    const source =
                      route.source === RSC_DISCOVERY_SOURCE
                        ? RSC_DISCOVERY_SOURCE
                        : PLAYWRIGHT_SPA_SOURCE;
                    urls.push({
                      url: route.url,
                      host: parsedRoute.hostname,
                      path: parsedRoute.pathname,
                      query: parsedRoute.search ? parsedRoute.search.slice(1) : undefined,
                      sources: Object.freeze([source]),
                      discoveredAt: obs.discoveredAt,
                      collectedAt: obs.collectedAt ?? obs.discoveredAt,
                      freshness: 'live',
                      sourceReliability: 'direct_observation',
                    });
                  } catch {
                    // Ignore invalid dynamic URLs
                  }
                }
                for (const input of obs.inputs) {
                  parameters.push({
                    url: input.formAction || obs.url,
                    method: input.method === 'POST' ? 'POST' : 'GET',
                    parameterName: input.inputName,
                    discoveredAt: obs.discoveredAt,
                  });
                }
              }
            } else if (spaResult.status === 'execution_failed') {
              if (spaResult.reasonCode === 'browser_unavailable') {
                const notice = degradedNotice('chromium');
                degradedCapabilityNotices.add(notice);
                degradedBinarySet.add('chromium');
                if (!stage4Warnings.includes(notice)) {
                  stage4Warnings.push(notice);
                }
                stage4Warnings.push(
                  `SPA discovery degraded (Playwright/Chromium missing) on ${spaUrl}: ${spaResult.reason}`
                );
                // Do not attempt further pages once browser is known missing.
                break;
              }
              stage4Warnings.push(
                `SPA discovery ${spaResult.status} on ${spaUrl}: ${spaResult.reasonCode}`
              );
            } else if (spaResult.status === 'preflight_denied') {
              stage4Warnings.push(
                `SPA discovery preflight_denied on ${spaUrl}: ${spaResult.reasonCode}`
              );
            }
          } catch (err) {
            if (err instanceof TargetInstabilityError || coordinator.isCircuitOpen(currentHost)) {
              createDraft('stage_4_crawling_parameters', request.targetDomain, 'discovered_urls', urls.length);
              createDraft('stage_4_crawling_parameters', request.targetDomain, 'discovered_content', content.length);
              createDraft('stage_4_crawling_parameters', request.targetDomain, 'discovered_parameters', parameters.length);
              createDraft('stage_4_crawling_parameters', request.targetDomain, 'discovered_spa_observations', spaObservations.length);
              await recordStageResult({
                stage: 'stage_4_crawling_parameters',
                status: 'partial_failure',
                durationMs: Date.now() - stage4Start,
                observationsCount: urls.length + content.length + parameters.length + spaObservations.length,
                warnings: [`Circuit breaker tripped on ${currentHost}`],
              });
              return buildCircuitBrokenResult(currentHost);
            }
            const errMsg = err instanceof Error ? err.message : String(err);
            stage4Warnings.push(`SPA discovery error on ${spaUrl}: ${errMsg}`);
            if (/Executable doesn't exist|browserType\.launch|chromium/i.test(errMsg)) {
              const notice = degradedNotice('chromium');
              degradedCapabilityNotices.add(notice);
              degradedBinarySet.add('chromium');
              if (!stage4Warnings.includes(notice)) {
                stage4Warnings.push(notice);
              }
              break;
            }
          }
        }
      } else if (spaEnabled && !this.tools.spaDiscoveryTool) {
        const notice = degradedNotice('chromium');
        degradedCapabilityNotices.add(notice);
        if (!stage4Warnings.includes(notice)) {
          stage4Warnings.push(notice);
        }
        stage4Warnings.push(
          'SPA/RSC discovery opted in but spaDiscoveryTool is not composed (loud degrade)'
        );
      }

      createDraft('stage_4_crawling_parameters', request.targetDomain, 'discovered_urls', urls.length);
      createDraft('stage_4_crawling_parameters', request.targetDomain, 'discovered_content', content.length);
      createDraft('stage_4_crawling_parameters', request.targetDomain, 'discovered_parameters', parameters.length);
      createDraft('stage_4_crawling_parameters', request.targetDomain, 'discovered_spa_observations', spaObservations.length);

      collectStageDegradation('stage_4_crawling_parameters', stage4Warnings);

      await recordStageResult({
        stage: 'stage_4_crawling_parameters',
        status: stage4Warnings.length > 0 && urls.length === 0 ? 'partial_failure' : 'completed',
        durationMs: Date.now() - stage4Start,
        observationsCount: urls.length + content.length + parameters.length + spaObservations.length,
        warnings: stage4Warnings.length > 0 ? stage4Warnings : undefined,
      });
    }

    // =========================================================================
    // Stage 5: Secret & Credential Inspection (Trufflehog)
    // =========================================================================
    if (coordinator.isCircuitOpen(request.targetDomain)) {
      return buildCircuitBrokenResult(request.targetDomain);
    }

    const stage5Start = Date.now();
    if (skipStages.has('stage_5_secret_inspection')) {
      await recordStageResult({
        stage: 'stage_5_secret_inspection',
        status: 'skipped',
        durationMs: 0,
        observationsCount: 0,
      });
    } else {
      const stage5Warnings: string[] = [];

      // Collect target endpoints/scripts to inspect
      const targetsToInspect: string[] = [];
      if (urls.length > 0) {
        for (const u of urls.slice(0, 5)) {
          targetsToInspect.push(u.url);
        }
      } else {
        targetsToInspect.push(`https://${request.targetDomain}`);
      }

      for (const targetUrl of targetsToInspect) {
        let currentHost = request.targetDomain;
        try {
          const parsed = new URL(targetUrl);
          currentHost = parsed.hostname;
          const secretResult: SecretDiscoveryResult = await coordinator.execute(
            parsed.hostname,
            () =>
              this.tools.secretTool.scanSecrets({
                targetUrlOrPath: targetUrl,
                verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
                authorizedScopeGrant: request.authorizedScopeGrant,
                lineage: request.lineage,
                timeoutMs: request.config?.timeoutMs,
              })
          );

          if (secretResult.status === 'success') {
            for (const obs of secretResult.observations) {
              secrets.push(obs);
            }
          }
        } catch (err) {
          if (err instanceof TargetInstabilityError || coordinator.isCircuitOpen(currentHost)) {
            createDraft('stage_5_secret_inspection', request.targetDomain, 'discovered_secrets', secrets.length);
            await recordStageResult({
              stage: 'stage_5_secret_inspection',
              status: 'partial_failure',
              durationMs: Date.now() - stage5Start,
              observationsCount: secrets.length,
              warnings: [`Circuit breaker tripped on ${currentHost}`],
            });
            return buildCircuitBrokenResult(currentHost);
          }
          stage5Warnings.push(`Secret scan error on ${targetUrl}: ${err instanceof Error ? err.message : String(err)}`);
        }
      }

      createDraft('stage_5_secret_inspection', request.targetDomain, 'discovered_secrets', secrets.length);

      collectStageDegradation('stage_5_secret_inspection', stage5Warnings);

      await recordStageResult({
        stage: 'stage_5_secret_inspection',
        status: stage5Warnings.length > 0 && secrets.length === 0 ? 'partial_failure' : 'completed',
        durationMs: Date.now() - stage5Start,
        observationsCount: secrets.length,
        warnings: stage5Warnings.length > 0 ? stage5Warnings : undefined,
      });
    }


    const aggregated: AggregatedReconObservations = {
      subdomains,
      dnsRecords,
      ports,
      webObservations,
      tlsCertificates,
      urls,
      content,
      parameters,
      secrets,
      spaObservations,
    };

    return {
      status: 'success',
      contractVersion: ACTIVE_RECON_ORCHESTRATION_CONTRACT_VERSION,
      targetDomain: request.targetDomain,
      stages: stageResults,
      drafts,
      aggregatedObservations: aggregated,
      explicitNonClaims: RECON_ORCHESTRATION_NON_CLAIMS,
      lineage: { ...request.lineage },
      durationMs: Date.now() - startTime,
      ...(degradedCapabilityNotices.size > 0
        ? { degradedCapabilities: Object.freeze(Array.from(degradedCapabilityNotices).sort()) }
        : {}),
    };
  }
}
