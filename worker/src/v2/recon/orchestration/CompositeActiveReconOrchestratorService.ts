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

import { runAdapterPreflight } from '../adapters/AdapterPreflightPipeline.js';
import { validateSessionHealth } from '../../core/SessionLifecycleService.js';
import { TargetExecutionCoordinator } from '../../runtime/TargetExecutionCoordinator.js';

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

function sanitizeToSafeId(raw: string): string {
  const cleaned = raw.replace(/[^A-Za-z0-9]/g, '').slice(0, 16);
  return cleaned.length > 0 ? cleaned : 'target';
}

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
    const dnsRecords: DiscoveredDnsObservation[] = [];
    const ports: DiscoveredPortObservation[] = [];
    const webObservations: DiscoveredWebObservation[] = [];
    const tlsCertificates: DiscoveredTlsObservation[] = [];
    const urls: DiscoveredUrlObservation[] = [];
    const content: DiscoveredContentObservation[] = [];
    const parameters: DiscoveredParameterObservation[] = [];
    const secrets: DiscoveredSecretObservation[] = [];

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

    // =========================================================================
    // Stage 1: Domain & Zone Enumeration (Subfinder + Dnsx)
    // =========================================================================
    const stage1Start = Date.now();
    if (skipStages.has('stage_1_domain_zone')) {
      stageResults.push({
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
            subdomains.push(obs);
          }
        } else {
          stage1Warnings.push(`Subdomain discovery denied: ${subResult.reasonCode}`);
        }
      } catch (err) {
        stage1Warnings.push(`Subdomain tool error: ${err instanceof Error ? err.message : String(err)}`);
      }

      // Collect hosts to resolve with Dnsx
      const hostsToResolve = new Set<string>();
      hostsToResolve.add(request.targetDomain);
      for (const sub of subdomains) {
        hostsToResolve.add(sub.subdomain);
      }

      for (const host of hostsToResolve) {
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
          stage1Warnings.push(`DNS resolution error on ${host}: ${err instanceof Error ? err.message : String(err)}`);
        }
      }

      createDraft('stage_1_domain_zone', request.targetDomain, 'subdomains', subdomains.length);
      createDraft('stage_1_domain_zone', request.targetDomain, 'dns_records', dnsRecords.length);

      stageResults.push({
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
    const stage2Start = Date.now();
    if (skipStages.has('stage_2_port_service')) {
      stageResults.push({
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
          stage2Warnings.push(`Port tool error on ${host}: ${err instanceof Error ? err.message : String(err)}`);
        }
      }

      createDraft('stage_2_port_service', request.targetDomain, 'open_ports', ports.length);

      stageResults.push({
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
    const stage3Start = Date.now();
    if (skipStages.has('stage_3_web_tls')) {
      stageResults.push({
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

      for (const targetUrl of urlsToInspect) {
        try {
          const parsed = new URL(targetUrl);
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
          }

          if (targetUrl.startsWith('https://')) {
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
            }
          }
        } catch (err) {
          stage3Warnings.push(`Web/TLS inspection error on ${targetUrl}: ${err instanceof Error ? err.message : String(err)}`);
        }
      }

      createDraft('stage_3_web_tls', request.targetDomain, 'web_technologies', webObservations.length);
      createDraft('stage_3_web_tls', request.targetDomain, 'tls_certificates', tlsCertificates.length);

      stageResults.push({
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
    const stage4Start = Date.now();
    if (skipStages.has('stage_4_crawling_parameters')) {
      stageResults.push({
        stage: 'stage_4_crawling_parameters',
        status: 'skipped',
        durationMs: 0,
        observationsCount: 0,
      });
    } else {
      const stage4Warnings: string[] = [];

      // Collect root URLs from Stage 3 web discoveries or default
      const rootUrls: string[] = [];
      if (webObservations.length > 0) {
        for (const w of webObservations) {
          rootUrls.push(w.url);
        }
      } else {
        rootUrls.push(`https://${request.targetDomain}`);
      }

      for (const rootUrl of rootUrls) {
        try {
          const parsed = new URL(rootUrl);

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
          stage4Warnings.push(`Crawling/parameter error on ${rootUrl}: ${err instanceof Error ? err.message : String(err)}`);
        }
      }

      createDraft('stage_4_crawling_parameters', request.targetDomain, 'discovered_urls', urls.length);
      createDraft('stage_4_crawling_parameters', request.targetDomain, 'discovered_content', content.length);
      createDraft('stage_4_crawling_parameters', request.targetDomain, 'discovered_parameters', parameters.length);

      stageResults.push({
        stage: 'stage_4_crawling_parameters',
        status: stage4Warnings.length > 0 && urls.length === 0 ? 'partial_failure' : 'completed',
        durationMs: Date.now() - stage4Start,
        observationsCount: urls.length + content.length + parameters.length,
        warnings: stage4Warnings.length > 0 ? stage4Warnings : undefined,
      });
    }

    // =========================================================================
    // Stage 5: Secret & Credential Inspection (Trufflehog)
    // =========================================================================
    const stage5Start = Date.now();
    if (skipStages.has('stage_5_secret_inspection')) {
      stageResults.push({
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
        try {
          const parsed = new URL(targetUrl);
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
          stage5Warnings.push(`Secret scan error on ${targetUrl}: ${err instanceof Error ? err.message : String(err)}`);
        }
      }

      createDraft('stage_5_secret_inspection', request.targetDomain, 'discovered_secrets', secrets.length);

      stageResults.push({
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
    };
  }
}
