/**
 * FixGuard V2 — Milestone F6 Orchestrated Assessment Application Service
 *
 * Coordinates end-to-end defensive assessments:
 * 1. Validates target host and enforces fail-closed SSRF egress preflight.
 * 2. Establishes AuthorizedScopeGrant and runtime-branded VerifiedAuthorizationDecision (ADR-001).
 * 3. Preserves continuous lineage tuple across all execution phases.
 * 4. Asynchronously dispatches CompositeActiveReconOrchestratorService (M73),
 *    CorsMisconfigurationDetectionService (F4), ParameterReflectionDetectionService (F4),
 *    TargetProfileBuilder (F5), and TargetRecommendationEngine (F5).
 * 5. Updates and exposes assessment lifecycle status and summary read models.
 */

import dns from 'node:dns/promises';

import { isInternalOrSsrfTarget } from '../recon/policy/PassiveEgressPolicy.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import type { VerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionContracts.js';
import { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';
import { TargetInstabilityError } from '../runtime/CircuitBreakerContracts.js';

import type {
  ReconToolAdapters,
  ActiveReconOrchestrationConfig,
} from '../recon/orchestration/ActiveReconOrchestrationContracts.js';
import { CompositeActiveReconOrchestratorService } from '../recon/orchestration/CompositeActiveReconOrchestratorService.js';
import { SUBDOMAIN_DISCOVERY_NON_CLAIMS } from '../recon/adapters/SubdomainDiscoveryContracts.js';
import { DNS_RESOLUTION_NON_CLAIMS } from '../recon/adapters/DnsResolutionContracts.js';
import { PORT_DISCOVERY_NON_CLAIMS } from '../recon/adapters/PortDiscoveryContracts.js';
import { WEB_INSPECTION_NON_CLAIMS } from '../recon/adapters/WebInspectionContracts.js';
import { TLS_INSPECTION_NON_CLAIMS } from '../recon/adapters/TlsInspectionContracts.js';
import { URL_DISCOVERY_NON_CLAIMS } from '../recon/adapters/UrlDiscoveryContracts.js';
import { CONTENT_DISCOVERY_NON_CLAIMS } from '../recon/adapters/ContentDiscoveryContracts.js';
import { PARAMETER_DISCOVERY_NON_CLAIMS } from '../recon/adapters/ParameterDiscoveryContracts.js';
import { SECRET_DISCOVERY_NON_CLAIMS } from '../recon/adapters/SecretDiscoveryContracts.js';
import { PlaywrightSpaAdapter } from '../recon/adapters/PlaywrightSpaAdapter.js';

import type {
  HttpProbeRequest,
  HttpProbeResponse,
  IdorHttpProbeTransport,
  ByotIdentity,
  ByotSessionIdentityBundle,
  ProbeAuthContext,
} from '../detection/DetectionContracts.js';
import { DETECTION_CONTRACT_VERSION } from '../detection/DetectionContracts.js';
import { runCorsMisconfigurationDetection } from '../detection/CorsMisconfigurationDetectionService.js';
import { runParameterReflectionDetection } from '../detection/ParameterReflectionDetectionService.js';
import { runIdorDifferentialDetection } from '../detection/IdorDifferentialDetectionService.js';
import { runSecurityHeaderDetection } from '../detection/SecurityHeaderDetectionService.js';
import { runOpenRedirectDetection } from '../detection/OpenRedirectDetectionService.js';
import { runInformationDisclosureDetection } from '../detection/InformationDisclosureDetectionService.js';
import { runSubdomainTakeoverDetection } from '../detection/SubdomainTakeoverDetectionService.js';
import { analyzeTlsConfiguration } from '../detection/TlsConfigurationAnalysisService.js';
import { runAuthBypassDetection } from '../detection/AuthBypassDetectionService.js';
import { runSourcemapExposureDetection } from '../detection/SourcemapExposureDetectionService.js';
import { runWordPressSurfaceDetection } from '../detection/WordPressSurfaceDetectionService.js';
import { runSqlErrorOracleDetection } from '../detection/SqlErrorOracleDetectionService.js';
import { runGraphQLSurfaceDetection } from '../detection/GraphQLSurfaceDetectionService.js';
import { runJwtAlgorithmConfusionDetection } from '../detection/JwtAlgorithmConfusionDetectionService.js';
import { runSessionFixationDetection } from '../detection/SessionFixationDetectionService.js';


import { buildTargetProfile } from '../intelligence/TargetProfileBuilder.js';
import { correlateTargetProfile } from '../intelligence/TargetRecommendationEngine.js';
import type { Finding } from '../core/Evidence.js';
import type { EvidenceDraftEnvelope } from '../evidence-mapping/ComparisonEvidenceMappingContracts.js';

import { SessionNotFoundError } from '../storage/StorageErrors.js';
import {
  ApiValidationError,
  UnauthorizedGatewayError,
  UnavailableToolsError,
  ConcurrencyLimitExceededError,
} from '../api/ApiErrors.js';
import { isStrictSafeId } from '../reporting-boundary/DefensiveReportContracts.js';
import { ReportGeneratorService } from '../reporting-boundary/ReportGeneratorService.js';
import { isForbiddenSyntheticReviewerId } from '../api/validation/ApiRequestValidators.js';
import { ReconToolAvailabilityService } from '../capabilities/ReconToolAvailabilityService.js';
import type { ReconToolName } from '../capabilities/CapabilityStatusContracts.js';
import { STAGE_REQUIRED_TOOLS } from '../capabilities/CapabilityStatusContracts.js';
import type { ReconStageName } from '../recon/orchestration/ActiveReconOrchestrationContracts.js';

export const ASSESSMENT_GLOBAL_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes

/**
 * Pure helper function mapping operator-provided ByotIdentity to frozen ProbeAuthContext
 * with normalized lowercase header keys.
 */
export function buildProbeAuthContext(identity: ByotIdentity): ProbeAuthContext {
  const normalizedHeaders: Record<string, string> = {};
  if (identity.injectHeaders) {
    for (const [key, val] of Object.entries(identity.injectHeaders)) {
      normalizedHeaders[key.toLowerCase()] = val;
    }
  }
  const cookies = identity.injectCookies ? { ...identity.injectCookies } : undefined;
  return Object.freeze({
    identityId: identity.identityId,
    headers: Object.freeze(normalizedHeaders),
    cookies: cookies ? Object.freeze(cookies) : undefined,
  });
}

/**
 * Pure helper function constructing an anonymous/unauthenticated ProbeAuthContext.
 */
export function buildAnonymousProbeContext(identityId: string = 'anonymous_probe'): ProbeAuthContext {
  return Object.freeze({
    identityId,
    headers: Object.freeze({}),
    cookies: Object.freeze({}),
  });
}

import type {
  DifferentialEvidenceContext,
  EnrichedEvidenceDraft,
  GetEvidenceDraftsResult,
  OrchestratedAssessmentRecord,
  OrchestratedAssessmentRepository,
  OrchestratedAssessmentStatusDto,
  OrchestratedAssessmentSummaryDto,
  ReviewEvidenceDraftCommand,
  ReviewEvidenceDraftResult,
  StartOrchestratedAssessmentCommand,
  StartOrchestratedAssessmentResult,
} from './OrchestratedAssessmentContracts.js';
import { ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION } from './OrchestratedAssessmentContracts.js';


export interface OrchestratedAssessmentServiceDependencies {
  readonly repository: OrchestratedAssessmentRepository;
  readonly reconAdapters?: ReconToolAdapters;
  readonly httpTransport?: IdorHttpProbeTransport;
  readonly dnsResolver?: (host: string) => Promise<string[]>;
  readonly availabilityService?: ReconToolAvailabilityService;
}

const defaultHttpTransport: IdorHttpProbeTransport = async (
  req: HttpProbeRequest
): Promise<HttpProbeResponse> => {
  const start = Date.now();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), req.timeoutMs ?? 10_000);

  try {
    const res = await fetch(req.url, {
      method: req.method,
      headers: req.headers,
      signal: controller.signal,
    });

    const bodyText = await res.text();
    const headers: Record<string, string> = {};
    res.headers.forEach((val, key) => {
      headers[key.toLowerCase()] = val;
    });

    return {
      statusCode: res.status,
      headers,
      bodyText,
      responseTimeMs: Date.now() - start,
    };
  } finally {
    clearTimeout(timeout);
  }
};

const defaultDnsResolver = async (host: string): Promise<string[]> => {
  try {
    return await dns.resolve4(host);
  } catch {
    return [];
  }
};

function createDefaultReconAdapters(
  dnsResolver: (host: string) => Promise<string[]>,
  httpTransport: IdorHttpProbeTransport
): ReconToolAdapters {
  return {
    subdomainTool: {
      async discoverSubdomains(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-subdomain-discovery/v0',
          targetDomain: req.targetDomain,
          observations: [],
          explicitNonClaims: SUBDOMAIN_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
    dnsTool: {
      async resolveDns(req) {
        const start = Date.now();
        const ips = await dnsResolver(req.targetDomain);
        return {
          status: 'success',
          contractVersion: 'fixguard-dns-resolution/v0',
          targetDomain: req.targetDomain,
          observations: ips.length > 0
            ? [
                {
                  domain: req.targetDomain,
                  recordType: 'A' as const,
                  values: ips,
                  discoveredAt: new Date().toISOString(),
                },
              ]
            : [],
          explicitNonClaims: DNS_RESOLUTION_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: Date.now() - start,
        };
      },
    },
    portTool: {
      async discoverPorts(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-port-discovery/v0',
          targetHostOrIp: req.targetHostOrIp,
          observations: [
            {
              host: req.targetHostOrIp,
              ip: req.targetHostOrIp,
              port: 443,
              protocol: 'tcp' as const,
              state: 'open' as const,
              discoveredAt: new Date().toISOString(),
            },
          ],
          explicitNonClaims: PORT_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
    webTool: {
      async inspectWeb(req) {
        const start = Date.now();
        try {
          const probe = await httpTransport({
            url: req.targetUrl,
            method: 'GET',
            headers: { 'User-Agent': 'FixGuard-V2-Orchestrator/1.0' },
          });
          const serverHeader = probe.headers['server'];
          const technologies: string[] = [];
          if (serverHeader) technologies.push(serverHeader);
          if (probe.headers['x-powered-by']) technologies.push(probe.headers['x-powered-by']);

          return {
            status: 'success',
            contractVersion: 'fixguard-web-inspection/v0',
            targetUrl: req.targetUrl,
            observations: [
              {
                url: req.targetUrl,
                method: 'GET',
                statusCode: probe.statusCode,
                webServer: serverHeader,
                technologies,
                discoveredAt: new Date().toISOString(),
              },
            ],
            explicitNonClaims: WEB_INSPECTION_NON_CLAIMS,
            lineage: req.lineage,
            durationMs: Date.now() - start,
          };
        } catch {
          return {
            status: 'success',
            contractVersion: 'fixguard-web-inspection/v0',
            targetUrl: req.targetUrl,
            observations: [],
            explicitNonClaims: WEB_INSPECTION_NON_CLAIMS,
            lineage: req.lineage,
            durationMs: Date.now() - start,
          };
        }
      },
    },
    tlsTool: {
      async inspectTls(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-tls-inspection/v0',
          targetHost: req.targetHostOrUrl,
          observations: [],
          explicitNonClaims: TLS_INSPECTION_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
    urlTool: {
      async discoverUrls(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-url-discovery/v0',
          targetUrlOrDomain: req.targetUrlOrDomain,
          observations: [],
          explicitNonClaims: URL_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
    contentTool: {
      async discoverContent(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-content-discovery/v0',
          targetUrl: req.targetUrl,
          wordlistPath: req.wordlistPath,
          observations: [],
          explicitNonClaims: CONTENT_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
    parameterTool: {
      async discoverParameters(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-parameter-discovery/v0',
          targetUrl: req.targetUrl,
          observations: [
            {
              url: req.targetUrl,
              method: 'GET',
              parameterName: 'q',
              discoveredAt: new Date().toISOString(),
            },
          ],
          explicitNonClaims: PARAMETER_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
    secretTool: {
      async scanSecrets(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-secret-discovery/v0',
          targetUrlOrPath: req.targetUrlOrPath,
          observations: [],
          explicitNonClaims: SECRET_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
    spaDiscoveryTool: new PlaywrightSpaAdapter(undefined, dnsResolver),
  };
}

const ALL_STAGE_NAMES: readonly ReconStageName[] = [
  'stage_1_domain_zone',
  'stage_2_port_service',
  'stage_3_web_tls',
  'stage_4_crawling_parameters',
  'stage_5_secret_inspection',
];

export class OrchestratedAssessmentApplicationService {
  private readonly repository: OrchestratedAssessmentRepository;
  private readonly reconAdapters: ReconToolAdapters;
  private readonly httpTransport: IdorHttpProbeTransport;
  private readonly dnsResolver: (host: string) => Promise<string[]>;
  private readonly availabilityService: ReconToolAvailabilityService;
  private readonly activeAssessments = new Map<string, Promise<void>>();

  constructor(deps: OrchestratedAssessmentServiceDependencies) {
    this.repository = deps.repository;
    this.httpTransport = deps.httpTransport ?? defaultHttpTransport;
    this.dnsResolver = deps.dnsResolver ?? defaultDnsResolver;
    this.availabilityService = deps.availabilityService ?? new ReconToolAvailabilityService();
    this.reconAdapters =
      deps.reconAdapters ??
      createDefaultReconAdapters(this.dnsResolver, this.httpTransport);
  }

  /**
   * Validates target host, verifies SSRF boundaries, establishes branded authorization,
   * creates an in-memory assessment record, and launches the orchestration pipeline.
   */
  public async startAssessment(
    command: StartOrchestratedAssessmentCommand
  ): Promise<StartOrchestratedAssessmentResult> {
    const maxConcurrent = parseInt(process.env.FIXGUARD_MAX_CONCURRENT_ASSESSMENTS ?? '3', 10);
    const concurrencyCeiling = Number.isNaN(maxConcurrent) || maxConcurrent <= 0 ? 3 : maxConcurrent;
    if (this.activeAssessments.size >= concurrencyCeiling) {
      throw new ConcurrencyLimitExceededError(
        `Maximum concurrent orchestrated assessments limit (${concurrencyCeiling}) reached. Please wait for running assessments to complete.`
      );
    }

    const rawTarget = command.targetDomain;
    if (!rawTarget || typeof rawTarget !== 'string' || rawTarget.trim().length === 0) {
      throw new ApiValidationError('Field targetDomain must be a non-empty string');
    }

    const cleanedDomain = rawTarget.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (!/^[a-z0-9.-]+$/i.test(cleanedDomain) || cleanedDomain.includes('..')) {
      throw new ApiValidationError(`Field targetDomain '${rawTarget}' contains invalid characters`);
    }

    // SSRF Gate 1: Check hostname string directly (loopback, private naming, localhost)
    if (isInternalOrSsrfTarget(cleanedDomain)) {
      throw new UnauthorizedGatewayError(
        `Target domain '${cleanedDomain}' resolves to a restricted or private address (SSRF blocked)`,
        'ssrf_target_blocked'
      );
    }

    // SSRF Gate 2: Resolve DNS and check all returned IP addresses
    let resolvedIps: string[];
    try {
      resolvedIps = await this.dnsResolver(cleanedDomain);
    } catch {
      resolvedIps = [];
    }

    if (resolvedIps.length === 0) {
      // If domain cannot be resolved at all, fail closed safe
      throw new ApiValidationError(`Unable to resolve target domain '${cleanedDomain}' via DNS`);
    }

    for (const ip of resolvedIps) {
      if (isInternalOrSsrfTarget(ip)) {
        throw new UnauthorizedGatewayError(
          `Target domain '${cleanedDomain}' resolves to a restricted or private address ${ip} (SSRF blocked)`,
          'ssrf_target_blocked'
        );
      }
    }

    // Pre-Scan Tool Availability Gate (Milestone P0-3 Honest Composition)
    const skipStages = new Set(command.config?.skipStages ?? []);
    const requiredToolSet = new Set<ReconToolName>();
    for (const stage of ALL_STAGE_NAMES) {
      if (!skipStages.has(stage)) {
        const tools = STAGE_REQUIRED_TOOLS[stage] ?? [];
        for (const tool of tools) {
          requiredToolSet.add(tool);
        }
      }
    }

    const requiredTools = Array.from(requiredToolSet);
    const availability = await this.availabilityService.verifyRequiredTools(requiredTools);
    if (!availability.allAvailable) {
      throw new UnavailableToolsError(
        `Required recon CLI binaries are missing from the host environment: ${availability.missingTools.join(', ')}`,
        availability.missingTools,
        'unavailable_tools'
      );
    }

    // Scope & Authorization Setup
    const nowIso = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 3600_000).toISOString();
    const rand = Math.random().toString(36).slice(2, 8);
    const timestamp = Date.now();

    const assessmentId = `asmt_orch_${timestamp}_${rand}`;
    const scanId = `scan_orch_${timestamp}_${rand}`;
    const grantId = `grant_orch_${timestamp}_${rand}`;
    const decisionId = `dec_orch_${timestamp}_${rand}`;
    const actorId =
      command.actorId && isStrictSafeId(command.actorId)
        ? command.actorId
        : 'usr_secops_api';

    const scopeGrant: AuthorizedScopeGrant = {
      contractVersion: 'fixguard-authorized-scope-policy/v0',
      kind: 'authorized_scope_grant',
      grantId,
      scanId,
      issuedAt: nowIso,
      expiresAt,
      subject: {
        targetKind: 'domain',
        domain: cleanedDomain,
      },
      authorizationBasis: {
        basisKind: 'internal_asset_record',
        recordedBy: 'human_user',
        authorizationText: `Authorized orchestrated assessment for ${cleanedDomain}`,
      },
      permissionSet: {
        passiveRecon: true,
        technologyFingerprinting: true,
        endpointDiscovery: true,
        activeCrawling: true,
        authenticatedTesting: true,
        lightValidation: true,
        activeValidation: true,
        aggressiveValidation: false,
        oobTesting: false,
        destructiveOperations: false,
      },

      boundaries: {
        allowedDomains: [cleanedDomain],
        allowedHosts: [cleanedDomain, ...resolvedIps],
        allowedOrigins: [`https://${cleanedDomain}`, `http://${cleanedDomain}`],
        allowedMethods: ['GET', 'HEAD', 'OPTIONS'],
      },
      constraints: {
        allowLoginRequiredAreas: true,
        allowStateChangingRequests: false,
        allowCredentialUse: true,
        allowOobCallbacks: false,
        allowThirdPartyTargets: false,
      },

      classification: {
        createsRealFindings: false,
        createsPersistedEvidence: false,
        confirmsVulnerabilities: false,
        makesRiskClaims: false,
        makesSeverityClaims: false,
        makesImpactClaims: false,
        executesNetwork: false,
        executesTools: false,
        persistsData: false,
      },
    };

    const authRes = establishVerifiedAuthorizationDecision(
      {
        contractVersion: 'fixguard-verified-authorization-decision/v0',
        kind: 'establish_verified_authorization_decision_request',
        assessmentId,
        scanId,
        authorizationDecisionId: decisionId,
        authorizedActor: { actorId, actorType: 'human' },
        decision: 'authorized',
        decidedAt: nowIso,
        scopeGrant,
      },
      nowIso
    );

    if (authRes.status !== 'established') {
      throw new UnauthorizedGatewayError(
        `Failed to establish verified authorization: ${authRes.reasonCode}`,
        authRes.reasonCode
      );
    }

    const verifiedDecision = authRes.decision;
    const lineage: AuthorizedActiveReconRequestLineage = {
      assessmentId,
      scanId,
      authorizationGrantId: grantId,
      authorizationDecisionId: decisionId,
      actorId,
    };

    const initialRecord: OrchestratedAssessmentRecord = {
      contractVersion: ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION,
      assessmentId,
      scanId,
      targetDomain: cleanedDomain,
      status: 'running',
      lineage,
      stages: [],
      timing: {
        startedAt: nowIso,
      },
      errorCount: 0,
      warningCount: 0,
      findings: [],
      pendingEvidenceDrafts: [],
      recommendations: [],
    };

    await this.repository.save(initialRecord);

    // Launch pipeline in background
    const pipelinePromise = this.runPipeline(
      initialRecord,
      verifiedDecision,
      scopeGrant,
      lineage,
      command.config,
      command.sessionIdentities
    );
    this.activeAssessments.set(assessmentId, pipelinePromise);

    return {
      assessmentId,
      scanId,
      status: 'running',
      lineage,
    };
  }

  /**
   * Returns the execution stage progress, timing metrics, and error counts.
   */
  public async getStatus(assessmentId: string): Promise<OrchestratedAssessmentStatusDto> {
    if (!assessmentId || typeof assessmentId !== 'string' || !isStrictSafeId(assessmentId)) {
      throw new ApiValidationError('Field assessmentId must satisfy strict identifier format');
    }

    const record = await this.repository.findById(assessmentId);
    if (!record) {
      throw new SessionNotFoundError(
        `Orchestrated assessment '${assessmentId}' was not found`,
        assessmentId
      );
    }

    return {
      assessmentId: record.assessmentId,
      scanId: record.scanId,
      targetDomain: record.targetDomain,
      status: record.status,
      stages: record.stages,
      timing: record.timing,
      errorCount: record.errorCount,
      warningCount: record.warningCount,
      lineage: record.lineage,
      pendingEvidenceDraftCount: record.pendingEvidenceDrafts?.length ?? 0,
      ...(record.error ? { error: record.error } : {}),
      ...(record.reasonCode ? { reasonCode: record.reasonCode } : {}),
    };
  }

  /**
   * Returns the synthesized TargetProfile, confirmed findings, and advisory recommendations.
   */
  public async getSummary(assessmentId: string): Promise<OrchestratedAssessmentSummaryDto> {
    if (!assessmentId || typeof assessmentId !== 'string' || !isStrictSafeId(assessmentId)) {
      throw new ApiValidationError('Field assessmentId must satisfy strict identifier format');
    }

    const record = await this.repository.findById(assessmentId);
    if (!record) {
      throw new SessionNotFoundError(
        `Orchestrated assessment '${assessmentId}' was not found`,
        assessmentId
      );
    }

    return {
      assessmentId: record.assessmentId,
      scanId: record.scanId,
      targetDomain: record.targetDomain,
      status: record.status,
      profile: record.profile,
      findings: record.findings,
      pendingEvidenceDrafts: record.pendingEvidenceDrafts ?? [],
      recommendations: record.recommendations,
      lineage: record.lineage,
      timing: record.timing,
      ...(record.error ? { error: record.error } : {}),
      ...(record.reasonCode ? { reasonCode: record.reasonCode } : {}),
    };
  }

  /**
   * Returns pending evidence drafts with full differential context for human triage.
   */
  public async getEvidenceDrafts(assessmentId: string): Promise<GetEvidenceDraftsResult> {
    if (!assessmentId || typeof assessmentId !== 'string' || !isStrictSafeId(assessmentId)) {
      throw new ApiValidationError('Field assessmentId must satisfy strict identifier format');
    }

    const record = await this.repository.findById(assessmentId);
    if (!record) {
      throw new SessionNotFoundError(
        `Orchestrated assessment '${assessmentId}' was not found`,
        assessmentId
      );
    }

    const drafts = record.pendingEvidenceDrafts ?? [];
    return {
      assessmentId: record.assessmentId,
      scanId: record.scanId,
      draftCount: drafts.length,
      drafts,
    };
  }

  /**
   * Generates a complete standalone defensive HTML report with mandatory operator attestation.
   */
  public async generateHtmlReport(
    assessmentId: string,
    operatorId: string,
    attestationText: string,
    verifiedAt?: string
  ): Promise<string> {
    if (!assessmentId || typeof assessmentId !== 'string' || !isStrictSafeId(assessmentId)) {
      throw new ApiValidationError('Field assessmentId must satisfy strict identifier format');
    }

    const record = await this.repository.findById(assessmentId);
    if (!record) {
      throw new SessionNotFoundError(
        `Orchestrated assessment '${assessmentId}' was not found`,
        assessmentId
      );
    }

    const generator = new ReportGeneratorService();
    return generator.generateHtmlReport({
      assessmentRecord: record,
      operatorId,
      attestationText,
      ...(verifiedAt ? { verifiedAt } : {}),
    });
  }

  /**
   * Evaluates human-in-the-loop review decision for a pending evidence draft.

   * On 'approve_evidence': promotes draft to strongly typed Finding and adds to assessment findings.
   * On 'reject_evidence': discards draft with ZERO findings or persisted evidence.
   */
  public async reviewEvidenceDraft(
    command: ReviewEvidenceDraftCommand
  ): Promise<ReviewEvidenceDraftResult> {
    const { assessmentId, draftId, decision, reviewerId, reviewedAt, notes } = command;

    if (!assessmentId || typeof assessmentId !== 'string' || !isStrictSafeId(assessmentId)) {
      throw new ApiValidationError('Field assessmentId must satisfy strict identifier format');
    }
    if (!draftId || typeof draftId !== 'string' || !isStrictSafeId(draftId)) {
      throw new ApiValidationError('Field draftId must satisfy strict identifier format');
    }
    if (isForbiddenSyntheticReviewerId(reviewerId)) {
      throw new ApiValidationError(
        `Field 'reviewerId' contains forbidden synthetic or unauthenticated reviewer pattern '${reviewerId}'`
      );
    }

    const record = await this.repository.findById(assessmentId);
    if (!record) {
      throw new SessionNotFoundError(
        `Orchestrated assessment '${assessmentId}' was not found`,
        assessmentId
      );
    }

    const existingDrafts = record.pendingEvidenceDrafts ?? [];
    const targetDraft = existingDrafts.find((d) => d.draftId === draftId);
    if (!targetDraft) {
      throw new ApiValidationError(
        `Evidence draft '${draftId}' was not found in assessment '${assessmentId}'`
      );
    }

    const remainingDrafts = existingDrafts.filter((d) => d.draftId !== draftId);

    let findingCreated: Finding | undefined;

    if (decision === 'approve_evidence') {
      const context = targetDraft.differentialContext;
      const detKind = context?.detectionKind;

      if (detKind === 'cors_misconfiguration') {
        findingCreated = {
          id: `fnd_cors_${draftId.replace(/^dft_/, '')}`,
          type: 'SECURITY_MISCONFIGURATION',
          severity: 'high',
          title: `Approved CORS Misconfiguration on ${context?.endpointUrl ?? record.targetDomain}`,
          description: `Human operator verified that origin '${context?.reflectedOrigin ?? 'untrusted'}' is reflected with credentials on ${context?.endpointUrl ?? record.targetDomain}.`,
          target: context?.endpointUrl ?? `https://${record.targetDomain}/`,
          evidence: JSON.stringify({
            draftId,
            reviewerId,
            reviewedAt,
            notes,
            differentialContext: context,
          }),
          confidence: 1.0,
          metadata: {
            kind: 'security_misconfiguration_metadata',
            category: 'CORS_MISCONFIGURATION',
            candidateId: `cnd_${draftId}`,
            evidenceRecordId: `evd_${draftId}`,
            lineage: {
              assessmentId: record.assessmentId,
              scanId: record.scanId,
              reviewerId,
              reviewedAt,
            },
            endpointUrl: context?.endpointUrl,
            reflectedOrigin: context?.reflectedOrigin,
            allowCredentials: context?.allowCredentials ?? true,
          },
        };
      } else if (detKind === 'parameter_reflection') {
        findingCreated = {
          id: `fnd_refl_${draftId.replace(/^dft_/, '')}`,
          type: 'INPUT_VALIDATION_FLAW',
          severity: 'medium',
          title: `Approved Parameter Reflection on ${context?.endpointUrl ?? record.targetDomain}`,
          description: `Human operator verified parameter reflection of parameter '${context?.parameterName ?? 'q'}' on ${context?.endpointUrl ?? record.targetDomain}.`,
          target: context?.endpointUrl ?? `https://${record.targetDomain}/`,
          evidence: JSON.stringify({
            draftId,
            reviewerId,
            reviewedAt,
            notes,
            differentialContext: context,
          }),
          confidence: 1.0,
          metadata: {
            kind: 'input_validation_flaw_metadata',
            category: 'PARAMETER_REFLECTION',
            candidateId: `cnd_${draftId}`,
            evidenceRecordId: `evd_${draftId}`,
            lineage: {
              assessmentId: record.assessmentId,
              scanId: record.scanId,
              reviewerId,
              reviewedAt,
            },
            endpointUrl: context?.endpointUrl,
            parameterName: context?.parameterName,
            reflectedCanary: context?.reflectedCanary,
          },
        };
      } else if (detKind === 'idor_access_control') {
        findingCreated = {
          id: `fnd_idor_${draftId.replace(/^dft_/, '')}`,
          type: 'BROKEN_ACCESS_CONTROL',
          severity: 'high',
          title: `Approved Broken Access Control on ${context?.endpointUrl ?? record.targetDomain}`,
          description: `Human operator verified broken access control on resource parameter '${context?.resourceParamName ?? 'id'}'.`,
          target: context?.endpointUrl ?? `https://${record.targetDomain}/`,
          evidence: JSON.stringify({
            draftId,
            reviewerId,
            reviewedAt,
            notes,
            differentialContext: context,
          }),
          confidence: 1.0,
          metadata: {
            kind: 'broken_access_control_metadata',
            category: 'BROKEN_ACCESS_CONTROL',
            candidateId: `cnd_${draftId}`,
            evidenceRecordId: `evd_${draftId}`,
            lineage: {
              assessmentId: record.assessmentId,
              scanId: record.scanId,
              reviewerId,
              reviewedAt,
            },
            endpointUrl: context?.endpointUrl,
            resourceParamName: context?.resourceParamName,
            baselineResourceId: context?.baselineResourceId,
          },
        };
      } else if (detKind === 'auth_bypass') {
        const mechanism = context?.bypassMechanism ?? 'header_stripping';
        const similarity = context?.bodySimilarityRatio ?? 1.0;
        const endpoint = context?.endpointUrl ?? `https://${record.targetDomain}/`;
        const method = context?.httpMethod ?? 'GET';
        findingCreated = {
          id: `fnd_ab_${draftId.replace(/^dft_/, '').replace(/^draft_/, '')}`,
          type: 'BROKEN_AUTHENTICATION',
          severity: 'high',
          title: `Approved Authentication Bypass on ${endpoint}`,
          description: `Human operator verified that protected endpoint '${endpoint}' is accessible anonymously via ${mechanism} with ${Math.round(similarity * 100)}% response body match.`,
          target: endpoint,
          evidence: JSON.stringify({
            draftId,
            reviewerId,
            reviewedAt,
            notes,
            differentialContext: context,
          }),
          confidence: 0.95,
          metadata: {
            kind: 'auth_bypass_metadata',
            category: 'BROKEN_AUTHENTICATION',
            endpointUrl: endpoint,
            httpMethod: method,
            authenticatedStatusCode: context?.baselineStatusCode ?? 200,
            anonymousStatusCode: context?.validationStatusCode ?? 200,
            bypassMechanism: mechanism,
            bodySimilarityRatio: similarity,
            observedAt: reviewedAt,
            candidateId: `cnd_${draftId}`,
            evidenceRecordId: `evd_${draftId}`,
            lineage: `${record.assessmentId}:${record.scanId}:${reviewerId}:${reviewedAt}`,
          },
        };
      } else if (detKind === 'missing_security_headers') {
        const missing = context?.missingHeaders ?? [];
        const present = context?.presentHeaders ?? [];
        findingCreated = {
          id: `fnd_sh_${draftId.replace(/^dft_/, '')}`,
          type: 'SECURITY_MISCONFIGURATION',
          severity: 'low',
          title: `Approved Missing HTTP Security Headers on ${context?.endpointUrl ?? record.targetDomain}`,
          description: `Human operator verified missing hardening security headers: ${missing.join(', ')}. Present headers: ${present.join(', ') || 'none'}.`,
          target: context?.endpointUrl ?? `https://${record.targetDomain}/`,
          evidence: JSON.stringify({
            draftId,
            reviewerId,
            reviewedAt,
            notes,
            differentialContext: context,
          }),
          confidence: 0.95,
          metadata: {
            kind: 'missing_security_headers_metadata',
            category: 'SECURITY_MISCONFIGURATION',
            candidateId: `cnd_${draftId}`,
            evidenceRecordId: `evd_${draftId}`,
            missingHeaders: missing,
            presentHeaders: present,
            observedAt: reviewedAt,
            endpointUrl: context?.endpointUrl,
            lineage: {
              assessmentId: record.assessmentId,
              scanId: record.scanId,
              reviewerId,
              reviewedAt,
            },
          },
        };
      } else if (detKind === 'open_redirect') {
        const param = context?.parameterName ?? 'redirect';
        const canary = context?.injectedCanary ?? 'https://canary.fixguard.internal/';
        const dest = context?.finalDestination ?? canary;
        const chain = context?.redirectChain ?? [dest];
        findingCreated = {
          id: `fnd_redir_${draftId.replace(/^dft_/, '')}`,
          type: 'INPUT_VALIDATION_FLAW',
          severity: 'medium',
          title: `Approved Open Redirect on ${context?.endpointUrl ?? record.targetDomain}`,
          description: `Human operator verified unvalidated redirection via parameter '${param}' to canary destination '${dest}'.`,
          target: context?.endpointUrl ?? `https://${record.targetDomain}/`,
          evidence: JSON.stringify({
            draftId,
            reviewerId,
            reviewedAt,
            notes,
            differentialContext: context,
          }),
          confidence: 1.0,
          metadata: {
            kind: 'open_redirect_metadata',
            category: 'INPUT_VALIDATION_FLAW',
            parameterName: param,
            injectedCanary: canary,
            finalDestination: dest,
            redirectChain: chain,
            observedAt: reviewedAt,
            endpointUrl: context?.endpointUrl,
            candidateId: `cnd_${draftId}`,
            evidenceRecordId: `evd_${draftId}`,
            lineage: {
              assessmentId: record.assessmentId,
              scanId: record.scanId,
              reviewerId,
              reviewedAt,
            },
          },
        };
      } else if (detKind === 'information_disclosure') {
        const discKind = context?.disclosureKind ?? 'server_banner';
        const fragment = context?.disclosedFragment ?? 'Disclosed internal fragment';
        const trig = context?.trigger ?? 'Anomalous probe';
        findingCreated = {
          id: `fnd_infodisc_${draftId.replace(/^dft_/, '')}`,
          type: 'SECURITY_MISCONFIGURATION',
          severity: discKind === 'stack_trace' ? 'low' : 'info',
          title: `Approved Information Disclosure (${discKind}) on ${context?.endpointUrl ?? record.targetDomain}`,
          description: `Human operator verified information disclosure (${discKind}) under trigger '${trig}': ${fragment}`,
          target: context?.endpointUrl ?? `https://${record.targetDomain}/`,
          evidence: JSON.stringify({
            draftId,
            reviewerId,
            reviewedAt,
            notes,
            differentialContext: context,
          }),
          confidence: 0.95,
          metadata: {
            kind: 'information_disclosure_metadata',
            category: 'SECURITY_MISCONFIGURATION',
            disclosureKind: discKind,
            disclosedFragment: fragment,
            trigger: trig,
            observedAt: reviewedAt,
            endpointUrl: context?.endpointUrl,
            candidateId: `cnd_${draftId}`,
            evidenceRecordId: `evd_${draftId}`,
            lineage: {
              assessmentId: record.assessmentId,
              scanId: record.scanId,
              reviewerId,
              reviewedAt,
            },
          },
        };
      } else if (detKind === 'subdomain_takeover') {
        const subdomain = context?.subdomain ?? record.targetDomain;
        const cnameTarget = context?.cnameTarget ?? 'cloud-provider-target';
        const provider = context?.hostingProvider ?? 'unknown';
        const fingerprint = context?.fingerprintMatch ?? 'unclaimed resource signature';

        findingCreated = {
          id: `fnd_takeover_${draftId.replace(/^dft_/, '')}`,
          type: 'DNS_HIJACKING_RISK',
          severity: 'high',
          title: `Approved Subdomain Takeover Risk (${provider}) on ${subdomain}`,
          description: `Human operator verified subdomain takeover vulnerability. Subdomain '${subdomain}' points via CNAME to '${cnameTarget}' (${provider}) with unclaimed fingerprint: "${fingerprint}".`,
          target: context?.endpointUrl ?? `https://${subdomain}/`,
          evidence: JSON.stringify({
            draftId,
            reviewerId,
            reviewedAt,
            notes,
            differentialContext: context,
          }),
          confidence: 1.0,
          metadata: {
            kind: 'subdomain_takeover_metadata',
            category: 'DNS_HIJACKING_RISK',
            subdomain,
            cnameTarget,
            hostingProvider: provider,
            fingerprintMatch: fingerprint,
            observedAt: reviewedAt,
            endpointUrl: context?.endpointUrl ?? `https://${subdomain}/`,
            candidateId: `cnd_${draftId}`,
            evidenceRecordId: `evd_${draftId}`,
            lineage: {
              assessmentId: record.assessmentId,
              scanId: record.scanId,
              reviewerId,
              reviewedAt,
            },
          },
        };
      } else if (detKind === 'weak_tls_configuration') {
        const targetHost = context?.targetHost ?? record.targetDomain;
        const port = context?.port ?? 443;
        const weakProtocols = context?.weakProtocols ?? [];
        const weakCiphers = context?.weakCiphers ?? [];
        const certificateIssues = context?.certificateIssues ?? [];
        const supportedTlsVersions = context?.supportedTlsVersions ?? [];
        const hasInsecure = weakProtocols.some((p) => {
          const norm = p.toLowerCase().trim();
          return (
            norm.includes('ssl2') ||
            norm.includes('ssl3') ||
            norm.includes('sslv2') ||
            norm.includes('sslv3') ||
            norm.includes('ssl 2') ||
            norm.includes('ssl 3') ||
            /(?:ssl|sslv)[23]|ssl\s*[23]/i.test(norm)
          );
        });



        const flawDescriptions: string[] = [];
        if (weakProtocols.length > 0) flawDescriptions.push(`Protocols: ${weakProtocols.join(', ')}`);
        if (weakCiphers.length > 0) flawDescriptions.push(`Weak Ciphers: ${weakCiphers.join(', ')}`);
        if (certificateIssues.length > 0) flawDescriptions.push(`Cert Issues: ${certificateIssues.join(', ')}`);

        findingCreated = {
          id: `fnd_tls_${draftId.replace(/^dft_/, '')}`,
          type: 'SECURITY_MISCONFIGURATION',
          severity: hasInsecure
            ? 'high'
            : weakProtocols.length > 0 || certificateIssues.includes('expired') || certificateIssues.includes('self_signed')
            ? 'medium'
            : 'low',
          title: `Approved Weak TLS Configuration on ${targetHost}:${port}`,
          description: `Human operator verified TLS weaknesses on ${targetHost}:${port}: ${flawDescriptions.join(' | ') || 'non-compliant configuration'}.`,
          target: context?.endpointUrl ?? `https://${targetHost}:${port}/`,
          evidence: JSON.stringify({
            draftId,
            reviewerId,
            reviewedAt,
            notes,
            differentialContext: context,
          }),
          confidence: 1.0,
          metadata: {
            kind: 'weak_tls_metadata',
            category: 'SECURITY_MISCONFIGURATION',
            targetHost,
            port,
            weakProtocols,
            weakCiphers,
            certificateIssues,
            supportedTlsVersions,
            observedAt: reviewedAt,
            endpointUrl: context?.endpointUrl ?? `https://${targetHost}:${port}/`,
            candidateId: `cnd_${draftId}`,
            evidenceRecordId: `evd_${draftId}`,
            lineage: {
              assessmentId: record.assessmentId,
              scanId: record.scanId,
              reviewerId,
              reviewedAt,
            },
          },
        };
      } else if (detKind === 'sourcemap_exposure') {
        const exposedMapUrl = context?.exposedMapUrl ?? `https://${record.targetDomain}/bundle.js.map`;
        const sourceJsUrl = context?.sourceJsUrl ?? `https://${record.targetDomain}/bundle.js`;
        const sampleSourcesCount = context?.sampleSourcesCount;
        const mapFileSizeBytes = context?.mapFileSizeBytes;
        findingCreated = {
          id: `fnd_smap_${draftId.replace(/^dft_/, '').replace(/^draft_/, '')}`,
          type: 'INFORMATION_DISCLOSURE',
          severity: 'medium',
          title: `Approved Sourcemap Exposure on ${exposedMapUrl}`,
          description: `Human operator verified that production JavaScript sourcemap is publicly exposed at '${exposedMapUrl}' (source: ${sourceJsUrl}). This exposes frontend source tree and internal API surface.`,
          target: exposedMapUrl,
          evidence: JSON.stringify({
            draftId,
            reviewerId,
            reviewedAt,
            notes,
            differentialContext: context,
          }),
          confidence: 1.0,
          metadata: {
            kind: 'sourcemap_exposure_metadata',
            category: 'INFORMATION_DISCLOSURE',
            exposedMapUrl,
            sourceJsUrl,
            detectionSignal: 'sourcemapping_url_comment',
            mapFileSizeBytes,
            sampleSourcesCount,
            observedAt: reviewedAt,
            candidateId: `cnd_${draftId}`,
            evidenceRecordId: `evd_${draftId}`,
            lineage: `${record.assessmentId}:${record.scanId}:${reviewerId}:${reviewedAt}`,
          },
        };
      } else if (detKind === 'wordpress_surface') {
        const wpProbeKind = context?.wpProbeKind ?? 'xmlrpc_capabilities';
        const endpointUrl = context?.endpointUrl ?? `https://${record.targetDomain}/xmlrpc.php`;
        const multicallSupported = context?.multicallSupported;
        const xmlRpcMethodsExposed = context?.xmlRpcMethodsExposed;
        const exposedUsersCount = context?.exposedUsersCount;
        const sampleUserSlugs = context?.sampleUserSlugs;

        if (wpProbeKind === 'xmlrpc_capabilities') {
          findingCreated = {
            id: `fnd_wpxml_${draftId.replace(/^dft_/, '').replace(/^draft_/, '')}`,
            type: 'SECURITY_MISCONFIGURATION',
            severity: multicallSupported ? 'medium' : 'low',
            title: `Approved WordPress XML-RPC API Exposure on ${endpointUrl}`,
            description: `Human operator verified that WordPress XML-RPC endpoint '${endpointUrl}' is publicly active${multicallSupported ? ' with system.multicall amplification support' : ''}.`,
            target: endpointUrl,
            evidence: JSON.stringify({
              draftId,
              reviewerId,
              reviewedAt,
              notes,
              differentialContext: context,
            }),
            confidence: 1.0,
            metadata: {
              kind: 'wordpress_surface_metadata',
              category: 'SECURITY_MISCONFIGURATION',
              probeKind: 'xmlrpc_capabilities',
              endpointUrl,
              xmlRpcMethodsExposed,
              multicallSupported,
              observedAt: reviewedAt,
              candidateId: `cnd_${draftId}`,
              evidenceRecordId: `evd_${draftId}`,
              lineage: `${record.assessmentId}:${record.scanId}:${reviewerId}:${reviewedAt}`,
            },
          };
        } else {
          findingCreated = {
            id: `fnd_wpusr_${draftId.replace(/^dft_/, '').replace(/^draft_/, '')}`,
            type: 'INFORMATION_DISCLOSURE',
            severity: 'medium',
            title: `Approved WordPress REST User Enumeration on ${endpointUrl}`,
            description: `Human operator verified that WordPress user identities are publicly disclosed at '${endpointUrl}' (${exposedUsersCount ?? 0} users, slugs: ${sampleUserSlugs?.join(', ') ?? 'n/a'}).`,
            target: endpointUrl,
            evidence: JSON.stringify({
              draftId,
              reviewerId,
              reviewedAt,
              notes,
              differentialContext: context,
            }),
            confidence: 1.0,
            metadata: {
              kind: 'wordpress_surface_metadata',
              category: 'INFORMATION_DISCLOSURE',
              probeKind: 'rest_user_enumeration',
              endpointUrl,
              exposedUsersCount,
              sampleUserSlugs,
              observedAt: reviewedAt,
              candidateId: `cnd_${draftId}`,
              evidenceRecordId: `evd_${draftId}`,
              lineage: `${record.assessmentId}:${record.scanId}:${reviewerId}:${reviewedAt}`,
            },
          };
        }
      } else if (detKind === 'sql_error_oracle') {
        const endpointUrl = context?.endpointUrl ?? `https://${record.targetDomain}/`;
        const parameterName = context?.parameterName ?? 'id';
        const databaseEngine = context?.databaseEngine ?? 'unknown';
        const injectedProbe = context?.injectedProbe ?? `'FixGuard_Oracle_${draftId}`;
        const errorFragment = context?.sqlErrorFragment ?? 'Unhandled database query error';

        findingCreated = {
          id: `fnd_sqlo_${draftId.replace(/^dft_/, '').replace(/^draft_/, '')}`,
          type: 'INFORMATION_DISCLOSURE',
          severity: 'medium',
          title: `Approved Database Error Oracle (${databaseEngine.toUpperCase()}) on '${parameterName}'`,
          description: `Human operator verified database error disclosure (${databaseEngine}) on parameter '${parameterName}' at ${endpointUrl}. Disclosed fragment: "${errorFragment}".`,
          target: endpointUrl,
          evidence: JSON.stringify({
            draftId,
            reviewerId,
            reviewedAt,
            notes,
            differentialContext: context,
          }),
          confidence: 1.0,
          metadata: {
            kind: 'sql_error_oracle_metadata',
            category: 'INFORMATION_DISCLOSURE',
            databaseEngine,
            parameterName,
            injectedProbe,
            errorFragment,
            endpointUrl,
            observedAt: reviewedAt,
            candidateId: `cnd_${draftId}`,
            evidenceRecordId: `evd_${draftId}`,
            lineage: `${record.assessmentId}:${record.scanId}:${reviewerId}:${reviewedAt}`,
          },
        };
      } else if (detKind === 'graphql_surface') {
        const endpointUrl = context?.endpointUrl ?? `https://${record.targetDomain}/graphql`;
        const introspectionEnabled = context?.introspectionEnabled ?? false;
        const batchingEnabled = context?.batchingEnabled ?? false;
        const fieldSuggestionsEnabled = context?.fieldSuggestionsEnabled ?? false;
        const discoveredRootTypes = context?.discoveredRootTypes;
        const suggestionLeak = context?.suggestionLeak;
        const category = introspectionEnabled ? 'INFORMATION_DISCLOSURE' : 'SECURITY_MISCONFIGURATION';

        let parsedPath = '/graphql';
        try {
          parsedPath = new URL(endpointUrl).pathname;
        } catch {
          // fallback
        }

        const details: string[] = [];
        if (introspectionEnabled) {
          details.push(`Schema introspection enabled (${(discoveredRootTypes ?? []).length} root types exposed).`);
        }
        if (fieldSuggestionsEnabled && suggestionLeak) {
          details.push(`Field suggestions enabled disclosing schema fields ("${suggestionLeak}").`);
        }
        if (batchingEnabled) {
          details.push('Array query batching enabled.');
        }

        findingCreated = {
          id: `fnd_gql_${draftId.replace(/^dft_/, '').replace(/^draft_/, '')}`,
          type: category,
          severity: introspectionEnabled ? 'medium' : 'low',
          title: introspectionEnabled
            ? `Approved GraphQL Schema Introspection on ${parsedPath}`
            : `Approved GraphQL Endpoint Misconfiguration on ${parsedPath}`,
          description: `Human operator verified active GraphQL capabilities at ${endpointUrl}. ${details.join(' ')}`,
          target: endpointUrl,
          evidence: JSON.stringify({
            draftId,
            reviewerId,
            reviewedAt,
            notes,
            differentialContext: context,
          }),
          confidence: 1.0,
          metadata: {
            kind: 'graphql_surface_metadata',
            category,
            endpointUrl,
            introspectionEnabled,
            batchingEnabled,
            fieldSuggestionsEnabled,
            discoveredRootTypes,
            suggestionLeak,
            observedAt: reviewedAt,
            candidateId: `cnd_${draftId}`,
            evidenceRecordId: `evd_${draftId}`,
            lineage: `${record.assessmentId}:${record.scanId}:${reviewerId}:${reviewedAt}`,
          },
        };
      } else if (detKind === 'jwt_algorithm_confusion') {
        const endpointUrl = context?.endpointUrl ?? `https://${record.targetDomain}/`;
        const httpMethod = context?.httpMethod ?? 'GET';
        const originalAlgorithm = context?.originalAlgorithm ?? 'RS256';
        const manipulatedAlgorithm = context?.manipulatedAlgorithm ?? 'none';
        const probeMechanism = context?.jwtProbeMechanism ?? 'alg_none_header';

        let parsedPath = '/';
        try {
          parsedPath = new URL(endpointUrl).pathname;
        } catch {
          // fallback
        }

        findingCreated = {
          id: `fnd_jwt_${draftId.replace(/^dft_/, '').replace(/^draft_/, '')}`,
          type: 'BROKEN_AUTHENTICATION',
          severity: 'high',
          title: `Approved JWT Algorithm Confusion (alg: none) on ${parsedPath}`,
          description: `Human operator verified that target application accepts unsigned JSON Web Tokens (alg: none) on ${endpointUrl}, bypassing signature verification.`,
          target: endpointUrl,
          evidence: JSON.stringify({
            draftId,
            reviewerId,
            reviewedAt,
            notes,
            differentialContext: context,
          }),
          confidence: 1.0,
          metadata: {
            kind: 'jwt_algorithm_confusion_metadata',
            category: 'BROKEN_AUTHENTICATION',
            endpointUrl,
            httpMethod,
            originalAlgorithm,
            manipulatedAlgorithm,
            probeMechanism,
            observedAt: reviewedAt,
            candidateId: `cnd_${draftId}`,
            evidenceRecordId: `evd_${draftId}`,
            lineage: `${record.assessmentId}:${record.scanId}:${reviewerId}:${reviewedAt}`,
          },
        };
      } else if (detKind === 'session_fixation') {
        const endpointUrl = context?.endpointUrl ?? `https://${record.targetDomain}/`;
        const httpMethod = context?.httpMethod ?? 'GET';
        const sessionCookieName = context?.sessionCookieName ?? 'PHPSESSID';
        const fixedSessionId = context?.fixedSessionId ?? 'fixguard_fix_token';
        const serverRegeneratedSession = context?.serverRegeneratedSession ?? false;

        let parsedPath = '/';
        try {
          parsedPath = new URL(endpointUrl).pathname;
        } catch {
          // fallback
        }

        findingCreated = {
          id: `fnd_fix_${draftId.replace(/^dft_/, '').replace(/^draft_/, '')}`,
          type: 'BROKEN_AUTHENTICATION',
          severity: 'medium',
          title: `Approved Session Fixation Vulnerability on ${parsedPath} (${sessionCookieName})`,
          description: `Human operator verified that target application accepts caller-supplied session identifier '${sessionCookieName}' on ${endpointUrl} without issuing a regenerating Set-Cookie header.`,
          target: endpointUrl,
          evidence: JSON.stringify({
            draftId,
            reviewerId,
            reviewedAt,
            notes,
            differentialContext: context,
          }),
          confidence: 1.0,
          metadata: {
            kind: 'session_fixation_metadata',
            category: 'BROKEN_AUTHENTICATION',
            endpointUrl,
            httpMethod,
            sessionCookieName,
            fixedSessionId,
            serverRegeneratedSession,
            observedAt: reviewedAt,
            candidateId: `cnd_${draftId}`,
            evidenceRecordId: `evd_${draftId}`,
            lineage: `${record.assessmentId}:${record.scanId}:${reviewerId}:${reviewedAt}`,
          },
        };
      } else {



        findingCreated = {
          id: `fnd_appr_${draftId.replace(/^dft_/, '')}`,
          type: 'SECURITY_MISCONFIGURATION',
          severity: 'medium',
          title: `Approved Finding from Evidence Draft ${draftId}`,
          description: `Human operator verified evidence draft with rationale: ${targetDraft.safeRationale}.`,
          target: context?.endpointUrl ?? `https://${record.targetDomain}/`,
          evidence: JSON.stringify({
            draftId,
            reviewerId,
            reviewedAt,
            notes,
            differentialContext: context,
          }),
          confidence: 1.0,
          metadata: {
            kind: 'security_misconfiguration_metadata',
            category: 'SECURITY_MISCONFIGURATION',
            candidateId: `cnd_${draftId}`,
            evidenceRecordId: `evd_${draftId}`,
            lineage: {
              assessmentId: record.assessmentId,
              scanId: record.scanId,
              reviewerId,
              reviewedAt,
            },
            endpointUrl: context?.endpointUrl,
          },
        };
      }

      await this.repository.update(assessmentId, (prev) => ({
        ...prev,
        findings: [...prev.findings, findingCreated!],
        pendingEvidenceDrafts: remainingDrafts,
      }));
    } else {
      // reject_evidence
      await this.repository.update(assessmentId, (prev) => ({
        ...prev,
        pendingEvidenceDrafts: remainingDrafts,
      }));
    }

    return {
      assessmentId,
      draftId,
      decision,
      reviewerId,
      reviewedAt,
      ...(findingCreated ? { findingCreated } : {}),
      remainingDraftCount: remainingDrafts.length,
    };
  }

  /**
   * Waits for an active assessment pipeline to complete (useful in tests and synchronous gateways).
   */
  public async awaitAssessment(assessmentId: string): Promise<OrchestratedAssessmentRecord | null> {

    const promise = this.activeAssessments.get(assessmentId);
    if (promise) {
      await promise;
    }
    return this.repository.findById(assessmentId);
  }

  private async runPipeline(
    record: OrchestratedAssessmentRecord,
    verifiedDecision: VerifiedAuthorizationDecision,
    scopeGrant: AuthorizedScopeGrant,
    lineage: AuthorizedActiveReconRequestLineage,
    config?: ActiveReconOrchestrationConfig,
    sessionIdentities?: ByotSessionIdentityBundle
  ): Promise<void> {
    const startTime = Date.now();
    let timeoutTimer: NodeJS.Timeout | undefined;

    const timeoutPromise = new Promise<never>((_, reject) => {
      timeoutTimer = setTimeout(() => {
        const err = new Error('Assessment exceeded global execution timeout limit (30m limit)');
        err.name = 'AssessmentTimeoutError';
        reject(err);
      }, ASSESSMENT_GLOBAL_TIMEOUT_MS);
      if (typeof timeoutTimer.unref === 'function') {
        timeoutTimer.unref();
      }
    });

    try {
      await Promise.race([
        this.executePipelineStages(
          record,
          verifiedDecision,
          scopeGrant,
          lineage,
          startTime,
          config,
          sessionIdentities
        ),
        timeoutPromise,
      ]);
    } catch (err: unknown) {
      if (err instanceof Error && err.name === 'AssessmentTimeoutError') {
        await this.repository.update(record.assessmentId, (prev) => ({
          ...prev,
          status: 'failed',
          error: 'Assessment global timeout exceeded (30m limit)',
          reasonCode: 'assessment_global_timeout',
          errorCount: prev.errorCount + 1,
          timing: {
            startedAt: prev.timing.startedAt,
            completedAt: new Date().toISOString(),
            durationMs: Date.now() - startTime,
          },
        }));
        return;
      }

      if (
        err instanceof TargetInstabilityError ||
        (err instanceof Error && err.name === 'TargetInstabilityError')
      ) {
        await this.repository.update(record.assessmentId, (prev) => ({
          ...prev,
          status: 'circuit_broken',
          error: err instanceof Error ? err.message : 'Target instability circuit open',
          warningCount: prev.warningCount + 1,
          timing: {
            startedAt: prev.timing.startedAt,
            completedAt: new Date().toISOString(),
            durationMs: Date.now() - startTime,
          },
        }));
        return;
      }

      const errorMsg = err instanceof Error ? err.message : 'Unknown execution failure';
      await this.repository.update(record.assessmentId, (prev) => ({
        ...prev,
        status: 'failed',
        error: errorMsg,
        errorCount: prev.errorCount + 1,
        timing: {
          startedAt: prev.timing.startedAt,
          completedAt: new Date().toISOString(),
          durationMs: Date.now() - startTime,
        },
      }));
    } finally {
      if (timeoutTimer) {
        clearTimeout(timeoutTimer);
      }
      this.activeAssessments.delete(record.assessmentId);
    }
  }

  private async executePipelineStages(
    record: OrchestratedAssessmentRecord,
    verifiedDecision: VerifiedAuthorizationDecision,
    scopeGrant: AuthorizedScopeGrant,
    lineage: AuthorizedActiveReconRequestLineage,
    startTime: number,
    config?: ActiveReconOrchestrationConfig,
    sessionIdentities?: ByotSessionIdentityBundle
  ): Promise<void> {
    const coordinator = new TargetExecutionCoordinator({
      requestsPerSecond: 5,
      maxConcurrency: 2,
    });

    const identityAContext = sessionIdentities?.identityA
      ? buildProbeAuthContext(sessionIdentities.identityA)
      : buildAnonymousProbeContext('identity_anon_a');

    const identityBContext = sessionIdentities?.identityB
      ? buildProbeAuthContext(sessionIdentities.identityB)
      : buildAnonymousProbeContext('identity_anon_b');

    // 1. M73 Composite Active Reconnaissance Orchestration
    const orchestrator = new CompositeActiveReconOrchestratorService(this.reconAdapters);
      const reconResult = await orchestrator.orchestrate({
        targetDomain: record.targetDomain,
        verifiedAuthorizationDecision: verifiedDecision,
        authorizedScopeGrant: scopeGrant,
        lineage,
        config,
        coordinator,
        dnsResolver: this.dnsResolver,
        onStageComplete: async (stageResult) => {
          await this.repository.update(record.assessmentId, (prev) => {
            const existingStages = prev.stages.filter((s) => s.stage !== stageResult.stage);
            return {
              ...prev,
              stages: [...existingStages, stageResult],
            };
          });
        },
      });

      if (reconResult.status === 'preflight_denied') {
        await this.repository.update(record.assessmentId, (prev) => ({
          ...prev,
          status: 'preflight_denied',
          stages: [],
          timing: {
            startedAt: prev.timing.startedAt,
            completedAt: new Date().toISOString(),
            durationMs: Date.now() - startTime,
          },
          error: reconResult.reason,
          errorCount: 1,
        }));
        return;
      }

      if (reconResult.status === 'circuit_broken') {
        const rawObservations = [
          ...reconResult.aggregatedObservations.webObservations,
          ...reconResult.aggregatedObservations.dnsRecords,
          ...reconResult.aggregatedObservations.ports,
          ...reconResult.aggregatedObservations.tlsCertificates,
        ];

        const profile = buildTargetProfile({
          targetHost: record.targetDomain,
          normalizedOrigin: `https://${record.targetDomain}`,
          findings: [],
          observations: rawObservations,
          lineage,
        });

        const recommendationResult = correlateTargetProfile(profile);

        await this.repository.update(record.assessmentId, (prev) => ({
          ...prev,
          status: 'circuit_broken',
          stages: reconResult.stages,
          profile,
          findings: [],
          recommendations: recommendationResult.recommendations,
          timing: {
            startedAt: prev.timing.startedAt,
            completedAt: new Date().toISOString(),
            durationMs: Date.now() - startTime,
          },
          error: reconResult.reason,
          warningCount: prev.warningCount + 1,
        }));
        return;
      }

      // 2. F4 Vulnerability Detection Verticals (CORS & Parameter Reflection)
      const targetUrl = `https://${record.targetDomain}/`;
      const findings: Finding[] = [];
      const pendingEvidenceDrafts: EnrichedEvidenceDraft[] = [];

      if (!coordinator.isCircuitOpen(record.targetDomain)) {
        try {
          const corsResult = await runCorsMisconfigurationDetection({
            contractVersion: DETECTION_CONTRACT_VERSION,
            kind: 'cors_misconfiguration_detection_request',
            detectionId: `det_cors_${record.assessmentId.slice(-8)}`,
            assessmentId: lineage.assessmentId,
            scanId: lineage.scanId,
            authorizationGrantId: lineage.authorizationGrantId,
            authorizationDecisionId: lineage.authorizationDecisionId,
            actorId: lineage.actorId,
            endpointUrl: targetUrl,
            verifiedAuthorizationDecision: verifiedDecision,
            scopeGrant,
            coordinator,
            transport: this.httpTransport,
            dnsResolver: this.dnsResolver,
          });

          if (corsResult.status === 'vulnerability_detected' && corsResult.finding) {
            findings.push(corsResult.finding);
          } else if (corsResult.status === 'pending_human_review' && corsResult.evidenceDraft) {
            const enrichedDraft: EnrichedEvidenceDraft = {
              ...corsResult.evidenceDraft,
              differentialContext: {
                endpointUrl: targetUrl,
                detectionKind: 'cors_misconfiguration',
                baselineStatusCode: corsResult.baselineSnapshot?.statusCode,
                baselineBodyHash: corsResult.baselineSnapshot?.bodyHash,
                validationStatusCode: corsResult.validationSnapshot?.statusCode,
                validationBodyHash: corsResult.validationSnapshot?.bodyHash,
                reflectedOrigin: corsResult.reflectedOrigin,
                allowCredentials: corsResult.allowCredentials,
              },
            };
            pendingEvidenceDrafts.push(enrichedDraft);
          }
        } catch {
          // Safe error containment
        }
      }

      if (!coordinator.isCircuitOpen(record.targetDomain)) {
        try {
          const reflectionResult = await runParameterReflectionDetection({
            contractVersion: DETECTION_CONTRACT_VERSION,
            kind: 'parameter_reflection_detection_request',
            detectionId: `det_refl_${record.assessmentId.slice(-8)}`,
            assessmentId: lineage.assessmentId,
            scanId: lineage.scanId,
            authorizationGrantId: lineage.authorizationGrantId,
            authorizationDecisionId: lineage.authorizationDecisionId,
            actorId: lineage.actorId,
            endpointUrl: targetUrl,
            parameterName: 'q',
            verifiedAuthorizationDecision: verifiedDecision,
            scopeGrant,
            coordinator,
            transport: this.httpTransport,
            dnsResolver: this.dnsResolver,
          });

          if (reflectionResult.status === 'vulnerability_detected' && reflectionResult.finding) {
            findings.push(reflectionResult.finding);
          } else if (reflectionResult.status === 'pending_human_review' && reflectionResult.evidenceDraft) {
            const enrichedDraft: EnrichedEvidenceDraft = {
              ...reflectionResult.evidenceDraft,
              differentialContext: {
                endpointUrl: targetUrl,
                detectionKind: 'parameter_reflection',
                baselineStatusCode: reflectionResult.baselineSnapshot?.statusCode,
                baselineBodyHash: reflectionResult.baselineSnapshot?.bodyHash,
                validationStatusCode: reflectionResult.validationSnapshot?.statusCode,
                validationBodyHash: reflectionResult.validationSnapshot?.bodyHash,
                parameterName: 'q',
                reflectedCanary: reflectionResult.reflectedCanary,
              },
            };
            pendingEvidenceDrafts.push(enrichedDraft);
          }
        } catch {
          // Safe error containment
        }
      }

      // Multi-Identity Differential IDOR Detection with BYOT (Milestone P3-3)
      if (!coordinator.isCircuitOpen(record.targetDomain)) {
        const candidateEndpoints: Array<{ endpointUrl: string; resourceParamName: string; baselineResourceId: string }> = [];

        // Check discovered parameters from recon
        if (reconResult?.aggregatedObservations?.parameters) {
          for (const paramObs of reconResult.aggregatedObservations.parameters) {
            const pName = paramObs.parameterName.toLowerCase();
            if (
              pName === 'id' ||
              pName === 'user_id' ||
              pName === 'userid' ||
              pName === 'account_id' ||
              pName === 'order_id' ||
              pName === 'doc_id' ||
              pName === 'item_id'
            ) {
              candidateEndpoints.push({
                endpointUrl: paramObs.url,
                resourceParamName: paramObs.parameterName,
                baselineResourceId: '1',
              });
            }
          }
        }

        // Also check discovered URLs for RESTful ID patterns (e.g. /users/1, /api/orders/123)
        if (reconResult?.aggregatedObservations?.urls) {
          for (const urlObs of reconResult.aggregatedObservations.urls) {
            const match = urlObs.url.match(/\/(users|orders|accounts|items|documents|api\/users|api\/orders|api\/accounts)\/([0-9a-zA-Z_-]+)$/i);
            if (match && match[2]) {
              candidateEndpoints.push({
                endpointUrl: urlObs.url,
                resourceParamName: match[1],
                baselineResourceId: match[2],
              });
            }
          }
        }

        // Fallback default endpoint candidate if none was explicitly crawled
        if (candidateEndpoints.length === 0) {
          candidateEndpoints.push({
            endpointUrl: `https://${record.targetDomain}/api/user/1`,
            resourceParamName: 'id',
            baselineResourceId: '1',
          });
        }

        for (const candidate of candidateEndpoints.slice(0, 3)) {
          if (coordinator.isCircuitOpen(record.targetDomain)) break;
          try {
            const idorResult = await runIdorDifferentialDetection({
              contractVersion: DETECTION_CONTRACT_VERSION,
              kind: 'idor_differential_detection_request',
              detectionId: `det_diff_${record.assessmentId.slice(-8)}_${candidate.resourceParamName.replace(/[^a-zA-Z0-9]/g, '')}`,
              assessmentId: lineage.assessmentId,
              scanId: lineage.scanId,
              authorizationGrantId: lineage.authorizationGrantId,
              authorizationDecisionId: lineage.authorizationDecisionId,
              actorId: lineage.actorId,
              endpointUrl: candidate.endpointUrl,
              resourceParamName: candidate.resourceParamName,
              baselineResourceId: candidate.baselineResourceId,
              identityA: identityAContext,
              identityB: identityBContext,
              verifiedAuthorizationDecision: verifiedDecision,
              scopeGrant,
              transport: this.httpTransport,
              dnsResolver: this.dnsResolver,
            });

            if (idorResult.status === 'vulnerability_detected' && idorResult.finding) {
              findings.push(idorResult.finding);
            } else if (idorResult.status === 'pending_human_review' && idorResult.evidenceDraft) {
              const enrichedDraft: EnrichedEvidenceDraft = {
                ...idorResult.evidenceDraft,
                differentialContext: {
                  endpointUrl: candidate.endpointUrl,
                  detectionKind: 'idor_access_control',
                  baselineStatusCode: idorResult.baselineSnapshot?.statusCode,
                  baselineBodyHash: idorResult.baselineSnapshot?.bodyHash,
                  validationStatusCode: idorResult.validationSnapshot?.statusCode,
                  validationBodyHash: idorResult.validationSnapshot?.bodyHash,
                  resourceParamName: candidate.resourceParamName,
                  baselineResourceId: candidate.baselineResourceId,
                },
              };
              pendingEvidenceDrafts.push(enrichedDraft);
            }
          } catch {
            // Safe error containment
          }
        }

        // Authentication Bypass Detection with BYOT (Milestone P4-1)
        if (!coordinator.isCircuitOpen(record.targetDomain) && sessionIdentities?.identityA) {
          for (const candidate of candidateEndpoints.slice(0, 3)) {
            if (coordinator.isCircuitOpen(record.targetDomain)) break;
            try {
              const authBypassResult = await runAuthBypassDetection({
                contractVersion: DETECTION_CONTRACT_VERSION,
                kind: 'auth_bypass_detection_request',
                detectionId: `det_ab_${record.assessmentId.slice(-8)}_${candidate.resourceParamName.replace(/[^a-zA-Z0-9]/g, '')}`,
                assessmentId: lineage.assessmentId,
                scanId: lineage.scanId,
                authorizationGrantId: lineage.authorizationGrantId,
                authorizationDecisionId: lineage.authorizationDecisionId,
                actorId: lineage.actorId,
                endpointUrl: candidate.endpointUrl,
                method: 'GET',
                identityA: identityAContext,
                bypassMechanism: 'header_stripping',
                verifiedAuthorizationDecision: verifiedDecision,
                scopeGrant,
                transport: this.httpTransport,
                dnsResolver: this.dnsResolver,
              });

              if (authBypassResult.status === 'vulnerability_detected' && authBypassResult.finding) {
                findings.push(authBypassResult.finding);
              } else if (authBypassResult.status === 'pending_human_review' && authBypassResult.evidenceDraft) {
                const enrichedDraft: EnrichedEvidenceDraft = {
                  ...authBypassResult.evidenceDraft,
                  differentialContext: {
                    endpointUrl: candidate.endpointUrl,
                    detectionKind: 'auth_bypass',
                    baselineStatusCode: authBypassResult.baselineSnapshot?.statusCode,
                    baselineBodyHash: authBypassResult.baselineSnapshot?.bodyHash,
                    validationStatusCode: authBypassResult.validationSnapshot?.statusCode,
                    validationBodyHash: authBypassResult.validationSnapshot?.bodyHash,
                    bypassMechanism: 'header_stripping',
                    bodySimilarityRatio: authBypassResult.similarityRatio ?? 1.0,
                    httpMethod: 'GET',
                  },
                };
                pendingEvidenceDrafts.push(enrichedDraft);
              }
            } catch {
              // Safe error containment
            }
          }
        }
      }

      if (!coordinator.isCircuitOpen(record.targetDomain)) {
        try {
          const headerResult = await runSecurityHeaderDetection({
            contractVersion: DETECTION_CONTRACT_VERSION,
            kind: 'security_header_detection_request',
            detectionId: `det_sh_${record.assessmentId.slice(-8)}`,
            assessmentId: lineage.assessmentId,
            scanId: lineage.scanId,
            authorizationGrantId: lineage.authorizationGrantId,
            authorizationDecisionId: lineage.authorizationDecisionId,
            actorId: lineage.actorId,
            endpointUrl: targetUrl,
            verifiedAuthorizationDecision: verifiedDecision,
            scopeGrant,
            coordinator,
            transport: this.httpTransport,
            dnsResolver: this.dnsResolver,
          });

          if (headerResult.status === 'potential_weakness' && headerResult.finding) {
            findings.push(headerResult.finding);
          } else if (headerResult.status === 'pending_human_review' && headerResult.evidenceDraft) {
            const enrichedDraft: EnrichedEvidenceDraft = {
              ...headerResult.evidenceDraft,
              differentialContext: {
                endpointUrl: targetUrl,
                detectionKind: 'missing_security_headers',
                missingHeaders: headerResult.missingHeaders,
                presentHeaders: headerResult.presentHeaders,
              },
            };
            pendingEvidenceDrafts.push(enrichedDraft);
          }
        } catch {
          // Safe error containment
        }
      }

      if (!coordinator.isCircuitOpen(record.targetDomain)) {
        try {
          const redirectResult = await runOpenRedirectDetection({
            contractVersion: DETECTION_CONTRACT_VERSION,
            kind: 'open_redirect_detection_request',
            detectionId: `det_redir_${record.assessmentId.slice(-8)}`,
            assessmentId: lineage.assessmentId,
            scanId: lineage.scanId,
            authorizationGrantId: lineage.authorizationGrantId,
            authorizationDecisionId: lineage.authorizationDecisionId,
            actorId: lineage.actorId,
            endpointUrl: targetUrl,
            verifiedAuthorizationDecision: verifiedDecision,
            scopeGrant,
            coordinator,
            transport: this.httpTransport,
            dnsResolver: this.dnsResolver,
          });

          if (redirectResult.status === 'exploit_confirmed' && redirectResult.finding) {
            findings.push(redirectResult.finding);
          } else if (redirectResult.status === 'pending_human_review' && redirectResult.evidenceDraft) {
            const enrichedDraft: EnrichedEvidenceDraft = {
              ...redirectResult.evidenceDraft,
              differentialContext: {
                endpointUrl: targetUrl,
                detectionKind: 'open_redirect',
                parameterName: redirectResult.parameterName,
                injectedCanary: redirectResult.injectedCanary,
                finalDestination: redirectResult.finalDestination,
                redirectChain: redirectResult.redirectChain,
              },
            };
            pendingEvidenceDrafts.push(enrichedDraft);
          }
        } catch {
          // Safe error containment
        }
      }

      if (!coordinator.isCircuitOpen(record.targetDomain)) {
        try {
          const infoDiscResult = await runInformationDisclosureDetection({
            contractVersion: DETECTION_CONTRACT_VERSION,
            kind: 'information_disclosure_detection_request',
            detectionId: `det_infodisc_${record.assessmentId.slice(-8)}`,
            assessmentId: lineage.assessmentId,
            scanId: lineage.scanId,
            authorizationGrantId: lineage.authorizationGrantId,
            authorizationDecisionId: lineage.authorizationDecisionId,
            actorId: lineage.actorId,
            endpointUrl: targetUrl,
            verifiedAuthorizationDecision: verifiedDecision,
            scopeGrant,
            coordinator,
            transport: this.httpTransport,
            dnsResolver: this.dnsResolver,
          });

          if (infoDiscResult.status === 'potential_weakness' && infoDiscResult.finding) {
            findings.push(infoDiscResult.finding);
          } else if (infoDiscResult.status === 'pending_human_review' && infoDiscResult.evidenceDraft) {
            const primaryDisc = infoDiscResult.disclosures[0];
            const enrichedDraft: EnrichedEvidenceDraft = {
              ...infoDiscResult.evidenceDraft,
              differentialContext: {
                endpointUrl: targetUrl,
                detectionKind: 'information_disclosure',
                disclosureKind: primaryDisc?.disclosureKind,
                disclosedFragment: primaryDisc?.disclosedFragment,
                trigger: primaryDisc?.trigger,
              },
            };
            pendingEvidenceDrafts.push(enrichedDraft);
          }
        } catch {
          // Safe error containment
        }
      }

      // Subdomain Takeover Detection (Milestone P2-4)
      const cnameRecords = reconResult.aggregatedObservations.dnsRecords.filter(
        (r) => r.recordType === 'CNAME'
      );

      for (const cnameRec of cnameRecords) {
        if (coordinator.isCircuitOpen(record.targetDomain)) break;
        for (const cnameTarget of cnameRec.values) {
          if (coordinator.isCircuitOpen(record.targetDomain)) break;
          try {
            const takeoverResult = await runSubdomainTakeoverDetection({
              contractVersion: DETECTION_CONTRACT_VERSION,
              kind: 'subdomain_takeover_detection_request',
              detectionId: `det_takeover_${record.assessmentId.slice(-8)}_${cnameRec.domain.replace(/[^a-zA-Z0-9]/g, '').slice(0, 8)}`,
              assessmentId: lineage.assessmentId,
              scanId: lineage.scanId,
              authorizationGrantId: lineage.authorizationGrantId,
              authorizationDecisionId: lineage.authorizationDecisionId,
              actorId: lineage.actorId,
              subdomain: cnameRec.domain,
              cnameTarget,
              verifiedAuthorizationDecision: verifiedDecision,
              scopeGrant,
              coordinator,
              transport: this.httpTransport,
              dnsResolver: this.dnsResolver,
            });

            if (takeoverResult.status === 'vulnerability_detected' && takeoverResult.finding) {
              findings.push(takeoverResult.finding);
            } else if (takeoverResult.status === 'pending_human_review' && takeoverResult.evidenceDraft) {
              const enrichedDraft: EnrichedEvidenceDraft = {
                ...takeoverResult.evidenceDraft,
                differentialContext: {
                  endpointUrl: `https://${cnameRec.domain}`,
                  detectionKind: 'subdomain_takeover',
                  subdomain: cnameRec.domain,
                  cnameTarget,
                  hostingProvider: takeoverResult.hostingProvider,
                  fingerprintMatch: takeoverResult.fingerprintMatch,
                },
              };
              pendingEvidenceDrafts.push(enrichedDraft);
            }
          } catch {
            // Safe error containment
          }
        }
      }

      // TLS Configuration Analysis (Milestone P2-5)
      const tlsObservations = reconResult.aggregatedObservations.tlsCertificates;
      for (const tlsObs of tlsObservations) {
        try {
          const tlsResult = analyzeTlsConfiguration({
            contractVersion: DETECTION_CONTRACT_VERSION,
            kind: 'tls_configuration_analysis_request',
            detectionId: `det_tls_${record.assessmentId.slice(-8)}_${tlsObs.host.replace(/[^a-zA-Z0-9]/g, '').slice(0, 8)}`,
            assessmentId: lineage.assessmentId,
            scanId: lineage.scanId,
            authorizationGrantId: lineage.authorizationGrantId,
            authorizationDecisionId: lineage.authorizationDecisionId,
            actorId: lineage.actorId,
            targetHost: tlsObs.host,
            port: tlsObs.port,
            tlsObservation: tlsObs,
          });

          if (tlsResult.status === 'vulnerability_detected' || tlsResult.status === 'potential_weakness') {
            if (tlsResult.finding) {
              findings.push(tlsResult.finding);
            }
          } else if (tlsResult.status === 'pending_human_review' && tlsResult.evidenceDraft) {
            const enrichedDraft: EnrichedEvidenceDraft = {
              ...tlsResult.evidenceDraft,
              differentialContext: {
                endpointUrl: `https://${tlsObs.host}:${tlsObs.port}`,
                detectionKind: 'weak_tls_configuration',
                targetHost: tlsObs.host,
                port: tlsObs.port,
                weakProtocols: tlsResult.weakProtocols,
                weakCiphers: tlsResult.weakCiphers,
                certificateIssues: tlsResult.certificateIssues,
                supportedTlsVersions: tlsResult.supportedTlsVersions,
              },
            };
            pendingEvidenceDrafts.push(enrichedDraft);
          }
        } catch {
          // Safe error containment
        }
      }

      // Sourcemap Exposure Detection (Milestone P4-3)
      if (!coordinator.isCircuitOpen(record.targetDomain)) {
        const jsCandidateUrls = new Set<string>();

        if (reconResult?.aggregatedObservations?.urls) {
          for (const urlObs of reconResult.aggregatedObservations.urls) {
            const cleanUrl = urlObs.url.split('?')[0];
            if (cleanUrl.endsWith('.js')) {
              jsCandidateUrls.add(urlObs.url);
            }
          }
        }

        if (reconResult?.aggregatedObservations?.webObservations) {
          for (const webObs of reconResult.aggregatedObservations.webObservations) {
            const cleanUrl = webObs.url.split('?')[0];
            if (cleanUrl.endsWith('.js')) {
              jsCandidateUrls.add(webObs.url);
            }
          }
        }

        if (jsCandidateUrls.size === 0) {
          jsCandidateUrls.add(`https://${record.targetDomain}/bundle.js`);
          jsCandidateUrls.add(`https://${record.targetDomain}/main.js`);
        }

        const candidateList = Array.from(jsCandidateUrls).slice(0, 5);
        for (const jsUrl of candidateList) {
          if (coordinator.isCircuitOpen(record.targetDomain)) break;
          try {
            const smapResult = await runSourcemapExposureDetection({
              contractVersion: DETECTION_CONTRACT_VERSION,
              kind: 'sourcemap_exposure_detection_request',
              detectionId: `det_smap_${record.assessmentId.slice(-8)}_${jsUrl.replace(/[^a-zA-Z0-9]/g, '').slice(-8)}`,
              assessmentId: lineage.assessmentId,
              scanId: lineage.scanId,
              authorizationGrantId: lineage.authorizationGrantId,
              authorizationDecisionId: lineage.authorizationDecisionId,
              actorId: lineage.actorId,
              sourceJsUrl: jsUrl,
              verifiedAuthorizationDecision: verifiedDecision,
              scopeGrant,
              transport: this.httpTransport,
              dnsResolver: this.dnsResolver,
            });

            if (smapResult.status === 'potential_weakness' && smapResult.finding) {
              findings.push(smapResult.finding);
            } else if (smapResult.status === 'pending_human_review' && smapResult.evidenceDraft) {
              const enrichedDraft: EnrichedEvidenceDraft = {
                ...smapResult.evidenceDraft,
                differentialContext: {
                  endpointUrl: smapResult.exposedMapUrl ?? jsUrl,
                  detectionKind: 'sourcemap_exposure',
                  exposedMapUrl: smapResult.exposedMapUrl,
                  sourceJsUrl: smapResult.sourceJsUrl,
                  sampleSourcesCount: smapResult.sampleSourcesCount,
                  mapFileSizeBytes: smapResult.mapFileSizeBytes,
                },
              };
              pendingEvidenceDrafts.push(enrichedDraft);
            }
          } catch {
            // Safe error containment
          }
        }
      }

      // WordPress Surface Detection (Milestone P4-4: XML-RPC & REST Users)
      if (!coordinator.isCircuitOpen(record.targetDomain)) {
        const wpProbes: ('xmlrpc_capabilities' | 'rest_user_enumeration')[] = [
          'xmlrpc_capabilities',
          'rest_user_enumeration',
        ];

        for (const wpProbe of wpProbes) {
          if (coordinator.isCircuitOpen(record.targetDomain)) break;
          try {
            const wpResult = await runWordPressSurfaceDetection({
              contractVersion: DETECTION_CONTRACT_VERSION,
              kind: 'wordpress_surface_detection_request',
              detectionId: `det_wp_${record.assessmentId.slice(-8)}_${wpProbe === 'xmlrpc_capabilities' ? 'xml' : 'usr'}`,
              assessmentId: lineage.assessmentId,
              scanId: lineage.scanId,
              authorizationGrantId: lineage.authorizationGrantId,
              authorizationDecisionId: lineage.authorizationDecisionId,
              actorId: lineage.actorId,
              targetBaseUrl: targetUrl,
              probeKind: wpProbe,
              verifiedAuthorizationDecision: verifiedDecision,
              scopeGrant,
              transport: this.httpTransport,
              dnsResolver: this.dnsResolver,
            });

            if (
              (wpResult.status === 'potential_weakness' || wpResult.status === 'information_disclosure') &&
              wpResult.finding
            ) {
              findings.push(wpResult.finding);
            } else if (wpResult.status === 'pending_human_review' && wpResult.evidenceDraft) {
              const enrichedDraft: EnrichedEvidenceDraft = {
                ...wpResult.evidenceDraft,
                differentialContext: {
                  endpointUrl: wpResult.endpointUrl ?? targetUrl,
                  detectionKind: 'wordpress_surface',
                  wpProbeKind: wpProbe,
                  xmlRpcMethodsExposed: wpResult.xmlRpcMethodsExposed,
                  multicallSupported: wpResult.multicallSupported,
                  exposedUsersCount: wpResult.exposedUsersCount,
                  sampleUserSlugs: wpResult.sampleUserSlugs,
                },
              };
              pendingEvidenceDrafts.push(enrichedDraft);
            }
          } catch {
            // Safe error containment
          }
        }
      }

      // SQL Error Oracle Detection (Milestone P4-5)
      if (!coordinator.isCircuitOpen(record.targetDomain)) {
        const sqlCandidates: { endpointUrl: string; parameterName: string; method?: 'GET' | 'POST' }[] = [];

        if (reconResult?.aggregatedObservations?.parameters) {
          for (const paramObs of reconResult.aggregatedObservations.parameters) {
            sqlCandidates.push({
              endpointUrl: paramObs.url,
              parameterName: paramObs.parameterName,
              method: 'GET',
            });
          }
        }

        if (reconResult?.aggregatedObservations?.urls) {
          for (const urlObs of reconResult.aggregatedObservations.urls) {
            try {
              const parsed = new URL(urlObs.url);
              for (const [key] of parsed.searchParams.entries()) {
                if (!sqlCandidates.some((c) => c.endpointUrl === urlObs.url && c.parameterName === key)) {
                  sqlCandidates.push({
                    endpointUrl: urlObs.url,
                    parameterName: key,
                    method: 'GET',
                  });
                }
              }
            } catch {
              // Ignore invalid URLs
            }
          }
        }

        if (sqlCandidates.length === 0) {
          sqlCandidates.push({ endpointUrl: targetUrl, parameterName: 'id', method: 'GET' });
          sqlCandidates.push({ endpointUrl: targetUrl, parameterName: 'q', method: 'GET' });
        }

        for (const candidate of sqlCandidates.slice(0, 5)) {
          if (coordinator.isCircuitOpen(record.targetDomain)) break;
          try {
            const sqlResult = await runSqlErrorOracleDetection({
              contractVersion: DETECTION_CONTRACT_VERSION,
              kind: 'sql_error_oracle_detection_request',
              detectionId: `det_sqlo_${record.assessmentId.slice(-8)}_${candidate.parameterName.replace(/[^a-zA-Z0-9]/g, '')}`,
              assessmentId: lineage.assessmentId,
              scanId: lineage.scanId,
              authorizationGrantId: lineage.authorizationGrantId,
              authorizationDecisionId: lineage.authorizationDecisionId,
              actorId: lineage.actorId,
              endpointUrl: candidate.endpointUrl,
              parameterName: candidate.parameterName,
              method: candidate.method,
              verifiedAuthorizationDecision: verifiedDecision,
              scopeGrant,
              transport: this.httpTransport,
              dnsResolver: this.dnsResolver,
            });

            if (
              (sqlResult.status === 'potential_weakness' || sqlResult.status === 'information_disclosure') &&
              sqlResult.finding
            ) {
              findings.push(sqlResult.finding);
            } else if (sqlResult.status === 'pending_human_review' && sqlResult.evidenceDraft) {
              const enrichedDraft: EnrichedEvidenceDraft = {
                ...sqlResult.evidenceDraft,
                differentialContext: {
                  endpointUrl: sqlResult.endpointUrl,
                  detectionKind: 'sql_error_oracle',
                  parameterName: sqlResult.parameterName,
                  databaseEngine: sqlResult.databaseEngine,
                  sqlErrorFragment: sqlResult.errorFragment,
                  injectedProbe: sqlResult.injectedProbe,
                },
              };
              pendingEvidenceDrafts.push(enrichedDraft);
            }
          } catch {
            // Safe error containment
          }
        }

        // GraphQL Surface Detection Probe
        if (!coordinator.isCircuitOpen(record.targetDomain)) {
          try {
            const gqlResult = await runGraphQLSurfaceDetection({
              contractVersion: DETECTION_CONTRACT_VERSION,
              kind: 'graphql_surface_detection_request',
              detectionId: `det_gql_${record.assessmentId.slice(-8)}`,
              assessmentId: lineage.assessmentId,
              scanId: lineage.scanId,
              authorizationGrantId: lineage.authorizationGrantId,
              authorizationDecisionId: lineage.authorizationDecisionId,
              actorId: lineage.actorId,
              endpointUrl: targetUrl,
              verifiedAuthorizationDecision: verifiedDecision,
              scopeGrant,
              transport: this.httpTransport,
              dnsResolver: this.dnsResolver,
            });

            if (
              (gqlResult.status === 'graphql_surface_detected' ||
                gqlResult.status === 'information_disclosure' ||
                gqlResult.status === 'security_misconfiguration') &&
              gqlResult.finding
            ) {
              findings.push(gqlResult.finding);
            } else if (gqlResult.status === 'pending_human_review' && gqlResult.evidenceDraft) {
              const enrichedDraft: EnrichedEvidenceDraft = {
                ...gqlResult.evidenceDraft,
                differentialContext: {
                  endpointUrl: gqlResult.endpointUrl,
                  detectionKind: 'graphql_surface',
                  introspectionEnabled: gqlResult.introspectionEnabled,
                  batchingEnabled: gqlResult.batchingEnabled,
                  fieldSuggestionsEnabled: gqlResult.fieldSuggestionsEnabled,
                  discoveredRootTypes: gqlResult.discoveredRootTypes,
                  suggestionLeak: gqlResult.suggestionLeak,
                },
              };
              pendingEvidenceDrafts.push(enrichedDraft);
            }
          } catch {
            // Safe error containment
          }
        }

        // JWT Algorithm Confusion Probe
        if (!coordinator.isCircuitOpen(record.targetDomain) && identityAContext) {
          try {
            const jwtResult = await runJwtAlgorithmConfusionDetection({
              contractVersion: DETECTION_CONTRACT_VERSION,
              kind: 'jwt_algorithm_confusion_detection_request',
              detectionId: `det_jwt_${record.assessmentId.slice(-8)}`,
              assessmentId: lineage.assessmentId,
              scanId: lineage.scanId,
              authorizationGrantId: lineage.authorizationGrantId,
              authorizationDecisionId: lineage.authorizationDecisionId,
              actorId: lineage.actorId,
              endpointUrl: targetUrl,
              httpMethod: 'GET',
              identityAContext,
              verifiedAuthorizationDecision: verifiedDecision,
              scopeGrant,
              transport: this.httpTransport,
              dnsResolver: this.dnsResolver,
            });

            if (jwtResult.status === 'vulnerability_detected' && jwtResult.finding) {
              findings.push(jwtResult.finding);
            } else if (jwtResult.status === 'pending_human_review' && jwtResult.evidenceDraft) {
              const enrichedDraft: EnrichedEvidenceDraft = {
                ...jwtResult.evidenceDraft,
                differentialContext: {
                  endpointUrl: jwtResult.endpointUrl,
                  detectionKind: 'jwt_algorithm_confusion',
                  httpMethod: jwtResult.httpMethod,
                  originalAlgorithm: jwtResult.originalAlgorithm,
                  manipulatedAlgorithm: jwtResult.manipulatedAlgorithm,
                  jwtProbeMechanism: jwtResult.probeMechanism,
                  baselineStatusCode: jwtResult.baselineStatusCode,
                  validationStatusCode: jwtResult.forgedStatusCode,
                },
              };
              pendingEvidenceDrafts.push(enrichedDraft);
            }
          } catch {
            // Safe error containment
          }
        }

        // Session Fixation Detection Probe
        if (!coordinator.isCircuitOpen(record.targetDomain)) {
          try {
            const fixResult = await runSessionFixationDetection({
              contractVersion: DETECTION_CONTRACT_VERSION,
              kind: 'session_fixation_detection_request',
              detectionId: `det_fix_${record.assessmentId.slice(-8)}`,
              assessmentId: lineage.assessmentId,
              scanId: lineage.scanId,
              authorizationGrantId: lineage.authorizationGrantId,
              authorizationDecisionId: lineage.authorizationDecisionId,
              actorId: lineage.actorId,
              endpointUrl: targetUrl,
              httpMethod: 'GET',
              verifiedAuthorizationDecision: verifiedDecision,
              scopeGrant,
              transport: this.httpTransport,
              dnsResolver: this.dnsResolver,
            });

            if (fixResult.status === 'vulnerability_detected' && fixResult.finding) {
              findings.push(fixResult.finding);
            } else if (fixResult.status === 'pending_human_review' && fixResult.evidenceDraft) {
              const enrichedDraft: EnrichedEvidenceDraft = {
                ...fixResult.evidenceDraft,
                differentialContext: {
                  endpointUrl: fixResult.endpointUrl,
                  detectionKind: 'session_fixation',
                  httpMethod: fixResult.httpMethod,
                  sessionCookieName: fixResult.sessionCookieName,
                  fixedSessionId: fixResult.fixedSessionId,
                  serverRegeneratedSession: fixResult.serverRegeneratedSession,
                  baselineStatusCode: fixResult.responseStatusCode,
                },
              };
              pendingEvidenceDrafts.push(enrichedDraft);
            }
          } catch {
            // Safe error containment
          }
        }
      }

      // 3. F5 Intelligence Synthesis (TargetProfile & Recommendations)
      const rawObservations = [
        ...reconResult.aggregatedObservations.webObservations,
        ...reconResult.aggregatedObservations.dnsRecords,
        ...reconResult.aggregatedObservations.ports,
        ...reconResult.aggregatedObservations.tlsCertificates,
      ];



      const profile = buildTargetProfile({
        targetHost: record.targetDomain,
        normalizedOrigin: `https://${record.targetDomain}`,
        findings,
        observations: rawObservations,
        lineage,
      });

      const recommendationResult = correlateTargetProfile(profile);

      // If circuit breaker opened during detection, record circuit_broken with evidence preserved
      if (coordinator.isCircuitOpen(record.targetDomain)) {
        await this.repository.update(record.assessmentId, (prev) => ({
          ...prev,
          status: 'circuit_broken',
          stages: reconResult.stages,
          profile,
          findings,
          pendingEvidenceDrafts,
          recommendations: recommendationResult.recommendations,
          timing: {
            startedAt: prev.timing.startedAt,
            completedAt: new Date().toISOString(),
            durationMs: Date.now() - startTime,
          },
          error: `Target circuit breaker tripped on '${record.targetDomain}'. Vulnerability probing safely halted.`,
          warningCount: prev.warningCount + 1,
        }));
        return;
      }

      // 4. Update repository with completed assessment state
      await this.repository.update(record.assessmentId, (prev) => ({
        ...prev,
        status: 'completed',
        stages: reconResult.stages,
        profile,
        findings,
        pendingEvidenceDrafts,
        recommendations: recommendationResult.recommendations,
        timing: {
          startedAt: prev.timing.startedAt,
          completedAt: new Date().toISOString(),
          durationMs: Date.now() - startTime,
        },
      }));
  }
}
