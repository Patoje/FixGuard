/**
 * Milestone 8 — Controlled Active Verification & Safe PoC Engine Service
 *
 * Enforces:
 * 1. Human Authorization Gate: Requires runtime-branded VerifiedExploitationAuthorizationDecision.
 * 2. Non-Destructive Payload Invariant: Strictly inert canaries and read-only differential probing.
 * 3. Double SSRF & Egress Gate: Preflight host check + dynamic DNS rebinding mitigation before execution.
 * 4. Blast Radius Protection: Respects TargetExecutionCoordinator ceilings, records responses, halts on OPEN.
 * 5. Cryptographic Proof: Auditable SHA-256 request/response hashes, sanitized diff excerpts, continuous lineage.
 * 6. Strictly zero type bypasses.
 */

import crypto from 'node:crypto';
import { isInternalOrSsrfTarget } from '../recon/policy/PassiveEgressPolicy.js';
import { validateDnsRebinding } from '../recon/adapters/AdapterPreflightPipeline.js';
import {
  CIRCUIT_OPEN_REASON_CODE,
  TargetInstabilityError,
} from '../runtime/CircuitBreakerContracts.js';
import type {
  ActiveVerificationCommand,
  ActiveVerificationProofRecord,
  ActiveVerificationResult,
  ConfirmedFindingCandidateRecord,
  IdorDifferentialExecuteRequest,
  IdorDifferentialExecuteResult,
  VerificationHttpRequest,
  VerificationHttpResponse,
  VerificationHttpTransport,
} from './ActiveVerificationContracts.js';
import {
  ACTIVE_VERIFICATION_CONTRACT_VERSION,
  ACTIVE_VERIFICATION_NON_CLAIMS,
  isRuntimeEstablishedExploitationDecision,
} from './ActiveVerificationContracts.js';

const defaultHttpTransport: VerificationHttpTransport = async (
  req: VerificationHttpRequest
): Promise<VerificationHttpResponse> => {
  const start = Date.now();
  const controller = new AbortController();
  const timeoutMs = req.timeoutMs ?? 10_000;
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const fetchOptions: RequestInit = {
      method: req.method,
      headers: { ...req.headers },
      signal: controller.signal,
    };

    if (req.bodyText && req.method === 'POST') {
      fetchOptions.body = req.bodyText;
    }

    const res = await fetch(req.url, fetchOptions);
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
    clearTimeout(timer);
  }
};

function computeSha256(content: string): string {
  return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}

function sanitizeExcerpt(raw: string, maxLen = 256): string {
  // Redact potential authorization or cookie values
  const redacted = raw
    .replace(/(?:bearer|token|key|secret|password|auth|cookie)[:=]\s*([^\s,;&]+)/gi, '$1=[REDACTED]')
    .replace(/[\r\n\t]+/g, ' ')
    .trim();
  return redacted.slice(0, maxLen);
}

export class ControlledActiveVerificationService {
  private readonly transport: VerificationHttpTransport;

  constructor(transport?: VerificationHttpTransport) {
    this.transport = transport ?? defaultHttpTransport;
  }

  /**
   * Dual-identity IDOR differential execute.
   * Applies static SSRF + optional DNS rebinding gates, then probes with both identities.
   * Does NOT mint exploitation WeakSet brands — callers must already hold attack-execution authority.
   */
  public async execute(
    request: IdorDifferentialExecuteRequest
  ): Promise<IdorDifferentialExecuteResult> {
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(request.targetUrl);
    } catch {
      return {
        status: 'preflight_denied',
        reasonCode: 'invalid_target_url',
        safeMessage: 'Target URL is malformed or invalid',
      };
    }

    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      return {
        status: 'preflight_denied',
        reasonCode: 'invalid_protocol',
        safeMessage: 'IDOR differential target URL must use HTTP or HTTPS',
      };
    }

    const host = parsedUrl.hostname.toLowerCase();

    if (isInternalOrSsrfTarget(host)) {
      return {
        status: 'preflight_denied',
        reasonCode: 'ssrf_target_blocked',
        safeMessage: 'Target URL points to blocked internal, loopback, or metadata host',
      };
    }

    if (request.dnsResolver) {
      const dnsCheck = await validateDnsRebinding(host, request.dnsResolver);
      if (!dnsCheck.ok) {
        return {
          status: 'preflight_denied',
          reasonCode: 'ssrf_target_blocked',
          safeMessage: `Target host resolves to blocked internal or private IP: ${dnsCheck.blockedIp}`,
        };
      }
    }

    const baseHeaders: Record<string, string> = {
      'User-Agent': 'FixGuard-Active-Verification/1.0',
      Accept: '*/*',
    };

    let primaryResponse: VerificationHttpResponse;
    let secondaryResponse: VerificationHttpResponse;
    try {
      primaryResponse = await this.transport({
        url: request.targetUrl,
        method: 'GET',
        headers: { ...baseHeaders, ...(request.primaryIdentity.headers ?? {}) },
        timeoutMs: request.timeoutMs,
      });
      secondaryResponse = await this.transport({
        url: request.targetUrl,
        method: 'GET',
        headers: { ...baseHeaders, ...(request.secondaryIdentity.headers ?? {}) },
        timeoutMs: request.timeoutMs,
      });
    } catch (err) {
      return {
        status: 'failed',
        reasonCode: 'network_execution_error',
        safeMessage: `Failed to execute IDOR differential probe: ${err instanceof Error ? err.message : String(err)}`,
      };
    }

    const denialCodes = new Set([401, 403, 404]);
    if (denialCodes.has(secondaryResponse.statusCode)) {
      const reasonCode =
        secondaryResponse.statusCode === 401
          ? 'http_401'
          : secondaryResponse.statusCode === 403
            ? 'http_403'
            : secondaryResponse.statusCode === 404
              ? 'http_404'
              : 'target_denied';
      return {
        status: 'access_denied',
        reasonCode,
        statusCode: secondaryResponse.statusCode,
        evidenceSummary: `Secondary identity denied object access with HTTP ${secondaryResponse.statusCode}`,
      };
    }

    const primaryOk =
      primaryResponse.statusCode === 200 && primaryResponse.bodyText.length > 0;
    const secondaryOk =
      secondaryResponse.statusCode === 200 && secondaryResponse.bodyText.length > 0;

    if (primaryOk && secondaryOk) {
      return {
        status: 'differential_access_observed',
        primaryStatusCode: primaryResponse.statusCode,
        secondaryStatusCode: secondaryResponse.statusCode,
        primaryBodyHash: computeSha256(primaryResponse.bodyText),
        secondaryBodyHash: computeSha256(secondaryResponse.bodyText),
        evidenceSummary: `Cross-identity differential read observed (primary=${request.primaryIdentity.identityId}, secondary=${request.secondaryIdentity.identityId})`,
      };
    }

    return {
      status: 'access_denied',
      reasonCode: 'target_denied',
      statusCode: secondaryResponse.statusCode,
      evidenceSummary: `No differential object access observed (primary HTTP ${primaryResponse.statusCode}, secondary HTTP ${secondaryResponse.statusCode})`,
    };
  }

  public async verifyActiveExploit(
    command: ActiveVerificationCommand
  ): Promise<ActiveVerificationResult> {
    const startTime = Date.now();

    // -------------------------------------------------------------------------
    // 1. Target URL & Format Validation
    // -------------------------------------------------------------------------
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(command.targetUrl);
    } catch {
      return {
        status: 'preflight_denied',
        contractVersion: ACTIVE_VERIFICATION_CONTRACT_VERSION,
        targetUrl: command.targetUrl,
        reasonCode: 'invalid_target_url',
        reason: 'Target URL is malformed or invalid',
        explicitNonClaims: ACTIVE_VERIFICATION_NON_CLAIMS,
        lineage: { ...command.lineage },
        durationMs: Date.now() - startTime,
      };
    }

    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      return {
        status: 'preflight_denied',
        contractVersion: ACTIVE_VERIFICATION_CONTRACT_VERSION,
        targetUrl: command.targetUrl,
        reasonCode: 'invalid_protocol',
        reason: 'Active verification target URL must use HTTP or HTTPS',
        explicitNonClaims: ACTIVE_VERIFICATION_NON_CLAIMS,
        lineage: { ...command.lineage },
        durationMs: Date.now() - startTime,
      };
    }

    const host = parsedUrl.hostname.toLowerCase();

    // -------------------------------------------------------------------------
    // 2. Double SSRF Gate — Pass 1: Static SSRF Check
    // -------------------------------------------------------------------------
    if (isInternalOrSsrfTarget(host)) {
      return {
        status: 'preflight_denied',
        contractVersion: ACTIVE_VERIFICATION_CONTRACT_VERSION,
        targetUrl: command.targetUrl,
        reasonCode: 'ssrf_target_blocked',
        reason: 'Target URL points to blocked internal, loopback, or metadata host',
        explicitNonClaims: ACTIVE_VERIFICATION_NON_CLAIMS,
        lineage: { ...command.lineage },
        durationMs: Date.now() - startTime,
      };
    }

    // -------------------------------------------------------------------------
    // 2. Double SSRF Gate — Pass 2: Dynamic Pre-Spawn DNS Rebinding Check
    // -------------------------------------------------------------------------
    const dnsCheck = await validateDnsRebinding(host, command.dnsResolver);
    if (!dnsCheck.ok) {
      return {
        status: 'preflight_denied',
        contractVersion: ACTIVE_VERIFICATION_CONTRACT_VERSION,
        targetUrl: command.targetUrl,
        reasonCode: 'ssrf_target_blocked',
        reason: `Target host resolves to blocked internal or private IP: ${dnsCheck.blockedIp}`,
        explicitNonClaims: ACTIVE_VERIFICATION_NON_CLAIMS,
        lineage: { ...command.lineage },
        durationMs: Date.now() - startTime,
      };
    }

    // -------------------------------------------------------------------------
    // 3. Human Authorization Gate (ADR-001 WeakSet Runtime Brand Verification)
    // -------------------------------------------------------------------------
    const dec = command.verifiedAuthorizationDecision;
    if (!dec || !isRuntimeEstablishedExploitationDecision(dec)) {
      return {
        status: 'preflight_denied',
        contractVersion: ACTIVE_VERIFICATION_CONTRACT_VERSION,
        targetUrl: command.targetUrl,
        reasonCode: 'authorization_unconfirmed',
        reason: 'Exploitation decision lacks runtime verification brand (ADR-001 violation)',
        explicitNonClaims: ACTIVE_VERIFICATION_NON_CLAIMS,
        lineage: { ...command.lineage },
        durationMs: Date.now() - startTime,
      };
    }

    if (dec.decision !== 'authorized') {
      return {
        status: 'preflight_denied',
        contractVersion: ACTIVE_VERIFICATION_CONTRACT_VERSION,
        targetUrl: command.targetUrl,
        reasonCode: 'authorization_denied',
        reason: 'Exploitation decision is not in authorized state',
        explicitNonClaims: ACTIVE_VERIFICATION_NON_CLAIMS,
        lineage: { ...command.lineage },
        durationMs: Date.now() - startTime,
      };
    }

    if (dec.allowedVector !== command.vector) {
      return {
        status: 'preflight_denied',
        contractVersion: ACTIVE_VERIFICATION_CONTRACT_VERSION,
        targetUrl: command.targetUrl,
        reasonCode: 'vector_mismatch',
        reason: `Authorized exploitation vector '${dec.allowedVector}' does not match command vector '${command.vector}'`,
        explicitNonClaims: ACTIVE_VERIFICATION_NON_CLAIMS,
        lineage: { ...command.lineage },
        durationMs: Date.now() - startTime,
      };
    }

    if (dec.candidateId !== command.candidateId) {
      return {
        status: 'preflight_denied',
        contractVersion: ACTIVE_VERIFICATION_CONTRACT_VERSION,
        targetUrl: command.targetUrl,
        reasonCode: 'candidate_mismatch',
        reason: `Authorized candidate ID '${dec.candidateId}' does not match command candidate ID '${command.candidateId}'`,
        explicitNonClaims: ACTIVE_VERIFICATION_NON_CLAIMS,
        lineage: { ...command.lineage },
        durationMs: Date.now() - startTime,
      };
    }

    // -------------------------------------------------------------------------
    // 4. Continuous Lineage & Scope Permissions Verification
    // -------------------------------------------------------------------------
    const lin = command.lineage;
    const grant = command.authorizedScopeGrant;
    if (
      !grant ||
      !lin ||
      lin.scanId !== dec.scanId ||
      lin.assessmentId !== dec.assessmentId ||
      lin.authorizationGrantId !== grant.grantId ||
      lin.authorizationDecisionId !== dec.authorizationDecisionId
    ) {
      return {
        status: 'preflight_denied',
        contractVersion: ACTIVE_VERIFICATION_CONTRACT_VERSION,
        targetUrl: command.targetUrl,
        reasonCode: 'lineage_mismatch',
        reason: 'Lineage tuple mismatch across execution command, grant, and authorization decision',
        explicitNonClaims: ACTIVE_VERIFICATION_NON_CLAIMS,
        lineage: { ...command.lineage },
        durationMs: Date.now() - startTime,
      };
    }

    if (!grant.permissionSet.activeValidation && !grant.permissionSet.lightValidation) {
      return {
        status: 'preflight_denied',
        contractVersion: ACTIVE_VERIFICATION_CONTRACT_VERSION,
        targetUrl: command.targetUrl,
        reasonCode: 'missing_permission',
        reason: 'Scope grant does not permit active validation capability',
        explicitNonClaims: ACTIVE_VERIFICATION_NON_CLAIMS,
        lineage: { ...command.lineage },
        durationMs: Date.now() - startTime,
      };
    }

    // -------------------------------------------------------------------------
    // 5. Blast Radius & Target Circuit Breaker Gate (Milestone F8)
    // -------------------------------------------------------------------------
    if (command.coordinator?.isCircuitOpen(host)) {
      return {
        status: 'circuit_broken',
        contractVersion: ACTIVE_VERIFICATION_CONTRACT_VERSION,
        targetHost: host,
        reasonCode: CIRCUIT_OPEN_REASON_CODE,
        reason: `Target circuit breaker tripped to OPEN on '${host}' to protect target availability. Verification paused.`,
        explicitNonClaims: ACTIVE_VERIFICATION_NON_CLAIMS,
        lineage: { ...command.lineage },
        durationMs: Date.now() - startTime,
      };
    }

    // -------------------------------------------------------------------------
    // 6. Safe PoC Payload Preparation (Inert Canaries / Non-Destructive Vectors)
    // -------------------------------------------------------------------------
    let effectiveUrl = command.targetUrl;
    const effectiveHeaders: Record<string, string> = {
      'User-Agent': 'FixGuard-Active-Verification/1.0',
      Accept: '*/*',
      ...(command.headers ?? {}),
    };
    let effectiveMethod = command.httpMethod ?? 'GET';
    let effectiveBody = command.bodyText;
    let canaryToken: string | undefined;

    switch (command.vector) {
      case 'parameter_reflection_canary': {
        canaryToken =
          command.canaryToken && /^[a-zA-Z0-9_-]{6,64}$/.test(command.canaryToken)
            ? command.canaryToken
            : `fgcanary${crypto.randomUUID().replace(/[^a-zA-Z0-9]/g, '').slice(0, 12)}`;

        const urlObj = new URL(effectiveUrl);
        urlObj.searchParams.set('q', canaryToken);
        urlObj.searchParams.set('test', canaryToken);
        effectiveUrl = urlObj.toString();
        effectiveMethod = 'GET';
        break;
      }

      case 'cors_arbitrary_origin_reflection': {
        effectiveHeaders['Origin'] = 'https://evil-fixguard-test.com';
        effectiveMethod = 'OPTIONS';
        break;
      }

      case 'idor_read_differential': {
        effectiveMethod = 'GET';
        break;
      }

      case 'security_header_enforcement': {
        effectiveMethod = 'GET';
        break;
      }
    }

    const requestFingerprint = `${effectiveMethod} ${effectiveUrl} ${JSON.stringify(effectiveHeaders)} ${effectiveBody ?? ''}`;
    const requestHash = computeSha256(requestFingerprint);

    // -------------------------------------------------------------------------
    // 7. Network Execution via Target Execution Coordinator
    // -------------------------------------------------------------------------
    let probeResponse: VerificationHttpResponse;
    try {
      const executeNetworkCall = async (): Promise<VerificationHttpResponse> => {
        return this.transport({
          url: effectiveUrl,
          method: effectiveMethod,
          headers: effectiveHeaders,
          bodyText: effectiveBody,
          timeoutMs: command.timeoutMs,
        });
      };

      if (command.coordinator) {
        probeResponse = await command.coordinator.execute(host, executeNetworkCall);
      } else {
        probeResponse = await executeNetworkCall();
      }

      // Record target response status for circuit breaker feedback
      command.coordinator?.recordTargetResponse(host, probeResponse.statusCode);
    } catch (err) {
      if (err instanceof TargetInstabilityError || command.coordinator?.isCircuitOpen(host)) {
        return {
          status: 'circuit_broken',
          contractVersion: ACTIVE_VERIFICATION_CONTRACT_VERSION,
          targetHost: host,
          reasonCode: CIRCUIT_OPEN_REASON_CODE,
          reason: `Target circuit breaker tripped on '${host}'. Verification aborted safely.`,
          explicitNonClaims: ACTIVE_VERIFICATION_NON_CLAIMS,
          lineage: { ...command.lineage },
          durationMs: Date.now() - startTime,
        };
      }

      command.coordinator?.recordTargetResponse(host, 'error');
      return {
        status: 'verification_failed',
        contractVersion: ACTIVE_VERIFICATION_CONTRACT_VERSION,
        targetUrl: command.targetUrl,
        reasonCode: 'network_execution_error',
        reason: `Failed to execute active verification probe: ${err instanceof Error ? err.message : String(err)}`,
        explicitNonClaims: ACTIVE_VERIFICATION_NON_CLAIMS,
        lineage: { ...command.lineage },
        durationMs: Date.now() - startTime,
      };
    }

    const responseHash = computeSha256(probeResponse.bodyText);
    const sanitizedExcerpt = sanitizeExcerpt(probeResponse.bodyText);

    // -------------------------------------------------------------------------
    // 8. Deterministic Proof Evaluation & Candidate Certification
    // -------------------------------------------------------------------------
    const proof: ActiveVerificationProofRecord = {
      candidateId: command.candidateId,
      vector: command.vector,
      targetUrl: effectiveUrl,
      requestHash,
      responseHash,
      statusCode: probeResponse.statusCode,
      canaryReflected: canaryToken ? probeResponse.bodyText.includes(canaryToken) : undefined,
      sanitizedExcerpt,
      responseTimeMs: probeResponse.responseTimeMs,
      verifiedAt: new Date().toISOString(),
    };

    switch (command.vector) {
      case 'parameter_reflection_canary': {
        if (canaryToken && probeResponse.bodyText.includes(canaryToken)) {
          const candidateRecord: ConfirmedFindingCandidateRecord = {
            candidateId: command.candidateId,
            type: 'REFLECTED_PARAMETER_INJECTION',
            severity: 'medium',
            exploitConfidence: 1.0,
            proofSummary: `Inert canary '${canaryToken}' reflected unencoded in HTTP response body (status ${probeResponse.statusCode})`,
          };

          return {
            status: 'exploit_confirmed',
            contractVersion: ACTIVE_VERIFICATION_CONTRACT_VERSION,
            command,
            proof,
            confirmedFindingCandidate: candidateRecord,
            explicitNonClaims: ACTIVE_VERIFICATION_NON_CLAIMS,
            lineage: { ...command.lineage },
            durationMs: Date.now() - startTime,
          };
        }

        return {
          status: 'exploit_refuted',
          contractVersion: ACTIVE_VERIFICATION_CONTRACT_VERSION,
          command,
          reasonCode: 'canary_not_reflected',
          reason: 'Inert canary token was properly sanitized, encoded, or stripped by the target application',
          responseStatus: probeResponse.statusCode,
          responseHash,
          explicitNonClaims: ACTIVE_VERIFICATION_NON_CLAIMS,
          lineage: { ...command.lineage },
          durationMs: Date.now() - startTime,
        };
      }

      case 'cors_arbitrary_origin_reflection': {
        const acao = probeResponse.headers['access-control-allow-origin'];
        const acac = probeResponse.headers['access-control-allow-credentials'];

        if (acao === 'https://evil-fixguard-test.com' || (acao === '*' && acac === 'true')) {
          const candidateRecord: ConfirmedFindingCandidateRecord = {
            candidateId: command.candidateId,
            type: 'CORS_MISCONFIGURATION',
            severity: 'high',
            exploitConfidence: 1.0,
            proofSummary: `Arbitrary Origin header reflected in Access-Control-Allow-Origin: ${acao}`,
          };

          return {
            status: 'exploit_confirmed',
            contractVersion: ACTIVE_VERIFICATION_CONTRACT_VERSION,
            command,
            proof,
            confirmedFindingCandidate: candidateRecord,
            explicitNonClaims: ACTIVE_VERIFICATION_NON_CLAIMS,
            lineage: { ...command.lineage },
            durationMs: Date.now() - startTime,
          };
        }

        return {
          status: 'exploit_refuted',
          contractVersion: ACTIVE_VERIFICATION_CONTRACT_VERSION,
          command,
          reasonCode: 'target_enforced_control',
          reason: `Target properly enforces CORS origin controls (ACAO: ${acao ?? 'absent'})`,
          responseStatus: probeResponse.statusCode,
          responseHash,
          explicitNonClaims: ACTIVE_VERIFICATION_NON_CLAIMS,
          lineage: { ...command.lineage },
          durationMs: Date.now() - startTime,
        };
      }

      case 'idor_read_differential': {
        if (probeResponse.statusCode === 200 && probeResponse.bodyText.length > 0) {
          const candidateRecord: ConfirmedFindingCandidateRecord = {
            candidateId: command.candidateId,
            type: 'BROKEN_OBJECT_LEVEL_AUTHORIZATION',
            severity: 'high',
            exploitConfidence: 1.0,
            proofSummary: `Object resource read accessed without authorization rejection (HTTP 200, length ${probeResponse.bodyText.length})`,
          };

          return {
            status: 'exploit_confirmed',
            contractVersion: ACTIVE_VERIFICATION_CONTRACT_VERSION,
            command,
            proof,
            confirmedFindingCandidate: candidateRecord,
            explicitNonClaims: ACTIVE_VERIFICATION_NON_CLAIMS,
            lineage: { ...command.lineage },
            durationMs: Date.now() - startTime,
          };
        }

        return {
          status: 'exploit_refuted',
          contractVersion: ACTIVE_VERIFICATION_CONTRACT_VERSION,
          command,
          reasonCode: 'access_denied',
          reason: `Target correctly denied unauthorized object access with HTTP status ${probeResponse.statusCode}`,
          responseStatus: probeResponse.statusCode,
          responseHash,
          explicitNonClaims: ACTIVE_VERIFICATION_NON_CLAIMS,
          lineage: { ...command.lineage },
          durationMs: Date.now() - startTime,
        };
      }

      case 'security_header_enforcement': {
        const csp = probeResponse.headers['content-security-policy'];
        const hsts = probeResponse.headers['strict-transport-security'];

        if (!csp && !hsts) {
          const candidateRecord: ConfirmedFindingCandidateRecord = {
            candidateId: command.candidateId,
            type: 'MISSING_CRITICAL_SECURITY_HEADERS',
            severity: 'medium',
            exploitConfidence: 1.0,
            proofSummary: 'Missing Content-Security-Policy and Strict-Transport-Security enforcement headers',
          };

          return {
            status: 'exploit_confirmed',
            contractVersion: ACTIVE_VERIFICATION_CONTRACT_VERSION,
            command,
            proof,
            confirmedFindingCandidate: candidateRecord,
            explicitNonClaims: ACTIVE_VERIFICATION_NON_CLAIMS,
            lineage: { ...command.lineage },
            durationMs: Date.now() - startTime,
          };
        }

        return {
          status: 'exploit_refuted',
          contractVersion: ACTIVE_VERIFICATION_CONTRACT_VERSION,
          command,
          reasonCode: 'target_enforced_control',
          reason: 'Critical security headers are present and enforced',
          responseStatus: probeResponse.statusCode,
          responseHash,
          explicitNonClaims: ACTIVE_VERIFICATION_NON_CLAIMS,
          lineage: { ...command.lineage },
          durationMs: Date.now() - startTime,
        };
      }
    }
  }
}
