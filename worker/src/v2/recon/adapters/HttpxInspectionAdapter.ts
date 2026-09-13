import type { ProcessRunner } from '../../core/ProcessRunner.js';
import { isRuntimeEstablishedVerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionService.js';
import { isInternalOrSsrfTarget } from '../policy/PassiveEgressPolicy.js';
import {
  WEB_INSPECTION_CONTRACT_VERSION,
  WEB_INSPECTION_NON_CLAIMS,
  type DiscoveredWebObservation,
  type WebInspectionRequest,
  type WebInspectionResult,
  type WebInspectionTool,
} from './WebInspectionContracts.js';

function extractHost(urlStr: string): string | null {
  try {
    const u = new URL(urlStr);
    return u.hostname.trim().toLowerCase().replace(/\.$/, '');
  } catch {
    return null;
  }
}

export class HttpxInspectionAdapter implements WebInspectionTool {
  constructor(private readonly processRunner: ProcessRunner) {}

  async inspectWeb(request: WebInspectionRequest): Promise<WebInspectionResult> {
    const rawTarget = typeof request.targetUrl === 'string' ? request.targetUrl.trim() : '';

    // 1. Atomic Preflight: Target URL format and protocol validation
    let targetParsedUrl: URL;
    try {
      targetParsedUrl = new URL(rawTarget);
    } catch {
      return {
        status: 'preflight_denied',
        contractVersion: WEB_INSPECTION_CONTRACT_VERSION,
        targetUrl: rawTarget,
        reasonCode: 'invalid_target_url',
        reason: 'Target URL is not a valid URL',
        explicitNonClaims: WEB_INSPECTION_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    if (targetParsedUrl.protocol !== 'http:' && targetParsedUrl.protocol !== 'https:') {
      return {
        status: 'preflight_denied',
        contractVersion: WEB_INSPECTION_CONTRACT_VERSION,
        targetUrl: rawTarget,
        reasonCode: 'unsupported_url_protocol',
        reason: 'Target URL protocol must be http: or https:',
        explicitNonClaims: WEB_INSPECTION_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    const targetHost = targetParsedUrl.hostname.toLowerCase().replace(/\.$/, '');
    if (!targetHost) {
      return {
        status: 'preflight_denied',
        contractVersion: WEB_INSPECTION_CONTRACT_VERSION,
        targetUrl: rawTarget,
        reasonCode: 'invalid_target_host',
        reason: 'Target URL does not contain a valid host',
        explicitNonClaims: WEB_INSPECTION_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    // 2. Atomic Preflight: Runtime-branded authorization verification
    if (
      !request.verifiedAuthorizationDecision ||
      !isRuntimeEstablishedVerifiedAuthorizationDecision(request.verifiedAuthorizationDecision)
    ) {
      return {
        status: 'preflight_denied',
        contractVersion: WEB_INSPECTION_CONTRACT_VERSION,
        targetUrl: rawTarget,
        reasonCode: 'authorization_unconfirmed',
        reason: 'Authorization decision is not runtime-established or lacks valid verification brand',
        explicitNonClaims: WEB_INSPECTION_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    if (request.verifiedAuthorizationDecision.decision !== 'authorized') {
      return {
        status: 'preflight_denied',
        contractVersion: WEB_INSPECTION_CONTRACT_VERSION,
        targetUrl: rawTarget,
        reasonCode: 'authorization_denied',
        reason: 'Authorization decision is not in authorized state',
        explicitNonClaims: WEB_INSPECTION_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    // 3. Atomic Preflight: Continuous Lineage tuple integrity verification
    const dec = request.verifiedAuthorizationDecision;
    const grant = request.authorizedScopeGrant;
    const lin = request.lineage;

    if (
      lin.scanId !== dec.scanId ||
      lin.assessmentId !== dec.assessmentId ||
      lin.authorizationGrantId !== grant.grantId ||
      lin.authorizationDecisionId !== dec.authorizationDecisionId
    ) {
      return {
        status: 'preflight_denied',
        contractVersion: WEB_INSPECTION_CONTRACT_VERSION,
        targetUrl: rawTarget,
        reasonCode: 'lineage_mismatch',
        reason: 'Execution lineage does not match authorization decision and scope grant',
        explicitNonClaims: WEB_INSPECTION_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    // 4. Atomic Preflight: Scope permissions check (endpointDiscovery, activeValidation, technologyFingerprinting, activeRecon)
    const ps = grant.permissionSet;
    let hasPermission = Boolean(
      ps.technologyFingerprinting ||
      ps.endpointDiscovery ||
      ps.activeValidation ||
      ps.lightValidation
    );
    if (!hasPermission && 'activeRecon' in ps) {
      const ext = ps as typeof ps & { activeRecon?: boolean };
      if (ext.activeRecon) {
        hasPermission = true;
      }
    }

    if (!hasPermission) {
      return {
        status: 'preflight_denied',
        contractVersion: WEB_INSPECTION_CONTRACT_VERSION,
        targetUrl: rawTarget,
        reasonCode: 'missing_permission',
        reason: 'Scope grant does not permit technology fingerprinting or active reconnaissance',
        explicitNonClaims: WEB_INSPECTION_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    // 5. Atomic Preflight: Scope boundary check
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

    const isHostInScope =
      allowedDomains.includes(targetHost) ||
      allowedDomains.some((d) => targetHost.endsWith('.' + d)) ||
      allowedHosts.includes(targetHost) ||
      subjectDomain === targetHost ||
      subjectHost === targetHost ||
      originHosts.includes(targetHost) ||
      originHosts.some((h) => targetHost.endsWith('.' + h));

    if (!isHostInScope) {
      return {
        status: 'preflight_denied',
        contractVersion: WEB_INSPECTION_CONTRACT_VERSION,
        targetUrl: rawTarget,
        reasonCode: 'target_out_of_scope',
        reason: 'Target URL host is outside authorized scope boundaries',
        explicitNonClaims: WEB_INSPECTION_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    // 6. Atomic Preflight: SSRF containment on target hostname
    if (isInternalOrSsrfTarget(targetHost)) {
      return {
        status: 'preflight_denied',
        contractVersion: WEB_INSPECTION_CONTRACT_VERSION,
        targetUrl: rawTarget,
        reasonCode: 'ssrf_target_blocked',
        reason: 'Target URL host points to prohibited internal, loopback, or metadata address',
        explicitNonClaims: WEB_INSPECTION_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    // 7. Command Execution: Strictly via ProcessRunner with shell: false and isolated argument array
    const args = [
      '-u', rawTarget,
      '-json',
      '-silent',
      '-title',
      '-tech-detect',
      '-status-code',
      '-follow-redirects'
    ];

    const timeoutMs = request.timeoutMs ?? 60_000;
    const execOutput = await this.processRunner.execute({
      binary: 'httpx',
      args,
      timeoutMs,
    });

    if (execOutput.timedOut) {
      return {
        status: 'execution_failed',
        contractVersion: WEB_INSPECTION_CONTRACT_VERSION,
        targetUrl: rawTarget,
        reasonCode: 'process_timeout',
        reason: `Httpx execution timed out after ${timeoutMs}ms`,
        explicitNonClaims: WEB_INSPECTION_NON_CLAIMS,
        lineage: request.lineage,
        exitCode: execOutput.exitCode,
        stderr: execOutput.stderr,
        durationMs: execOutput.durationMs,
      };
    }

    if (execOutput.exitCode !== 0) {
      return {
        status: 'execution_failed',
        contractVersion: WEB_INSPECTION_CONTRACT_VERSION,
        targetUrl: rawTarget,
        reasonCode: 'non_zero_exit_code',
        reason: `Httpx process failed with exit code ${execOutput.exitCode}`,
        explicitNonClaims: WEB_INSPECTION_NON_CLAIMS,
        lineage: request.lineage,
        exitCode: execOutput.exitCode,
        stderr: execOutput.stderr,
        durationMs: execOutput.durationMs,
      };
    }

    // 8. Output Parsing & Deep SSRF Egress Filtering
    const lines = execOutput.stdout.split('\n');
    const observationsMap = new Map<string, DiscoveredWebObservation>();
    const nowIso = new Date().toISOString();

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      let rawObj: unknown;
      try {
        rawObj = JSON.parse(trimmed);
      } catch {
        // Fail closed on corrupted / non-JSON lines without crashing
        continue;
      }

      if (!rawObj || typeof rawObj !== 'object' || Array.isArray(rawObj)) {
        continue;
      }

      const rec = rawObj as Record<string, unknown>;
      const observedUrl = typeof rec.url === 'string' ? rec.url.trim() : '';
      if (!observedUrl) continue;

      let finalParsedUrl: URL;
      try {
        finalParsedUrl = new URL(observedUrl);
      } catch {
        continue;
      }

      const finalHost = finalParsedUrl.hostname.toLowerCase().replace(/\.$/, '');

      // Deep SSRF Egress Gate: Check if final URL redirected to internal/loopback/metadata host
      if (isInternalOrSsrfTarget(finalHost)) {
        continue;
      }

      // Check resolved IPs (ip or host or chain)
      const ipsToCheck: string[] = [];
      if (typeof rec.ip === 'string' && rec.ip.trim()) {
        ipsToCheck.push(rec.ip.trim());
      }
      if (typeof rec.host === 'string' && rec.host.trim() && rec.host !== finalHost) {
        ipsToCheck.push(rec.host.trim());
      }
      if (Array.isArray(rec.a)) {
        for (const item of rec.a) {
          if (typeof item === 'string' && item.trim()) {
            ipsToCheck.push(item.trim());
          }
        }
      }
      if (Array.isArray(rec.chain)) {
        for (const hop of rec.chain) {
          if (hop && typeof hop === 'object' && !Array.isArray(hop)) {
            const h = hop as Record<string, unknown>;
            if (typeof h.ip === 'string' && h.ip.trim()) {
              ipsToCheck.push(h.ip.trim());
            }
            if (typeof h.host === 'string' && h.host.trim()) {
              ipsToCheck.push(h.host.trim());
            }
          }
        }
      }

      // Drop observation if any resolved IP in redirection chain hits loopback, RFC-1918, or metadata
      const hasBlockedIp = ipsToCheck.some((ip) => isInternalOrSsrfTarget(ip));
      if (hasBlockedIp) {
        continue;
      }

      const statusCode = typeof rec.status_code === 'number'
        ? rec.status_code
        : (typeof rec.statusCode === 'number' ? rec.statusCode : parseInt(String(rec.status_code), 10) || 0);

      const method = typeof rec.method === 'string' && rec.method ? rec.method.toUpperCase() : 'GET';
      const title = typeof rec.title === 'string' && rec.title.trim() ? rec.title.trim() : undefined;
      const webServer = typeof rec.webserver === 'string' && rec.webserver.trim() ? rec.webserver.trim() : undefined;

      const rawTech = Array.isArray(rec.tech)
        ? rec.tech
        : (Array.isArray(rec.technologies) ? rec.technologies : []);
      const technologies: string[] = rawTech
        .filter((t): t is string => typeof t === 'string' && t.trim().length > 0)
        .map((t) => t.trim())
        .sort();

      const resolvedIp = typeof rec.ip === 'string' && rec.ip.trim() ? rec.ip.trim() : undefined;

      if (!observationsMap.has(observedUrl)) {
        observationsMap.set(observedUrl, {
          url: observedUrl,
          method,
          statusCode,
          title,
          webServer,
          technologies,
          resolvedIp,
          discoveredAt: nowIso,
        });
      }
    }

    const observations: DiscoveredWebObservation[] = Array.from(observationsMap.values()).sort(
      (a, b) => a.url.localeCompare(b.url)
    );

    return {
      status: 'success',
      contractVersion: WEB_INSPECTION_CONTRACT_VERSION,
      targetUrl: rawTarget,
      observations,
      explicitNonClaims: WEB_INSPECTION_NON_CLAIMS,
      lineage: request.lineage,
      durationMs: execOutput.durationMs,
    };
  }
}
