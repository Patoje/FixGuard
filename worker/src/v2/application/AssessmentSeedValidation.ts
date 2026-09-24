/**
 * Phase D1 — Assessment seed URL/path validation against sealed scope + egress.
 *
 * Fail-closed, side-effect free: no network, no persistence.
 * Out-of-scope / egress-denied seeds abort atomically with reasonCode seed_out_of_scope.
 */

import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import {
  evaluateScopePolicy,
  isPathAllowedByScopeBoundaries,
} from '../scope/AuthorizedScopePolicyService.js';
import { deriveM30EgressScope } from '../authorization/VerifiedAuthorizationDecisionService.js';
import { evaluateEgressPolicy } from '../recon/policy/PassiveEgressPolicy.js';
import type { AssessmentSeed } from './OrchestratedAssessmentContracts.js';

export type AssessmentSeedValidationResult =
  | {
      readonly status: 'validated';
      readonly absoluteSeedUrls: readonly string[];
    }
  | {
      readonly status: 'denied';
      readonly reasonCode: 'seed_out_of_scope' | 'seed_malformed';
      readonly reason: string;
      readonly offendingSeed?: string;
    };

/**
 * Combine a relative seed path with the authorized target domain into an absolute HTTPS URL.
 * Rejects absolute URLs, traversal, and empty/malformed paths.
 */
export function resolveSeedPathToAbsoluteUrl(
  targetDomain: string,
  seedPath: string
): { ok: true; url: string } | { ok: false; reason: string } {
  if (typeof seedPath !== 'string' || seedPath.trim().length === 0) {
    return { ok: false, reason: 'seedPath must be a non-empty string' };
  }
  const raw = seedPath.trim();
  if (raw.includes('://') || raw.startsWith('//')) {
    return { ok: false, reason: 'seedPath must be a path, not an absolute URL' };
  }
  if (raw.includes('..') || raw.includes('\\')) {
    return { ok: false, reason: 'seedPath must not contain path traversal or backslashes' };
  }
  const domain = targetDomain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  if (!domain || !/^[a-z0-9.-]+$/i.test(domain) || domain.includes('..')) {
    return { ok: false, reason: 'targetDomain is invalid for seed path resolution' };
  }
  const normalizedPath = raw.startsWith('/') ? raw : `/${raw}`;
  return { ok: true, url: `https://${domain}${normalizedPath}` };
}

function isHostInScope(grant: AuthorizedScopeGrant, targetHost: string): boolean {
  const host = targetHost.trim().toLowerCase().replace(/\.$/, '');
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
    try {
      const u = new URL(origin);
      originHosts.push(u.hostname.trim().toLowerCase().replace(/\.$/, ''));
    } catch {
      // ignore malformed origin strings
    }
  }

  return (
    allowedDomains.includes(host) ||
    allowedDomains.some((d) => host.endsWith('.' + d)) ||
    allowedHosts.includes(host) ||
    subjectDomain === host ||
    subjectHost === host ||
    originHosts.includes(host) ||
    originHosts.some((h) => host.endsWith('.' + h))
  );
}

/**
 * Validate all AssessmentSeed URLs/paths against a sealed AuthorizedScopeGrant and egress policy.
 * Atomic: any single denial fails the entire batch with zero network side effects.
 */
export function validateAssessmentSeeds(
  seed: AssessmentSeed,
  scopeGrant: AuthorizedScopeGrant,
  evaluatedAt: string
): AssessmentSeedValidationResult {
  const targetDomain = seed.targetDomain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  const candidates: string[] = [];

  if (seed.seedUrls) {
    for (const raw of seed.seedUrls) {
      if (typeof raw !== 'string' || raw.trim().length === 0) {
        return {
          status: 'denied',
          reasonCode: 'seed_malformed',
          reason: 'seedUrls entries must be non-empty strings',
          offendingSeed: String(raw),
        };
      }
      candidates.push(raw.trim());
    }
  }

  if (seed.seedPaths) {
    for (const rawPath of seed.seedPaths) {
      const resolved = resolveSeedPathToAbsoluteUrl(targetDomain, rawPath);
      if (!resolved.ok) {
        return {
          status: 'denied',
          reasonCode: 'seed_malformed',
          reason: resolved.reason,
          offendingSeed: rawPath,
        };
      }
      candidates.push(resolved.url);
    }
  }

  if (candidates.length === 0) {
    return { status: 'validated', absoluteSeedUrls: Object.freeze([]) };
  }

  const egressScope = deriveM30EgressScope(scopeGrant);
  const validated: string[] = [];
  const seen = new Set<string>();

  for (let i = 0; i < candidates.length; i++) {
    const candidate = candidates[i]!;
    let parsed: URL;
    try {
      parsed = new URL(candidate);
    } catch {
      return {
        status: 'denied',
        reasonCode: 'seed_malformed',
        reason: 'seed URL is malformed',
        offendingSeed: candidate,
      };
    }

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return {
        status: 'denied',
        reasonCode: 'seed_out_of_scope',
        reason: 'seed URL protocol must be http or https',
        offendingSeed: candidate,
      };
    }

    const hostname = parsed.hostname.trim().toLowerCase().replace(/\.$/, '');
    if (!hostname || !isHostInScope(scopeGrant, hostname)) {
      return {
        status: 'denied',
        reasonCode: 'seed_out_of_scope',
        reason: `seed host '${hostname}' is outside authorized scope boundaries`,
        offendingSeed: candidate,
      };
    }

    const pathname = parsed.pathname || '/';
    if (!isPathAllowedByScopeBoundaries(pathname, scopeGrant)) {
      return {
        status: 'denied',
        reasonCode: 'seed_out_of_scope',
        reason: `seed path '${pathname}' is outside allowed path patterns or explicitly denied`,
        offendingSeed: candidate,
      };
    }

    const origin = `${parsed.protocol}//${parsed.host}`;
    const scopeDecision = evaluateScopePolicy({
      grant: scopeGrant,
      request: {
        contractVersion: 'fixguard-authorized-scope-policy/v0',
        kind: 'scope_action_request',
        requestId: `seed_val_${i}_${scopeGrant.grantId}`.slice(0, 128),
        scanId: scopeGrant.scanId,
        requestedAt: evaluatedAt,
        actionKind: 'endpoint_discovery',
        target: {
          targetKind: 'origin',
          normalizedOrigin: origin,
          host: hostname,
          domain: hostname,
        },
        method: 'GET',
        pathTemplate: pathname,
        intensity: 'passive',
        usesCredentials: false,
        mayChangeServerState: false,
        usesOob: false,
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
      },
      decisionId: `seed_dec_${scopeGrant.grantId}`.slice(0, 128),
      evaluatedAt,
    });

    if (scopeDecision.decision !== 'allowed') {
      return {
        status: 'denied',
        reasonCode: 'seed_out_of_scope',
        reason: `seed denied by scope policy (${scopeDecision.reasonCode}): ${candidate}`,
        offendingSeed: candidate,
      };
    }

    const egressDecision = evaluateEgressPolicy({
      targetUrl: candidate,
      authorizedScope: egressScope,
      capabilityId: 'assessment.seed.validate',
    });

    if (egressDecision.decision !== 'allow') {
      return {
        status: 'denied',
        reasonCode: 'seed_out_of_scope',
        reason: `seed denied by egress policy (${egressDecision.decision === 'block' ? egressDecision.blockReason : 'candidate'}): ${candidate}`,
        offendingSeed: candidate,
      };
    }

    const absolute = `${parsed.protocol}//${parsed.host}${pathname}${parsed.search}`;
    if (!seen.has(absolute)) {
      seen.add(absolute);
      validated.push(absolute);
    }
  }

  return { status: 'validated', absoluteSeedUrls: Object.freeze(validated) };
}
