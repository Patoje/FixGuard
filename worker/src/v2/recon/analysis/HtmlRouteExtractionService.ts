/**
 * Phase D1 Step 3 — Passive HTML link & route extraction (hermetic).
 *
 * Parses already-captured response bodies (≤64KB) for in-scope internal routes
 * from <a href>, <form action>, and <script src>. Zero network I/O.
 *
 * Fail-closed: media assets and out-of-scope / egress-denied URLs are dropped
 * before registration. Next.js bundle paths (/_next/static/...) are retained
 * as discovered URLs but classified separately from app endpoints.
 */

import { isScopeAllowed } from '../../attack-execution/AttackExecutionContracts.js';
import { deriveM30EgressScope } from '../../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../../scope/AuthorizedScopeContracts.js';
import { evaluateEgressPolicy } from '../policy/PassiveEgressPolicy.js';
import { WEB_OBSERVATION_BODY_CHUNK_MAX_BYTES } from '../adapters/WebInspectionContracts.js';

export const HTML_LINK_EXTRACTION_SOURCE = 'html_link_extraction' as const;

/** Hard cap applied by callers per recon stage (orchestrator). */
export const HTML_ROUTE_EXTRACTION_MAX_PER_STAGE = 25;

/** Static media extensions rejected from endpoint inventory (case-insensitive). */
const REJECTED_MEDIA_EXTENSIONS = Object.freeze([
  '.png',
  '.jpg',
  '.svg',
  '.woff2',
  '.css',
] as const);

export type HtmlExtractedRouteKind = 'app_endpoint' | 'static_bundle';

export type HtmlExtractedAttribute = 'href' | 'action' | 'src';

export interface HtmlExtractedRouteCandidate {
  readonly url: string;
  readonly host: string;
  readonly path: string;
  readonly query?: string;
  readonly kind: HtmlExtractedRouteKind;
  readonly attribute: HtmlExtractedAttribute;
  readonly rawHref: string;
}

export interface HtmlRouteExtractionInput {
  readonly bodyText: string;
  readonly baseUrl: string;
  readonly targetDomain: string;
  readonly authorizedScopeGrant: AuthorizedScopeGrant;
  /** Optional soft cap on accepted candidates from a single body (document order). */
  readonly maxResults?: number;
}

export interface HtmlRouteExtractionResult {
  readonly accepted: readonly HtmlExtractedRouteCandidate[];
  readonly rejectedMediaCount: number;
  readonly rejectedOutOfScopeCount: number;
  readonly rejectedMalformedCount: number;
}

interface RawAttrMatch {
  readonly index: number;
  readonly attribute: HtmlExtractedAttribute;
  readonly value: string;
}

function truncateBody(bodyText: string): string {
  if (bodyText.length <= WEB_OBSERVATION_BODY_CHUNK_MAX_BYTES) {
    return bodyText;
  }
  return bodyText.slice(0, WEB_OBSERVATION_BODY_CHUNK_MAX_BYTES);
}

function collectAttributeMatches(body: string): RawAttrMatch[] {
  const matches: RawAttrMatch[] = [];

  const patterns: ReadonlyArray<{
    readonly attribute: HtmlExtractedAttribute;
    readonly regex: RegExp;
  }> = [
    {
      attribute: 'href',
      regex: /<a\b[^>]*?\bhref\s*=\s*(?:"([^"]*)"|'([^']*)')/gi,
    },
    {
      attribute: 'action',
      regex: /<form\b[^>]*?\baction\s*=\s*(?:"([^"]*)"|'([^']*)')/gi,
    },
    {
      attribute: 'src',
      regex: /<script\b[^>]*?\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)')/gi,
    },
  ];

  for (const { attribute, regex } of patterns) {
    for (const m of body.matchAll(regex)) {
      const value = (m[1] ?? m[2] ?? '').trim();
      if (value.length === 0) continue;
      matches.push({
        index: m.index ?? 0,
        attribute,
        value,
      });
    }
  }

  matches.sort((a, b) => a.index - b.index || a.attribute.localeCompare(b.attribute));
  return matches;
}

function isRejectedMediaPath(pathname: string): boolean {
  const lower = pathname.toLowerCase();
  // Next.js bundles are retained even when they end in a rejected extension (e.g. .css).
  if (lower.includes('/_next/static/')) {
    return false;
  }
  return REJECTED_MEDIA_EXTENSIONS.some((ext) => lower.endsWith(ext));
}

function classifyRouteKind(pathname: string): HtmlExtractedRouteKind {
  if (pathname.toLowerCase().includes('/_next/static/')) {
    return 'static_bundle';
  }
  return 'app_endpoint';
}

function normalizeTargetDomain(targetDomain: string): string {
  return targetDomain
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/\.$/, '');
}

function isSkippableSchemeOrFragment(raw: string): boolean {
  const lower = raw.trim().toLowerCase();
  if (lower.length === 0 || lower === '#') return true;
  if (lower.startsWith('#')) return true;
  if (lower.startsWith('javascript:')) return true;
  if (lower.startsWith('mailto:')) return true;
  if (lower.startsWith('tel:')) return true;
  if (lower.startsWith('data:')) return true;
  if (lower.startsWith('blob:')) return true;
  return false;
}

/**
 * Pure hermetic HTML route extractor.
 * Scope + egress gates run before a candidate is accepted; denials are dropped (fail-closed).
 */
export class HtmlRouteExtractionService {
  public extract(input: HtmlRouteExtractionInput): HtmlRouteExtractionResult {
    const body = truncateBody(typeof input.bodyText === 'string' ? input.bodyText : '');
    const accepted: HtmlExtractedRouteCandidate[] = [];
    let rejectedMediaCount = 0;
    let rejectedOutOfScopeCount = 0;
    let rejectedMalformedCount = 0;

    if (body.length === 0) {
      return {
        accepted: Object.freeze([]),
        rejectedMediaCount: 0,
        rejectedOutOfScopeCount: 0,
        rejectedMalformedCount: 0,
      };
    }

    let base: URL;
    try {
      base = new URL(input.baseUrl);
    } catch {
      return {
        accepted: Object.freeze([]),
        rejectedMediaCount: 0,
        rejectedOutOfScopeCount: 0,
        rejectedMalformedCount: 1,
      };
    }

    if (base.protocol !== 'http:' && base.protocol !== 'https:') {
      return {
        accepted: Object.freeze([]),
        rejectedMediaCount: 0,
        rejectedOutOfScopeCount: 0,
        rejectedMalformedCount: 1,
      };
    }

    const targetDomain = normalizeTargetDomain(input.targetDomain);
    const egressScope = deriveM30EgressScope(input.authorizedScopeGrant);
    const maxResults =
      typeof input.maxResults === 'number' && input.maxResults > 0
        ? Math.floor(input.maxResults)
        : Number.POSITIVE_INFINITY;
    const seen = new Set<string>();

    for (const match of collectAttributeMatches(body)) {
      if (accepted.length >= maxResults) break;

      if (isSkippableSchemeOrFragment(match.value)) {
        rejectedMalformedCount += 1;
        continue;
      }

      let resolved: URL;
      try {
        resolved = new URL(match.value, base);
      } catch {
        rejectedMalformedCount += 1;
        continue;
      }

      if (resolved.protocol !== 'http:' && resolved.protocol !== 'https:') {
        rejectedMalformedCount += 1;
        continue;
      }

      resolved.hash = '';
      const pathname = resolved.pathname || '/';

      if (isRejectedMediaPath(pathname)) {
        rejectedMediaCount += 1;
        continue;
      }

      const host = resolved.hostname.trim().toLowerCase().replace(/\.$/, '');
      if (!host) {
        rejectedMalformedCount += 1;
        continue;
      }

      // Prefer same registrable target: host must equal targetDomain or be an in-scope subdomain.
      const sameTargetFamily =
        host === targetDomain || host.endsWith('.' + targetDomain);
      if (!sameTargetFamily) {
        rejectedOutOfScopeCount += 1;
        continue;
      }

      if (!isScopeAllowed(host, input.authorizedScopeGrant)) {
        rejectedOutOfScopeCount += 1;
        continue;
      }

      const absoluteUrl = `${resolved.protocol}//${resolved.host}${pathname}${resolved.search}`;

      const egressDecision = evaluateEgressPolicy({
        targetUrl: absoluteUrl,
        authorizedScope: egressScope,
        capabilityId: 'recon.html_link_extraction',
      });
      if (egressDecision.decision !== 'allow') {
        rejectedOutOfScopeCount += 1;
        continue;
      }

      if (seen.has(absoluteUrl)) {
        continue;
      }
      seen.add(absoluteUrl);

      const query =
        resolved.search.length > 1 ? resolved.search.slice(1) : undefined;

      accepted.push({
        url: absoluteUrl,
        host,
        path: pathname,
        ...(query !== undefined ? { query } : {}),
        kind: classifyRouteKind(pathname),
        attribute: match.attribute,
        rawHref: match.value,
      });
    }

    return {
      accepted: Object.freeze(accepted),
      rejectedMediaCount,
      rejectedOutOfScopeCount,
      rejectedMalformedCount,
    };
  }
}
