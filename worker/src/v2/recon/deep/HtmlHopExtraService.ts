/**
 * Optional HTML hop-3 extraction (Deep recon P4 / html_hop_extra).
 * Mines app_endpoint bodies only; never /_next/static. Zero network I/O.
 */

import type { AuthorizedScopeGrant } from '../../scope/AuthorizedScopeContracts.js';
import type { DiscoveredUrlObservation } from '../adapters/UrlDiscoveryContracts.js';
import {
  HTML_LINK_EXTRACTION_SOURCE,
  HTML_ROUTE_EXTRACTION_MAX_HOP3,
  HtmlRouteExtractionService,
} from '../analysis/HtmlRouteExtractionService.js';

export const HTML_HOP_EXTRA_SOURCE = 'html_hop_extra' as const;

export interface HtmlHopExtraRequest {
  readonly targetDomain: string;
  readonly authorizedScopeGrant: AuthorizedScopeGrant;
  /** Hop-2 (or later) app_endpoint bodies already observed. */
  readonly appEndpointBodies: readonly {
    readonly url: string;
    readonly bodyText: string;
  }[];
  readonly maxResults?: number;
}

export interface HtmlHopExtraResult {
  readonly urlObservations: readonly DiscoveredUrlObservation[];
  readonly urlsSeeded: number;
  readonly reasonCode: 'hop3_seeded' | 'hop3_empty' | 'no_app_endpoint_bodies';
}

/**
 * Extract optional hop-3 URL seeds from app_endpoint response bodies.
 */
export function runHtmlHopExtra(request: HtmlHopExtraRequest): HtmlHopExtraResult {
  const max =
    typeof request.maxResults === 'number' && request.maxResults > 0
      ? Math.min(Math.floor(request.maxResults), HTML_ROUTE_EXTRACTION_MAX_HOP3)
      : HTML_ROUTE_EXTRACTION_MAX_HOP3;

  if (!request.appEndpointBodies || request.appEndpointBodies.length === 0) {
    return {
      urlObservations: Object.freeze([]),
      urlsSeeded: 0,
      reasonCode: 'no_app_endpoint_bodies',
    };
  }

  const extractor = new HtmlRouteExtractionService();
  const out: DiscoveredUrlObservation[] = [];
  const seen = new Set<string>();
  const discoveredAt = new Date().toISOString();

  for (const body of request.appEndpointBodies) {
    if (out.length >= max) break;
    try {
      const path = new URL(body.url).pathname;
      if (/\/_next\/static\//i.test(path)) continue;
    } catch {
      continue;
    }
    const remaining = max - out.length;
    const extracted = extractor.extract({
      bodyText: body.bodyText,
      baseUrl: body.url,
      targetDomain: request.targetDomain,
      authorizedScopeGrant: request.authorizedScopeGrant,
      maxResults: remaining,
    });
    for (const candidate of extracted.accepted) {
      if (out.length >= max) break;
      if (candidate.kind !== 'app_endpoint') continue;
      if (seen.has(candidate.url)) continue;
      seen.add(candidate.url);
      out.push({
        url: candidate.url,
        host: candidate.host,
        path: candidate.path,
        ...(candidate.query ? { query: candidate.query } : {}),
        sources: Object.freeze([HTML_HOP_EXTRA_SOURCE, HTML_LINK_EXTRACTION_SOURCE]),
        discoveredAt,
        collectedAt: discoveredAt,
        freshness: 'live',
        sourceReliability: 'inferred_relationship',
      });
    }
  }

  return {
    urlObservations: Object.freeze(out),
    urlsSeeded: out.length,
    reasonCode: out.length > 0 ? 'hop3_seeded' : 'hop3_empty',
  };
}
