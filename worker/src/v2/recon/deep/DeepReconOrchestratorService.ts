/**
 * Deep recon — method-kit orchestrator.
 * P0: robots_sitemap_feed. P4: gated_dict_topk + optional html_hop_extra.
 * Other methods remain planned/skipped until wired.
 */

import type { VerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../../lineage/AuthorizedExecutionLineageContracts.js';
import type { DiscoveredUrlObservation } from '../adapters/UrlDiscoveryContracts.js';
import type { IdorHttpProbeTransport } from '../../detection/DetectionContracts.js';
import type { PreSpawnDnsResolver } from '../adapters/AdapterPreflightPipeline.js';
import type { ContentDiscoveryTool } from '../adapters/ContentDiscoveryContracts.js';
import type { ParameterDiscoveryTool } from '../adapters/ParameterDiscoveryContracts.js';
import { runRobotsSitemapInventoryFeed } from '../analysis/RobotsSitemapInventoryFeedService.js';
import {
  DEEP_RECON_CONTRACT_VERSION,
  DEEP_RECON_NON_CLAIMS,
  type DeepReconBudget,
  type DeepReconContractVersion,
  type DeepReconMethodPlanEntry,
  type DeepReconMethodResultSummary,
  type DeepReconStackSignals,
} from './DeepReconContracts.js';
import { planDeepReconMethods } from './DeepReconMethodPlanner.js';
import { runGatedDictTopK } from './GatedDictTopKService.js';
import { runHtmlHopExtra } from './HtmlHopExtraService.js';

export interface DeepReconOrchestratorRequest {
  readonly originUrl: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly authorizedScopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly stack: DeepReconStackSignals;
  readonly budget: DeepReconBudget;
  readonly enableByotHarvest?: boolean;
  readonly enableGatedDicts?: boolean;
  /** Inventory URLs for gated dict / ranking (optional; falls back to origin). */
  readonly inventoryUrls?: readonly { readonly url: string }[];
  readonly contentTool?: ContentDiscoveryTool;
  readonly parameterTool?: ParameterDiscoveryTool;
  readonly wordlistPath?: string;
  readonly maxFfufRoots?: number;
  readonly maxArjunTargets?: number;
  /** Optional hop-3 bodies (app_endpoint only). */
  readonly hopExtraBodies?: readonly {
    readonly url: string;
    readonly bodyText: string;
  }[];
  readonly maxHop3?: number;
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
  readonly timeoutMs?: number;
}

export interface DeepReconOrchestratorResult {
  readonly contractVersion: DeepReconContractVersion;
  readonly status: 'completed' | 'budget_exhausted' | 'no_methods';
  readonly planned: readonly DeepReconMethodPlanEntry[];
  readonly methodResults: readonly DeepReconMethodResultSummary[];
  readonly urlObservations: readonly DiscoveredUrlObservation[];
  readonly requestsUsed: number;
  readonly nonClaims: typeof DEEP_RECON_NON_CLAIMS;
}

export async function runDeepReconOrchestrator(
  request: DeepReconOrchestratorRequest
): Promise<DeepReconOrchestratorResult> {
  const planned = planDeepReconMethods({
    stack: request.stack,
    budget: request.budget,
    enableByotHarvest: request.enableByotHarvest,
    enableGatedDicts: request.enableGatedDicts,
  });

  if (planned.length === 0) {
    return {
      contractVersion: DEEP_RECON_CONTRACT_VERSION,
      status: 'no_methods',
      planned,
      methodResults: [],
      urlObservations: [],
      requestsUsed: 0,
      nonClaims: DEEP_RECON_NON_CLAIMS,
    };
  }

  const methodResults: DeepReconMethodResultSummary[] = [];
  const urls: DiscoveredUrlObservation[] = [];
  let requestsUsed = 0;
  let remaining = request.budget.remainingRequests;

  let targetDomain = 'example.com';
  try {
    targetDomain = new URL(request.originUrl).hostname;
  } catch {
    // keep fallback
  }

  for (const entry of planned) {
    if (remaining < entry.expectedRequestCost) {
      methodResults.push({
        method: entry.method,
        status: 'budget_exceeded',
        reasonCode: 'insufficient_remaining_budget',
        requestsUsed: 0,
        urlsSeeded: 0,
      });
      continue;
    }

    if (entry.method === 'robots_sitemap_feed') {
      const feed = await runRobotsSitemapInventoryFeed({
        originUrl: request.originUrl,
        verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
        authorizedScopeGrant: request.authorizedScopeGrant,
        lineage: request.lineage,
        transport: request.transport,
        dnsResolver: request.dnsResolver,
        timeoutMs: request.timeoutMs,
      });
      const seeded =
        feed.status === 'success' ? feed.urlObservations.length : 0;
      const used =
        feed.status === 'success'
          ? 1 + feed.sitemapUrls.length
          : feed.status === 'preflight_denied'
            ? 0
            : 1;
      if (feed.status === 'success') {
        for (const u of feed.urlObservations) urls.push(u);
      }
      methodResults.push({
        method: entry.method,
        status:
          feed.status === 'success'
            ? 'ran'
            : feed.status === 'preflight_denied'
              ? 'preflight_denied'
              : 'failed',
        reasonCode: feed.reasonCode,
        requestsUsed: used,
        urlsSeeded: seeded,
      });
      requestsUsed += used;
      remaining -= used;
      continue;
    }

    if (entry.method === 'gated_dict_topk') {
      const inventory =
        request.inventoryUrls && request.inventoryUrls.length > 0
          ? request.inventoryUrls
          : [
              { url: request.originUrl },
              ...urls.map((u) => ({ url: u.url })),
            ];
      const gated = await runGatedDictTopK({
        verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
        authorizedScopeGrant: request.authorizedScopeGrant,
        lineage: request.lineage,
        inventoryUrls: inventory,
        contentTool: request.contentTool,
        parameterTool: request.parameterTool,
        wordlistPath: request.wordlistPath,
        maxFfufRoots: request.maxFfufRoots,
        maxArjunTargets: request.maxArjunTargets,
        transport: request.transport,
        dnsResolver: request.dnsResolver,
        timeoutMs: request.timeoutMs,
        skipWafCanary: !request.transport,
      });
      for (const u of gated.urlObservations) urls.push(u);
      const status =
        gated.status === 'success'
          ? 'ran'
          : gated.status === 'waf_aborted'
            ? 'skipped'
            : gated.status === 'preflight_denied'
              ? 'preflight_denied'
              : gated.status === 'tools_missing' || gated.status === 'empty_inventory'
                ? 'skipped'
                : 'failed';
      methodResults.push({
        method: entry.method,
        status,
        reasonCode: gated.reasonCode,
        requestsUsed: gated.requestsUsed,
        urlsSeeded: gated.urlObservations.length,
      });
      requestsUsed += gated.requestsUsed;
      remaining -= gated.requestsUsed;
      continue;
    }

    if (entry.method === 'html_hop_extra') {
      const hop = runHtmlHopExtra({
        targetDomain,
        authorizedScopeGrant: request.authorizedScopeGrant,
        appEndpointBodies: request.hopExtraBodies ?? [],
        maxResults: request.maxHop3,
      });
      for (const u of hop.urlObservations) urls.push(u);
      methodResults.push({
        method: entry.method,
        status: hop.reasonCode === 'no_app_endpoint_bodies' ? 'skipped' : 'ran',
        reasonCode: hop.reasonCode,
        requestsUsed: 0,
        urlsSeeded: hop.urlsSeeded,
      });
      continue;
    }

    // Later phases wire these; record skip honestly.
    // Checkpoint 6 start: BYOT harvest stub activates when FG_ACCESS_TOKEN is set.
    if (entry.method === 'byot_network_harvest') {
      const token = process.env.FG_ACCESS_TOKEN?.trim() ?? '';
      if (token.length < 20) {
        methodResults.push({
          method: entry.method,
          status: 'skipped',
          reasonCode: 'byot_harvest_token_absent',
          requestsUsed: 0,
          urlsSeeded: 0,
        });
      } else {
        methodResults.push({
          method: entry.method,
          status: 'ran',
          reasonCode: 'byot_harvest_stub_activated',
          requestsUsed: 0,
          urlsSeeded: 0,
        });
      }
      continue;
    }

    methodResults.push({
      method: entry.method,
      status: 'skipped',
      reasonCode: 'method_not_wired_in_p0',
      requestsUsed: 0,
      urlsSeeded: 0,
    });
  }

  return {
    contractVersion: DEEP_RECON_CONTRACT_VERSION,
    status: requestsUsed > 0 || urls.length > 0 ? 'completed' : 'no_methods',
    planned,
    methodResults: Object.freeze(methodResults),
    urlObservations: Object.freeze(urls),
    requestsUsed,
    nonClaims: DEEP_RECON_NON_CLAIMS,
  };
}
