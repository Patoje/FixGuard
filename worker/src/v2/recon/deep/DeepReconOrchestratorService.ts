/**
 * Deep recon P0 — thin orchestrator.
 * Runs planned methods fail-soft; P0 executes robots_sitemap_feed concretely.
 * Other methods are planned/skipped until later phases wire them.
 */

import type { VerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../../lineage/AuthorizedExecutionLineageContracts.js';
import type { DiscoveredUrlObservation } from '../adapters/UrlDiscoveryContracts.js';
import type { IdorHttpProbeTransport } from '../../detection/DetectionContracts.js';
import type { PreSpawnDnsResolver } from '../adapters/AdapterPreflightPipeline.js';
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

export interface DeepReconOrchestratorRequest {
  readonly originUrl: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly authorizedScopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly stack: DeepReconStackSignals;
  readonly budget: DeepReconBudget;
  readonly enableByotHarvest?: boolean;
  readonly enableGatedDicts?: boolean;
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

    // Later phases wire these; P0 records skip honestly.
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
    status: requestsUsed > 0 ? 'completed' : 'no_methods',
    planned,
    methodResults: Object.freeze(methodResults),
    urlObservations: Object.freeze(urls),
    requestsUsed,
    nonClaims: DEEP_RECON_NON_CLAIMS,
  };
}
