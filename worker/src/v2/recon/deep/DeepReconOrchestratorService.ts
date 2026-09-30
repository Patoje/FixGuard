/**
 * Deep recon — method-kit orchestrator.
 * P0: robots_sitemap_feed. P1: js_surface_mining + sourcemap_surface.
 * P3: byot_network_harvest. P4: gated_dict_topk + html_hop_extra.
 * js/sourcemap skip URLs already mined in stage 4 so the composite does not double-spend.
 */

import type { VerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../../lineage/AuthorizedExecutionLineageContracts.js';
import type { DiscoveredUrlObservation } from '../adapters/UrlDiscoveryContracts.js';
import type { JsLuiceDiscoveryTool } from '../adapters/JsLuiceDiscoveryContracts.js';
import { selectJsLuiceTargets } from '../adapters/JsLuiceAdapter.js';
import { runSourcemapSurfaceExtraction } from '../analysis/SourcemapSurfaceExtractionService.js';
import type { IdorHttpProbeTransport } from '../../detection/DetectionContracts.js';
import type { PreSpawnDnsResolver } from '../adapters/AdapterPreflightPipeline.js';
import type { ContentDiscoveryTool } from '../adapters/ContentDiscoveryContracts.js';
import type { ParameterDiscoveryTool } from '../adapters/ParameterDiscoveryContracts.js';
import type { PlaywrightBrowserLauncher } from '../adapters/BrowserAutomationContracts.js';
import { runRobotsSitemapInventoryFeed } from '../analysis/RobotsSitemapInventoryFeedService.js';
import { inspectOpenIdAndOAuth, inspectSecurityTxt } from './WellKnownInspectService.js';
import {
  DEEP_RECON_CONTRACT_VERSION,
  DEEP_RECON_NON_CLAIMS,
  type DeepReconBudget,
  type DeepReconContractVersion,
  type DeepReconMethodPlanEntry,
  type DeepReconMethodResultSummary,
  type DeepReconParameterSeed,
  type DeepReconSchemaObservation,
  type DeepReconStackSignals,
} from './DeepReconContracts.js';
import { runApiSchemaDiscovery } from './ApiSchemaDiscoveryService.js';
import { isInventorySurfaceMethod, planDeepReconMethods } from './DeepReconMethodPlanner.js';
import { runGatedDictTopK } from './GatedDictTopKService.js';
import { runHtmlHopExtra } from './HtmlHopExtraService.js';
import {
  runByotNetworkHarvest,
  type ByotNetworkHarvestRequest,
} from './ByotNetworkHarvestService.js';
import type { ByotHarvestServerActionHint } from './ByotNetworkHarvestContracts.js';
import type { ObservedFact } from '../../observation/ObservedFactContracts.js';

export interface DeepReconOrchestratorRequest {
  readonly originUrl: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly authorizedScopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly stack: DeepReconStackSignals;
  readonly budget: DeepReconBudget;
  readonly enableByotHarvest?: boolean;
  readonly enableGatedDicts?: boolean;
  /** Inventory URLs for gated dict / JS / sourcemap ranking (optional; falls back to origin). */
  readonly inventoryUrls?: readonly { readonly url: string }[];
  /** Ranked jsluice port. Absent → js_surface_mining skips without network. */
  readonly jsLuiceTool?: JsLuiceDiscoveryTool;
  /** JS URLs already mined by composite stage 4. Not fetched again. */
  readonly jsSurfaceExcludeUrls?: readonly string[];
  /** JS URLs whose sourcemaps stage 4 already probed. */
  readonly sourcemapExcludeUrls?: readonly string[];
  /**
   * Supabase anon key only when recon already observed it.
   * Never copied into the orchestrator result.
   */
  readonly observedAnonApiKey?: string;
  /** BYOT Identity A headers for authenticated harvest (never logged). */
  readonly byotAuthHeaders?: Readonly<Record<string, string>>;
  /** Extra page seeds for BYOT harvest (capped inside harvest). */
  readonly byotHarvestPageUrls?: readonly string[];
  /** Injectable Playwright launcher for authenticated BYOT harvest. */
  readonly byotBrowserLauncher?: PlaywrightBrowserLauncher;
  /** Force HTTP-only BYOT harvest (skip Playwright). */
  readonly byotHttpOnly?: boolean;
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
  /** Auth hosts already observed and present in allowedHosts. */
  readonly observedAuthHosts?: readonly string[];
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
  readonly timeoutMs?: number;
  /** Optional heartbeat hint callback (UI liveness only). */
  readonly onMethodStart?: (info: {
    readonly method: string;
    readonly toolHint: string;
  }) => Promise<void> | void;
}

export interface DeepReconOrchestratorResult {
  readonly contractVersion: DeepReconContractVersion;
  readonly status: 'completed' | 'budget_exhausted' | 'no_methods';
  readonly planned: readonly DeepReconMethodPlanEntry[];
  readonly methodResults: readonly DeepReconMethodResultSummary[];
  readonly urlObservations: readonly DiscoveredUrlObservation[];
  readonly serverActionHints: readonly ByotHarvestServerActionHint[];
  readonly observedFacts: readonly ObservedFact[];
  readonly sourcemapTexts?: readonly string[];
  readonly parameterSeeds: readonly DeepReconParameterSeed[];
  readonly schemaObservations: readonly DeepReconSchemaObservation[];
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
      serverActionHints: [],
      observedFacts: [],
      parameterSeeds: [],
      schemaObservations: [],
      requestsUsed: 0,
      nonClaims: DEEP_RECON_NON_CLAIMS,
    };
  }

  const methodResults: DeepReconMethodResultSummary[] = [];
  const urls: DiscoveredUrlObservation[] = [];
  const serverActionHints: ByotHarvestServerActionHint[] = [];
  const observedFacts: ObservedFact[] = [];
  const sourcemapTexts: string[] = [];
  const parameterSeeds: DeepReconParameterSeed[] = [];
  const schemaObservations: DeepReconSchemaObservation[] = [];
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

    if (request.onMethodStart) {
      try {
        await request.onMethodStart({
          method: entry.method,
          toolHint: `deep_recon:${entry.method}`,
        });
      } catch {
        // Non-blocking — heartbeat must never abort deep recon.
      }
    }

    if (entry.method === 'security_txt' || entry.method === 'well_known_oauth') {
      if (!request.transport) {
        methodResults.push({
          method: entry.method,
          status: 'skipped',
          reasonCode: 'transport_missing',
          requestsUsed: 0,
          urlsSeeded: 0,
        });
        continue;
      }
      const observedAt = new Date().toISOString();
      if (entry.method === 'security_txt') {
        const inspected = await inspectSecurityTxt({
          originUrl: request.originUrl,
          verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
          scopeGrant: request.authorizedScopeGrant,
          lineage: request.lineage,
          transport: request.transport,
          ...(request.dnsResolver ? { dnsResolver: request.dnsResolver } : {}),
          observedAt,
        });
        if (inspected.fact) observedFacts.push(inspected.fact);
        if (inspected.documentFact) observedFacts.push(inspected.documentFact);
        methodResults.push({
          method: entry.method,
          status: inspected.status === 'preflight_denied' ? 'preflight_denied' : inspected.status === 'skipped' ? 'skipped' : 'ran',
          reasonCode: inspected.status,
          requestsUsed: inspected.requestCount,
          urlsSeeded: 0,
        });
        requestsUsed += inspected.requestCount;
        remaining -= inspected.requestCount;
        continue;
      }
      const inspected = await inspectOpenIdAndOAuth({
        originUrl: request.originUrl,
        authHosts: request.observedAuthHosts ?? [],
        verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
        scopeGrant: request.authorizedScopeGrant,
        lineage: request.lineage,
        transport: request.transport,
        ...(request.dnsResolver ? { dnsResolver: request.dnsResolver } : {}),
        observedAt,
      });
      for (const fact of inspected.facts) observedFacts.push(fact);
      methodResults.push({
        method: entry.method,
        status: inspected.status === 'preflight_denied' ? 'preflight_denied' : inspected.status === 'skipped' ? 'skipped' : 'ran',
        reasonCode: inspected.status,
        requestsUsed: inspected.requestCount,
        urlsSeeded: 0,
      });
      requestsUsed += inspected.requestCount;
      remaining -= inspected.requestCount;
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
        for (const fact of feed.observedFacts) observedFacts.push(fact);
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
      const plannedInventory = planned.filter((item) => isInventorySurfaceMethod(item.method));
      const inventoryFinished =
        plannedInventory.length > 0 &&
        plannedInventory.every((item) =>
          methodResults.some((result) => result.method === item.method)
        );
      if (!inventoryFinished) {
        methodResults.push({
          method: entry.method,
          status: 'skipped',
          reasonCode: 'gated_dict_before_inventory_methods',
          requestsUsed: 0,
          urlsSeeded: 0,
        });
        continue;
      }
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
      for (const fact of gated.observedFacts ?? []) {
        if (!observedFacts.some((existing) => existing.factId === fact.factId)) {
          observedFacts.push(fact);
        }
      }
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

    if (entry.method === 'byot_network_harvest') {
      const harvestReq: ByotNetworkHarvestRequest = {
        originUrl: request.originUrl,
        verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
        authorizedScopeGrant: request.authorizedScopeGrant,
        lineage: request.lineage,
        ...(request.byotAuthHeaders
          ? { authHeaders: request.byotAuthHeaders }
          : {}),
        ...(request.byotHarvestPageUrls && request.byotHarvestPageUrls.length > 0
          ? { pageUrls: request.byotHarvestPageUrls }
          : {}),
        ...(request.byotBrowserLauncher
          ? { browserLauncher: request.byotBrowserLauncher }
          : {}),
        ...(request.byotHttpOnly === true ? { httpOnly: true } : {}),
        transport: request.transport,
        dnsResolver: request.dnsResolver,
        timeoutMs: request.timeoutMs,
      };
      const harvest = await runByotNetworkHarvest(harvestReq);
      for (const u of harvest.urlObservations) urls.push(u);
      for (const h of harvest.serverActionHints) serverActionHints.push(h);
      if (harvest.status === 'success') {
        for (const fact of harvest.observedFacts) observedFacts.push(fact);
      }
      const status =
        harvest.status === 'success'
          ? 'ran'
          : harvest.status === 'skipped'
            ? 'skipped'
            : harvest.status === 'preflight_denied'
              ? 'preflight_denied'
              : 'failed';
      methodResults.push({
        method: entry.method,
        status,
        reasonCode: harvest.reasonCode,
        requestsUsed: harvest.requestsUsed,
        urlsSeeded: harvest.urlObservations.length,
      });
      requestsUsed += harvest.requestsUsed;
      remaining -= harvest.requestsUsed;
      continue;
    }

    if (entry.method === 'js_surface_mining') {
      const jsOutcome = await runJsSurfaceMining({
        request,
        entry,
        seededUrls: urls,
        parameterSeeds,
      });
      for (const obs of jsOutcome.urlObservations) urls.push(obs);
      methodResults.push(jsOutcome.summary);
      requestsUsed += jsOutcome.summary.requestsUsed;
      remaining -= jsOutcome.summary.requestsUsed;
      continue;
    }

    if (entry.method === 'api_schema_discovery') {
      const inventory =
        request.inventoryUrls && request.inventoryUrls.length > 0
          ? request.inventoryUrls
          : urls.map((item) => ({ url: item.url }));
      const schema = await runApiSchemaDiscovery({
        originUrl: request.originUrl,
        verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
        authorizedScopeGrant: request.authorizedScopeGrant,
        lineage: request.lineage,
        inventoryUrls: inventory,
        ...(request.transport ? { transport: request.transport } : {}),
        ...(request.dnsResolver ? { dnsResolver: request.dnsResolver } : {}),
        timeoutMs: request.timeoutMs,
        ...(request.observedAnonApiKey
          ? { observedAnonApiKey: request.observedAnonApiKey }
          : {}),
        maxTargets: entry.expectedRequestCost,
      });
      for (const obs of schema.urlObservations) urls.push(obs);
      for (const item of schema.schemaObservations) schemaObservations.push(item);
      for (const fact of schema.observedFacts) observedFacts.push(fact);
      methodResults.push({
        method: entry.method,
        status: schema.status,
        reasonCode: schema.reasonCode,
        requestsUsed: schema.requestsUsed,
        urlsSeeded: schema.urlObservations.length,
      });
      requestsUsed += schema.requestsUsed;
      remaining -= schema.requestsUsed;
      continue;
    }

    if (entry.method === 'sourcemap_surface') {
      const mapOutcome = await runSourcemapSurfaceMethod({
        request,
        entry,
        seededUrls: urls,
      });
      for (const obs of mapOutcome.urlObservations) urls.push(obs);
      for (const fact of mapOutcome.observedFacts) observedFacts.push(fact);
      for (const text of mapOutcome.sourcemapTexts) sourcemapTexts.push(text);
      methodResults.push(mapOutcome.summary);
      requestsUsed += mapOutcome.summary.requestsUsed;
      remaining -= mapOutcome.summary.requestsUsed;
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
    serverActionHints: Object.freeze(serverActionHints),
    observedFacts: Object.freeze(observedFacts),
    ...(sourcemapTexts.length > 0 ? { sourcemapTexts: Object.freeze(sourcemapTexts) } : {}),
    parameterSeeds: Object.freeze(parameterSeeds),
    schemaObservations: Object.freeze(schemaObservations),
    requestsUsed,
    nonClaims: DEEP_RECON_NON_CLAIMS,
  };
}

function jsInventory(
  request: DeepReconOrchestratorRequest,
  seededUrls: readonly DiscoveredUrlObservation[]
): { url: string }[] {
  const inventory: { url: string }[] = [];
  for (const item of request.inventoryUrls ?? []) {
    inventory.push({ url: item.url });
  }
  for (const item of seededUrls) {
    inventory.push({ url: item.url });
  }
  return inventory;
}

async function runJsSurfaceMining(input: {
  readonly request: DeepReconOrchestratorRequest;
  readonly entry: DeepReconMethodPlanEntry;
  readonly seededUrls: readonly DiscoveredUrlObservation[];
  readonly parameterSeeds: DeepReconParameterSeed[];
}): Promise<{
  readonly summary: DeepReconMethodResultSummary;
  readonly urlObservations: readonly DiscoveredUrlObservation[];
}> {
  const empty = (reasonCode: string): {
    summary: DeepReconMethodResultSummary;
    urlObservations: readonly DiscoveredUrlObservation[];
  } => ({
    summary: {
      method: input.entry.method,
      status: 'skipped',
      reasonCode,
      requestsUsed: 0,
      urlsSeeded: 0,
    },
    urlObservations: [],
  });

  if (!input.request.jsLuiceTool) {
    return empty('jsluice_tool_not_configured');
  }

  const cap = input.entry.expectedRequestCost;
  const inventory = jsInventory(input.request, input.seededUrls);
  const available = selectJsLuiceTargets({ inventoryUrls: inventory, maxTargets: cap });
  const targets = selectJsLuiceTargets({
    inventoryUrls: inventory,
    maxTargets: cap,
    excludeUrls: input.request.jsSurfaceExcludeUrls ?? [],
  });
  if (targets.length === 0) {
    return empty(
      available.length > 0 ? 'jsluice_already_mined_in_stage_4' : 'no_js_inventory'
    );
  }

  const urlObservations: DiscoveredUrlObservation[] = [];
  let used = 0;
  let successes = 0;
  let unavailable = false;
  const tool = input.request.jsLuiceTool;
  for (const jsUrl of targets) {
    if (used >= cap) break;
    const jsResult = await tool.discoverFromJavaScript({
      targetJsUrlOrPath: jsUrl,
      resolvePathsBase: input.request.originUrl,
      verifiedAuthorizationDecision: input.request.verifiedAuthorizationDecision,
      authorizedScopeGrant: input.request.authorizedScopeGrant,
      lineage: input.request.lineage,
      timeoutMs: input.request.timeoutMs,
    });
    used += 1;
    if (jsResult.status === 'success') {
      successes += 1;
      for (const obs of jsResult.urlObservations) urlObservations.push(obs);
      for (const obs of jsResult.parameterObservations) {
        input.parameterSeeds.push({
          url: obs.sourceUrl,
          parameterName: obs.parameterName,
          source: 'js_surface_mining',
        });
      }
    } else if (jsResult.status === 'tool_unavailable') {
      unavailable = true;
      break;
    }
  }

  const status = successes > 0 ? 'ran' : unavailable ? 'skipped' : 'failed';
  const reasonCode =
    successes > 0
      ? 'js_surface_seeded'
      : unavailable
        ? 'jsluice_binary_missing'
        : 'js_surface_failed';
  return {
    summary: {
      method: input.entry.method,
      status,
      reasonCode,
      requestsUsed: used,
      urlsSeeded: urlObservations.length,
    },
    urlObservations,
  };
}

async function runSourcemapSurfaceMethod(input: {
  readonly request: DeepReconOrchestratorRequest;
  readonly entry: DeepReconMethodPlanEntry;
  readonly seededUrls: readonly DiscoveredUrlObservation[];
}): Promise<{
  readonly summary: DeepReconMethodResultSummary;
  readonly urlObservations: readonly DiscoveredUrlObservation[];
  readonly observedFacts: readonly ObservedFact[];
  readonly sourcemapTexts: readonly string[];
}> {
  const cap = input.entry.expectedRequestCost;
  const inventory = jsInventory(input.request, input.seededUrls);
  const available = selectJsLuiceTargets({ inventoryUrls: inventory, maxTargets: cap });
  const targets = selectJsLuiceTargets({
    inventoryUrls: inventory,
    maxTargets: cap,
    excludeUrls: input.request.sourcemapExcludeUrls ?? [],
  });
  if (targets.length === 0) {
    return {
      summary: {
        method: input.entry.method,
        status: 'skipped',
        reasonCode:
          available.length > 0 ? 'sourcemap_already_probed_in_stage_4' : 'no_js_inventory',
        requestsUsed: 0,
        urlsSeeded: 0,
      },
      urlObservations: [],
      observedFacts: [],
      sourcemapTexts: [],
    };
  }
  if (!input.request.transport) {
    return {
      summary: {
        method: input.entry.method,
        status: 'skipped',
        reasonCode: 'transport_not_configured',
        requestsUsed: 0,
        urlsSeeded: 0,
      },
      urlObservations: [],
      observedFacts: [],
      sourcemapTexts: [],
    };
  }

  const urlObservations: DiscoveredUrlObservation[] = [];
  const documentFacts: ObservedFact[] = [];
  const downloadedMaps: string[] = [];
  let used = 0;
  let denied = 0;
  let opened = 0;
  for (const jsUrl of targets) {
    if (used + denied >= cap) break;
    const mapResult = await runSourcemapSurfaceExtraction({
      sourceJsUrl: jsUrl,
      resolvePathsBase: input.request.originUrl,
      verifiedAuthorizationDecision: input.request.verifiedAuthorizationDecision,
      authorizedScopeGrant: input.request.authorizedScopeGrant,
      lineage: input.request.lineage,
      ...(input.request.transport ? { transport: input.request.transport } : {}),
      ...(input.request.dnsResolver ? { dnsResolver: input.request.dnsResolver } : {}),
      timeoutMs: input.request.timeoutMs,
    });
    if (mapResult.status === 'preflight_denied') {
      denied += 1;
      continue;
    }
    used += 1;
    for (const fact of mapResult.observedFacts ?? []) documentFacts.push(fact);
    if (mapResult.status === 'success') {
      opened += 1;
      if (mapResult.bodyText.length > 0) downloadedMaps.push(mapResult.bodyText);
      for (const obs of mapResult.urlObservations) urlObservations.push(obs);
    }
  }

  const status =
    used > 0 ? 'ran' : denied > 0 ? 'preflight_denied' : 'skipped';
  const reasonCode =
    urlObservations.length > 0
      ? 'sourcemap_paths_seeded'
      : opened > 0
        ? 'sourcemap_opened_without_finding'
        : used > 0
          ? 'sourcemap_not_accessible'
          : denied > 0
            ? 'preflight_denied'
            : 'no_js_inventory';
  return {
    summary: {
      method: input.entry.method,
      status,
      reasonCode,
      requestsUsed: used,
      urlsSeeded: urlObservations.length,
    },
    urlObservations,
    observedFacts: documentFacts,
    sourcemapTexts: downloadedMaps,
  };
}
