/**
 * Deep recon P0 — MethodPlanner.
 * Chooses ordered methods from stack signals + remaining budget (fail-soft).
 */

import type {
  DeepReconBudget,
  DeepReconMethodPlanEntry,
  DeepReconStackSignals,
} from './DeepReconContracts.js';

export function planDeepReconMethods(input: {
  readonly stack: DeepReconStackSignals;
  readonly budget: DeepReconBudget;
  readonly enableByotHarvest?: boolean;
  readonly enableGatedDicts?: boolean;
}): readonly DeepReconMethodPlanEntry[] {
  const remaining =
    input.budget.remainingRequests > 0
      ? Math.floor(input.budget.remainingRequests)
      : 0;
  if (remaining <= 0) return Object.freeze([]);

  const candidates: DeepReconMethodPlanEntry[] = [
    {
      method: 'robots_sitemap_feed',
      expectedRequestCost: 4,
      priority: 10,
      rationale: 'Inject robots Allow/Sitemap locs into inventory (cheap, high signal)',
      epistemicIntent: 'OBSERVED',
    },
  ];

  if (input.stack.hasSpa || input.stack.hasNextJs || input.stack.hasVercel) {
    candidates.push({
      method: 'js_surface_mining',
      expectedRequestCost: 12,
      priority: 20,
      rationale: 'Ranked jsluice + chunk surface for Next/Vercel SPAs',
      epistemicIntent: 'OBSERVED',
    });
    candidates.push({
      method: 'sourcemap_surface',
      expectedRequestCost: 8,
      priority: 25,
      rationale: 'Unpack accessible .map sources into API/path seeds (discovery-only)',
      epistemicIntent: 'OBSERVED',
    });
  }

  if (input.stack.hasSupabase || input.stack.hasNextJs) {
    candidates.push({
      method: 'api_schema_discovery',
      expectedRequestCost: 6,
      priority: 30,
      rationale: 'OpenAPI/PostgREST schema seeds when Data API host in scope',
      epistemicIntent: 'OBSERVED',
    });
  }

  if (input.enableByotHarvest === true && input.stack.hasJwtIdentity === true) {
    candidates.push({
      method: 'byot_network_harvest',
      expectedRequestCost: 10,
      priority: 40,
      rationale: 'Authenticated XHR/RSC/Server Action metadata harvest (BYOT)',
      epistemicIntent: 'OBSERVED',
    });
  }

  if (input.enableGatedDicts === true) {
    candidates.push({
      method: 'gated_dict_topk',
      expectedRequestCost: 15,
      priority: 50,
      rationale: 'Ffuf/arjun on top-K inventory only (WAF-aware abort)',
      epistemicIntent: 'INFERRED',
    });
  }

  candidates.push({
    method: 'html_hop_extra',
    expectedRequestCost: 8,
    priority: 60,
    rationale: 'Optional extra HTML hop on app_endpoint only',
    epistemicIntent: 'OBSERVED',
  });

  candidates.sort((a, b) => a.priority - b.priority);

  const selected: DeepReconMethodPlanEntry[] = [];
  let used = 0;
  for (const c of candidates) {
    if (used + c.expectedRequestCost > remaining) continue;
    selected.push(c);
    used += c.expectedRequestCost;
  }
  return Object.freeze(selected);
}
