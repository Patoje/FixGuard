/**
 * Milestone 7 — Browser Automation Engine for SPA & DOM Discovery Contracts
 * Contract version: fixguard-browser-automation/v0
 *
 * Defines contracts, observation types, request/result interfaces, and launcher abstractions
 * for headless browser crawling, JS hydration, DOM-based parameter extraction, and route discovery.
 */

import type { VerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../../lineage/AuthorizedExecutionLineageContracts.js';
import type { TargetExecutionCoordinator } from '../../runtime/TargetExecutionCoordinator.js';
import type { PreSpawnDnsResolver } from './AdapterPreflightPipeline.js';

export type BrowserAutomationContractVersion = 'fixguard-browser-automation/v0';
export const BROWSER_AUTOMATION_CONTRACT_VERSION: BrowserAutomationContractVersion =
  'fixguard-browser-automation/v0';

/** Provenance for DOM/form routes mined after Playwright hydration (OBSERVED). */
export const PLAYWRIGHT_SPA_SOURCE = 'playwright_spa' as const;
/** Provenance for Next.js / RSC signals mined from hydrated page state (OBSERVED). */
export const RSC_DISCOVERY_SOURCE = 'rsc_discovery' as const;
/** Provenance for in-scope XHR/fetch URLs captured during Playwright render (OBSERVED). */
export const PLAYWRIGHT_NETWORK_SOURCE = 'playwright_network' as const;
/** Alternate provenance label for SPA network mining (OBSERVED). */
export const SPA_NETWORK_SOURCE = 'spa_network' as const;

/** Hard cap: pages rendered per recon stage (seeds + app endpoints). */
export const SPA_DISCOVERY_MAX_PAGES = 5;
/** Hard cap: accepted in-scope routes retained per rendered page. */
export const SPA_DISCOVERY_MAX_ROUTES_PER_PAGE = 40;
/** Hard cap: accepted in-scope network (XHR/fetch) URLs retained per rendered page. */
export const SPA_DISCOVERY_MAX_NETWORK_URLS_PER_PAGE = 40;
/** Default navigation + hydration timeout. */
export const SPA_DISCOVERY_DEFAULT_TIMEOUT_MS = 15_000;
/** Default post-domcontentloaded hydration settle wait (capped by MAX). */
export const SPA_DISCOVERY_DEFAULT_HYDRATION_WAIT_MS = 2_000;
/** Hard cap on explicit waitForHydrationMs. */
export const SPA_DISCOVERY_MAX_HYDRATION_WAIT_MS = 5_000;
/** Soft networkidle settle after hydration wait (best-effort, capped). */
export const SPA_DISCOVERY_NETWORKIDLE_WAIT_MS = 2_000;

export type BrowserUnavailableReasonCode = 'browser_unavailable';

export interface BrowserAutomationExplicitNonClaims {
  readonly createsRealFindings: false;
  readonly createsPersistedEvidence: false;
  readonly confirmsVulnerabilities: false;
  readonly makesRiskClaims: false;
  readonly makesSeverityClaims: false;
  readonly makesImpactClaims: false;
  readonly executesNetworkPayloads: false;
  readonly severity: 'info';
}

export const BROWSER_AUTOMATION_NON_CLAIMS: BrowserAutomationExplicitNonClaims = Object.freeze({
  createsRealFindings: false,
  createsPersistedEvidence: false,
  confirmsVulnerabilities: false,
  makesRiskClaims: false,
  makesSeverityClaims: false,
  makesImpactClaims: false,
  executesNetworkPayloads: false,
  severity: 'info',
});

export type SpaRouteType = 'dom_link' | 'api_fetch' | 'form_action' | 'history_push' | 'rsc_hint';

export type SpaRouteDiscoverySource =
  | typeof PLAYWRIGHT_SPA_SOURCE
  | typeof RSC_DISCOVERY_SOURCE
  | typeof PLAYWRIGHT_NETWORK_SOURCE
  | typeof SPA_NETWORK_SOURCE
  | string;

export interface DiscoveredSpaRouteObservation {
  readonly url: string;
  readonly path: string;
  readonly method?: string;
  readonly routeType: SpaRouteType;
  readonly source: SpaRouteDiscoverySource;
  readonly discoveredAt: string;
}

export interface DiscoveredDomInputObservation {
  readonly formAction?: string;
  readonly inputName: string;
  readonly inputType: string;
  readonly method?: string;
  readonly discoveredAt: string;
}

export interface DiscoveredSpaObservation {
  readonly url: string;
  readonly targetHost: string;
  readonly pageTitle?: string;
  readonly frameworks: readonly string[];
  readonly routes: readonly DiscoveredSpaRouteObservation[];
  readonly inputs: readonly DiscoveredDomInputObservation[];
  readonly technologies: readonly string[];
  readonly discoveredAt: string;
  readonly collectedAt?: string;
  readonly freshness?: 'live' | 'historical' | 'unknown';
  readonly sourceReliability?: 'direct_observation' | 'historical_archive' | 'inferred_relationship';
}

/** Minimal shape of the response `RouteInstance.fetch()` returns, round-tripped opaquely to `fulfill()`. */
export interface RouteFetchResponse {
  status(): number;
  headers(): Record<string, string>;
}

export interface RouteInstance {
  request(): {
    url(): string;
    method(): string;
    resourceType(): string;
    /** Optional; the request's own headers before any override. */
    headers?(): Record<string, string>;
  };
  abort(errorCode?: string): Promise<void>;
  /** `headers`, when given, replaces the request's outgoing headers entirely. */
  continue(options?: { headers?: Record<string, string> }): Promise<void>;
  /**
   * Performs the request without fulfilling it, so the response can be
   * inspected before deciding whether to serve it. `maxRedirects: 0`
   * returns the hop's own response (e.g. a bare 3xx) without following it.
   *
   * Verified directly (not assumed, not from documentation alone) against
   * a real two-origin redirect: the route handler fires exactly once per
   * intercepted request — fulfilling a 3xx response does NOT give this
   * handler a second interception opportunity for the hop the browser
   * then auto-navigates to. `continue({headers})`'s header override is
   * never carried into that auto-navigation either (it is scoped to the
   * one request `fetch()`/`continue()` issues), but the caller must not
   * rely on the handler re-firing to re-validate a later hop's origin —
   * callers that need every hop of a redirect chain credential-checked
   * must loop `fetch({url, method, maxRedirects: 0})` themselves and never
   * `fulfill()` an in-flight credentialed hop back to the browser.
   */
  fetch(options?: {
    url?: string;
    method?: string;
    headers?: Record<string, string>;
    maxRedirects?: number;
  }): Promise<RouteFetchResponse>;
  /** Serves a previously-fetched response (from `fetch()`) to the page. */
  fulfill(options: { response: RouteFetchResponse }): Promise<void>;
}

export interface ResponseInstance {
  status(): number;
  url(): string;
}

/**
 * Subset of Playwright Request used for network mining.
 * Default miners retain URL/method/type only (never Authorization/Cookie bodies).
 * Optional `headerValue` exists solely so authenticated harvest can OBSERVE
 * `Next-Action` ids without retaining other header values.
 */
export interface NetworkRequestInstance {
  url(): string;
  method(): string;
  resourceType(): string;
  /** Optional; read a single request header by name (case-insensitive). */
  headerValue?(name: string): string | undefined;
}

export interface PageInstance {
  goto(url: string, options?: { waitUntil?: 'load' | 'domcontentloaded' | 'networkidle'; timeout?: number }): Promise<unknown>;
  route(urlPattern: string, handler: (route: RouteInstance) => Promise<void>): Promise<void>;
  on(event: 'response', handler: (response: ResponseInstance) => void): void;
  on(event: 'request', handler: (request: NetworkRequestInstance) => void): void;
  waitForLoadState(state?: 'load' | 'domcontentloaded' | 'networkidle', options?: { timeout?: number }): Promise<void>;
  waitForTimeout(ms: number): Promise<void>;
  evaluate<T>(fn: () => T | Promise<T>): Promise<T>;
  title(): Promise<string>;
  close(): Promise<void>;
}

export interface BrowserProxyConfig {
  readonly server: string;
  readonly username?: string;
  readonly password?: string;
  readonly bypass?: string;
}

export interface BrowserCookieRecord {
  readonly name: string;
  readonly value: string;
  readonly domain?: string;
  readonly path?: string;
  readonly expires?: number;
  readonly httpOnly?: boolean;
  readonly secure?: boolean;
  readonly sameSite?: 'Strict' | 'Lax' | 'None';
}

export interface BrowserContextInstance {
  newPage(): Promise<PageInstance>;
  addInitScript?(script: string | { content?: string; path?: string }): Promise<void>;
  cookies?(urls?: string | readonly string[]): Promise<readonly BrowserCookieRecord[]>;
  /** Populates the browser's own cookie jar — scoped by domain/path/secure like a real browser. */
  addCookies?(cookies: readonly BrowserCookieRecord[]): Promise<void>;
  close(): Promise<void>;
}

export interface BrowserInstance {
  newContext(options?: Record<string, unknown>): Promise<BrowserContextInstance>;
  close(): Promise<void>;
  disconnect?(): Promise<void>;
}

export interface PlaywrightBrowserLauncher {
  launch(options?: {
    headless?: boolean;
    args?: readonly string[];
    proxy?: BrowserProxyConfig;
  }): Promise<BrowserInstance>;
  connectOverCDP?(endpointUrl: string): Promise<BrowserInstance>;
}

export interface BrowserAutomationRequest {
  readonly targetUrlOrDomain: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly authorizedScopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly coordinator?: TargetExecutionCoordinator;
  readonly browserLauncher?: PlaywrightBrowserLauncher;
  readonly dnsResolver?: PreSpawnDnsResolver;
  readonly timeoutMs?: number;
  readonly waitForHydrationMs?: number;
  /** Soft cap on accepted in-scope routes for this page (default SPA_DISCOVERY_MAX_ROUTES_PER_PAGE). */
  readonly maxRoutes?: number;
  /** Optional proxy configuration (must not target loopback/RFC1918/cloud-metadata). */
  readonly proxyConfig?: BrowserProxyConfig;
  /** Explicit opt-out for stealth evasions (default: false, stealth is enabled). */
  readonly disableStealth?: boolean;
  /** Optional profile identifier (e.g. 'macos-chrome-131', 'windows-chrome-131'). */
  readonly browserProfileId?: string;
  /** Optional Chrome DevTools Protocol endpoint (e.g. 'http://127.0.0.1:9222') for HITL sessions. */
  readonly cdpEndpoint?: string;
  /**
   * Scoped session credentials (e.g. from a resolved challenge, or a BYOT
   * identity) so SPA/JS route discovery resumes with the same session
   * continuity the HTTP crawl loop already gets — WITHOUT ever sending
   * them to a third-party origin the page happens to load a subresource
   * from. `origin` is the exact scheme+host+port the credentials are
   * valid for (never trusted blindly — discoverSpa() cross-checks it
   * against the preflighted target host before using either field).
   *
   * `cookies` is injected via the browser's own cookie jar
   * (BrowserContextInstance.addCookies()), host-scoped to `origin`'s
   * hostname — the same mechanism a real browser uses, so the browser
   * itself (not application code) decides per request, including every
   * redirect hop, whether a given destination gets the cookie.
   *
   * `headers` (e.g. Authorization, or a BYOT-injected custom header) has
   * no such browser-native scoping mechanism, so it is never placed on
   * the context (Playwright's extraHTTPHeaders apply unconditionally to
   * every request, including allowed third-party CDN subresource loads —
   * that was the exact cross-origin leak this contract replaced). Instead
   * it is attached per request, inside the existing Gate 2 route handler,
   * only when that specific request's origin is an exact match for
   * `origin` — re-evaluated on every request, including each hop of a
   * redirect chain.
   */
  readonly sessionCredentials?: {
    readonly origin: string;
    readonly cookies?: Readonly<Record<string, string>>;
    readonly headers?: Readonly<Record<string, string>>;
  };
}

export type BrowserAutomationResult =
  | {
      readonly status: 'success';
      readonly contractVersion: BrowserAutomationContractVersion;
      readonly targetUrlOrDomain: string;
      readonly targetHost: string;
      readonly observations: readonly DiscoveredSpaObservation[];
      readonly routes: readonly DiscoveredSpaRouteObservation[];
      readonly inputs: readonly DiscoveredDomInputObservation[];
      readonly explicitNonClaims: BrowserAutomationExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
      readonly durationMs: number;
    }
  | {
      readonly status: 'circuit_broken';
      readonly contractVersion: BrowserAutomationContractVersion;
      readonly targetUrlOrDomain: string;
      readonly targetHost: string;
      readonly reasonCode: 'target_instability_circuit_open';
      readonly reason: string;
      readonly observations: readonly DiscoveredSpaObservation[];
      readonly routes: readonly DiscoveredSpaRouteObservation[];
      readonly inputs: readonly DiscoveredDomInputObservation[];
      readonly explicitNonClaims: BrowserAutomationExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
      readonly durationMs: number;
    }
  | {
      readonly status: 'preflight_denied';
      readonly contractVersion: BrowserAutomationContractVersion;
      readonly targetUrlOrDomain: string;
      readonly reasonCode: string;
      readonly reason: string;
      readonly explicitNonClaims: BrowserAutomationExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
      readonly durationMs: number;
    }
  | {
      readonly status: 'execution_failed';
      readonly contractVersion: BrowserAutomationContractVersion;
      readonly targetUrlOrDomain: string;
      readonly targetHost: string;
      readonly reasonCode: string;
      readonly reason: string;
      readonly explicitNonClaims: BrowserAutomationExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
      readonly durationMs: number;
    };

export interface BrowserAutomationTool {
  discoverSpa(request: BrowserAutomationRequest): Promise<BrowserAutomationResult>;
}
