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

export type SpaRouteType = 'dom_link' | 'api_fetch' | 'form_action' | 'history_push';

export interface DiscoveredSpaRouteObservation {
  readonly url: string;
  readonly path: string;
  readonly method?: string;
  readonly routeType: SpaRouteType;
  readonly source: string;
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
}

export interface RouteInstance {
  request(): { url(): string; method(): string };
  abort(errorCode?: string): Promise<void>;
  continue(): Promise<void>;
}

export interface ResponseInstance {
  status(): number;
  url(): string;
}

export interface PageInstance {
  goto(url: string, options?: { waitUntil?: 'load' | 'domcontentloaded' | 'networkidle'; timeout?: number }): Promise<unknown>;
  route(urlPattern: string, handler: (route: RouteInstance) => Promise<void>): Promise<void>;
  on(event: 'response', handler: (response: ResponseInstance) => void): void;
  waitForLoadState(state?: 'load' | 'domcontentloaded' | 'networkidle', options?: { timeout?: number }): Promise<void>;
  waitForTimeout(ms: number): Promise<void>;
  evaluate<T>(fn: () => T | Promise<T>): Promise<T>;
  title(): Promise<string>;
  close(): Promise<void>;
}

export interface BrowserContextInstance {
  newPage(): Promise<PageInstance>;
  close(): Promise<void>;
}

export interface BrowserInstance {
  newContext(options?: Record<string, unknown>): Promise<BrowserContextInstance>;
  close(): Promise<void>;
}

export interface PlaywrightBrowserLauncher {
  launch(options?: { headless?: boolean; args?: readonly string[] }): Promise<BrowserInstance>;
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
