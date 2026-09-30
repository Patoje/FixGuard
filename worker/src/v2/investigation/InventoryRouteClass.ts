/**
 * Inventory URL classes for the read loop.
 * Screens are real app routes seen by HTML, Playwright, or RSC.
 * Noise and platform paths do not get a runnable attack plan.
 */

import {
  isPublicStaticAssetPath,
  isVercelSecurityChallengePath,
} from '../detection/PublicStaticAsset.js';

export type InventoryRouteClass = 'screen' | 'noise' | 'platform' | 'other';

const SCREEN_SOURCES = new Set([
  'html_link_extraction',
  'html_hop_extra',
  'playwright_spa',
  'playwright_network',
  'spa_network',
  'rsc_discovery',
  'spa_discovery',
]);

const JSLUICE_ONLY_SOURCES = new Set([
  'jsluice',
  'js_client_from_hint',
  'js_surface_mining',
]);

export interface InventoryRouteInput {
  readonly path: string;
  readonly sources: readonly string[];
}

function pathOnly(pathname: string): string {
  const raw = pathname.length > 0 ? pathname : '/';
  const cut = raw.split('?')[0] ?? raw;
  return cut.length > 0 ? cut : '/';
}

/** jsluice-only fragments such as /a/i, /b, /_tree, /_not-found. */
export function isJsluiceFragmentPath(pathname: string): boolean {
  const path = pathOnly(pathname);
  if (/^\/[a-z](?:\/[a-z])?$/.test(path)) return true;
  return /^\/_(?:tree|head|index|not-found|full)$/.test(path);
}

function hasScreenSource(sources: readonly string[]): boolean {
  return sources.some((source) => SCREEN_SOURCES.has(source));
}

function isJsluiceOnly(sources: readonly string[]): boolean {
  if (sources.length === 0) return false;
  return sources.every((source) => JSLUICE_ONLY_SOURCES.has(source));
}

export function classifyInventoryEntry(entry: InventoryRouteInput): InventoryRouteClass {
  const path = pathOnly(entry.path);
  if (isVercelSecurityChallengePath(path)) return 'platform';
  if (isPublicStaticAssetPath(path)) return 'other';
  const screen = hasScreenSource(entry.sources);
  if (isJsluiceFragmentPath(path) && !screen) return 'noise';
  if (isJsluiceOnly(entry.sources)) return 'noise';
  if (screen) return 'screen';
  return 'other';
}

export function inventoryHasScreen(
  entries: readonly InventoryRouteInput[]
): boolean {
  return entries.some((entry) => classifyInventoryEntry(entry) === 'screen');
}
