/**
 * F4.0 — counts automatic invocations of surface detectors.
 * The assessment pipeline must not call them. Authorized execute may.
 */

export const DEFERRED_SURFACE_PROBE_KINDS = Object.freeze([
  'cors_misconfiguration',
  'security_header',
  'open_redirect',
  'information_disclosure',
  'subdomain_takeover',
  'graphql_surface',
  'session_fixation',
] as const);

export type DeferredSurfaceProbeKind = (typeof DEFERRED_SURFACE_PROBE_KINDS)[number];

const counts: Record<DeferredSurfaceProbeKind, number> = {
  cors_misconfiguration: 0,
  security_header: 0,
  open_redirect: 0,
  information_disclosure: 0,
  subdomain_takeover: 0,
  graphql_surface: 0,
  session_fixation: 0,
};

export function noteDeferredSurfaceProbeInvoked(kind: DeferredSurfaceProbeKind): void {
  counts[kind] += 1;
}

export function deferredSurfaceProbeInvocationCount(kind: DeferredSurfaceProbeKind): number {
  return counts[kind];
}

export function resetDeferredSurfaceProbeLedger(): void {
  for (const kind of DEFERRED_SURFACE_PROBE_KINDS) {
    counts[kind] = 0;
  }
}
