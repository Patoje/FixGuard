/**
 * Facts taken from bytes already captured. No new network.
 */

import type { AuthorizedExecutionLineageTuple } from '../detection/DetectionContracts.js';
import type { DetectedTechnology } from '../core/TechnologyContracts.js';
import type { DiscoveredHostRecord, ExternalDependency } from '../intelligence/IntelligenceContracts.js';
import { extractCookieFlagRecords, extractNextBuildId, headerValue } from '../intelligence/CapturedHostIdentity.js';
import { tryBuildObservedFact } from './ObservedFactCatalogService.js';
import type { ObservedFact } from './ObservedFactContracts.js';
import { extractHtmlDocumentFields } from '../recon/analysis/HtmlRouteExtractionService.js';

export interface CapturedWebSlice {
  readonly url: string;
  readonly bodyText?: string;
  readonly headers?: Readonly<Record<string, string | string[] | undefined>>;
}

export interface CapturedDnsSlice {
  readonly domain: string;
  readonly asn?: string;
  readonly cdn?: string;
}

export interface CapturedTlsSlice {
  readonly host: string;
  readonly subjectAlternativeNames?: readonly string[];
}

export function factsFromCapturedRecon(input: {
  readonly webs: readonly CapturedWebSlice[];
  readonly dns: readonly CapturedDnsSlice[];
  readonly tls: readonly CapturedTlsSlice[];
  readonly externalDependencies: readonly ExternalDependency[];
  readonly technologies: readonly DetectedTechnology[];
  readonly sourcemapTexts?: readonly string[];
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly observedAt: string;
}): readonly ObservedFact[] {
  const facts: ObservedFact[] = [];
  const seen = new Set<string>();
  const add = (fact: ObservedFact | null): void => {
    if (!fact || seen.has(fact.factId)) return;
    seen.add(fact.factId);
    facts.push(fact);
  };

  for (const web of input.webs) {
    const body = web.bodyText ?? '';
    const buildId = extractNextBuildId(body);
    if (buildId) {
      add(tryBuildObservedFact({
        factKind: 'observed_build_id',
        value: buildId,
        observationText: body,
        sourceUrl: web.url,
        observationKind: 'http_body',
        lineage: input.lineage,
        observedAt: input.observedAt,
        sourceLabel: 'next_build_id',
      }));
    }
    const setCookie = headerValue(web.headers, 'set-cookie') ?? '';
    if (setCookie.length > 0 && setCookie !== '[REDACTED]') {
      for (const cookie of extractCookieFlagRecords(setCookie)) {
        add(tryBuildObservedFact({
          factKind: 'observed_cookie_flags',
          value: cookie.factValue,
          observationText: setCookie,
          sourceUrl: web.url,
          observationKind: 'http_header',
          lineage: input.lineage,
          observedAt: input.observedAt,
          sourceLabel: 'set_cookie',
        }));
      }
    }
    const powered = headerValue(web.headers, 'x-powered-by') ?? '';
    for (const tech of input.technologies) {
      if (!tech.version) continue;
      if (tech.name !== 'Next.js' && tech.name !== 'React') continue;
      const candidates = [`${tech.name} ${tech.version}`, `${tech.name} v${tech.version}`];
      const source = [body, powered, ...(input.sourcemapTexts ?? [])].find((text) =>
        candidates.some((literal) => text.includes(literal))
      );
      const literal = source ? candidates.find((item) => source.includes(item)) : undefined;
      if (!source || !literal) continue;
      add(tryBuildObservedFact({
        factKind: 'observed_tech_version',
        value: literal,
        observationText: source,
        sourceUrl: web.url,
        observationKind: source === powered ? 'http_header' : 'http_body',
        lineage: input.lineage,
        observedAt: input.observedAt,
        sourceLabel: 'tech_version',
      }));
    }
    const htmlFields = extractHtmlDocumentFields(body);
    for (const field of htmlFields.inputs) {
      add(tryBuildObservedFact({
        factKind: 'observed_html_field',
        value: `action=${field.action};method=${field.method};name=${field.name};type=${field.type}`,
        observationText: body,
        sourceUrl: web.url,
        observationKind: 'http_body',
        lineage: input.lineage,
        observedAt: input.observedAt,
        sourceLabel: 'html_document',
      }));
    }
    for (const comment of htmlFields.comments) {
      add(tryBuildObservedFact({
        factKind: 'observed_html_field',
        value: `comment=${comment}`,
        observationText: body,
        sourceUrl: web.url,
        observationKind: 'http_body',
        lineage: input.lineage,
        observedAt: input.observedAt,
        sourceLabel: 'html_document',
      }));
    }
    let jsFacts = 0;
    for (const match of body.matchAll(/(?:src|href)=["']https?:\/\/([a-z0-9.-]+\.[a-z]{2,})/gi)) {
      if (jsFacts >= 20) break;
      const host = (match[1] ?? '').toLowerCase();
      if (!host || !body.toLowerCase().includes(host)) continue;
      jsFacts += 1;
      add(tryBuildObservedFact({
        factKind: 'observed_related_host',
        value: host,
        observationText: body,
        sourceUrl: web.url,
        observationKind: 'http_body',
        lineage: input.lineage,
        observedAt: input.observedAt,
        sourceLabel: 'js',
      }));
    }
  }

  for (const dns of input.dns) {
    if (dns.asn) {
      add(tryBuildObservedFact({
        factKind: 'observed_asn',
        value: dns.asn,
        observationText: `${dns.domain} ${dns.asn}`,
        sourceUrl: `dns://${dns.domain}`,
        observationKind: 'dns_json',
        lineage: input.lineage,
        observedAt: input.observedAt,
        sourceLabel: 'dnsx',
      }));
    }
    if (dns.cdn) {
      add(tryBuildObservedFact({
        factKind: 'observed_cdn',
        value: dns.cdn,
        observationText: `${dns.domain} ${dns.cdn}`,
        sourceUrl: `dns://${dns.domain}`,
        observationKind: 'dns_json',
        lineage: input.lineage,
        observedAt: input.observedAt,
        sourceLabel: 'dnsx',
      }));
    }
  }

  for (const tls of input.tls) {
    const names = (tls.subjectAlternativeNames ?? []).join(' ');
    for (const name of tls.subjectAlternativeNames ?? []) {
      const host = name.toLowerCase().replace(/^\*\./, '');
      if (!names.toLowerCase().includes(host)) continue;
      add(tryBuildObservedFact({
        factKind: 'observed_related_host',
        value: host,
        observationText: names,
        sourceUrl: `tls://${tls.host}`,
        observationKind: 'tls_certificate',
        lineage: input.lineage,
        observedAt: input.observedAt,
        sourceLabel: 'tls_san',
      }));
    }
  }

  for (const dep of input.externalDependencies) {
    if (!dep.kind.startsWith('csp_')) continue;
    const host = dep.value.toLowerCase();
    if (!dep.value.toLowerCase().includes(host)) continue;
    add(tryBuildObservedFact({
      factKind: 'observed_related_host',
      value: host,
      observationText: dep.value,
      sourceUrl: `csp://${dep.sourceHost ?? 'captured'}`,
      observationKind: 'http_header',
      lineage: input.lineage,
      observedAt: input.observedAt,
      sourceLabel: 'csp',
    }));
  }

  return Object.freeze(facts);
}

export function wafIdentityForHost(
  hosts: readonly DiscoveredHostRecord[],
  targetHost: string
): string | null {
  const match = hosts.find((host) => host.fqdn.toLowerCase() === targetHost.toLowerCase());
  return match?.wafIdentity ?? null;
}
