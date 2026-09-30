/**
 * F6.3 — metadata of bytes that were already downloaded.
 * No download here. Retention writes a bounded local file from those bytes.
 * The reader opens that file and emits strings present in it.
 */

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { isAbsolute, join } from 'node:path';
import { tryBuildObservedFact } from './ObservedFactCatalogService.js';
import type { AuthorizedExecutionLineageTuple } from '../detection/DetectionContracts.js';
import type { ObservedFact } from './ObservedFactContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import { isPathAllowedByScopeBoundaries } from '../scope/AuthorizedScopePolicyService.js';
import { isInternalOrSsrfTarget } from '../recon/policy/PassiveEgressPolicy.js';

const MAX_RETAINED_BYTES = 1_048_576;

export const MAX_RETAINED_DOCUMENT_BYTES = MAX_RETAINED_BYTES;

export function defaultDocumentCopyDirectory(): string {
  return join(tmpdir(), 'fixguard-document-copies');
}

export interface RetainedDocumentCopy {
  readonly url: string;
  readonly bytes: Uint8Array;
}

export function retainBoundedDocumentCopy(input: {
  readonly downloaded: boolean;
  readonly url: string;
  readonly bytes: Uint8Array | null;
}): RetainedDocumentCopy | null {
  if (!input.downloaded || !input.bytes || input.bytes.byteLength === 0) return null;
  const bounded =
    input.bytes.byteLength > MAX_RETAINED_BYTES
      ? input.bytes.slice(0, MAX_RETAINED_BYTES)
      : input.bytes;
  return { url: input.url, bytes: bounded };
}

export function readLocalDocumentMetadata(input: {
  readonly filePath: string;
  readonly sourceUrl: string;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly observedAt: string;
}): { readonly fact: ObservedFact | null } {
  const bytes = readFileSync(input.filePath);
  const text = bytes.toString('utf8');
  const parts: string[] = [];
  for (const match of text.matchAll(/(?:^|\n)\s*(Title|Author|Producer)\s*:\s*([^\r\n]+)/g)) {
    const key = match[1];
    const raw = match[2]?.trim() ?? '';
    if (!key || raw.length === 0 || !text.includes(raw)) continue;
    const line = `${key}: ${raw}`.replace(/[;\r\n]/g, '');
    if (!text.includes(line) && !text.includes(raw)) continue;
    parts.push(text.includes(line) ? line : raw);
  }
  if (parts.length === 0) return { fact: null };
  const value = parts.join(';');
  const fact = tryBuildObservedFact({
    factKind: 'observed_document_metadata',
    value,
    observationText: text,
    sourceUrl: input.sourceUrl,
    observationKind: 'document_bytes',
    lineage: input.lineage,
    observedAt: input.observedAt,
    sourceLabel: 'local_document',
  });
  return { fact };
}

export interface DownloadedDocumentRetention {
  readonly fact: ObservedFact | null;
  readonly filePath: string | null;
}

const DOCUMENT_TYPES = new Set([
  'application/pdf',
  'application/msword',
  'application/rtf',
  'application/vnd.ms-excel',
  'application/vnd.ms-powerpoint',
  'application/vnd.ms-word',
  'application/epub+zip',
]);

function none(): DownloadedDocumentRetention {
  return { fact: null, filePath: null };
}

function mediaType(contentType: string | undefined): string {
  if (!contentType) return '';
  const base = contentType.toLowerCase().split(';')[0]?.trim() ?? '';
  return base;
}

function isDocumentOrImageType(contentType: string | undefined): boolean {
  const ct = mediaType(contentType);
  if (ct.length === 0) return false;
  if (ct === 'text/html' || ct === 'application/xhtml+xml' || ct === 'image/svg+xml') return false;
  if (ct.startsWith('image/')) return true;
  if (DOCUMENT_TYPES.has(ct)) return true;
  if (ct.startsWith('application/vnd.openxmlformats-officedocument.')) return true;
  if (ct.startsWith('application/vnd.oasis.opendocument.')) return true;
  return false;
}

function prefixText(bytes: Uint8Array): string {
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes.subarray(0, 512)).trimStart().toLowerCase();
}

function isHtmlCookieOrSecretShell(bytes: Uint8Array): boolean {
  const sample = prefixText(bytes);
  if (
    sample.startsWith('<!doctype') ||
    sample.startsWith('<html') ||
    sample.startsWith('<head') ||
    sample.startsWith('<body')
  ) {
    return true;
  }
  if (sample.startsWith('set-cookie:') || sample.startsWith('cookie:')) return true;
  if (sample.startsWith('authorization:') || sample.startsWith('bearer ')) return true;
  if (sample.includes('begin private key')) return true;
  return false;
}

function urlInScope(url: string, grant: AuthorizedScopeGrant): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false;
  const host = parsed.hostname.toLowerCase().replace(/\.$/, '');
  if (host.length === 0 || isInternalOrSsrfTarget(host)) return false;
  if (!isPathAllowedByScopeBoundaries(parsed.pathname || '/', grant)) return false;
  const methods = grant.boundaries.allowedMethods;
  if (methods && methods.length > 0 && !methods.includes('GET')) return false;
  const origins = grant.boundaries.allowedOrigins ?? [];
  if (origins.length > 0) {
    return origins.some((origin) => {
      try {
        return new URL(origin).origin === parsed.origin;
      } catch {
        return false;
      }
    });
  }
  const hosts = (grant.boundaries.allowedHosts ?? []).map((item) => item.toLowerCase().replace(/\.$/, ''));
  if (hosts.length > 0) return hosts.includes(host);
  const domains = (grant.boundaries.allowedDomains ?? []).map((item) =>
    item.toLowerCase().replace(/\.$/, '')
  );
  if (domains.length > 0) {
    return domains.some((domain) => host === domain || host.endsWith(`.${domain}`));
  }
  const subjectHost = grant.subject.host?.toLowerCase().replace(/\.$/, '');
  const subjectDomain = grant.subject.domain?.toLowerCase().replace(/\.$/, '');
  if (grant.subject.targetKind === 'host' && subjectHost) return host === subjectHost;
  if (grant.subject.targetKind === 'domain' && subjectDomain) {
    return host === subjectDomain || host.endsWith(`.${subjectDomain}`);
  }
  if (grant.subject.targetKind === 'origin' && grant.subject.normalizedOrigin) {
    return parsed.origin === grant.subject.normalizedOrigin;
  }
  return false;
}

function assessmentDirectory(root: string, assessmentId: string): string | null {
  if (!isAbsolute(root) || root.includes('..')) return null;
  const safeId = assessmentId.replace(/[^A-Za-z0-9_-]/g, '');
  if (safeId.length === 0 || safeId.length > 128) return null;
  return join(root, safeId);
}

function fileNameFor(url: string): string {
  let hash = 2166136261;
  for (let i = 0; i < url.length; i += 1) {
    hash ^= url.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return `doc_${(hash >>> 0).toString(16).padStart(8, '0')}.bin`;
}

/**
 * Keep a bounded local copy of a document or image an in-scope GET already
 * downloaded, then read metadata from that file. No network.
 */
export function observeDownloadedDocument(input: {
  readonly downloaded: boolean;
  readonly url: string;
  readonly method?: string;
  readonly statusCode?: number;
  readonly contentType?: string;
  readonly body: Uint8Array | string | null;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly observedAt: string;
  readonly directory: string;
}): DownloadedDocumentRetention {
  if (!input.downloaded) return none();
  const method = (input.method ?? 'GET').toUpperCase();
  if (method !== 'GET') return none();
  if (input.body === null) return none();
  if (typeof input.statusCode === 'number' && (input.statusCode < 200 || input.statusCode >= 300)) {
    return none();
  }
  if (!isDocumentOrImageType(input.contentType)) return none();
  if (!urlInScope(input.url, input.scopeGrant)) return none();
  const bytes = typeof input.body === 'string' ? new TextEncoder().encode(input.body) : input.body;
  if (bytes.byteLength === 0 || isHtmlCookieOrSecretShell(bytes)) return none();
  const bounded = retainBoundedDocumentCopy({
    downloaded: true,
    url: input.url,
    bytes,
  });
  if (!bounded) return none();
  const dir = assessmentDirectory(input.directory, input.lineage.assessmentId);
  if (!dir) return none();
  const filePath = join(dir, fileNameFor(input.url));
  try {
    mkdirSync(dir, { recursive: true });
    writeFileSync(filePath, bounded.bytes);
  } catch {
    return none();
  }
  let fact: ObservedFact | null = null;
  try {
    fact = readLocalDocumentMetadata({
      filePath,
      sourceUrl: input.url,
      lineage: input.lineage,
      observedAt: input.observedAt,
    }).fact;
  } catch {
    fact = null;
  }
  return { fact, filePath };
}
