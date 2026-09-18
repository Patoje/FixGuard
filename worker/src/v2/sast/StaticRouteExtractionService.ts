/**
 * Milestone P6-3 — Static Route & Endpoint Extraction Engine (Phase 6 Finale)
 *
 * Core Invariant: Purely analytical local source code and routing structure
 * inspection. The engine statically parses routes, controllers, and hidden
 * endpoints across frameworks (Express, Next.js, FastAPI, Spring, Generic)
 * to enrich DAST assessment coverage with zero network overhead.
 *
 * Safety & Quality Guarantees:
 * - Operates entirely offline using local source file inspection.
 * - Exact key validation & continuous lineage tracking.
 * - HITL review routing via EvidenceDraftEnvelope.
 * - 0 occurrences of 'as any'.
 */

import type { Finding } from '../core/Evidence.js';
import type { EvidenceDraftEnvelope } from '../evidence-mapping/ComparisonEvidenceMappingContracts.js';

export type FrameworkType = 'express' | 'nextjs' | 'fastapi' | 'spring' | 'generic';

export interface SourceFilePayload {
  readonly filePath: string;
  readonly content: string;
  readonly frameworkHint?: FrameworkType;
}

export interface StaticRouteExtractionRequest {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly actorId: string;
  readonly targetDomain: string;
  readonly sourceFiles: readonly SourceFilePayload[];
  readonly humanReviewDecision?: {
    readonly decision: 'approve_evidence' | 'reject' | 'needs_more_review';
    readonly reviewerId: string;
    readonly reviewedAt: string;
  };
}

export interface ExtractedRoute {
  readonly frameworkType: FrameworkType;
  readonly sourceFilePath: string;
  readonly extractedRoutePattern: string;
  readonly supportedMethods: readonly string[];
  readonly isInternalOnly: boolean;
  readonly rawDeclarationSnippet: string;
}

export interface StaticRouteExtractionResult {
  readonly contractVersion: 'fixguard-detection-expansion/v0';
  readonly kind: 'static_route_extraction_result';
  readonly hasRoutes: boolean;
  readonly extractedRoutes: readonly ExtractedRoute[];
  readonly enrichedEndpointCandidates: readonly string[];
  readonly evidenceDrafts: readonly EvidenceDraftEnvelope[];
  readonly findings: readonly Finding[];
}

const INTERNAL_ROUTE_KEYWORDS = [
  'admin',
  'internal',
  'debug',
  'actuator',
  'private',
  'test',
  'metrics',
  'health',
  'swagger',
  'console',
  'dump',
  'backdoor',
];

export function isInternalRoute(routePath: string): boolean {
  const lower = routePath.toLowerCase();
  return INTERNAL_ROUTE_KEYWORDS.some((kw) => lower.includes(kw));
}

function normalizeRoutePath(path: string): string {
  let cleaned = path.trim();
  if (!cleaned.startsWith('/')) {
    cleaned = '/' + cleaned;
  }
  // Replace multiple slashes with single slash
  cleaned = cleaned.replace(/\/+/g, '/');
  // Strip trailing slash unless root
  if (cleaned.length > 1 && cleaned.endsWith('/')) {
    cleaned = cleaned.slice(0, -1);
  }
  return cleaned;
}

/**
 * Parses Express / NestJS router definitions.
 */
export function extractExpressRoutes(filePath: string, content: string): ExtractedRoute[] {
  const routes: ExtractedRoute[] = [];
  const lines = content.split(/\r?\n/);

  // app.get('/path', ...), router.post('/path', ...), etc.
  const expressRegex = /(?:app|router|server)\.(get|post|put|delete|patch|options|head|use|all)\s*\(\s*['"`]([^'"`]+)['"`]/gi;
  
  // NestJS @Get('/path'), @Post('/path'), @Delete('/path')
  const nestJsRegex = /@(Get|Post|Put|Delete|Patch|Options|Head)\s*\(\s*['"`]([^'"`]*)['"`]\s*\)/gi;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    let match: RegExpExecArray | null;

    expressRegex.lastIndex = 0;
    while ((match = expressRegex.exec(line)) !== null) {
      const method = match[1].toUpperCase();
      const rawPath = match[2];
      if (rawPath.startsWith('/') || rawPath.startsWith('api') || rawPath.includes('/')) {
        const normPath = normalizeRoutePath(rawPath);
        routes.push({
          frameworkType: 'express',
          sourceFilePath: filePath,
          extractedRoutePattern: normPath,
          supportedMethods: method === 'USE' || method === 'ALL' ? ['GET', 'POST', 'PUT', 'DELETE'] : [method],
          isInternalOnly: isInternalRoute(normPath),
          rawDeclarationSnippet: line.trim().slice(0, 128),
        });
      }
    }

    nestJsRegex.lastIndex = 0;
    while ((match = nestJsRegex.exec(line)) !== null) {
      const method = match[1].toUpperCase();
      const rawPath = match[2] || '/';
      const normPath = normalizeRoutePath(rawPath);
      routes.push({
        frameworkType: 'express',
        sourceFilePath: filePath,
        extractedRoutePattern: normPath,
        supportedMethods: [method],
        isInternalOnly: isInternalRoute(normPath),
        rawDeclarationSnippet: line.trim().slice(0, 128),
      });
    }
  }

  return routes;
}

/**
 * Parses Next.js App and Pages router paths.
 */
export function extractNextJsRoutes(filePath: string, content: string): ExtractedRoute[] {
  const routes: ExtractedRoute[] = [];
  const normalizedFile = filePath.replace(/\\/g, '/');

  // App router: app/api/users/route.ts -> /api/users
  const appApiMatch = normalizedFile.match(/(?:^|\/)app(\/api\/.*?)\/route\.[a-z]+/i);
  if (appApiMatch && appApiMatch[1]) {
    const routePattern = normalizeRoutePath(appApiMatch[1]);
    const methods: string[] = [];
    if (/export\s+async\s+function\s+GET/i.test(content) || /export\s+const\s+GET/i.test(content)) methods.push('GET');
    if (/export\s+async\s+function\s+POST/i.test(content) || /export\s+const\s+POST/i.test(content)) methods.push('POST');
    if (/export\s+async\s+function\s+PUT/i.test(content) || /export\s+const\s+PUT/i.test(content)) methods.push('PUT');
    if (/export\s+async\s+function\s+DELETE/i.test(content) || /export\s+const\s+DELETE/i.test(content)) methods.push('DELETE');
    if (/export\s+async\s+function\s+PATCH/i.test(content) || /export\s+const\s+PATCH/i.test(content)) methods.push('PATCH');

    routes.push({
      frameworkType: 'nextjs',
      sourceFilePath: filePath,
      extractedRoutePattern: routePattern,
      supportedMethods: methods.length > 0 ? methods : ['GET', 'POST'],
      isInternalOnly: isInternalRoute(routePattern),
      rawDeclarationSnippet: `Next.js App Route: ${filePath}`,
    });
  }

  // Pages router: pages/api/v1/checkout.ts -> /api/v1/checkout
  const pagesApiMatch = normalizedFile.match(/(?:^|\/)pages(\/api\/.*?)\.[a-z]+/i);
  if (pagesApiMatch && pagesApiMatch[1]) {
    const routePattern = normalizeRoutePath(pagesApiMatch[1].replace(/\/index$/, ''));
    routes.push({
      frameworkType: 'nextjs',
      sourceFilePath: filePath,
      extractedRoutePattern: routePattern,
      supportedMethods: ['GET', 'POST'],
      isInternalOnly: isInternalRoute(routePattern),
      rawDeclarationSnippet: `Next.js Pages Route: ${filePath}`,
    });
  }

  return routes;
}

/**
 * Parses Python FastAPI / Flask route definitions.
 */
export function extractFastApiRoutes(filePath: string, content: string): ExtractedRoute[] {
  const routes: ExtractedRoute[] = [];
  const lines = content.split(/\r?\n/);
  const pyRegex = /@(app|router|api_router)\.(get|post|put|delete|patch|options|head|api_route)\s*\(\s*['"]([^'"]+)['"]/gi;

  for (const line of lines) {
    let match: RegExpExecArray | null;
    pyRegex.lastIndex = 0;
    while ((match = pyRegex.exec(line)) !== null) {
      const method = match[2].toUpperCase();
      const rawPath = match[3];
      const normPath = normalizeRoutePath(rawPath);
      routes.push({
        frameworkType: 'fastapi',
        sourceFilePath: filePath,
        extractedRoutePattern: normPath,
        supportedMethods: method === 'API_ROUTE' ? ['GET', 'POST'] : [method],
        isInternalOnly: isInternalRoute(normPath),
        rawDeclarationSnippet: line.trim().slice(0, 128),
      });
    }
  }

  return routes;
}

/**
 * Parses Java Spring Boot @GetMapping / @PostMapping / @RequestMapping annotations.
 */
export function extractSpringRoutes(filePath: string, content: string): ExtractedRoute[] {
  const routes: ExtractedRoute[] = [];
  const lines = content.split(/\r?\n/);
  const springRegex = /@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\s*\(\s*(?:value\s*=\s*)?['"]([^'"]+)['"]/gi;

  for (const line of lines) {
    let match: RegExpExecArray | null;
    springRegex.lastIndex = 0;
    while ((match = springRegex.exec(line)) !== null) {
      const annot = match[1].toLowerCase();
      let method = 'GET';
      if (annot.includes('post')) method = 'POST';
      else if (annot.includes('put')) method = 'PUT';
      else if (annot.includes('delete')) method = 'DELETE';
      else if (annot.includes('patch')) method = 'PATCH';
      else if (annot.includes('request')) method = 'ALL';

      const rawPath = match[2];
      const normPath = normalizeRoutePath(rawPath);
      routes.push({
        frameworkType: 'spring',
        sourceFilePath: filePath,
        extractedRoutePattern: normPath,
        supportedMethods: method === 'ALL' ? ['GET', 'POST', 'PUT', 'DELETE'] : [method],
        isInternalOnly: isInternalRoute(normPath),
        rawDeclarationSnippet: line.trim().slice(0, 128),
      });
    }
  }

  return routes;
}

/**
 * Extract static routes from a single file across supported frameworks.
 */
export function extractRoutesFromFile(file: SourceFilePayload): ExtractedRoute[] {
  const { filePath, content, frameworkHint } = file;
  const results: ExtractedRoute[] = [];

  if (frameworkHint === 'nextjs' || filePath.includes('app/api') || filePath.includes('pages/api')) {
    results.push(...extractNextJsRoutes(filePath, content));
  }
  if (frameworkHint === 'fastapi' || filePath.endsWith('.py')) {
    results.push(...extractFastApiRoutes(filePath, content));
  }
  if (frameworkHint === 'spring' || filePath.endsWith('.java') || filePath.endsWith('.kt')) {
    results.push(...extractSpringRoutes(filePath, content));
  }
  if (frameworkHint === 'express' || filePath.endsWith('.ts') || filePath.endsWith('.js')) {
    results.push(...extractExpressRoutes(filePath, content));
  }

  // Generic fallback if empty and looks like code
  if (results.length === 0) {
    const genericMatches = content.match(/['"`](\/api\/[a-zA-Z0-9_\-\/]+)['"`]/g);
    if (genericMatches) {
      for (const m of genericMatches) {
        const raw = m.replace(/['"`]/g, '');
        const norm = normalizeRoutePath(raw);
        results.push({
          frameworkType: 'generic',
          sourceFilePath: filePath,
          extractedRoutePattern: norm,
          supportedMethods: ['GET'],
          isInternalOnly: isInternalRoute(norm),
          rawDeclarationSnippet: `Generic match: ${norm}`,
        });
      }
    }
  }

  // Deduplicate by route pattern and methods within same file
  const uniqueMap = new Map<string, ExtractedRoute>();
  for (const r of results) {
    const key = `${r.extractedRoutePattern}::${r.supportedMethods.join(',')}`;
    if (!uniqueMap.has(key)) {
      uniqueMap.set(key, r);
    }
  }

  return Array.from(uniqueMap.values());
}

/**
 * Analytical static route extraction service.
 */
export function scanFilesForStaticRoutes(request: StaticRouteExtractionRequest): StaticRouteExtractionResult {
  const { assessmentId, scanId, actorId, targetDomain, sourceFiles } = request;
  const allRoutes: ExtractedRoute[] = [];

  for (const file of sourceFiles) {
    const extracted = extractRoutesFromFile(file);
    allRoutes.push(...extracted);
  }

  // Deduplicate across files
  const deduplicatedRoutes: ExtractedRoute[] = [];
  const seenPatterns = new Set<string>();
  for (const r of allRoutes) {
    const key = `${r.extractedRoutePattern}::${[...r.supportedMethods].sort().join(',')}`;
    if (!seenPatterns.has(key)) {
      seenPatterns.add(key);
      deduplicatedRoutes.push(r);
    }
  }

  if (deduplicatedRoutes.length === 0) {
    return {
      contractVersion: 'fixguard-detection-expansion/v0',
      kind: 'static_route_extraction_result',
      hasRoutes: false,
      extractedRoutes: [],
      enrichedEndpointCandidates: [],
      evidenceDrafts: [],
      findings: [],
    };
  }

  const enrichedEndpointCandidates = deduplicatedRoutes.map((r) => r.extractedRoutePattern);
  const evidenceDrafts: EvidenceDraftEnvelope[] = [];
  const findings: Finding[] = [];

  for (let i = 0; i < deduplicatedRoutes.length; i++) {
    const r = deduplicatedRoutes[i];
    const safePath = r.extractedRoutePattern.replace(/[^a-zA-Z0-9]/g, '').toLowerCase().slice(0, 10);
    const safeSeed = `${assessmentId.replace(/[^a-zA-Z0-9]/g, '').toLowerCase().slice(0, 6)}_${safePath}_${i}`;
    const draftId = `dft_stroute_${safeSeed}`;
    const candidateId = `cnd_stroute_${safeSeed}`;
    const evidenceRecordId = `evd_stroute_${safeSeed}`;
    const findingId = `fnd_stroute_${safeSeed}`;

    const internalBadge = r.isInternalOnly ? ' (Internal/Privileged Endpoint)' : '';
    const title = `Static Route Discovered: ${r.extractedRoutePattern} [${r.supportedMethods.join(', ')}]${internalBadge}`;
    const rationale = `Static code analysis extracted route pattern '${r.extractedRoutePattern}' (${r.frameworkType}) from ${r.sourceFilePath}. Supported verbs: ${r.supportedMethods.join(', ')}. Internal status: ${r.isInternalOnly}.`;

    if (request.humanReviewDecision?.decision === 'approve_evidence') {
      const nowIso = new Date().toISOString();
      const finding: Finding = {
        id: findingId,
        type: 'SECURITY_MISCONFIGURATION',
        severity: r.isInternalOnly ? 'medium' : 'low',
        title: `Approved Discovered Static Route: ${r.extractedRoutePattern}`,
        description: `Human operator verified statically extracted route ${r.extractedRoutePattern} from ${r.sourceFilePath} (${r.frameworkType}). Supported verbs: ${r.supportedMethods.join(', ')}.`,
        target: `https://${targetDomain}${r.extractedRoutePattern}`,
        evidence: JSON.stringify({
          assessmentId,
          scanId,
          frameworkType: r.frameworkType,
          sourceFilePath: r.sourceFilePath,
          extractedRoutePattern: r.extractedRoutePattern,
          supportedMethods: r.supportedMethods,
          isInternalOnly: r.isInternalOnly,
          rawDeclarationSnippet: r.rawDeclarationSnippet,
          reviewedBy: request.actorId,
          reviewedAt: nowIso,
        }),
        confidence: 1.0,
        metadata: {
          kind: 'static_route_extraction_metadata',
          category: 'SECURITY_MISCONFIGURATION',
          frameworkType: r.frameworkType,
          sourceFilePath: r.sourceFilePath,
          extractedRoutePattern: r.extractedRoutePattern,
          supportedMethods: r.supportedMethods,
          isInternalOnly: r.isInternalOnly,
          observedAt: nowIso,
          candidateId,
          evidenceRecordId,
          lineage: `${assessmentId}:${scanId}:${actorId}:${nowIso}`,
        },
      };
      findings.push(finding);
    } else {
      const draft: EvidenceDraftEnvelope = {
        draftKind: 'non_persisted_comparison_evidence_draft',
        draftId,
        suggestedEvidenceType: 'http_difference',
        suggestedStrength: 'strong',
        sourceComparisonId: `cmp_stroute_${safeSeed}`,
        sourceSnapshotIds: {
          baselineSnapshotId: `snp_base_${safePath}`,
          validationSnapshotId: `snp_val_${safePath}`,
        },
        requiresHumanReview: true,
        notPersisted: true,
        notARealFinding: true,
        notConfirmedEvidence: true,
        notForExternalDelivery: true,
        notM45EvidenceRecord: true,
        safeRationale: rationale,
      };
      evidenceDrafts.push(draft);
    }
  }

  return {
    contractVersion: 'fixguard-detection-expansion/v0',
    kind: 'static_route_extraction_result',
    hasRoutes: true,
    extractedRoutes: deduplicatedRoutes,
    enrichedEndpointCandidates,
    evidenceDrafts,
    findings,
  };
}
