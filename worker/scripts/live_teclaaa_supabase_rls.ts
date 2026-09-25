/**
 * Live Teclaaa assessment — Supabase RLS world-readable path (Phase B).
 * Extracts OBSERVED sb_publishable key from live JS at runtime — never commits secrets.
 */

import dns from 'node:dns/promises';
import { writeFileSync } from 'node:fs';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createV2App, DEFAULT_V2_HOST } from '../src/v2/api/createV2App.js';
import { V2CompositionRoot } from '../src/v2/api/V2CompositionRoot.js';
import { OrchestratedAssessmentApplicationService } from '../src/v2/application/OrchestratedAssessmentApplicationService.js';
import { InMemoryOrchestratedAssessmentRepository } from '../src/v2/storage/InMemoryOrchestratedAssessmentRepository.js';
import { ReconToolAvailabilityService } from '../src/v2/capabilities/ReconToolAvailabilityService.js';
import { InMemoryAttackPlanRepository } from '../src/v2/attack-planning/InMemoryAttackPlanRepository.js';
import { AttackPlanGeneratorService } from '../src/v2/attack-planning/AttackPlanGeneratorService.js';
import { InMemoryAttackChainRepository } from '../src/v2/attack-chain/InMemoryAttackChainRepository.js';
import { AttackChainService } from '../src/v2/attack-chain/AttackChainService.js';
import { InMemoryPostExploitationRepository } from '../src/v2/post-exploitation/InMemoryPostExploitationRepository.js';
import { CredentialVaultService } from '../src/v2/post-exploitation/CredentialVaultService.js';
import { PostExploitationService } from '../src/v2/post-exploitation/PostExploitationService.js';
import { LateralMovementService } from '../src/v2/attack-planning/LateralMovementService.js';
import { ImpactAssessmentService } from '../src/v2/reporting-boundary/ImpactAssessmentService.js';
import { AttackAuthorizationService } from '../src/v2/attack-authorization/AttackAuthorizationService.js';
import { AttackCapabilityRegistry } from '../src/v2/attack-execution/AttackCapabilityRegistry.js';
import { AttackExecutionService } from '../src/v2/attack-execution/AttackExecutionService.js';

const TARGET_HOST = 'teclaaa.vercel.app';
const SUPABASE_HOST_FALLBACK = 'vawrzoncszqauzxwqide.supabase.co';
const API_SECRET = 'fixguard_live_teclaaa_rls_secret';
const OPERATOR_ID = 'usr_secops_lead_live';
const POLL_MS = 2_000;
const MAX_WAIT_MS = 12 * 60_000;

interface JsonRecord {
  readonly [key: string]: unknown;
}

function asRecord(value: unknown): JsonRecord {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Expected JSON object response');
  }
  return value as JsonRecord;
}

function redactKey(key: string): string {
  if (key.length <= 12) return '…';
  return `${key.slice(0, 10)}…${key.slice(-4)}`;
}

async function extractObservedSupabaseAnonKey(): Promise<{
  readonly key: string;
  readonly projectHost: string;
  readonly seedTableNames: readonly string[];
}> {
  const pageUrl = `https://${TARGET_HOST}/carrera/93kpw`;
  const htmlRes = await fetch(pageUrl);
  const html = await htmlRes.text();
  const scriptPaths = Array.from(
    html.matchAll(/src="(\/_next\/static\/[^"]+\.js)"/g),
    (m) => m[1]!
  );
  const bodies: string[] = [html];
  for (const path of scriptPaths.slice(0, 40)) {
    try {
      const r = await fetch(`https://${TARGET_HOST}${path}`);
      bodies.push(await r.text());
    } catch {
      // ignore
    }
  }
  const text = bodies.join('\n');
  const hostMatch = text.match(/https:\/\/([a-z0-9-]+\.supabase\.co)/i);
  const projectHost = hostMatch?.[1] ?? SUPABASE_HOST_FALLBACK;

  // Same OBSERVED JS surface the P2 `.from()` miner uses — feed enum even if stage_4 is bounded.
  const fromHints = Array.from(
    text.matchAll(/\.from\(\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*\)/g),
    (m) => m[1]!
  );
  const restHints = Array.from(
    text.matchAll(/\/rest\/v1\/([A-Za-z_][A-Za-z0-9_]*)/g),
    (m) => m[1]!
  );
  const seedTableNames = Object.freeze(
    [...new Set([...fromHints, ...restHints, 'profiles'])].sort()
  );

  const publishable = text.match(/sb_publishable_[A-Za-z0-9_-]+/);
  if (publishable) {
    return { key: publishable[0], projectHost, seedTableNames };
  }

  const jwts = text.match(
    /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g
  );
  if (jwts) {
    for (const j of jwts) {
      try {
        const payload = j.split('.')[1]!;
        const pad = '='.repeat((4 - (payload.length % 4)) % 4);
        const json = JSON.parse(
          Buffer.from(payload + pad, 'base64url').toString('utf8')
        ) as { role?: string; iss?: string };
        if (json.role === 'anon' || json.iss === 'supabase') {
          return { key: j, projectHost, seedTableNames };
        }
      } catch {
        // continue
      }
    }
  }
  throw new Error('No OBSERVED Supabase anon/publishable key found in Teclaaa JS');
}

async function apiJson(
  baseUrl: string,
  path: string,
  init?: RequestInit
): Promise<{ status: number; body: unknown }> {
  const res = await fetch(`${baseUrl}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      Authorization: `Bearer ${API_SECRET}`,
      ...(init?.headers ?? {}),
    },
  });
  const text = await res.text();
  let body: unknown = null;
  if (text.length > 0) {
    try {
      body = JSON.parse(text);
    } catch {
      body = { raw: text.slice(0, 400) };
    }
  }
  return { status: res.status, body };
}

async function main(): Promise<void> {
  console.log('================================================================================');
  console.log('  FIXGUARD V2 — LIVE TECLAAA SUPABASE RLS');
  console.log('================================================================================\n');

  const observed = await extractObservedSupabaseAnonKey();
  console.log(`[*] OBSERVED key ${redactKey(observed.key)} host=${observed.projectHost}`);
  console.log(`[*] OBSERVED seed tables from JS: ${observed.seedTableNames.join(',')}`);

  const directProbes: Array<{
    readonly table: string;
    readonly status: number;
    readonly json: boolean;
    readonly preview: string;
  }> = [];
  for (const table of observed.seedTableNames) {
    const probe = await fetch(
      `https://${observed.projectHost}/rest/v1/${table}?select=*&limit=1`,
      {
        headers: {
          apikey: observed.key,
          Authorization: `Bearer ${observed.key}`,
          Accept: 'application/json',
        },
      }
    );
    const probeBody = await probe.text();
    const probeIsJson =
      probeBody.trim().startsWith('[') || probeBody.trim().startsWith('{');
    directProbes.push({
      table,
      status: probe.status,
      json: probeIsJson,
      preview: probeBody.slice(0, 120).replace(/\s+/g, ' '),
    });
    console.log(
      `[*] direct_${table} status=${probe.status} json=${probeIsJson}`
    );
  }
  const profilesProbe = directProbes.find((p) => p.table === 'profiles');

  const resolvedIps = await dns.resolve4(TARGET_HOST);
  console.log(`[*] dns ${TARGET_HOST} -> ${resolvedIps.join(',')}`);

  const availabilityService = new ReconToolAvailabilityService({
    async execute() {
      return {
        stdout: 'version: 1.0.0\n',
        stderr: '',
        exitCode: 0,
        durationMs: 1,
        timedOut: false,
      };
    },
  });

  const orchestratedRepository = new InMemoryOrchestratedAssessmentRepository();
  const attackPlanRepository = new InMemoryAttackPlanRepository();
  const attackPlanGenerator = new AttackPlanGeneratorService();
  const attackChainRepository = new InMemoryAttackChainRepository();
  const attackChainService = new AttackChainService(attackChainRepository);
  const postExploitationRepository = new InMemoryPostExploitationRepository();
  const credentialVaultService = new CredentialVaultService();
  const postExploitationService = new PostExploitationService(
    postExploitationRepository,
    credentialVaultService
  );
  const lateralMovementService = new LateralMovementService();
  const impactAssessmentService = new ImpactAssessmentService();
  const attackAuthorizationService = new AttackAuthorizationService(
    attackPlanRepository
  );
  const attackCapabilityRegistry = AttackCapabilityRegistry.createDefault();
  const attackExecutionService = new AttackExecutionService({
    planRepository: attackPlanRepository,
    capabilityRegistry: attackCapabilityRegistry,
    postExploitationService,
  });

  const orchestratedService = new OrchestratedAssessmentApplicationService({
    repository: orchestratedRepository,
    availabilityService,
    attackPlanRepository,
    attackPlanGenerator,
    attackChainRepository,
    attackChainService,
    postExploitationRepository,
    credentialVaultService,
    postExploitationService,
    lateralMovementService,
    impactAssessmentService,
  });

  const root = V2CompositionRoot.withDependencies({
    orchestratedRepository,
    orchestratedService,
    availabilityService,
    attackPlanRepository,
    attackPlanGenerator,
    attackAuthorizationService,
    attackCapabilityRegistry,
    attackExecutionService,
    attackChainRepository,
    attackChainService,
    postExploitationRepository,
    credentialVaultService,
    postExploitationService,
    lateralMovementService,
    impactAssessmentService,
  });
  const app = createV2App(root, { apiSecret: API_SECRET });
  const server: Server = await new Promise((resolve) => {
    const s = app.listen(0, DEFAULT_V2_HOST, () => resolve(s));
  });
  const addr = server.address() as AddressInfo;
  const baseUrl = `http://${DEFAULT_V2_HOST}:${addr.port}/api/v2`;
  console.log(`[*] In-process API: ${baseUrl}`);

  const userJwt = process.env.FG_ACCESS_TOKEN?.trim();
  const identityHeaders: Record<string, string> = {
    apikey: observed.key,
  };
  if (userJwt && userJwt.length > 20) {
    identityHeaders.authorization = `Bearer ${userJwt}`;
    console.log('[*] BYOT: FG_ACCESS_TOKEN present');
  } else {
    identityHeaders.authorization = `Bearer ${observed.key}`;
    console.log('[*] BYOT: anon-only (no FG_ACCESS_TOKEN)');
  }

  try {
    console.log('\n[*] POST /orchestrated/assessments/start');
    const startRes = await apiJson(baseUrl, '/orchestrated/assessments/start', {
      method: 'POST',
      body: JSON.stringify({
        targetDomain: TARGET_HOST,
        actorId: OPERATOR_ID,
        relatedAllowedHosts: [observed.projectHost],
        // P2 slam-dunk: JS `.from()` / rest path hints → PostgREST enum seeds (OpenAPI often closed).
        seedUrls: observed.seedTableNames.map(
          (t) => `https://${observed.projectHost}/rest/v1/${t}`
        ),
        seedPaths: ['/carrera/93kpw', '/login', '/perfil'],
        config: {
          enableSpaDiscovery: false,
          // Skip stage_4 when gau/crawl hangs on SPA hosts; JS `.from()` seeds above feed enum.
          skipStages: ['stage_2_port_service', 'stage_4_crawling_parameters'],
        },
        sessionIdentities: {
          identityA: {
            identityId: 'identity_teclaaa_a',
            injectHeaders: identityHeaders,
          },
        },
      }),
    });
    if (startRes.status !== 202) {
      throw new Error(
        `start failed HTTP ${startRes.status}: ${JSON.stringify(startRes.body)}`
      );
    }
    const startBody = asRecord(startRes.body);
    const assessmentId = String(startBody.assessmentId);
    console.log(`    assessmentId=${assessmentId}`);

    const deadline = Date.now() + MAX_WAIT_MS;
    let status = 'running';
    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, POLL_MS));
      const st = await apiJson(
        baseUrl,
        `/orchestrated/assessments/${assessmentId}/status`
      );
      const body = asRecord(st.body);
      status = String(body.status);
      process.stdout.write(
        `\r    poll status=${status} elapsed=${Math.round((Date.now() + MAX_WAIT_MS - deadline) / 1000)}s   `
      );
      if (
        status === 'completed' ||
        status === 'failed' ||
        status === 'circuit_broken' ||
        status === 'preflight_denied'
      ) {
        console.log('');
        break;
      }
    }

    const summary = await apiJson(
      baseUrl,
      `/orchestrated/assessments/${assessmentId}/summary`
    );
    const drafts = await apiJson(
      baseUrl,
      `/orchestrated/assessments/${assessmentId}/evidence-drafts`
    );
    const plans = await apiJson(
      baseUrl,
      `/assessments/${assessmentId}/attack-plans`
    );

    const summaryRec = asRecord(summary.body);
    const findings = Array.isArray(summaryRec.findings)
      ? summaryRec.findings
      : [];
    const draftList = Array.isArray(asRecord(drafts.body).drafts)
      ? (asRecord(drafts.body).drafts as unknown[])
      : Array.isArray(drafts.body)
        ? drafts.body
        : [];

    const rlsFindings = findings.filter((f) => {
      if (!f || typeof f !== 'object') return false;
      const meta = (f as { metadata?: { kind?: string } }).metadata;
      const title = (f as { title?: string }).title ?? '';
      return (
        meta?.kind === 'supabase_rls_abuse_metadata' ||
        title.toLowerCase().includes('supabase rls')
      );
    });
    const rlsDrafts = draftList.filter((d) => {
      if (!d || typeof d !== 'object') return false;
      const ctx = (
        d as {
          differentialContext?: {
            detectionKind?: string;
            supabaseTableName?: string;
          };
        }
      ).differentialContext;
      return ctx?.detectionKind === 'supabase_rls_abuse';
    });

    const planList = Array.isArray(asRecord(plans.body).plans)
      ? (asRecord(plans.body).plans as unknown[])
      : Array.isArray(plans.body)
        ? plans.body
        : [];
    const rlsPlans = planList.filter((p) => {
      if (!p || typeof p !== 'object') return false;
      return (p as { capability?: string }).capability === 'supabase_rls_read_confirm';
    });

    const rlsTables = [
      ...rlsFindings.map((f) => {
        const meta = (f as { metadata?: { tableName?: string } }).metadata;
        return meta?.tableName;
      }),
      ...rlsDrafts.map((d) => {
        const ctx = (
          d as { differentialContext?: { supabaseTableName?: string } }
        ).differentialContext;
        return ctx?.supabaseTableName;
      }),
    ].filter(Boolean);

    const out = {
      status,
      supabaseHost: observed.projectHost,
      anonKeyPreview: redactKey(observed.key),
      seedTableNames: observed.seedTableNames,
      directProbes,
      directProfilesStatus: profilesProbe?.status ?? null,
      findingsCount: findings.length,
      draftsCount: draftList.length,
      rlsFindingsCount: rlsFindings.length,
      rlsDraftsCount: rlsDrafts.length,
      rlsTables: [...new Set(rlsTables)],
      rlsPlanTitles: rlsPlans.map((p) => (p as { title?: string }).title),
      plansCount: planList.length,
    };

    writeFileSync(
      '/tmp/fixguard_teclaaa_rls_live.json',
      JSON.stringify(
        { out, rlsFindings, rlsDrafts, rlsPlans, summary: summaryRec },
        null,
        2
      )
    );
    console.log('\n[*] Summary');
    console.log(JSON.stringify(out, null, 2));
    console.log('artifact: /tmp/fixguard_teclaaa_rls_live.json');

    const hasProfiles =
      out.rlsTables.includes('profiles') ||
      out.directProfilesStatus === 200;
    const shopInSeeds = observed.seedTableNames.includes('shop_items');
    const shopSurfaced = out.rlsTables.includes('shop_items');
    const ok =
      hasProfiles &&
      (out.rlsFindingsCount > 0 || out.rlsDraftsCount > 0) &&
      (!shopInSeeds || shopSurfaced || directProbes.some((p) => p.table === 'shop_items' && p.status === 404));
    if (!ok) {
      console.error(
        '\n[!] ASSERT FAIL: expected RLS finding/draft; shop_items should surface when JS-seeded + world-readable'
      );
      process.exitCode = 1;
    } else if (shopInSeeds && !shopSurfaced) {
      console.log(
        '\n[~] profiles OK; shop_items seeded but not in RLS findings (see directProbes)'
      );
    } else {
      console.log(
        '\n[+] ASSERT OK: world-readable Supabase tables surfaced via assessment'
      );
    }
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
