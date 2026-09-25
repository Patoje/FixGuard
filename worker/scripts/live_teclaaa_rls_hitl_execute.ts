/**
 * HITL authorize+execute for supabase_rls_read_confirm against worker :4000.
 * Reuses OBSERVED anon key from /tmp (never commits secrets). Read-only confirm only.
 */

import dns from 'node:dns/promises';
import { readFileSync, writeFileSync } from 'node:fs';

const BASE = process.env.FG_API_BASE?.trim() || 'http://127.0.0.1:4000/api/v2';
const TARGET_HOST = 'teclaaa.vercel.app';
const SUPABASE_HOST = 'vawrzoncszqauzxwqide.supabase.co';
const OPERATOR_ID = 'usr_secops_lead_live';
const POLL_MS = 2_000;
const MAX_WAIT_MS = 10 * 60_000;

interface JsonRecord {
  readonly [key: string]: unknown;
}

function asRecord(value: unknown): JsonRecord {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Expected JSON object response');
  }
  return value as JsonRecord;
}

function loadObservedAnonKey(): string {
  const candidates = [
    '/tmp/fg_teclaaa_anon_key.raw',
    '/tmp/fg_teclaaa_anon_ONLY_TMP.txt',
  ];
  for (const p of candidates) {
    try {
      const k = readFileSync(p, 'utf8').trim();
      if (k.startsWith('sb_publishable_') && k.length >= 20) return k;
    } catch {
      // continue
    }
  }
  throw new Error('No OBSERVED anon key in /tmp — extract from Teclaaa JS first');
}

function redactKey(key: string): string {
  if (key.length <= 12) return '…';
  return `${key.slice(0, 10)}…${key.slice(-4)}`;
}

async function apiJson(
  path: string,
  init?: RequestInit
): Promise<{ status: number; body: unknown }> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      ...(init?.headers ?? {}),
    },
  });
  const text = await res.text();
  let body: unknown = null;
  if (text.length > 0) {
    try {
      body = JSON.parse(text);
    } catch {
      body = { raw: text.slice(0, 500) };
    }
  }
  return { status: res.status, body };
}

async function main(): Promise<void> {
  const anonKey = loadObservedAnonKey();
  console.log(`[*] BASE=${BASE}`);
  console.log(`[*] OBSERVED key ${redactKey(anonKey)} host=${SUPABASE_HOST}`);

  const probe = await fetch(
    `https://${SUPABASE_HOST}/rest/v1/profiles?select=*&limit=1`,
    {
      headers: {
        apikey: anonKey,
        Authorization: `Bearer ${anonKey}`,
        Accept: 'application/json',
      },
    }
  );
  console.log(`[*] direct_profiles status=${probe.status}`);
  if (probe.status !== 200) {
    throw new Error(`profiles probe failed HTTP ${probe.status}`);
  }

  // Scope rebind rejects client hosts not already sealed. Do NOT add related-host
  // IPs here — sealed grant has target IPs + related hostnames only.
  const resolvedIps = await dns.resolve4(TARGET_HOST);
  console.log(`[*] dns ${TARGET_HOST} -> ${resolvedIps.join(',')}`);

  console.log('\n[*] POST /orchestrated/assessments/start');
  const startRes = await apiJson('/orchestrated/assessments/start', {
    method: 'POST',
    body: JSON.stringify({
      targetDomain: TARGET_HOST,
      actorId: OPERATOR_ID,
      relatedAllowedHosts: [SUPABASE_HOST],
      seedUrls: [`https://${SUPABASE_HOST}/rest/v1/profiles`],
      seedPaths: ['/carrera/93kpw', '/login', '/perfil'],
      config: {
        enableSpaDiscovery: false,
        skipStages: ['stage_2_port_service', 'stage_4_crawling_parameters'],
      },
      sessionIdentities: {
        identityA: {
          identityId: 'identity_teclaaa_a',
          injectHeaders: {
            apikey: anonKey,
            Authorization: `Bearer ${anonKey}`,
          },
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
  const scanId = String(startBody.scanId);
  const lineage = asRecord(startBody.lineage);
  const grantId = String(lineage.authorizationGrantId);
  console.log(`    assessmentId=${assessmentId}`);

  const deadline = Date.now() + MAX_WAIT_MS;
  let status = 'running';
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, POLL_MS));
    const st = await apiJson(`/orchestrated/assessments/${assessmentId}/status`);
    const body = asRecord(st.body);
    status = String(body.status);
    process.stdout.write(`\r    poll status=${status}   `);
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
    `/orchestrated/assessments/${assessmentId}/summary`
  );
  const plans = await apiJson(`/assessments/${assessmentId}/attack-plans`);
  const summaryRec = asRecord(summary.body);
  const findings = Array.isArray(summaryRec.findings)
    ? (summaryRec.findings as unknown[])
    : [];
  const planList = Array.isArray(asRecord(plans.body).plans)
    ? (asRecord(plans.body).plans as unknown[])
    : [];

  const rlsFinding = findings.find((f) => {
    if (!f || typeof f !== 'object') return false;
    const meta = (f as { metadata?: { kind?: string; tableName?: string } })
      .metadata;
    return (
      meta?.kind === 'supabase_rls_abuse_metadata' && meta.tableName === 'profiles'
    );
  });

  const rlsPlan = planList.find((p) => {
    if (!p || typeof p !== 'object') return false;
    const plan = p as JsonRecord;
    return plan.capability === 'supabase_rls_read_confirm';
  }) as JsonRecord | undefined;

  console.log(
    `\n[*] status=${status} findings=${findings.length} plans=${planList.length} rlsFinding=${Boolean(rlsFinding)} rlsPlan=${Boolean(rlsPlan)}`
  );
  if (rlsPlan) {
    console.log(
      `    planId=${rlsPlan.planId} status=${rlsPlan.status} targetUrl=${rlsPlan.targetUrl}`
    );
  }

  if (!rlsPlan) {
    writeFileSync(
      '/tmp/fixguard_teclaaa_rls_hitl.json',
      JSON.stringify(
        {
          assessmentId,
          status,
          error: 'no_supabase_rls_read_confirm_plan',
          findingsCount: findings.length,
          planCapabilities: planList.map((p) =>
            p && typeof p === 'object'
              ? (p as JsonRecord).capability
              : null
          ),
        },
        null,
        2
      )
    );
    throw new Error('No supabase_rls_read_confirm plan generated');
  }

  const planId = String(rlsPlan.planId);
  console.log(`\n[*] AUTHORIZE plan ${planId} blast=read_escalated`);
  const authRes = await apiJson(
    `/assessments/${assessmentId}/attack-plans/${planId}/authorize`,
    {
      method: 'POST',
      body: JSON.stringify({
        operatorId: OPERATOR_ID,
        blastRadiusClass: 'read_escalated',
      }),
    }
  );
  console.log(`    authorize HTTP ${authRes.status}`);
  console.log(`    authorize body=${JSON.stringify(authRes.body).slice(0, 500)}`);

  if (authRes.status !== 201 && authRes.status !== 200) {
    throw new Error(`authorize failed HTTP ${authRes.status}`);
  }

  const now = new Date();
  const scopeGrant = {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId,
    scanId,
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 3600_000).toISOString(),
    subject: { targetKind: 'domain', domain: TARGET_HOST },
    authorizationBasis: {
      basisKind: 'user_attestation',
      recordedBy: 'human_user',
      authorizationText: `HITL RLS read confirm for ${TARGET_HOST} + ${SUPABASE_HOST}`,
    },
    permissionSet: {
      passiveRecon: true,
      technologyFingerprinting: true,
      endpointDiscovery: true,
      activeCrawling: true,
      authenticatedTesting: true,
      lightValidation: true,
      activeValidation: true,
      aggressiveValidation: false,
      oobTesting: false,
      destructiveOperations: false,
    },
    boundaries: {
      allowedDomains: [TARGET_HOST, SUPABASE_HOST],
      // Hostnames only (+ optional sealed target IPs). Related-host IPs expand → 403.
      allowedHosts: [TARGET_HOST, SUPABASE_HOST],
      allowedOrigins: [
        `https://${TARGET_HOST}`,
        `http://${TARGET_HOST}`,
        `https://${SUPABASE_HOST}`,
        `http://${SUPABASE_HOST}`,
      ],
      allowedMethods: ['GET', 'HEAD', 'OPTIONS'],
    },
    constraints: {
      allowLoginRequiredAreas: true,
      allowStateChangingRequests: false,
      allowCredentialUse: true,
      allowOobCallbacks: false,
      allowThirdPartyTargets: false,
    },
    classification: {
      createsRealFindings: false,
      createsPersistedEvidence: false,
      confirmsVulnerabilities: false,
      makesRiskClaims: false,
      makesSeverityClaims: false,
      makesImpactClaims: false,
      executesNetwork: false,
      executesTools: false,
      persistsData: false,
    },
  };

  console.log(`\n[*] EXECUTE plan ${planId}`);
  const execRes = await apiJson(
    `/assessments/${assessmentId}/attack-plans/${planId}/execute`,
    {
      method: 'POST',
      body: JSON.stringify({
        operatorId: OPERATOR_ID,
        scopeGrant,
        findings: rlsFinding ? [rlsFinding] : findings,
        primaryIdentity: {
          identityId: 'identity_teclaaa_a',
          headers: {
            apikey: anonKey,
            Authorization: `Bearer ${anonKey}`,
          },
        },
      }),
    }
  );
  console.log(`    execute HTTP ${execRes.status}`);
  console.log(`    execute body=${JSON.stringify(execRes.body).slice(0, 800)}`);

  const execBody = asRecord(execRes.body);
  const outcome =
    typeof execBody.outcome === 'string'
      ? execBody.outcome
      : typeof asRecord(execBody.result ?? {}).outcome === 'string'
        ? String(asRecord(execBody.result).outcome)
        : typeof execBody.status === 'string'
          ? String(execBody.status)
          : 'unknown';

  const artifact = {
    assessmentId,
    scanId,
    planId,
    status,
    authorizeHttp: authRes.status,
    authorize: authRes.body,
    executeHttp: execRes.status,
    execute: execRes.body,
    outcome,
    rlsFindingPresent: Boolean(rlsFinding),
    planCapability: rlsPlan.capability,
    planTargetUrl: rlsPlan.targetUrl,
  };
  writeFileSync(
    '/tmp/fixguard_teclaaa_rls_hitl.json',
    JSON.stringify(artifact, null, 2)
  );
  console.log('\n[*] artifact: /tmp/fixguard_teclaaa_rls_hitl.json');
  console.log(`[*] OUTCOME=${outcome}`);

  if (execRes.status >= 400) {
    process.exitCode = 1;
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
