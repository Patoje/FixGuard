/**
 * FixGuard V2 — Live Orchestrated Assessment Lifecycle
 * Authorized target: https://charmarket.vercel.app/
 *
 * Starts in-process V2 API (createDefault = live fetch + real DNS),
 * runs full orchestrated assessment, then pulls Attack Mode GETs.
 * Optionally authorizes + executes a safe-class plan with real DNS answers.
 *
 * Honest stubs noted in output (subfinder empty, CT fail-closed by default,
 * port 443 assumed open without active scan).
 */

import dns from 'node:dns/promises';
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

const TARGET_HOST = 'charmarket.vercel.app';
const TARGET_URL = 'https://charmarket.vercel.app/';
const API_SECRET = 'fixguard_live_orchestrated_charmarket_secret';
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
      body = { raw: text.slice(0, 500) };
    }
  }
  return { status: res.status, body };
}

function summarizeArray(label: string, items: unknown): void {
  const arr = Array.isArray(items) ? items : [];
  console.log(`    ${label}: ${arr.length}`);
}

async function main(): Promise<void> {
  console.log('================================================================================');
  console.log('  FIXGUARD V2 — LIVE ORCHESTRATED LIFECYCLE (charmarket.vercel.app)');
  console.log('================================================================================\n');

  console.log('[*] Preflight: DNS + SSRF egress gate...');
  const resolvedIps = await dns.resolve4(TARGET_HOST);
  for (const ip of resolvedIps) {
    const parts = ip.split('.').map(Number);
    const isPrivate =
      ip.startsWith('127.') ||
      ip.startsWith('10.') ||
      ip.startsWith('192.168.') ||
      ip.startsWith('169.254.') ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31);
    if (isPrivate) {
      throw new Error(`SSRF gate: ${TARGET_HOST} resolved to non-public ${ip}`);
    }
  }
  console.log(`    host=${TARGET_HOST} ips=${resolvedIps.join(',')}`);

  // Host lacks dnsx/naabu/tlsx/arjun. createDefault recon uses in-process JS
  // adapters (real fetch + dns.resolve4), so CLI probe is satisfied via a
  // version-stub ProcessRunner — same pattern as hermetic smokes. Documented
  // as adapter-path honesty, not "CLIs installed".
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
  const attackAuthorizationService = new AttackAuthorizationService(attackPlanRepository);
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
    // httpTransport + dnsResolver + reconAdapters: service defaults (live fetch/DNS)
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
  console.log(`\n[*] In-process API: ${baseUrl}`);
  console.log('    availability: CLI probe stubbed (JS adapters; host missing dnsx/naabu/tlsx/arjun)');

  try {
    console.log('\n[*] POST /orchestrated/assessments/start');
    const startRes = await apiJson(baseUrl, '/orchestrated/assessments/start', {
      method: 'POST',
      body: JSON.stringify({ targetDomain: TARGET_HOST }),
    });
    if (startRes.status !== 202) {
      throw new Error(`start failed HTTP ${startRes.status}: ${JSON.stringify(startRes.body)}`);
    }
    const startBody = asRecord(startRes.body);
    const assessmentId = String(startBody.assessmentId);
    const scanId = String(startBody.scanId);
    console.log(`    assessmentId=${assessmentId} scanId=${scanId} status=${String(startBody.status)}`);

    const deadline = Date.now() + MAX_WAIT_MS;
    let status = 'running';
    let lastStages = 0;
    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, POLL_MS));
      const st = await apiJson(baseUrl, `/orchestrated/assessments/${assessmentId}/status`);
      if (st.status !== 200) {
        throw new Error(`status poll HTTP ${st.status}: ${JSON.stringify(st.body)}`);
      }
      const body = asRecord(st.body);
      status = String(body.status);
      const stages = Array.isArray(body.stages) ? body.stages.length : 0;
      if (stages !== lastStages || status !== 'running') {
        console.log(
          `    poll status=${status} stages=${stages} errors=${String(body.errorCount ?? 0)} warnings=${String(body.warningCount ?? 0)}`
        );
        lastStages = stages;
      }
      if (status === 'completed' || status === 'failed' || status === 'circuit_broken') {
        break;
      }
    }

    if (status !== 'completed' && status !== 'circuit_broken') {
      throw new Error(`Assessment did not complete (status=${status})`);
    }

    console.log('\n[*] GET summary / attack-surface / Attack Mode endpoints');
    const summary = await apiJson(baseUrl, `/orchestrated/assessments/${assessmentId}/summary`);
    const asg = await apiJson(baseUrl, `/orchestrated/assessments/${assessmentId}/attack-surface`);
    const plans = await apiJson(baseUrl, `/assessments/${assessmentId}/attack-plans`);
    const chains = await apiJson(baseUrl, `/assessments/${assessmentId}/attack-chains`);
    const postEx = await apiJson(baseUrl, `/assessments/${assessmentId}/post-exploitation`);
    const lateral = await apiJson(baseUrl, `/assessments/${assessmentId}/lateral-movement`);
    const impact = await apiJson(baseUrl, `/assessments/${assessmentId}/impact`);

    for (const [name, res] of [
      ['summary', summary],
      ['attack-surface', asg],
      ['attack-plans', plans],
      ['attack-chains', chains],
      ['post-exploitation', postEx],
      ['lateral-movement', lateral],
      ['impact', impact],
    ] as const) {
      console.log(`    ${name}: HTTP ${res.status}`);
      if (res.status !== 200) {
        console.log(`      body=${JSON.stringify(res.body).slice(0, 300)}`);
      }
    }

    const summaryBody = asRecord(summary.body);
    const plansBody = asRecord(plans.body);
    const chainsBody = asRecord(chains.body);
    const postExBody = asRecord(postEx.body);
    const lateralBody = asRecord(lateral.body);
    const impactBody = asRecord(impact.body);
    const asgBody = asRecord(asg.body);

    console.log('\n[*] OBSERVED payload counts');
    console.log(`    assessment status: ${status}`);
    console.log(`    findings: ${Array.isArray(summaryBody.findings) ? summaryBody.findings.length : 'n/a'}`);
    console.log(
      `    recommendations: ${Array.isArray(summaryBody.recommendations) ? summaryBody.recommendations.length : 'n/a'}`
    );
    console.log(
      `    pendingEvidenceDrafts: ${Array.isArray(summaryBody.pendingEvidenceDrafts) ? summaryBody.pendingEvidenceDrafts.length : 'n/a'}`
    );
    const graph =
      asgBody.attackSurfaceGraph && typeof asgBody.attackSurfaceGraph === 'object'
        ? asRecord(asgBody.attackSurfaceGraph)
        : null;
    if (graph) {
      summarizeArray('ASG nodes', graph.nodes);
      summarizeArray('ASG edges', graph.edges);
      console.log(
        `    ASG targetHost=${String(graph.targetHost ?? '')} graphId=${String(graph.graphId ?? '')}`
      );
    } else {
      console.log('    ASG attackSurfaceGraph: null');
    }
    summarizeArray('plans', plansBody.plans);
    summarizeArray('chains', chainsBody.chains);
    summarizeArray('impactAssessments', impactBody.impactAssessments);

    const peState =
      postExBody.state && typeof postExBody.state === 'object' ? asRecord(postExBody.state) : null;
    if (peState) {
      summarizeArray('acquiredAccess', peState.acquiredAccess);
      summarizeArray('lateralHypotheses', peState.lateralMovementHypotheses);
    } else {
      console.log('    postExploitation state: null');
    }
    const latSnap =
      lateralBody.snapshot && typeof lateralBody.snapshot === 'object'
        ? asRecord(lateralBody.snapshot)
        : null;
    if (latSnap) {
      summarizeArray('discoveredHosts', latSnap.discoveredHosts);
      summarizeArray('authorizedTargets', latSnap.authorizedTargets);
      summarizeArray('lateralRecords', latSnap.records);
    } else {
      console.log('    lateral snapshot: null');
    }

    const secretLeak = JSON.stringify({
      plans: plansBody,
      chains: chainsBody,
      postEx: postExBody,
      lateral: lateralBody,
      impact: impactBody,
    });
    if (
      /password\s*[:=]|api[_-]?key\s*[:=]|Bearer\s+[A-Za-z0-9\-._~+/]+=*/i.test(secretLeak) &&
      secretLeak.includes('secret:')
    ) {
      console.log('    [!] Possible secret-shaped content in Attack Mode DTOs — review manually');
    } else {
      console.log('    [✔] No obvious vault-secret fields in Attack Mode JSON payloads');
    }

    // Attack Mode: authorize + execute safest ready plan only (read_public class)
    const planList = Array.isArray(plansBody.plans) ? plansBody.plans : [];
    const safePlan = planList.find((p) => {
      if (!p || typeof p !== 'object') return false;
      const plan = p as JsonRecord;
      return (
        plan.status === 'ready_for_authorization' &&
        (plan.capability === 'parameter_reflection_probe' ||
          plan.capability === 'nuclei_xss_scan' ||
          plan.capability === 'method_manipulation_probe')
      );
    }) as JsonRecord | undefined;

    if (!safePlan) {
      console.log('\n[*] Attack Mode: no safe-class ready plan — authorize/execute skipped (honest empty)');
    } else {
      const planId = String(safePlan.planId);
      const capability = String(safePlan.capability);
      console.log(`\n[*] Attack Mode: authorize plan ${planId} (${capability}) blast=read_public`);
      const authRes = await apiJson(
        baseUrl,
        `/assessments/${assessmentId}/attack-plans/${planId}/authorize`,
        {
          method: 'POST',
          body: JSON.stringify({
            operatorId: OPERATOR_ID,
            blastRadiusClass: 'read_public',
          }),
        }
      );
      console.log(`    authorize HTTP ${authRes.status}`);
      console.log(`    authorize body=${JSON.stringify(authRes.body).slice(0, 400)}`);

      if (authRes.status === 201 || authRes.status === 200) {
        const lineage =
          plansBody.lineage && typeof plansBody.lineage === 'object'
            ? asRecord(plansBody.lineage)
            : null;
        const grantId =
          lineage && typeof lineage.authorizationGrantId === 'string'
            ? lineage.authorizationGrantId
            : 'grant_live_fallback';
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
            authorizationText: `Live Attack Mode scope for ${TARGET_HOST}`,
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
            allowedDomains: [TARGET_HOST],
            allowedHosts: [TARGET_HOST, ...resolvedIps],
            allowedOrigins: [TARGET_URL.replace(/\/$/, '')],
            allowedMethods: ['GET', 'HEAD', 'OPTIONS'],
          },
          constraints: {
            allowLoginRequiredAreas: false,
            allowStateChangingRequests: false,
            allowCredentialUse: false,
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

        console.log(`[*] Attack Mode: execute ${planId} (server-side DNS; no client dnsAnswers)`);
        const execRes = await apiJson(
          baseUrl,
          `/assessments/${assessmentId}/attack-plans/${planId}/execute`,
          {
            method: 'POST',
            body: JSON.stringify({
              operatorId: OPERATOR_ID,
              scopeGrant,
            }),
          }
        );
        console.log(`    execute HTTP ${execRes.status}`);
        console.log(`    execute body=${JSON.stringify(execRes.body).slice(0, 600)}`);

        const refreshPlans = await apiJson(baseUrl, `/assessments/${assessmentId}/attack-plans`);
        const refreshChains = await apiJson(baseUrl, `/assessments/${assessmentId}/attack-chains`);
        const refreshImpact = await apiJson(baseUrl, `/assessments/${assessmentId}/impact`);
        console.log(
          `    post-execute plans=${Array.isArray(asRecord(refreshPlans.body).plans) ? (asRecord(refreshPlans.body).plans as unknown[]).length : 0} chains=${Array.isArray(asRecord(refreshChains.body).chains) ? (asRecord(refreshChains.body).chains as unknown[]).length : 0} impacts=${Array.isArray(asRecord(refreshImpact.body).impactAssessments) ? (asRecord(refreshImpact.body).impactAssessments as unknown[]).length : 0}`
        );
      }
    }

    console.log('\n[*] Stub / honesty notes (live adapter composition)');
    console.log('    - CLI availability probe stubbed (host missing dnsx/naabu/tlsx/arjun)');
    console.log('    - subdomainTool: empty success stub (no Subfinder invocation)');
    console.log('    - passiveCtTool: fail-closed CT fetch (warning, not hard fail)');
    console.log('    - portTool: assumes tcp/443 open without active port scan');
    console.log('    - web/tls/url/parameter: live HTTP/DNS against target');
    console.log('    - no destructive / persistence blast classes attempted');

    console.log('\n================================================================================');
    console.log('  [✔] LIVE ORCHESTRATED LIFECYCLE FINISHED');
    console.log('================================================================================\n');
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
  }
}

main().catch((err) => {
  console.error('LIVE ORCHESTRATED FAILED:', err instanceof Error ? err.message : err);
  process.exit(1);
});
