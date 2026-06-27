/**
 * Milestone 6.5 - End-to-End V2 Smoke Test
 * 
 * This is a standalone smoke test and demo harness.
 * It is NOT a production entrypoint.
 * 
 * Purpose: Verify the first full V2 architectural loop without crossing boundaries.
 * 
 * Usage: npx tsx src/v2/smoke/milestone6_5_smoke.ts
 */

import { MinimalOrchestrator } from '../core/MinimalOrchestrator';
import { LocalProcessRunner } from '../core/ProcessRunner';
import { createV2ToolRegistry } from '../composition/createV2ToolRegistry';
import type { CapabilityRequest } from '../core/ExecutionContracts';
import type { Finding } from '../core/Evidence';
import { LocalEvidenceAccumulator } from '../intelligence/EvidenceAccumulator';
import { LocalCorrelationEngine } from '../intelligence/CorrelationEngine';
import { LocalTargetProfileBuilder } from '../intelligence/TargetProfileBuilder';
import { LocalRecommendationEngine } from '../intelligence/RecommendationEngine';
import { SubdomainProfilerRule } from '../intelligence/rules/SubdomainProfilerRule';
import { HttpProbeProfilerRule } from '../intelligence/rules/HttpProbeProfilerRule';
import { SubdomainHttpProbeRule } from '../intelligence/rules/SubdomainHttpProbeRule';
import { LocalRecommendationInbox } from '../approval/RecommendationInbox';
import { LocalApprovalGateway } from '../approval/ApprovalGateway';
import { LocalAuditLog } from '../approval/AuditLog';
import { LocalIntentTranslator } from '../approval/IntentTranslator';
import { spawn } from 'child_process';
import * as os from 'os';

function getExtendedPath(): string {
  const homedir = os.homedir();
  const extraPaths = [
    `${homedir}/go/bin`,
    `${homedir}/bin`,
    `${homedir}/.local/bin`,
  ];
  const separator = process.platform === 'win32' ? ';' : ':';
  const currentPath = process.env.PATH || '';
  
  const toAdd = extraPaths.filter(p => !currentPath.includes(p));
  return toAdd.length > 0 
    ? `${currentPath}${separator}${toAdd.join(separator)}` 
    : currentPath;
}

async function assertBinaryAvailable(binaryName: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const proc = spawn(binaryName, ['-version'], { 
      shell: false,
      env: { ...process.env, PATH: getExtendedPath() }
    });

    proc.on('error', () => {
      reject(new Error(`Binary '${binaryName}' is missing or not executable.`));
    });

    proc.on('close', () => {
      console.log(`[+] Preflight: ${binaryName} found`);
      resolve();
    });
  });
}

async function runSmokeTest() {
  console.log('--- V2 End-to-End Smoke Test ---');
  
  // 1. Compose the Layers
  console.log('[*] Composing V2 Layers...');
  
  // Execution Core
  const registry = createV2ToolRegistry();
  const runner = new LocalProcessRunner();
  const orchestrator = new MinimalOrchestrator(registry, runner);

  // Intelligence Layer
  const accumulator = new LocalEvidenceAccumulator();
  const correlationEngine = new LocalCorrelationEngine();
  const targetProfileBuilder = new LocalTargetProfileBuilder([
    new SubdomainProfilerRule(),
    new HttpProbeProfilerRule()
  ]);
  const recommendationEngine = new LocalRecommendationEngine([
    new SubdomainHttpProbeRule()
  ]);

  // Approval Boundary
  const inbox = new LocalRecommendationInbox();
  const auditLog = new LocalAuditLog();
  const intentTranslator = new LocalIntentTranslator();
  const approvalGateway = new LocalApprovalGateway(inbox, auditLog, intentTranslator);

  // 1.5 Preflight Checks
  console.log('[*] Running Preflight Tool Checks...');
  try {
    await assertBinaryAvailable('subfinder');
    await assertBinaryAvailable('httpx');
  } catch (err: any) {
    console.error(`[!] Preflight failed: ${err.message}`);
    console.error(`[!] Smoke test requires actual tools to be installed in PATH.`);
    process.exit(1);
  }

  // 2. Initial Execution (subdomain_discovery)
  const targetUri = 'https://example.com';
  const discoveryReq: CapabilityRequest = {
    capability: 'subdomain_discovery',
    target: { uri: targetUri },
    config: {}
  };

  console.log(`[*] Executing initial capability: ${discoveryReq.capability} against ${targetUri}`);
  
  let discoveryEvidence;
  try {
    discoveryEvidence = await orchestrator.run(discoveryReq);
  } catch (err: any) {
    console.error(`[!] subdomain_discovery execution failed:`, err);
    process.exit(1);
  }

  // Fallback if needed
  if (discoveryEvidence.findings.length === 0) {
    console.log(`[!] Subdomain discovery returned zero findings; injecting deterministic fallback trigger...`);
    const mockFinding: Finding = {
      id: `subfinder_mock_${Date.now()}`,
      type: 'subdomain_discovery',
      severity: 'info',
      title: 'Discovered Subdomain',
      description: 'Mock finding injected for smoke test fallback',
      // NOTE: This mock finding is ONLY a trigger for SubdomainHttpProbeRule.
      target: 'api.example.com', 
      evidence: '{}',
      confidence: 1.0,
      metadata: {}
    };
    discoveryEvidence.findings.push(mockFinding);
  } else {
    console.log(`[+] subdomain_discovery returned ${discoveryEvidence.findings.length} finding(s)`);
  }

  // 3. First Intelligence Pass
  console.log('[*] Running First Intelligence Pass...');
  accumulator.add(discoveryEvidence);
  const correlated1 = correlationEngine.correlate(accumulator.getAllFindings());
  const profile1 = targetProfileBuilder.build(correlated1, targetUri);
  const recommendations = recommendationEngine.recommend(profile1);

  const httpProbeRec = recommendations.find(r => r.capability === 'http_probe');
  if (!httpProbeRec) {
    console.error('[!] Intelligence failed to produce http_probe recommendation');
    process.exit(1);
  }

  console.log(`[+] Intelligence produced recommendation: ${httpProbeRec.id} for capability ${httpProbeRec.capability}`);

  // 4. Approval Flow
  console.log('[*] Routing through Approval Boundary...');
  inbox.add(httpProbeRec);

  const approvalResult = approvalGateway.approve(httpProbeRec.id, 'operator-smoke-test');
  
  if (!approvalResult.request) {
    console.error('[!] ApprovalGateway did not produce a CapabilityRequest');
    process.exit(1);
  }

  if (!approvalResult.request.config || !approvalResult.request.config.sourceRecommendationId) {
    console.error('[!] sourceRecommendationId is missing from approvalResult.request.config');
    process.exit(1);
  }

  // CRITICAL ASSERTION
  if (approvalResult.request.target.uri !== 'https://example.com') {
    console.error(`[!] Target URI mismatch! Expected https://example.com, got ${approvalResult.request.target.uri}`);
    process.exit(1);
  }
  
  console.log(`[+] Approval successful. Synthesized CapabilityRequest targets ${approvalResult.request.target.uri}`);

  // 5. Active Probing Execution
  console.log(`[*] Executing approved capability: ${approvalResult.request.capability}`);
  
  let probeEvidence;
  try {
    probeEvidence = await orchestrator.run(approvalResult.request);
  } catch (err: any) {
    console.error(`[!] http_probe execution failed:`, err);
    process.exit(1);
  }

  const liveHosts = probeEvidence.findings.filter(f => f.type === 'http_live_host');
  if (liveHosts.length === 0) {
    console.error('[!] http_probe returned no http_live_host findings');
    process.exit(1);
  }

  console.log(`[+] http_probe returned ${liveHosts.length} live host(s)`);

  // 6. Second Intelligence Pass
  console.log('[*] Running Second Intelligence Pass...');
  accumulator.add(probeEvidence);
  const correlated2 = correlationEngine.correlate(accumulator.getAllFindings());
  const profile2 = targetProfileBuilder.build(correlated2, targetUri);

  if (!profile2.exposedCapabilities.includes('http_service_detected')) {
    console.error('[!] Second TargetProfile pass does not contain http_service_detected in exposedCapabilities');
    process.exit(1);
  }

  const httpServices = profile2.metadata.httpServices as any[];
  if (!httpServices || httpServices.length === 0) {
    console.error('[!] Second TargetProfile pass metadata.httpServices is empty');
    process.exit(1);
  }

  console.log(`[+] TargetProfile enriched with HTTP service metadata`);
  console.log('--- Smoke Test Completed Successfully ---');
  process.exit(0);
}

runSmokeTest().catch(err => {
  console.error('[!] Unhandled error in smoke test:', err);
  process.exit(1);
});
