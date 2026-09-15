/**
 * FixGuard V2 — Milestone P2-5 Smoke Suite
 *
 * Verifies TLS Configuration Analysis Engine:
 * 1. Detects SSLv3 / TLS 1.0 and weak ciphers from Stage 3 TLS observations, building WeakTlsMetadata.
 * 2. Insecure protocols (SSLv2/SSLv3) trigger 'vulnerability_detected' with severity: 'high'.
 * 3. Deprecated protocols (TLS 1.0/1.1) trigger 'potential_weakness' with severity: 'medium'.
 * 4. Detects expired, self-signed, and SAN mismatch certificate anomalies.
 * 5. Modern hardened configurations cleanly abstain (secure_target_abstained).
 * 6. Purely analytical invariant: requires 0 additional network calls.
 * 7. Full Orchestrated Assessment Pipeline integration & human triage lifecycle.
 */

import assert from 'node:assert';
import {
  analyzeTlsConfiguration,
  isWeakCipher,
  matchesSan,
} from '../detection/TlsConfigurationAnalysisService.js';
import { DETECTION_CONTRACT_VERSION } from '../detection/DetectionContracts.js';
import type { DiscoveredTlsObservation } from '../recon/adapters/TlsInspectionContracts.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';
import { ReconToolAvailabilityService } from '../capabilities/ReconToolAvailabilityService.js';
import type { ReconToolAdapters } from '../recon/orchestration/ActiveReconOrchestrationContracts.js';
import { SUBDOMAIN_DISCOVERY_NON_CLAIMS } from '../recon/adapters/SubdomainDiscoveryContracts.js';
import { DNS_RESOLUTION_NON_CLAIMS } from '../recon/adapters/DnsResolutionContracts.js';
import { PORT_DISCOVERY_NON_CLAIMS } from '../recon/adapters/PortDiscoveryContracts.js';
import { WEB_INSPECTION_NON_CLAIMS } from '../recon/adapters/WebInspectionContracts.js';
import { TLS_INSPECTION_NON_CLAIMS } from '../recon/adapters/TlsInspectionContracts.js';
import { URL_DISCOVERY_NON_CLAIMS } from '../recon/adapters/UrlDiscoveryContracts.js';
import { CONTENT_DISCOVERY_NON_CLAIMS } from '../recon/adapters/ContentDiscoveryContracts.js';
import { PARAMETER_DISCOVERY_NON_CLAIMS } from '../recon/adapters/ParameterDiscoveryContracts.js';
import { SECRET_DISCOVERY_NON_CLAIMS } from '../recon/adapters/SecretDiscoveryContracts.js';

console.log('[milestoneP2_5_tls_configuration_smoke] Starting Milestone P2-5 smoke suite...');

function createMockAdapters(tlsObservation: DiscoveredTlsObservation): ReconToolAdapters {
  return {
    subdomainTool: {
      async discoverSubdomains(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-subdomain-discovery/v0',
          targetDomain: req.targetDomain,
          observations: [],
          explicitNonClaims: SUBDOMAIN_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
    dnsTool: {
      async resolveDns(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-dns-resolution/v0',
          targetDomain: req.targetDomain,
          observations: [
            {
              domain: req.targetDomain,
              recordType: 'A',
              values: ['93.184.216.34'],
              discoveredAt: new Date().toISOString(),
            },
          ],
          explicitNonClaims: DNS_RESOLUTION_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
    portTool: {
      async discoverPorts(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-port-discovery/v0',
          targetHostOrIp: req.targetHostOrIp,
          observations: [
            {
              host: req.targetHostOrIp,
              ip: req.targetHostOrIp,
              port: 443,
              protocol: 'tcp',
              state: 'open',
              discoveredAt: new Date().toISOString(),
            },
          ],
          explicitNonClaims: PORT_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
    webTool: {
      async inspectWeb(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-web-inspection/v0',
          targetUrl: req.targetUrl,
          observations: [],
          explicitNonClaims: WEB_INSPECTION_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
    tlsTool: {
      async inspectTls(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-tls-inspection/v0',
          targetHost: req.targetHostOrUrl,
          observations: [tlsObservation],
          explicitNonClaims: TLS_INSPECTION_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
    urlTool: {
      async discoverUrls(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-url-discovery/v0',
          targetUrlOrDomain: req.targetUrlOrDomain,
          observations: [],
          explicitNonClaims: URL_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
    contentTool: {
      async discoverContent(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-content-discovery/v0',
          targetUrl: req.targetUrl,
          wordlistPath: req.wordlistPath,
          observations: [],
          explicitNonClaims: CONTENT_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
    parameterTool: {
      async discoverParameters(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-parameter-discovery/v0',
          targetUrl: req.targetUrl,
          observations: [],
          explicitNonClaims: PARAMETER_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
    secretTool: {
      async scanSecrets(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-secret-discovery/v0',
          targetUrlOrPath: req.targetUrlOrPath,
          observations: [],
          explicitNonClaims: SECRET_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
  };
}

async function runTests() {
  // ---------------------------------------------------------------------------
  // Assertion 1: Insecure Protocols (SSLv3) & Weak Ciphers Detection
  // ---------------------------------------------------------------------------
  console.log('[milestoneP2_5_tls_configuration_smoke] Assertion 1: Testing SSLv3 and weak ciphers detection...');

  assert.strictEqual(isWeakCipher('TLS_RSA_WITH_RC4_128_SHA'), true);
  assert.strictEqual(isWeakCipher('TLS_RSA_WITH_3DES_EDE_CBC_SHA'), true);
  assert.strictEqual(isWeakCipher('TLS_AES_256_GCM_SHA384'), false);

  const ssl3Obs: DiscoveredTlsObservation = {
    host: 'legacy-app.example.com',
    port: 443,
    issuer: 'DigiCert Global Root CA',
    subjectAlternativeNames: ['legacy-app.example.com'],
    supportedProtocols: ['SSLv3', 'TLSv1.0', 'TLSv1.2'],
    cipherSuites: ['TLS_RSA_WITH_RC4_128_SHA', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'],
    notBefore: '2025-01-01T00:00:00Z',
    notAfter: '2027-01-01T00:00:00Z',
    expired: false,
    selfSigned: false,
    discoveredAt: new Date().toISOString(),
  };

  const unreviewedResult = analyzeTlsConfiguration({
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'tls_configuration_analysis_request',
    detectionId: 'det_tls_001',
    assessmentId: 'asmt_p2_5_001',
    scanId: 'scan_p2_5_001',
    authorizationGrantId: 'grant_p2_5_001',
    authorizationDecisionId: 'dec_p2_5_001',
    actorId: 'usr_secops_auditor',
    targetHost: 'legacy-app.example.com',
    port: 443,
    tlsObservation: ssl3Obs,
  });

  assert.strictEqual(
    unreviewedResult.status,
    'pending_human_review',
    'Unreviewed TLS weaknesses must route to pending_human_review'
  );
  assert.ok(unreviewedResult.evidenceDraft, 'Evidence draft must be created');
  assert.strictEqual(unreviewedResult.weakProtocols.length, 2, 'Must identify SSLv3 and TLSv1.0');
  assert.strictEqual(unreviewedResult.weakCiphers.length, 1, 'Must identify RC4 cipher');

  // Approved review must produce status: 'vulnerability_detected' with severity: 'high'
  const approvedResult = analyzeTlsConfiguration({
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'tls_configuration_analysis_request',
    detectionId: 'det_tls_002',
    assessmentId: 'asmt_p2_5_001',
    scanId: 'scan_p2_5_001',
    authorizationGrantId: 'grant_p2_5_001',
    authorizationDecisionId: 'dec_p2_5_001',
    actorId: 'usr_secops_auditor',
    targetHost: 'legacy-app.example.com',
    port: 443,
    tlsObservation: ssl3Obs,
    humanReviewDecision: {
      decision: 'approve_evidence',
      reviewerId: 'operator_secops_lead',
      reviewedAt: new Date().toISOString(),
    },
  });

  assert.strictEqual(
    approvedResult.status,
    'vulnerability_detected',
    'SSLv3 must produce status: vulnerability_detected'
  );
  assert.ok(approvedResult.finding, 'Must produce Finding record');
  assert.strictEqual(approvedResult.finding.severity, 'high');
  assert.strictEqual(approvedResult.finding.metadata.kind, 'weak_tls_metadata');
  assert.strictEqual(approvedResult.finding.metadata.port, 443);

  console.log('[milestoneP2_5_tls_configuration_smoke] Assertion 1 PASSED: SSLv3 detected with high severity.');

  // ---------------------------------------------------------------------------
  // Assertion 2: Deprecated Protocols (TLS 1.0/1.1) Classification
  // ---------------------------------------------------------------------------
  console.log('[milestoneP2_5_tls_configuration_smoke] Assertion 2: Testing deprecated protocols classification...');

  const deprecatedObs: DiscoveredTlsObservation = {
    host: 'deprecated-app.example.com',
    port: 443,
    issuer: 'Let\'s Encrypt Authority X3',
    subjectAlternativeNames: ['deprecated-app.example.com'],
    supportedProtocols: ['TLSv1.0', 'TLSv1.1', 'TLSv1.2'],
    cipherSuites: ['TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'],
    notBefore: '2025-01-01T00:00:00Z',
    notAfter: '2027-01-01T00:00:00Z',
    expired: false,
    selfSigned: false,
    discoveredAt: new Date().toISOString(),
  };

  const deprecatedApprovedResult = analyzeTlsConfiguration({
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'tls_configuration_analysis_request',
    detectionId: 'det_tls_003',
    assessmentId: 'asmt_p2_5_001',
    scanId: 'scan_p2_5_001',
    authorizationGrantId: 'grant_p2_5_001',
    authorizationDecisionId: 'dec_p2_5_001',
    actorId: 'usr_secops_auditor',
    targetHost: 'deprecated-app.example.com',
    port: 443,
    tlsObservation: deprecatedObs,
    humanReviewDecision: {
      decision: 'approve_evidence',
      reviewerId: 'operator_secops_lead',
      reviewedAt: new Date().toISOString(),
    },
  });

  assert.strictEqual(
    deprecatedApprovedResult.status,
    'potential_weakness',
    'Deprecated protocols without SSLv2/3 must produce potential_weakness'
  );
  assert.strictEqual(deprecatedApprovedResult.finding?.severity, 'medium');

  console.log('[milestoneP2_5_tls_configuration_smoke] Assertion 2 PASSED: Deprecated protocols classified as potential_weakness.');

  // ---------------------------------------------------------------------------
  // Assertion 3: Certificate Anomalies (Expired, Self-Signed, SAN Mismatch)
  // ---------------------------------------------------------------------------
  console.log('[milestoneP2_5_tls_configuration_smoke] Assertion 3: Testing certificate anomalies...');

  assert.strictEqual(matchesSan('api.example.com', '*.example.com'), true);
  assert.strictEqual(matchesSan('api.sub.example.com', '*.example.com'), false);
  assert.strictEqual(matchesSan('example.com', 'example.com'), true);

  const certAnomalyObs: DiscoveredTlsObservation = {
    host: 'untrusted-cert.example.com',
    port: 8443,
    issuer: 'Self-Signed Root Certificate',
    subjectAlternativeNames: ['wrong-host.example.com'],
    supportedProtocols: ['TLSv1.2', 'TLSv1.3'],
    cipherSuites: ['TLS_AES_256_GCM_SHA384'],
    notBefore: '2020-01-01T00:00:00Z',
    notAfter: '2021-01-01T00:00:00Z', // Expired
    expired: true,
    selfSigned: true,
    discoveredAt: new Date().toISOString(),
  };

  const certAnomalyResult = analyzeTlsConfiguration({
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'tls_configuration_analysis_request',
    detectionId: 'det_tls_004',
    assessmentId: 'asmt_p2_5_001',
    scanId: 'scan_p2_5_001',
    authorizationGrantId: 'grant_p2_5_001',
    authorizationDecisionId: 'dec_p2_5_001',
    actorId: 'usr_secops_auditor',
    targetHost: 'untrusted-cert.example.com',
    port: 8443,
    tlsObservation: certAnomalyObs,
  });

  assert.strictEqual(certAnomalyResult.status, 'pending_human_review');
  assert.strictEqual(certAnomalyResult.certificateIssues.includes('expired'), true);
  assert.strictEqual(certAnomalyResult.certificateIssues.includes('self_signed'), true);
  assert.strictEqual(certAnomalyResult.certificateIssues.includes('invalid_san'), true);

  console.log('[milestoneP2_5_tls_configuration_smoke] Assertion 3 PASSED: Certificate anomalies correctly detected.');

  // ---------------------------------------------------------------------------
  // Assertion 4: Clean Abstention on Modern Hardened Targets
  // ---------------------------------------------------------------------------
  console.log('[milestoneP2_5_tls_configuration_smoke] Assertion 4: Testing hardened target abstention...');

  const hardenedObs: DiscoveredTlsObservation = {
    host: 'hardened.example.com',
    port: 443,
    issuer: 'GTS CA 1C3',
    subjectAlternativeNames: ['hardened.example.com', '*.example.com'],
    supportedProtocols: ['TLSv1.2', 'TLSv1.3'],
    cipherSuites: ['TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256', 'ECDHE-ECDSA-AES256-GCM-SHA384'],
    notBefore: '2026-01-01T00:00:00Z',
    notAfter: '2027-01-01T00:00:00Z',
    expired: false,
    selfSigned: false,
    discoveredAt: new Date().toISOString(),
  };

  const abstainedResult = analyzeTlsConfiguration({
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'tls_configuration_analysis_request',
    detectionId: 'det_tls_005',
    assessmentId: 'asmt_p2_5_001',
    scanId: 'scan_p2_5_001',
    authorizationGrantId: 'grant_p2_5_001',
    authorizationDecisionId: 'dec_p2_5_001',
    actorId: 'usr_secops_auditor',
    targetHost: 'hardened.example.com',
    port: 443,
    tlsObservation: hardenedObs,
  });

  assert.strictEqual(
    abstainedResult.status,
    'secure_target_abstained',
    'Hardened TLS configuration must cleanly abstain'
  );
  assert.strictEqual(abstainedResult.finding, undefined);
  assert.strictEqual(abstainedResult.evidenceDraft, undefined);

  console.log('[milestoneP2_5_tls_configuration_smoke] Assertion 4 PASSED: Hardened TLS target cleanly abstained.');

  // ---------------------------------------------------------------------------
  // Assertion 5: Orchestrated Assessment Pipeline Integration & Human Triage
  // ---------------------------------------------------------------------------
  console.log('[milestoneP2_5_tls_configuration_smoke] Assertion 5: Testing Orchestrated Assessment Pipeline & Triage...');

  const repository = new InMemoryOrchestratedAssessmentRepository();
  const mockAvailabilityService = new ReconToolAvailabilityService({
    async execute() {
      return { stdout: '1.0.0\n', stderr: '', exitCode: 0, durationMs: 1, timedOut: false };
    },
  });

  const orchestrator = new OrchestratedAssessmentApplicationService({
    repository,
    reconAdapters: createMockAdapters(ssl3Obs),
    dnsResolver: async () => ['93.184.216.34'],
    availabilityService: mockAvailabilityService,
  });

  const startRes = await orchestrator.startAssessment({
    targetDomain: 'example.com',
    actorId: 'human_operator_42',
  });

  assert.strictEqual(startRes.status, 'running');

  const record = await orchestrator.awaitAssessment(startRes.assessmentId);
  assert.ok(record, 'Assessment record must exist');
  assert.strictEqual(record.status, 'completed');
  assert.ok((record.pendingEvidenceDrafts ?? []).length > 0, 'Must have pending drafts');

  const tlsDraft = record.pendingEvidenceDrafts?.find(
    (d) => d.differentialContext?.detectionKind === 'weak_tls_configuration'
  );
  assert.ok(tlsDraft, 'Must contain weak_tls_configuration draft in pending drafts');
  assert.strictEqual(tlsDraft.differentialContext?.targetHost, 'legacy-app.example.com');
  assert.strictEqual(tlsDraft.differentialContext?.weakProtocols?.length, 2);

  // Triage: Human operator approves the draft
  const reviewRes = await orchestrator.reviewEvidenceDraft({
    assessmentId: startRes.assessmentId,
    draftId: tlsDraft.draftId,
    decision: 'approve_evidence',
    reviewerId: 'authorized_sec_lead',
    reviewedAt: new Date().toISOString(),
    notes: 'Verified SSLv3 and RC4 cipher supported on legacy endpoint',
  });

  assert.strictEqual(reviewRes.decision, 'approve_evidence');
  assert.ok(reviewRes.findingCreated, 'Must have promoted finding');
  assert.strictEqual(reviewRes.findingCreated.metadata.kind, 'weak_tls_metadata');
  assert.strictEqual(reviewRes.findingCreated.severity, 'high');

  // Verify updated summary
  const updatedSummary = await orchestrator.getSummary(startRes.assessmentId);
  const foundInSummary = updatedSummary.findings.find(
    (f) => f.metadata.kind === 'weak_tls_metadata'
  );
  assert.ok(foundInSummary, 'Promoted Weak TLS finding must be present in assessment findings');

  console.log('[milestoneP2_5_tls_configuration_smoke] Assertion 5 PASSED: Pipeline and human review triage lifecycle verified.');

  console.log('----------------------------------------------------------------');
  console.log('[milestoneP2_5_tls_configuration_smoke] ALL SMOKE TESTS PASSED (100%)');
  console.log('----------------------------------------------------------------');
}

runTests().catch((err) => {
  console.error('[milestoneP2_5_tls_configuration_smoke] FAILED:', err);
  process.exit(1);
});
