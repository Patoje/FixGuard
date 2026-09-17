/**
 * Milestone P3-1 Smoke Test Suite
 * BYOT Session Injection Contract & Anti-Leak Boundary (Milestone P3-1)
 *
 * Verifies:
 * 1. parseStartOrchestratedAssessmentBody parses valid ByotSessionIdentityBundle and rejects invalid payloads.
 * 2. buildProbeAuthContext maps ByotIdentity to frozen ProbeAuthContext with normalized headers.
 * 3. sanitizeEvidenceFragment redacts JWTs, Bearer tokens, cookies, and secrets from raw fragments.
 * 4. Anti-Persistence Invariant: JSON.stringify(record) after an authenticated run contains ZERO session secrets.
 */

import {
  parseStartOrchestratedAssessmentBody,
  parseByotIdentity,
  parseByotSessionIdentityBundle,
} from '../api/validation/ApiRequestValidators.js';
import {
  buildProbeAuthContext,
  buildAnonymousProbeContext,
  OrchestratedAssessmentApplicationService,
} from '../application/OrchestratedAssessmentApplicationService.js';
import { sanitizeEvidenceFragment } from '../core/EvidenceSanitizer.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';
import { ApiValidationError } from '../api/ApiErrors.js';
import type { ByotIdentity, ByotSessionIdentityBundle } from '../detection/DetectionContracts.js';

import { ReconToolAvailabilityService } from '../capabilities/ReconToolAvailabilityService.js';

console.log('[milestoneP3_1_byot_smoke] Starting Milestone P3-1 smoke suite...');

async function runTests(): Promise<void> {
  // Test 1: Validation of ByotIdentity & ByotSessionIdentityBundle
  console.log('-> Test 1: API Request Validation for BYOT Identifies');

  // 1.1 Valid Bundle
  const validPayload = {
    targetDomain: 'target.example.com',
    actorId: 'usr_operator_01',
    sessionIdentities: {
      identityA: {
        identityId: 'user_admin_01',
        injectHeaders: {
          Authorization: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.do_not_leak',
          'X-Custom-Auth': 'secret-token-value-12345',
        },
        injectCookies: {
          session_id: 'sess_secret_cookie_abcdef',
        },
      },
      identityB: {
        identityId: 'user_guest_02',
        injectHeaders: {
          Authorization: 'Bearer guest_token_secret_xyz',
        },
      },
    },
  };

  const parsed = parseStartOrchestratedAssessmentBody(validPayload);
  if (!parsed.sessionIdentities || !parsed.sessionIdentities.identityA || !parsed.sessionIdentities.identityB) {
    throw new Error('Test 1.1 Failed: sessionIdentities not parsed properly');
  }
  if (parsed.sessionIdentities.identityA.identityId !== 'user_admin_01') {
    throw new Error('Test 1.1 Failed: identityA.identityId mismatch');
  }
  console.log('  [PASS] Valid ByotSessionIdentityBundle parsed successfully.');

  // 1.2 Malformed Extra Keys (Closed-world)
  let rejectedExtraKey = false;
  try {
    parseStartOrchestratedAssessmentBody({
      targetDomain: 'target.example.com',
      sessionIdentities: {
        identityA: {
          identityId: 'valid_id',
          unauthorizedField: 'malicious_data',
        },
      },
    });
  } catch (err) {
    if (err instanceof ApiValidationError && err.message.includes('unexpected field')) {
      rejectedExtraKey = true;
    }
  }
  if (!rejectedExtraKey) {
    throw new Error('Test 1.2 Failed: Closed-world validation did not reject unknown key');
  }
  console.log('  [PASS] Closed-world rejection of unknown fields in ByotIdentity.');

  // 1.3 Invalid Safe ID Pattern
  let rejectedIllegalId = false;
  try {
    parseByotIdentity({
      identityId: 'invalid ID with spaces!!',
    });
  } catch (err) {
    if (err instanceof ApiValidationError) {
      rejectedIllegalId = true;
    }
  }
  if (!rejectedIllegalId) {
    throw new Error('Test 1.3 Failed: Illegal identityId was not rejected');
  }
  console.log('  [PASS] Illegal identityId rejected with strict identifier checks.');

  // 1.4 Oversized Value (> 4096 chars)
  let rejectedOversized = false;
  try {
    parseByotIdentity({
      identityId: 'valid_id',
      injectHeaders: {
        Authorization: 'Bearer ' + 'A'.repeat(5000),
      },
    });
  } catch (err) {
    if (err instanceof ApiValidationError && err.message.includes('exceeds maximum allowed length')) {
      rejectedOversized = true;
    }
  }
  if (!rejectedOversized) {
    throw new Error('Test 1.4 Failed: Oversized header value was not rejected');
  }
  console.log('  [PASS] Oversized header values rejected (> 4096 chars).');

  // Test 2: In-Memory Lifecycle Mapping (buildProbeAuthContext)
  console.log('-> Test 2: In-Memory Lifecycle Mapping (buildProbeAuthContext)');
  const rawIdentity: ByotIdentity = {
    identityId: 'operator_id_1',
    injectHeaders: {
      Authorization: 'Bearer secret_jwt_token',
      'X-CSRF-TOKEN': 'csrf_secret_999',
    },
    injectCookies: {
      'connect.sid': 's%3Asession_cookie_value',
    },
  };

  const authContext = buildProbeAuthContext(rawIdentity);
  if (authContext.identityId !== 'operator_id_1') {
    throw new Error('Test 2 Failed: identityId mismatch in ProbeAuthContext');
  }
  if (authContext.headers?.['authorization'] !== 'Bearer secret_jwt_token') {
    throw new Error('Test 2 Failed: authorization header was not lowercase-normalized');
  }
  if (authContext.headers?.['x-csrf-token'] !== 'csrf_secret_999') {
    throw new Error('Test 2 Failed: x-csrf-token header was not lowercase-normalized');
  }
  if (authContext.cookies?.['connect.sid'] !== 's%3Asession_cookie_value') {
    throw new Error('Test 2 Failed: cookies not preserved in ProbeAuthContext');
  }
  if (!Object.isFrozen(authContext) || !Object.isFrozen(authContext.headers)) {
    throw new Error('Test 2 Failed: ProbeAuthContext is not frozen');
  }

  const anonContext = buildAnonymousProbeContext('anon_user');
  if (anonContext.identityId !== 'anon_user' || Object.keys(anonContext.headers ?? {}).length !== 0) {
    throw new Error('Test 2 Failed: Anonymous probe context invalid');
  }
  console.log('  [PASS] buildProbeAuthContext maps normalized headers to frozen context.');

  // Test 3: Anti-Leak Evidence Sanitizer
  console.log('-> Test 3: Anti-Leak Evidence Sanitizer');
  const sampleLeakText = `
    HTTP/1.1 200 OK
    Set-Cookie: sessionid=secret_session_value_987654; Path=/; Secure; HttpOnly
    Authorization: Bearer token_sample_abc123456789
    Raw-Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
    X-Auth-Token: "auth_token_secret_secret_12345"
    Basic YWRtaW46cGFzc3dvcmQxMjM=
    Body: {"status": "ok", "api_key": "mock_api_key_secret_99887766"}
  `;

  const sanitized = sanitizeEvidenceFragment(sampleLeakText, 500);

  // Assertions: All secrets redacted
  if (sanitized.includes('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9')) {
    throw new Error('Test 3 Failed: JWT was not redacted!');
  }
  if (sanitized.includes('secret_session_value_987654')) {
    throw new Error('Test 3 Failed: Cookie sessionid was not redacted!');
  }
  if (sanitized.includes('auth_token_secret_secret_12345')) {
    throw new Error('Test 3 Failed: Auth token was not redacted!');
  }
  if (sanitized.includes('YWRtaW46cGFzc3dvcmQxMjM=')) {
    throw new Error('Test 3 Failed: Basic auth was not redacted!');
  }
  if (sanitized.includes('mock_api_key_secret_99887766')) {
    throw new Error('Test 3 Failed: API key was not redacted!');
  }
  if (!sanitized.includes('[REDACTED_JWT]') || !sanitized.includes('[REDACTED_TOKEN]')) {
    throw new Error('Test 3 Failed: Redaction placeholders missing');
  }
  console.log('  [PASS] sanitizeEvidenceFragment cleanly redacts JWTs, Bearer, Basic, and API keys.');

  // Test 4: Anti-Persistence Invariant
  console.log('-> Test 4: Anti-Persistence Invariant (BYOT-SI-01 through BYOT-SI-06)');
  const repo = new InMemoryOrchestratedAssessmentRepository();
  const mockAvailabilityService = new ReconToolAvailabilityService({
    async execute() {
      return { stdout: '1.0.0\n', stderr: '', exitCode: 0, durationMs: 1, timedOut: false };
    },
  });

  const service = new OrchestratedAssessmentApplicationService({
    repository: repo,
    dnsResolver: async () => ['93.184.216.34'],
    availabilityService: mockAvailabilityService,
  });

  const secretJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.super_secret_signature';
  const secretCookie = 'session_super_secret_cookie_value_999';

  const startRes = await service.startAssessment({
    targetDomain: 'target.example.com',
    actorId: 'usr_secops_lead',
    sessionIdentities: {
      identityA: {
        identityId: 'user_admin',
        injectHeaders: {
          authorization: `Bearer ${secretJwt}`,
        },
        injectCookies: {
          session: secretCookie,
        },
      },
    },
  });

  const persistedRecord = await repo.findById(startRes.assessmentId);
  if (!persistedRecord) {
    throw new Error('Test 4 Failed: Record was not persisted');
  }

  const serialized = JSON.stringify(persistedRecord);
  if (serialized.includes(secretJwt)) {
    throw new Error('Test 4 VIOLATION: Ephemeral JWT leaked into persisted repository record!');
  }
  if (serialized.includes(secretCookie)) {
    throw new Error('Test 4 VIOLATION: Ephemeral Cookie leaked into persisted repository record!');
  }
  if ('sessionIdentities' in persistedRecord) {
    throw new Error('Test 4 VIOLATION: sessionIdentities key leaked into OrchestratedAssessmentRecord!');
  }
  console.log('  [PASS] ZERO session credentials persisted to storage (Anti-Persistence Verified).');

  console.log('[milestoneP3_1_byot_smoke] ALL SMOKE TESTS PASSED (100%)');
}

runTests().catch((err) => {
  console.error('[milestoneP3_1_byot_smoke] TEST FAILED:', err);
  process.exit(1);
});
