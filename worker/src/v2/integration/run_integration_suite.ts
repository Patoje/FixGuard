/**
 * FixGuard V2 — Level 2 Real Target Integration Suite Runner (Milestone P1-2)
 *
 * Orchestrates Level 2 real execution tests against authorized, low-risk public targets
 * without mock transports (using real ProcessRunner, real CLI binaries, and real network).
 *
 * Invariant:
 * Runs only when RUN_INTEGRATION=true is explicitly set in the environment.
 * Otherwise, cleanly skips execution with diagnostic notice (exit code 0).
 */

import process from 'node:process';

import { runRealSsrfContainmentSmoke } from './real_ssrf_containment_smoke.js';
import { runRealTargetDnsSmoke } from './real_target_dns_smoke.js';
import { runRealTargetHttpxSmoke } from './real_target_httpx_smoke.js';

async function main(): Promise<void> {
  const isEnabled = process.env.RUN_INTEGRATION === 'true';

  if (!isEnabled) {
    console.log('\n[INFO] RUN_INTEGRATION is not set to "true".');
    console.log('Skipping Level 2 Real Target Integration Suite.');
    console.log('To execute real binary reconnaissance tests against authorized public targets, run:');
    console.log('  RUN_INTEGRATION=true npm run test:v2:integration\n');
    process.exit(0);
  }

  console.log('\n================================================================');
  console.log('=== FIXGUARD V2 LEVEL 2 REAL TARGET INTEGRATION SUITE (P1-2) ===');
  console.log('================================================================\n');

  try {
    // 1. SSRF Boundary & Preflight Gate Containment in Real Context
    await runRealSsrfContainmentSmoke();
    console.log('');

    // 2. Real Target DNS Resolution (dnsx against example.com)
    await runRealTargetDnsSmoke();
    console.log('');

    // 3. Real Target Web Inspection (httpx against scanme.nmap.org)
    await runRealTargetHttpxSmoke();
    console.log('');

    console.log('================================================================');
    console.log('>>> ALL FIXGUARD V2 LEVEL 2 INTEGRATION TESTS PASSED (100%) <<<');
    console.log('================================================================\n');
  } catch (err) {
    console.error('\n[!] Level 2 Real Target Integration Suite FAILED:', err);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error('[!] Unexpected error in integration runner:', err);
  process.exit(1);
});
