/**
 * F1.7 — Single wait policy on 429 and 5xx.
 * Reuses TargetExecutionCoordinator pacing. Does not add a second limiter.
 */
import assert from 'node:assert/strict';
import { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';
import {
  TargetExecutionCancelledError,
  TargetInstabilityError,
} from '../runtime/CircuitBreakerContracts.js';

const HOST = 'pace.example.com';

async function main(): Promise<void> {
  console.log('=== F1.7 status pacing smoke ===');

  {
    const coordinator = new TargetExecutionCoordinator({
      requestsPerSecond: 1000,
      maxConcurrency: 1,
    });
    let calls = 0;
    const result = await coordinator.executeWithStatusPacing(HOST, async () => {
      calls++;
      return { statusCode: calls < 3 ? 429 : 200 };
    });
    assert.equal(result.statusCode, 200);
    assert.equal(calls, 3);
    assert.equal(coordinator.getCircuitState(HOST), 'CLOSED');
    assert.equal(coordinator.getCircuitStats(HOST).consecutiveFailures, 0);
    console.log('[+] 429 waits through the existing pacing slot and retries');
  }

  {
    const coordinator = new TargetExecutionCoordinator({
      requestsPerSecond: 1000,
      maxConcurrency: 1,
    });
    coordinator.recordTargetResponse(HOST, 500);
    const result = await coordinator.executeWithStatusPacing(
      HOST,
      async () => ({ statusCode: 429 }),
      { max429Retries: 1 }
    );
    assert.equal(result.statusCode, 429);
    assert.equal(coordinator.getCircuitState(HOST), 'CLOSED');
    assert.equal(coordinator.getCircuitStats(HOST).consecutiveFailures, 1);
    assert.equal(coordinator.getCircuitStats(HOST).total5xxErrors, 1);
    console.log('[+] 429 neither resets nor trips the circuit');
  }

  {
    const coordinator = new TargetExecutionCoordinator({
      requestsPerSecond: 1000,
      maxConcurrency: 1,
      circuitBreakerConfig: {
        consecutive5xxThreshold: 3,
        consecutiveErrorThreshold: 3,
        halfOpenSuccessThreshold: 2,
        openCooldownMs: 30_000,
      },
    });
    let calls = 0;
    const task = async (): Promise<{ statusCode: number }> => {
      calls++;
      return { statusCode: 503 };
    };
    assert.equal((await coordinator.executeWithStatusPacing(HOST, task)).statusCode, 503);
    assert.equal((await coordinator.executeWithStatusPacing(HOST, task)).statusCode, 503);
    assert.equal(coordinator.isCircuitOpen(HOST), false);
    await assert.rejects(
      coordinator.executeWithStatusPacing(HOST, task),
      (err: unknown) => err instanceof TargetInstabilityError
    );
    assert.equal(calls, 3);
    assert.equal(coordinator.isCircuitOpen(HOST), true);
    let laterRan = false;
    await assert.rejects(
      coordinator.execute(HOST, async () => {
        laterRan = true;
        return { statusCode: 200 };
      }),
      (err: unknown) => err instanceof TargetInstabilityError
    );
    assert.equal(laterRan, false);
    console.log('[+] open circuit stops the queue');
  }

  {
    const coordinator = new TargetExecutionCoordinator({
      requestsPerSecond: 1,
      maxConcurrency: 1,
    });
    let calls = 0;
    const pending = coordinator.executeWithStatusPacing(
      HOST,
      async () => {
        calls++;
        return { statusCode: 429 };
      },
      { max429Retries: 5 }
    );
    await new Promise((resolve) => setTimeout(resolve, 30));
    coordinator.cancel(HOST);
    await assert.rejects(pending, (err: unknown) => err instanceof TargetExecutionCancelledError);
    const callsAtCancel = calls;
    await new Promise((resolve) => setTimeout(resolve, 40));
    assert.equal(calls, callsAtCancel);
    assert.ok(calls < 6);
    await assert.rejects(
      coordinator.execute(HOST, async () => ({ statusCode: 200 })),
      (err: unknown) => err instanceof TargetExecutionCancelledError
    );
    console.log('[+] cancel stops the retry loop and rejects queued work');
  }

  console.log('=== F1.7 status pacing smoke: ALL PASSED ===');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
