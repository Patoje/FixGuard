/**
 * F0.2 — Attack plan dependency smoke.
 * A child plan is emitted only when the prior step produced the cited fact
 * or capability. Without that dependency, nothing is emitted.
 */
import assert from 'node:assert/strict';
import type { AttackPlan } from '../attack-planning/AttackPlanContracts.js';
import { emitDependentChildPlan } from '../attack-planning/AttackPlanDependencyService.js';
import { validateAttackPlan } from '../storage/AttackPlanChainPersistenceValidation.js';

const lineage = {
  assessmentId: 'asmt_f0_dep_001',
  scanId: 'scan_f0_dep_001',
  authorizationGrantId: 'grant_f0_dep_001',
  authorizationDecisionId: 'dec_f0_dep_001',
  actorId: 'act_f0_dep_op',
} as const;

const observedAt = '2026-09-28T12:00:00.000Z';
const parentPlanId = 'plan_f0_parent_001';
const factId = 'fact_aabbccdd';

function childPlan(extra: Pick<AttackPlan, 'dependsOn' | 'requiredFactIds' | 'requiredCapabilityGained'>): AttackPlan {
  return {
    contractVersion: 'fixguard-attack-planning/v0',
    kind: 'attack_plan',
    planId: 'plan_f0_child_001',
    assessmentId: lineage.assessmentId,
    scanId: lineage.scanId,
    capability: 'idor_read_differential',
    title: 'Child read differential',
    reasoning: 'Emitted only after the prior step produced the required fact or capability.',
    status: 'prerequisite_missing',
    blastRadius: 'single_resource',
    capabilityGained: 'read_authenticated',
    sourceFindingIds: [],
    sourceFindingTypes: ['observed_surface'],
    prerequisites: [],
    steps: [
      {
        stepId: 'step_child_1',
        ordinal: 1,
        title: 'Compare reads',
        description: 'Advisory read comparison. Not executed by this emitter.',
        status: 'blocked',
        requiredPermissions: ['activeValidation'],
      },
    ],
    planOrigin: 'observed_surface',
    lineage,
    createdAt: observedAt,
    executable: false,
    ...extra,
  };
}

async function main(): Promise<void> {
  console.log('=== F0.2 plan dependency smoke ===');

  const missingFact = emitDependentChildPlan({
    prior: {
      planId: parentPlanId,
      producedFactIds: [],
      capabilityGained: 'none',
    },
    child: childPlan({
      dependsOn: [parentPlanId],
      requiredFactIds: [factId],
    }),
  });
  assert.equal(missingFact.status, 'not_emitted');
  if (missingFact.status === 'not_emitted') {
    assert.equal(missingFact.reasonCode, 'dependency_not_produced');
  }
  console.log('[+] child plan is not emitted when the prior step lacks the fact');

  const missingDependsOn = emitDependentChildPlan({
    prior: {
      planId: parentPlanId,
      producedFactIds: [factId],
      capabilityGained: 'read_authenticated',
    },
    child: childPlan({}),
  });
  assert.equal(missingDependsOn.status, 'not_emitted');
  if (missingDependsOn.status === 'not_emitted') {
    assert.equal(missingDependsOn.reasonCode, 'dependency_not_declared');
  }
  console.log('[+] child plan is not emitted without dependsOn');

  const emitted = emitDependentChildPlan({
    prior: {
      planId: parentPlanId,
      producedFactIds: [factId],
      capabilityGained: 'none',
    },
    child: childPlan({
      dependsOn: [parentPlanId],
      requiredFactIds: [factId],
    }),
  });
  assert.equal(emitted.status, 'emitted');
  if (emitted.status === 'emitted') {
    assert.equal(emitted.plan.executable, false);
    assert.deepEqual(emitted.plan.requiredFactIds, [factId]);
    assert.equal(validateAttackPlan(emitted.plan), true);
    const leaked = { ...emitted.plan, executable: true, severity: 'high' };
    assert.equal(validateAttackPlan(leaked), false);
  }
  console.log('[+] child plan emits when the fact was produced and stays non-executable');

  const byCapability = emitDependentChildPlan({
    prior: {
      planId: parentPlanId,
      producedFactIds: [],
      capabilityGained: 'read_authenticated',
    },
    child: childPlan({
      dependsOn: [parentPlanId],
      requiredCapabilityGained: 'read_authenticated',
    }),
  });
  assert.equal(byCapability.status, 'emitted');
  if (byCapability.status === 'emitted') {
    assert.equal(byCapability.plan.executable, false);
    assert.equal(validateAttackPlan(byCapability.plan), true);
  }

  const capabilityMiss = emitDependentChildPlan({
    prior: {
      planId: parentPlanId,
      producedFactIds: [],
      capabilityGained: 'none',
    },
    child: childPlan({
      dependsOn: [parentPlanId],
      requiredCapabilityGained: 'read_authenticated',
    }),
  });
  assert.equal(capabilityMiss.status, 'not_emitted');
  console.log('[+] capability dependency emits only when the prior step gained it');

  const bothRequired = emitDependentChildPlan({
    prior: {
      planId: parentPlanId,
      producedFactIds: [],
      capabilityGained: 'read_authenticated',
    },
    child: childPlan({
      dependsOn: [parentPlanId],
      requiredFactIds: [factId],
      requiredCapabilityGained: 'read_authenticated',
    }),
  });
  assert.equal(bothRequired.status, 'not_emitted');
  console.log('[+] a plan that cites both fact and capability waits until both exist');

  console.log('=== F0.2 plan dependency smoke: ALL PASSED ===');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
