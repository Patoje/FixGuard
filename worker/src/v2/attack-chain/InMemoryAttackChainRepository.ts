/**
 * Milestone A6 — In-memory AttackChainRepository
 *
 * Hermetic, mutation-safe persistence for attack-chain hypotheses.
 */

import type { AttackChain } from './AttackChainContracts.js';
import type { AttackChainRepository } from './AttackChainRepository.js';
import { PersistenceConflictError } from '../storage/StorageErrors.js';

function isAttackChainShape(value: unknown): value is AttackChain {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const rec = value as Record<string, unknown>;
  return (
    rec.contractVersion === 'fixguard-attack-chain/v0' &&
    rec.kind === 'attack_chain' &&
    typeof rec.chainId === 'string' &&
    typeof rec.assessmentId === 'string' &&
    typeof rec.scanId === 'string' &&
    typeof rec.hypothesis === 'string' &&
    typeof rec.objectiveKind === 'string' &&
    Array.isArray(rec.steps) &&
    typeof rec.overallEpistemicStatus === 'string' &&
    typeof rec.status === 'string' &&
    typeof rec.impactLevel === 'string' &&
    typeof rec.declaredImpactLevel === 'string' &&
    typeof rec.lineage === 'object' &&
    rec.lineage !== null &&
    typeof rec.createdAt === 'string'
  );
}

export class InMemoryAttackChainRepository implements AttackChainRepository {
  private readonly chains = new Map<string, AttackChain>();

  private clone(chain: AttackChain): AttackChain {
    return JSON.parse(JSON.stringify(chain)) as AttackChain;
  }

  async saveChain(chain: AttackChain): Promise<AttackChain> {
    if (!isAttackChainShape(chain)) {
      throw new Error('Invalid AttackChain: failed exact-key shape validation');
    }
    if (this.chains.has(chain.chainId)) {
      throw new PersistenceConflictError(`Duplicate chainId: ${chain.chainId}`, chain.chainId);
    }
    const cloned = this.clone(chain);
    this.chains.set(cloned.chainId, cloned);
    return this.clone(cloned);
  }

  async updateChain(chain: AttackChain): Promise<AttackChain> {
    if (!isAttackChainShape(chain)) {
      throw new Error('Invalid AttackChain: failed exact-key shape validation');
    }
    const existing = this.chains.get(chain.chainId);
    if (!existing) {
      throw new Error(`AttackChain not found: ${chain.chainId}`);
    }
    if (
      existing.assessmentId !== chain.assessmentId ||
      existing.scanId !== chain.scanId
    ) {
      throw new Error(
        'AttackChain update rejected: assessmentId/scanId isolation violation'
      );
    }
    const cloned = this.clone(chain);
    this.chains.set(cloned.chainId, cloned);
    return this.clone(cloned);
  }

  async getChain(chainId: string): Promise<AttackChain | null> {
    const chain = this.chains.get(chainId);
    return chain ? this.clone(chain) : null;
  }

  async listByAssessmentId(assessmentId: string): Promise<readonly AttackChain[]> {
    const matched = Array.from(this.chains.values()).filter(
      (c) => c.assessmentId === assessmentId
    );
    matched.sort((a, b) => {
      const t = a.createdAt.localeCompare(b.createdAt);
      if (t !== 0) return t;
      return a.chainId.localeCompare(b.chainId);
    });
    return matched.map((c) => this.clone(c));
  }

  async deleteByAssessmentId(assessmentId: string): Promise<number> {
    let removed = 0;
    for (const [id, chain] of this.chains.entries()) {
      if (chain.assessmentId === assessmentId) {
        this.chains.delete(id);
        removed += 1;
      }
    }
    return removed;
  }
}
