/**
 * Milestone A6 — AttackChainRepository port
 *
 * Persistence boundary for attack-chain hypothesis records.
 * Implementations must deep-clone on write/read to prevent shared mutation.
 */

import type { AttackChain } from './AttackChainContracts.js';

export interface AttackChainRepository {
  saveChain(chain: AttackChain): Promise<AttackChain>;
  updateChain(chain: AttackChain): Promise<AttackChain>;
  getChain(chainId: string): Promise<AttackChain | null>;
  listByAssessmentId(assessmentId: string): Promise<readonly AttackChain[]>;
  deleteByAssessmentId(assessmentId: string): Promise<number>;
}
