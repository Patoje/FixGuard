import type { CapabilityRequest } from '../../core/ExecutionContracts';
import type { EvidenceCollection } from '../../core/Evidence';

export interface PassiveCapabilityExecutor {
  execute(request: CapabilityRequest): Promise<EvidenceCollection>;
}
