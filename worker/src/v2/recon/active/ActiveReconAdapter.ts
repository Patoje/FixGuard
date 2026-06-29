import type { ActiveReconProbeRequest, SafeActiveReconObservation } from './ActiveReconContracts.js';

export interface ActiveReconAdapter {
  probe(request: ActiveReconProbeRequest): Promise<SafeActiveReconObservation[]>;
}
