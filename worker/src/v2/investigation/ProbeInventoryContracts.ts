/**
 * Phase 1 — probe inventory built from recon observations already returned
 * by the composite orchestrator. Discovery catalog only: no probes, no
 * detectors, no authorization minting.
 */

import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';

export const PROBE_INVENTORY_CONTRACT_VERSION = 'fixguard-probe-inventory/v0' as const;

export type ProbeInventoryContractVersion = typeof PROBE_INVENTORY_CONTRACT_VERSION;

/**
 * One in-scope URL the orchestrator already observed.
 * `method` is the method on the raw observation when that observation carried one.
 */
export interface ProbeInventoryEntry {
  readonly origin: string;
  readonly path: string;
  readonly method: string;
  readonly parameters: readonly string[];
  readonly sources: readonly string[];
}

export interface ProbeInventory {
  readonly contractVersion: ProbeInventoryContractVersion;
  readonly kind: 'probe_inventory';
  readonly assessmentId: string;
  readonly scanId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly entries: readonly ProbeInventoryEntry[];
}

export type ProbeInventoryLineage = AuthorizedActiveReconRequestLineage;
