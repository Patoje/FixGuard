import type { RawExecutionOutput } from '../core/ExecutionContracts';
import type { EvidenceCollection } from '../core/Evidence';

export interface Parser {
  parse(output: RawExecutionOutput): EvidenceCollection;
}
