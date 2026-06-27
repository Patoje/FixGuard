import type { Finding, EvidenceCollection } from '../core/Evidence';

export interface EvidenceAccumulator {
  add(collection: EvidenceCollection): void;
  getAllFindings(): Finding[];
}

export class LocalEvidenceAccumulator implements EvidenceAccumulator {
  private findings: Finding[] = [];

  add(collection: EvidenceCollection): void {
    this.findings.push(...collection.findings);
  }

  getAllFindings(): Finding[] {
    return [...this.findings];
  }
}
