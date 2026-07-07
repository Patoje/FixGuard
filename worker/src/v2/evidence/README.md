# Evidence Boundary

M45 defines DB-free evidence boundary contracts. It separates the concepts of:
- `ObservationRecord`
- `IndicatorRecord`
- `EvidenceRecord`
- `FindingCandidateRecord`
- `SafeReportItemSnapshot`

### Key Principles

- **FindingCandidate is not a real finding.** It is a candidate that requires human review.
- **EvidenceRecord is not persisted evidence.** It is an in-memory representation during the promotion boundary.
- **SafeReportItemSnapshot is not a final vulnerability report.** It explicitly declares it is not ready for external delivery without review.
- **M45 does not create real persisted findings.** 
- **M45 does not persist evidence records.**
- **M45 does not confirm vulnerabilities.**
- **M45 does not make risk/severity/impact claims.** It enforces a `SeverityGate` that blocks assignment until human review.
- **M45 does not execute tools.** It is a pure logic boundary.
- **M45 prevents raw tool output from becoming a finding directly.** A tool output observation must be correlated with an indicator and further validated by evidence before it can be promoted.
- **M45 requires later human review for external delivery.** Explicit flags (`notForExternalDelivery: true`, `requiresHumanReview: true`) enforce this.

### No Claims

All records within this boundary are rigidly constrained to output:
```ts
createsRealFindings: false
createsPersistedEvidence: false
confirmsVulnerabilities: false
makesRiskClaims: false
makesSeverityClaims: false
makesImpactClaims: false
```
