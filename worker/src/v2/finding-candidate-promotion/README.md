# Reviewed Evidence Finding Candidate Promotion (M54)

## Goal
The `finding-candidate-promotion` boundary handles the creation of a `ReviewedEvidenceFormalFindingCandidate` by consuming a strictly validated M53 `ReviewedEvidenceFindingCandidateDraft` and an explicit human triage decision. This represents the human authorization step required to promote triaged evidence into formal candidates.

## M54 Constraints
- M54 is DB-free and non-persistent.
- M54 consumes validated M53 finding candidate drafts.
- M54 requires explicit human triage approval to create a formal candidate.
- M54 creates non-persisted M54 formal finding candidates only.
- M54 does not create M45 finding candidates.
- M54 does not create confirmed findings.
- M54 does not create safe report items or external reports.
- M54 does not confirm vulnerabilities.
- M54 does not make exploitability/severity/risk/impact claims.
- M54 does not provide remediation advice.
- M54 does not use Postgres/DB/runtime/API/UI.

Future milestones may adapt M54 candidates to M45-compatible records or route them to explicit finding/report workflows.
