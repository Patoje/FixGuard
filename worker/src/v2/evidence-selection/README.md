# FixGuard V2 DB-Free Reviewed Evidence Selection

## Principles
M52 is DB-free and non-persistent.
M52 selects reviewed evidence from M51.
M52 uses M51 read model as primary source boundary.
M52 does not create findings/candidates/report items.
M52 does not confirm vulnerabilities.
M52 does not make severity/risk/impact claims.
M52 does not use Postgres/DB/runtime/API/UI.
M52 returns non-persisted selection sets.
M52 always includes safe M51 summaries.
M52 returns safe refs/summaries only.
M52 can summarize a provided selection set but does not persist/retrieve selection sets.
Future milestones may use selection sets as input.
