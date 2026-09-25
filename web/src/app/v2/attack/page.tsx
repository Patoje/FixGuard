"use client";

import React, { useCallback, useEffect, useMemo, useState, Suspense } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
  Crosshair,
  ArrowLeft,
  AlertCircle,
  ChevronDown,
  ChevronRight,
} from "lucide-react";
import {
  v2AttackApi,
  V2ApiError,
  buildWorkbenchScopeGrant,
  type AttackPlan,
  type AttackChain,
  type AttackExecutionRecordDto,
  type PostExploitationState,
  type LateralMovementSnapshot,
  type ImpactAssessment,
  type BlastRadiusClass,
  type LateralMovementMechanism,
  type AuthorizeAttackPlanResponse,
  type ActiveInvestigationSnapshotDto,
} from "@/lib/v2AttackApi";
import {
  getOrchestratedAssessmentSummary,
  type LineageTuple,
} from "@/lib/v2Api";
import { isStrictSafeId } from "@/lib/v2/idGenerator";
import { AttackPlansList } from "./components/AttackPlansList";
import { AttackAuthorizationModal } from "./components/AttackAuthorizationModal";
import { StepExecutionMonitor } from "./components/StepExecutionMonitor";
import { AttackChainViewer } from "./components/AttackChainViewer";
import { PostExploitationPanel } from "./components/PostExploitationPanel";
import { ImpactAssessmentView } from "./components/ImpactAssessmentView";
import { AttackRecommendationCards } from "./components/AttackRecommendationCards";
import type { OperatorAttackRecommendation } from "@/lib/v2AttackApi";

type ResultsPanel = "chains" | "impact" | "post_exploit" | null;

export type AttackModeContentProps = {
  readonly forcedAssessmentId?: string;
  readonly embedded?: boolean;
  readonly onContinueToReport?: () => void;
};

const LATERAL_MECHANISMS: ReadonlySet<string> = new Set([
  "credential_reuse",
  "session_token_reuse",
  "api_key_reuse",
  "oauth_token_scope",
  "shared_auth_backend",
  "cors_credential_relay",
  "trust_relationship",
  "subdomain_session_share",
]);

function asLateralMechanism(value: string): LateralMovementMechanism {
  if (LATERAL_MECHANISMS.has(value)) {
    return value as LateralMovementMechanism;
  }
  return "credential_reuse";
}

function AttackModeContent({
  forcedAssessmentId,
  embedded = false,
  onContinueToReport,
}: AttackModeContentProps) {
  const searchParams = useSearchParams();
  const assessmentIdFromQuery =
    forcedAssessmentId || searchParams.get("assessmentId") || "";

  const [assessmentId, setAssessmentId] = useState(assessmentIdFromQuery);
  const [operatorId] = useState("usr_secops_lead");
  const [targetDomain, setTargetDomain] = useState("");
  const [lineage, setLineage] = useState<LineageTuple | null>(null);

  const [prevQueryId, setPrevQueryId] = useState(assessmentIdFromQuery);
  if (assessmentIdFromQuery !== prevQueryId) {
    setPrevQueryId(assessmentIdFromQuery);
    if (assessmentIdFromQuery) {
      setAssessmentId(assessmentIdFromQuery);
    }
  }

  const [plans, setPlans] = useState<readonly AttackPlan[]>([]);
  const [chains, setChains] = useState<readonly AttackChain[]>([]);
  const [postExploit, setPostExploit] = useState<PostExploitationState | null>(null);
  const [lateral, setLateral] = useState<LateralMovementSnapshot | null>(null);
  const [impacts, setImpacts] = useState<readonly ImpactAssessment[]>([]);

  const [selectedPlanId, setSelectedPlanId] = useState<string | null>(null);
  const [authModalPlan, setAuthModalPlan] = useState<AttackPlan | null>(null);
  const [completedPlanIds, setCompletedPlanIds] = useState<ReadonlySet<string>>(
    () => new Set()
  );
  const [authorizedPlanIds, setAuthorizedPlanIds] = useState<ReadonlySet<string>>(
    () => new Set()
  );
  const [lastAuthMeta, setLastAuthMeta] = useState<AuthorizeAttackPlanResponse["token"] | null>(
    null
  );
  const [executionRecord, setExecutionRecord] = useState<AttackExecutionRecordDto | null>(null);
  const [executionError, setExecutionError] = useState<string | null>(null);
  const [recommendations, setRecommendations] = useState<readonly OperatorAttackRecommendation[]>(
    []
  );
  const [rulesApplied, setRulesApplied] = useState<readonly string[]>([]);
  const [selectedRecRank, setSelectedRecRank] = useState<"A" | "B" | null>(null);
  const [investigationId, setInvestigationId] = useState("");
  const [investigationSnapshot, setInvestigationSnapshot] =
    useState<ActiveInvestigationSnapshotDto | null>(null);
  const [authorizeThenExecute, setAuthorizeThenExecute] = useState(false);
  const [showTechDetails, setShowTechDetails] = useState(false);
  const [resultsPanel, setResultsPanel] = useState<ResultsPanel>("chains");
  const [showMorePlans, setShowMorePlans] = useState(true);

  const [isLoading, setIsLoading] = useState(false);
  const [busyPlanId, setBusyPlanId] = useState<string | null>(null);
  const [isAuthorizing, setIsAuthorizing] = useState(false);
  const [lateralBusy, setLateralBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const selectedPlan = useMemo(
    () => plans.find((p) => p.planId === selectedPlanId) ?? null,
    [plans, selectedPlanId]
  );

  const displayPlans = useMemo(() => {
    return plans.map((p) => {
      if (authorizedPlanIds.has(p.planId) && p.status === "ready_for_authorization") {
        return { ...p, status: "authorized" as const };
      }
      return p;
    });
  }, [plans, authorizedPlanIds]);

  const loadAll = useCallback(async (id: string) => {
    if (!id || !isStrictSafeId(id)) {
      setError("Assessment ID inválido");
      return;
    }

    setIsLoading(true);
    setError(null);
    try {
      const [plansRes, chainsRes, peRes, latRes, impactRes] = await Promise.all([
        v2AttackApi.getAttackPlans(id),
        v2AttackApi.getAttackChains(id),
        v2AttackApi.getPostExploitation(id),
        v2AttackApi.getLateralMovement(id),
        v2AttackApi.getImpactAssessments(id),
      ]);

      setPlans(plansRes.plans);
      setChains(chainsRes.chains);
      setPostExploit(peRes.state);
      setLateral(latRes.snapshot);
      setImpacts(impactRes.impactAssessments);
      setLineage(plansRes.lineage);

      try {
        const recRes = await v2AttackApi.getAttackRecommendations(id, {
          ...(investigationId && isStrictSafeId(investigationId)
            ? { investigationId }
            : {}),
        });
        setRecommendations(recRes.recommendations);
        setRulesApplied(recRes.rulesApplied);
      } catch {
        setRecommendations([]);
        setRulesApplied([]);
      }

      try {
        const summary = await getOrchestratedAssessmentSummary(id);
        setTargetDomain(summary.targetDomain);
      } catch {
        // Summary optional when hermetic attack-only assessments exist
      }

      if (investigationId && isStrictSafeId(investigationId)) {
        try {
          const invRes = await v2AttackApi.getActiveInvestigation(id, investigationId);
          setInvestigationSnapshot(invRes.snapshot);
        } catch {
          setInvestigationSnapshot(null);
        }
      }

      if (plansRes.plans.length > 0) {
        setSelectedPlanId((prev) => prev ?? plansRes.plans[0].planId);
      }
    } catch (err) {
      if (err instanceof V2ApiError) {
        setError(`[${err.errorType}] ${err.message}${err.reasonCode ? ` (${err.reasonCode})` : ""}`);
      } else {
        setError(err instanceof Error ? err.message : "Error al cargar Attack Mode");
      }
    } finally {
      setIsLoading(false);
    }
  }, [investigationId]);

  useEffect(() => {
    if (!assessmentIdFromQuery) return;
    const handle = window.setTimeout(() => {
      void loadAll(assessmentIdFromQuery);
    }, 0);
    return () => window.clearTimeout(handle);
  }, [assessmentIdFromQuery, loadAll]);

  const resolveScopeGrant = useCallback(
    (extraHosts?: readonly string[]) => {
      if (!lineage) {
        throw new Error("Lineage not loaded — refresh assessment first");
      }
      const domain = targetDomain.trim();
      if (!domain) {
        throw new Error("Target domain required — load an assessment first");
      }
      return buildWorkbenchScopeGrant({
        grantId: lineage.authorizationGrantId,
        scanId: lineage.scanId,
        targetDomain: domain,
        extraHosts,
        allowCredentialUse: true,
      });
    },
    [lineage, targetDomain]
  );

  const handleAuthorize = async (blastRadiusClass: BlastRadiusClass) => {
    if (!authModalPlan) return;
    if (!isStrictSafeId(operatorId)) {
      setError("Operator ID inválido");
      return;
    }

    const planToAuth = authModalPlan;
    const shouldExecute = authorizeThenExecute;
    setIsAuthorizing(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const res = await v2AttackApi.authorizeAttackPlan(
        assessmentId,
        planToAuth.planId,
        { operatorId, blastRadiusClass }
      );
      setLastAuthMeta(res.token);
      setAuthorizedPlanIds((prev) => new Set([...prev, planToAuth.planId]));
      setSuccessMsg(`Autorizado · ${planToAuth.title}`);
      setAuthModalPlan(null);
      setAuthorizeThenExecute(false);
      if (shouldExecute) {
        await handleExecute(planToAuth);
      }
    } catch (err) {
      if (err instanceof V2ApiError) {
        setError(`[${err.errorType}] ${err.message}${err.reasonCode ? ` (${err.reasonCode})` : ""}`);
      } else {
        setError(err instanceof Error ? err.message : "Authorization failed");
      }
    } finally {
      setIsAuthorizing(false);
    }
  };

  const handleExecute = async (plan: AttackPlan) => {
    if (!isStrictSafeId(operatorId)) {
      setError("Operator ID inválido");
      return;
    }

    setBusyPlanId(plan.planId);
    setExecutionError(null);
    setError(null);
    setSuccessMsg(null);

    try {
      let extraHosts: string[] | undefined;
      if (plan.targetUrl) {
        try {
          extraHosts = [new URL(plan.targetUrl).hostname];
        } catch {
          extraHosts = undefined;
        }
      }
      const scopeGrant = resolveScopeGrant(extraHosts);
      const res = await v2AttackApi.executeAttackPlan(assessmentId, plan.planId, {
        operatorId,
        scopeGrant,
        ...(investigationId && isStrictSafeId(investigationId)
          ? { investigationId }
          : {}),
      });
      setExecutionRecord(res.record);
      setCompletedPlanIds((prev) => new Set([...prev, plan.planId]));

      if (investigationId && isStrictSafeId(investigationId)) {
        try {
          const invRes = await v2AttackApi.getActiveInvestigation(
            assessmentId,
            investigationId
          );
          setInvestigationSnapshot(invRes.snapshot);
        } catch {
          // Snapshot refresh is best-effort after execute
        }
      }

      if (res.refresh) {
        setChains(res.refresh.attackChains);
        setPostExploit(res.refresh.postExploitationState);
        setLateral(res.refresh.lateralMovementSnapshot);
        setImpacts(res.refresh.impactAssessments);
      } else {
        await loadAll(assessmentId);
      }

      setSuccessMsg(`Ejecución: ${res.record.status}`);
      setResultsPanel("chains");
    } catch (err) {
      const msg =
        err instanceof V2ApiError
          ? `[${err.errorType}] ${err.message}${err.reasonCode ? ` (${err.reasonCode})` : ""}`
          : err instanceof Error
            ? err.message
            : "Execution failed";
      setExecutionError(msg);
      setError(msg);
    } finally {
      setBusyPlanId(null);
    }
  };

  const handleRecommendAuthorizeRun = async (rec: OperatorAttackRecommendation) => {
    if (!rec.planId) {
      setError("La recomendación no tiene plan vinculado — carga planes primero");
      return;
    }
    const plan = displayPlans.find((p) => p.planId === rec.planId);
    if (!plan) {
      setError("Plan vinculado no encontrado en este assessment");
      return;
    }
    setSelectedRecRank(rec.rank);
    setSelectedPlanId(plan.planId);
    setAuthorizeThenExecute(true);
    setAuthModalPlan(plan);
  };

  const handlePromote = async (hostname: string) => {
    if (!isStrictSafeId(operatorId)) {
      setError("Operator ID inválido");
      return;
    }
    setLateralBusy(true);
    setError(null);
    try {
      const scopeGrant = resolveScopeGrant([hostname]);
      const res = await v2AttackApi.promoteLateralTarget(assessmentId, {
        hostname,
        operatorId,
        scopeGrant,
      });
      setLateral(res.snapshot);
      setSuccessMsg(`Promovido ${hostname}`);
      setResultsPanel("post_exploit");
    } catch (err) {
      if (err instanceof V2ApiError) {
        setError(`[${err.errorType}] ${err.message}${err.reasonCode ? ` (${err.reasonCode})` : ""}`);
      } else {
        setError(err instanceof Error ? err.message : "Promote failed");
      }
    } finally {
      setLateralBusy(false);
    }
  };

  const handleCredentialReuse = async (params: {
    readonly hostname: string;
    readonly credentialRefId: string;
    readonly mechanism: string;
  }) => {
    if (!isStrictSafeId(operatorId) || !isStrictSafeId(params.credentialRefId)) {
      setError("IDs inválidos");
      return;
    }

    const reusePlan =
      displayPlans.find(
        (p) =>
          p.capability === "credential_reuse" &&
          (authorizedPlanIds.has(p.planId) || p.status === "authorized")
      ) ?? displayPlans.find((p) => authorizedPlanIds.has(p.planId) || p.status === "authorized");

    if (!reusePlan) {
      setError("Autorizá un plan primero (p. ej. credential_reuse)");
      return;
    }

    setLateralBusy(true);
    setError(null);
    try {
      const sourceHost = targetDomain.trim() || params.hostname;
      const scopeGrant = resolveScopeGrant([params.hostname, sourceHost]);
      const res = await v2AttackApi.evaluateCredentialReuse(assessmentId, {
        planId: reusePlan.planId,
        sourceHost,
        destinationHost: params.hostname,
        mechanism: asLateralMechanism(params.mechanism),
        credentialRefId: params.credentialRefId,
        operatorId,
        scopeGrant,
      });
      setLateral(res.snapshot);
      setSuccessMsg(`Credential reuse: ${res.status}`);
      setResultsPanel("post_exploit");
    } catch (err) {
      if (err instanceof V2ApiError) {
        setError(`[${err.errorType}] ${err.message}${err.reasonCode ? ` (${err.reasonCode})` : ""}`);
      } else {
        setError(err instanceof Error ? err.message : "Credential reuse failed");
      }
    } finally {
      setLateralBusy(false);
    }
  };

  const attackSurfaceHints = useMemo(() => {
    const routes = new Set<string>();
    const endpoints = new Set<string>();
    const tables = new Set<string>();
    for (const p of displayPlans) {
      if (p.targetUrl) {
        try {
          const u = new URL(p.targetUrl);
          endpoints.add(`${u.pathname}${u.search}`);
          if (u.pathname.includes("/rest/v1/")) {
            const seg = u.pathname.split("/rest/v1/")[1]?.split("/")[0];
            if (seg) tables.add(seg);
          }
        } catch {
          endpoints.add(p.targetUrl);
        }
      }
      const tableMatch = /table['\s:=]+([a-z0-9_]+)/i.exec(p.reasoning ?? "");
      if (tableMatch?.[1]) tables.add(tableMatch[1]);
      if (/^\//.test(p.title)) routes.add(p.title);
      const pathInTitle = /\/[a-z0-9/_-]+/i.exec(p.title);
      if (pathInTitle) routes.add(pathInTitle[0]);
    }
    return {
      routes: Array.from(routes).slice(0, 12),
      endpoints: Array.from(endpoints).slice(0, 12),
      tables: Array.from(tables).slice(0, 12),
    };
  }, [displayPlans]);

  useEffect(() => {
    if (recommendations.length === 0 && displayPlans.length > 0) {
      setShowMorePlans(true);
    }
  }, [recommendations.length, displayPlans.length]);

  const triageHref = assessmentId
    ? `/v2?assessmentId=${encodeURIComponent(assessmentId)}`
    : "/v2";

  const toggleResults = (panel: ResultsPanel) => {
    setResultsPanel((prev) => (prev === panel ? null : panel));
  };

  return (
    <div
      className={`${embedded ? "" : "min-h-screen"} bg-black text-zinc-100 font-sans ${embedded ? "pb-6" : "pb-24"}`}
    >
      {!embedded && (
      <header className="border-b border-zinc-900 bg-zinc-950/70 backdrop-blur-xl sticky top-14 z-40">
        <div className="max-w-6xl mx-auto px-6 py-4 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <Link
              href={triageHref}
              className="flex h-9 w-9 items-center justify-center rounded-lg border border-zinc-800 bg-zinc-900 text-zinc-400 hover:text-white hover:border-zinc-700 transition"
              title="Volver al wizard / Triage"
            >
              <ArrowLeft className="h-4 w-4" />
            </Link>
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-orange-500/30 bg-orange-500/10 text-orange-400">
              <Crosshair className="h-5 w-5" />
            </div>
            <div>
              <h1 className="text-base font-bold tracking-tight text-white">
                Attack Mode
              </h1>
              <p className="text-xs text-zinc-400">
                Autorización humana · evidencia real · sin secretos en UI
              </p>
            </div>
          </div>

          <Link
            href={triageHref}
            className="rounded-lg border border-zinc-800 bg-zinc-900/60 hover:bg-zinc-900 px-3 py-1.5 text-xs text-zinc-400 hover:text-zinc-200 transition"
          >
            Triage
          </Link>
        </div>
      </header>
      )}

      <main className={`${embedded ? "" : "max-w-6xl mx-auto px-6 mt-6"} space-y-5`}>
        {embedded && (
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-orange-500/20 bg-orange-500/5 px-4 py-3">
            <div className="flex items-center gap-2">
              <Crosshair className="h-4 w-4 text-orange-400" />
              <div>
                <h2 className="text-sm font-semibold text-zinc-100">
                  Stage 4: Attack Mode
                </h2>
                <p className="text-[11px] text-zinc-500">
                  Autorización humana · evidencia real · sin secretos en UI
                </p>
              </div>
            </div>
            {onContinueToReport && (
              <button
                type="button"
                onClick={onContinueToReport}
                className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-emerald-500"
              >
                Continue to Report →
              </button>
            )}
          </div>
        )}

        <section className="rounded-xl border border-zinc-900 bg-zinc-950/80 p-4 space-y-3">
          <div>
            <span className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">
              Target actual
            </span>
            <p className="mt-1 font-mono text-sm text-zinc-100">
              {targetDomain || "—"}
            </p>
            <p className="mt-0.5 text-[10px] text-zinc-600">
              Del assessment en curso — autorizá y ejecutá planes (sin investigación aparte).
            </p>
          </div>

          {(attackSurfaceHints.routes.length > 0 ||
            attackSurfaceHints.endpoints.length > 0 ||
            attackSurfaceHints.tables.length > 0) && (
            <div className="space-y-2 border-t border-zinc-900 pt-3">
              <p className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">
                Superficie desde planes
              </p>
              {attackSurfaceHints.routes.length > 0 && (
                <div>
                  <span className="text-[10px] text-zinc-600">Rutas · </span>
                  <span className="font-mono text-[11px] text-zinc-400">
                    {attackSurfaceHints.routes.join(" · ")}
                  </span>
                </div>
              )}
              {attackSurfaceHints.endpoints.length > 0 && (
                <div>
                  <span className="text-[10px] text-zinc-600">Endpoints · </span>
                  <span className="font-mono text-[11px] text-zinc-400 break-all">
                    {attackSurfaceHints.endpoints.join(" · ")}
                  </span>
                </div>
              )}
              {attackSurfaceHints.tables.length > 0 && (
                <div>
                  <span className="text-[10px] text-zinc-600">Tablas · </span>
                  <span className="font-mono text-[11px] text-amber-400/90">
                    {attackSurfaceHints.tables.join(" · ")}
                  </span>
                </div>
              )}
            </div>
          )}

          <button
            type="button"
            onClick={() => setShowTechDetails((v) => !v)}
            className="inline-flex items-center gap-1 text-[10px] font-mono text-zinc-600 hover:text-zinc-400"
          >
            {showTechDetails ? (
              <ChevronDown className="h-3 w-3" />
            ) : (
              <ChevronRight className="h-3 w-3" />
            )}
            Detalles técnicos
          </button>
          {showTechDetails && (
            <div className="rounded-lg border border-zinc-900 bg-black/40 p-3 space-y-2 text-[10px] font-mono text-zinc-500">
              <div>assessment: {assessmentId || "—"}</div>
              <div>operator: {operatorId}</div>
              {lineage && (
                <>
                  <div>grant: {lineage.authorizationGrantId}</div>
                  <div>scan: {lineage.scanId}</div>
                  <div>actor: {lineage.actorId}</div>
                </>
              )}
              {lastAuthMeta && (
                <div>
                  last auth: class={lastAuthMeta.blastRadiusClass} · by=
                  {lastAuthMeta.authorizedBy}
                </div>
              )}
              {selectedPlan && (
                <div>
                  plan seleccionado: {selectedPlan.title} ({selectedPlan.steps.length} steps)
                </div>
              )}
            </div>
          )}
        </section>

        {error && (
          <div className="flex items-start justify-between gap-3 rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-300">
            <div className="flex items-start gap-2">
              <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
            <button type="button" onClick={() => setError(null)} className="text-rose-400 hover:text-rose-200">
              Cerrar
            </button>
          </div>
        )}

        {successMsg && (
          <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-[11px] text-emerald-300">
            {successMsg}
          </div>
        )}

        {/* Main: suggested attacks + docked console */}
        <div className="grid gap-4 lg:grid-cols-[1fr_minmax(280px,34%)]">
          <section className="rounded-xl border border-zinc-900 bg-zinc-950/60 p-4 space-y-4 min-h-[280px]">
            <div>
              <h2 className="text-sm font-semibold text-zinc-100">Ataques sugeridos</h2>
              <p className="text-[11px] text-zinc-500 mt-0.5">
                Prioridad A/B y planes listos. Autorizá antes de ejecutar — nada corre solo.
              </p>
            </div>

            <AttackRecommendationCards
              recommendations={recommendations}
              rulesApplied={rulesApplied}
              selectedRank={selectedRecRank}
              busy={busyPlanId !== null || isAuthorizing}
              onSelect={(r) => setSelectedRecRank(r.rank)}
              onAuthorizeRun={(r) => void handleRecommendAuthorizeRun(r)}
            />

            <div className="border-t border-zinc-900 pt-3">
              <button
                type="button"
                onClick={() => setShowMorePlans((v) => !v)}
                className="inline-flex items-center gap-1 text-[11px] font-medium text-zinc-400 hover:text-zinc-200"
              >
                {showMorePlans ? (
                  <ChevronDown className="h-3.5 w-3.5" />
                ) : (
                  <ChevronRight className="h-3.5 w-3.5" />
                )}
                Todos los planes ({displayPlans.length})
              </button>
              {showMorePlans && (
                <div className="mt-3">
                  <AttackPlansList
                    plans={displayPlans}
                    completedPlanIds={completedPlanIds}
                    selectedPlanId={selectedPlanId}
                    busyPlanId={busyPlanId}
                    onSelectPlan={(p) => setSelectedPlanId(p.planId)}
                    onAuthorizeClick={(p) => {
                      setAuthorizeThenExecute(false);
                      setAuthModalPlan(p);
                    }}
                    onExecuteClick={(p) => void handleExecute(p)}
                  />
                </div>
              )}
            </div>
          </section>

          <aside className="rounded-xl border border-zinc-900 bg-zinc-950/80 p-3 lg:sticky lg:top-20 lg:self-start space-y-2">
            <h2 className="text-xs font-semibold text-zinc-300 px-1">Consola</h2>
            <p className="text-[10px] text-zinc-600 px-1">
              Salida de ejecución — siempre visible
            </p>
            <StepExecutionMonitor record={executionRecord} lastError={executionError} />
          </aside>
        </div>

        {/* Results accordion */}
        <section className="rounded-xl border border-zinc-900 bg-zinc-950/60 overflow-hidden">
          <div className="border-b border-zinc-900 px-4 py-2.5">
            <h2 className="text-sm font-semibold text-zinc-100">Resultados</h2>
            <p className="text-[11px] text-zinc-500">
              Cadenas de prueba, impacto y post-explotación — en lenguaje claro
            </p>
          </div>

          <ResultsAccordion
            id="chains"
            title={`Cadenas (${chains.length})`}
            subtitle="Secuencia de pasos OBSERVED / VERIFIED / REFUTED contra el objetivo"
            open={resultsPanel === "chains"}
            onToggle={() => toggleResults("chains")}
          >
            <AttackChainViewer chains={chains} />
          </ResultsAccordion>

          <ResultsAccordion
            id="impact"
            title={`Impacto (${impacts.length})`}
            subtitle="Qué se probó, resultado y qué implica para el target"
            open={resultsPanel === "impact"}
            onToggle={() => toggleResults("impact")}
          >
            <ImpactAssessmentView assessments={impacts} />
          </ResultsAccordion>

          <ResultsAccordion
            id="post_exploit"
            title="Post-explotación"
            subtitle="Alcance lateral y promoción de hosts (solo con autorización)"
            open={resultsPanel === "post_exploit"}
            onToggle={() => toggleResults("post_exploit")}
            last
          >
            <PostExploitationPanel
              state={postExploit}
              lateral={lateral}
              busy={lateralBusy}
              onPromote={(h) => void handlePromote(h)}
              onCredentialReuse={(p) => void handleCredentialReuse(p)}
            />
          </ResultsAccordion>
        </section>
      </main>

      {authModalPlan && (
        <AttackAuthorizationModal
          plan={authModalPlan}
          operatorId={operatorId}
          isSubmitting={isAuthorizing}
          onAuthorize={(c) => void handleAuthorize(c)}
          onDecline={() => {
            setAuthorizeThenExecute(false);
            setAuthModalPlan(null);
          }}
        />
      )}
    </div>
  );
}

function ResultsAccordion({
  title,
  subtitle,
  open,
  onToggle,
  children,
  last,
}: {
  readonly id: string;
  readonly title: string;
  readonly subtitle: string;
  readonly open: boolean;
  readonly onToggle: () => void;
  readonly children: React.ReactNode;
  readonly last?: boolean;
}) {
  return (
    <div className={last ? "" : "border-b border-zinc-900"}>
      <button
        type="button"
        onClick={onToggle}
        className="flex w-full items-start gap-2 px-4 py-3 text-left hover:bg-zinc-900/40 transition"
      >
        {open ? (
          <ChevronDown className="h-4 w-4 text-zinc-500 mt-0.5 shrink-0" />
        ) : (
          <ChevronRight className="h-4 w-4 text-zinc-500 mt-0.5 shrink-0" />
        )}
        <span className="min-w-0">
          <span className="block text-xs font-semibold text-zinc-200">{title}</span>
          <span className="block text-[10px] text-zinc-500">{subtitle}</span>
        </span>
      </button>
      {open && <div className="px-4 pb-4">{children}</div>}
    </div>
  );
}

export function EmbeddedAttackMode({
  assessmentId,
  onContinueToReport,
}: {
  readonly assessmentId: string;
  readonly onContinueToReport?: () => void;
}) {
  return (
    <Suspense
      fallback={
        <div className="rounded-xl border border-zinc-800 bg-zinc-950/60 p-8 text-center text-sm font-mono text-zinc-500">
          Cargando Attack Mode…
        </div>
      }
    >
      <AttackModeContent
        forcedAssessmentId={assessmentId}
        embedded
        onContinueToReport={onContinueToReport}
      />
    </Suspense>
  );
}

export default function AttackModePage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-black text-zinc-500 flex items-center justify-center text-sm font-mono">
          Cargando Attack Mode…
        </div>
      }
    >
      <AttackModeContent />
    </Suspense>
  );
}
