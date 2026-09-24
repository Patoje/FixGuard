"use client";

import React, { useCallback, useEffect, useMemo, useState, Suspense } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
  Crosshair,
  ArrowLeft,
  RefreshCw,
  AlertCircle,
  Layers,
  Shield,
  Activity,
  Zap,
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

type WorkbenchTab =
  | "plans"
  | "execution"
  | "chains"
  | "post_exploit"
  | "impact";

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

function AttackModeContent() {
  const searchParams = useSearchParams();
  const assessmentIdFromQuery = searchParams.get("assessmentId") || "";

  const [assessmentId, setAssessmentId] = useState(assessmentIdFromQuery);
  const [operatorId, setOperatorId] = useState("usr_secops_lead");
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

  const [tab, setTab] = useState<WorkbenchTab>("plans");
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
      setError("Assessment ID must match /^[A-Za-z0-9_-]{1,64}$/");
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
        const summary = await getOrchestratedAssessmentSummary(id);
        setTargetDomain(summary.targetDomain);
      } catch {
        // Summary optional when hermetic attack-only assessments exist
      }

      if (plansRes.plans.length > 0) {
        setSelectedPlanId((prev) => prev ?? plansRes.plans[0].planId);
      }
    } catch (err) {
      if (err instanceof V2ApiError) {
        setError(`[${err.errorType}] ${err.message}${err.reasonCode ? ` (${err.reasonCode})` : ""}`);
      } else {
        setError(err instanceof Error ? err.message : "Failed to load Attack Mode data");
      }
    } finally {
      setIsLoading(false);
    }
  }, []);

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
      const domain = targetDomain.trim() || "example.com";
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
      setError("Operator ID must be a strict safe id");
      return;
    }

    setIsAuthorizing(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const res = await v2AttackApi.authorizeAttackPlan(
        assessmentId,
        authModalPlan.planId,
        { operatorId, blastRadiusClass }
      );
      setLastAuthMeta(res.token);
      setAuthorizedPlanIds((prev) => new Set([...prev, authModalPlan.planId]));
      setSuccessMsg(
        `Authorized ${authModalPlan.planId} · ${res.token.blastRadiusClass} · level ${res.token.authorizationLevel} (WeakSet brand sealed server-side)`
      );
      setAuthModalPlan(null);
      setTab("plans");
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
      setError("Operator ID must be a strict safe id");
      return;
    }

    setBusyPlanId(plan.planId);
    setExecutionError(null);
    setError(null);
    setSuccessMsg(null);
    setTab("execution");

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
      });
      setExecutionRecord(res.record);
      setCompletedPlanIds((prev) => new Set([...prev, plan.planId]));

      if (res.refresh) {
        setChains(res.refresh.attackChains);
        setPostExploit(res.refresh.postExploitationState);
        setLateral(res.refresh.lateralMovementSnapshot);
        setImpacts(res.refresh.impactAssessments);
      } else {
        await loadAll(assessmentId);
      }

      setSuccessMsg(`Execution ${res.record.status}: ${res.reasonCode}`);
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

  const handlePromote = async (hostname: string) => {
    if (!isStrictSafeId(operatorId)) {
      setError("Operator ID must be a strict safe id");
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
      setSuccessMsg(`Promoted ${hostname} to authorized lateral target`);
      setTab("post_exploit");
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
      setError("Operator ID and credentialRefId must be strict safe ids");
      return;
    }

    const reusePlan =
      displayPlans.find(
        (p) =>
          p.capability === "credential_reuse" &&
          (authorizedPlanIds.has(p.planId) || p.status === "authorized")
      ) ?? displayPlans.find((p) => authorizedPlanIds.has(p.planId) || p.status === "authorized");

    if (!reusePlan) {
      setError("Authorize a credential_reuse (or any) plan first — reuse requires WeakSet brand");
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
      setSuccessMsg(
        `Credential reuse ${res.status} · networkDispatched=${res.networkDispatched}`
      );
      setTab("post_exploit");
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

  const tabs: { id: WorkbenchTab; label: string }[] = [
    { id: "plans", label: "Plans" },
    { id: "execution", label: "Execution" },
    { id: "chains", label: "Chains" },
    { id: "post_exploit", label: "Post-Exploit" },
    { id: "impact", label: "Impact" },
  ];

  return (
    <div className="min-h-screen bg-black text-zinc-100 font-sans pb-24">
      <header className="border-b border-zinc-900 bg-zinc-950/70 backdrop-blur-xl sticky top-0 z-40">
        <div className="max-w-6xl mx-auto px-6 py-4 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <Link
              href="/v2/assessments"
              className="flex h-9 w-9 items-center justify-center rounded-lg border border-zinc-800 bg-zinc-900 text-zinc-400 hover:text-white hover:border-zinc-700 transition"
              title="Back to orchestrated assessments"
            >
              <ArrowLeft className="h-4 w-4" />
            </Link>
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-orange-500/30 bg-orange-500/10 text-orange-400">
              <Crosshair className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-base font-bold tracking-tight text-white">
                  FixGuard V2 — Attack Mode
                </h1>
                <span className="rounded bg-orange-500/10 border border-orange-500/30 px-2 py-0.5 text-[10px] font-mono font-semibold text-orange-400">
                  A13
                </span>
              </div>
              <p className="text-xs text-zinc-400">
                Graduated authorization · epistemic triage · zero secrets in UI
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 text-xs font-mono">
            <Link
              href="/v2/review"
              className="rounded-lg border border-zinc-800 bg-zinc-900/60 hover:bg-zinc-900 px-3 py-1.5 text-zinc-400 hover:text-zinc-200 transition"
            >
              Evidence review
            </Link>
            <Link
              href="/v2"
              className="rounded-lg border border-zinc-800 bg-zinc-900/60 hover:bg-zinc-900 px-3 py-1.5 text-zinc-400 hover:text-zinc-200 transition"
            >
              MVP board
            </Link>
          </div>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-6 mt-6 space-y-5">
        {/* Operator controls */}
        <section className="rounded-xl border border-zinc-900 bg-zinc-950/80 p-4 space-y-3">
          <div className="grid gap-3 sm:grid-cols-3">
            <label className="block space-y-1">
              <span className="text-[10px] font-mono uppercase text-zinc-500">Assessment ID</span>
              <input
                value={assessmentId}
                onChange={(e) => setAssessmentId(e.target.value.trim())}
                placeholder="asmt_orch_…"
                className="w-full rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-2 text-xs font-mono text-zinc-100 focus:outline-none focus:border-emerald-500/40"
              />
            </label>
            <label className="block space-y-1">
              <span className="text-[10px] font-mono uppercase text-zinc-500">Operator ID</span>
              <input
                value={operatorId}
                onChange={(e) => setOperatorId(e.target.value.trim())}
                className="w-full rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-2 text-xs font-mono text-zinc-100 focus:outline-none focus:border-emerald-500/40"
              />
            </label>
            <label className="block space-y-1">
              <span className="text-[10px] font-mono uppercase text-zinc-500">Target domain</span>
              <input
                value={targetDomain}
                onChange={(e) => setTargetDomain(e.target.value.trim())}
                placeholder="example.com"
                className="w-full rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-2 text-xs font-mono text-zinc-100 focus:outline-none focus:border-emerald-500/40"
              />
            </label>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              disabled={isLoading || !assessmentId}
              onClick={() => void loadAll(assessmentId)}
              className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-1.5 text-xs font-mono font-semibold text-emerald-400 hover:bg-emerald-500/20 disabled:opacity-40"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${isLoading ? "animate-spin" : ""}`} />
              {isLoading ? "Loading…" : "Load / Refresh"}
            </button>
            {lineage && (
              <span className="text-[10px] font-mono text-zinc-500">
                grant {lineage.authorizationGrantId} · scan {lineage.scanId} · actor{" "}
                {lineage.actorId}
              </span>
            )}
          </div>
        </section>

        {error && (
          <div className="flex items-start justify-between gap-3 rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-300">
            <div className="flex items-start gap-2">
              <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
            <button type="button" onClick={() => setError(null)} className="text-rose-400 hover:text-rose-200">
              Dismiss
            </button>
          </div>
        )}

        {successMsg && (
          <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-[11px] text-emerald-300 font-mono">
            {successMsg}
          </div>
        )}

        {lastAuthMeta && (
          <div className="rounded-lg border border-sky-500/30 bg-sky-500/5 px-3 py-2 text-[11px] font-mono text-sky-200/90">
            Last auth token meta (safe DTO — no brand): plan={lastAuthMeta.planId} · class=
            {lastAuthMeta.blastRadiusClass} · by={lastAuthMeta.authorizedBy} · at=
            {lastAuthMeta.authorizedAt}
          </div>
        )}

        {/* Tabs */}
        <nav className="flex flex-wrap gap-1.5" aria-label="Attack Mode sections">
          {tabs.map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => setTab(t.id)}
              className={`rounded-lg border px-3 py-1.5 text-[11px] font-mono transition ${
                tab === t.id
                  ? "border-orange-500/50 bg-orange-500/10 text-orange-300"
                  : "border-zinc-800 bg-zinc-950 text-zinc-500 hover:border-zinc-700 hover:text-zinc-300"
              }`}
            >
              {t.label}
            </button>
          ))}
        </nav>

        <div className="rounded-xl border border-zinc-900 bg-zinc-950/60 p-4 min-h-[280px]">
          {tab === "plans" && (
            <AttackPlansList
              plans={displayPlans}
              completedPlanIds={completedPlanIds}
              selectedPlanId={selectedPlanId}
              busyPlanId={busyPlanId}
              onSelectPlan={(p) => setSelectedPlanId(p.planId)}
              onAuthorizeClick={(p) => setAuthModalPlan(p)}
              onExecuteClick={(p) => void handleExecute(p)}
            />
          )}
          {tab === "execution" && (
            <StepExecutionMonitor record={executionRecord} lastError={executionError} />
          )}
          {tab === "chains" && <AttackChainViewer chains={chains} />}
          {tab === "post_exploit" && (
            <PostExploitationPanel
              state={postExploit}
              lateral={lateral}
              busy={lateralBusy}
              onPromote={(h) => void handlePromote(h)}
              onCredentialReuse={(p) => void handleCredentialReuse(p)}
            />
          )}
          {tab === "impact" && <ImpactAssessmentView assessments={impacts} />}
        </div>

        {selectedPlan && tab === "plans" && (
          <aside className="rounded-xl border border-zinc-900 bg-zinc-950/90 p-4 text-[11px] font-mono text-zinc-400">
            <div className="flex flex-wrap items-center gap-3">
              <span className="inline-flex items-center gap-1">
                <Layers className="h-3.5 w-3.5 text-sky-400" />
                Selected: <strong className="text-zinc-200">{selectedPlan.planId}</strong>
              </span>
              <span className="text-zinc-700">|</span>
              <span>{selectedPlan.steps.length} steps</span>
              <span className="text-zinc-700">|</span>
              <span>gained: {selectedPlan.capabilityGained}</span>
            </div>
          </aside>
        )}

        <footer className="flex flex-wrap items-center gap-4 text-[10px] font-mono text-zinc-600 pt-2">
          <span className="inline-flex items-center gap-1">
            <Shield className="h-3 w-3" /> Anti-fabrication
          </span>
          <span className="inline-flex items-center gap-1">
            <Zap className="h-3 w-3" /> HITL authorize → execute
          </span>
          <span className="inline-flex items-center gap-1">
            <Activity className="h-3 w-3" /> Epistemic badges required
          </span>
        </footer>
      </main>

      {authModalPlan && (
        <AttackAuthorizationModal
          plan={authModalPlan}
          operatorId={operatorId}
          isSubmitting={isAuthorizing}
          onAuthorize={(c) => void handleAuthorize(c)}
          onDecline={() => setAuthModalPlan(null)}
        />
      )}
    </div>
  );
}

export default function AttackModePage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-black text-zinc-500 flex items-center justify-center text-sm font-mono">
          Loading Attack Mode…
        </div>
      }
    >
      <AttackModeContent />
    </Suspense>
  );
}
