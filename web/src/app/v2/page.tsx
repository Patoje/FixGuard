"use client";

import React, { useState, useCallback, useEffect, useRef } from "react";
import Link from "next/link";
import { AlertCircle, Check } from "lucide-react";
import {
  getOrchestratedAssessmentStatus,
  V2ApiError,
  type StartOrchestratedAssessmentResponse,
  type OrchestratedAssessmentStatusResponse,
} from "@/lib/v2Api";
import { TargetLaunchCard } from "./components/TargetLaunchCard";
import { SessionStatusCard } from "./components/SessionStatusCard";
import { EvidenceTriageBoard } from "./components/EvidenceTriageBoard";
import { ReportGenerationCard } from "./components/ReportGenerationCard";

type Stage =
  | "stage1_launch"
  | "stage2_overview"
  | "stage3_triage"
  | "stage4_report";

const STAGE_ORDER: Stage[] = [
  "stage1_launch",
  "stage2_overview",
  "stage3_triage",
  "stage4_report",
];

const STAGE_META: Record<
  Stage,
  { label: string; subtitle: string; activeClass: string; badgeClass: string }
> = {
  stage1_launch: {
    label: "Target Launch",
    subtitle: "Scope & authorize",
    activeClass:
      "border-emerald-500/50 bg-emerald-500/10 shadow-lg shadow-emerald-500/10",
    badgeClass: "border-emerald-500/30 bg-emerald-500/20 text-emerald-400",
  },
  stage2_overview: {
    label: "Active Recon",
    subtitle: "Orchestrated pipeline",
    activeClass: "border-blue-500/50 bg-blue-500/10 shadow-lg shadow-blue-500/10",
    badgeClass: "border-blue-500/30 bg-blue-500/20 text-blue-400",
  },
  stage3_triage: {
    label: "Evidence Triage",
    subtitle: "Incluir o descartar drafts",
    activeClass:
      "border-amber-500/50 bg-amber-500/10 shadow-lg shadow-amber-500/10",
    badgeClass: "border-amber-500/30 bg-amber-500/20 text-amber-300",
  },
  stage4_report: {
    label: "Defensive Report",
    subtitle: "Sign-off",
    activeClass:
      "border-emerald-500/50 bg-emerald-500/10 shadow-lg shadow-emerald-500/10",
    badgeClass: "border-emerald-500/30 bg-emerald-500/20 text-emerald-400",
  },
};

function stageIndex(stage: Stage): number {
  return STAGE_ORDER.indexOf(stage);
}

export default function V2DashboardPage() {
  const [activeStage, setActiveStage] = useState<Stage>("stage1_launch");
  const [maxUnlockedIndex, setMaxUnlockedIndex] = useState<number>(0);
  const [completedThrough, setCompletedThrough] = useState<number>(-1);

  const [assessmentId, setAssessmentId] = useState<string | null>(null);
  const [scanId, setScanId] = useState<string>("");
  const [targetDomain, setTargetDomain] = useState<string>("");
  const [status, setStatus] =
    useState<OrchestratedAssessmentStatusResponse | null>(null);
  const [isPolling, setIsPolling] = useState<boolean>(false);
  const [reviewedDraftIds, setReviewedDraftIds] = useState<string[]>([]);
  const [globalError, setGlobalError] = useState<string | null>(null);

  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const stopPolling = useCallback(() => {
    if (pollingRef.current) {
      clearInterval(pollingRef.current);
      pollingRef.current = null;
    }
    setIsPolling(false);
  }, []);

  const fetchStatus = useCallback(
    async (id: string) => {
      try {
        const current = await getOrchestratedAssessmentStatus(id);
        setStatus(current);
        setScanId(current.scanId);

        if (
          current.status === "completed" ||
          current.status === "circuit_broken" ||
          current.status === "failed" ||
          current.status === "preflight_denied"
        ) {
          stopPolling();
        }
      } catch (err) {
        if (err instanceof V2ApiError) {
          if (err.errorType === "NotFound" || err.status === 404) {
            try {
              sessionStorage.removeItem("fg_v2_active_assessment");
            } catch {
              // ignore
            }
            setAssessmentId(null);
            setStatus(null);
            setIsPolling(false);
            setActiveStage("stage1_launch");
            setMaxUnlockedIndex(0);
            setGlobalError(
              "Assessment session expired (worker restart / memory). Launch again from Stage 1."
            );
            return;
          }
          setGlobalError(`Status poll failed (${err.errorType}): ${err.message}`);
        } else {
          setGlobalError(
            (err as Error).message || "Failed to fetch assessment status"
          );
        }
        stopPolling();
      }
    },
    [stopPolling]
  );

  const handleAssessmentStarted = (
    data: StartOrchestratedAssessmentResponse,
    domain: string
  ) => {
    stopPolling();
    setAssessmentId(data.assessmentId);
    setScanId(data.scanId);
    setTargetDomain(domain);
    setReviewedDraftIds([]);
    setGlobalError(null);
    try {
      sessionStorage.setItem(
        "fg_v2_active_assessment",
        JSON.stringify({
          assessmentId: data.assessmentId,
          scanId: data.scanId,
          targetDomain: domain,
        })
      );
    } catch {
      // ignore storage quota / private mode
    }
    setStatus({
      assessmentId: data.assessmentId,
      scanId: data.scanId,
      targetDomain: domain,
      status: "running",
      stages: [],
      timing: { startedAt: new Date().toISOString() },
      errorCount: 0,
      warningCount: 0,
      lineage: data.lineage,
      alive: true,
    });
    setCompletedThrough(0);
    setMaxUnlockedIndex(1);
    setActiveStage("stage2_overview");
    setIsPolling(true);
  };

  // Resume mid-run after reload / Stage-2 crash (sessionStorage or ?assessmentId=)
  useEffect(() => {
    if (assessmentId) return;
    let resumeId: string | null = null;
    let resumeDomain = "";
    try {
      const params = new URLSearchParams(window.location.search);
      resumeId = params.get("assessmentId");
      if (!resumeId) {
        const raw = sessionStorage.getItem("fg_v2_active_assessment");
        if (raw) {
          const parsed = JSON.parse(raw) as {
            assessmentId?: string;
            targetDomain?: string;
          };
          if (typeof parsed.assessmentId === "string") {
            resumeId = parsed.assessmentId;
            resumeDomain =
              typeof parsed.targetDomain === "string"
                ? parsed.targetDomain
                : "";
          }
        }
      }
    } catch {
      return;
    }
    if (!resumeId) return;
    setAssessmentId(resumeId);
    setTargetDomain(resumeDomain);
    setCompletedThrough(0);
    setMaxUnlockedIndex(1);
    setActiveStage("stage2_overview");
    setIsPolling(true);
  }, [assessmentId]);

  useEffect(() => {
    if (!assessmentId || !isPolling) return;

    void fetchStatus(assessmentId);
    pollingRef.current = setInterval(() => {
      void fetchStatus(assessmentId);
    }, 2000);

    return () => {
      if (pollingRef.current) {
        clearInterval(pollingRef.current);
      }
    };
  }, [assessmentId, isPolling, fetchStatus]);

  // When recon finishes, unlock Triage without forcing navigation away from Stage 2
  useEffect(() => {
    if (!status) return;
    if (
      status.status === "completed" ||
      status.status === "circuit_broken" ||
      status.status === "failed" ||
      status.status === "preflight_denied"
    ) {
      setCompletedThrough((prev) => Math.max(prev, 1));
      setMaxUnlockedIndex((prev) => Math.max(prev, 2));
    }
  }, [status]);

  const unlockThrough = (stage: Stage) => {
    const idx = stageIndex(stage);
    setMaxUnlockedIndex((prev) => Math.max(prev, idx));
  };

  const markCompleteAndGo = (completed: Stage, next: Stage) => {
    const completedIdx = stageIndex(completed);
    setCompletedThrough((prev) => Math.max(prev, completedIdx));
    unlockThrough(next);
    setActiveStage(next);
  };

  const canNavigateTo = (stage: Stage): boolean => {
    return stageIndex(stage) <= maxUnlockedIndex;
  };

  /** Stepper only advances the wizard on /v2 — never leaves to Assessments/Attack. */
  const handleStageClick = (stage: Stage) => {
    if (!canNavigateTo(stage)) return;
    setActiveStage(stage);
  };

  const handleContinueToTriage = () => {
    markCompleteAndGo("stage2_overview", "stage3_triage");
  };

  const handleContinueToReport = () => {
    markCompleteAndGo("stage3_triage", "stage4_report");
  };

  const handleDraftReviewed = (draftId: string) => {
    setReviewedDraftIds((prev) =>
      prev.includes(draftId) ? prev : [...prev, draftId]
    );
  };

  const showStageChrome = activeStage !== "stage1_launch";

  return (
    <div className="min-h-screen bg-black text-zinc-100 font-sans pb-16">
      <main className="max-w-6xl mx-auto px-6 mt-8">
        {globalError && (
          <div className="mb-6 flex items-center justify-between rounded-lg border border-rose-500/30 bg-rose-500/10 p-4 text-xs text-rose-300">
            <div className="flex items-center gap-2">
              <AlertCircle className="h-4 w-4 shrink-0" />
              <span>{globalError}</span>
            </div>
            <button
              onClick={() => setGlobalError(null)}
              className="text-rose-400 hover:text-rose-200"
            >
              Dismiss
            </button>
          </div>
        )}

        {showStageChrome ? (
          <nav
            className="mb-8 grid grid-cols-2 gap-2 sm:grid-cols-4"
            aria-label="Assessment Pipeline Stages"
          >
            {STAGE_ORDER.map((stage, index) => {
              const meta = STAGE_META[stage];
              const isActive = activeStage === stage;
              const isCompleted = index <= completedThrough;
              const isLocked = !canNavigateTo(stage);
              const numberLabel =
                isCompleted && !isActive ? (
                  <Check className="h-3.5 w-3.5" />
                ) : (
                  index + 1
                );

              return (
                <button
                  key={stage}
                  type="button"
                  onClick={() => handleStageClick(stage)}
                  disabled={isLocked}
                  aria-disabled={isLocked}
                  aria-current={isActive ? "step" : undefined}
                  title={
                    isLocked
                      ? "Completá la etapa anterior para continuar"
                      : `Ir a ${meta.label}`
                  }
                  className={`flex items-center gap-2.5 rounded-xl border p-3.5 text-left transition-all ${
                    isActive
                      ? meta.activeClass
                      : isLocked
                        ? "border-zinc-900 bg-zinc-950/40 text-zinc-600 cursor-not-allowed opacity-50"
                        : "border-zinc-800 bg-zinc-950/60 hover:border-zinc-700 text-zinc-400 cursor-pointer"
                  }`}
                >
                  <div
                    className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border text-xs font-mono font-bold ${
                      isActive
                        ? meta.badgeClass
                        : isCompleted
                          ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                          : "border-zinc-800 bg-zinc-900 text-zinc-500"
                    }`}
                  >
                    {numberLabel}
                  </div>
                  <div className="overflow-hidden">
                    <div className="text-xs font-semibold text-zinc-200 truncate">
                      {meta.label}
                    </div>
                    <div className="text-[10px] text-zinc-500 truncate">
                      {meta.subtitle}
                    </div>
                  </div>
                </button>
              );
            })}
          </nav>
        ) : (
          <div className="mb-6 flex items-end justify-between gap-4">
            <div>
              <h1 className="text-lg font-semibold tracking-tight text-zinc-100">
                Nuevo assessment
              </h1>
              <p className="mt-0.5 text-sm text-zinc-500">
                Pegá el dominio y dale a Iniciar.
              </p>
            </div>
            <Link
              href="/v2/assessments"
              className="shrink-0 text-[11px] font-mono text-zinc-600 hover:text-zinc-400 transition"
            >
              Pipeline →
            </Link>
          </div>
        )}

        <div className="space-y-6">
          {activeStage === "stage1_launch" && (
            <TargetLaunchCard
              onAssessmentStarted={handleAssessmentStarted}
              isRunning={status?.status === "running"}
              activeDomain={targetDomain || null}
              activeAssessmentId={assessmentId}
            />
          )}

          {activeStage === "stage2_overview" && (
            <SessionStatusCard
              status={status}
              isPolling={isPolling}
              onRefresh={() => {
                if (assessmentId) void fetchStatus(assessmentId);
              }}
              onContinueToTriage={handleContinueToTriage}
            />
          )}

          {activeStage === "stage3_triage" && (
            <EvidenceTriageBoard
              assessmentId={assessmentId || ""}
              scanId={scanId}
              onDraftReviewed={handleDraftReviewed}
              reviewedDraftIds={reviewedDraftIds}
              onContinueToReport={handleContinueToReport}
            />
          )}

          {activeStage === "stage4_report" && (
            <ReportGenerationCard
              assessmentId={assessmentId || ""}
              scanId={scanId}
              reviewedCount={reviewedDraftIds.length}
            />
          )}
        </div>
      </main>
    </div>
  );
}
