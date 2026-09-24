"use client";

import React, { useState, useCallback, useEffect, useRef } from "react";
import Link from "next/link";
import { Shield, AlertCircle, Check } from "lucide-react";
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
    subtitle: "Approve or reject drafts",
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
    });
    setCompletedThrough(0);
    setMaxUnlockedIndex(1);
    setActiveStage("stage2_overview");
    setIsPolling(true);
  };

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

  return (
    <div className="min-h-screen bg-black text-zinc-100 font-sans pb-16">
      <header className="border-b border-zinc-900 bg-zinc-950/70 backdrop-blur-xl sticky top-14 z-40">
        <div className="max-w-6xl mx-auto px-6 py-4 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-emerald-500/30 bg-emerald-500/10 text-emerald-400">
              <Shield className="h-5 w-5" />
            </div>
            <div>
              <h1 className="text-base font-bold tracking-tight text-white">
                FixGuard V2
              </h1>
              <p className="text-xs text-zinc-500">
                Authorized web security assessment
              </p>
            </div>
          </div>

          <Link
            href="/v2/assessments"
            className="text-xs font-mono text-zinc-500 hover:text-zinc-300 transition"
          >
            Full pipeline view →
          </Link>
        </div>
      </header>

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

        <nav
          className="mb-8 grid grid-cols-2 gap-2 sm:grid-cols-4"
          aria-label="Assessment Pipeline Stages"
        >
          {STAGE_ORDER.map((stage, index) => {
            const meta = STAGE_META[stage];
            const isActive = activeStage === stage;
            const isCompleted = index <= completedThrough;
            const isLocked = !canNavigateTo(stage);
            const numberLabel = isCompleted && !isActive ? (
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
                title={
                  isLocked
                    ? "Complete the previous stage before continuing"
                    : meta.label
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
