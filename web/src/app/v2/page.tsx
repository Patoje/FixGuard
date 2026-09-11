"use client";

import React, { useState, useCallback } from "react";
import {
  Shield,
  Layers,
  Activity,
  Terminal,
  AlertCircle
} from "lucide-react";
import { v2ApiClient, V2ApiError } from "@/lib/v2/apiClient";
import type {
  AssessmentSummaryDto,
  AssessmentDetailsDto,
  FormalFindingCandidateDto
} from "@/lib/v2/types";
import { TargetLaunchCard } from "./components/TargetLaunchCard";
import { SessionStatusCard } from "./components/SessionStatusCard";
import { EvidenceTriageBoard } from "./components/EvidenceTriageBoard";
import { ReportGenerationCard } from "./components/ReportGenerationCard";

type Stage = "stage1_launch" | "stage2_overview" | "stage3_triage" | "stage4_report";

export default function V2DashboardPage() {
  const [activeStage, setActiveStage] = useState<Stage>("stage1_launch");
  const [session, setSession] = useState<AssessmentSummaryDto | AssessmentDetailsDto | null>(null);
  const [scanId, setScanId] = useState<string>("");
  const [promotedCandidates, setPromotedCandidates] = useState<FormalFindingCandidateDto[]>([]);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [globalError, setGlobalError] = useState<string | null>(null);

  // When a new session is launched in Stage 1
  const handleAssessmentCreated = (newSession: AssessmentSummaryDto) => {
    setSession(newSession);
    // In FixGuard V2 initial recon, scanId defaults to sessionId or resolves from scan
    setScanId(newSession.sessionId);
    setActiveStage("stage2_overview");
    setGlobalError(null);
  };

  // When recon is triggered or refreshed in Stage 2
  const handleSessionUpdated = (details: AssessmentDetailsDto) => {
    setSession(details);
    if (!scanId) {
      setScanId(details.sessionId);
    }
    setGlobalError(null);
  };

  // Refresh handler
  const handleRefresh = useCallback(async () => {
    if (!session?.sessionId) return;
    setIsRefreshing(true);
    setGlobalError(null);
    try {
      const details = await v2ApiClient.getAssessment(session.sessionId);
      setSession(details);
    } catch (err) {
      if (err instanceof V2ApiError) {
        setGlobalError(`Refresh Failed (${err.errorType}): ${err.message}`);
      } else {
        setGlobalError((err as Error).message || "Failed to refresh assessment state");
      }
    } finally {
      setIsRefreshing(false);
    }
  }, [session]);

  // When a candidate is promoted in Stage 3
  const handleCandidatePromoted = (candidate: FormalFindingCandidateDto) => {
    setPromotedCandidates((prev) => {
      if (prev.some((c) => c.candidateId === candidate.candidateId)) return prev;
      return [...prev, candidate];
    });
  };

  return (
    <div className="min-h-screen bg-black text-zinc-100 font-sans pb-24">
      {/* Top Header Banner */}
      <header className="border-b border-zinc-900 bg-zinc-950/70 backdrop-blur-xl sticky top-14 z-40">
        <div className="max-w-6xl mx-auto px-6 py-4 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-emerald-500/30 bg-emerald-500/10 text-emerald-400">
              <Shield className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-base font-bold tracking-tight text-white">
                  FixGuard V2
                </h1>
                <span className="rounded bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 text-[10px] font-mono font-semibold text-emerald-400">
                  MVP ACTIVE
                </span>
                <span className="rounded bg-zinc-800 border border-zinc-700 px-2 py-0.5 text-[10px] font-mono text-zinc-400">
                  Express 5 Gateway
                </span>
              </div>
              <p className="text-xs text-zinc-400">
                Authorized Web Security Assessment — Defensive Core (Layered Architecture)
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 text-xs font-mono">
            <div className="flex items-center gap-1.5 rounded-full border border-zinc-800 bg-zinc-900/60 px-3 py-1 text-zinc-400">
              <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
              <span>Anti-Fabrication: ACTIVE</span>
            </div>
            <div className="hidden sm:flex items-center gap-1.5 rounded-full border border-zinc-800 bg-zinc-900/60 px-3 py-1 text-zinc-400">
              <Terminal className="h-3 w-3 text-zinc-500" />
              <span>HITL Authorization Gate</span>
            </div>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="max-w-6xl mx-auto px-6 mt-8">
        {/* Global Error Banner */}
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

        {/* 4-Stage Navigation Stepper */}
        <nav className="mb-8 grid grid-cols-2 gap-2 sm:grid-cols-4" aria-label="Assessment Pipeline Stages">
          <button
            type="button"
            onClick={() => setActiveStage("stage1_launch")}
            className={`flex items-center gap-2.5 rounded-xl border p-3.5 text-left transition-all ${
              activeStage === "stage1_launch"
                ? "border-emerald-500/50 bg-emerald-500/10 shadow-lg shadow-emerald-500/10"
                : "border-zinc-800 bg-zinc-950/60 hover:border-zinc-700 text-zinc-400"
            }`}
          >
            <div
              className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border text-xs font-mono font-bold ${
                activeStage === "stage1_launch"
                  ? "border-emerald-500/30 bg-emerald-500/20 text-emerald-400"
                  : "border-zinc-800 bg-zinc-900 text-zinc-500"
              }`}
            >
              1
            </div>
            <div className="overflow-hidden">
              <div className="text-xs font-semibold text-zinc-200 truncate">Target Launch</div>
              <div className="text-[10px] text-zinc-500 truncate">Session &amp; Scope</div>
            </div>
          </button>

          <button
            type="button"
            onClick={() => setActiveStage("stage2_overview")}
            className={`flex items-center gap-2.5 rounded-xl border p-3.5 text-left transition-all ${
              activeStage === "stage2_overview"
                ? "border-blue-500/50 bg-blue-500/10 shadow-lg shadow-blue-500/10"
                : "border-zinc-800 bg-zinc-950/60 hover:border-zinc-700 text-zinc-400"
            }`}
          >
            <div
              className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border text-xs font-mono font-bold ${
                activeStage === "stage2_overview"
                  ? "border-blue-500/30 bg-blue-500/20 text-blue-400"
                  : "border-zinc-800 bg-zinc-900 text-zinc-500"
              }`}
            >
              2
            </div>
            <div className="overflow-hidden">
              <div className="text-xs font-semibold text-zinc-200 truncate">Session Overview</div>
              <div className="text-[10px] text-zinc-500 truncate">Active Reconnaissance</div>
            </div>
          </button>

          <button
            type="button"
            onClick={() => setActiveStage("stage3_triage")}
            className={`flex items-center gap-2.5 rounded-xl border p-3.5 text-left transition-all ${
              activeStage === "stage3_triage"
                ? "border-purple-500/50 bg-purple-500/10 shadow-lg shadow-purple-500/10"
                : "border-zinc-800 bg-zinc-950/60 hover:border-zinc-700 text-zinc-400"
            }`}
          >
            <div
              className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border text-xs font-mono font-bold ${
                activeStage === "stage3_triage"
                  ? "border-purple-500/30 bg-purple-500/20 text-purple-400"
                  : "border-zinc-800 bg-zinc-900 text-zinc-500"
              }`}
            >
              3
            </div>
            <div className="overflow-hidden">
              <div className="text-xs font-semibold text-zinc-200 truncate">Evidence Triage</div>
              <div className="text-[10px] text-zinc-500 truncate">Human-in-the-Loop</div>
            </div>
          </button>

          <button
            type="button"
            onClick={() => setActiveStage("stage4_report")}
            className={`flex items-center gap-2.5 rounded-xl border p-3.5 text-left transition-all ${
              activeStage === "stage4_report"
                ? "border-emerald-500/50 bg-emerald-500/10 shadow-lg shadow-emerald-500/10"
                : "border-zinc-800 bg-zinc-950/60 hover:border-zinc-700 text-zinc-400"
            }`}
          >
            <div
              className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border text-xs font-mono font-bold ${
                activeStage === "stage4_report"
                  ? "border-emerald-500/30 bg-emerald-500/20 text-emerald-400"
                  : "border-zinc-800 bg-zinc-900 text-zinc-500"
              }`}
            >
              4
            </div>
            <div className="overflow-hidden">
              <div className="text-xs font-semibold text-zinc-200 truncate">Defensive Report</div>
              <div className="text-[10px] text-zinc-500 truncate">Sign-Off Gatekeeper</div>
            </div>
          </button>
        </nav>

        {/* Stage Content View */}
        <div className="space-y-6">
          {activeStage === "stage1_launch" && (
            <TargetLaunchCard
              onAssessmentCreated={handleAssessmentCreated}
              activeSession={session}
            />
          )}

          {activeStage === "stage2_overview" && (
            <SessionStatusCard
              session={session}
              onSessionUpdated={handleSessionUpdated}
              onRefresh={handleRefresh}
              isRefreshing={isRefreshing}
            />
          )}

          {activeStage === "stage3_triage" && (
            <EvidenceTriageBoard
              initialScanId={scanId || session?.sessionId || ""}
              onCandidatePromoted={handleCandidatePromoted}
              promotedCandidates={promotedCandidates}
            />
          )}

          {activeStage === "stage4_report" && (
            <ReportGenerationCard
              sessionId={session?.sessionId || ""}
              scanId={scanId || session?.sessionId || ""}
              candidateCount={promotedCandidates.length}
            />
          )}
        </div>

        {/* Quick Lifecycle Footer Bar */}
        {session && (
          <aside aria-label="Active Assessment Status" className="mt-8 rounded-xl border border-zinc-900 bg-zinc-950/90 p-4 shadow-xl backdrop-blur-xl flex flex-wrap items-center justify-between gap-4 text-xs font-mono">
            <div className="flex items-center gap-3">
              <span className="flex items-center gap-1.5 text-zinc-400">
                <Activity className="h-3.5 w-3.5 text-blue-400" />
                Session: <strong className="text-zinc-200">{session.sessionId}</strong>
              </span>
              <span className="text-zinc-700">|</span>
              <span className="flex items-center gap-1.5 text-zinc-400">
                <Layers className="h-3.5 w-3.5 text-purple-400" />
                Scan: <strong className="text-zinc-200">{scanId || session.sessionId}</strong>
              </span>
            </div>

            <div className="flex items-center gap-4 text-zinc-400">
              <span>Status: <strong className="text-emerald-400">{session.lifecycleStatus}</strong></span>
              <span>Candidates: <strong className="text-purple-400">{promotedCandidates.length}</strong></span>
            </div>
          </aside>
        )}
      </main>
    </div>
  );
}
