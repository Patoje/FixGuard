"use client";

import React, { useState, useEffect, useCallback, useRef } from "react";
import Link from "next/link";
import {
  Shield,
  Layers,
  Activity,
  ArrowLeft,
  Sparkles,
  Zap,
  Terminal,
  CheckCircle2
} from "lucide-react";
import {
  getOrchestratedAssessmentStatus,
  getOrchestratedAssessmentSummary,
  V2ApiError,
  type StartOrchestratedAssessmentResponse,
  type OrchestratedAssessmentStatusResponse,
  type OrchestratedAssessmentSummaryResponse
} from "@/lib/v2Api";

import { AssessmentLauncherCard } from "./components/AssessmentLauncherCard";
import { PipelineStageTracker } from "./components/PipelineStageTracker";
import { ExecutiveResultsPanel } from "./components/ExecutiveResultsPanel";
import { AbstentionAlert } from "./components/AbstentionAlert";

export default function OrchestratedAssessmentsPage() {
  const [assessmentId, setAssessmentId] = useState<string | null>(null);
  const [targetDomain, setTargetDomain] = useState<string>("");
  const [status, setStatus] = useState<OrchestratedAssessmentStatusResponse | null>(null);
  const [summary, setSummary] = useState<OrchestratedAssessmentSummaryResponse | null>(null);
  const [isPolling, setIsPolling] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const pollingRef = useRef<NodeJS.Timeout | null>(null);

  const stopPolling = useCallback(() => {
    if (pollingRef.current) {
      clearInterval(pollingRef.current);
      pollingRef.current = null;
    }
    setIsPolling(false);
  }, []);

  const fetchStatusAndSummary = useCallback(
    async (id: string) => {
      try {
        const currentStatus = await getOrchestratedAssessmentStatus(id);
        setStatus(currentStatus);

        if (
          currentStatus.status === "completed" ||
          currentStatus.status === "circuit_broken"
        ) {
          stopPolling();
          try {
            const currentSummary = await getOrchestratedAssessmentSummary(id);
            setSummary(currentSummary);
          } catch (summaryErr) {
            console.error("Failed to fetch assessment summary:", summaryErr);
          }
        } else if (
          currentStatus.status === "failed" ||
          currentStatus.status === "preflight_denied"
        ) {
          stopPolling();
        }

      } catch (err) {
        if (err instanceof V2ApiError) {
          setError(`[${err.errorType}] ${err.message}`);
        } else {
          setError((err as Error).message || "Failed to fetch assessment status");
        }
        stopPolling();
      }
    },
    [stopPolling]
  );

  // When assessment is started via launcher
  const handleAssessmentStarted = (
    data: StartOrchestratedAssessmentResponse,
    domain: string
  ) => {
    stopPolling();
    setAssessmentId(data.assessmentId);
    setTargetDomain(domain);
    setSummary(null);
    setError(null);

    // Initial status representation
    setStatus({
      assessmentId: data.assessmentId,
      scanId: data.scanId,
      targetDomain: domain,
      status: "running",
      stages: [],
      timing: { startedAt: new Date().toISOString() },
      errorCount: 0,
      warningCount: 0,
      lineage: data.lineage
    });

    setIsPolling(true);
  };

  // Polling loop
  useEffect(() => {
    if (!assessmentId || !isPolling) return;

    // Immediately fetch once
    fetchStatusAndSummary(assessmentId);

    pollingRef.current = setInterval(() => {
      fetchStatusAndSummary(assessmentId);
    }, 2000);

    return () => {
      if (pollingRef.current) {
        clearInterval(pollingRef.current);
      }
    };
  }, [assessmentId, isPolling, fetchStatusAndSummary]);

  return (
    <div className="min-h-screen bg-black text-zinc-100 font-sans pb-24">
      {/* Header Banner */}
      <header className="border-b border-zinc-900 bg-zinc-950/70 backdrop-blur-xl sticky top-0 z-40">
        <div className="max-w-6xl mx-auto px-6 py-4 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <Link
              href="/v2"
              className="flex h-9 w-9 items-center justify-center rounded-lg border border-zinc-800 bg-zinc-900 text-zinc-400 hover:text-white hover:border-zinc-700 transition cursor-pointer"
              title="Return to MVP Dashboard"
            >
              <ArrowLeft className="h-4 w-4" />
            </Link>

            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-emerald-500/30 bg-emerald-500/10 text-emerald-400">
              <Zap className="h-5 w-5" />
            </div>

            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-base font-bold tracking-tight text-white">
                  FixGuard V2 — Orchestrated Assessments
                </h1>
                <span className="rounded bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 text-[10px] font-mono font-semibold text-emerald-400">
                  M73 / F4 / F5 / F6
                </span>
                <span className="rounded bg-purple-500/10 border border-purple-500/30 px-2 py-0.5 text-[10px] font-mono text-purple-300">
                  Real Time
                </span>
              </div>
              <p className="text-xs text-zinc-400">
                End-to-End Orchestrated Pipeline: 5-Stage Recon, CORS &amp; Reflection Detection, TargetProfile &amp; Advisory Engine
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 text-xs font-mono">
            <Link
              href={assessmentId ? `/v2/attack?assessmentId=${encodeURIComponent(assessmentId)}` : "/v2/attack"}
              className="rounded-lg border border-orange-500/40 bg-orange-500/10 hover:bg-orange-500/20 px-3 py-1.5 text-orange-300 font-semibold transition"
            >
              Attack Mode (A13) &rarr;
            </Link>
            <Link
              href="/v2"
              className="rounded-lg border border-zinc-800 bg-zinc-900/60 hover:bg-zinc-900 px-3 py-1.5 text-zinc-400 hover:text-zinc-200 transition"
            >
              View M62 Triage Board &rarr;
            </Link>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="max-w-6xl mx-auto px-6 mt-8 space-y-8">
        {/* Launcher Card */}
        <section aria-labelledby="launcher-heading">
          <h2 id="launcher-heading" className="sr-only">Assessment Launcher</h2>
          <AssessmentLauncherCard
            onAssessmentStarted={handleAssessmentStarted}
            isRunning={status?.status === "running"}
          />
        </section>

        {/* Abstention & Error Alerts */}
        {status && (
          <section aria-label="Preflight and Execution Alerts">
            <AbstentionAlert status={status} />
          </section>
        )}

        {/* Real-Time Pipeline Tracker */}
        {status && (
          <section aria-label="Pipeline Stage Tracker">
            <PipelineStageTracker
              status={status}
              onRefresh={() => {
                if (assessmentId) fetchStatusAndSummary(assessmentId);
              }}
              isPolling={isPolling}
            />
          </section>
        )}

        {/* Executive Results Panel */}
        {summary && (
          <section aria-label="Executive Assessment Results">
            <ExecutiveResultsPanel summary={summary} />
          </section>
        )}
      </main>
    </div>
  );
}
