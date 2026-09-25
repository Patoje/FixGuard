"use client";

import React, { useState, useEffect, useCallback, useRef } from "react";
import Link from "next/link";
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
      lineage: data.lineage,
      alive: true,
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
      <main className="max-w-6xl mx-auto px-6 mt-8 space-y-8">
        <div className="flex items-end justify-between gap-4">
          <div>
            <h1 className="text-lg font-semibold tracking-tight text-zinc-100">
              Assessments
            </h1>
            <p className="mt-0.5 text-sm text-zinc-500">
              Pegá el dominio y dale a Iniciar.
            </p>
          </div>
          <div className="flex items-center gap-3 text-[11px] font-mono">
            <Link
              href={
                assessmentId
                  ? `/v2/attack?assessmentId=${encodeURIComponent(assessmentId)}`
                  : "/v2/attack"
              }
              className="text-zinc-600 hover:text-zinc-400 transition"
            >
              Attack →
            </Link>
            <Link
              href="/v2"
              className="text-zinc-600 hover:text-zinc-400 transition"
            >
              Triage →
            </Link>
          </div>
        </div>

        <section aria-labelledby="launcher-heading">
          <h2 id="launcher-heading" className="sr-only">
            Assessment Launcher
          </h2>
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
