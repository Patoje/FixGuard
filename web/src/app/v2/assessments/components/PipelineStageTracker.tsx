"use client";

import React from "react";
import {
  Activity,
  CheckCircle2,
  Clock,
  AlertCircle,
  Loader2,
  Radio,
  Layers,
  Key,
  Globe2,
  Network,
  Cpu,
  Search,
  Lock,
  RefreshCw
} from "lucide-react";
import type {
  OrchestratedAssessmentStatusResponse,
  StageResultDto
} from "@/lib/v2Api";

interface PipelineStageTrackerProps {
  status: OrchestratedAssessmentStatusResponse | null;
  onRefresh: () => void;
  isPolling: boolean;
}

interface StageDefinition {
  key: string;
  name: string;
  subtitle: string;
  icon: React.ComponentType<{ className?: string }>;
}

const STAGES: StageDefinition[] = [
  {
    key: "stage_1_domain_zone",
    name: "Stage 1: Domain & DNS",
    subtitle: "Subfinder & Dnsx multi-record discovery",
    icon: Globe2
  },
  {
    key: "stage_2_port_service",
    name: "Stage 2: Ports & Services",
    subtitle: "Naabu non-intrusive TCP port enumeration",
    icon: Network
  },
  {
    key: "stage_3_web_tls",
    name: "Stage 3: HTTP & TLS Inspection",
    subtitle: "Httpx technology fingerprinting & Tlsx certificates",
    icon: Cpu
  },
  {
    key: "stage_4_crawling_parameters",
    name: "Stage 4: Crawling & Parameters",
    subtitle: "Katana URL discovery, Ffuf content & Arjun parameters",
    icon: Search
  },
  {
    key: "stage_5_secret_inspection",
    name: "Stage 5: Secret Inspection",
    subtitle: "Trufflehog credential & API token scanning",
    icon: Lock
  }
];

export function PipelineStageTracker({
  status,
  onRefresh,
  isPolling
}: PipelineStageTrackerProps) {
  if (!status) {
    return (
      <div className="rounded-2xl border border-zinc-800/60 bg-zinc-950/40 p-8 text-center text-zinc-500 backdrop-blur-xl">
        <Activity className="mx-auto h-8 w-8 text-zinc-600 opacity-40 animate-pulse" />
        <p className="mt-3 text-sm font-medium text-zinc-400">No active assessment in progress</p>
        <p className="text-xs text-zinc-600 mt-1">
          Launch an assessment above to observe live 5-stage orchestration progression.
        </p>
      </div>
    );
  }

  const isCompleted = status.status === "completed";
  const isDenied = status.status === "preflight_denied";
  const isFailed = status.status === "failed";
  const isRunning = status.status === "running";
  const isCircuitBroken = status.status === "circuit_broken";

  const stageMap = new Map<string, StageResultDto>();
  for (const st of status.stages) {
    stageMap.set(st.stage, st);
  }

  return (
    <div className="rounded-2xl border border-zinc-800 bg-zinc-950/80 p-6 shadow-2xl backdrop-blur-xl space-y-6">
      {/* Header Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-zinc-800/80 pb-5">
        <div className="flex items-center gap-3">
          <div
            className={`flex h-10 w-10 items-center justify-center rounded-xl border ${
              isCompleted
                ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                : isCircuitBroken
                ? "border-amber-500/30 bg-amber-500/10 text-amber-400"
                : isDenied || isFailed
                ? "border-rose-500/30 bg-rose-500/10 text-rose-400"
                : "border-blue-500/30 bg-blue-500/10 text-blue-400"
            }`}
          >
            {isRunning ? (
              <Loader2 className="h-5 w-5 animate-spin" />
            ) : isCompleted ? (
              <CheckCircle2 className="h-5 w-5" />
            ) : isCircuitBroken ? (
              <AlertCircle className="h-5 w-5 text-amber-400" />
            ) : (
              <AlertCircle className="h-5 w-5" />
            )}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold text-white tracking-wide">
                Target Pipeline Tracker: <span className="font-mono text-emerald-400">{status.targetDomain}</span>
              </h3>
              <span
                className={`rounded px-2 py-0.5 text-[10px] font-mono font-semibold uppercase ${
                  isCompleted
                    ? "bg-emerald-500/10 border border-emerald-500/30 text-emerald-400"
                    : isCircuitBroken
                    ? "bg-amber-500/10 border border-amber-500/30 text-amber-400"
                    : isDenied || isFailed
                    ? "bg-rose-500/10 border border-rose-500/30 text-rose-400"
                    : "bg-blue-500/10 border border-blue-500/30 text-blue-400"
                }`}
              >
                {status.status}
              </span>
            </div>
            <p className="text-xs text-zinc-400 font-mono mt-0.5">
              Assessment ID: {status.assessmentId}
            </p>
          </div>
        </div>


        <div className="flex items-center gap-3 text-xs font-mono">
          {isPolling && (
            <span className="flex items-center gap-1.5 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-3 py-1 text-emerald-400">
              <Radio className="h-3 w-3 animate-pulse text-emerald-400" />
              <span>Polling Gateway (2s)</span>
            </span>
          )}
          <button
            type="button"
            onClick={onRefresh}
            className="flex items-center gap-1.5 rounded-lg border border-zinc-800 bg-zinc-900/80 hover:bg-zinc-800 px-3 py-1 text-zinc-300 transition cursor-pointer"
          >
            <RefreshCw className="h-3 w-3" />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Progress Stepper (5 Stages) */}
      <div className="space-y-3">
        <h4 className="text-xs font-mono uppercase tracking-wider text-zinc-400">
          M73 Composite Orchestration Stages
        </h4>

        <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
          {STAGES.map((stageDef, index) => {
            const stageResult = stageMap.get(stageDef.key);
            const isStageDone = stageResult !== undefined;
            const isCurrent = isRunning && !isStageDone && (index === 0 || stageMap.has(STAGES[index - 1].key));
            const Icon = stageDef.icon;

            return (
              <div
                key={stageDef.key}
                className={`relative rounded-xl border p-4 transition-all ${
                  isStageDone
                    ? "border-emerald-500/30 bg-emerald-500/5 shadow-sm shadow-emerald-500/5"
                    : isCurrent
                    ? "border-blue-500/50 bg-blue-500/10 shadow-lg shadow-blue-500/10 animate-pulse"
                    : isDenied || isFailed
                    ? "border-zinc-900 bg-zinc-950/40 opacity-40"
                    : "border-zinc-800/80 bg-zinc-900/40 text-zinc-500"
                }`}
              >
                <div className="flex items-center justify-between gap-2 mb-2">
                  <div
                    className={`flex h-7 w-7 items-center justify-center rounded-lg border text-xs font-mono font-bold ${
                      isStageDone
                        ? "border-emerald-500/40 bg-emerald-500/20 text-emerald-400"
                        : isCurrent
                        ? "border-blue-500/40 bg-blue-500/20 text-blue-400"
                        : "border-zinc-800 bg-zinc-900 text-zinc-600"
                    }`}
                  >
                    {isStageDone ? (
                      <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                    ) : isCurrent ? (
                      <Loader2 className="h-4 w-4 animate-spin text-blue-400" />
                    ) : (
                      index + 1
                    )}
                  </div>
                  <Icon className={`h-4 w-4 ${isStageDone ? "text-emerald-400" : isCurrent ? "text-blue-400" : "text-zinc-600"}`} />
                </div>

                <div className="text-xs font-semibold text-zinc-200 truncate">{stageDef.name}</div>
                <div className="text-[11px] text-zinc-500 line-clamp-2 mt-0.5">{stageDef.subtitle}</div>

                {stageResult && (
                  <div className="mt-3 pt-2 border-t border-zinc-800/60 flex items-center justify-between text-[11px] font-mono">
                    <span className="text-emerald-400">
                      {stageResult.observationsCount} obs
                    </span>
                    <span className="text-zinc-500">
                      {stageResult.durationMs}ms
                    </span>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Timing and Errors Banner */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-zinc-900 bg-zinc-900/40 p-4 text-xs font-mono text-zinc-400">
        <div className="flex items-center gap-4">
          <span className="flex items-center gap-1.5">
            <Clock className="h-3.5 w-3.5 text-zinc-500" />
            Started: <strong className="text-zinc-300">{new Date(status.timing.startedAt).toLocaleTimeString()}</strong>
          </span>
          {status.timing.durationMs !== undefined && (
            <span>
              Duration: <strong className="text-zinc-200">{status.timing.durationMs}ms</strong>
            </span>
          )}
        </div>

        <div className="flex items-center gap-4">
          <span>Errors: <strong className={status.errorCount > 0 ? "text-rose-400" : "text-zinc-400"}>{status.errorCount}</strong></span>
          <span>Warnings: <strong className={status.warningCount > 0 ? "text-amber-400" : "text-zinc-400"}>{status.warningCount}</strong></span>
        </div>
      </div>

      {/* Lineage Tuple Panel */}
      <div className="rounded-xl border border-zinc-900 bg-black/50 p-4 space-y-2">
        <div className="flex items-center gap-2 text-xs font-semibold text-zinc-400">
          <Layers className="h-3.5 w-3.5 text-purple-400" />
          <span>Continuous Lineage Tuple (ADR-001 Verified)</span>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-2 text-[11px] font-mono">
          <div className="rounded bg-zinc-900/60 p-2 border border-zinc-800/60">
            <span className="text-zinc-500 block text-[10px]">ASSESSMENT ID</span>
            <span className="text-zinc-200 truncate block">{status.lineage.assessmentId}</span>
          </div>
          <div className="rounded bg-zinc-900/60 p-2 border border-zinc-800/60">
            <span className="text-zinc-500 block text-[10px]">SCAN ID</span>
            <span className="text-zinc-200 truncate block">{status.lineage.scanId}</span>
          </div>
          <div className="rounded bg-zinc-900/60 p-2 border border-zinc-800/60">
            <span className="text-zinc-500 block text-[10px]">GRANT ID</span>
            <span className="text-zinc-200 truncate block">{status.lineage.authorizationGrantId}</span>
          </div>
          <div className="rounded bg-zinc-900/60 p-2 border border-zinc-800/60">
            <span className="text-zinc-500 block text-[10px]">DECISION ID</span>
            <span className="text-zinc-200 truncate block">{status.lineage.authorizationDecisionId}</span>
          </div>
          <div className="rounded bg-zinc-900/60 p-2 border border-zinc-800/60">
            <span className="text-zinc-500 block text-[10px]">ACTOR ID</span>
            <span className="text-zinc-200 truncate block">{status.lineage.actorId}</span>
          </div>
        </div>
      </div>
    </div>
  );
}
