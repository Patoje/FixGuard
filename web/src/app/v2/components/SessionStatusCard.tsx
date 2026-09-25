"use client";

import React, { useEffect, useRef, useState } from "react";
import {
  Activity,
  ArrowRight,
  CheckCircle2,
  Clock,
  AlertTriangle,
  Loader2,
  Terminal,
} from "lucide-react";
import type {
  OrchestratedAssessmentStatusResponse,
  StageResultDto,
} from "@/lib/v2Api";
import { consoleLineClassFromText } from "@/lib/v2/consoleLineTone";

interface SessionStatusCardProps {
  status: OrchestratedAssessmentStatusResponse | null;
  isPolling: boolean;
  onContinueToTriage: () => void;
}

interface TerminalLine {
  readonly id: string;
  readonly at: string;
  readonly stream: "event" | "stdout" | "verdict" | "stderr";
  readonly text: string;
}

const STAGE_LABELS: Record<string, { name: string; tools: string }> = {
  stage_1_domain_zone: {
    name: "Domain & DNS",
    tools: "subfinder, dnsx",
  },
  stage_2_port_service: {
    name: "Ports & Services",
    tools: "naabu",
  },
  stage_3_web_tls: {
    name: "HTTP & TLS",
    tools: "httpx, tlsx",
  },
  stage_4_crawling_parameters: {
    name: "Crawling & Parameters",
    tools: "katana, ffuf, arjun",
  },
  stage_5_secret_inspection: {
    name: "Secret Inspection",
    tools: "trufflehog",
  },
  stage_deep_recon: {
    name: "Deep Recon",
    tools: "SPA / stack probes",
  },
};

/** Ordered pipeline keys used for progress display (includes deep_recon). */
const PIPELINE_ORDER = [
  "stage_1_domain_zone",
  "stage_2_port_service",
  "stage_3_web_tls",
  "stage_4_crawling_parameters",
  "stage_5_secret_inspection",
  "stage_deep_recon",
] as const;

const PIPELINE_TOTAL = PIPELINE_ORDER.length;

/** UI throttle for heartbeat console lines (~25s), even if poller is faster. */
const CONSOLE_HEARTBEAT_MIN_GAP_MS = 25_000;

function formatDurationMs(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return `${ms}ms`;
  if (ms < 60_000) return `${Math.round(ms)}ms`;
  const totalSec = Math.floor(ms / 1000);
  const m = Math.floor(totalSec / 60);
  const s = totalSec % 60;
  return `${m}m ${s}s`;
}

function formatStageLine(stage: StageResultDto): TerminalLine {
  const meta = STAGE_LABELS[stage.stage] ?? {
    name: stage.stage,
    tools: "pipeline",
  };
  const stamp = new Date().toISOString().slice(11, 19);
  const ok = stage.status === "success" || stage.status === "partial_failure";
  return {
    id: `${stage.stage}-${stage.durationMs}-${stage.observationsCount}`,
    at: stamp,
    stream: ok ? "stdout" : "stderr",
    text: `[${stamp}] ${meta.name} → ${stage.status} · ${stage.observationsCount} obs · ${formatDurationMs(stage.durationMs)} · tools: ${meta.tools}`,
  };
}

export function SessionStatusCard({
  status,
  isPolling,
  onContinueToTriage,
}: SessionStatusCardProps) {
  const [lines, setLines] = useState<TerminalLine[]>([]);
  const seenStagesRef = useRef<Set<string>>(new Set());
  const lastStatusRef = useRef<string | null>(null);
  const lastHeartbeatRef = useRef<string | null>(null);
  const lastHbShownAtMsRef = useRef<number>(0);
  const terminalRef = useRef<HTMLPreElement>(null);

  useEffect(() => {
    if (!status) {
      setLines([]);
      seenStagesRef.current = new Set();
      lastStatusRef.current = null;
      lastHeartbeatRef.current = null;
      lastHbShownAtMsRef.current = 0;
      return;
    }

    const next: TerminalLine[] = [];
    const stamp = () => new Date().toISOString().slice(11, 19);

    if (lastStatusRef.current === null) {
      next.push({
        id: `start-${status.assessmentId}`,
        at: stamp(),
        stream: "event",
        text: `[${stamp()}] assessment ${status.assessmentId} · target ${status.targetDomain} · status=${status.status}`,
      });
      next.push({
        id: `scan-${status.scanId}`,
        at: stamp(),
        stream: "event",
        text: `[${stamp()}] scanId=${status.scanId} · polling orchestrated gateway`,
      });
    } else if (lastStatusRef.current !== status.status) {
      next.push({
        id: `status-${status.status}-${Date.now()}`,
        at: stamp(),
        stream:
          status.status === "failed" || status.status === "preflight_denied"
            ? "stderr"
            : status.status === "completed" || status.status === "circuit_broken"
              ? "verdict"
              : "event",
        text: `[${stamp()}] status → ${status.status}${status.error ? ` · ${status.error}` : ""}`,
      });
    }

    for (const key of PIPELINE_ORDER) {
      const stage = status.stages.find((s) => s.stage === key);
      if (!stage) continue;
      const seenKey = `${stage.stage}:${stage.status}:${stage.observationsCount}:${stage.durationMs}`;
      if (seenStagesRef.current.has(seenKey)) continue;
      seenStagesRef.current.add(seenKey);
      next.push(formatStageLine(stage));
      const warnings = Array.isArray(stage.warnings) ? stage.warnings : [];
      if (warnings.length > 0) {
        next.push({
          id: `warn-${stage.stage}-${warnings.length}`,
          at: stamp(),
          stream: "event",
          text: `[${stamp()}]   ↳ warnings: ${warnings.slice(0, 3).join("; ")}`,
        });
      }
    }

    if (status.status === "running") {
      const doneKeys = new Set(status.stages.map((s) => s.stage));
      const current = PIPELINE_ORDER.find((k) => !doneKeys.has(k));
      if (current) {
        const meta = STAGE_LABELS[current];
        const progressId = `progress-${current}`;
        const already = [...seenStagesRef.current].some((k) =>
          k.startsWith(`progress:${current}`)
        );
        if (!already) {
          seenStagesRef.current.add(`progress:${current}`);
          next.push({
            id: progressId,
            at: stamp(),
            stream: "event",
            text: `[${stamp()}] ▶ running ${meta.name} (${meta.tools})…`,
          });
        }
      }
    }

    // Soft liveness — throttle console spam; prefer richer keep-alive / tool hints.
    if (
      status.status === "running" &&
      status.lastHeartbeatAt &&
      status.lastHeartbeatAt !== lastHeartbeatRef.current
    ) {
      const nowMs = Date.now();
      const gapOk =
        lastHbShownAtMsRef.current === 0 ||
        nowMs - lastHbShownAtMsRef.current >= CONSOLE_HEARTBEAT_MIN_GAP_MS;
      const richHint =
        (status.sessionKeepAliveHint && status.sessionKeepAliveHint.trim()) ||
        null;
      const stagePart = status.heartbeatStageHint
        ? STAGE_LABELS[status.heartbeatStageHint]?.name ??
          status.heartbeatStageHint
        : "pipeline";
      const toolPart = status.heartbeatToolHint
        ? ` · ${status.heartbeatToolHint}`
        : "";
      const detail = richHint
        ? richHint
        : `hb still running… ${stagePart}${toolPart}`;

      if (gapOk || richHint) {
        const hbStamp = status.lastHeartbeatAt.slice(11, 19) || stamp();
        next.push({
          id: `hb-${status.lastHeartbeatAt}`,
          at: hbStamp,
          stream: "event",
          text: `[${hbStamp}] ${detail}`,
        });
        lastHbShownAtMsRef.current = nowMs;
      }
      lastHeartbeatRef.current = status.lastHeartbeatAt;
    }

    if (
      (status.status === "completed" || status.status === "circuit_broken") &&
      !seenStagesRef.current.has("done-banner")
    ) {
      seenStagesRef.current.add("done-banner");
      const draftHint =
        typeof status.pendingEvidenceDraftCount === "number"
          ? ` · pending drafts=${status.pendingEvidenceDraftCount}`
          : "";
      next.push({
        id: `done-${status.status}`,
        at: stamp(),
        stream: "verdict",
        text: `[${stamp()}] pipeline ${status.status} · errors=${status.errorCount} warnings=${status.warningCount}${draftHint}`,
      });
    }

    lastStatusRef.current = status.status;

    if (next.length > 0) {
      setLines((prev) => [...prev, ...next].slice(-200));
    }
  }, [status]);

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [lines]);

  if (!status) {
    return (
      <div className="rounded-xl border border-zinc-800/80 bg-zinc-950/40 p-6 text-center text-zinc-500 backdrop-blur-xl">
        <Activity className="mx-auto h-8 w-8 text-zinc-600 opacity-50" />
        <p className="mt-2 text-sm">No active assessment.</p>
        <p className="text-xs text-zinc-600">
          Complete Stage 1 to launch an orchestrated assessment.
        </p>
      </div>
    );
  }

  const isRunning = status.status === "running" || status.status === "pending";
  const isReconDone =
    status.status === "completed" || status.status === "circuit_broken";
  const isFailed =
    status.status === "failed" || status.status === "preflight_denied";
  const canContinueToTriage = isReconDone || isFailed;
  const totalObs = status.stages.reduce((n, s) => n + s.observationsCount, 0);
  const pipelineKeys = new Set<string>(PIPELINE_ORDER);
  const stagesDone = Math.min(
    status.stages.filter((s) => pipelineKeys.has(s.stage)).length,
    PIPELINE_TOTAL
  );
  const stagesLabel =
    isReconDone && stagesDone >= PIPELINE_TOTAL
      ? "Pipeline completo"
      : `${stagesDone}/${PIPELINE_TOTAL}`;

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-950/80 p-6 shadow-2xl backdrop-blur-xl space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-zinc-800/80 pb-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-blue-500/20 bg-blue-500/10 text-blue-400">
            {isRunning ? (
              <Loader2 className="h-5 w-5 animate-spin" />
            ) : (
              <Activity className="h-5 w-5" />
            )}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-semibold tracking-tight text-zinc-100">
                Stage 2: Active Reconnaissance
              </h2>
              <span
                className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-mono font-medium ${
                  isReconDone
                    ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                    : isFailed
                      ? "border-rose-500/30 bg-rose-500/10 text-rose-400"
                      : "border-blue-500/30 bg-blue-500/10 text-blue-400"
                }`}
              >
                <span
                  className={`h-1.5 w-1.5 rounded-full ${
                    isRunning ? "bg-blue-400 animate-pulse" : "bg-current"
                  }`}
                />
                {status.status}
              </span>
            </div>
            <p className="text-xs text-zinc-400 font-mono mt-0.5">
              {status.targetDomain}
              {isRunning && status.lastHeartbeatAt
                ? ` · hb ${status.lastHeartbeatAt.slice(11, 19)}`
                : ""}
              {isPolling ? " · live" : ""}
            </p>
          </div>
        </div>
      </div>

      {isFailed && status.error && (
        <div className="flex items-start gap-2 rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-300">
          <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
          <span>{status.error}</span>
        </div>
      )}

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div className="rounded-lg border border-zinc-800/80 bg-zinc-900/40 p-3">
          <div className="text-[11px] font-medium text-zinc-400 uppercase tracking-wider">
            Etapas
          </div>
          <div className="mt-1 text-xl font-bold font-mono text-zinc-100">
            {stagesLabel}
          </div>
        </div>
        <div className="rounded-lg border border-zinc-800/80 bg-zinc-900/40 p-3">
          <div className="text-[11px] font-medium text-zinc-400 uppercase tracking-wider">
            Señales / URLs vistas
          </div>
          <div className="mt-1 text-xl font-bold font-mono text-blue-400">
            {totalObs}
          </div>
          <p className="mt-0.5 text-[10px] text-zinc-600 leading-snug">
            Respuestas y superficies observadas (no hallazgos)
          </p>
        </div>
        <div className="rounded-lg border border-zinc-800/80 bg-zinc-900/40 p-3">
          <div className="text-[11px] font-medium text-zinc-400 uppercase tracking-wider">
            Errors
          </div>
          <div
            className={`mt-1 text-xl font-bold font-mono ${
              status.errorCount > 0 ? "text-rose-400" : "text-zinc-100"
            }`}
          >
            {status.errorCount}
          </div>
        </div>
        <div className="rounded-lg border border-zinc-800/80 bg-zinc-900/40 p-3">
          <div className="text-[11px] font-medium text-zinc-400 uppercase tracking-wider">
            Drafts
          </div>
          <div className="mt-1 text-xl font-bold font-mono text-purple-400">
            {status.pendingEvidenceDraftCount ?? "—"}
          </div>
        </div>
      </div>

      <div className="rounded-lg border border-zinc-800 bg-black overflow-hidden">
        <div className="flex items-center gap-2 border-b border-zinc-900 bg-zinc-950 px-3 py-1.5 text-[10px] font-mono text-zinc-500">
          <Terminal className="h-3 w-3 text-emerald-500" />
          orchestrated recon console
          {isRunning && (
            <span className="ml-auto text-blue-400 animate-pulse">● running</span>
          )}
        </div>
        <pre
          ref={terminalRef}
          className="h-[28rem] min-h-[18rem] max-h-[70vh] overflow-auto p-3 text-[11px] font-mono leading-relaxed whitespace-pre-wrap break-all"
        >
          {lines.length === 0 ? (
            <span className="text-zinc-600">
              Waiting for pipeline events…
            </span>
          ) : (
            lines.map((line) => (
              <div key={line.id} className={consoleLineClassFromText(line.text)}>
                {line.text}
              </div>
            ))
          )}
          {isRunning && (
            <div className="text-zinc-600 animate-pulse">_</div>
          )}
        </pre>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-zinc-900 bg-zinc-900/20 px-3.5 py-2 text-xs text-zinc-500">
        <div className="flex items-center gap-1.5 font-mono">
          <Clock className="h-3.5 w-3.5 text-zinc-500" />
          Started: {new Date(status.timing.startedAt).toLocaleTimeString()}
        </div>
        {status.timing.durationMs !== undefined && (
          <div className="font-mono">
            Duration: {formatDurationMs(status.timing.durationMs)}
          </div>
        )}
      </div>

      <div className="flex items-center justify-between border-t border-zinc-800/60 pt-4">
        <div className="text-xs text-zinc-400">
          {isReconDone ? (
            <span className="flex items-center gap-1.5 text-emerald-400 font-medium">
              <CheckCircle2 className="h-4 w-4" />
              Reconnaissance finished — continue to evidence triage
            </span>
          ) : isFailed ? (
            <span className="text-rose-400">
              Pipeline stopped. You can still open Triage (may be empty) or
              start a fresh assessment from inicio.
            </span>
          ) : (
            <span>Pipeline de reconocimiento en curso…</span>
          )}
        </div>
        <button
          type="button"
          onClick={onContinueToTriage}
          disabled={!canContinueToTriage}
          className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-xs font-semibold text-white transition hover:bg-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/40 disabled:cursor-not-allowed disabled:opacity-40 shadow-lg shadow-blue-600/20"
        >
          Continue to Triage
          <ArrowRight className="h-3.5 w-3.5" />
        </button>
      </div>
    </div>
  );
}
