"use client";

import React, { useState } from "react";
import { Activity, RefreshCw, Play, CheckCircle2, Clock, AlertTriangle, Loader2 } from "lucide-react";
import { v2ApiClient, V2ApiError } from "@/lib/v2/apiClient";
import type { AssessmentDetailsDto, AssessmentSummaryDto } from "@/lib/v2/types";

interface SessionStatusCardProps {
  session: AssessmentSummaryDto | AssessmentDetailsDto | null;
  onSessionUpdated: (details: AssessmentDetailsDto) => void;
  onRefresh: () => Promise<void>;
  isRefreshing: boolean;
}

export function SessionStatusCard({
  session,
  onSessionUpdated,
  onRefresh,
  isRefreshing
}: SessionStatusCardProps) {
  const [runningRecon, setRunningRecon] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  if (!session) {
    return (
      <div className="rounded-xl border border-zinc-800/80 bg-zinc-950/40 p-6 text-center text-zinc-500 backdrop-blur-xl">
        <Activity className="mx-auto h-8 w-8 text-zinc-600 opacity-50" />
        <p className="mt-2 text-sm">No active assessment session loaded.</p>
        <p className="text-xs text-zinc-600">Complete Stage 1 to launch or enter a session ID.</p>
      </div>
    );
  }

  const handleTriggerRecon = async () => {
    setRunningRecon(true);
    setError(null);
    try {
      const details = await v2ApiClient.triggerRecon(session.sessionId);
      onSessionUpdated(details);
    } catch (err) {
      if (err instanceof V2ApiError) {
        setError(`[${err.errorType}] ${err.message}`);
      } else {
        setError((err as Error).message || "Failed to trigger reconnaissance");
      }
    } finally {
      setRunningRecon(false);
    }
  };

  const isReconDone =
    session.lifecycleStatus === "profile_updated" ||
    session.lifecycleStatus === "intelligence_running" ||
    session.lifecycleStatus === "completed";

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-950/80 p-6 shadow-2xl backdrop-blur-xl">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-zinc-800/80 pb-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-blue-500/20 bg-blue-500/10 text-blue-400">
            <Activity className="h-5 w-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-semibold tracking-tight text-zinc-100">
                Stage 2: Session & Active Recon Overview
              </h2>
              <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-0.5 text-xs font-mono font-medium text-emerald-400">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                {session.lifecycleStatus}
              </span>
            </div>
            <p className="text-xs text-zinc-400">
              Session state managed by V2AssessmentRuntime with optimistic versioning
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={onRefresh}
            disabled={isRefreshing}
            className="inline-flex items-center gap-1.5 rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-1.5 text-xs font-medium text-zinc-300 transition hover:bg-zinc-800 focus:outline-none focus:ring-2 focus:ring-zinc-700 disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isRefreshing ? "animate-spin text-blue-400" : ""}`} />
            Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="mt-4 flex items-start gap-2 rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-300">
          <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
          <span>{error}</span>
        </div>
      )}

      {/* Metrics Grid */}
      <div className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div className="rounded-lg border border-zinc-800/80 bg-zinc-900/40 p-3">
          <div className="text-[11px] font-medium text-zinc-400 uppercase tracking-wider">Version</div>
          <div className="mt-1 text-xl font-bold font-mono text-zinc-100">{session.version}</div>
        </div>
        <div className="rounded-lg border border-zinc-800/80 bg-zinc-900/40 p-3">
          <div className="text-[11px] font-medium text-zinc-400 uppercase tracking-wider">Evidence Collections</div>
          <div className="mt-1 text-xl font-bold font-mono text-blue-400">{session.evidenceCount}</div>
        </div>
        <div className="rounded-lg border border-zinc-800/80 bg-zinc-900/40 p-3">
          <div className="text-[11px] font-medium text-zinc-400 uppercase tracking-wider">Pending Recommendations</div>
          <div className="mt-1 text-xl font-bold font-mono text-amber-400">{session.pendingRecommendationCount}</div>
        </div>
        <div className="rounded-lg border border-zinc-800/80 bg-zinc-900/40 p-3">
          <div className="text-[11px] font-medium text-zinc-400 uppercase tracking-wider">Approved Requests</div>
          <div className="mt-1 text-xl font-bold font-mono text-emerald-400">{session.approvedRequestCount}</div>
        </div>
      </div>

      {/* Metadata Footprint */}
      <div className="mt-4 flex flex-wrap items-center justify-between gap-2 rounded-lg border border-zinc-900 bg-zinc-900/20 px-3.5 py-2 text-xs text-zinc-500">
        <div className="flex items-center gap-1.5 font-mono">
          <Clock className="h-3.5 w-3.5 text-zinc-500" />
          Created: {new Date(session.createdAt).toLocaleTimeString()}
        </div>
        <div className="font-mono">
          Last Updated: {new Date(session.updatedAt).toLocaleTimeString()}
        </div>
      </div>

      {/* Action Trigger */}
      <div className="mt-5 flex items-center justify-between border-t border-zinc-800/60 pt-4">
        <div className="text-xs text-zinc-400">
          {isReconDone ? (
            <span className="flex items-center gap-1.5 text-emerald-400 font-medium">
              <CheckCircle2 className="h-4 w-4" />
              Reconnaissance executed; evidence captured
            </span>
          ) : (
            <span>Execute discovery probes to populate findings</span>
          )}
        </div>
        <button
          type="button"
          onClick={handleTriggerRecon}
          disabled={runningRecon || isReconDone}
          className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-xs font-semibold text-white transition hover:bg-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/40 disabled:cursor-not-allowed disabled:opacity-40 shadow-lg shadow-blue-600/20"
        >
          {runningRecon ? (
            <>
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
              Running Probes...
            </>
          ) : (
            <>
              <Play className="h-3.5 w-3.5" />
              {isReconDone ? "Recon Complete" : "Trigger Initial Recon"}
            </>
          )}
        </button>
      </div>
    </div>
  );
}
