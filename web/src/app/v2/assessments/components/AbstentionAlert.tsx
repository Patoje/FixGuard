"use client";

import React from "react";
import { ShieldCheck, ShieldAlert, AlertTriangle, CheckCircle2, Lock } from "lucide-react";
import type { OrchestratedAssessmentStatusResponse } from "@/lib/v2Api";

interface AbstentionAlertProps {
  status: OrchestratedAssessmentStatusResponse | null;
}

export function AbstentionAlert({ status }: AbstentionAlertProps) {
  if (!status) return null;

  if (status.status === "preflight_denied") {
    return (
      <div className="rounded-2xl border border-amber-500/30 bg-amber-500/10 p-5 backdrop-blur-xl space-y-2 text-xs text-amber-200">
        <div className="flex items-center gap-2.5 font-semibold text-amber-400">
          <ShieldAlert className="h-5 w-5 shrink-0" />
          <span className="text-sm">Preflight Gatekeeper Denied Execution</span>
        </div>
        <p className="leading-relaxed text-zinc-300">
          The requested target was blocked prior to network probing. Reason:{" "}
          <strong className="text-amber-300 font-mono">{status.error || "Preflight validation failed"}</strong>.
        </p>
        <div className="flex items-center gap-2 pt-1 font-mono text-[11px] text-amber-400/90">
          <Lock className="h-3.5 w-3.5" />
          <span>Fail-Closed Security Guarantee: Zero network requests, zero side effects, zero tool spawns.</span>
        </div>
      </div>
    );
  }

  if (status.status === "failed") {
    return (
      <div className="rounded-2xl border border-rose-500/30 bg-rose-500/10 p-5 backdrop-blur-xl space-y-2 text-xs text-rose-200">
        <div className="flex items-center gap-2.5 font-semibold text-rose-400">
          <AlertTriangle className="h-5 w-5 shrink-0" />
          <span className="text-sm">Assessment Execution Failed</span>
        </div>
        <p className="leading-relaxed text-zinc-300">
          An error occurred during stage orchestration:{" "}
          <strong className="text-rose-300 font-mono">{status.error || "Unknown execution error"}</strong>.
        </p>
      </div>
    );
  }

  if (status.status === "circuit_broken") {
    return (
      <div className="rounded-2xl border border-amber-500/30 bg-amber-500/10 p-5 backdrop-blur-xl space-y-2 text-xs text-amber-200">
        <div className="flex items-center gap-2.5 font-semibold text-amber-400">
          <ShieldAlert className="h-5 w-5 shrink-0" />
          <span className="text-sm">Adaptive Target Protection Active (Circuit Breaker Tripped)</span>
        </div>
        <p className="leading-relaxed text-zinc-300">
          Execution safely halted to protect target availability after detecting repeated server errors or timeouts.
          Reason: <strong className="text-amber-300 font-mono">{status.error || "target_instability_circuit_open"}</strong>.
        </p>
        <div className="flex items-center gap-2 pt-1 font-mono text-[11px] text-amber-400/90">
          <ShieldCheck className="h-3.5 w-3.5" />
          <span>Blast Radius Protection: Verified evidence from completed stages is preserved; zero invasive probes dispatched during target distress.</span>
        </div>
      </div>
    );
  }

  return null;

}
