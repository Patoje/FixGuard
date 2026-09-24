"use client";

import { Activity, CheckCircle2, XCircle, AlertOctagon, CircleDot } from "lucide-react";
import type { AttackExecutionRecordDto, AttackStepExecutionDto } from "@/lib/v2AttackApi";

interface StepExecutionMonitorProps {
  readonly record: AttackExecutionRecordDto | null;
  readonly lastError?: string | null;
}

type DisplayOutcome = "succeeded" | "refuted" | "circuit_broken" | "failed" | "other";

function classifyOutcome(step: AttackStepExecutionDto): DisplayOutcome {
  if (step.outcome === "succeeded" || step.outcome === "observed") return "succeeded";
  if (step.outcome === "refuted") return "refuted";
  if (
    step.gatesPassed === "gate_circuit_open" ||
    step.reasonCode === "gate_circuit_open" ||
    step.reasonCode.includes("circuit")
  ) {
    return "circuit_broken";
  }
  if (step.outcome === "failed" || step.outcome === "preflight_denied") return "failed";
  return "other";
}

function OutcomeIcon({ outcome }: { readonly outcome: DisplayOutcome }) {
  switch (outcome) {
    case "succeeded":
      return <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />;
    case "refuted":
      return <XCircle className="h-3.5 w-3.5 text-rose-400" />;
    case "circuit_broken":
      return <AlertOctagon className="h-3.5 w-3.5 text-orange-400" />;
    case "failed":
      return <XCircle className="h-3.5 w-3.5 text-zinc-400" />;
    default:
      return <CircleDot className="h-3.5 w-3.5 text-zinc-500" />;
  }
}

function outcomeLabel(outcome: DisplayOutcome, raw: string): string {
  if (outcome === "circuit_broken") return "circuit_broken";
  if (outcome === "succeeded") return raw === "observed" ? "succeeded (observed)" : "succeeded";
  return raw;
}

export function StepExecutionMonitor({ record, lastError }: StepExecutionMonitorProps) {
  if (!record && !lastError) {
    return (
      <div className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-4 text-xs text-zinc-500">
        No execution yet. Authorize a plan, then execute to populate step outcomes.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {lastError && (
        <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-[11px] text-rose-300">
          {lastError}
        </div>
      )}

      {record && (
        <>
          <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono text-zinc-400">
            <Activity className="h-3.5 w-3.5 text-sky-400" />
            <span>
              exec <strong className="text-zinc-200">{record.executionId}</strong>
            </span>
            <span className="text-zinc-700">·</span>
            <span>
              status{" "}
              <strong
                className={
                  record.status === "completed" ? "text-emerald-400" : "text-amber-400"
                }
              >
                {record.status}
              </strong>
            </span>
            <span className="text-zinc-700">·</span>
            <span className="text-zinc-500">{record.capability}</span>
          </div>

          <ul className="space-y-2">
            {record.stepRecords.map((step) => {
              const display = classifyOutcome(step);
              return (
                <li
                  key={step.stepId}
                  className={`rounded-lg border px-3 py-2 ${
                    display === "refuted"
                      ? "border-rose-500/40 bg-rose-950/20"
                      : display === "circuit_broken"
                        ? "border-orange-500/40 bg-orange-950/20"
                        : display === "succeeded"
                          ? "border-emerald-500/30 bg-emerald-950/10"
                          : "border-zinc-800 bg-zinc-950/60"
                  }`}
                >
                  <div className="flex items-start gap-2">
                    <OutcomeIcon outcome={display} />
                    <div className="min-w-0 flex-1 space-y-1">
                      <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono">
                        <span className="text-zinc-200">{step.stepId}</span>
                        <span
                          className={`rounded border px-1.5 py-0.5 text-[10px] ${
                            display === "succeeded"
                              ? "border-emerald-500/40 text-emerald-400"
                              : display === "refuted"
                                ? "border-rose-500/40 text-rose-300"
                                : display === "circuit_broken"
                                  ? "border-orange-500/40 text-orange-300"
                                  : "border-zinc-700 text-zinc-400"
                          }`}
                        >
                          {outcomeLabel(display, step.outcome)}
                        </span>
                      </div>
                      <p className="text-[11px] text-zinc-500">
                        reason: <span className="text-zinc-400">{step.reasonCode}</span>
                      </p>
                      {step.evidenceId && (
                        <p className="text-[10px] font-mono text-zinc-600">
                          evidenceId: {step.evidenceId}
                        </p>
                      )}
                      {typeof step.gatesPassed === "string" && (
                        <p className="text-[10px] font-mono text-amber-400/80">
                          gate: {step.gatesPassed}
                        </p>
                      )}
                      {(step.verificationStateBefore || step.verificationStateAfter) && (
                        <p className="text-[10px] font-mono text-zinc-600">
                          verification: {step.verificationStateBefore ?? "?"} →{" "}
                          {step.verificationStateAfter ?? "?"}
                        </p>
                      )}
                    </div>
                  </div>
                </li>
              );
            })}
          </ul>

          {record.updatedFindingStates.length > 0 && (
            <div className="rounded border border-zinc-800 bg-zinc-900/40 px-3 py-2">
              <h4 className="text-[10px] font-mono uppercase text-zinc-500 mb-1">
                Finding verification deltas
              </h4>
              <ul className="space-y-0.5 text-[10px] font-mono text-zinc-400">
                {record.updatedFindingStates.map((f) => (
                  <li key={f.id}>
                    {f.id}: {f.verificationState}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
    </div>
  );
}
