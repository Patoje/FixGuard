"use client";

import type { AttackChain } from "@/lib/v2AttackApi";
import { EpistemicBadge, epistemicBorderClass } from "./EpistemicBadge";

interface AttackChainViewerProps {
  readonly chains: readonly AttackChain[];
}

export function AttackChainViewer({ chains }: AttackChainViewerProps) {
  if (chains.length === 0) {
    return (
      <div className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-4 text-xs text-zinc-500">
        No attack chains recorded.
      </div>
    );
  }

  return (
    <ul className="space-y-3">
      {chains.map((chain) => (
        <li
          key={chain.chainId}
          className={`rounded-lg border-2 p-3 ${epistemicBorderClass(chain.overallEpistemicStatus)}`}
        >
          <div className="flex flex-wrap items-start justify-between gap-2 mb-2">
            <div className="min-w-0 space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <EpistemicBadge status={chain.overallEpistemicStatus} />
                <span className="text-[10px] font-mono text-zinc-500">{chain.status}</span>
                <span className="text-[10px] font-mono text-zinc-600">{chain.objectiveKind}</span>
              </div>
              <p className="text-xs text-zinc-200">{chain.hypothesis}</p>
              <p className="text-[10px] font-mono text-zinc-500">
                impactLevel: <span className="text-zinc-300">{chain.impactLevel}</span>
                <span className="text-zinc-700 mx-1">·</span>
                declared: <span className="text-zinc-400">{chain.declaredImpactLevel}</span>
                <span className="text-zinc-700 mx-1">·</span>
                <EpistemicBadge status={chain.overallEpistemicStatus} />
              </p>
            </div>
            <span className="text-[10px] font-mono text-zinc-600 shrink-0">{chain.chainId}</span>
          </div>

          <ol className="space-y-2 border-t border-zinc-900/80 pt-2">
            {chain.steps.map((step) => (
              <li
                key={step.stepId}
                className={`rounded border px-2.5 py-2 ${epistemicBorderClass(step.epistemicStatus)} ${
                  step.epistemicStatus === "REFUTED" ? "ring-1 ring-rose-500/40" : ""
                }`}
              >
                <div className="flex flex-wrap items-center gap-2 mb-1">
                  <span className="text-[10px] font-mono text-zinc-500">#{step.sequence}</span>
                  <EpistemicBadge status={step.epistemicStatus} />
                  <span
                    className={`rounded border px-1.5 py-0.5 text-[10px] font-mono ${
                      step.outcome === "succeeded"
                        ? "border-emerald-500/30 text-emerald-400"
                        : step.outcome === "refuted"
                          ? "border-rose-500/40 text-rose-300"
                          : "border-zinc-700 text-zinc-400"
                    }`}
                  >
                    {step.outcome}
                  </span>
                  <span className="text-[10px] font-mono text-zinc-500">{step.capabilityKind}</span>
                </div>
                <p className="text-[11px] text-zinc-400">{step.evidence.safeMessage}</p>
                <p className="text-[10px] font-mono text-zinc-600 mt-0.5">
                  {step.evidence.reasonCode}
                  {step.evidence.evidenceId ? ` · ${step.evidence.evidenceId}` : ""}
                </p>
              </li>
            ))}
          </ol>
        </li>
      ))}
    </ul>
  );
}
