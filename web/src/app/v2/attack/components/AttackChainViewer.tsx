"use client";

import type { AttackChain, AttackChainStepOutcome, ImpactLevel } from "@/lib/v2AttackApi";
import { EpistemicBadge, epistemicBorderClass } from "./EpistemicBadge";

interface AttackChainViewerProps {
  readonly chains: readonly AttackChain[];
}

const OUTCOME_ES: Record<AttackChainStepOutcome, string> = {
  succeeded: "succeeded",
  refuted: "refuted",
  failed: "falló",
  inconclusive: "inconcluso",
};

const IMPACT_ES: Partial<Record<ImpactLevel, string>> = {
  information_exposure: "exposición de información",
  authentication_bypass: "bypass de auth",
  authorization_bypass: "bypass de autorización",
  data_access: "acceso a datos",
  privilege_escalation: "escalada de privilegios",
  lateral_movement: "movimiento lateral",
  rce_demonstrated: "RCE demostrado",
};

export function AttackChainViewer({ chains }: AttackChainViewerProps) {
  if (chains.length === 0) {
    return (
      <div className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-4 text-xs text-zinc-500">
        Todavía no hay cadenas. Aparecen cuando un plan autorizado se ejecuta y deja evidencia.
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
          <div className="min-w-0 space-y-1 mb-2">
            <div className="flex flex-wrap items-center gap-2">
              <EpistemicBadge status={chain.overallEpistemicStatus} />
              <span className="text-[11px] text-zinc-400">
                {IMPACT_ES[chain.impactLevel] ?? chain.impactLevel}
              </span>
            </div>
            <p className="text-xs text-zinc-200 leading-relaxed">{chain.hypothesis}</p>
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
                  <span className="text-[10px] text-zinc-500">Paso {step.sequence}</span>
                  <EpistemicBadge status={step.epistemicStatus} />
                  <span
                    className={`rounded border px-1.5 py-0.5 text-[10px] ${
                      step.outcome === "succeeded"
                        ? "border-emerald-500/30 text-emerald-400"
                        : step.outcome === "refuted"
                          ? "border-rose-500/40 text-rose-300"
                          : "border-zinc-700 text-zinc-400"
                    }`}
                  >
                    {OUTCOME_ES[step.outcome] ?? step.outcome}
                  </span>
                </div>
                <p className="text-[11px] text-zinc-400">{step.evidence.safeMessage}</p>
              </li>
            ))}
          </ol>
        </li>
      ))}
    </ul>
  );
}
