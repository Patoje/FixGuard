"use client";

import type { EpistemicStatus, ImpactAssessment, ImpactLevel } from "@/lib/v2AttackApi";
import { EpistemicBadge, epistemicBorderClass } from "./EpistemicBadge";

interface ImpactAssessmentViewProps {
  readonly assessments: readonly ImpactAssessment[];
}

const IMPACT_ES: Record<ImpactLevel, string> = {
  information_exposure: "Exposición de información",
  authentication_bypass: "Bypass de autenticación",
  authorization_bypass: "Bypass de autorización",
  data_access: "Acceso a datos",
  privilege_escalation: "Escalada de privilegios",
  lateral_movement: "Movimiento lateral",
  rce_demonstrated: "Ejecución remota demostrada",
};

const EPISTEMIC_ES: Record<EpistemicStatus, string> = {
  OBSERVED: "Observado en el objetivo (hecho medible).",
  INFERRED: "Inferido — hipótesis derivada, no cerrada.",
  VERIFIED: "Verificado con evidencia suficiente.",
  REFUTED: "Refutado — la hipótesis no se sostuvo.",
};

function resultPhrase(status: EpistemicStatus): string {
  switch (status) {
    case "VERIFIED":
      return "Resultado: succeeded — la prueba se sostuvo.";
    case "OBSERVED":
      return "Resultado: observed — hubo respuesta real del objetivo.";
    case "REFUTED":
      return "Resultado: refuted — no se confirmó el impacto.";
    default:
      return "Resultado: inferred — aún no es un hallazgo cerrado.";
  }
}

/**
 * Displays structured impact assessments in plain Spanish.
 * ALWAYS pairs epistemicStatus with impactLevel — never rank/sort by level alone.
 */
export function ImpactAssessmentView({ assessments }: ImpactAssessmentViewProps) {
  if (assessments.length === 0) {
    return (
      <div className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-4 text-xs text-zinc-500">
        Todavía no hay impacto evaluado. Aparece solo después de cadenas con
        evidencia real.
      </div>
    );
  }

  return (
    <ul className="space-y-3">
      {assessments.map((item) => (
        <li
          key={`${item.chainId}-${item.assessedAt}`}
          className={`rounded-lg border-2 p-3 space-y-2 ${epistemicBorderClass(item.epistemicStatus)}`}
        >
          <div className="flex flex-wrap items-center gap-2">
            <EpistemicBadge status={item.epistemicStatus} />
            <span className="text-xs font-medium text-zinc-200">
              {IMPACT_ES[item.impactLevel] ?? item.impactLevel}
            </span>
          </div>

          <p className="text-[11px] text-zinc-400">
            <span className="text-zinc-500">Qué se probó: </span>
            {item.impactDescription}
          </p>

          <p className="text-[11px] text-zinc-300">{resultPhrase(item.epistemicStatus)}</p>

          <p className="text-[11px] text-zinc-400 leading-relaxed">
            <span className="text-zinc-500">Qué significa para el objetivo: </span>
            {EPISTEMIC_ES[item.epistemicStatus]}
            {item.evidenceBasis.length > 0
              ? ` · ${item.evidenceBasis.length} evidencia(s) enlazadas.`
              : ""}
          </p>
        </li>
      ))}
    </ul>
  );
}
