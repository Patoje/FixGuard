"use client";

import { Database, ShieldAlert, FileText, CheckCircle2 } from "lucide-react";
import type { AttackChain, EpistemicStatus, ImpactAssessment, ImpactLevel } from "@/lib/v2AttackApi";
import { EpistemicBadge, epistemicBorderClass } from "./EpistemicBadge";

interface ImpactAssessmentViewProps {
  readonly assessments: readonly ImpactAssessment[];
  readonly chains?: readonly AttackChain[];
}

const IMPACT_ES: Record<ImpactLevel, string> = {
  information_exposure: "Exposición de información",
  authentication_bypass: "Bypass de autenticación",
  authorization_bypass: "Bypass de autorización",
  data_access: "Acceso a datos no autorizado",
  privilege_escalation: "Escalada de privilegios",
  lateral_movement: "Movimiento lateral",
  rce_demonstrated: "Ejecución remota demostrada",
};

const EPISTEMIC_ES: Record<EpistemicStatus, string> = {
  OBSERVED: "Observado empíricamente en el objetivo mediante respuesta directa.",
  INFERRED: "Inferido — hipótesis técnica pendiente de validación completa.",
  VERIFIED: "Verificado y confirmado con evidencia forense inobjetable.",
  REFUTED: "Refutado — la prueba no encontró debilidad o fue bloqueada.",
  INCONCLUSIVE: "Inconcluso — evidencia insuficiente para determinar vulnerabilidad o protección.",
};

function resultPhrase(status: EpistemicStatus): string {
  switch (status) {
    case "VERIFIED":
      return "Resultado: Éxito comprobado — La vulnerabilidad se sostuvo con evidencia real.";
    case "OBSERVED":
      return "Resultado: Observado — Hubo respuesta medible del objetivo.";
    case "REFUTED":
      return "Resultado: Refutado — El objetivo resistió o bloqueó el intento.";
    case "INCONCLUSIVE":
      return "Resultado: Inconcluso — Evidencia insuficiente para validar o refutar.";
    default:
      return "Resultado: En análisis — Hipótesis derivada.";
  }
}

function parseHumanImpact(item: ImpactAssessment, chain?: AttackChain) {
  const stepMessages =
    (chain?.steps.map((s) => s.evidence?.safeMessage).filter(Boolean) as string[]) || [];

  // Detect if any step touches Supabase RLS
  const rlsStep = chain?.steps.find(
    (s) =>
      s.capabilityKind === "supabase_rls_read_confirm" ||
      s.capabilityKind === "supabase_rls_write_probe"
  );

  const rawMsg =
    rlsStep?.evidence?.safeMessage ||
    stepMessages.find((m) => m.includes("Data API read on") || m.includes("RLS")) ||
    "";
  const tableMatch = rawMsg.match(/'([^']+)'/) || item.impactDescription.match(/'([^']+)'/);
  const tableName = tableMatch ? tableMatch[1] : null;

  let whatWasTested = item.impactDescription;
  if (tableName) {
    if (rawMsg.includes("read on") || rlsStep?.capabilityKind === "supabase_rls_read_confirm") {
      whatWasTested = `Prueba de lectura anónima contra la tabla '${tableName}' de Supabase REST API (GET ?select=*&limit=1) con clave pública sin autenticación de usuario.`;
    } else if (rawMsg.includes("write on") || rlsStep?.capabilityKind === "supabase_rls_write_probe") {
      whatWasTested = `Prueba de inyección/escritura (POST) de registros en la tabla '${tableName}' con clave pública sin autenticación.`;
    }
  } else if (chain?.hypothesis) {
    whatWasTested = chain.hypothesis;
  } else if (item.impactDescription.startsWith("Chain chn_")) {
    whatWasTested = `Comprobación de control de acceso (${item.impactLevel.replace("_", " ")}).`;
  }

  // Derive business risk and posture based strictly on epistemic status and step outcome
  const isInconclusive =
    item.epistemicStatus === "INCONCLUSIVE" ||
    rlsStep?.outcome === "inconclusive" ||
    /inconclus/i.test(rawMsg) ||
    /0 records observed/i.test(rawMsg);
  const isProtectedBoundary =
    (item.epistemicStatus === "REFUTED" || rlsStep?.outcome === "refuted") &&
    (rawMsg.includes("401") ||
      rawMsg.includes("403") ||
      rawMsg.includes("boundary enforced") ||
      rawMsg.includes("proteg"));
  const isRefuted =
    (item.epistemicStatus === "REFUTED" || rlsStep?.outcome === "refuted") &&
    !isInconclusive;
  const isFailed = rlsStep?.outcome === "failed";
  const isVerifiedOrObserved =
    !isInconclusive &&
    (item.epistemicStatus === "VERIFIED" || item.epistemicStatus === "OBSERVED") &&
    (!rlsStep || rlsStep.outcome === "succeeded");

  let businessRisk: string;
  let riskLevel: "protected" | "vulnerable" | "inconclusive" | "failed" = "inconclusive";

  if (isInconclusive) {
    riskLevel = "inconclusive";
    if (tableName) {
      businessRisk = `Observación inconclusa: La prueba en la tabla '${tableName}' devolvió una respuesta vacía, no estructurada o de tipo HTML/soft-404. No se observó exposición de datos, pero tampoco una denegación explícita (HTTP 401/403). La postura de seguridad permanece no determinada.`;
    } else {
      businessRisk = `Observación inconclusa: La evidencia obtenida es insuficiente para determinar si el objetivo es vulnerable o si el control de seguridad está activo.`;
    }
  } else if (isRefuted) {
    if (isProtectedBoundary) {
      riskLevel = "protected";
      if (tableName) {
        businessRisk = `Control verificado: El acceso anónimo fue denegado por las políticas Row Level Security (RLS) del objetivo (HTTP 401/403). La tabla '${tableName}' protegió sus registros correctamente y no se observó exposición de datos.`;
      } else {
        businessRisk = `Control verificado: Las defensas del objetivo bloquearon el vector de acceso evaluado (HTTP 401/403). El control de seguridad se sostuvo y no se observó compromiso.`;
      }
    } else {
      riskLevel = "inconclusive";
      businessRisk = `Prueba refutada: La hipótesis de vulnerabilidad no se sostuvo, pero no se observó una denegación explícita de seguridad (HTTP 401/403).`;
    }
  } else if (isFailed) {
    riskLevel = "failed";
    businessRisk = `Fallo en la ejecución de la prueba: La evaluación no pudo completarse con éxito. No se pudo verificar la postura de seguridad y no se confirma ninguna vulnerabilidad ni exposición de datos.`;
  } else if (isVerifiedOrObserved) {
    riskLevel = "vulnerable";
    if (tableName) {
      if (rawMsg.includes("write on") || rlsStep?.capabilityKind === "supabase_rls_write_probe") {
        businessRisk = `Manipulación de datos confirmada: La tabla '${tableName}' permitió la inserción/escritura anónima de datos sin credenciales válidas. Un atacante no autenticado podría alterar o inyectar registros.`;
      } else {
        businessRisk = `Exposición de datos confirmada: La tabla '${tableName}' respondió satisfactoriamente (HTTP 200) ante solicitudes anónimas. Row Level Security (RLS) no está activo o posee una política pública permisiva, permitiendo a visitantes no autenticados descargar registros de la base de datos.`;
      }
    } else {
      businessRisk = `Impacto comprobado: La vulnerabilidad fue confirmada empíricamente en el objetivo, sosteniendo evidencia real de ${IMPACT_ES[item.impactLevel] ?? item.impactLevel}.`;
    }
  } else {
    riskLevel = "inconclusive";
    if (tableName) {
      businessRisk = `Hipótesis técnica pendiente de validación empírica. No se ha confirmado debilidad en la tabla '${tableName}' ni se ha demostrado exposición de datos.`;
    } else {
      businessRisk =
        EPISTEMIC_ES[item.epistemicStatus] ?? "Hipótesis técnica pendiente de validación empírica.";
    }
  }

  return {
    tableName,
    whatWasTested,
    businessRisk,
    riskLevel,
    stepMessages,
  };
}

/**
 * Displays structured impact assessments in plain, human-friendly Spanish.
 * Transforms internal machine telemetry into clear security findings.
 */
export function ImpactAssessmentView({ assessments, chains }: ImpactAssessmentViewProps) {
  if (assessments.length === 0) {
    return (
      <div className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-4 text-xs text-zinc-500 flex items-center gap-2">
        <FileText className="h-4 w-4 text-zinc-600" />
        Todavía no hay impacto evaluado. Aparece automáticamente cuando se ejecuta una prueba y genera evidencia real.
      </div>
    );
  }

  return (
    <ul className="space-y-3">
      {assessments.map((item) => {
        const matchingChain = chains?.find((c) => c.chainId === item.chainId);
        const { tableName, whatWasTested, businessRisk, riskLevel, stepMessages } =
          parseHumanImpact(item, matchingChain);

        return (
          <li
            key={`${item.chainId}-${item.assessedAt}`}
            className={`rounded-lg border-2 p-3.5 space-y-3 transition-all ${epistemicBorderClass(
              item.epistemicStatus
            )}`}
          >
            {/* Header */}
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-zinc-900 pb-2">
              <div className="flex flex-wrap items-center gap-2">
                <EpistemicBadge status={item.epistemicStatus} />
                <span className="text-xs font-semibold text-zinc-100">
                  {IMPACT_ES[item.impactLevel] ?? item.impactLevel}
                </span>
                {tableName && (
                  <span className="flex items-center gap-1 rounded bg-zinc-900 border border-zinc-800 px-2 py-0.5 font-mono text-[11px] text-emerald-400">
                    <Database className="h-3 w-3" />
                    tabla: {tableName}
                  </span>
                )}
              </div>

              <span className="text-[10px] font-mono text-zinc-500">
                {item.chainId.slice(-12)}
              </span>
            </div>

            {/* What was tested */}
            <div className="space-y-1">
              <span className="text-[11px] font-medium text-zinc-400 block">
                Qué se probó exactamente:
              </span>
              <p className="text-xs text-zinc-200 leading-relaxed bg-zinc-950/50 p-2 rounded border border-zinc-900">
                {whatWasTested}
              </p>
            </div>

            {/* Evidence messages */}
            {stepMessages.length > 0 && (
              <div className="space-y-1.5">
                <span className="text-[11px] font-medium text-zinc-400 block">
                  Evidencia empírica obtenida del objetivo:
                </span>
                <ul className="space-y-1">
                  {stepMessages.map((msg, idx) => (
                    <li
                      key={idx}
                      className="flex items-start gap-2 rounded bg-zinc-900/60 px-2.5 py-1.5 text-[11px] font-mono text-emerald-300 border border-zinc-800/80"
                    >
                      <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0 mt-0.5" />
                      <span>{msg}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Outcome phrase */}
            <p className="text-[11px] font-medium text-emerald-400">
              {resultPhrase(item.epistemicStatus)}
            </p>

            {/* Business risk & meaning */}
            {riskLevel === "protected" ? (
              <div className="rounded-md border border-emerald-900/40 bg-emerald-950/20 p-2.5 space-y-1">
                <span className="text-[11px] font-semibold text-emerald-300 flex items-center gap-1.5">
                  <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                  Control de seguridad verificado (Acceso denegado):
                </span>
                <p className="text-[11px] text-zinc-300 leading-relaxed">
                  {businessRisk}
                </p>
              </div>
            ) : riskLevel === "vulnerable" ? (
              <div className="rounded-md border border-rose-900/40 bg-rose-950/20 p-2.5 space-y-1">
                <span className="text-[11px] font-semibold text-rose-300 flex items-center gap-1.5">
                  <ShieldAlert className="h-3.5 w-3.5 text-rose-400" />
                  Qué significa para la seguridad del objetivo (Riesgo confirmado):
                </span>
                <p className="text-[11px] text-zinc-300 leading-relaxed">
                  {businessRisk}
                </p>
              </div>
            ) : riskLevel === "failed" ? (
              <div className="rounded-md border border-amber-900/40 bg-amber-950/20 p-2.5 space-y-1">
                <span className="text-[11px] font-semibold text-amber-300 flex items-center gap-1.5">
                  <ShieldAlert className="h-3.5 w-3.5 text-amber-400" />
                  Fallo en la prueba de evaluación:
                </span>
                <p className="text-[11px] text-zinc-300 leading-relaxed">
                  {businessRisk}
                </p>
              </div>
            ) : (
              <div className="rounded-md border border-zinc-800 bg-zinc-900/40 p-2.5 space-y-1">
                <span className="text-[11px] font-semibold text-zinc-400 flex items-center gap-1.5">
                  <FileText className="h-3.5 w-3.5 text-zinc-400" />
                  Evaluación técnica preliminar (Hipótesis):
                </span>
                <p className="text-[11px] text-zinc-300 leading-relaxed">
                  {businessRisk}
                </p>
              </div>
            )}

            {item.evidenceBasis.length > 0 && (
              <div className="flex items-center gap-2 pt-1 text-[10px] text-zinc-500 font-mono">
                <span>Evidencias forenses enlazadas:</span>
                {item.evidenceBasis.map((evId, idx) => (
                  <span key={`${evId}-${idx}`} className="rounded bg-zinc-900 px-1.5 py-0.5 text-zinc-400 border border-zinc-800">
                    {evId}
                  </span>
                ))}
              </div>
            )}
          </li>
        );
      })}
    </ul>
  );
}
