"use client";

import { useCallback, useEffect, useState } from "react";
import { FlaskConical, Download, Check, X } from "lucide-react";
import {
  getParrotImportObservations,
  reviewParrotImportObservation,
  type ParrotImportedObservationDto,
} from "@/lib/v2Api";
import { getOperatorSessionIdentity } from "@/lib/v2/operatorSession";

/**
 * Validación manual (Parrot) — handoff panel for Stage 4: Attack Mode.
 * Export dossier -> operator validates by hand in Parrot -> import result
 * -> review here. Never starts/stops the VM, never auto-confirms anything.
 */
export function ParrotHandoffPanel({ assessmentId }: { assessmentId: string }) {
  const [observations, setObservations] = useState<readonly ParrotImportedObservationDto[]>([]);
  const [busyId, setBusyId] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await getParrotImportObservations(assessmentId);
      setObservations(res.observations);
    } catch {
      // Transient fetch errors shouldn't blank an already-loaded list.
    }
  }, [assessmentId]);

  useEffect(() => {
    load();
  }, [load]);

  const review = async (observationId: string, decision: "approve_evidence" | "reject") => {
    setBusyId(observationId);
    try {
      await reviewParrotImportObservation(assessmentId, observationId, {
        decision,
        reviewerId: getOperatorSessionIdentity(),
      });
      await load();
    } finally {
      setBusyId(null);
    }
  };

  const pending = observations.filter((o) => !o.review);

  return (
    <div className="rounded-xl border border-zinc-800/90 bg-zinc-950/80 p-4 space-y-3">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <FlaskConical className="h-4 w-4 text-purple-400" />
          <h3 className="text-sm font-semibold text-zinc-100">Validación manual (Parrot)</h3>
        </div>
        <span className="text-[11px] font-mono px-2 py-0.5 rounded-full border border-zinc-800 bg-zinc-900 text-zinc-400">
          {pending.length} pendientes
        </span>
      </div>
      <p className="text-[11px] text-zinc-500 leading-relaxed">
        Exportá el dossier, validá a mano en Parrot, subí el resultado. Nada se confirma sin tu
        aprobación.
      </p>
      <a
        href={`${process.env.NEXT_PUBLIC_V2_API_URL ?? "/api/v2"}/assessments/${encodeURIComponent(assessmentId)}/dossier/export?format=md`}
        className="inline-flex items-center gap-1.5 rounded-lg border border-zinc-700 px-3 py-1.5 text-[11px] font-medium text-zinc-200 hover:bg-zinc-900 transition"
      >
        <Download className="h-3.5 w-3.5" />
        Descargar dossier
      </a>

      <div className="space-y-2 max-h-[320px] overflow-y-auto pr-1">
        {observations.length === 0 && (
          <p className="text-[11px] text-zinc-500 text-center py-4">
            Sin observaciones importadas. Import de archivo es por API
            (<code className="font-mono text-zinc-400">POST /parrot-import</code>) — subida por
            drag&amp;drop todavía no está construida.
          </p>
        )}
        {observations.map((o) => (
          <div key={o.observationId} className="rounded-lg border border-zinc-800/80 bg-zinc-900/40 p-3">
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono text-[11px] text-zinc-300 truncate">{o.hypothesisId}</span>
              <span className="font-mono text-[10px] px-1.5 py-0.5 rounded border border-zinc-800 text-zinc-500">
                {o.outcome}
              </span>
            </div>
            <p className="mt-1 text-xs text-zinc-300">{o.operatorNote}</p>
            {o.review ? (
              <p
                className={`mt-1.5 font-mono text-[10px] ${
                  o.review.decision === "approve_evidence" ? "text-emerald-400" : "text-zinc-500"
                }`}
              >
                review={o.review.decision}
                {o.review.findingId ? ` → ${o.review.findingId}` : ""}
              </p>
            ) : (
              <div className="mt-2 flex gap-2">
                <button
                  type="button"
                  onClick={() => review(o.observationId, "approve_evidence")}
                  disabled={busyId === o.observationId}
                  className="inline-flex items-center gap-1 rounded-md border border-emerald-500/40 bg-emerald-500/10 px-2 py-1 text-[10px] font-medium text-emerald-300 hover:bg-emerald-500/20 disabled:opacity-40 transition"
                >
                  <Check className="h-3 w-3" />
                  Aprobar
                </button>
                <button
                  type="button"
                  onClick={() => review(o.observationId, "reject")}
                  disabled={busyId === o.observationId}
                  className="inline-flex items-center gap-1 rounded-md border border-zinc-700 px-2 py-1 text-[10px] text-zinc-400 hover:text-zinc-200 disabled:opacity-40 transition"
                >
                  <X className="h-3 w-3" />
                  Rechazar
                </button>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
