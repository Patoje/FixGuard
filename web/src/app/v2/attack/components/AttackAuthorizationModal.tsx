"use client";

import { useState } from "react";
import { X, ShieldAlert } from "lucide-react";
import type {
  AttackPlan,
  AuthorizableBlastRadiusClass,
  BlastRadiusClass,
} from "@/lib/v2AttackApi";
import {
  AUTHORIZABLE_BLAST_RADIUS_CLASSES,
  suggestBlastRadiusForCapability,
} from "@/lib/v2AttackApi";
import { BLAST_RADIUS_LABELS } from "@/lib/v2/blastRadiusLabels";

interface AttackAuthorizationModalProps {
  readonly plan: AttackPlan;
  readonly operatorId: string;
  readonly isSubmitting: boolean;
  readonly onAuthorize: (blastRadiusClass: BlastRadiusClass) => void;
  readonly onDecline: () => void;
}

function hostFromPlan(plan: AttackPlan): string {
  if (!plan.targetUrl) return "(sin URL de destino)";
  try {
    return new URL(plan.targetUrl).hostname;
  } catch {
    return plan.targetUrl;
  }
}

function whatWillHappen(plan: AttackPlan): string {
  const first = plan.steps[0];
  if (first?.description) {
    return first.description.length > 220
      ? `${first.description.slice(0, 217)}…`
      : first.description;
  }
  if (plan.reasoning) {
    return plan.reasoning.length > 220
      ? `${plan.reasoning.slice(0, 217)}…`
      : plan.reasoning;
  }
  return `Se autorizará el plan «${plan.title}» para ejecución humana posterior.`;
}

function isWriteCapability(plan: AttackPlan): boolean {
  return (
    plan.capability.includes("write") ||
    plan.capability === "supabase_authz_write_matrix" ||
    plan.capability === "supabase_rls_write_probe"
  );
}

export function AttackAuthorizationModal({
  plan,
  isSubmitting,
  onAuthorize,
  onDecline,
}: AttackAuthorizationModalProps) {
  const suggested = suggestBlastRadiusForCapability(plan.capability);
  const initialClass: AuthorizableBlastRadiusClass =
    suggested && BLAST_RADIUS_LABELS[suggested] ? suggested : "read_public";
  const [blastRadiusClass, setBlastRadiusClass] =
    useState<AuthorizableBlastRadiusClass>(initialClass);
  const activeLabelMeta =
    BLAST_RADIUS_LABELS[blastRadiusClass] ?? BLAST_RADIUS_LABELS["read_public"];
  const writeRisk =
    isWriteCapability(plan) || Boolean(activeLabelMeta?.writeRisk);
  const host = hostFromPlan(plan);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 p-4 backdrop-blur-md"
      role="dialog"
      aria-modal="true"
      aria-labelledby="auth-modal-title"
    >
      <div className="w-full max-w-2xl rounded-2xl border border-zinc-800 bg-zinc-950 shadow-2xl flex flex-col max-h-[90vh] overflow-hidden">
        {/* Header */}
        <header className="flex items-start justify-between gap-3 border-b border-zinc-900 px-6 py-4 bg-zinc-900/40">
          <div className="flex items-start gap-3">
            <div className="mt-0.5 flex h-9 w-9 items-center justify-center rounded-xl border border-amber-500/30 bg-amber-500/10 text-amber-400 shrink-0">
              <ShieldAlert className="h-5 w-5" />
            </div>
            <div>
              <h2 id="auth-modal-title" className="text-base font-semibold text-white">
                Autorizar Ejecución de Ataque
              </h2>
              <p className="text-xs text-zinc-400 mt-0.5">
                Plan: <span className="text-zinc-200 font-mono">{plan.title}</span>
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onDecline}
            disabled={isSubmitting}
            className="rounded-lg p-1.5 text-zinc-400 hover:text-white hover:bg-zinc-800 transition"
            aria-label="Cerrar"
          >
            <X className="h-5 w-5" />
          </button>
        </header>

        {/* Content */}
        <div className="flex-1 overflow-y-auto px-6 py-4 space-y-5 text-xs">
          {/* Target & Risk Badges */}
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 p-3 rounded-xl border border-zinc-900 bg-zinc-900/30">
            <div>
              <span className="block text-[10px] text-zinc-500 uppercase tracking-wider font-mono">Destino</span>
              <span className="font-mono text-zinc-200 text-xs truncate block mt-0.5">{host}</span>
            </div>
            <div>
              <span className="block text-[10px] text-zinc-500 uppercase tracking-wider font-mono">Capacidad</span>
              <span className="font-mono text-zinc-200 text-xs truncate block mt-0.5">{plan.capability}</span>
            </div>
            <div>
              <span className="block text-[10px] text-zinc-500 uppercase tracking-wider font-mono">Nivel de Riesgo</span>
              <span
                className={`inline-flex items-center gap-1 mt-0.5 px-2 py-0.5 rounded text-[11px] font-medium border ${
                  writeRisk
                    ? "border-rose-500/40 bg-rose-500/10 text-rose-300"
                    : "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                }`}
              >
                {writeRisk ? "Escritura / Modificación" : "Solo Lectura"}
              </span>
            </div>
          </div>

          <div>
            <h3 className="mb-1 text-[11px] font-medium text-zinc-400 uppercase tracking-wider font-mono">
              Qué va a pasar en este plan
            </h3>
            <p className="text-sm text-zinc-200 leading-relaxed bg-zinc-900/20 p-3 rounded-lg border border-zinc-900">
              {whatWillHappen(plan)}
            </p>
          </div>

          {/* Options Selection */}
          <fieldset className="space-y-2">
            <div className="flex items-center justify-between">
              <legend className="text-xs font-semibold text-zinc-200">
                Seleccioná el Alcance Autorizado (Blast Radius)
              </legend>
              <span className="text-[11px] text-zinc-500 font-mono">
                {AUTHORIZABLE_BLAST_RADIUS_CLASSES.length} opciones disponibles
              </span>
            </div>
            <p className="text-[11px] text-zinc-400">
              Podés elegir libremente qué nivel de prueba autorizar para esta ejecución. La opción sugerida está marcada.
            </p>

            <div className="space-y-2 mt-3 max-h-[320px] overflow-y-auto pr-1">
              {AUTHORIZABLE_BLAST_RADIUS_CLASSES.map((c) => {
                const meta = BLAST_RADIUS_LABELS[c] ?? {
                  label: c,
                  hint: "",
                  technicalDetail: "",
                  writeRisk: false,
                  category: "read",
                };
                const id = `blast-${c}`;
                const isSelected = blastRadiusClass === c;
                const isSuggested = c === suggested;

                return (
                  <label
                    key={c}
                    htmlFor={id}
                    className={`flex cursor-pointer items-start gap-3 rounded-xl border p-3 transition ${
                      isSelected
                        ? "border-emerald-500 bg-emerald-950/20 shadow-md shadow-emerald-950/20"
                        : "border-zinc-800/80 bg-zinc-900/30 hover:border-zinc-700 hover:bg-zinc-900/50"
                    }`}
                  >
                    <input
                      id={id}
                      type="radio"
                      name="blast-radius"
                      value={c}
                      checked={isSelected}
                      onChange={() => setBlastRadiusClass(c)}
                      disabled={isSubmitting}
                      className="mt-1 shrink-0 accent-emerald-500"
                    />
                    <div className="min-w-0 flex-1 space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={`text-xs font-semibold ${isSelected ? "text-emerald-300" : "text-zinc-200"}`}>
                          {meta.label}
                        </span>
                        {isSuggested && (
                          <span className="rounded-full border border-emerald-500/40 bg-emerald-500/10 px-2 py-0.2 text-[10px] font-medium text-emerald-400">
                            Sugerido por motor
                          </span>
                        )}
                        {meta.writeRisk ? (
                          <span className="rounded border border-rose-500/30 bg-rose-500/10 px-1.5 py-0.2 text-[9px] font-mono text-rose-300">
                            modifica datos
                          </span>
                        ) : (
                          <span className="rounded border border-zinc-800 bg-zinc-900 px-1.5 py-0.2 text-[9px] font-mono text-zinc-400">
                            solo lectura
                          </span>
                        )}
                      </div>
                      <p className="text-[11px] text-zinc-300 leading-snug">
                        {meta.hint}
                      </p>
                      {meta.technicalDetail && (
                        <p className="text-[10px] text-zinc-400 leading-relaxed pt-0.5">
                          {meta.technicalDetail}
                        </p>
                      )}
                    </div>
                  </label>
                );
              })}
            </div>
          </fieldset>
        </div>

        {/* Footer */}
        <footer className="flex items-center justify-between border-t border-zinc-900 px-6 py-4 bg-zinc-950">
          <div className="text-[11px] text-zinc-400 truncate max-w-[320px]">
            Seleccionado: <span className="font-semibold text-zinc-200">{activeLabelMeta.label}</span>
          </div>
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={onDecline}
              disabled={isSubmitting}
              className="rounded-lg border border-zinc-800 bg-zinc-900 px-4 py-2 text-xs font-semibold text-zinc-300 hover:bg-zinc-800 hover:text-white transition disabled:opacity-40"
            >
              Cancelar
            </button>
            <button
              type="button"
              onClick={() => onAuthorize(blastRadiusClass)}
              disabled={isSubmitting}
              className="rounded-lg border border-emerald-500/60 bg-emerald-600 px-4 py-2 text-xs font-semibold text-white hover:bg-emerald-500 shadow-md shadow-emerald-600/20 transition disabled:opacity-40"
            >
              {isSubmitting ? "Autorizando…" : "Autorizar y Ejecutar"}
            </button>
          </div>
        </footer>
      </div>
    </div>
  );
}
