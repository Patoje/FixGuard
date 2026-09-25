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
  const [blastRadiusClass, setBlastRadiusClass] =
    useState<AuthorizableBlastRadiusClass>(suggested);
  const writeRisk =
    isWriteCapability(plan) || BLAST_RADIUS_LABELS[blastRadiusClass].writeRisk;
  const host = hostFromPlan(plan);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-labelledby="auth-modal-title"
    >
      <div className="w-full max-w-md rounded-xl border border-zinc-800 bg-zinc-950 shadow-2xl">
        <header className="flex items-start justify-between gap-3 border-b border-zinc-900 px-4 py-3">
          <div className="flex items-start gap-2">
            <div className="mt-0.5 flex h-8 w-8 items-center justify-center rounded-lg border border-amber-500/30 bg-amber-500/10 text-amber-400">
              <ShieldAlert className="h-4 w-4" />
            </div>
            <div>
              <h2 id="auth-modal-title" className="text-sm font-semibold text-white">
                Autorizar ataque
              </h2>
              <p className="text-[11px] text-zinc-400 mt-0.5">{plan.title}</p>
            </div>
          </div>
          <button
            type="button"
            onClick={onDecline}
            disabled={isSubmitting}
            className="rounded p-1 text-zinc-500 hover:text-zinc-200"
            aria-label="Cerrar"
          >
            <X className="h-4 w-4" />
          </button>
        </header>

        <div className="space-y-4 px-4 py-4 text-xs">
          <div>
            <h3 className="mb-1 text-[11px] font-medium text-zinc-500">
              Qué va a pasar
            </h3>
            <p className="text-sm text-zinc-200 leading-relaxed">
              {whatWillHappen(plan)}
            </p>
          </div>

          <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px]">
            <div>
              <span className="text-zinc-500">Destino: </span>
              <span className="font-mono text-zinc-200">{host}</span>
            </div>
            <div>
              <span className="text-zinc-500">Riesgo: </span>
              <span
                className={
                  writeRisk ? "text-rose-300 font-medium" : "text-emerald-300"
                }
              >
                {writeRisk ? "Puede escribir / modificar" : "Solo lectura"}
              </span>
            </div>
          </div>

          {plan.steps.length > 1 && (
            <p className="text-[11px] text-zinc-500">
              {plan.steps.length} pasos planificados · sin ejecutar hasta que
              confirmes y lances.
            </p>
          )}

          <fieldset className="space-y-2">
            <legend className="text-[11px] font-medium text-zinc-500 mb-1.5">
              Alcance autorizado
            </legend>
            <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
              {AUTHORIZABLE_BLAST_RADIUS_CLASSES.map((c) => {
                const meta = BLAST_RADIUS_LABELS[c];
                const id = `blast-${c}`;
                return (
                  <label
                    key={c}
                    htmlFor={id}
                    className={`flex cursor-pointer gap-2.5 rounded-lg border px-2.5 py-2 transition ${
                      blastRadiusClass === c
                        ? "border-emerald-500/40 bg-emerald-500/5"
                        : "border-zinc-800 bg-zinc-900/40 hover:border-zinc-700"
                    }`}
                  >
                    <input
                      id={id}
                      type="radio"
                      name="blast-radius"
                      value={c}
                      checked={blastRadiusClass === c}
                      onChange={() => setBlastRadiusClass(c)}
                      disabled={isSubmitting}
                      className="mt-0.5 shrink-0"
                    />
                    <span className="min-w-0">
                      <span className="block text-[12px] text-zinc-100 font-medium">
                        {meta.label}
                        {c === suggested ? (
                          <span className="ml-1.5 text-[10px] font-normal text-emerald-400">
                            sugerido
                          </span>
                        ) : null}
                      </span>
                      <span className="block text-[10px] text-zinc-500 mt-0.5">
                        {meta.hint}
                      </span>
                    </span>
                  </label>
                );
              })}
            </div>
          </fieldset>
        </div>

        <footer className="flex items-center justify-end gap-2 border-t border-zinc-900 px-4 py-3">
          <button
            type="button"
            onClick={onDecline}
            disabled={isSubmitting}
            className="rounded-lg border border-zinc-700 bg-zinc-900 px-4 py-2 text-xs font-semibold text-zinc-300 hover:bg-zinc-800 disabled:opacity-40"
          >
            Rechazar
          </button>
          <button
            type="button"
            onClick={() => onAuthorize(blastRadiusClass)}
            disabled={isSubmitting}
            className="rounded-lg border border-emerald-500/50 bg-emerald-500/15 px-4 py-2 text-xs font-semibold text-emerald-400 hover:bg-emerald-500/25 disabled:opacity-40"
          >
            {isSubmitting ? "Autorizando…" : "Autorizar"}
          </button>
        </footer>
      </div>
    </div>
  );
}
