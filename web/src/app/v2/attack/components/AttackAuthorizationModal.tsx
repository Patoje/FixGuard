"use client";

import { useState } from "react";
import { X, ShieldAlert, Ban } from "lucide-react";
import type {
  AttackPlan,
  AuthorizableBlastRadiusClass,
  BlastRadiusClass,
} from "@/lib/v2AttackApi";
import {
  AUTHORIZABLE_BLAST_RADIUS_CLASSES,
  suggestBlastRadiusForCapability,
} from "@/lib/v2AttackApi";

interface AttackAuthorizationModalProps {
  readonly plan: AttackPlan;
  readonly operatorId: string;
  readonly isSubmitting: boolean;
  readonly onAuthorize: (blastRadiusClass: BlastRadiusClass) => void;
  readonly onDecline: () => void;
}

const NON_CLAIMS: readonly string[] = [
  "Plans are advisory until a separate human authorization seals a runtime brand.",
  "Authorization does not execute network probes.",
  "No severity (Critical/High) is assigned by this modal.",
  "Raw secrets are never accepted or displayed.",
  "Persistence and destructive blast-radius classes are permanently prohibited.",
];

export function AttackAuthorizationModal({
  plan,
  operatorId,
  isSubmitting,
  onAuthorize,
  onDecline,
}: AttackAuthorizationModalProps) {
  const suggested = suggestBlastRadiusForCapability(plan.capability);
  const [blastRadiusClass, setBlastRadiusClass] =
    useState<AuthorizableBlastRadiusClass>(suggested);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-labelledby="auth-modal-title"
    >
      <div className="w-full max-w-lg rounded-xl border border-zinc-800 bg-zinc-950 shadow-2xl">
        <header className="flex items-start justify-between gap-3 border-b border-zinc-900 px-4 py-3">
          <div className="flex items-start gap-2">
            <div className="mt-0.5 flex h-8 w-8 items-center justify-center rounded-lg border border-amber-500/30 bg-amber-500/10 text-amber-400">
              <ShieldAlert className="h-4 w-4" />
            </div>
            <div>
              <h2 id="auth-modal-title" className="text-sm font-semibold text-white">
                Authorize Attack Plan
              </h2>
              <p className="text-[11px] text-zinc-500 font-mono">{plan.planId}</p>
            </div>
          </div>
          <button
            type="button"
            onClick={onDecline}
            disabled={isSubmitting}
            className="rounded p-1 text-zinc-500 hover:text-zinc-200"
            aria-label="Close"
          >
            <X className="h-4 w-4" />
          </button>
        </header>

        <div className="max-h-[70vh] overflow-y-auto space-y-4 px-4 py-4 text-xs">
          <div className="grid grid-cols-2 gap-2 font-mono text-[11px]">
            <div className="rounded border border-zinc-800 bg-zinc-900/50 p-2">
              <div className="text-zinc-500">Target</div>
              <div className="text-zinc-200 truncate">{plan.targetUrl ?? "(none)"}</div>
            </div>
            <div className="rounded border border-zinc-800 bg-zinc-900/50 p-2">
              <div className="text-zinc-500">Plan scope</div>
              <div className="text-zinc-200">{plan.blastRadius}</div>
            </div>
            <div className="rounded border border-zinc-800 bg-zinc-900/50 p-2">
              <div className="text-zinc-500">Capability</div>
              <div className="text-zinc-200">{plan.capability}</div>
            </div>
            <div className="rounded border border-zinc-800 bg-zinc-900/50 p-2">
              <div className="text-zinc-500">Operator</div>
              <div className="text-zinc-200 truncate">{operatorId}</div>
            </div>
          </div>

          <div>
            <h3 className="mb-1.5 text-[11px] font-mono uppercase tracking-wider text-zinc-500">
              Steps ({plan.steps.length})
            </h3>
            <ol className="space-y-1.5">
              {plan.steps.map((step) => (
                <li
                  key={step.stepId}
                  className="rounded border border-zinc-800 bg-zinc-900/40 px-2.5 py-1.5"
                >
                  <div className="font-medium text-zinc-200">
                    {step.ordinal}. {step.title}
                  </div>
                  <p className="text-[11px] text-zinc-500 mt-0.5">{step.description}</p>
                </li>
              ))}
            </ol>
          </div>

          <label className="block space-y-1.5">
            <span className="text-[11px] font-mono uppercase tracking-wider text-zinc-500">
              Authorization blast-radius class
            </span>
            <select
              value={blastRadiusClass}
              onChange={(e) =>
                setBlastRadiusClass(e.target.value as AuthorizableBlastRadiusClass)
              }
              disabled={isSubmitting}
              className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-xs font-mono text-zinc-100 focus:outline-none focus:border-emerald-500/50"
            >
              {AUTHORIZABLE_BLAST_RADIUS_CLASSES.map((c) => (
                <option key={c} value={c}>
                  {c}
                  {c === suggested ? " (suggested)" : ""}
                </option>
              ))}
            </select>
            <p className="text-[10px] text-zinc-600">
              Seals a server-side WeakSet brand for this class. Brand is not transferable via JSON.
            </p>
          </label>

          <div className="rounded-lg border border-zinc-800 bg-zinc-900/30 p-3">
            <h3 className="mb-2 flex items-center gap-1.5 text-[11px] font-mono uppercase tracking-wider text-zinc-500">
              <Ban className="h-3 w-3" /> Explicit non-claims
            </h3>
            <ul className="space-y-1 text-[11px] text-zinc-400">
              {NON_CLAIMS.map((claim) => (
                <li key={claim} className="flex gap-1.5">
                  <span className="text-zinc-600">·</span>
                  <span>{claim}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>

        <footer className="flex items-center justify-end gap-2 border-t border-zinc-900 px-4 py-3">
          <button
            type="button"
            onClick={onDecline}
            disabled={isSubmitting}
            className="rounded-lg border border-zinc-700 bg-zinc-900 px-4 py-2 text-xs font-mono font-semibold text-zinc-300 hover:bg-zinc-800 disabled:opacity-40"
          >
            DECLINE
          </button>
          <button
            type="button"
            onClick={() => onAuthorize(blastRadiusClass)}
            disabled={isSubmitting}
            className="rounded-lg border border-emerald-500/50 bg-emerald-500/15 px-4 py-2 text-xs font-mono font-semibold text-emerald-400 hover:bg-emerald-500/25 disabled:opacity-40"
          >
            {isSubmitting ? "AUTHORIZING…" : "AUTHORIZE"}
          </button>
        </footer>
      </div>
    </div>
  );
}
