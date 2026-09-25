"use client";

import { CheckCircle2, CircleDashed, Lock, AlertTriangle } from "lucide-react";
import type { AttackPlan } from "@/lib/v2AttackApi";

export type PlanWorkbenchBucket = "proposed" | "authorized" | "completed";

interface AttackPlansListProps {
  readonly plans: readonly AttackPlan[];
  readonly completedPlanIds: ReadonlySet<string>;
  readonly busyPlanId: string | null;
  readonly onAuthorizeClick: (plan: AttackPlan) => void;
  readonly onExecuteClick: (plan: AttackPlan) => void;
}

function bucketForPlan(
  plan: AttackPlan,
  completedPlanIds: ReadonlySet<string>
): PlanWorkbenchBucket {
  if (completedPlanIds.has(plan.planId)) return "completed";
  if (plan.status === "authorized") return "authorized";
  return "proposed";
}

function BlastBadge({ label }: { readonly label: string }) {
  return (
    <span className="rounded border border-zinc-700 bg-zinc-900 px-1.5 py-0.5 text-[10px] font-mono text-zinc-300">
      {label}
    </span>
  );
}

function spanishLockReason(kind: string, description: string, detail?: string): string {
  switch (kind) {
    case "identity_present":
      return "Bloqueado: hace falta una identidad autenticada (BYOT). Pegá cookie/token en Opciones avanzadas al iniciar, o usá un plan RLS anon que no requiere identidad.";
    case "identity_count_at_least_2":
      return "Bloqueado: hace falta BYOT A+B (dos identidades) para un diferencial.";
    case "identity_with_jwt":
      return "Bloqueado: hace falta una identidad con JWT (Bearer eyJ…).";
    case "credentialed_cors":
      return "Bloqueado: falta señal CORS con credentials OBSERVED.";
    case "parameter_present":
      return "Bloqueado: falta un parámetro OBSERVED para el probe.";
    case "finding_present":
      return "Bloqueado: falta un finding validado de ese tipo.";
    case "host_in_scope":
      return "Bloqueado: el host destino no está en el alcance autorizado.";
    case "pending_draft":
      return "Bloqueado: el draft HITL aún no fue promovido/revisado.";
    case "observed_surface_signal":
      return description;
    default:
      return detail
        ? `${description} — ${detail}`
        : description || `Prerequisito no satisfecho: ${kind}`;
  }
}

function PlanRow({
  plan,
  bucket,
  busy,
  onAuthorize,
  onExecute,
}: {
  readonly plan: AttackPlan;
  readonly bucket: PlanWorkbenchBucket;
  readonly busy: boolean;
  readonly onAuthorize: () => void;
  readonly onExecute: () => void;
}) {
  const prereqOk = plan.prerequisites.every((p) => p.satisfied);
  const prereqFail = plan.prerequisites.filter((p) => !p.satisfied);
  const canAuthorize =
    (bucket === "proposed" || plan.status === "ready_for_authorization") &&
    plan.status !== "rejected" &&
    plan.status !== "superseded" &&
    plan.status !== "prerequisite_missing" &&
    prereqOk;

  return (
    <li className="rounded-lg border border-zinc-800 bg-zinc-950/80 p-3 space-y-2 hover:border-zinc-700 transition">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0 space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-semibold text-zinc-100 truncate">{plan.title}</span>
            <BlastBadge label={plan.blastRadius} />
            <span className="rounded border border-zinc-800 px-1.5 py-0.5 text-[10px] font-mono text-zinc-500">
              {plan.capability}
            </span>
          </div>
          <p className="text-[11px] text-zinc-500 line-clamp-2">{plan.reasoning}</p>
          {plan.planOrigin && plan.planOrigin !== "validated_finding" && (
            <p className="text-[10px] font-mono text-amber-400/90">
              origin: {plan.planOrigin}
              {plan.planOrigin === "pending_draft"
                ? " — señal draft HITL (no finding validado)"
                : " — hipótesis de superficie OBSERVED (no finding validado)"}
            </p>
          )}
          {plan.targetUrl && (
            <p className="text-[10px] font-mono text-zinc-600 truncate">target: {plan.targetUrl}</p>
          )}
        </div>
        <span
          className={`shrink-0 rounded px-1.5 py-0.5 text-[10px] font-mono ${
            bucket === "completed"
              ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
              : bucket === "authorized"
                ? "bg-sky-500/10 text-sky-300 border border-sky-500/30"
                : "bg-zinc-900 text-zinc-400 border border-zinc-700"
          }`}
        >
          {bucket === "completed" ? "completed" : plan.status}
        </span>
      </div>

      <div className="flex flex-wrap items-center gap-2 text-[10px] font-mono">
        {prereqOk ? (
          <span className="inline-flex items-center gap-1 text-emerald-400">
            <CheckCircle2 className="h-3 w-3" /> prerequisitos ok
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 text-amber-400">
            <AlertTriangle className="h-3 w-3" /> {prereqFail.length} faltante
            {prereqFail.length === 1 ? "" : "s"}
          </span>
        )}
        <span className="text-zinc-600">·</span>
        <span className="text-zinc-500">{plan.steps.length} steps</span>
        {!prereqOk && (
          <>
            <span className="text-zinc-600">·</span>
            <span className="inline-flex items-center gap-1 text-zinc-500">
              <Lock className="h-3 w-3" /> bloqueado
            </span>
          </>
        )}
      </div>

      {!prereqOk && prereqFail.length > 0 && (
        <ul className="space-y-1 border-t border-zinc-900 pt-2">
          {prereqFail.map((p) => (
            <li key={p.kind} className="flex items-start gap-1.5 text-[11px] text-amber-200/90">
              <CircleDashed className="h-3.5 w-3.5 mt-0.5 shrink-0" />
              <span>{spanishLockReason(p.kind, p.description, p.detail)}</span>
            </li>
          ))}
        </ul>
      )}

      <div className="mt-1 flex flex-wrap gap-2">
        {(bucket === "proposed" || plan.status === "ready_for_authorization") &&
          plan.status !== "rejected" &&
          plan.status !== "superseded" && (
            <button
              type="button"
              disabled={busy || !canAuthorize}
              onClick={onAuthorize}
              className="rounded border border-emerald-500/40 bg-emerald-500/10 px-2.5 py-1 text-[10px] font-mono font-semibold text-emerald-400 hover:bg-emerald-500/20 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              AUTHORIZE…
            </button>
          )}
        {(bucket === "authorized" || plan.status === "authorized") && bucket !== "completed" && (
          <button
            type="button"
            disabled={busy}
            onClick={onExecute}
            className="rounded border border-sky-500/40 bg-sky-500/10 px-2.5 py-1 text-[10px] font-mono font-semibold text-sky-300 hover:bg-sky-500/20 disabled:opacity-40"
          >
            EXECUTE
          </button>
        )}
      </div>
    </li>
  );
}

export function AttackPlansList({
  plans,
  completedPlanIds,
  onAuthorizeClick,
  onExecuteClick,
  busyPlanId,
}: AttackPlansListProps) {
  const groups: Record<PlanWorkbenchBucket, AttackPlan[]> = {
    proposed: [],
    authorized: [],
    completed: [],
  };

  for (const plan of plans) {
    groups[bucketForPlan(plan, completedPlanIds)].push(plan);
  }

  const sections: { key: PlanWorkbenchBucket; label: string }[] = [
    { key: "proposed", label: "Proposed" },
    { key: "authorized", label: "Authorized" },
    { key: "completed", label: "Completed" },
  ];

  if (plans.length === 0) {
    return (
      <div className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-4 text-xs text-zinc-500">
        No attack plans for this assessment.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {sections.map(({ key, label }) => (
        <section key={key} aria-labelledby={`plans-${key}`}>
          <h3
            id={`plans-${key}`}
            className="mb-2 flex items-center gap-2 text-[11px] font-mono uppercase tracking-wider text-zinc-500"
          >
            {label} {groups[key].length}
          </h3>
          {groups[key].length === 0 ? (
            <p className="text-[11px] text-zinc-600 px-1">None</p>
          ) : (
            <ul className="space-y-2">
              {groups[key].map((plan) => (
                <PlanRow
                  key={plan.planId}
                  plan={plan}
                  bucket={key}
                  busy={busyPlanId === plan.planId}
                  onAuthorize={() => onAuthorizeClick(plan)}
                  onExecute={() => onExecuteClick(plan)}
                />
              ))}
            </ul>
          )}
        </section>
      ))}
    </div>
  );
}
