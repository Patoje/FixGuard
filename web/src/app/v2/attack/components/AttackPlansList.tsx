"use client";

import { CheckCircle2, CircleDashed, Lock, AlertTriangle } from "lucide-react";
import type { AttackPlan } from "@/lib/v2AttackApi";

export type PlanWorkbenchBucket = "proposed" | "authorized" | "completed";

interface AttackPlansListProps {
  readonly plans: readonly AttackPlan[];
  readonly completedPlanIds: ReadonlySet<string>;
  readonly selectedPlanId: string | null;
  readonly onSelectPlan: (plan: AttackPlan) => void;
  readonly onAuthorizeClick: (plan: AttackPlan) => void;
  readonly onExecuteClick: (plan: AttackPlan) => void;
  readonly busyPlanId: string | null;
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

function PlanRow({
  plan,
  bucket,
  selected,
  busy,
  onSelect,
  onAuthorize,
  onExecute,
}: {
  readonly plan: AttackPlan;
  readonly bucket: PlanWorkbenchBucket;
  readonly selected: boolean;
  readonly busy: boolean;
  readonly onSelect: () => void;
  readonly onAuthorize: () => void;
  readonly onExecute: () => void;
}) {
  const prereqOk = plan.prerequisites.every((p) => p.satisfied);
  const prereqFail = plan.prerequisites.filter((p) => !p.satisfied);

  return (
    <li
      className={`rounded-lg border p-3 transition ${
        selected
          ? "border-emerald-500/50 bg-emerald-500/5"
          : "border-zinc-800 bg-zinc-950/80 hover:border-zinc-700"
      }`}
    >
      <button type="button" onClick={onSelect} className="w-full text-left space-y-2">
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
              <CheckCircle2 className="h-3 w-3" /> prerequisites ok
            </span>
          ) : (
            <span className="inline-flex items-center gap-1 text-amber-400">
              <AlertTriangle className="h-3 w-3" /> {prereqFail.length} missing
            </span>
          )}
          <span className="text-zinc-600">·</span>
          <span className="text-zinc-500">{plan.steps.length} steps</span>
          <span className="text-zinc-600">·</span>
          <span className="inline-flex items-center gap-1 text-zinc-500">
            <Lock className="h-3 w-3" /> executable: false
          </span>
        </div>

        {!prereqOk && prereqFail.length > 0 && (
          <ul className="space-y-0.5 border-t border-zinc-900 pt-2">
            {prereqFail.map((p) => (
              <li key={p.kind} className="flex items-start gap-1.5 text-[10px] text-amber-300/90">
                <CircleDashed className="h-3 w-3 mt-0.5 shrink-0" />
                <span>
                  {p.kind}: {p.description}
                  {p.detail ? ` — ${p.detail}` : ""}
                </span>
              </li>
            ))}
          </ul>
        )}
      </button>

      <div className="mt-2 flex flex-wrap gap-2">
        {(bucket === "proposed" || plan.status === "ready_for_authorization") &&
          plan.status !== "rejected" &&
          plan.status !== "superseded" && (
            <button
              type="button"
              disabled={busy || plan.status === "prerequisite_missing"}
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
  selectedPlanId,
  onSelectPlan,
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
            {label}
            <span className="rounded bg-zinc-900 border border-zinc-800 px-1.5 text-zinc-400">
              {groups[key].length}
            </span>
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
                  selected={selectedPlanId === plan.planId}
                  busy={busyPlanId === plan.planId}
                  onSelect={() => onSelectPlan(plan)}
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
