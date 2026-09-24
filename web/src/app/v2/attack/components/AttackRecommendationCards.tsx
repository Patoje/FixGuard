"use client";

import { Crosshair, Lock, Play, ShieldAlert } from "lucide-react";
import type { OperatorAttackRecommendation } from "@/lib/v2AttackApi";

interface AttackRecommendationCardsProps {
  readonly recommendations: readonly OperatorAttackRecommendation[];
  readonly rulesApplied: readonly string[];
  readonly selectedRank: "A" | "B" | null;
  readonly busy: boolean;
  readonly onSelect: (rec: OperatorAttackRecommendation) => void;
  readonly onAuthorizeRun: (rec: OperatorAttackRecommendation) => void;
}

function FlagList({ flags }: { readonly flags: OperatorAttackRecommendation["suggestedFlags"] }) {
  const entries = Object.entries(flags);
  if (entries.length === 0) {
    return <span className="text-zinc-600">—</span>;
  }
  return (
    <ul className="space-y-0.5 font-mono text-[10px] text-zinc-400">
      {entries.map(([k, v]) => (
        <li key={k}>
          <span className="text-zinc-500">{k}=</span>
          {String(v)}
        </li>
      ))}
    </ul>
  );
}

function RecCard({
  rec,
  selected,
  busy,
  onSelect,
  onAuthorizeRun,
}: {
  readonly rec: OperatorAttackRecommendation;
  readonly selected: boolean;
  readonly busy: boolean;
  readonly onSelect: () => void;
  readonly onAuthorizeRun: () => void;
}) {
  return (
    <article
      className={`rounded-xl border p-4 space-y-3 transition ${
        selected
          ? "border-orange-500/50 bg-orange-500/5"
          : "border-zinc-800 bg-zinc-950/80 hover:border-zinc-700"
      }`}
    >
      <button type="button" onClick={onSelect} className="w-full text-left space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <span
            className={`inline-flex h-7 w-7 items-center justify-center rounded-lg border font-mono text-sm font-bold ${
              rec.rank === "A"
                ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                : "border-sky-500/40 bg-sky-500/10 text-sky-300"
            }`}
          >
            {rec.rank}
          </span>
          <span className="text-sm font-semibold text-zinc-100">{rec.humanLabel}</span>
          <span className="rounded border border-zinc-800 px-1.5 py-0.5 text-[10px] font-mono text-zinc-500">
            {rec.capabilityKind}
          </span>
          <span
            className={`rounded border px-1.5 py-0.5 text-[10px] font-mono ${
              rec.reasonKind === "OBSERVED"
                ? "border-emerald-500/30 text-emerald-400"
                : "border-amber-500/30 text-amber-300"
            }`}
          >
            {rec.reasonKind}
          </span>
          <span className="text-[10px] font-mono text-zinc-600">score {rec.score}</span>
        </div>
        <p className="text-[11px] text-zinc-400">{rec.reason}</p>
        <p className="text-[10px] font-mono text-zinc-500">why: {rec.whyPreferred}</p>
        <div className="rounded-lg border border-zinc-900 bg-black/60 px-3 py-2">
          <p className="text-[10px] font-mono uppercase text-zinc-600 mb-1">flags</p>
          <FlagList flags={rec.suggestedFlags} />
        </div>
        <p className="text-[10px] font-mono text-zinc-500 truncate">$ {rec.commandSummary}</p>
        {!rec.executable && rec.disabilityReason && (
          <p className="inline-flex items-start gap-1.5 text-[10px] text-amber-300/90">
            <ShieldAlert className="h-3 w-3 shrink-0 mt-0.5" />
            {rec.disabilityReason}
          </p>
        )}
        {rec.planId && (
          <p className="text-[10px] font-mono text-zinc-600">plan: {rec.planId}</p>
        )}
      </button>

      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          disabled={busy || !rec.executable || !rec.planId}
          onClick={onAuthorizeRun}
          className="inline-flex items-center gap-1.5 rounded-lg border border-orange-500/40 bg-orange-500/10 px-3 py-1.5 text-[11px] font-mono font-semibold text-orange-300 hover:bg-orange-500/20 disabled:opacity-40"
          title={
            !rec.planId
              ? "No linked attack plan — generate/load plans first"
              : !rec.executable
                ? "Not executable"
                : "Authorize then run linked plan"
          }
        >
          {rec.executable ? (
            <>
              <Play className="h-3 w-3" /> Authorize + Run
            </>
          ) : (
            <>
              <Lock className="h-3 w-3" /> Disabled
            </>
          )}
        </button>
      </div>
    </article>
  );
}

export function AttackRecommendationCards({
  recommendations,
  rulesApplied,
  selectedRank,
  busy,
  onSelect,
  onAuthorizeRun,
}: AttackRecommendationCardsProps) {
  if (recommendations.length === 0) {
    return (
      <div className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-4 text-xs text-zinc-500">
        No A/B recommendations yet. Load an assessment with findings or select a plan.
      </div>
    );
  }

  const a = recommendations.find((r) => r.rank === "A");
  const b = recommendations.find((r) => r.rank === "B");

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono text-zinc-500">
        <Crosshair className="h-3.5 w-3.5 text-orange-400" />
        Deterministic A/B · humans authorize · no auto-execute
        {rulesApplied.length > 0 && (
          <span className="text-zinc-600">· rules: {rulesApplied.join(", ")}</span>
        )}
      </div>
      <div className="grid gap-3 md:grid-cols-2">
        {a && (
          <RecCard
            rec={a}
            selected={selectedRank === "A"}
            busy={busy}
            onSelect={() => onSelect(a)}
            onAuthorizeRun={() => onAuthorizeRun(a)}
          />
        )}
        {b && (
          <RecCard
            rec={b}
            selected={selectedRank === "B"}
            busy={busy}
            onSelect={() => onSelect(b)}
            onAuthorizeRun={() => onAuthorizeRun(b)}
          />
        )}
      </div>
    </div>
  );
}
