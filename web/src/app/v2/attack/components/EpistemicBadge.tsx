"use client";

import type { EpistemicStatus } from "@/lib/v2AttackApi";
import { formatEpistemicBadge } from "@/lib/v2AttackApi";

interface EpistemicBadgeProps {
  readonly status: EpistemicStatus;
  readonly className?: string;
}

export function epistemicBorderClass(status: EpistemicStatus): string {
  switch (status) {
    case "VERIFIED":
      return "border-solid border-emerald-500/60";
    case "INFERRED":
      return "border-dashed border-amber-500/50";
    case "REFUTED":
      return "border-solid border-rose-500/70 bg-rose-950/30";
    case "OBSERVED":
      return "border-solid border-sky-500/50";
    default: {
      const _exhaustive: never = status;
      return _exhaustive;
    }
  }
}

export function epistemicTextClass(status: EpistemicStatus): string {
  switch (status) {
    case "VERIFIED":
      return "text-emerald-400 border-emerald-500/40 bg-emerald-500/10";
    case "INFERRED":
      return "text-amber-300 border-amber-500/40 bg-amber-500/10";
    case "REFUTED":
      return "text-rose-300 border-rose-500/50 bg-rose-500/15";
    case "OBSERVED":
      return "text-sky-300 border-sky-500/40 bg-sky-500/10";
    default: {
      const _exhaustive: never = status;
      return _exhaustive;
    }
  }
}

export function EpistemicBadge({ status, className = "" }: EpistemicBadgeProps) {
  return (
    <span
      className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-mono font-semibold tracking-tight ${epistemicTextClass(status)} ${className}`}
      title={`Epistemic status: ${status}`}
    >
      {formatEpistemicBadge(status)}
    </span>
  );
}
