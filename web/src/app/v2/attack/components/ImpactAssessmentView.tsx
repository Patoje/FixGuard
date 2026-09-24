"use client";

import type { ImpactAssessment } from "@/lib/v2AttackApi";
import { EpistemicBadge, epistemicBorderClass } from "./EpistemicBadge";

interface ImpactAssessmentViewProps {
  readonly assessments: readonly ImpactAssessment[];
}

/**
 * Displays structured impact assessments.
 * ALWAYS pairs epistemicStatus with impactLevel — never rank/sort by level alone.
 */
export function ImpactAssessmentView({ assessments }: ImpactAssessmentViewProps) {
  if (assessments.length === 0) {
    return (
      <div className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-4 text-xs text-zinc-500">
        No impact assessments. Impact is derived only from completed chains with evidence.
      </div>
    );
  }

  // Preserve server order — do NOT sort by impactLevel.
  return (
    <ul className="space-y-2">
      {assessments.map((item) => (
        <li
          key={`${item.chainId}-${item.assessedAt}`}
          className={`rounded-lg border-2 p-3 ${epistemicBorderClass(item.epistemicStatus)}`}
        >
          <div className="flex flex-wrap items-center gap-2 mb-2">
            <EpistemicBadge status={item.epistemicStatus} />
            <span className="rounded border border-zinc-700 bg-zinc-900 px-1.5 py-0.5 text-[10px] font-mono text-zinc-300">
              {item.impactLevel}
            </span>
            <span className="text-[10px] font-mono text-zinc-600">chain: {item.chainId}</span>
          </div>
          <p className="text-xs text-zinc-300 leading-relaxed">{item.impactDescription}</p>
          {item.evidenceBasis.length > 0 && (
            <p className="mt-2 text-[10px] font-mono text-zinc-600">
              evidence: {item.evidenceBasis.join(", ")}
            </p>
          )}
          <p className="mt-1 text-[10px] font-mono text-zinc-700">
            assessedAt: {item.assessedAt}
          </p>
        </li>
      ))}
    </ul>
  );
}
