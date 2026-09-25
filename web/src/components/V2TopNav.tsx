"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";

function readStoredAssessmentId(): string | null {
  try {
    const raw = sessionStorage.getItem("fg_v2_active_assessment");
    if (!raw) return null;
    const parsed = JSON.parse(raw) as { assessmentId?: string };
    return typeof parsed.assessmentId === "string" ? parsed.assessmentId : null;
  } catch {
    return null;
  }
}

export function V2TopNav() {
  const pathname = usePathname();
  const [assessmentId, setAssessmentId] = useState<string | null>(null);

  useEffect(() => {
    setAssessmentId(readStoredAssessmentId());
  }, [pathname]);

  const triageHref = assessmentId
    ? `/v2?assessmentId=${encodeURIComponent(assessmentId)}`
    : "/v2";
  const attackHref = assessmentId
    ? `/v2/attack?assessmentId=${encodeURIComponent(assessmentId)}`
    : "/v2/attack";

  const linkClass = (active: boolean) =>
    active
      ? "text-emerald-400 hover:text-emerald-300 font-semibold transition-colors flex items-center gap-1.5"
      : "text-zinc-400 hover:text-white transition-colors";

  const isAssessments =
    pathname === "/v2/assessments" || pathname.startsWith("/v2/assessments/");
  const isTriage = pathname === "/v2";
  const isAttack = pathname.startsWith("/v2/attack");
  const isReview = pathname.startsWith("/v2/review");

  return (
    <nav className="w-full border-b border-zinc-800 bg-black/50 backdrop-blur-xl sticky top-0 z-50">
      <div className="max-w-6xl mx-auto px-6 h-14 flex items-center justify-between">
        <Link href="/v2" className="font-bold tracking-tight text-xl">
          Fix<span className="text-zinc-500">Guard</span>
        </Link>
        <div className="flex items-center gap-6 text-sm font-medium">
          <Link href="/v2/assessments" className={linkClass(isAssessments)}>
            {isAssessments && (
              <span className="h-2 w-2 rounded-full bg-emerald-400" />
            )}
            Assessments
          </Link>
          <Link href={triageHref} className={linkClass(isTriage)}>
            {isTriage && (
              <span className="h-2 w-2 rounded-full bg-emerald-400" />
            )}
            Triage
          </Link>
          <Link href={attackHref} className={linkClass(isAttack)}>
            {isAttack && (
              <span className="h-2 w-2 rounded-full bg-emerald-400" />
            )}
            Attack
          </Link>
          <Link
            href={
              assessmentId
                ? `/v2/review?assessmentId=${encodeURIComponent(assessmentId)}`
                : "/v2/review"
            }
            className={linkClass(isReview)}
          >
            {isReview && (
              <span className="h-2 w-2 rounded-full bg-emerald-400" />
            )}
            Review
          </Link>
        </div>
      </div>
    </nav>
  );
}
