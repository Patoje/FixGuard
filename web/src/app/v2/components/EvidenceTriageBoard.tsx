"use client";

import React, { useState, useEffect, useCallback } from "react";
import {
  FileText,
  CheckCircle,
  AlertCircle,
  Loader2,
  RefreshCw,
  ArrowRight,
  Check,
  X,
} from "lucide-react";
import {
  getEvidenceDrafts,
  getOrchestratedAssessmentSummary,
  reviewEvidenceDraft,
  V2ApiError,
  type EvidenceDraftDto,
  type FindingDto,
} from "@/lib/v2Api";
import {
  draftPlainTitle,
  draftWhyItMatters,
  presentSeverity,
  severityFromDetectionKind,
} from "@/lib/v2/severityPresentation";
import Link from "next/link";

/** Default reviewer for promote API — not shown in UI. */
const DEFAULT_REVIEWER_ID = "op_lead_analyst_01";

/** Soft/cosmetic kinds sorted below attack-relevant drafts. */
const LOW_INFO_KIND_ORDER = new Set([
  "missing_security_headers",
  "wordpress_surface",
  "graphql_surface",
  "api_versioning_sprawl",
  "manifest_exposure",
  "object_mapping_anomaly",
  "state_transition_anomaly",
  "custom_difference",
  "static_route_extraction",
  "attack_surface_delta",
  "sourcemap_exposure",
]);

function draftSortRank(draft: EvidenceDraftDto): number {
  const kind = draft.differentialContext?.detectionKind;
  if (kind && LOW_INFO_KIND_ORDER.has(kind)) return 1;
  return 0;
}

interface EvidenceTriageBoardProps {
  assessmentId: string;
  scanId: string;
  onDraftReviewed: (
    draftId: string,
    decision: "approve_evidence" | "reject_evidence"
  ) => void;
  reviewedDraftIds: readonly string[];
  onContinueToReport: () => void;
}

function targetFromDraft(draft: EvidenceDraftDto): string {
  const url = draft.differentialContext?.endpointUrl;
  if (url && url.trim().length > 0) return url;
  return "Target path not attached to this draft";
}

export function EvidenceTriageBoard({
  assessmentId,
  onDraftReviewed,
  reviewedDraftIds,
  onContinueToReport,
}: EvidenceTriageBoardProps) {
  const [drafts, setDrafts] = useState<EvidenceDraftDto[]>([]);
  const [promotedFindings, setPromotedFindings] = useState<FindingDto[]>([]);
  const [loadingDrafts, setLoadingDrafts] = useState<boolean>(false);
  const [reviewingDraftId, setReviewingDraftId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const loadDrafts = useCallback(async () => {
    if (!assessmentId) return;

    setLoadingDrafts(true);
    setError(null);
    try {
      const [response, summary] = await Promise.all([
        getEvidenceDrafts(assessmentId),
        getOrchestratedAssessmentSummary(assessmentId).catch(() => null),
      ]);
      const sorted = [...response.drafts].sort((a, b) => {
        const ra = draftSortRank(a);
        const rb = draftSortRank(b);
        if (ra !== rb) return ra - rb;
        return a.draftId.localeCompare(b.draftId);
      });
      setDrafts(sorted);
      const findings = summary?.findings ?? [];
      const rlsOrAccess = findings.filter((f) => {
        const kind = f.metadata?.kind ?? "";
        const title = (f.title ?? "").toLowerCase();
        return (
          kind === "supabase_rls_abuse_metadata" ||
          title.includes("supabase rls") ||
          f.type === "BROKEN_ACCESS_CONTROL"
        );
      });
      setPromotedFindings(rlsOrAccess);
    } catch (err) {
      if (err instanceof V2ApiError) {
        setError(err.message);
      } else {
        setError((err as Error).message || "Failed to load drafts");
      }
      setDrafts([]);
      setPromotedFindings([]);
    } finally {
      setLoadingDrafts(false);
    }
  }, [assessmentId]);

  useEffect(() => {
    void loadDrafts();
  }, [loadDrafts]);

  const handleReview = async (
    draft: EvidenceDraftDto,
    decision: "approve_evidence" | "reject_evidence"
  ) => {
    setReviewingDraftId(draft.draftId);
    setError(null);
    setSuccessMessage(null);

    try {
      const res = await reviewEvidenceDraft(assessmentId, draft.draftId, {
        decision,
        reviewerId: DEFAULT_REVIEWER_ID,
        reviewedAt: new Date().toISOString(),
      });
      onDraftReviewed(draft.draftId, decision);
      setSuccessMessage(
        decision === "approve_evidence"
          ? res.findingCreated
            ? `Approved — created finding ${res.findingCreated.id}. ${res.remainingDraftCount} left.`
            : `Approved. ${res.remainingDraftCount} drafts remaining.`
          : `Rejected. ${res.remainingDraftCount} drafts remaining.`
      );
      await loadDrafts();
    } catch (err) {
      if (err instanceof V2ApiError) {
        setError(err.message);
      } else {
        setError((err as Error).message || "Failed to review draft");
      }
    } finally {
      setReviewingDraftId(null);
    }
  };

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-950/80 p-6 shadow-2xl backdrop-blur-xl">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-zinc-800/80 pb-4">
        <div>
          <h2 className="text-lg font-semibold tracking-tight text-zinc-100">
            Evidence Triage
          </h2>
          <p className="mt-1 max-w-xl text-xs text-zinc-400 leading-relaxed">
            Review pending drafts from detection. Approve useful evidence or
            reject noise before they become findings or feed Attack Mode. This
            is not a second scan.
          </p>
        </div>

        <button
          type="button"
          onClick={() => void loadDrafts()}
          disabled={loadingDrafts || !assessmentId}
          title="Re-fetch drafts if the pipeline finished more while you were here"
          className="inline-flex items-center gap-1.5 rounded-md border border-zinc-800/80 bg-transparent px-2.5 py-1 text-[11px] font-medium text-zinc-500 transition hover:border-zinc-700 hover:text-zinc-300 disabled:opacity-40"
        >
          <RefreshCw
            className={`h-3 w-3 ${loadingDrafts ? "animate-spin" : ""}`}
          />
          Refresh
        </button>
      </div>

      {error && (
        <div className="mt-4 flex items-start gap-2 rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-300">
          <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
          <span>{error}</span>
        </div>
      )}

      {successMessage && (
        <div className="mt-4 flex items-start gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3 text-xs text-emerald-300">
          <CheckCircle className="h-4 w-4 shrink-0 mt-0.5" />
          <span>{successMessage}</span>
        </div>
      )}

      <div className="mt-6 space-y-3">
        {promotedFindings.length > 0 && (
          <div className="space-y-2 rounded-lg border border-orange-500/30 bg-orange-500/5 p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="text-xs font-semibold text-orange-200">
                Auto-promoted findings ({promotedFindings.length}) — already in
                Attack Mode
              </p>
              <Link
                href={`/v2/attack?assessmentId=${encodeURIComponent(assessmentId)}`}
                className="text-[11px] font-mono text-orange-300 hover:text-orange-200 underline-offset-2 hover:underline"
              >
                Open Attack Mode →
              </Link>
            </div>
            <p className="text-[10px] text-zinc-500">
              RLS / access-control signals that met auto-promote gates skip the
              draft queue. Review plans there; drafts below are optional noise
              filter.
            </p>
            <div className="space-y-2">
              {promotedFindings.map((f, idx) => {
                const severity = presentSeverity(
                  severityFromDetectionKind(
                    f.metadata?.kind === "supabase_rls_abuse_metadata"
                      ? "supabase_rls_abuse"
                      : undefined,
                    { findingSeverity: f.severity }
                  )
                );
                const table =
                  typeof f.metadata?.tableName === "string"
                    ? f.metadata.tableName
                    : undefined;
                return (
                  <div
                    key={`${f.id}-${idx}`}
                    className="rounded-md border border-orange-500/20 bg-zinc-950/60 p-3"
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="text-sm font-semibold text-zinc-100">
                        {f.title}
                      </h3>
                      <span
                        className={`rounded border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${severity.badgeClass}`}
                      >
                        {severity.label}
                      </span>
                    </div>
                    {f.description && (
                      <p className="mt-1 text-[11px] text-zinc-400 leading-relaxed">
                        {f.description}
                      </p>
                    )}
                    <p className="mt-1 truncate font-mono text-[10px] text-zinc-500">
                      {f.target}
                    </p>
                    {table && (
                      <p className="mt-0.5 text-[10px] font-mono text-amber-400/90">
                        table: {table}
                        {typeof f.metadata?.claimKind === "string"
                          ? ` · ${f.metadata.claimKind}`
                          : ""}
                      </p>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        <div className="flex items-center justify-between text-xs text-zinc-400">
          <span className="font-semibold text-zinc-300">
            Pending drafts ({drafts.length})
          </span>
          <span>{reviewedDraftIds.length} reviewed this session</span>
        </div>

        {loadingDrafts ? (
          <div className="flex items-center justify-center gap-2 rounded-lg border border-zinc-800 bg-zinc-900/30 py-8 text-xs text-zinc-400">
            <Loader2 className="h-4 w-4 animate-spin" />
            Loading drafts…
          </div>
        ) : drafts.length === 0 ? (
          <div className="rounded-lg border border-dashed border-zinc-800/80 bg-zinc-900/20 p-6 text-center text-xs text-zinc-500">
            <FileText className="mx-auto h-6 w-6 text-zinc-600 mb-2" />
            No pending drafts for this assessment.
            <p className="mt-1 text-[11px] text-zinc-600">
              You can continue to the report even with zero drafts — abstention
              is valid.
            </p>
          </div>
        ) : (
          (() => {
            const primary = drafts.filter((d) => draftSortRank(d) === 0);
            const lowInfo = drafts.filter((d) => draftSortRank(d) === 1);
            const renderDraft = (draft: EvidenceDraftDto) => {
            const already = reviewedDraftIds.includes(draft.draftId);
            const reviewing = reviewingDraftId === draft.draftId;
            const kind = draft.differentialContext?.detectionKind;
            const level = severityFromDetectionKind(kind, {
              disclosureKind: draft.differentialContext?.disclosureKind,
            });
            const severity = presentSeverity(level);
            const title = draftPlainTitle(kind, draft.suggestedEvidenceType);
            const why = draftWhyItMatters(kind, draft.safeRationale);
            const target = targetFromDraft(draft);

            return (
              <div
                key={draft.draftId}
                className={`rounded-lg border p-4 transition-all ${
                  already
                    ? "border-emerald-500/30 bg-emerald-950/10"
                    : draftSortRank(draft) === 1
                      ? "border-zinc-800/60 bg-zinc-950/40 opacity-90"
                      : "border-zinc-800 bg-zinc-900/50 hover:border-zinc-700"
                }`}
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0 flex-1 space-y-1.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="text-sm font-semibold text-zinc-100">
                        {title}
                      </h3>
                      <span
                        className={`rounded border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${severity.badgeClass}`}
                      >
                        {severity.label}
                      </span>
                    </div>
                    <p className="text-[11px] text-zinc-400 leading-relaxed">
                      {draft.safeRationale}
                    </p>
                    <p className="text-[11px] text-zinc-500 leading-relaxed">
                      <span className="text-zinc-600">Why it matters: </span>
                      {why}
                    </p>
                    <p className="truncate font-mono text-[10px] text-zinc-500">
                      {target}
                    </p>
                    {draft.differentialContext?.supabaseTableName && (
                      <p className="text-[10px] font-mono text-amber-400/90">
                        table: {draft.differentialContext.supabaseTableName}
                        {draft.differentialContext.supabaseClaimKind
                          ? ` · ${draft.differentialContext.supabaseClaimKind}`
                          : ""}
                        {typeof draft.differentialContext.supabaseRowCountHint ===
                        "number"
                          ? ` · ~${draft.differentialContext.supabaseRowCountHint} rows`
                          : ""}
                      </p>
                    )}
                  </div>

                  <div className="flex shrink-0 items-center gap-2">
                    {already ? (
                      <span className="inline-flex items-center gap-1 rounded border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1 text-[11px] font-medium text-emerald-400">
                        <CheckCircle className="h-3.5 w-3.5" />
                        Done
                      </span>
                    ) : (
                      <>
                        <button
                          type="button"
                          onClick={() =>
                            void handleReview(draft, "approve_evidence")
                          }
                          disabled={reviewing}
                          className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-semibold text-white transition hover:bg-emerald-500 disabled:opacity-50"
                        >
                          {reviewing ? (
                            <Loader2 className="h-3.5 w-3.5 animate-spin" />
                          ) : (
                            <Check className="h-3.5 w-3.5" />
                          )}
                          Approve
                        </button>
                        <button
                          type="button"
                          onClick={() =>
                            void handleReview(draft, "reject_evidence")
                          }
                          disabled={reviewing}
                          className="inline-flex items-center gap-1.5 rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-1.5 text-xs font-semibold text-zinc-300 transition hover:bg-zinc-800 disabled:opacity-50"
                        >
                          <X className="h-3.5 w-3.5" />
                          Reject
                        </button>
                      </>
                    )}
                  </div>
                </div>
              </div>
            );
            };

            return (
              <>
                {primary.map(renderDraft)}
                {lowInfo.length > 0 && (
                  <div className="pt-2 space-y-2">
                    <p className="text-[10px] font-mono uppercase tracking-wide text-zinc-600">
                      Low-info / cosmetic ({lowInfo.length}) — not Attack Mode primary
                    </p>
                    {lowInfo.map(renderDraft)}
                  </div>
                )}
              </>
            );
          })()
        )}
      </div>

      <div className="mt-6 flex items-center justify-end border-t border-zinc-800/60 pt-4">
        <button
          type="button"
          onClick={onContinueToReport}
          className="inline-flex items-center gap-2 rounded-lg bg-emerald-600 px-4 py-2 text-xs font-semibold text-white transition hover:bg-emerald-500"
        >
          Continue to Report
          <ArrowRight className="h-3.5 w-3.5" />
        </button>
      </div>
    </div>
  );
}
