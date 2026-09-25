"use client";

import React, { useState, useEffect, useCallback, useMemo } from "react";
import {
  FileText,
  CheckCircle,
  AlertCircle,
  Loader2,
  ArrowRight,
  Check,
  X,
  Layers,
} from "lucide-react";
import {
  getEvidenceDrafts,
  getOrchestratedAssessmentSummary,
  reviewEvidenceDraft,
  V2ApiError,
  type EvidenceDraftDto,
  type FindingDto,
  type TargetProfileDto,
} from "@/lib/v2Api";
import {
  draftPlainTitle,
  draftWhyItMatters,
  presentSeverity,
  severityFromDetectionKind,
  type SeverityLevel,
} from "@/lib/v2/severityPresentation";
import { classifyTechArchitecture } from "@/lib/v2/techArchitecture";

/** Default reviewer for promote API — not shown in UI. */
const DEFAULT_REVIEWER_ID = "op_lead_analyst_01";

const SEVERITY_RANK: Record<SeverityLevel, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

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
  const level = severityFromDetectionKind(kind, {
    disclosureKind: draft.differentialContext?.disclosureKind,
  });
  if (kind === "supabase_rls_abuse") return 0;
  if (kind && LOW_INFO_KIND_ORDER.has(kind)) {
    return 10 + SEVERITY_RANK[level];
  }
  return SEVERITY_RANK[level];
}

interface EvidenceTriageBoardProps {
  assessmentId: string;
  scanId: string;
  onDraftReviewed: (
    draftId: string,
    decision: "approve_evidence" | "reject_evidence"
  ) => void;
  reviewedDraftIds: readonly string[];
  onContinueToAttack: () => void;
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
  onContinueToAttack,
}: EvidenceTriageBoardProps) {
  const [drafts, setDrafts] = useState<EvidenceDraftDto[]>([]);
  const [promotedFindings, setPromotedFindings] = useState<FindingDto[]>([]);
  const [profile, setProfile] = useState<TargetProfileDto | null>(null);
  const [loadingDrafts, setLoadingDrafts] = useState<boolean>(false);
  const [reviewingDraftId, setReviewingDraftId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const techBits = useMemo(
    () => classifyTechArchitecture(profile),
    [profile]
  );

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
      setProfile(summary?.profile ?? null);
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
      setProfile(null);
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
            ? `Incluido en hallazgos — finding creado. ${res.remainingDraftCount} restantes.`
            : `Incluido. ${res.remainingDraftCount} drafts restantes.`
          : `Ruido descartado. ${res.remainingDraftCount} drafts restantes.`
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
            Revisá drafts del detection.{" "}
            <span className="text-zinc-300">Incluir en hallazgos</span> si hay
            impacto o explotabilidad;{" "}
            <span className="text-zinc-300">Descartar ruido</span> si es solo
            hardening cosmético. Esto no es un segundo scan.
          </p>
        </div>

        <button
          type="button"
          onClick={onContinueToAttack}
          className="inline-flex items-center gap-2 rounded-lg bg-orange-600 px-4 py-2 text-xs font-semibold text-white transition hover:bg-orange-500"
        >
          Continue to Attack
          <ArrowRight className="h-3.5 w-3.5" />
        </button>
      </div>

      {/* Tech / architecture panel */}
      <div className="mt-4 rounded-lg border border-zinc-800/80 bg-zinc-900/30 p-4">
        <div className="flex items-center gap-2 mb-3">
          <Layers className="h-4 w-4 text-sky-400" />
          <h3 className="text-xs font-semibold text-zinc-200 uppercase tracking-wider">
            Tech / arquitectura
          </h3>
        </div>
        {techBits.groups.length === 0 ? (
          <p className="text-[11px] text-zinc-600">
            Sin fingerprint aún — aparece cuando el recon termina y hay perfil.
          </p>
        ) : (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {techBits.groups.map((g) => (
              <div key={g.label} className="space-y-1.5">
                <p className="text-[10px] font-mono uppercase tracking-wide text-zinc-600">
                  {g.label}
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {g.items.map((item) => (
                    <span
                      key={`${g.label}-${item.name}`}
                      className="inline-flex items-center gap-1 rounded border border-zinc-800 bg-zinc-950/80 px-2 py-0.5 text-[11px] text-zinc-300"
                      title={item.epistemic}
                    >
                      {item.name}
                      {item.version ? (
                        <span className="font-mono text-zinc-500">
                          {item.version}
                        </span>
                      ) : null}
                      <span
                        className="text-[9px] text-zinc-600"
                        title={
                          item.epistemic === "OBSERVED"
                            ? "Visto en respuestas reales del target"
                            : "Hipótesis derivada (aún no confirmada en respuesta)"
                        }
                      >
                        {item.epistemic === "OBSERVED"
                          ? "Observado"
                          : "Inferido"}
                      </span>
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
        {techBits.hostHint && (
          <p className="mt-2 text-[10px] text-zinc-600 font-mono">
            Host: {techBits.hostHint}
          </p>
        )}
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
        {/* RLS always above cosmetics — even when only promoted findings exist. */}
        {promotedFindings.length > 0 ? (
          <div className="space-y-2 rounded-lg border border-orange-500/30 bg-orange-500/5 p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="text-xs font-semibold text-orange-200">
                Hallazgos RLS / access-control ({promotedFindings.length}) — ya
                en Attack Mode
              </p>
            </div>
            <p className="text-[10px] text-zinc-500">
              Señales que pasaron el gate de auto-promote. Los drafts de abajo
              son filtro opcional de ruido.
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
        ) : (
          <div className="rounded-lg border border-dashed border-orange-500/20 bg-orange-500/[0.03] px-3 py-2.5">
            <p className="text-[11px] font-medium text-orange-200/80">
              RLS / access-control
            </p>
            <p className="mt-0.5 text-[10px] text-zinc-600">
              Sin hallazgos RLS auto-promovidos en este assessment. Si aparecen
              drafts RLS en pendientes, quedan arriba del bloque cosmético.
            </p>
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
              Podés continuar a Attack aunque no haya drafts — la abstención es
              válida.
            </p>
          </div>
        ) : (
          (() => {
            const primary = drafts.filter((d) => draftSortRank(d) < 10);
            const lowInfo = drafts.filter((d) => draftSortRank(d) >= 10);
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
                      : draftSortRank(draft) >= 10
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
                          {typeof draft.differentialContext
                            .supabaseRowCountHint === "number"
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
                            Incluir en hallazgos
                          </button>
                          <button
                            type="button"
                            onClick={() =>
                              void handleReview(draft, "reject_evidence")
                            }
                            disabled={reviewing}
                            className="inline-flex items-center gap-1.5 rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-1.5 text-xs font-semibold text-zinc-300 transition hover:bg-zinc-800 disabled:opacity-50"
                            title="Descartar como ruido — no pasa a hallazgos"
                          >
                            <X className="h-3.5 w-3.5" />
                            Descartar ruido
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
                {primary.length > 0 && (
                  <div className="space-y-2">
                    {primary.some(
                      (d) =>
                        d.differentialContext?.detectionKind ===
                        "supabase_rls_abuse"
                    ) && (
                      <p className="text-[10px] font-mono uppercase tracking-wide text-orange-400/80">
                        RLS / access — pendientes de triage
                      </p>
                    )}
                    {primary.map(renderDraft)}
                  </div>
                )}
                {lowInfo.length > 0 && (
                  <div className="pt-2 space-y-2">
                    <p className="text-[10px] font-mono uppercase tracking-wide text-zinc-600">
                      Low-info / cosmético ({lowInfo.length}) — no primario para
                      Attack
                    </p>
                    {lowInfo.map(renderDraft)}
                  </div>
                )}
              </>
            );
          })()
        )}
      </div>
    </div>
  );
}
