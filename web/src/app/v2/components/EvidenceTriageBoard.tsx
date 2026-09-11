"use client";

import React, { useState, useEffect, useCallback } from "react";
import {
  FileText,
  UserCheck,
  CheckCircle,
  AlertCircle,
  Clock,
  Layers,
  ArrowUpRight,
  Loader2,
  RefreshCw,
  ShieldCheck
} from "lucide-react";
import { v2ApiClient, V2ApiError } from "@/lib/v2/apiClient";
import { generateCandidateId, generateTriageDecisionId, isStrictSafeId } from "@/lib/v2/idGenerator";
import type {
  ReviewedEvidenceFindingCandidateDraftDto,
  FormalFindingCandidateDto
} from "@/lib/v2/types";

interface EvidenceTriageBoardProps {
  initialScanId: string;
  onCandidatePromoted: (candidate: FormalFindingCandidateDto) => void;
  promotedCandidates: FormalFindingCandidateDto[];
}

export function EvidenceTriageBoard({
  initialScanId,
  onCandidatePromoted,
  promotedCandidates
}: EvidenceTriageBoardProps) {
  const [scanId, setScanId] = useState<string>(initialScanId);
  const [reviewerId, setReviewerId] = useState<string>("op_lead_analyst_01");
  const [drafts, setDrafts] = useState<ReviewedEvidenceFindingCandidateDraftDto[]>([]);
  const [loadingDrafts, setLoadingDrafts] = useState<boolean>(false);
  const [promotingDraftId, setPromotingDraftId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const [prevInitialScanId, setPrevInitialScanId] = useState<string>(initialScanId);
  if (initialScanId !== prevInitialScanId) {
    setPrevInitialScanId(initialScanId);
    if (!scanId) {
      setScanId(initialScanId);
    }
  }

  const loadDrafts = useCallback(async (targetScanId: string) => {
    if (!targetScanId || !isStrictSafeId(targetScanId)) {
      return;
    }

    setLoadingDrafts(true);
    setError(null);
    try {
      const response = await v2ApiClient.listEvidenceDrafts(targetScanId);
      setDrafts(response.drafts || []);
    } catch (err) {
      if (err instanceof V2ApiError) {
        setError(`[${err.errorType}] ${err.message}`);
      } else {
        setError((err as Error).message || "Failed to load evidence drafts");
      }
      setDrafts([]);
    } finally {
      setLoadingDrafts(false);
    }
  }, []);

  useEffect(() => {
    let isCancelled = false;

    async function fetchDraftsAsync() {
      if (!scanId || !isStrictSafeId(scanId)) return;
      try {
        const response = await v2ApiClient.listEvidenceDrafts(scanId);
        if (!isCancelled) {
          setDrafts(response.drafts || []);
        }
      } catch (err) {
        if (!isCancelled) {
          if (err instanceof V2ApiError) {
            setError(`[${err.errorType}] ${err.message}`);
          } else {
            setError((err as Error).message || "Failed to load evidence drafts");
          }
          setDrafts([]);
        }
      }
    }

    if (scanId && isStrictSafeId(scanId)) {
      void fetchDraftsAsync();
    }

    return () => {
      isCancelled = true;
    };
  }, [scanId]);

  const handlePromote = async (draft: ReviewedEvidenceFindingCandidateDraftDto) => {
    if (!isStrictSafeId(reviewerId)) {
      setError("Please provide a valid Reviewer ID (letters, numbers, underscore, hyphens)");
      return;
    }

    setPromotingDraftId(draft.draftId);
    setError(null);
    setSuccessMessage(null);

    const candidateId = generateCandidateId();
    const triageDecisionId = generateTriageDecisionId();

    try {
      // ANTI-FABRICATION: ONLY IDENTIFIERS AND OPERATOR METADATA ARE SENT
      const res = await v2ApiClient.promoteCandidate({
        candidateId,
        scanId: draft.scanId,
        draftId: draft.draftId,
        reviewerId: reviewerId.trim(),
        triageDecisionId
      });

      onCandidatePromoted(res.candidate);
      setSuccessMessage(`Draft ${draft.draftId} promoted to candidate ${res.candidate.candidateId}`);
    } catch (err) {
      if (err instanceof V2ApiError) {
        setError(`Promotion Error (${err.errorType}): ${err.message}`);
      } else {
        setError((err as Error).message || "Failed to promote draft to candidate");
      }
    } finally {
      setPromotingDraftId(null);
    }
  };

  const isAlreadyPromoted = (draftId: string) => {
    return promotedCandidates.some((c) => c.draftId === draftId);
  };

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-950/80 p-6 shadow-2xl backdrop-blur-xl">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-zinc-800/80 pb-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-purple-500/20 bg-purple-500/10 text-purple-400">
            <UserCheck className="h-5 w-5" />
          </div>
          <div>
            <h2 className="text-lg font-semibold tracking-tight text-zinc-100">
              Stage 3: Evidence Triage Board (Human-in-the-Loop)
            </h2>
            <p className="text-xs text-zinc-400">
              Review authentic evidence drafts grouped by scanId and promote to formal finding candidates
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => loadDrafts(scanId)}
            disabled={loadingDrafts || !scanId}
            className="inline-flex items-center gap-1.5 rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-1.5 text-xs font-medium text-zinc-300 transition hover:bg-zinc-800 disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loadingDrafts ? "animate-spin text-purple-400" : ""}`} />
            Refresh Drafts
          </button>
        </div>
      </div>

      {/* Control Bar: Scan ID & Reviewer ID */}
      <div className="mt-5 grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div>
          <label htmlFor="scanIdInput" className="block text-xs font-medium text-zinc-300">
            Active Scan ID for Querying Drafts
          </label>
          <div className="mt-1 flex rounded-lg shadow-sm">
            <input
              id="scanIdInput"
              type="text"
              value={scanId}
              onChange={(e) => setScanId(e.target.value.trim())}
              placeholder="e.g. session_12345 or scn_beta_01"
              className="block w-full rounded-lg border border-zinc-800 bg-zinc-900/60 px-3.5 py-2 text-xs font-mono text-zinc-200 placeholder-zinc-600 focus:border-purple-500/50 focus:outline-none focus:ring-2 focus:ring-purple-500/20"
            />
          </div>
          <p className="mt-1 text-[11px] text-zinc-500">
            Resolves drafts via GET /api/v2/scans/:scanId/evidence-drafts
          </p>
        </div>

        <div>
          <label htmlFor="reviewerIdInput" className="block text-xs font-medium text-zinc-300">
            Human Reviewer Signature ID (HITL Gate)
          </label>
          <div className="mt-1 flex rounded-lg shadow-sm">
            <input
              id="reviewerIdInput"
              type="text"
              value={reviewerId}
              onChange={(e) => setReviewerId(e.target.value.trim())}
              placeholder="op_security_auditor"
              className="block w-full rounded-lg border border-zinc-800 bg-zinc-900/60 px-3.5 py-2 text-xs font-mono text-zinc-200 placeholder-zinc-600 focus:border-purple-500/50 focus:outline-none focus:ring-2 focus:ring-purple-500/20"
            />
          </div>
          <p className="mt-1 text-[11px] text-zinc-500">
            Authorizes candidate promotion with immutable lineage logging
          </p>
        </div>
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

      {/* Drafts List */}
      <div className="mt-6 space-y-3">
        <div className="flex items-center justify-between text-xs text-zinc-400">
          <span className="font-semibold text-zinc-300">
            Pending Evidence Drafts ({drafts.length})
          </span>
          <span>{promotedCandidates.length} Promoted to Formal Candidates</span>
        </div>

        {loadingDrafts ? (
          <div className="flex items-center justify-center gap-2 rounded-lg border border-zinc-800 bg-zinc-900/30 py-8 text-xs text-zinc-400">
            <Loader2 className="h-4 w-4 animate-spin text-purple-400" />
            Loading authentic drafts from backend...
          </div>
        ) : drafts.length === 0 ? (
          <div className="rounded-lg border border-dashed border-zinc-800/80 bg-zinc-900/20 p-6 text-center text-xs text-zinc-500">
            <FileText className="mx-auto h-6 w-6 text-zinc-600 mb-2" />
            No unreviewed evidence drafts found for scan ID:{" "}
            <span className="font-mono text-zinc-400">{scanId || "none"}</span>.
            <p className="mt-1 text-[11px] text-zinc-600">
              Run active recon or execute evidence collection to populate drafts.
            </p>
          </div>
        ) : (
          drafts.map((draft) => {
            const promoted = isAlreadyPromoted(draft.draftId);
            const isPromotingThis = promotingDraftId === draft.draftId;

            return (
              <div
                key={draft.draftId}
                className={`rounded-lg border p-4 transition-all ${
                  promoted
                    ? "border-emerald-500/30 bg-emerald-950/10"
                    : "border-zinc-800 bg-zinc-900/50 hover:border-zinc-700"
                }`}
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-semibold text-zinc-200">
                      {draft.draftId}
                    </span>
                    <span className="rounded bg-zinc-800 px-2 py-0.5 text-[10px] font-mono text-zinc-400">
                      Scan: {draft.scanId}
                    </span>
                  </div>

                  <div className="flex items-center gap-2 text-xs">
                    {promoted ? (
                      <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-0.5 text-[11px] font-medium text-emerald-400">
                        <CheckCircle className="h-3.5 w-3.5" />
                        Promoted to Candidate
                      </span>
                    ) : (
                      <button
                        type="button"
                        onClick={() => handlePromote(draft)}
                        disabled={isPromotingThis}
                        className="inline-flex items-center gap-1.5 rounded-lg bg-purple-600 px-3 py-1.5 text-xs font-semibold text-white transition hover:bg-purple-500 focus:outline-none focus:ring-2 focus:ring-purple-500/40 disabled:opacity-50 shadow-md shadow-purple-600/20"
                      >
                        {isPromotingThis ? (
                          <>
                            <Loader2 className="h-3.5 w-3.5 animate-spin" />
                            Promoting...
                          </>
                        ) : (
                          <>
                            Promote to Candidate
                            <ArrowUpRight className="h-3.5 w-3.5" />
                          </>
                        )}
                      </button>
                    )}
                  </div>
                </div>

                {/* Evidence Summary Badges */}
                <div className="mt-3 flex flex-wrap items-center gap-2 text-[11px] text-zinc-400">
                  <span className="flex items-center gap-1 rounded border border-zinc-800 bg-zinc-900 px-2 py-0.5 font-mono">
                    <Layers className="h-3 w-3 text-zinc-500" />
                    Refs: {draft.sourceSelection.selectedCount}
                  </span>
                  {Object.entries(draft.observedEvidenceSummary.evidenceTypeCounts || {}).map(
                    ([type, count]) => (
                      <span
                        key={type}
                        className="rounded border border-blue-500/20 bg-blue-500/10 px-2 py-0.5 font-mono text-blue-300"
                      >
                        {type}: {count}
                      </span>
                    )
                  )}
                  <span className="flex items-center gap-1 font-mono text-zinc-500">
                    <Clock className="h-3 w-3" />
                    {new Date(draft.createdAt).toLocaleTimeString()}
                  </span>
                </div>

                {/* Anti-Fabrication Notice */}
                <div className="mt-3 border-t border-zinc-800/60 pt-2 text-[10px] text-zinc-500 flex items-center justify-between">
                  <span className="flex items-center gap-1">
                    <ShieldCheck className="h-3 w-3 text-emerald-500" />
                    Human Review Required: {draft.draftTriage.humanReviewRequired ? "YES" : "NO"}
                  </span>
                  <span className="italic">
                    Backend enforces pure observation verification
                  </span>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
