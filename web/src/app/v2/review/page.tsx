"use client";

import React, { useState, useEffect, useCallback, Suspense } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
  ShieldAlert,
  ShieldCheck,
  ArrowLeft,
  Zap,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  FileSearch,
  Fingerprint,
  Layers,
  ArrowRight,
  Info,
  RefreshCw,
  UserCheck,
  Scale
} from "lucide-react";
import {
  getEvidenceDrafts,
  reviewEvidenceDraft,
  getOrchestratedAssessmentSummary,
  V2ApiError,
  type EvidenceDraftDto,
  type OrchestratedAssessmentSummaryResponse
} from "@/lib/v2Api";

function HumanReviewContent() {
  const searchParams = useSearchParams();
  const assessmentIdFromQuery = searchParams.get("assessmentId") || "";

  const [assessmentId, setAssessmentId] = useState<string>(assessmentIdFromQuery);
  const [operatorId, setOperatorId] = useState<string>("usr_secops_lead");
  const [drafts, setDrafts] = useState<readonly EvidenceDraftDto[]>([]);
  const [summary, setSummary] = useState<OrchestratedAssessmentSummaryResponse | null>(null);
  const [selectedDraftId, setSelectedDraftId] = useState<string | null>(null);
  const [notes, setNotes] = useState<string>("");
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const fetchDraftsAndSummary = useCallback(async (id: string) => {
    if (!id || id.trim().length === 0) return;
    setIsLoading(true);
    setError(null);
    try {
      const [draftsRes, summaryRes] = await Promise.all([
        getEvidenceDrafts(id),
        getOrchestratedAssessmentSummary(id).catch(() => null),
      ]);
      setDrafts(draftsRes.drafts);
      setSummary(summaryRes);
      if (draftsRes.drafts.length > 0) {
        setSelectedDraftId(draftsRes.drafts[0].draftId);
      } else {
        setSelectedDraftId(null);
      }
    } catch (err) {
      if (err instanceof V2ApiError) {
        setError(`[${err.errorType}] ${err.message}`);
      } else {
        setError((err as Error).message || "Failed to load evidence drafts");
      }
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (assessmentIdFromQuery) {
      setAssessmentId(assessmentIdFromQuery);
      fetchDraftsAndSummary(assessmentIdFromQuery);
    }
  }, [assessmentIdFromQuery, fetchDraftsAndSummary]);

  const handleReviewAction = async (decision: "approve_evidence" | "reject_evidence") => {
    if (!selectedDraftId || !assessmentId) return;

    if (!operatorId || operatorId.trim().length === 0) {
      setError("Debe especificar un ID de operador válido");
      return;
    }

    if (operatorId.toLowerCase().includes("reviewer_lead_sec") || operatorId.toLowerCase().startsWith("synthetic_")) {
      setError("Anti-Bypass Gate: El ID de operador sintético/mock no está autorizado en producción.");
      return;
    }

    setIsSubmitting(true);
    setError(null);
    setSuccessMsg(null);

    try {
      const result = await reviewEvidenceDraft(assessmentId, selectedDraftId, {
        decision,
        reviewerId: operatorId.trim(),
        reviewedAt: new Date().toISOString(),
        ...(notes.trim() ? { notes: notes.trim() } : {}),
      });

      setSuccessMsg(
        decision === "approve_evidence"
          ? `Evidencia '${selectedDraftId}' aprobada y promovida exitosamente a Hallazgo formal.`
          : `Borrador de evidencia '${selectedDraftId}' rechazado y descartado limpiamente.`
      );
      setNotes("");

      // Refresh drafts and summary
      await fetchDraftsAndSummary(assessmentId);
    } catch (err) {
      if (err instanceof V2ApiError) {
        setError(`[${err.errorType}] ${err.message}`);
      } else {
        setError((err as Error).message || "Error al procesar la revisión");
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  const selectedDraft = drafts.find((d) => d.draftId === selectedDraftId);
  const diffContext = selectedDraft?.differentialContext;

  return (
    <div className="min-h-screen bg-black text-zinc-100 font-sans pb-24">
      {/* Header Banner */}
      <header className="border-b border-zinc-900 bg-zinc-950/70 backdrop-blur-xl sticky top-0 z-40">
        <div className="max-w-6xl mx-auto px-6 py-4 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <Link
              href={assessmentId ? `/v2/assessments` : `/v2`}
              className="flex h-9 w-9 items-center justify-center rounded-lg border border-zinc-800 bg-zinc-900 text-zinc-400 hover:text-white hover:border-zinc-700 transition cursor-pointer"
              title="Return to Assessments"
            >
              <ArrowLeft className="h-4 w-4" />
            </Link>

            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-amber-500/30 bg-amber-500/10 text-amber-400">
              <Scale className="h-5 w-5" />
            </div>

            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-base font-bold tracking-tight text-white">
                  FixGuard V2 — Human Review &amp; Evidence Triage (HITL)
                </h1>
                <span className="rounded bg-amber-500/10 border border-amber-500/30 px-2 py-0.5 text-[10px] font-mono font-semibold text-amber-400">
                  Milestone P1-3
                </span>
                <span className="rounded bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 text-[10px] font-mono text-emerald-300">
                  Level 2 HITL
                </span>
              </div>
              <p className="text-xs text-zinc-400">
                Human-in-the-Loop Verification: Differential HTTP Evidence Inspection &amp; Finding Promotion Gate
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 text-xs font-mono">
            <Link
              href="/v2/assessments"
              className="rounded-lg border border-zinc-800 bg-zinc-900/60 hover:bg-zinc-900 px-3 py-1.5 text-zinc-400 hover:text-zinc-200 transition"
            >
              Assessments &rarr;
            </Link>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="max-w-6xl mx-auto px-6 mt-8 space-y-8">
        {/* Controls Bar */}
        <section className="rounded-2xl border border-zinc-800 bg-zinc-950/80 p-5 shadow-2xl backdrop-blur-xl">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-end">
            <div>
              <label className="text-[11px] font-mono text-zinc-400 uppercase tracking-wider block mb-1.5">
                Assessment ID
              </label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={assessmentId}
                  onChange={(e) => setAssessmentId(e.target.value)}
                  placeholder="asmt_orch_..."
                  className="w-full rounded-xl border border-zinc-800 bg-zinc-900/60 px-3.5 py-2 text-xs font-mono text-white placeholder:text-zinc-600 focus:border-amber-500/50 focus:outline-none focus:ring-1 focus:ring-amber-500/50"
                />
                <button
                  type="button"
                  onClick={() => fetchDraftsAndSummary(assessmentId)}
                  disabled={isLoading || !assessmentId}
                  className="rounded-xl border border-zinc-800 bg-zinc-900 px-3 py-2 text-xs font-mono text-zinc-300 hover:bg-zinc-800 hover:text-white transition disabled:opacity-50 cursor-pointer flex items-center gap-1"
                >
                  <RefreshCw className={`h-3.5 w-3.5 ${isLoading ? "animate-spin" : ""}`} />
                  Cargar
                </button>
              </div>
            </div>

            <div>
              <label className="text-[11px] font-mono text-zinc-400 uppercase tracking-wider block mb-1.5">
                Operator Authenticated Identity (HITL)
              </label>
              <div className="flex items-center gap-2 rounded-xl border border-zinc-800 bg-zinc-900/60 px-3.5 py-2">
                <UserCheck className="h-4 w-4 text-emerald-400 shrink-0" />
                <input
                  type="text"
                  value={operatorId}
                  onChange={(e) => setOperatorId(e.target.value)}
                  placeholder="usr_secops_lead"
                  className="w-full bg-transparent text-xs font-mono text-white placeholder:text-zinc-600 focus:outline-none"
                />
              </div>
            </div>

            <div className="flex items-center justify-between border border-zinc-800/80 rounded-xl bg-zinc-900/30 p-2.5 px-4 text-xs font-mono">
              <div>
                <span className="text-zinc-500 block text-[10px]">Borradores Pendientes</span>
                <span className="text-sm font-bold text-amber-400">{drafts.length}</span>
              </div>
              <div className="text-right">
                <span className="text-zinc-500 block text-[10px]">Hallazgos Promovidos</span>
                <span className="text-sm font-bold text-emerald-400">{summary?.findings.length ?? 0}</span>
              </div>
            </div>
          </div>
        </section>

        {/* Alerts */}
        {error && (
          <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 flex items-start gap-3 text-xs text-rose-300">
            <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400 mt-0.5" />
            <div className="space-y-0.5">
              <span className="font-semibold block font-mono">Error de Validación / Autorización</span>
              <p className="leading-relaxed">{error}</p>
            </div>
          </div>
        )}

        {successMsg && (
          <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-4 flex items-start gap-3 text-xs text-emerald-300">
            <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400 mt-0.5" />
            <div className="space-y-0.5">
              <span className="font-semibold block font-mono">Acción de Triage Registrada</span>
              <p className="leading-relaxed">{successMsg}</p>
            </div>
          </div>
        )}

        {/* Review Workspace Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Column: Draft Queue */}
          <div className="lg:col-span-4 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-mono uppercase tracking-wider text-zinc-400 flex items-center gap-2">
                <Layers className="h-3.5 w-3.5 text-amber-400" />
                Cola de Evidencia ({drafts.length})
              </h3>
            </div>

            {drafts.length === 0 ? (
              <div className="rounded-2xl border border-zinc-800 bg-zinc-950/60 p-8 text-center space-y-3">
                <CheckCircle2 className="mx-auto h-8 w-8 text-emerald-400" />
                <div className="text-xs font-semibold text-white">Cola de Triage Vacía</div>
                <p className="text-[11px] text-zinc-400">
                  No hay borradores de evidencia pendientes de revisión humana para esta evaluación.
                </p>
              </div>
            ) : (
              <div className="space-y-2.5 max-h-[600px] overflow-y-auto pr-1">
                {drafts.map((d) => (
                  <button
                    key={d.draftId}
                    type="button"
                    onClick={() => setSelectedDraftId(d.draftId)}
                    className={`w-full text-left rounded-xl border p-3.5 transition cursor-pointer space-y-2 ${
                      selectedDraftId === d.draftId
                        ? "border-amber-500/50 bg-amber-500/10 shadow-lg"
                        : "border-zinc-800 bg-zinc-900/40 hover:bg-zinc-900 hover:border-zinc-700"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="rounded bg-amber-500/20 border border-amber-500/40 px-2 py-0.5 text-[10px] font-mono font-bold text-amber-300 uppercase">
                        {d.differentialContext?.detectionKind?.replace(/_/g, " ") ?? d.suggestedEvidenceType}
                      </span>
                      <span className="text-[10px] font-mono text-zinc-500">
                        {d.suggestedStrength}
                      </span>
                    </div>

                    <div className="text-xs font-mono text-white font-medium truncate">
                      {d.draftId}
                    </div>

                    <p className="text-[11px] text-zinc-400 line-clamp-2 leading-relaxed">
                      {d.safeRationale}
                    </p>
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Right Column: Differential Viewer & Action Controls */}
          <div className="lg:col-span-8 space-y-6">
            {selectedDraft ? (
              <div className="rounded-2xl border border-zinc-800 bg-zinc-950/80 p-6 shadow-2xl backdrop-blur-xl space-y-6">
                {/* Draft Header */}
                <div className="flex flex-wrap items-center justify-between gap-4 border-b border-zinc-800/80 pb-4">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="rounded bg-amber-500 text-black px-2 py-0.5 text-[10px] font-bold uppercase font-mono">
                        HITL Review Required
                      </span>
                      <h3 className="text-sm font-semibold text-white font-mono">
                        {selectedDraft.draftId}
                      </h3>
                    </div>
                    <p className="text-xs text-zinc-400 mt-1">
                      Target Endpoint: <strong className="text-zinc-200 font-mono">{diffContext?.endpointUrl ?? "N/A"}</strong>
                    </p>
                  </div>

                  <div className="text-right text-[11px] font-mono text-zinc-500">
                    <div>Comparison ID: {selectedDraft.sourceComparisonId}</div>
                    <div>Strength: {selectedDraft.suggestedStrength}</div>
                  </div>
                </div>

                {/* Differential Viewer: HTTP Observation Evidence */}
                <div className="space-y-4">
                  <h4 className="text-xs font-mono uppercase tracking-wider text-zinc-400 flex items-center gap-2">
                    <FileSearch className="h-4 w-4 text-purple-400" />
                    Visor de Evidencia Diferencial HTTP (M47 / M49)
                  </h4>

                  {/* Differential Cards Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* Baseline Snapshot Card */}
                    <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-4 space-y-2">
                      <div className="flex items-center justify-between text-[11px] font-mono border-b border-zinc-800 pb-2">
                        <span className="text-zinc-400 font-semibold uppercase">Baseline (Control)</span>
                        <span className="text-zinc-500">{selectedDraft.sourceSnapshotIds.baselineSnapshotId}</span>
                      </div>
                      <div className="space-y-1 text-xs font-mono">
                        <div className="flex justify-between">
                          <span className="text-zinc-500">Status Code:</span>
                          <span className="text-zinc-200">{diffContext?.baselineStatusCode ?? "200 OK"}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-zinc-500">Body Hash:</span>
                          <span className="text-zinc-400 text-[10px] truncate max-w-[150px]">
                            {diffContext?.baselineBodyHash ?? "N/A"}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-zinc-500">Auth Signal:</span>
                          <span className="text-zinc-400">Baseline Context</span>
                        </div>
                      </div>
                    </div>

                    {/* Validation Snapshot Card */}
                    <div className="rounded-xl border border-purple-500/30 bg-purple-500/5 p-4 space-y-2">
                      <div className="flex items-center justify-between text-[11px] font-mono border-b border-purple-500/20 pb-2">
                        <span className="text-purple-300 font-semibold uppercase">Validation (Probe)</span>
                        <span className="text-purple-400/60">{selectedDraft.sourceSnapshotIds.validationSnapshotId}</span>
                      </div>
                      <div className="space-y-1 text-xs font-mono">
                        <div className="flex justify-between">
                          <span className="text-zinc-500">Status Code:</span>
                          <span className="text-emerald-400 font-bold">{diffContext?.validationStatusCode ?? "200 OK"}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-zinc-500">Body Hash:</span>
                          <span className="text-zinc-400 text-[10px] truncate max-w-[150px]">
                            {diffContext?.validationBodyHash ?? "N/A"}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-zinc-500">Detection Type:</span>
                          <span className="text-purple-300 font-bold">{diffContext?.detectionKind ?? "N/A"}</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Differential Specifics (CORS / Parameter Reflection details) */}
                  <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 space-y-3">
                    <span className="text-[11px] font-mono text-zinc-400 uppercase tracking-wider block">
                      Parámetros &amp; Observaciones Específicas
                    </span>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
                      {diffContext?.reflectedOrigin && (
                        <div className="rounded-lg bg-black/40 border border-zinc-800 p-2.5">
                          <span className="text-zinc-500 text-[10px] block">Reflected Origin (ACAO):</span>
                          <span className="text-rose-400 font-bold">{diffContext.reflectedOrigin}</span>
                        </div>
                      )}

                      {diffContext?.allowCredentials !== undefined && (
                        <div className="rounded-lg bg-black/40 border border-zinc-800 p-2.5">
                          <span className="text-zinc-500 text-[10px] block">Allow Credentials (ACAC):</span>
                          <span className="text-amber-400 font-bold">{String(diffContext.allowCredentials)}</span>
                        </div>
                      )}

                      {diffContext?.parameterName && (
                        <div className="rounded-lg bg-black/40 border border-zinc-800 p-2.5">
                          <span className="text-zinc-500 text-[10px] block">Parameter Tested:</span>
                          <span className="text-blue-400 font-bold">{diffContext.parameterName}</span>
                        </div>
                      )}

                      {diffContext?.reflectedCanary && (
                        <div className="rounded-lg bg-black/40 border border-zinc-800 p-2.5">
                          <span className="text-zinc-500 text-[10px] block">Reflected Canary Payload:</span>
                          <span className="text-emerald-400 font-bold">{diffContext.reflectedCanary}</span>
                        </div>
                      )}

                      {diffContext?.resourceParamName && (
                        <div className="rounded-lg bg-black/40 border border-zinc-800 p-2.5">
                          <span className="text-zinc-500 text-[10px] block">Resource Param:</span>
                          <span className="text-amber-400 font-bold">{diffContext.resourceParamName}</span>
                        </div>
                      )}

                      {diffContext?.finalDestination && (
                        <div className="rounded-lg bg-black/40 border border-zinc-800 p-2.5">
                          <span className="text-zinc-500 text-[10px] block">Redirect Destination (Location):</span>
                          <span className="text-rose-400 font-bold">{diffContext.finalDestination}</span>
                        </div>
                      )}

                      {diffContext?.injectedCanary && (
                        <div className="rounded-lg bg-black/40 border border-zinc-800 p-2.5">
                          <span className="text-zinc-500 text-[10px] block">Injected Canary:</span>
                          <span className="text-amber-400 font-bold">{diffContext.injectedCanary}</span>
                        </div>
                      )}

                      {diffContext?.missingHeaders && diffContext.missingHeaders.length > 0 && (
                        <div className="rounded-lg bg-black/40 border border-zinc-800 p-2.5 col-span-2">
                          <span className="text-zinc-500 text-[10px] block">Missing Hardening Headers:</span>
                          <span className="text-amber-400 font-bold">{diffContext.missingHeaders.join(', ')}</span>
                        </div>
                      )}

                      {diffContext?.disclosureKind && (
                        <div className="rounded-lg bg-black/40 border border-zinc-800 p-2.5">
                          <span className="text-zinc-500 text-[10px] block">Disclosure Kind:</span>
                          <span className="text-rose-400 font-bold uppercase">{diffContext.disclosureKind.replace('_', ' ')}</span>
                        </div>
                      )}

                      {diffContext?.trigger && (
                        <div className="rounded-lg bg-black/40 border border-zinc-800 p-2.5">
                          <span className="text-zinc-500 text-[10px] block">Observed Trigger:</span>
                          <span className="text-zinc-300 font-bold">{diffContext.trigger}</span>
                        </div>
                      )}

                      {diffContext?.subdomain && (
                        <div className="rounded-lg bg-black/40 border border-zinc-800 p-2.5">
                          <span className="text-zinc-500 text-[10px] block">Dangling Subdomain:</span>
                          <span className="text-rose-400 font-bold">{diffContext.subdomain}</span>
                        </div>
                      )}

                      {diffContext?.cnameTarget && (
                        <div className="rounded-lg bg-black/40 border border-zinc-800 p-2.5">
                          <span className="text-zinc-500 text-[10px] block">CNAME Target:</span>
                          <span className="text-amber-400 font-bold">{diffContext.cnameTarget}</span>
                        </div>
                      )}

                      {diffContext?.hostingProvider && (
                        <div className="rounded-lg bg-black/40 border border-zinc-800 p-2.5">
                          <span className="text-zinc-500 text-[10px] block">Hosting Provider:</span>
                          <span className="text-purple-300 font-bold uppercase">{diffContext.hostingProvider.replace('_', ' ')}</span>
                        </div>
                      )}

                      {diffContext?.fingerprintMatch && (
                        <div className="rounded-lg bg-black/40 border border-rose-500/30 p-2.5 col-span-2">
                          <span className="text-rose-400 text-[10px] block font-semibold mb-1">Matched Unclaimed Resource Fingerprint:</span>
                          <code className="text-rose-300 text-[11px] font-mono bg-black/60 p-2 rounded border border-zinc-900 block">
                            {diffContext.fingerprintMatch}
                          </code>
                        </div>
                      )}

                      {diffContext?.weakProtocols && diffContext.weakProtocols.length > 0 && (
                        <div className="rounded-lg bg-black/40 border border-rose-500/30 p-2.5">
                          <span className="text-zinc-500 text-[10px] block">Insecure / Deprecated Protocols:</span>
                          <span className="text-rose-400 font-bold">{diffContext.weakProtocols.join(', ')}</span>
                        </div>
                      )}

                      {diffContext?.weakCiphers && diffContext.weakCiphers.length > 0 && (
                        <div className="rounded-lg bg-black/40 border border-amber-500/30 p-2.5">
                          <span className="text-zinc-500 text-[10px] block">Weak / Insecure Cipher Suites:</span>
                          <span className="text-amber-400 font-bold text-[11px] truncate block" title={diffContext.weakCiphers.join(', ')}>
                            {diffContext.weakCiphers.join(', ')}
                          </span>
                        </div>
                      )}

                      {diffContext?.certificateIssues && diffContext.certificateIssues.length > 0 && (
                        <div className="rounded-lg bg-black/40 border border-rose-500/30 p-2.5">
                          <span className="text-zinc-500 text-[10px] block">Certificate Health Anomalies:</span>
                          <span className="text-rose-300 font-bold uppercase">{diffContext.certificateIssues.join(', ')}</span>
                        </div>
                      )}

                      {diffContext?.bypassMechanism && (
                        <div className="rounded-lg bg-black/40 border border-rose-500/30 p-2.5">
                          <span className="text-zinc-500 text-[10px] block">Bypass Mechanism:</span>
                          <span className="text-rose-400 font-bold uppercase">{diffContext.bypassMechanism.replace('_', ' ')}</span>
                        </div>
                      )}

                      {diffContext?.bodySimilarityRatio !== undefined && (
                        <div className="rounded-lg bg-black/40 border border-amber-500/30 p-2.5">
                          <span className="text-zinc-500 text-[10px] block">Body Match Similarity:</span>
                          <span className="text-amber-400 font-bold">{Math.round(diffContext.bodySimilarityRatio * 100)}%</span>
                        </div>
                      )}

                      {diffContext?.supportedTlsVersions && diffContext.supportedTlsVersions.length > 0 && (
                        <div className="rounded-lg bg-black/40 border border-zinc-800 p-2.5">
                          <span className="text-zinc-500 text-[10px] block">Supported TLS Versions:</span>
                          <span className="text-zinc-300 font-mono text-[11px]">{diffContext.supportedTlsVersions.join(', ')}</span>
                        </div>
                      )}

                      {diffContext?.disclosedFragment && (
                        <div className="rounded-lg bg-black/40 border border-rose-500/30 p-2.5 col-span-2">
                          <span className="text-rose-400 text-[10px] block font-semibold mb-1">Disclosed Fragment (Sanitized):</span>
                          <pre className="text-zinc-200 text-[11px] whitespace-pre-wrap break-all font-mono bg-black/60 p-2 rounded border border-zinc-900">
                            {diffContext.disclosedFragment}
                          </pre>
                        </div>
                      )}

                      {diffContext?.exposedMapUrl && (
                        <div className="rounded-lg bg-black/40 border border-rose-500/30 p-2.5 col-span-2">
                          <span className="text-rose-400 text-[10px] block font-semibold mb-1">Exposed Sourcemap URL (.map):</span>
                          <span className="text-rose-300 text-[11px] font-mono break-all">{diffContext.exposedMapUrl}</span>
                        </div>
                      )}

                      {diffContext?.sourceJsUrl && (
                        <div className="rounded-lg bg-black/40 border border-zinc-800 p-2.5 col-span-2">
                          <span className="text-zinc-500 text-[10px] block font-semibold mb-1">Source JavaScript Bundle:</span>
                          <span className="text-zinc-300 text-[11px] font-mono break-all">{diffContext.sourceJsUrl}</span>
                        </div>
                      )}

                      {diffContext?.sampleSourcesCount !== undefined && (
                        <div className="rounded-lg bg-black/40 border border-amber-500/30 p-2.5">
                          <span className="text-zinc-500 text-[10px] block">Exposed Source Files Count:</span>
                          <span className="text-amber-400 font-bold">{diffContext.sampleSourcesCount} files</span>
                        </div>
                      )}

                      {diffContext?.mapFileSizeBytes !== undefined && (
                        <div className="rounded-lg bg-black/40 border border-zinc-800 p-2.5">
                          <span className="text-zinc-500 text-[10px] block">Sourcemap File Size:</span>
                          <span className="text-zinc-300 font-bold font-mono">{(diffContext.mapFileSizeBytes / 1024).toFixed(1)} KB</span>
                        </div>
                      )}

                      {diffContext?.wpProbeKind && (
                        <div className="rounded-lg bg-black/40 border border-blue-500/30 p-2.5">
                          <span className="text-zinc-500 text-[10px] block">WordPress Surface Kind:</span>
                          <span className="text-blue-400 font-bold uppercase">{diffContext.wpProbeKind.replace('_', ' ')}</span>
                        </div>
                      )}

                      {diffContext?.multicallSupported !== undefined && (
                        <div className="rounded-lg bg-black/40 border border-rose-500/30 p-2.5">
                          <span className="text-zinc-500 text-[10px] block">system.multicall Amplification:</span>
                          <span className={`font-bold ${diffContext.multicallSupported ? 'text-rose-400' : 'text-zinc-400'}`}>
                            {diffContext.multicallSupported ? 'SUPPORTED (Amplification Risk)' : 'Not Present'}
                          </span>
                        </div>
                      )}

                      {diffContext?.xmlRpcMethodsExposed && diffContext.xmlRpcMethodsExposed.length > 0 && (
                        <div className="rounded-lg bg-black/40 border border-zinc-800 p-2.5 col-span-2">
                          <span className="text-zinc-500 text-[10px] block font-semibold mb-1">Exposed XML-RPC Methods ({diffContext.xmlRpcMethodsExposed.length}):</span>
                          <span className="text-zinc-300 text-[11px] font-mono break-all">{diffContext.xmlRpcMethodsExposed.join(', ')}</span>
                        </div>
                      )}

                      {diffContext?.exposedUsersCount !== undefined && (
                        <div className="rounded-lg bg-black/40 border border-amber-500/30 p-2.5">
                          <span className="text-zinc-500 text-[10px] block">Exposed Users Count:</span>
                          <span className="text-amber-400 font-bold">{diffContext.exposedUsersCount} users</span>
                        </div>
                      )}

                      {diffContext?.sampleUserSlugs && diffContext.sampleUserSlugs.length > 0 && (
                        <div className="rounded-lg bg-black/40 border border-rose-500/30 p-2.5 col-span-2">
                          <span className="text-rose-400 text-[10px] block font-semibold mb-1">Disclosed Author Usernames / Slugs:</span>
                          <span className="text-rose-300 text-[11px] font-mono break-all font-bold">{diffContext.sampleUserSlugs.join(', ')}</span>
                        </div>
                      )}

                      {diffContext?.databaseEngine && (
                        <div className="rounded-lg bg-black/40 border border-rose-500/30 p-2.5">
                          <span className="text-zinc-500 text-[10px] block">Disclosed Database Engine:</span>
                          <span className="text-rose-400 font-bold uppercase">{diffContext.databaseEngine}</span>
                        </div>
                      )}

                      {diffContext?.sqlErrorFragment && (
                        <div className="rounded-lg bg-black/40 border border-rose-500/30 p-2.5 col-span-2">
                          <span className="text-rose-400 text-[10px] block font-semibold mb-1">Sanitized Database Error Fragment:</span>
                          <pre className="text-rose-300 text-[11px] whitespace-pre-wrap break-all font-mono bg-black/60 p-2 rounded border border-zinc-900">
                            {diffContext.sqlErrorFragment}
                          </pre>
                        </div>
                      )}

                      {diffContext?.introspectionEnabled !== undefined && (
                        <div className="rounded-lg bg-black/40 border border-rose-500/30 p-2.5">
                          <span className="text-zinc-500 text-[10px] block">Schema Introspection:</span>
                          <span className={`font-bold ${diffContext.introspectionEnabled ? 'text-rose-400' : 'text-zinc-400'}`}>
                            {diffContext.introspectionEnabled ? 'ENABLED (Schema Exposed)' : 'Disabled'}
                          </span>
                        </div>
                      )}

                      {diffContext?.batchingEnabled !== undefined && (
                        <div className="rounded-lg bg-black/40 border border-amber-500/30 p-2.5">
                          <span className="text-zinc-500 text-[10px] block">Query Batching:</span>
                          <span className={`font-bold ${diffContext.batchingEnabled ? 'text-amber-400' : 'text-zinc-400'}`}>
                            {diffContext.batchingEnabled ? 'SUPPORTED (Amplification Risk)' : 'Not Supported'}
                          </span>
                        </div>
                      )}

                      {diffContext?.fieldSuggestionsEnabled !== undefined && (
                        <div className="rounded-lg bg-black/40 border border-purple-500/30 p-2.5">
                          <span className="text-zinc-500 text-[10px] block">Field Suggestions:</span>
                          <span className={`font-bold ${diffContext.fieldSuggestionsEnabled ? 'text-purple-300' : 'text-zinc-400'}`}>
                            {diffContext.fieldSuggestionsEnabled ? 'LEAKING (Field Autocomplete)' : 'Disabled'}
                          </span>
                        </div>
                      )}

                      {diffContext?.discoveredRootTypes && diffContext.discoveredRootTypes.length > 0 && (
                        <div className="rounded-lg bg-black/40 border border-zinc-800 p-2.5 col-span-2">
                          <span className="text-zinc-500 text-[10px] block font-semibold mb-1">Exposed Root Types ({diffContext.discoveredRootTypes.length}):</span>
                          <span className="text-zinc-300 text-[11px] font-mono break-all">{diffContext.discoveredRootTypes.join(', ')}</span>
                        </div>
                      )}

                      {diffContext?.suggestionLeak && (
                        <div className="rounded-lg bg-black/40 border border-purple-500/30 p-2.5 col-span-2">
                          <span className="text-purple-400 text-[10px] block font-semibold mb-1">Field Suggestion Leak Excerpt:</span>
                          <pre className="text-purple-200 text-[11px] whitespace-pre-wrap break-all font-mono bg-black/60 p-2 rounded border border-zinc-900">
                            {diffContext.suggestionLeak}
                          </pre>
                        </div>
                      )}

                      {diffContext?.originalAlgorithm && (
                        <div className="rounded-lg bg-black/40 border border-zinc-800 p-2.5">
                          <span className="text-zinc-500 text-[10px] block">Original JWT Algorithm:</span>
                          <span className="text-zinc-300 font-bold font-mono uppercase">{diffContext.originalAlgorithm}</span>
                        </div>
                      )}

                      {diffContext?.manipulatedAlgorithm && (
                        <div className="rounded-lg bg-black/40 border border-rose-500/30 p-2.5">
                          <span className="text-zinc-500 text-[10px] block">Manipulated Algorithm (Bypass):</span>
                          <span className="text-rose-400 font-bold font-mono uppercase">{diffContext.manipulatedAlgorithm} (Unsigned)</span>
                        </div>
                      )}

                      {diffContext?.jwtProbeMechanism && (
                        <div className="rounded-lg bg-black/40 border border-rose-500/30 p-2.5 col-span-2">
                          <span className="text-zinc-500 text-[10px] block">JWT Probe Mechanism:</span>
                          <span className="text-rose-300 font-mono text-[11px]">{diffContext.jwtProbeMechanism.replace('_', ' ').toUpperCase()}</span>
                        </div>
                      )}

                      {diffContext?.sessionCookieName && (
                        <div className="rounded-lg bg-black/40 border border-zinc-800 p-2.5">
                          <span className="text-zinc-500 text-[10px] block">Session Cookie Tested:</span>
                          <span className="text-zinc-300 font-bold font-mono">{diffContext.sessionCookieName}</span>
                        </div>
                      )}

                      {diffContext?.fixedSessionId && (
                        <div className="rounded-lg bg-black/40 border border-rose-500/30 p-2.5">
                          <span className="text-zinc-500 text-[10px] block">Fixed Identifier Excerpt:</span>
                          <span className="text-rose-300 font-mono text-[11px] break-all">{diffContext.fixedSessionId}</span>
                        </div>
                      )}

                      {diffContext?.serverRegeneratedSession !== undefined && (
                        <div className="rounded-lg bg-black/40 border border-rose-500/30 p-2.5 col-span-2">
                          <span className="text-zinc-500 text-[10px] block">Session Regeneration:</span>
                          <span className={`font-bold ${diffContext.serverRegeneratedSession ? 'text-emerald-400' : 'text-rose-400'}`}>
                            {diffContext.serverRegeneratedSession ? 'REGENERATED (Set-Cookie Issued)' : 'NOT REGENERATED (Caller-Supplied Cookie Accepted)'}
                          </span>
                        </div>
                      )}

                      {diffContext?.suppliedOrigin && (
                        <div className="rounded-lg bg-black/40 border border-zinc-800 p-2.5">
                          <span className="text-zinc-500 text-[10px] block">Supplied Untrusted Origin:</span>
                          <span className="text-blue-400 font-bold font-mono text-[11px] break-all">{diffContext.suppliedOrigin}</span>
                        </div>
                      )}

                      {diffContext?.allowCredentialsHeader !== undefined && (
                        <div className="rounded-lg bg-black/40 border border-rose-500/30 p-2.5">
                          <span className="text-zinc-500 text-[10px] block">Allow-Credentials Header (ACAC):</span>
                          <span className={`font-bold ${diffContext.allowCredentialsHeader ? 'text-rose-400' : 'text-zinc-400'}`}>
                            {diffContext.allowCredentialsHeader ? 'TRUE (Credentialed)' : 'FALSE / Missing'}
                          </span>
                        </div>
                      )}

                      {diffContext?.acaoHeader && (
                        <div className="rounded-lg bg-black/40 border border-rose-500/30 p-2.5 col-span-2">
                          <span className="text-zinc-500 text-[10px] block">Reflected Access-Control-Allow-Origin:</span>
                          <span className="text-rose-300 font-mono text-[11px] break-all font-bold">{diffContext.acaoHeader}</span>
                        </div>
                      )}

                      {diffContext?.pluginSlug && (
                        <div className="rounded-lg bg-black/40 border border-amber-500/30 p-2.5">
                          <span className="text-zinc-500 text-[10px] block">CMS Plugin Target:</span>
                          <span className="text-amber-400 font-bold font-mono text-[11px] uppercase">
                            {diffContext.cmsType ?? 'WordPress'}: {diffContext.pluginSlug}
                          </span>
                        </div>
                      )}

                      {diffContext?.detectedVersion && (
                        <div className="rounded-lg bg-black/40 border border-rose-500/30 p-2.5">
                          <span className="text-zinc-500 text-[10px] block">Detected Plugin Version:</span>
                          <span className="text-rose-400 font-bold font-mono text-[11px]">
                            v{diffContext.detectedVersion}
                          </span>
                        </div>
                      )}

                      {diffContext?.minimumSafeVersion && (
                        <div className="rounded-lg bg-black/40 border border-emerald-500/30 p-2.5">
                          <span className="text-zinc-500 text-[10px] block">Minimum Safe Baseline:</span>
                          <span className="text-emerald-400 font-bold font-mono text-[11px]">
                            v{diffContext.minimumSafeVersion}
                          </span>
                        </div>
                      )}

                      {diffContext?.isOutdated !== undefined && (
                        <div className="rounded-lg bg-black/40 border border-rose-500/30 p-2.5">
                          <span className="text-zinc-500 text-[10px] block">Version Status:</span>
                          <span className={`font-bold ${diffContext.isOutdated ? 'text-rose-400' : 'text-emerald-400'}`}>
                            {diffContext.isOutdated ? 'OUTDATED (Vulnerable Surface)' : 'CURRENT / SAFE'}
                          </span>
                        </div>
                      )}

                      {diffContext?.chainKind && (
                        <div className="rounded-lg bg-black/40 border border-rose-500/40 p-2.5 col-span-2">
                          <span className="text-rose-400 text-[10px] block font-bold uppercase tracking-wider mb-1">
                            Exploit Chain: {diffContext.chainKind.replace(/_/g, ' ').toUpperCase()}
                          </span>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px] font-mono mt-2">
                            {diffContext.primaryFindingId && (
                              <div className="rounded bg-black/60 p-2 border border-zinc-800">
                                <span className="text-zinc-500 text-[10px] block">Primary Finding (CORS Vector):</span>
                                <span className="text-amber-400 font-bold">{diffContext.primaryFindingId}</span>
                              </div>
                            )}
                            {diffContext.secondaryFindingId && (
                              <div className="rounded bg-black/60 p-2 border border-zinc-800">
                                <span className="text-zinc-500 text-[10px] block">Secondary Finding (IDOR Exfiltration):</span>
                                <span className="text-rose-400 font-bold">{diffContext.secondaryFindingId}</span>
                              </div>
                            )}
                            {diffContext.sharedOrigin && (
                              <div className="rounded bg-black/60 p-2 border border-zinc-800">
                                <span className="text-zinc-500 text-[10px] block">Matching Target Origin:</span>
                                <span className="text-blue-400">{diffContext.sharedOrigin}</span>
                              </div>
                            )}
                            {diffContext.compoundImpactScore !== undefined && (
                              <div className="rounded bg-black/60 p-2 border border-rose-500/30">
                                <span className="text-zinc-500 text-[10px] block">Compound Impact Score:</span>
                                <span className="text-rose-400 font-bold">{diffContext.compoundImpactScore.toFixed(2)} (CRITICAL)</span>
                              </div>
                            )}
                          </div>
                        </div>
                      )}

                      {diffContext?.detectionKind === 'api_versioning_sprawl' && (
                        <div className="rounded-lg bg-black/40 border border-amber-500/40 p-2.5 col-span-2">
                          <span className="text-amber-400 text-[10px] block font-bold uppercase tracking-wider mb-1">
                            API Versioning Sprawl &amp; Shadow Endpoint Exposure
                          </span>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px] font-mono mt-2">
                            {diffContext.currentEndpointUrl && (
                              <div className="rounded bg-black/60 p-2 border border-zinc-800">
                                <span className="text-zinc-500 text-[10px] block">Current Version Endpoint:</span>
                                <span className="text-blue-400 break-all">{diffContext.currentEndpointUrl}</span>
                                <span className="text-zinc-400 text-[10px] block mt-0.5">HTTP Status: {diffContext.currentStatusCode ?? 'Auth Required'}</span>
                              </div>
                            )}
                            {diffContext.legacyEndpointUrl && (
                              <div className="rounded bg-black/60 p-2 border border-zinc-800">
                                <span className="text-zinc-500 text-[10px] block">Legacy Version Endpoint:</span>
                                <span className="text-rose-400 font-bold break-all">{diffContext.legacyEndpointUrl}</span>
                                <span className="text-zinc-400 text-[10px] block mt-0.5">HTTP Status: {diffContext.legacyStatusCode ?? 200} OK</span>
                              </div>
                            )}
                            {diffContext.detectedVersions && diffContext.detectedVersions.length > 0 && (
                              <div className="rounded bg-black/60 p-2 border border-zinc-800">
                                <span className="text-zinc-500 text-[10px] block">Detected Version Tags:</span>
                                <span className="text-amber-300 font-bold">{diffContext.detectedVersions.join(' vs ')}</span>
                              </div>
                            )}
                            {diffContext.unauthenticatedExposure !== undefined && (
                              <div className="rounded bg-black/60 p-2 border border-rose-500/30">
                                <span className="text-zinc-500 text-[10px] block">Exposure Classification:</span>
                                <span className={`font-bold ${diffContext.unauthenticatedExposure ? 'text-rose-400' : 'text-amber-400'}`}>
                                  {diffContext.unauthenticatedExposure ? 'CRITICAL: Unauthenticated Data Leak' : 'LOW: Deprecated Endpoint Accessible'}
                                </span>
                              </div>
                            )}
                          </div>
                        </div>
                      )}

                      {diffContext?.detectionKind === 'http_method_manipulation' && (
                        <div className="rounded-lg bg-black/40 border border-purple-500/40 p-2.5 col-span-2">
                          <span className="text-purple-400 text-[10px] block font-bold uppercase tracking-wider mb-1">
                            HTTP Method Manipulation &amp; Verb Tampering
                          </span>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px] font-mono mt-2">
                            {diffContext.baselineMethod && (
                              <div className="rounded bg-black/60 p-2 border border-zinc-800">
                                <span className="text-zinc-500 text-[10px] block">Baseline Method &amp; Action:</span>
                                <span className="text-zinc-300 font-bold">{diffContext.baselineMethod} ({diffContext.targetOperation ?? 'action'})</span>
                                <span className="text-zinc-400 text-[10px] block mt-0.5">Baseline Status: HTTP {diffContext.baselineStatusCode ?? 403}</span>
                              </div>
                            )}
                            {diffContext.bypassMethodOrHeader && (
                              <div className="rounded bg-black/60 p-2 border border-zinc-800">
                                <span className="text-zinc-500 text-[10px] block">Bypass Technique &amp; Override:</span>
                                <span className="text-purple-400 font-bold break-all">{diffContext.bypassMethodOrHeader}</span>
                                <span className="text-emerald-400 text-[10px] block mt-0.5">Manipulated Status: HTTP {diffContext.manipulatedStatusCode ?? 200} OK</span>
                              </div>
                            )}
                            {diffContext.bypassType && (
                              <div className="rounded bg-black/60 p-2 border border-zinc-800">
                                <span className="text-zinc-500 text-[10px] block">Tampering Mechanism:</span>
                                <span className="text-amber-300 font-bold uppercase">{diffContext.bypassType.replace(/_/g, ' ')}</span>
                              </div>
                            )}
                            {diffContext.endpointUrl && (
                              <div className="rounded bg-black/60 p-2 border border-purple-500/30">
                                <span className="text-zinc-500 text-[10px] block">Target Endpoint:</span>
                                <span className="text-purple-300 font-mono break-all">{diffContext.endpointUrl}</span>
                              </div>
                            )}
                          </div>
                        </div>
                      )}

                      {diffContext?.detectionKind === 'dependency_confusion' && (
                        <div className="rounded-lg bg-black/40 border border-red-500/40 p-2.5 col-span-2">
                          <span className="text-red-400 text-[10px] block font-bold uppercase tracking-wider mb-1">
                            Dependency Confusion &amp; Unclaimed Package Supply Chain Risk
                          </span>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px] font-mono mt-2">
                            {diffContext.packageName && (
                              <div className="rounded bg-black/60 p-2 border border-zinc-800">
                                <span className="text-zinc-500 text-[10px] block">Internal Package Name:</span>
                                <span className="text-red-400 font-bold break-all">{diffContext.packageName}</span>
                                {diffContext.detectedVersion && (
                                  <span className="text-zinc-400 text-[10px] block mt-0.5">Declared Version: {diffContext.detectedVersion}</span>
                                )}
                              </div>
                            )}
                            {diffContext.publicRegistryUrl && (
                              <div className="rounded bg-black/60 p-2 border border-zinc-800">
                                <span className="text-zinc-500 text-[10px] block">Public Registry Check:</span>
                                <span className="text-blue-400 break-all">{diffContext.publicRegistryUrl}</span>
                                <span className="text-rose-400 text-[10px] block mt-0.5 font-bold">
                                  Status: HTTP {diffContext.registryStatusCode ?? 404} (Unclaimed / Not Found)
                                </span>
                              </div>
                            )}
                            {diffContext.sourceManifestUrl && (
                              <div className="rounded bg-black/60 p-2 border border-zinc-800">
                                <span className="text-zinc-500 text-[10px] block">Exposed Source Manifest:</span>
                                <span className="text-zinc-300 font-mono break-all">{diffContext.sourceManifestUrl}</span>
                              </div>
                            )}
                            {diffContext.isUnclaimedPublicly !== undefined && (
                              <div className="rounded bg-black/60 p-2 border border-red-500/30">
                                <span className="text-zinc-500 text-[10px] block">Namespace Registration:</span>
                                <span className={`font-bold ${diffContext.isUnclaimedPublicly ? 'text-red-400' : 'text-emerald-400'}`}>
                                  {diffContext.isUnclaimedPublicly ? 'CRITICAL: Unclaimed Public Namespace (Substitution Risk)' : 'CLAIMED: Registered in Public Registry'}
                                </span>
                              </div>
                            )}
                          </div>
                        </div>
                      )}

                      {diffContext?.detectionKind === 'manifest_exposure' && (
                        <div className="rounded-lg bg-black/40 border border-amber-500/40 p-2.5 col-span-2">
                          <span className="text-amber-400 text-[10px] block font-bold uppercase tracking-wider mb-1">
                            Frontend Manifest &amp; Environment Exposure
                          </span>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px] font-mono mt-2">
                            {diffContext.exposedFilePath && (
                              <div className="rounded bg-black/60 p-2 border border-zinc-800">
                                <span className="text-zinc-500 text-[10px] block">Exposed File Path:</span>
                                <span className="text-amber-300 font-bold break-all">{diffContext.exposedFilePath}</span>
                                {diffContext.fileKind && (
                                  <span className="text-zinc-400 text-[10px] block mt-0.5 uppercase">Kind: {diffContext.fileKind.replace(/_/g, ' ')}</span>
                                )}
                              </div>
                            )}
                            {diffContext.exposureSeverity && (
                              <div className="rounded bg-black/60 p-2 border border-zinc-800">
                                <span className="text-zinc-500 text-[10px] block">Exposure Severity:</span>
                                <span className={`font-bold uppercase ${diffContext.exposureSeverity === 'critical' ? 'text-rose-400' : 'text-amber-400'}`}>
                                  {diffContext.exposureSeverity}
                                </span>
                              </div>
                            )}
                            {diffContext.endpointUrl && (
                              <div className="rounded bg-black/60 p-2 border border-zinc-800 col-span-2">
                                <span className="text-zinc-500 text-[10px] block">Endpoint URL:</span>
                                <span className="text-blue-400 font-mono break-all">{diffContext.endpointUrl}</span>
                              </div>
                            )}
                            {diffContext.sanitizedSnippet && (
                              <div className="rounded bg-black/60 p-2 border border-amber-500/30 col-span-2">
                                <span className="text-zinc-500 text-[10px] block">Sanitized File Excerpt (Credentials Redacted):</span>
                                <span className="text-zinc-300 font-mono text-[10px] break-all block mt-0.5">{diffContext.sanitizedSnippet}</span>
                              </div>
                            )}
                          </div>
                        </div>
                      )}
                    </div>


                    <div className="rounded bg-black/40 p-3 border border-zinc-800 text-xs text-zinc-300 font-mono leading-relaxed">
                      <strong className="text-zinc-500 block text-[10px] uppercase mb-1">Fundamento del Borrador:</strong>
                      {selectedDraft.safeRationale}
                    </div>
                  </div>
                </div>

                {/* Operator Notes & Triage Actions */}
                <div className="border-t border-zinc-800/80 pt-5 space-y-4">
                  <div>
                    <label className="text-[11px] font-mono text-zinc-400 uppercase tracking-wider block mb-1.5">
                      Notas del Operador (Opcional)
                    </label>
                    <textarea
                      value={notes}
                      onChange={(e) => setNotes(e.target.value)}
                      placeholder="Observaciones adicionales, contexto de la aplicación, o justificación de triage..."
                      rows={2}
                      className="w-full rounded-xl border border-zinc-800 bg-zinc-900/60 px-3.5 py-2 text-xs font-mono text-white placeholder:text-zinc-600 focus:border-amber-500/50 focus:outline-none focus:ring-1 focus:ring-amber-500/50"
                    />
                  </div>

                  <div className="flex flex-wrap items-center justify-between gap-4 pt-2">
                    <div className="text-[11px] font-mono text-zinc-500">
                      Operador: <strong className="text-zinc-300">{operatorId || "N/A"}</strong>
                    </div>

                    <div className="flex items-center gap-3">
                      <button
                        type="button"
                        onClick={() => handleReviewAction("reject_evidence")}
                        disabled={isSubmitting}
                        className="rounded-xl border border-zinc-800 bg-zinc-900 hover:bg-rose-950/40 hover:border-rose-500/50 hover:text-rose-300 px-4 py-2.5 text-xs font-mono font-medium text-zinc-300 transition cursor-pointer disabled:opacity-50 flex items-center gap-2"
                      >
                        <XCircle className="h-4 w-4 text-rose-400" />
                        Rechazar Evidencia
                      </button>

                      <button
                        type="button"
                        onClick={() => handleReviewAction("approve_evidence")}
                        disabled={isSubmitting}
                        className="rounded-xl border border-emerald-500/50 bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 px-5 py-2.5 text-xs font-mono font-bold transition cursor-pointer disabled:opacity-50 shadow-lg flex items-center gap-2"
                      >
                        <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                        Aprobar y Promover a Hallazgo
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <div className="rounded-2xl border border-zinc-800 bg-zinc-950/60 p-12 text-center space-y-3">
                <FileSearch className="mx-auto h-10 w-10 text-zinc-600" />
                <div className="text-sm font-semibold text-white">Seleccione un Borrador de Evidencia</div>
                <p className="text-xs text-zinc-400 max-w-md mx-auto">
                  Seleccione un elemento de la cola de la izquierda para inspeccionar las diferencias de respuesta HTTP y tomar una decisión de autorización.
                </p>
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}

export default function HumanReviewPage() {
  return (
    <Suspense fallback={<div className="min-h-screen bg-black text-zinc-400 p-8 font-mono text-xs">Cargando interfaz de revisión...</div>}>
      <HumanReviewContent />
    </Suspense>
  );
}
