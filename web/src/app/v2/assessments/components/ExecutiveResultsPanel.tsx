"use client";

import React, { useState } from "react";
import Link from "next/link";
import {
  ShieldAlert,
  ShieldCheck,
  Cpu,
  Layers,
  FileCode,
  Sparkles,
  Lock,
  ArrowUpRight,
  Fingerprint,
  Info,
  CheckCircle2,
  AlertTriangle,
  Scale,
  FileText,
  Download,
  X,
  Loader2
} from "lucide-react";
import {
  type OrchestratedAssessmentSummaryResponse,
  type FindingDto,
  type RecommendationDto,
  type ProfileEndpointDto,
  generateHtmlReport
} from "@/lib/v2Api";

interface ExecutiveResultsPanelProps {
  summary: OrchestratedAssessmentSummaryResponse | null;
}

export function ExecutiveResultsPanel({ summary }: ExecutiveResultsPanelProps) {
  const [activeTab, setActiveTab] = useState<"profile" | "findings" | "recommendations">("profile");
  const [isReportModalOpen, setIsReportModalOpen] = useState(false);
  const [operatorId, setOperatorId] = useState("operator_lead");
  const [attestationText, setAttestationText] = useState("");
  const [isGenerating, setIsGenerating] = useState(false);
  const [reportError, setReportError] = useState<string | null>(null);

  const handleDownloadReport = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!summary) return;
    if (attestationText.trim().length < 10) {
      setReportError("La declaración de atestación debe tener al menos 10 caracteres.");
      return;
    }

    try {
      setIsGenerating(true);
      setReportError(null);
      const htmlContent = await generateHtmlReport(summary.assessmentId, {
        operatorId: operatorId.trim() || "operator_lead",
        attestationText: attestationText.trim()
      });

      const blob = new Blob([htmlContent], { type: "text/html;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `FixGuard_Defensive_Report_${summary.assessmentId}.html`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);

      setIsReportModalOpen(false);
      setAttestationText("");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Error al generar informe defensivo";
      setReportError(msg);
    } finally {
      setIsGenerating(false);
    }
  };

  if (!summary) return null;

  const profile = summary.profile;
  const findings = summary.findings || [];
  const recommendations = summary.recommendations || [];
  const pendingDrafts = summary.pendingEvidenceDrafts || [];

  return (
    <div className="rounded-2xl border border-zinc-800 bg-zinc-950/80 p-6 shadow-2xl backdrop-blur-xl space-y-6">
      {/* Top Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-zinc-800/80 pb-5">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-purple-500/30 bg-purple-500/10 text-purple-400">
            <Sparkles className="h-5 w-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold text-white tracking-wide">
                Executive Assessment Results
              </h3>
              <span className="rounded bg-purple-500/10 border border-purple-500/30 px-2 py-0.5 text-[10px] font-mono font-medium text-purple-400">
                F5 Intelligence Synthesized
              </span>
            </div>
            <p className="text-xs text-zinc-400 mt-0.5">
              Factual target profile, verified detection findings, and advisory recommendations
            </p>
          </div>
        </div>

        {/* Tab Switcher & Triage Link */}
        <div className="flex flex-wrap items-center gap-2">
          {pendingDrafts.length > 0 && (
            <Link
              href={`/v2/review?assessmentId=${encodeURIComponent(summary.assessmentId)}`}
              className="rounded-xl border border-amber-500/40 bg-amber-500/10 hover:bg-amber-500/20 px-3 py-1.5 text-xs font-mono text-amber-300 font-bold flex items-center gap-1.5 transition"
            >
              <Scale className="h-3.5 w-3.5 text-amber-400" />
              Revisión HITL ({pendingDrafts.length}) &rarr;
            </Link>
          )}

          <button
            type="button"
            onClick={() => setIsReportModalOpen(true)}
            className="rounded-xl border border-emerald-500/40 bg-emerald-500/10 hover:bg-emerald-500/20 px-3 py-1.5 text-xs font-mono text-emerald-300 font-semibold flex items-center gap-1.5 transition cursor-pointer"
          >
            <FileText className="h-3.5 w-3.5 text-emerald-400" />
            Generar Informe Defensivo (HTML)
          </button>

          <div className="flex items-center gap-1 rounded-xl border border-zinc-800 bg-zinc-900/60 p-1 text-xs font-mono">
            <button
              type="button"
              onClick={() => setActiveTab("profile")}
              className={`rounded-lg px-3 py-1.5 transition cursor-pointer ${
                activeTab === "profile"
                  ? "bg-purple-500/20 text-purple-300 font-semibold border border-purple-500/40"
                  : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              Target Profile ({profile?.endpoints.length || 0} routes)
            </button>
            <button
              type="button"
              onClick={() => setActiveTab("findings")}
              className={`rounded-lg px-3 py-1.5 transition cursor-pointer flex items-center gap-1.5 ${
                activeTab === "findings"
                  ? "bg-rose-500/20 text-rose-300 font-semibold border border-rose-500/40"
                  : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              Findings
              <span className={`rounded px-1.5 py-0.2 text-[10px] ${findings.length > 0 ? "bg-rose-500 text-black font-bold" : "bg-zinc-800 text-zinc-500"}`}>
                {findings.length}
              </span>
            </button>
            <button
              type="button"
              onClick={() => setActiveTab("recommendations")}
              className={`rounded-lg px-3 py-1.5 transition cursor-pointer flex items-center gap-1.5 ${
                activeTab === "recommendations"
                  ? "bg-blue-500/20 text-blue-300 font-semibold border border-blue-500/40"
                  : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              Advisory Recommendations
              <span className={`rounded px-1.5 py-0.2 text-[10px] ${recommendations.length > 0 ? "bg-blue-500 text-black font-bold" : "bg-zinc-800 text-zinc-500"}`}>
                {recommendations.length}
              </span>
            </button>
          </div>
        </div>
      </div>


      {/* Tab 1: Target Profile */}
      {activeTab === "profile" && profile && (
        <div className="space-y-6">
          {/* Target Metadata & Technologies */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="rounded-xl border border-zinc-900 bg-zinc-900/40 p-4 space-y-2 md:col-span-2">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono text-zinc-500 uppercase tracking-wider block">
                  Discovered Technologies &amp; Edge Infrastructure
                </span>
                {profile.ecosystemProfile && (
                  <div className="flex flex-wrap gap-1.5 text-[10px] font-mono">
                    {profile.ecosystemProfile.hasSpa && (
                      <span className="rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 px-1.5 py-0.5">
                        SPA ({profile.ecosystemProfile.spaFramework ?? 'SPA'})
                      </span>
                    )}
                    {profile.ecosystemProfile.hasCms && (
                      <span className="rounded bg-amber-500/10 border border-amber-500/30 text-amber-300 px-1.5 py-0.5">
                        CMS ({profile.ecosystemProfile.cmsType ?? 'CMS'})
                      </span>
                    )}
                    {profile.ecosystemProfile.hasGraphQL && (
                      <span className="rounded bg-pink-500/10 border border-pink-500/30 text-pink-300 px-1.5 py-0.5">
                        GraphQL
                      </span>
                    )}
                    {profile.ecosystemProfile.hasPhpLegacy && (
                      <span className="rounded bg-rose-500/10 border border-rose-500/30 text-rose-300 px-1.5 py-0.5">
                        Legacy PHP
                      </span>
                    )}
                    {profile.ecosystemProfile.hasExposedSourcemaps && (
                      <span className="rounded bg-amber-500/10 border border-amber-500/30 text-amber-300 px-1.5 py-0.5">
                        Sourcemaps
                      </span>
                    )}
                  </div>
                )}
              </div>

              <div className="flex flex-wrap items-center gap-2 pt-1">
                {profile.detectedTechnologies && profile.detectedTechnologies.length > 0 ? (
                  profile.detectedTechnologies.map((tech) => (
                    <span
                      key={`${tech.name}-${tech.version ?? 'any'}`}
                      className="rounded-lg border border-purple-500/30 bg-purple-500/10 px-2.5 py-1 text-xs font-mono font-medium text-purple-300 flex items-center gap-1.5"
                      title={tech.detectionSignal}
                    >
                      <span>{tech.name}</span>
                      {tech.version && (
                        <span className="rounded bg-purple-950 border border-purple-500/40 px-1 py-0.2 text-[10px] text-purple-200 font-bold">
                          v{tech.version}
                        </span>
                      )}
                    </span>
                  ))
                ) : profile.technologies.length > 0 ? (
                  profile.technologies.map((tech) => (
                    <span
                      key={tech}
                      className="rounded-lg border border-purple-500/30 bg-purple-500/10 px-2.5 py-1 text-xs font-mono font-medium text-purple-300"
                    >
                      {tech}
                    </span>
                  ))
                ) : (
                  <span className="text-xs text-zinc-500 font-mono">Standard HTTP Stack</span>
                )}
              </div>
            </div>

            <div className="rounded-xl border border-zinc-900 bg-zinc-900/40 p-4 space-y-1">
              <span className="text-[11px] font-mono text-zinc-500 uppercase tracking-wider block">
                Target Host &amp; Origin
              </span>
              <div className="text-xs font-mono text-white font-semibold pt-1">
                {profile.targetHost}
              </div>
              <div className="text-[11px] font-mono text-zinc-400 truncate">
                {profile.normalizedOrigin}
              </div>
            </div>
          </div>

          {/* Endpoints Table */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-mono uppercase tracking-wider text-zinc-400">
                Indexed Surface Endpoints ({profile.endpoints.length})
              </h4>
              <span className="text-[11px] font-mono text-zinc-500">
                Discovered via Httpx, Katana &amp; Arjun
              </span>
            </div>

            {profile.endpoints.length === 0 ? (
              <div className="rounded-xl border border-zinc-900 bg-zinc-900/20 p-6 text-center text-xs text-zinc-500 font-mono">
                No active endpoints indexed during this assessment run.
              </div>
            ) : (
              <div className="overflow-x-auto rounded-xl border border-zinc-900">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="border-b border-zinc-800 bg-zinc-900/60 text-zinc-400">
                    <tr>
                      <th className="py-2.5 px-3">Method</th>
                      <th className="py-2.5 px-3">Path</th>
                      <th className="py-2.5 px-3">Auth Requirement</th>
                      <th className="py-2.5 px-3">Parameters</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-900 bg-zinc-950/40">
                    {profile.endpoints.map((ep, idx) => (
                      <tr key={`${ep.method}-${ep.path}-${idx}`} className="hover:bg-zinc-900/30 transition">
                        <td className="py-2 px-3">
                          <span className={`rounded px-1.5 py-0.5 text-[10px] font-bold ${
                            ep.method === "GET"
                              ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
                              : ep.method === "POST"
                              ? "bg-blue-500/10 text-blue-400 border border-blue-500/30"
                              : "bg-zinc-800 text-zinc-400"
                          }`}>
                            {ep.method}
                          </span>
                        </td>
                        <td className="py-2 px-3 text-zinc-200 font-medium">{ep.path}</td>
                        <td className="py-2 px-3 text-zinc-400">
                          <span className="capitalize">{ep.authRequirement}</span>
                        </td>
                        <td className="py-2 px-3">
                          {ep.parameters && ep.parameters.length > 0 ? (
                            <div className="flex flex-wrap gap-1">
                              {ep.parameters.map((p) => (
                                <span key={p} className="rounded bg-zinc-900 border border-zinc-800 px-1.5 py-0.2 text-[10px] text-zinc-400">
                                  {p}
                                </span>
                              ))}
                            </div>
                          ) : (
                            <span className="text-zinc-600">—</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab 2: Findings */}
      {activeTab === "findings" && (
        <div className="space-y-4">
          {findings.length === 0 ? (
            <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-6 text-center space-y-2">
              <ShieldCheck className="mx-auto h-8 w-8 text-emerald-400" />
              <div className="text-sm font-semibold text-white">Clean Target Abstention</div>
              <p className="text-xs text-zinc-400 max-w-lg mx-auto">
                No exploitable vulnerabilities (CORS origin reflection, unescaped parameter reflection, or IDOR)
                were observed. FixGuard strictly records honest abstention without hallucinating findings.
              </p>
              <div className="flex items-center justify-center gap-2 pt-2 text-[11px] font-mono text-emerald-400">
                <span className="rounded border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1">
                  CORS: Policy Enforced
                </span>
                <span className="rounded border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1">
                  Parameters: Sanitized
                </span>
              </div>
            </div>
          ) : (
            <div className="space-y-3">
              {findings.map((f) => (
                <div
                  key={f.id}
                  className="rounded-xl border border-rose-500/30 bg-rose-500/5 p-4 space-y-2"
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="rounded bg-rose-500 text-black px-2 py-0.5 text-[10px] font-bold uppercase font-mono">
                        {f.severity}
                      </span>
                      <h4 className="text-xs font-semibold text-white">{f.title}</h4>
                    </div>
                    <span className="text-[11px] font-mono text-zinc-500">{f.type}</span>
                  </div>
                  <div className="text-xs text-zinc-400 font-mono">Target: {f.target}</div>
                  <div className="rounded bg-black/60 p-2.5 border border-zinc-900 font-mono text-[11px] text-zinc-300 overflow-x-auto">
                    {f.evidence}
                  </div>
                  <div className="flex items-center justify-between text-[10px] font-mono text-zinc-500 pt-1">
                    <span>Evidence Hash: {f.hash}</span>
                    <span>Line: {f.line}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Tab 3: Advisory Recommendations */}
      {activeTab === "recommendations" && (
        <div className="space-y-4">
          <div className="rounded-xl border border-blue-500/20 bg-blue-500/5 p-4 flex items-start gap-3 text-xs text-blue-300">
            <Info className="h-4 w-4 shrink-0 text-blue-400 mt-0.5" />
            <div className="space-y-0.5">
              <span className="font-semibold block">Human Review Boundary (HITL)</span>
              <p className="text-zinc-400 leading-relaxed">
                FixGuard operates under strict defensive governance. Recommendations are non-executable advisory
                proposals derived from target observations and require operator authorization before capability dispatch.
              </p>
            </div>
          </div>

          {recommendations.length === 0 ? (
            <div className="rounded-xl border border-zinc-900 bg-zinc-900/20 p-6 text-center text-xs text-zinc-500 font-mono">
              <CheckCircle2 className="mx-auto h-7 w-7 text-zinc-600 mb-2 opacity-50" />
              <span>Clean Profile: 0 speculative recommendations generated. (Abstention discipline enforced)</span>
            </div>
          ) : (
            <div className="space-y-3">
              {recommendations.map((rec) => (
                <div
                  key={rec.id}
                  className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-4 space-y-3"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="rounded bg-blue-500/10 border border-blue-500/30 text-blue-400 px-2 py-0.5 text-[10px] font-mono uppercase font-semibold">
                        {rec.category.replace(/_/g, " ")}
                      </span>
                      <h4 className="text-xs font-semibold text-white">{rec.title}</h4>
                    </div>
                    <span className="text-[11px] font-mono text-emerald-400">
                      Confidence: {Math.round(rec.confidence * 100)}%
                    </span>
                  </div>

                  <p className="text-xs text-zinc-300 leading-relaxed">{rec.reasoning}</p>

                  <div className="flex flex-wrap items-center justify-between gap-2 border-t border-zinc-800/60 pt-3 text-[11px] font-mono text-zinc-400">
                    <div>
                      Suggested Capability:{" "}
                      <strong className="text-zinc-200">{rec.suggestedCapability}</strong>
                    </div>
                    <div className="flex items-center gap-1">
                      <span>Permissions Required:</span>
                      {rec.requiredPermissions.map((perm) => (
                        <span
                          key={perm}
                          className="rounded bg-zinc-800 border border-zinc-700 px-1.5 py-0.2 text-[10px] text-zinc-300"
                        >
                          {perm}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Operator Attestation & HTML Report Modal */}
      {isReportModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="relative w-full max-w-lg rounded-2xl border border-zinc-700 bg-zinc-900 p-6 shadow-2xl space-y-5">
            {/* Modal Header */}
            <div className="flex items-center justify-between border-b border-zinc-800 pb-4">
              <div className="flex items-center gap-2.5">
                <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-emerald-500/30 bg-emerald-500/10 text-emerald-400">
                  <FileText className="h-4 w-4" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-white">
                    Generar Informe Defensivo (HTML)
                  </h3>
                  <p className="text-[11px] font-mono text-zinc-400">
                    Artefacto auditable con atestación de operador
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setIsReportModalOpen(false)}
                className="rounded-lg p-1.5 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200 transition cursor-pointer"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {/* Defensive Notice */}
            <div className="rounded-xl border border-zinc-800 bg-zinc-950/60 p-3 space-y-1.5 text-[11px] font-mono text-zinc-300">
              <div className="flex items-center gap-1.5 text-amber-400 font-semibold">
                <AlertTriangle className="h-3.5 w-3.5" />
                <span>Requisitos de Integridad y Atestación</span>
              </div>
              <p className="text-zinc-400 text-[10px] leading-relaxed">
                El informe exportado incluirá únicamente los hallazgos confirmados mediante revisión humana (HITL),
                las limitaciones obligatorias de la auditoría y la cadena de linaje inmutable.
              </p>
            </div>

            {/* Attestation Form */}
            <form onSubmit={handleDownloadReport} className="space-y-4">
              <div className="space-y-1.5">
                <label className="text-xs font-mono text-zinc-300 block">
                  Identificador del Operador (Operator ID)
                </label>
                <input
                  type="text"
                  value={operatorId}
                  onChange={(e) => setOperatorId(e.target.value)}
                  placeholder="operator_lead"
                  required
                  className="w-full rounded-xl border border-zinc-700 bg-zinc-950 px-3 py-2 text-xs font-mono text-zinc-100 placeholder-zinc-500 focus:border-emerald-500 focus:outline-none"
                />
              </div>

              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-mono text-zinc-300 block">
                    Declaración de Atestación del Operador
                  </label>
                  <span className="text-[10px] font-mono text-zinc-500">
                    Mínimo 10 caracteres ({attestationText.trim().length}/10)
                  </span>
                </div>
                <textarea
                  value={attestationText}
                  onChange={(e) => setAttestationText(e.target.value)}
                  placeholder="Certifico que la evaluación fue realizada dentro del alcance autorizado y que los hallazgos presentados reflejan observaciones genuinas verificadas..."
                  rows={4}
                  required
                  className="w-full rounded-xl border border-zinc-700 bg-zinc-950 p-3 text-xs font-mono text-zinc-100 placeholder-zinc-500 focus:border-emerald-500 focus:outline-none resize-none"
                />
              </div>

              {reportError && (
                <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-2.5 text-xs font-mono text-rose-300">
                  {reportError}
                </div>
              )}

              {/* Modal Actions */}
              <div className="flex items-center justify-end gap-2.5 pt-2">
                <button
                  type="button"
                  onClick={() => setIsReportModalOpen(false)}
                  disabled={isGenerating}
                  className="rounded-xl border border-zinc-700 bg-zinc-800 hover:bg-zinc-750 px-4 py-2 text-xs font-mono text-zinc-300 transition cursor-pointer disabled:opacity-50"
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  disabled={isGenerating || attestationText.trim().length < 10}
                  className="rounded-xl border border-emerald-500/40 bg-emerald-500 hover:bg-emerald-400 px-4 py-2 text-xs font-mono font-bold text-black flex items-center gap-2 transition cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isGenerating ? (
                    <>
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      Generando...
                    </>
                  ) : (
                    <>
                      <Download className="h-3.5 w-3.5" />
                      Descargar Informe HTML
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
