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
  Scale
} from "lucide-react";
import type {
  OrchestratedAssessmentSummaryResponse,
  FindingDto,
  RecommendationDto,
  ProfileEndpointDto
} from "@/lib/v2Api";

interface ExecutiveResultsPanelProps {
  summary: OrchestratedAssessmentSummaryResponse | null;
}

export function ExecutiveResultsPanel({ summary }: ExecutiveResultsPanelProps) {
  const [activeTab, setActiveTab] = useState<"profile" | "findings" | "recommendations">("profile");

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
            <div className="rounded-xl border border-zinc-900 bg-zinc-900/40 p-4 space-y-1 md:col-span-2">
              <span className="text-[11px] font-mono text-zinc-500 uppercase tracking-wider block">
                Discovered Technologies &amp; Edge Infrastructure
              </span>
              <div className="flex flex-wrap items-center gap-2 pt-1">
                {profile.technologies.length > 0 ? (
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
    </div>
  );
}
