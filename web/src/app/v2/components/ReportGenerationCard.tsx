"use client";

import React, { useState } from "react";
import {
  FileCheck,
  ShieldCheck,
  AlertCircle,
  Copy,
  Download,
  Loader2,
  CheckCircle,
  Lock
} from "lucide-react";
import { v2ApiClient, V2ApiError } from "@/lib/v2/apiClient";
import { generateReportId, isStrictSafeId } from "@/lib/v2/idGenerator";
import type { DefensiveAssessmentReportDto } from "@/lib/v2/types";

interface ReportGenerationCardProps {
  sessionId: string;
  scanId: string;
  candidateCount: number;
}

export function ReportGenerationCard({
  sessionId,
  scanId,
  candidateCount
}: ReportGenerationCardProps) {
  const [operatorSignatureId, setOperatorSignatureId] = useState<string>("op_sec_admin");
  const [operatorAttestationText, setOperatorAttestationText] = useState<string>(
    "I have verified all candidate findings against defensive audit constraints and live target evidence."
  );
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<DefensiveAssessmentReportDto | null>(null);
  const [copied, setCopied] = useState<boolean>(false);

  const canGenerate =
    sessionId &&
    scanId &&
    isStrictSafeId(operatorSignatureId) &&
    operatorAttestationText.trim().length >= 10;

  const handleGenerateReport = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canGenerate) {
      setError(
        "Please ensure Session ID and Scan ID are set, signature ID is valid, and attestation text has at least 10 characters."
      );
      return;
    }

    setLoading(true);
    setError(null);

    const now = new Date().toISOString();
    const reportId = generateReportId();

    try {
      const generated = await v2ApiClient.generateReport({
        reportId,
        sessionId,
        scanId,
        requestedAt: now,
        operatorSignatureId: operatorSignatureId.trim(),
        operatorVerifiedAt: now,
        operatorAttestationText: operatorAttestationText.trim()
      });

      setReport(generated);
    } catch (err) {
      if (err instanceof V2ApiError) {
        setError(`Report Compilation Blocked (${err.errorType}): ${err.message}`);
      } else {
        setError((err as Error).message || "Failed to compile defensive report");
      }
    } finally {
      setLoading(false);
    }
  };

  const handleCopyJson = () => {
    if (!report) return;
    navigator.clipboard.writeText(JSON.stringify(report, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadJson = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${report.reportId}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-950/80 p-6 shadow-2xl backdrop-blur-xl">
      <div className="flex items-center gap-3 border-b border-zinc-800/80 pb-4">
        <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-emerald-500/20 bg-emerald-500/10 text-emerald-400">
          <FileCheck className="h-5 w-5" />
        </div>
        <div>
          <h2 className="text-lg font-semibold tracking-tight text-zinc-100">
            Stage 4: Defensive Report Gatekeeper
          </h2>
          <p className="text-xs text-zinc-400">
            Enforce mandatory human operator signature and generate authentic 11-key Defensive Assessment Report
          </p>
        </div>
      </div>

      <form onSubmit={handleGenerateReport} className="mt-5 space-y-4">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div>
            <label htmlFor="signatureId" className="block text-xs font-medium text-zinc-300">
              Operator Signature ID (HITL Sign-Off)
            </label>
            <input
              id="signatureId"
              type="text"
              value={operatorSignatureId}
              onChange={(e) => setOperatorSignatureId(e.target.value.trim())}
              placeholder="op_sec_admin"
              className="mt-1.5 block w-full rounded-lg border border-zinc-800 bg-zinc-900/60 px-3.5 py-2 text-xs font-mono text-zinc-100 placeholder-zinc-600 focus:border-emerald-500/50 focus:outline-none focus:ring-2 focus:ring-emerald-500/20"
              disabled={loading}
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-zinc-300">
              Promoted Formal Candidates
            </label>
            <div className="mt-1.5 flex h-[34px] items-center justify-between rounded-lg border border-zinc-800 bg-zinc-900/40 px-3 text-xs font-mono text-zinc-300">
              <span>Candidate Pool:</span>
              <span className="font-bold text-emerald-400">{candidateCount} Formal Candidates</span>
            </div>
          </div>
        </div>

        <div>
          <label htmlFor="attestationText" className="block text-xs font-medium text-zinc-300">
            Operator Attestation Text (Mandatory &ge; 10 chars)
          </label>
          <textarea
            id="attestationText"
            rows={3}
            value={operatorAttestationText}
            onChange={(e) => setOperatorAttestationText(e.target.value)}
            placeholder="Document human verification statement..."
            className="mt-1.5 block w-full rounded-lg border border-zinc-800 bg-zinc-900/60 px-3.5 py-2.5 text-xs text-zinc-100 placeholder-zinc-600 focus:border-emerald-500/50 focus:outline-none focus:ring-2 focus:ring-emerald-500/20"
            disabled={loading}
          />
          <div className="mt-1 flex items-center justify-between text-[11px] text-zinc-500">
            <span>Minimum 10 characters required for fail-closed gate</span>
            <span>{operatorAttestationText.length} characters</span>
          </div>
        </div>

        {error && (
          <div className="flex items-start gap-2 rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-300">
            <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        <div className="flex items-center justify-between pt-2">
          <span className="text-xs text-zinc-500 flex items-center gap-1">
            <Lock className="h-3.5 w-3.5 text-zinc-500" />
            Zero Speculation Invariant Enforced
          </span>
          <button
            type="submit"
            disabled={loading || !canGenerate}
            className="inline-flex items-center gap-2 rounded-lg bg-emerald-500 px-5 py-2.5 text-sm font-semibold text-zinc-950 transition hover:bg-emerald-400 focus:outline-none focus:ring-2 focus:ring-emerald-500/40 disabled:cursor-not-allowed disabled:opacity-40 shadow-lg shadow-emerald-500/20"
          >
            {loading ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Compiling Report...
              </>
            ) : (
              <>
                <ShieldCheck className="h-4 w-4" />
                Generate Defensive Report
              </>
            )}
          </button>
        </div>
      </form>

      {/* Render Compiled Defensive Report */}
      {report && (
        <div className="mt-8 rounded-xl border border-emerald-500/30 bg-zinc-900/70 p-6 shadow-2xl">
          <div className="flex flex-wrap items-center justify-between gap-4 border-b border-zinc-800 pb-4">
            <div>
              <div className="flex items-center gap-2">
                <span className="inline-flex items-center gap-1 rounded bg-emerald-500/20 px-2 py-0.5 text-xs font-mono font-semibold text-emerald-400">
                  {report.kind}
                </span>
                <span className="font-mono text-xs text-zinc-400">
                  ID: {report.reportId}
                </span>
              </div>
              <p className="mt-1 text-xs text-zinc-400 font-mono">
                Scan: {report.scanId} | Session: {report.assessmentId}
              </p>
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handleCopyJson}
                className="inline-flex items-center gap-1.5 rounded-lg border border-zinc-800 bg-zinc-800/80 px-3 py-1.5 text-xs font-medium text-zinc-300 transition hover:bg-zinc-700"
              >
                {copied ? (
                  <>
                    <CheckCircle className="h-3.5 w-3.5 text-emerald-400" />
                    Copied
                  </>
                ) : (
                  <>
                    <Copy className="h-3.5 w-3.5" />
                    Copy JSON
                  </>
                )}
              </button>
              <button
                type="button"
                onClick={handleDownloadJson}
                className="inline-flex items-center gap-1.5 rounded-lg border border-zinc-800 bg-zinc-800/80 px-3 py-1.5 text-xs font-medium text-zinc-300 transition hover:bg-zinc-700"
              >
                <Download className="h-3.5 w-3.5" />
                Export
              </button>
            </div>
          </div>

          {/* Attestation Details */}
          <div className="mt-4 rounded-lg border border-zinc-800 bg-zinc-950/60 p-3.5 text-xs">
            <div className="text-[11px] font-semibold text-zinc-400 uppercase tracking-wider">
              Operator Attestation
            </div>
            <p className="mt-1.5 italic text-zinc-200">
              &ldquo;{report.operatorAttestation.attestationText}&rdquo;
            </p>
            <div className="mt-2 flex flex-wrap items-center justify-between gap-2 text-[11px] text-zinc-500 font-mono">
              <span>Signer: {report.operatorAttestation.operatorSignatureId}</span>
              <span>Verified: {new Date(report.operatorAttestation.verifiedAt).toLocaleString()}</span>
            </div>
          </div>

          {/* Audit Limitations */}
          <div className="mt-4 rounded-lg border border-zinc-800 bg-zinc-950/60 p-3.5 text-xs">
            <div className="text-[11px] font-semibold text-zinc-400 uppercase tracking-wider">
              Enforced Audit Limitations
            </div>
            <p className="mt-1 text-[11px] text-zinc-400">
              {report.auditLimitations.disclaimerText}
            </p>
            <div className="mt-2.5 grid grid-cols-2 gap-2 text-[11px] font-mono sm:grid-cols-4">
              <span className="text-emerald-400">
                Scope Gated: {report.auditLimitations.scopeBoundariesEnforced ? "YES" : "NO"}
              </span>
              <span className="text-emerald-400">
                Egress SSRF Filter: {report.auditLimitations.egressFilteringActive ? "ACTIVE" : "OFF"}
              </span>
              <span className="text-emerald-400">
                Auto-Exploit: {report.auditLimitations.noAutonomousExploitation ? "BLOCKED" : "ALLOWED"}
              </span>
              <span className="text-emerald-400">
                HITL Gate: {report.auditLimitations.humanAuthorizedOnly ? "ENFORCED" : "BYPASSED"}
              </span>
            </div>
          </div>

          {/* Formal Finding Candidates */}
          <div className="mt-4 space-y-2">
            <div className="text-[11px] font-semibold text-zinc-400 uppercase tracking-wider">
              Formal Finding Candidates ({report.candidateCount})
            </div>
            {report.candidates.length === 0 ? (
              <div className="rounded-lg border border-zinc-800 bg-zinc-950/40 p-3 text-center text-xs text-zinc-500">
                No candidates were promoted into this report.
              </div>
            ) : (
              report.candidates.map((cand) => (
                <div
                  key={cand.candidateId}
                  className="rounded-lg border border-zinc-800 bg-zinc-950/80 p-3.5 text-xs font-mono"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-emerald-400">{cand.candidateId}</span>
                    <span className="text-zinc-500">Draft: {cand.draftId}</span>
                  </div>
                  <div className="mt-1.5 flex flex-wrap gap-2 text-[11px]">
                    <span className="text-zinc-400">Reviewer: {cand.triageAssessment.reviewerId}</span>
                    <span className="text-zinc-400">Decision: {cand.triageAssessment.decisionId}</span>
                    <span className="text-zinc-400">Refs: {cand.sourceSelection.selectedCount}</span>
                  </div>
                </div>
              ))
            )}
          </div>

          {/* Explicit Non-Claims Verification */}
          <div className="mt-4 rounded-lg border border-zinc-800 bg-zinc-950/60 p-3.5 text-[11px]">
            <div className="font-semibold text-zinc-400 uppercase tracking-wider">
              Verified Explicit Non-Claims
            </div>
            <div className="mt-1.5 grid grid-cols-2 gap-1.5 text-zinc-400 font-mono sm:grid-cols-3">
              {Object.entries(report.explicitNonClaims).map(([nonClaim, active]) => (
                <span key={nonClaim} className="flex items-center gap-1 text-zinc-300">
                  <CheckCircle className="h-3 w-3 text-emerald-500 shrink-0" />
                  {nonClaim}: {String(active)}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
