"use client";

import React, { useState } from "react";
import {
  FileCheck,
  ShieldCheck,
  AlertCircle,
  Download,
  Loader2,
  CheckCircle,
} from "lucide-react";
import { generateHtmlReport, V2ApiError } from "@/lib/v2Api";
import {
  getOperatorSessionIdentity,
  setOperatorSessionIdentity,
} from "@/lib/v2/operatorSession";

const DEFAULT_ATTESTATION =
  "Verifiqué los hallazgos candidatos contra evidencia del target y restricciones del audit defensivo.";

interface ReportGenerationCardProps {
  assessmentId: string;
  reviewedCount: number;
}

export function ReportGenerationCard({
  assessmentId,
  reviewedCount,
}: ReportGenerationCardProps) {
  const [operatorId, setOperatorId] = useState<string>(() =>
    getOperatorSessionIdentity()
  );
  const [attestationText, setAttestationText] =
    useState<string>(DEFAULT_ATTESTATION);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [htmlReport, setHtmlReport] = useState<string | null>(null);

  const canGenerate =
    Boolean(assessmentId) &&
    operatorId.trim().length >= 3 &&
    attestationText.trim().length >= 10;

  const handleGenerateReport = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canGenerate) {
      setError(
        "Se requiere un identificador de operador válido y una atestación de al menos 10 caracteres."
      );
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const html = await generateHtmlReport(assessmentId, {
        operatorId: operatorId.trim(),
        attestationText: attestationText.trim(),
      });
      setHtmlReport(html);
    } catch (err) {
      if (err instanceof V2ApiError) {
        setError(`Report blocked (${err.errorType}): ${err.message}`);
      } else {
        setError((err as Error).message || "Failed to generate report");
      }
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadHtml = () => {
    if (!htmlReport) return;
    const blob = new Blob([htmlReport], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${assessmentId}-report.html`;
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
            Stage 5: Defensive Report
          </h2>
          <p className="text-xs text-zinc-400">
            Firmá el assessment y descargá el reporte HTML
          </p>
        </div>
      </div>

      <form onSubmit={handleGenerateReport} className="mt-5 space-y-4">
        {reviewedCount > 0 && (
          <p className="text-xs text-zinc-500">
            Drafts revisados en esta sesión:{" "}
            <span className="text-emerald-400 font-mono">{reviewedCount}</span>
          </p>
        )}

        <div>
          <label
            htmlFor="operatorId"
            className="block text-xs font-medium text-zinc-300"
          >
            Identificador del Operador (HITL)
          </label>
          <input
            id="operatorId"
            type="text"
            value={operatorId}
            onChange={(e) => {
              setOperatorId(e.target.value);
              setOperatorSessionIdentity(e.target.value);
            }}
            placeholder="op_local_analyst"
            className="mt-1.5 block w-full rounded-lg border border-zinc-800 bg-zinc-900/60 px-3.5 py-2 text-xs font-mono text-zinc-100 placeholder-zinc-600 focus:border-emerald-500/50 focus:outline-none focus:ring-2 focus:ring-emerald-500/20"
            disabled={loading}
          />
          <p className="mt-1 text-[11px] text-zinc-600">
            Identidad de sesión activa que atestigua la revisión defensiva.
          </p>
        </div>

        <div>
          <label
            htmlFor="attestationText"
            className="block text-xs font-medium text-zinc-300"
          >
            Atestación del operador
          </label>
          <textarea
            id="attestationText"
            rows={2}
            value={attestationText}
            onChange={(e) => setAttestationText(e.target.value)}
            placeholder="Confirmación breve de revisión humana…"
            className="mt-1.5 block w-full rounded-lg border border-zinc-800 bg-zinc-900/60 px-3.5 py-2.5 text-xs text-zinc-100 placeholder-zinc-600 focus:border-emerald-500/50 focus:outline-none focus:ring-2 focus:ring-emerald-500/20"
            disabled={loading}
          />
          <p className="mt-1 text-[11px] text-zinc-600">
            Requerida por el gate fail-closed del reporte (≥ 10 chars)
          </p>
        </div>

        {error && (
          <div className="flex items-start gap-2 rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-300">
            <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        <div className="flex items-center justify-end pt-2">
          <button
            type="submit"
            disabled={loading || !canGenerate}
            className="inline-flex items-center gap-2 rounded-lg bg-emerald-500 px-5 py-2.5 text-sm font-semibold text-zinc-950 transition hover:bg-emerald-400 focus:outline-none focus:ring-2 focus:ring-emerald-500/40 disabled:cursor-not-allowed disabled:opacity-40 shadow-lg shadow-emerald-500/20"
          >
            {loading ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Compiling…
              </>
            ) : (
              <>
                <ShieldCheck className="h-4 w-4" />
                Generate HTML Report
              </>
            )}
          </button>
        </div>
      </form>

      {htmlReport && (
        <div className="mt-8 rounded-xl border border-emerald-500/30 bg-zinc-900/70 p-6 shadow-2xl space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <span className="inline-flex items-center gap-1 rounded bg-emerald-500/20 px-2 py-0.5 text-xs font-mono font-semibold text-emerald-400">
                <CheckCircle className="h-3.5 w-3.5" />
                HTML report ready
              </span>
              <span className="font-mono text-xs text-zinc-400">
                {Math.round(htmlReport.length / 1024)} KB
              </span>
            </div>
            <button
              type="button"
              onClick={handleDownloadHtml}
              className="inline-flex items-center gap-1.5 rounded-lg border border-zinc-800 bg-zinc-800/80 px-3 py-1.5 text-xs font-medium text-zinc-300 transition hover:bg-zinc-700"
            >
              <Download className="h-3.5 w-3.5" />
              Download HTML
            </button>
          </div>
          <iframe
            title="Defensive assessment report preview"
            srcDoc={htmlReport}
            className="w-full h-[28rem] rounded-lg border border-zinc-800 bg-white"
            sandbox=""
          />
        </div>
      )}
    </div>
  );
}
