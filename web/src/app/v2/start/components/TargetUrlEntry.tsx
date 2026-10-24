"use client";

import React, { useState } from "react";
import {
  startOrchestratedAssessment,
  V2ApiError,
  type StartOrchestratedAssessmentResponse,
} from "@/lib/v2Api";
import {
  getOperatorSessionIdentity,
  setOperatorSessionIdentity,
} from "@/lib/v2/operatorSession";
import {
  cleanDomain,
  isPrivateOrLoopbackHost,
} from "../../components/TargetLaunchCard";

/**
 * Initial screen for FixGuard V2. Single function: accept a target URL and
 * continue. No other stages or functionality here — the pipeline/triage
 * flow already exists at /v2/assessments.
 */
export function TargetUrlEntry() {
  const [urlInput, setUrlInput] = useState("");
  const [actorId] = useState<string>(() => getOperatorSessionIdentity());
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<StartOrchestratedAssessmentResponse | null>(null);
  const [startedDomain, setStartedDomain] = useState<string>("");

  const cleaned = cleanDomain(urlInput);
  const isValidFormat = cleaned.length > 2 && /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(cleaned);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!isValidFormat) {
      setError("Ingresá una URL válida (ej. target.com).");
      return;
    }
    if (isPrivateOrLoopbackHost(cleaned)) {
      setError(`'${cleaned}' es un host privado/loopback. Usá un target público autorizado.`);
      return;
    }

    setLoading(true);
    setError(null);
    try {
      setOperatorSessionIdentity(actorId);
      const response = await startOrchestratedAssessment({
        targetDomain: cleaned,
        actorId,
      });
      setResult(response);
      setStartedDomain(cleaned);
    } catch (err) {
      if (err instanceof V2ApiError) {
        setError(
          err.errorType === "V2GatewayUnreachable" || err.status === 0
            ? "V2 API Gateway no responde. Ejecutá: cd worker && npm run dev (puerto 4000)."
            : `[${err.errorType}] ${err.message}`
        );
      } else {
        setError((err as Error).message || "No se pudo iniciar el assessment.");
      }
    } finally {
      setLoading(false);
    }
  };

  if (result) {
    return (
      <div className="w-full max-w-md rounded-lg border border-zinc-800 bg-zinc-950 p-6">
        <h2 className="text-sm font-medium text-zinc-200">Assessment iniciado</h2>
        <dl className="mt-4 space-y-2 font-mono text-sm">
          <div className="flex justify-between gap-4">
            <dt className="text-zinc-500">Target</dt>
            <dd className="text-zinc-200">{startedDomain}</dd>
          </div>
          <div className="flex justify-between gap-4">
            <dt className="text-zinc-500">Assessment ID</dt>
            <dd className="truncate text-zinc-200">{result.assessmentId}</dd>
          </div>
        </dl>
        <a
          href="/v2/assessments"
          className="mt-6 block rounded-md border border-zinc-700 px-4 py-2 text-center text-sm text-zinc-200 hover:bg-zinc-900"
        >
          Ver progreso
        </a>
      </div>
    );
  }

  return (
    <form
      onSubmit={handleSubmit}
      className="w-full max-w-md rounded-lg border border-zinc-800 bg-zinc-950 p-6"
    >
      <label htmlFor="target-url" className="block text-sm font-medium text-zinc-200">
        Target URL
      </label>
      <input
        id="target-url"
        type="text"
        value={urlInput}
        onChange={(e) => setUrlInput(e.target.value)}
        placeholder="target.com"
        autoComplete="off"
        spellCheck={false}
        className="mt-2 w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 font-mono text-sm text-zinc-100 placeholder:text-zinc-600 focus:border-zinc-500 focus:outline-none"
      />
      {error && <p className="mt-2 text-sm text-red-400">{error}</p>}
      <button
        type="submit"
        disabled={loading || !urlInput}
        className="mt-4 w-full rounded-md border border-zinc-700 bg-zinc-100 px-4 py-2 text-sm font-medium text-zinc-900 disabled:cursor-not-allowed disabled:opacity-40"
      >
        {loading ? "Iniciando..." : "Continuar"}
      </button>
    </form>
  );
}
