"use client";

import React, { useState } from "react";
import { Globe, Shield, AlertCircle, ArrowRight, Loader2 } from "lucide-react";
import {
  startOrchestratedAssessment,
  V2ApiError,
  type StartOrchestratedAssessmentResponse,
} from "@/lib/v2Api";

interface TargetLaunchCardProps {
  onAssessmentStarted: (
    data: StartOrchestratedAssessmentResponse,
    domain: string
  ) => void;
  isRunning: boolean;
  activeDomain: string | null;
  activeAssessmentId: string | null;
}

function cleanDomain(input: string): string {
  return input
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "");
}

function isPrivateOrLoopbackHost(hostname: string): boolean {
  if (hostname === "localhost" || hostname.endsWith(".localhost")) return true;
  if (/^127\./.test(hostname)) return true;
  if (/^10\./.test(hostname)) return true;
  if (/^192\.168\./.test(hostname)) return true;
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(hostname)) return true;
  if (/^169\.254\./.test(hostname)) return true;
  return false;
}

export function TargetLaunchCard({
  onAssessmentStarted,
  isRunning,
  activeDomain,
  activeAssessmentId,
}: TargetLaunchCardProps) {
  const [domainInput, setDomainInput] = useState<string>("teclaaa.vercel.app");
  const [actorId, setActorId] = useState<string>("usr_secops_lead");
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const cleaned = cleanDomain(domainInput);
  const isValidFormat =
    cleaned.length > 2 && /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(cleaned);
  const isSsrfRisk = isPrivateOrLoopbackHost(cleaned);

  const handleLaunch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!isValidFormat) {
      setError("Enter a valid public domain (e.g. teclaaa.vercel.app)");
      return;
    }
    if (isSsrfRisk) {
      setError(
        `Egress gate blocked '${cleaned}' (private/loopback). Use a public authorized target.`
      );
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const result = await startOrchestratedAssessment({
        targetDomain: cleaned,
        actorId: actorId.trim() || undefined,
      });
      onAssessmentStarted(result, cleaned);
    } catch (err) {
      if (err instanceof V2ApiError) {
        if (err.reasonCode === "ssrf_target_blocked") {
          setError(
            `SSRF egress gate: '${cleaned}' resolves to a restricted IP. Assessment aborted.`
          );
        } else if (err.errorType === "V2GatewayUnreachable" || err.status === 0) {
          setError(
            "V2 API Gateway unreachable. Run: cd worker && npm run dev (port 4000)."
          );
        } else {
          setError(`[${err.errorType}] ${err.message}`);
        }
      } else {
        const msg =
          (err as Error).message || "Failed to start orchestrated assessment";
        if (/Failed to fetch|NetworkError|ECONNREFUSED/i.test(msg)) {
          setError(
            "V2 API Gateway unreachable. Run: cd worker && npm run dev (port 4000)."
          );
        } else {
          setError(msg);
        }
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-950/80 p-6 shadow-2xl backdrop-blur-xl">
      <div className="flex items-center gap-3 border-b border-zinc-800/80 pb-4">
        <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-emerald-500/20 bg-emerald-500/10 text-emerald-400 shadow-inner">
          <Shield className="h-5 w-5" />
        </div>
        <div>
          <h2 className="text-lg font-semibold tracking-tight text-zinc-100">
            Stage 1: Target Launch
          </h2>
          <p className="text-xs text-zinc-400">
            Start an authorized orchestrated assessment against a public domain
          </p>
        </div>
      </div>

      <form onSubmit={handleLaunch} className="mt-5 space-y-4">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <div className="sm:col-span-2">
            <label
              htmlFor="targetDomain"
              className="block text-xs font-medium text-zinc-300"
            >
              Target Domain
            </label>
            <div className="relative mt-1.5 flex rounded-lg shadow-sm">
              <span className="inline-flex items-center rounded-l-lg border border-r-0 border-zinc-800 bg-zinc-900/90 px-3 text-zinc-500">
                <Globe className="h-4 w-4" />
              </span>
              <input
                id="targetDomain"
                type="text"
                value={domainInput}
                onChange={(e) => {
                  setDomainInput(e.target.value);
                  if (error) setError(null);
                }}
                placeholder="teclaaa.vercel.app"
                className={`block w-full rounded-r-lg border bg-zinc-900/60 px-3.5 py-2.5 text-sm font-mono text-zinc-100 placeholder-zinc-600 focus:outline-none focus:ring-2 ${
                  domainInput && !isValidFormat
                    ? "border-rose-500/50 focus:border-rose-500 focus:ring-rose-500/20"
                    : "border-zinc-800 focus:border-emerald-500/50 focus:ring-emerald-500/20"
                }`}
                disabled={loading || isRunning}
              />
            </div>
          </div>

          <div>
            <label
              htmlFor="actorId"
              className="block text-xs font-medium text-zinc-300"
            >
              Operator ID
            </label>
            <input
              id="actorId"
              type="text"
              value={actorId}
              onChange={(e) => setActorId(e.target.value)}
              placeholder="usr_operator"
              className="mt-1.5 block w-full rounded-lg border border-zinc-800 bg-zinc-900/60 px-3.5 py-2.5 text-sm font-mono text-zinc-100 placeholder-zinc-600 focus:border-emerald-500/50 focus:outline-none focus:ring-2 focus:ring-emerald-500/20"
              disabled={loading || isRunning}
            />
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 text-xs">
          <span className="text-zinc-500 font-mono text-[11px]">Presets:</span>
          {["teclaaa.vercel.app", "charmarket.vercel.app", "example.com"].map(
            (domain) => (
              <button
                key={domain}
                type="button"
                onClick={() => {
                  setDomainInput(domain);
                  setError(null);
                }}
                disabled={loading || isRunning}
                className="rounded-lg border border-zinc-800 bg-zinc-900/70 hover:border-emerald-500/40 hover:bg-emerald-500/10 px-2.5 py-1 font-mono text-[11px] text-zinc-300 transition disabled:opacity-50"
              >
                {domain}
              </button>
            )
          )}
        </div>

        {error && (
          <div className="flex items-start gap-2 rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-300">
            <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        <div className="flex items-center justify-between pt-2">
          <span className="text-xs text-zinc-500">
            Uses POST /api/v2/orchestrated/assessments/start
          </span>
          <button
            type="submit"
            disabled={loading || isRunning || !isValidFormat}
            className="inline-flex items-center gap-2 rounded-lg bg-emerald-500 px-4 py-2.5 text-sm font-semibold text-zinc-950 transition hover:bg-emerald-400 focus:outline-none focus:ring-2 focus:ring-emerald-500/40 disabled:cursor-not-allowed disabled:opacity-40 shadow-lg shadow-emerald-500/20"
          >
            {loading ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Authorizing...
              </>
            ) : isRunning ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Assessment Running...
              </>
            ) : (
              <>
                Launch Assessment
                <ArrowRight className="h-4 w-4" />
              </>
            )}
          </button>
        </div>
      </form>

      {activeAssessmentId && activeDomain && (
        <div className="mt-5 rounded-lg border border-zinc-800 bg-zinc-900/40 p-3.5 text-xs text-zinc-400">
          <div className="flex items-center justify-between">
            <span className="font-semibold text-zinc-300">Assessment ID:</span>
            <span className="font-mono text-emerald-400">{activeAssessmentId}</span>
          </div>
          <div className="mt-1.5 flex items-center justify-between">
            <span>Target:</span>
            <span className="font-mono text-zinc-300">{activeDomain}</span>
          </div>
        </div>
      )}
    </div>
  );
}
