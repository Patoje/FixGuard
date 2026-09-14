"use client";

import React, { useState } from "react";
import {
  Globe,
  Shield,
  AlertTriangle,
  ArrowRight,
  Loader2,
  CheckCircle2,
  Terminal,
  Zap
} from "lucide-react";
import {
  startOrchestratedAssessment,
  V2ApiError,
  type StartOrchestratedAssessmentResponse
} from "@/lib/v2Api";

interface AssessmentLauncherCardProps {
  onAssessmentStarted: (data: StartOrchestratedAssessmentResponse, domain: string) => void;
  isRunning: boolean;
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

export function AssessmentLauncherCard({
  onAssessmentStarted,
  isRunning
}: AssessmentLauncherCardProps) {
  const [domainInput, setDomainInput] = useState<string>("charmarket.vercel.app");
  const [actorId, setActorId] = useState<string>("usr_secops_lead");
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const cleaned = cleanDomain(domainInput);
  const isValidFormat = cleaned.length > 2 && /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(cleaned);
  const isSsrfRisk = isPrivateOrLoopbackHost(cleaned);

  const handleLaunch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!isValidFormat) {
      setError("Please enter a valid target domain (e.g. charmarket.vercel.app)");
      return;
    }

    if (isSsrfRisk) {
      setError(
        `Preflight Security Gate: '${cleaned}' is a private, loopback, or cloud-internal target. FixGuard fail-closed egress policy blocks non-public IPs to prevent SSRF vulnerabilities.`
      );
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const result = await startOrchestratedAssessment({
        targetDomain: cleaned,
        actorId: actorId.trim() || undefined
      });
      onAssessmentStarted(result, cleaned);
    } catch (err) {
      if (err instanceof V2ApiError) {
        if (err.reasonCode === "ssrf_target_blocked") {
          setError(
            `SSRF Egress Gatekeeper: Target domain '${cleaned}' resolves to a private or restricted IP address. Assessment aborted with strictly 0 stages dispatched.`
          );
        } else {
          setError(`[${err.errorType}] ${err.message}`);
        }
      } else {
        setError((err as Error).message || "Failed to initiate orchestrated assessment");
      }
    } finally {
      setLoading(false);
    }
  };

  const setPreset = (domain: string) => {
    setDomainInput(domain);
    setError(null);
  };

  return (
    <div className="rounded-2xl border border-zinc-800 bg-zinc-950/80 p-6 shadow-2xl backdrop-blur-xl">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-zinc-800/80 pb-5">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-emerald-500/30 bg-emerald-500/10 text-emerald-400">
            <Zap className="h-5 w-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-semibold text-white tracking-wide">
                Orchestrated Assessment Launcher
              </h2>
              <span className="rounded bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 text-[10px] font-mono font-medium text-emerald-400">
                Milestone 73 / F6
              </span>
            </div>
            <p className="text-xs text-zinc-400 mt-0.5">
              Automated 5-stage discovery, dual detection engines (CORS &amp; Reflection), and TargetProfile synthesis
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-zinc-400">
          <span className="flex items-center gap-1.5 rounded-full border border-zinc-800 bg-zinc-900/60 px-3 py-1">
            <Shield className="h-3.5 w-3.5 text-emerald-400" />
            <span>ADR-001 WeakSet Brand</span>
          </span>
          <span className="hidden sm:flex items-center gap-1.5 rounded-full border border-zinc-800 bg-zinc-900/60 px-3 py-1">
            <Terminal className="h-3.5 w-3.5 text-blue-400" />
            <span>Safe Transports Only</span>
          </span>
        </div>
      </div>

      <form onSubmit={handleLaunch} className="mt-6 space-y-5">
        {error && (
          <div className="flex items-start gap-2.5 rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-xs text-rose-300 animate-in fade-in duration-200">
            <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400 mt-0.5" />
            <div className="flex-1 leading-relaxed">
              <strong className="font-semibold block mb-0.5">Preflight Denial / Gate Error</strong>
              {error}
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="md:col-span-2 space-y-1.5">
            <label htmlFor="targetDomain" className="block text-xs font-medium text-zinc-300">
              Target FQDN / Domain <span className="text-rose-400">*</span>
            </label>
            <div className="relative">
              <Globe className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-zinc-500" />
              <input
                id="targetDomain"
                type="text"
                value={domainInput}
                onChange={(e) => {
                  setDomainInput(e.target.value);
                  if (error) setError(null);
                }}
                placeholder="e.g. charmarket.vercel.app"
                disabled={loading || isRunning}
                className="w-full rounded-xl border border-zinc-800 bg-zinc-900/80 py-2.5 pl-10 pr-4 text-xs font-mono text-white placeholder-zinc-500 focus:border-emerald-500/60 focus:bg-zinc-900 focus:outline-none focus:ring-1 focus:ring-emerald-500/40 transition disabled:opacity-50"
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <label htmlFor="actorId" className="block text-xs font-medium text-zinc-300">
              Authorized Operator ID
            </label>
            <input
              id="actorId"
              type="text"
              value={actorId}
              onChange={(e) => setActorId(e.target.value)}
              placeholder="usr_operator"
              disabled={loading || isRunning}
              className="w-full rounded-xl border border-zinc-800 bg-zinc-900/80 py-2.5 px-3.5 text-xs font-mono text-white placeholder-zinc-500 focus:border-blue-500/60 focus:bg-zinc-900 focus:outline-none focus:ring-1 focus:ring-blue-500/40 transition disabled:opacity-50"
            />
          </div>
        </div>

        {/* Target Presets */}
        <div className="flex flex-wrap items-center gap-2 pt-1 text-xs">
          <span className="text-zinc-500 font-mono text-[11px]">Quick Authorized Targets:</span>
          <button
            type="button"
            onClick={() => setPreset("charmarket.vercel.app")}
            disabled={loading || isRunning}
            className="rounded-lg border border-zinc-800 bg-zinc-900/70 hover:border-emerald-500/40 hover:bg-emerald-500/10 px-2.5 py-1 font-mono text-[11px] text-zinc-300 transition"
          >
            charmarket.vercel.app (Live Verified)
          </button>
          <button
            type="button"
            onClick={() => setPreset("example.com")}
            disabled={loading || isRunning}
            className="rounded-lg border border-zinc-800 bg-zinc-900/70 hover:border-zinc-700 hover:bg-zinc-800/60 px-2.5 py-1 font-mono text-[11px] text-zinc-400 transition"
          >
            example.com
          </button>
        </div>

        {/* Security & SSRF Banner Note */}
        <div className="rounded-xl border border-zinc-800/60 bg-zinc-900/30 p-3.5 flex items-center justify-between text-xs text-zinc-400 font-mono">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
            <span>Scope boundary strictly restricted to declared target. Rate limited to 5 req/s.</span>
          </div>
          <span className="text-[11px] text-zinc-500 hidden md:inline">202 Accepted Async Gateway</span>
        </div>

        <div className="flex justify-end pt-2">
          <button
            type="submit"
            disabled={loading || isRunning || !domainInput.trim()}
            className="flex items-center gap-2 rounded-xl bg-emerald-500 hover:bg-emerald-400 active:bg-emerald-600 px-5 py-2.5 text-xs font-semibold text-zinc-950 shadow-lg shadow-emerald-500/20 transition duration-150 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
          >
            {loading ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                <span>Authorizing &amp; Preflighting...</span>
              </>
            ) : isRunning ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin text-zinc-950" />
                <span>Assessment Running...</span>
              </>
            ) : (
              <>
                <span>Launch Orchestrated Assessment</span>
                <ArrowRight className="h-4 w-4" />
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
}
