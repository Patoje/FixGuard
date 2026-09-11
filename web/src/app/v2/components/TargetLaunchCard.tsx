"use client";

import React, { useState } from "react";
import { Globe, Shield, AlertCircle, ArrowRight, Loader2 } from "lucide-react";
import { v2ApiClient, V2ApiError } from "@/lib/v2/apiClient";
import { isValidTargetUri } from "@/lib/v2/idGenerator";
import type { AssessmentSummaryDto } from "@/lib/v2/types";

interface TargetLaunchCardProps {
  onAssessmentCreated: (session: AssessmentSummaryDto) => void;
  activeSession: AssessmentSummaryDto | null;
}

export function TargetLaunchCard({
  onAssessmentCreated,
  activeSession
}: TargetLaunchCardProps) {
  const [targetUri, setTargetUri] = useState<string>("https://api-test.fixguard.internal");
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const isValid = isValidTargetUri(targetUri);

  const handleLaunch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!isValid) {
      setError("Please enter a valid target URL starting with http:// or https://");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const summary = await v2ApiClient.createAssessment(targetUri.trim());
      onAssessmentCreated(summary);
    } catch (err) {
      if (err instanceof V2ApiError) {
        setError(`[${err.errorType}] ${err.message}`);
      } else {
        setError((err as Error).message || "Failed to initialize assessment");
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
            Stage 1: Target Launch & Scope Boundary
          </h2>
          <p className="text-xs text-zinc-400">
            Define an authorized target URL to establish an in-memory assessment session
          </p>
        </div>
      </div>

      <form onSubmit={handleLaunch} className="mt-5 space-y-4">
        <div>
          <label htmlFor="targetUri" className="block text-xs font-medium text-zinc-300">
            Target Host or Origin (HTTP/HTTPS)
          </label>
          <div className="relative mt-1.5 flex rounded-lg shadow-sm">
            <span className="inline-flex items-center rounded-l-lg border border-r-0 border-zinc-800 bg-zinc-900/90 px-3 text-zinc-500">
              <Globe className="h-4 w-4" />
            </span>
            <input
              id="targetUri"
              type="text"
              value={targetUri}
              onChange={(e) => {
                setTargetUri(e.target.value);
                if (error) setError(null);
              }}
              placeholder="https://example.com"
              className={`block w-full rounded-r-lg border bg-zinc-900/60 px-3.5 py-2.5 text-sm font-mono text-zinc-100 placeholder-zinc-600 focus:outline-none focus:ring-2 ${
                targetUri && !isValid
                  ? "border-rose-500/50 focus:border-rose-500 focus:ring-rose-500/20"
                  : "border-zinc-800 focus:border-emerald-500/50 focus:ring-emerald-500/20"
              }`}
              disabled={loading}
            />
          </div>
          {targetUri && !isValid && (
            <p className="mt-1.5 flex items-center gap-1.5 text-xs text-rose-400">
              <AlertCircle className="h-3.5 w-3.5" />
              Must be an absolute URL (e.g. https://api-test.fixguard.internal)
            </p>
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
            Fail-closed client validation active
          </span>
          <button
            type="submit"
            disabled={loading || !isValid}
            className="inline-flex items-center gap-2 rounded-lg bg-emerald-500 px-4 py-2.5 text-sm font-semibold text-zinc-950 transition hover:bg-emerald-400 focus:outline-none focus:ring-2 focus:ring-emerald-500/40 disabled:cursor-not-allowed disabled:opacity-40 shadow-lg shadow-emerald-500/20"
          >
            {loading ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Initializing...
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

      {activeSession && (
        <div className="mt-5 rounded-lg border border-zinc-800 bg-zinc-900/40 p-3.5 text-xs text-zinc-400">
          <div className="flex items-center justify-between">
            <span className="font-semibold text-zinc-300">Active Session ID:</span>
            <span className="font-mono text-emerald-400">{activeSession.sessionId}</span>
          </div>
          <div className="mt-1.5 flex items-center justify-between">
            <span>Target:</span>
            <span className="font-mono text-zinc-300">{activeSession.targetUri}</span>
          </div>
        </div>
      )}
    </div>
  );
}
