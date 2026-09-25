"use client";

import React, { useState } from "react";
import {
  Globe,
  Shield,
  AlertCircle,
  ArrowRight,
  Loader2,
  Key,
  ChevronDown,
  ChevronRight,
  Lock,
  UserCheck,
} from "lucide-react";
import {
  startOrchestratedAssessment,
  V2ApiError,
  type StartOrchestratedAssessmentResponse,
  type ByotIdentityDto,
  type ByotSessionIdentityBundleDto,
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

function parseCookieInput(cookieStr: string): Record<string, string> {
  const cookies: Record<string, string> = {};
  if (!cookieStr.trim()) return cookies;
  if (cookieStr.includes("=")) {
    const [k, ...v] = cookieStr.split("=");
    cookies[k.trim()] = v.join("=").trim();
  } else {
    cookies["session"] = cookieStr.trim();
  }
  return cookies;
}

export function TargetLaunchCard({
  onAssessmentStarted,
  isRunning,
  activeDomain,
  activeAssessmentId,
}: TargetLaunchCardProps) {
  const [domainInput, setDomainInput] = useState<string>("teclaaa.vercel.app");
  const [actorId, setActorId] = useState<string>("usr_secops_lead");
  const [relatedHostsInput, setRelatedHostsInput] = useState<string>(
    "vawrzoncszqauzxwqide.supabase.co"
  );
  const [seedUrlsInput, setSeedUrlsInput] = useState<string>(
    "https://vawrzoncszqauzxwqide.supabase.co/rest/v1/profiles\nhttps://vawrzoncszqauzxwqide.supabase.co/rest/v1/shop_items"
  );
  const [seedPathsInput, setSeedPathsInput] = useState<string>(
    "/carrera/93kpw, /login, /perfil"
  );
  const [skipSlowCrawl, setSkipSlowCrawl] = useState<boolean>(true);
  const [showAdvanced, setShowAdvanced] = useState(true);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const [showByot, setShowByot] = useState(false);
  const [identityAId, setIdentityAId] = useState("operator_identity_a");
  const [identityAAuthHeader, setIdentityAAuthHeader] = useState("");
  const [identityAApiKey, setIdentityAApiKey] = useState("");
  const [identityACookie, setIdentityACookie] = useState("");
  const [enableIdentityB, setEnableIdentityB] = useState(false);
  const [identityBId, setIdentityBId] = useState("operator_identity_b");
  const [identityBAuthHeader, setIdentityBAuthHeader] = useState("");
  const [identityBApiKey, setIdentityBApiKey] = useState("");
  const [identityBCookie, setIdentityBCookie] = useState("");

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
      let sessionIdentities: ByotSessionIdentityBundleDto | undefined;
      if (
        showByot &&
        (identityAAuthHeader.trim() ||
          identityAApiKey.trim() ||
          identityACookie.trim())
      ) {
        const headersA: Record<string, string> = {};
        if (identityAAuthHeader.trim()) {
          headersA["authorization"] = identityAAuthHeader.trim();
        }
        if (identityAApiKey.trim()) {
          headersA["apikey"] = identityAApiKey.trim();
          // Anon RLS: Authorization Bearer often mirrors the publishable key.
          if (!headersA["authorization"]) {
            headersA["authorization"] = `Bearer ${identityAApiKey.trim()}`;
          }
        }
        const cookiesA = parseCookieInput(identityACookie);

        let identityB: ByotIdentityDto | undefined;
        if (
          enableIdentityB &&
          (identityBAuthHeader.trim() ||
            identityBApiKey.trim() ||
            identityBCookie.trim())
        ) {
          const headersB: Record<string, string> = {};
          if (identityBAuthHeader.trim()) {
            headersB["authorization"] = identityBAuthHeader.trim();
          }
          if (identityBApiKey.trim()) {
            headersB["apikey"] = identityBApiKey.trim();
            if (!headersB["authorization"]) {
              headersB["authorization"] = `Bearer ${identityBApiKey.trim()}`;
            }
          }
          const cookiesB = parseCookieInput(identityBCookie);
          identityB = {
            identityId: identityBId.trim() || "operator_identity_b",
            ...(Object.keys(headersB).length > 0 ? { injectHeaders: headersB } : {}),
            ...(Object.keys(cookiesB).length > 0 ? { injectCookies: cookiesB } : {}),
          };
        }

        sessionIdentities = {
          identityA: {
            identityId: identityAId.trim() || "operator_identity_a",
            ...(Object.keys(headersA).length > 0 ? { injectHeaders: headersA } : {}),
            ...(Object.keys(cookiesA).length > 0 ? { injectCookies: cookiesA } : {}),
          },
          ...(identityB ? { identityB } : {}),
        };
      }

      const relatedAllowedHosts = relatedHostsInput
        .split(/[\s,;]+/)
        .map((h) =>
          h
            .trim()
            .toLowerCase()
            .replace(/^https?:\/\//, "")
            .replace(/\/.*$/, "")
        )
        .filter((h) => h.length > 0 && /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(h));

      const seedUrls = seedUrlsInput
        .split(/[\n,;]+/)
        .map((u) => u.trim())
        .filter((u) => /^https?:\/\/.+/i.test(u));

      const seedPaths = seedPathsInput
        .split(/[\s,;]+/)
        .map((p) => p.trim())
        .filter((p) => p.startsWith("/"));

      const skipStages = skipSlowCrawl
        ? (["stage_2_port_service", "stage_4_crawling_parameters"] as const)
        : undefined;

      const result = await startOrchestratedAssessment({
        targetDomain: cleaned,
        actorId: actorId.trim() || undefined,
        ...(sessionIdentities ? { sessionIdentities } : {}),
        ...(relatedAllowedHosts.length > 0
          ? { relatedAllowedHosts }
          : {}),
        ...(seedUrls.length > 0 ? { seedUrls } : {}),
        ...(seedPaths.length > 0 ? { seedPaths } : {}),
        ...(skipStages
          ? { config: { skipStages: [...skipStages] } }
          : {}),
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

        <div>
          <label
            htmlFor="relatedAllowedHosts"
            className="block text-xs font-medium text-zinc-300"
          >
            Related allowed hosts{" "}
            <span className="font-normal text-zinc-500">
              (optional — e.g. Supabase project for RLS)
            </span>
          </label>
          <input
            id="relatedAllowedHosts"
            type="text"
            value={relatedHostsInput}
            onChange={(e) => {
              setRelatedHostsInput(e.target.value);
              if (error) setError(null);
            }}
            placeholder="project.supabase.co"
            className="mt-1.5 block w-full rounded-lg border border-zinc-800 bg-zinc-900/60 px-3.5 py-2.5 text-sm font-mono text-zinc-100 placeholder-zinc-600 focus:border-emerald-500/50 focus:outline-none focus:ring-2 focus:ring-emerald-500/20"
            disabled={loading || isRunning}
          />
          <p className="mt-1 text-[10px] text-zinc-500">
            Comma-separated. Added to authorized scope so deep recon can probe
            backend APIs (anon RLS needs no JWT).
          </p>
        </div>

        <div className="rounded-lg border border-zinc-800/80 bg-zinc-900/40 overflow-hidden">
          <button
            type="button"
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="w-full flex items-center justify-between p-3 text-xs text-left hover:bg-zinc-800/40 transition"
          >
            <div className="flex items-center gap-2 text-zinc-200 font-medium">
              <span>Advanced scope seeds</span>
              <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-wider">
                seedUrls · skip crawl
              </span>
            </div>
            {showAdvanced ? (
              <ChevronDown className="h-4 w-4 text-zinc-400" />
            ) : (
              <ChevronRight className="h-4 w-4 text-zinc-400" />
            )}
          </button>
          {showAdvanced && (
            <div className="p-3 pt-0 border-t border-zinc-800/60 space-y-3">
              <label className="flex items-start gap-2 text-xs text-zinc-300">
                <input
                  type="checkbox"
                  checked={skipSlowCrawl}
                  onChange={(e) => setSkipSlowCrawl(e.target.checked)}
                  disabled={loading || isRunning}
                  className="mt-0.5 rounded border-zinc-700"
                />
                <span>
                  Skip slow ports + crawl (stage_2 / stage_4) — recommended for
                  SPA + Supabase RLS; avoids gau idle timeout.
                </span>
              </label>
              <div>
                <label
                  htmlFor="seedUrls"
                  className="block text-xs font-medium text-zinc-300"
                >
                  Seed URLs{" "}
                  <span className="font-normal text-zinc-500">
                    (REST tables / known paths)
                  </span>
                </label>
                <textarea
                  id="seedUrls"
                  rows={3}
                  value={seedUrlsInput}
                  onChange={(e) => setSeedUrlsInput(e.target.value)}
                  placeholder="https://project.supabase.co/rest/v1/profiles"
                  disabled={loading || isRunning}
                  className="mt-1.5 block w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs font-mono text-zinc-100 placeholder-zinc-600 focus:border-emerald-500/50 focus:outline-none focus:ring-2 focus:ring-emerald-500/20"
                />
              </div>
              <div>
                <label
                  htmlFor="seedPaths"
                  className="block text-xs font-medium text-zinc-300"
                >
                  Seed paths
                </label>
                <input
                  id="seedPaths"
                  type="text"
                  value={seedPathsInput}
                  onChange={(e) => setSeedPathsInput(e.target.value)}
                  placeholder="/carrera/93kpw, /login"
                  disabled={loading || isRunning}
                  className="mt-1.5 block w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs font-mono text-zinc-100 placeholder-zinc-600 focus:border-emerald-500/50 focus:outline-none focus:ring-2 focus:ring-emerald-500/20"
                />
              </div>
            </div>
          )}
        </div>

        <div className="rounded-lg border border-zinc-800/80 bg-zinc-900/40 overflow-hidden">
          <button
            type="button"
            onClick={() => setShowByot(!showByot)}
            className="w-full flex items-center justify-between p-3 text-xs text-left hover:bg-zinc-800/40 transition"
          >
            <div className="flex items-center gap-2 text-zinc-200 font-medium">
              <Key className="h-3.5 w-3.5 text-amber-400" />
              <span>BYOT dual identity (optional)</span>
              <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-wider">
                IDOR A↔B
              </span>
            </div>
            {showByot ? (
              <ChevronDown className="h-4 w-4 text-zinc-400" />
            ) : (
              <ChevronRight className="h-4 w-4 text-zinc-400" />
            )}
          </button>
          {showByot && (
            <div className="p-3 pt-0 border-t border-zinc-800/60 space-y-3">
              <div className="flex items-start gap-2 rounded-md border border-amber-500/20 bg-amber-500/5 p-2 text-[10px] text-amber-300 font-mono">
                <Lock className="h-3 w-3 shrink-0 mt-0.5" />
                Ephemeral only — never persisted. For Supabase RLS: paste OBSERVED
                sb_publishable_… into apikey (anon; no user JWT required).
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                <input
                  type="text"
                  value={identityAId}
                  onChange={(e) => setIdentityAId(e.target.value)}
                  placeholder="identity_a id"
                  disabled={loading || isRunning}
                  className="rounded-md border border-zinc-800 bg-zinc-950 px-2 py-1.5 text-xs font-mono text-white"
                />
                <input
                  type="password"
                  autoComplete="off"
                  value={identityAApiKey}
                  onChange={(e) => setIdentityAApiKey(e.target.value)}
                  placeholder="apikey (sb_publishable_…)"
                  disabled={loading || isRunning}
                  className="rounded-md border border-zinc-800 bg-zinc-950 px-2 py-1.5 text-xs font-mono text-white"
                />
                <input
                  type="password"
                  autoComplete="off"
                  value={identityAAuthHeader}
                  onChange={(e) => setIdentityAAuthHeader(e.target.value)}
                  placeholder="Authorization (optional if apikey set)"
                  disabled={loading || isRunning}
                  className="rounded-md border border-zinc-800 bg-zinc-950 px-2 py-1.5 text-xs font-mono text-white"
                />
                <input
                  type="password"
                  autoComplete="off"
                  value={identityACookie}
                  onChange={(e) => setIdentityACookie(e.target.value)}
                  placeholder="Cookie"
                  disabled={loading || isRunning}
                  className="rounded-md border border-zinc-800 bg-zinc-950 px-2 py-1.5 text-xs font-mono text-white"
                />
              </div>
              <label className="flex items-center gap-2 text-xs text-zinc-400">
                <input
                  type="checkbox"
                  checked={enableIdentityB}
                  onChange={(e) => setEnableIdentityB(e.target.checked)}
                  disabled={loading || isRunning}
                  className="rounded border-zinc-700"
                />
                <UserCheck className="h-3.5 w-3.5 text-sky-400" />
                Enable Identity B (differential IDOR)
              </label>
              {enableIdentityB && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  <input
                    type="text"
                    value={identityBId}
                    onChange={(e) => setIdentityBId(e.target.value)}
                    placeholder="identity_b id"
                    disabled={loading || isRunning}
                    className="rounded-md border border-zinc-800 bg-zinc-950 px-2 py-1.5 text-xs font-mono text-white"
                  />
                  <input
                    type="password"
                    autoComplete="off"
                    value={identityBApiKey}
                    onChange={(e) => setIdentityBApiKey(e.target.value)}
                    placeholder="apikey (sb_publishable_…)"
                    disabled={loading || isRunning}
                    className="rounded-md border border-zinc-800 bg-zinc-950 px-2 py-1.5 text-xs font-mono text-white"
                  />
                  <input
                    type="password"
                    autoComplete="off"
                    value={identityBAuthHeader}
                    onChange={(e) => setIdentityBAuthHeader(e.target.value)}
                    placeholder="Authorization (optional if apikey set)"
                    disabled={loading || isRunning}
                    className="rounded-md border border-zinc-800 bg-zinc-950 px-2 py-1.5 text-xs font-mono text-white"
                  />
                  <input
                    type="password"
                    autoComplete="off"
                    value={identityBCookie}
                    onChange={(e) => setIdentityBCookie(e.target.value)}
                    placeholder="Cookie"
                    disabled={loading || isRunning}
                    className="rounded-md border border-zinc-800 bg-zinc-950 px-2 py-1.5 text-xs font-mono text-white"
                  />
                </div>
              )}
            </div>
          )}
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
                  if (domain === "teclaaa.vercel.app") {
                    setRelatedHostsInput("vawrzoncszqauzxwqide.supabase.co");
                    setSeedUrlsInput(
                      "https://vawrzoncszqauzxwqide.supabase.co/rest/v1/profiles\nhttps://vawrzoncszqauzxwqide.supabase.co/rest/v1/shop_items"
                    );
                    setSeedPathsInput("/carrera/93kpw, /login, /perfil");
                    setSkipSlowCrawl(true);
                    setShowAdvanced(true);
                  }
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
