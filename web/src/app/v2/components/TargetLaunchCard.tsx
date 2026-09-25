"use client";

import React, { useState } from "react";
import {
  Globe,
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

/** OBSERVED Teclaaa backend — applied quietly so RLS path works without opening advanced. */
const TECLAAA_SUPABASE = "vawrzoncszqauzxwqide.supabase.co";

const KNOWN_TARGET_DEFAULTS: Record<
  string,
  {
    relatedHosts: string;
    seedUrls: string;
    seedPaths: string;
    skipSlowCrawl: boolean;
  }
> = {
  "teclaaa.vercel.app": {
    relatedHosts: TECLAAA_SUPABASE,
    seedUrls: `https://${TECLAAA_SUPABASE}/rest/v1/profiles\nhttps://${TECLAAA_SUPABASE}/rest/v1/shop_items`,
    seedPaths: "/carrera/93kpw, /login, /perfil",
    skipSlowCrawl: true,
  },
};

const PRESETS = ["teclaaa.vercel.app", "charmarket.vercel.app"] as const;

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

function parseHostList(input: string): string[] {
  return input
    .split(/[\s,;]+/)
    .map((h) =>
      h
        .trim()
        .toLowerCase()
        .replace(/^https?:\/\//, "")
        .replace(/\/.*$/, "")
    )
    .filter((h) => h.length > 0 && /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(h));
}

function parseSeedUrls(input: string): string[] {
  return input
    .split(/[\n,;]+/)
    .map((u) => u.trim())
    .filter((u) => /^https?:\/\/.+/i.test(u));
}

function parseSeedPaths(input: string): string[] {
  return input
    .split(/[\s,;]+/)
    .map((p) => p.trim())
    .filter((p) => p.startsWith("/"));
}

function applyKnownDefaults(domain: string) {
  const known = KNOWN_TARGET_DEFAULTS[domain];
  if (!known) {
    return {
      relatedHosts: "",
      seedUrls: "",
      seedPaths: "",
      skipSlowCrawl: true,
    };
  }
  return {
    relatedHosts: known.relatedHosts,
    seedUrls: known.seedUrls,
    seedPaths: known.seedPaths,
    skipSlowCrawl: known.skipSlowCrawl,
  };
}

export function TargetLaunchCard({
  onAssessmentStarted,
  isRunning,
  activeDomain,
  activeAssessmentId,
}: TargetLaunchCardProps) {
  const initialDefaults = applyKnownDefaults("teclaaa.vercel.app");
  const [domainInput, setDomainInput] = useState<string>("teclaaa.vercel.app");
  const [actorId, setActorId] = useState<string>("usr_secops_lead");
  const [relatedHostsInput, setRelatedHostsInput] = useState<string>(
    initialDefaults.relatedHosts
  );
  const [seedUrlsInput, setSeedUrlsInput] = useState<string>(
    initialDefaults.seedUrls
  );
  const [seedPathsInput, setSeedPathsInput] = useState<string>(
    initialDefaults.seedPaths
  );
  const [skipSlowCrawl, setSkipSlowCrawl] = useState<boolean>(
    initialDefaults.skipSlowCrawl
  );
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

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

  const applyPreset = (domain: string) => {
    setDomainInput(domain);
    const defaults = applyKnownDefaults(domain);
    setRelatedHostsInput(defaults.relatedHosts);
    setSeedUrlsInput(defaults.seedUrls);
    setSeedPathsInput(defaults.seedPaths);
    setSkipSlowCrawl(defaults.skipSlowCrawl);
    setError(null);
  };

  const handleLaunch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!isValidFormat) {
      setError("Ingresá un dominio público válido (ej. teclaaa.vercel.app)");
      return;
    }
    if (isSsrfRisk) {
      setError(
        `Egress bloqueó '${cleaned}' (privado/loopback). Usá un target público autorizado.`
      );
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const known = KNOWN_TARGET_DEFAULTS[cleaned];

      let sessionIdentities: ByotSessionIdentityBundleDto | undefined;
      if (
        identityAAuthHeader.trim() ||
        identityAApiKey.trim() ||
        identityACookie.trim()
      ) {
        const headersA: Record<string, string> = {};
        if (identityAAuthHeader.trim()) {
          headersA["authorization"] = identityAAuthHeader.trim();
        }
        if (identityAApiKey.trim()) {
          headersA["apikey"] = identityAApiKey.trim();
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
            ...(Object.keys(headersB).length > 0
              ? { injectHeaders: headersB }
              : {}),
            ...(Object.keys(cookiesB).length > 0
              ? { injectCookies: cookiesB }
              : {}),
          };
        }

        sessionIdentities = {
          identityA: {
            identityId: identityAId.trim() || "operator_identity_a",
            ...(Object.keys(headersA).length > 0
              ? { injectHeaders: headersA }
              : {}),
            ...(Object.keys(cookiesA).length > 0
              ? { injectCookies: cookiesA }
              : {}),
          },
          ...(identityB ? { identityB } : {}),
        };
      }

      // Soft-default: known targets keep RLS path even if advanced stays closed/cleared.
      let relatedAllowedHosts = parseHostList(relatedHostsInput);
      if (relatedAllowedHosts.length === 0 && known) {
        relatedAllowedHosts = parseHostList(known.relatedHosts);
      }

      let seedUrls = parseSeedUrls(seedUrlsInput);
      if (seedUrls.length === 0 && known) {
        seedUrls = parseSeedUrls(known.seedUrls);
      }

      let seedPaths = parseSeedPaths(seedPathsInput);
      if (seedPaths.length === 0 && known) {
        seedPaths = parseSeedPaths(known.seedPaths);
      }

      const effectiveSkip =
        skipSlowCrawl || (known?.skipSlowCrawl ?? false);
      const skipStages = effectiveSkip
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
            `SSRF egress: '${cleaned}' resuelve a IP restringida. Assessment abortado.`
          );
        } else if (err.errorType === "V2GatewayUnreachable" || err.status === 0) {
          setError(
            "V2 API Gateway no responde. Ejecutá: cd worker && npm run dev (puerto 4000)."
          );
        } else {
          setError(`[${err.errorType}] ${err.message}`);
        }
      } else {
        const msg =
          (err as Error).message || "No se pudo iniciar el assessment";
        if (/Failed to fetch|NetworkError|ECONNREFUSED/i.test(msg)) {
          setError(
            "V2 API Gateway no responde. Ejecutá: cd worker && npm run dev (puerto 4000)."
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
      <form onSubmit={handleLaunch} className="space-y-5">
        <div>
          <label
            htmlFor="targetDomain"
            className="block text-sm font-medium text-zinc-200"
          >
            Target
          </label>
          <div className="mt-2 flex flex-col gap-3 sm:flex-row sm:items-stretch">
            <div className="relative flex min-w-0 flex-1 rounded-lg shadow-sm">
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
                placeholder="https://tu-aplicacion.com"
                className={`block w-full rounded-r-lg border bg-zinc-900/60 px-3.5 py-3 text-base font-mono text-zinc-100 placeholder-zinc-600 focus:outline-none focus:ring-2 ${
                  domainInput && !isValidFormat
                    ? "border-rose-500/50 focus:border-rose-500 focus:ring-rose-500/20"
                    : "border-zinc-800 focus:border-emerald-500/50 focus:ring-emerald-500/20"
                }`}
                disabled={loading || isRunning}
                autoFocus
              />
            </div>
            <button
              type="submit"
              disabled={loading || isRunning || !isValidFormat}
              className="inline-flex shrink-0 items-center justify-center gap-2 rounded-lg bg-emerald-500 px-8 py-3 text-sm font-semibold text-zinc-950 transition hover:bg-emerald-400 focus:outline-none focus:ring-2 focus:ring-emerald-500/40 disabled:cursor-not-allowed disabled:opacity-40 shadow-lg shadow-emerald-500/20"
            >
              {loading ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Iniciando…
                </>
              ) : isRunning ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  En curso…
                </>
              ) : (
                <>
                  Iniciar
                  <ArrowRight className="h-4 w-4" />
                </>
              )}
            </button>
          </div>

          <div className="mt-3 flex flex-wrap items-center gap-2">
            {PRESETS.map((domain) => (
              <button
                key={domain}
                type="button"
                onClick={() => applyPreset(domain)}
                disabled={loading || isRunning}
                className={`rounded-md px-2 py-0.5 font-mono text-[11px] transition disabled:opacity-50 ${
                  cleanDomain(domainInput) === domain
                    ? "text-emerald-400/90"
                    : "text-zinc-600 hover:text-zinc-400"
                }`}
              >
                {domain.replace(".vercel.app", "")}
              </button>
            ))}
          </div>
        </div>

        <div className="rounded-lg border border-zinc-800/80 bg-zinc-900/30 overflow-hidden">
          <button
            type="button"
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="w-full flex items-center justify-between px-3.5 py-2.5 text-xs text-left hover:bg-zinc-800/30 transition"
          >
            <span className="text-zinc-500 font-medium">Opciones avanzadas</span>
            {showAdvanced ? (
              <ChevronDown className="h-3.5 w-3.5 text-zinc-600" />
            ) : (
              <ChevronRight className="h-3.5 w-3.5 text-zinc-600" />
            )}
          </button>

          {showAdvanced && (
            <div className="space-y-4 border-t border-zinc-800/60 p-3.5 pt-3">
              <div>
                <label
                  htmlFor="actorId"
                  className="block text-xs font-medium text-zinc-400"
                >
                  Operator ID
                </label>
                <input
                  id="actorId"
                  type="text"
                  value={actorId}
                  onChange={(e) => setActorId(e.target.value)}
                  placeholder="usr_operator"
                  className="mt-1.5 block w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs font-mono text-zinc-100 placeholder-zinc-600 focus:border-emerald-500/50 focus:outline-none focus:ring-2 focus:ring-emerald-500/20"
                  disabled={loading || isRunning}
                />
              </div>

              <div>
                <label
                  htmlFor="relatedAllowedHosts"
                  className="block text-xs font-medium text-zinc-400"
                >
                  Related hosts{" "}
                  <span className="font-normal text-zinc-600">
                    (Supabase / APIs)
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
                  className="mt-1.5 block w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs font-mono text-zinc-100 placeholder-zinc-600 focus:border-emerald-500/50 focus:outline-none focus:ring-2 focus:ring-emerald-500/20"
                  disabled={loading || isRunning}
                />
                <p className="mt-1 text-[10px] text-zinc-600">
                  Teclaaa: si dejás vacío, se usa{" "}
                  <span className="font-mono text-zinc-500">
                    {TECLAAA_SUPABASE}
                  </span>{" "}
                  al iniciar. Otros targets: agregá el host explícitamente — no
                  inventamos Supabase desde *.vercel.app.
                </p>
              </div>

              <label className="flex items-start gap-2 text-xs text-zinc-400">
                <input
                  type="checkbox"
                  checked={skipSlowCrawl}
                  onChange={(e) => setSkipSlowCrawl(e.target.checked)}
                  disabled={loading || isRunning}
                  className="mt-0.5 rounded border-zinc-700"
                />
                <span>
                  Skip ports + crawl lento (recomendado SPA / RLS)
                </span>
              </label>

              <div>
                <label
                  htmlFor="seedUrls"
                  className="block text-xs font-medium text-zinc-400"
                >
                  Seed URLs
                </label>
                <textarea
                  id="seedUrls"
                  rows={2}
                  value={seedUrlsInput}
                  onChange={(e) => setSeedUrlsInput(e.target.value)}
                  placeholder="https://project.supabase.co/rest/v1/…"
                  disabled={loading || isRunning}
                  className="mt-1.5 block w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs font-mono text-zinc-100 placeholder-zinc-600 focus:border-emerald-500/50 focus:outline-none focus:ring-2 focus:ring-emerald-500/20"
                />
              </div>

              <div>
                <label
                  htmlFor="seedPaths"
                  className="block text-xs font-medium text-zinc-400"
                >
                  Seed paths
                </label>
                <input
                  id="seedPaths"
                  type="text"
                  value={seedPathsInput}
                  onChange={(e) => setSeedPathsInput(e.target.value)}
                  placeholder="/login, /perfil"
                  disabled={loading || isRunning}
                  className="mt-1.5 block w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs font-mono text-zinc-100 placeholder-zinc-600 focus:border-emerald-500/50 focus:outline-none focus:ring-2 focus:ring-emerald-500/20"
                />
              </div>

              <div className="rounded-lg border border-zinc-800/80 bg-zinc-950/50 overflow-hidden">
                <div className="flex items-center gap-2 px-3 py-2 text-xs text-zinc-400">
                  <Key className="h-3.5 w-3.5 text-amber-500/80" />
                  <span>BYOT / identidades (opcional)</span>
                </div>
                <div className="space-y-3 border-t border-zinc-800/60 p-3">
                  <div className="flex items-start gap-2 rounded-md border border-zinc-800 bg-zinc-900/40 p-2 text-[10px] text-zinc-500 font-mono">
                    <Lock className="h-3 w-3 shrink-0 mt-0.5" />
                    Efímero — no se persiste. Supabase RLS anon: apikey
                    sb_publishable_… (sin JWT de usuario).
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
                      placeholder="Authorization (opcional)"
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
                  <label className="flex items-center gap-2 text-xs text-zinc-500">
                    <input
                      type="checkbox"
                      checked={enableIdentityB}
                      onChange={(e) => setEnableIdentityB(e.target.checked)}
                      disabled={loading || isRunning}
                      className="rounded border-zinc-700"
                    />
                    <UserCheck className="h-3.5 w-3.5 text-zinc-500" />
                    Identity B (IDOR diferencial)
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
                        onChange={(e) =>
                          setIdentityBAuthHeader(e.target.value)
                        }
                        placeholder="Authorization (opcional)"
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
              </div>
            </div>
          )}
        </div>

        {error && (
          <div className="flex items-start gap-2 rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-300">
            <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}
      </form>

      {activeAssessmentId && activeDomain && (
        <div className="mt-5 rounded-lg border border-zinc-800 bg-zinc-900/40 p-3 text-xs text-zinc-500">
          <div className="flex items-center justify-between gap-2">
            <span>En curso</span>
            <span className="font-mono text-emerald-400/90 truncate">
              {activeDomain}
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
