"use client";

import React, { useState } from "react";
import {
  Globe,
  AlertTriangle,
  ArrowRight,
  Loader2,
  Key,
  ChevronDown,
  ChevronRight,
  UserCheck,
} from "lucide-react";
import {
  startOrchestratedAssessment,
  V2ApiError,
  type StartOrchestratedAssessmentResponse,
  type ByotIdentityDto,
  type ByotSessionIdentityBundleDto,
} from "@/lib/v2Api";

interface AssessmentLauncherCardProps {
  onAssessmentStarted: (
    data: StartOrchestratedAssessmentResponse,
    domain: string
  ) => void;
  isRunning: boolean;
}

const TECLAAA_SUPABASE = "vawrzoncszqauzxwqide.supabase.co";

/** Soft-defaults only — never skip Stage 2/4; full recon is the default.
 * seedUrls are soft rest fallbacks; prefer live OBSERVED JS/OpenAPI when available.
 */
const KNOWN_TARGET_DEFAULTS: Record<
  string,
  {
    relatedHosts: string;
    seedUrls?: string[];
    seedPaths?: string[];
  }
> = {
  "teclaaa.vercel.app": {
    relatedHosts: TECLAAA_SUPABASE,
    seedUrls: [
      `https://${TECLAAA_SUPABASE}/rest/v1/profiles`,
      `https://${TECLAAA_SUPABASE}/rest/v1/shop_items`,
    ],
    seedPaths: ["/carrera/93kpw", "/login", "/perfil"],
  },
};

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

function mapTokenOrCookie(raw: string): {
  headers: Record<string, string>;
  cookies: Record<string, string>;
} {
  const headers: Record<string, string> = {};
  const cookies: Record<string, string> = {};
  const value = raw.trim();
  if (!value) return { headers, cookies };

  const lower = value.toLowerCase();
  if (
    lower.startsWith("bearer ") ||
    lower.startsWith("basic ") ||
    /^eyj[a-z0-9_-]+\.[a-z0-9_-]+\.[a-z0-9_-]+$/i.test(value)
  ) {
    headers["authorization"] = lower.startsWith("bearer ")
      ? value
      : `Bearer ${value}`;
    return { headers, cookies };
  }

  if (value.includes("=") && !value.includes(" ")) {
    const [k, ...v] = value.split("=");
    cookies[k.trim()] = v.join("=").trim();
    return { headers, cookies };
  }

  if (value.includes("=")) {
    const first = value.split(";")[0] ?? value;
    const [k, ...v] = first.split("=");
    cookies[k.trim()] = v.join("=").trim();
    return { headers, cookies };
  }

  headers["authorization"] = `Bearer ${value}`;
  cookies["session"] = value;
  return { headers, cookies };
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

export function AssessmentLauncherCard({
  onAssessmentStarted,
  isRunning,
}: AssessmentLauncherCardProps) {
  const [domainInput, setDomainInput] = useState<string>("teclaaa.vercel.app");
  const [actorId, setActorId] = useState<string>("usr_secops_lead");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const [byotUsuario, setByotUsuario] = useState("");
  const [byotTokenOrCookie, setByotTokenOrCookie] = useState("");
  const [enableIdentityB, setEnableIdentityB] = useState(false);
  const [byotUsuarioB, setByotUsuarioB] = useState("");
  const [byotTokenOrCookieB, setByotTokenOrCookieB] = useState("");

  const cleaned = cleanDomain(domainInput);
  const isValidFormat =
    cleaned.length > 2 && /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(cleaned);
  const isSsrfRisk = isPrivateOrLoopbackHost(cleaned);

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
      if (byotTokenOrCookie.trim() || byotUsuario.trim()) {
        const mapped = mapTokenOrCookie(byotTokenOrCookie);
        const identityId = byotUsuario.trim() || "operator_identity_a";

        let identityB: ByotIdentityDto | undefined;
        if (
          enableIdentityB &&
          (byotTokenOrCookieB.trim() || byotUsuarioB.trim())
        ) {
          const mappedB = mapTokenOrCookie(byotTokenOrCookieB);
          identityB = {
            identityId: byotUsuarioB.trim() || "operator_identity_b",
            ...(Object.keys(mappedB.headers).length > 0
              ? { injectHeaders: mappedB.headers }
              : {}),
            ...(Object.keys(mappedB.cookies).length > 0
              ? { injectCookies: mappedB.cookies }
              : {}),
          };
        }

        sessionIdentities = {
          identityA: {
            identityId,
            ...(Object.keys(mapped.headers).length > 0
              ? { injectHeaders: mapped.headers }
              : {}),
            ...(Object.keys(mapped.cookies).length > 0
              ? { injectCookies: mapped.cookies }
              : {}),
          },
          ...(identityB ? { identityB } : {}),
        };
      }

      const relatedAllowedHosts = known
        ? parseHostList(known.relatedHosts)
        : [];
      const seedUrls = known?.seedUrls ?? [];
      const seedPaths = known?.seedPaths ?? [];

      const result = await startOrchestratedAssessment({
        targetDomain: cleaned,
        actorId: actorId.trim() || undefined,
        ...(sessionIdentities ? { sessionIdentities } : {}),
        ...(relatedAllowedHosts.length > 0
          ? { relatedAllowedHosts }
          : {}),
        ...(seedUrls.length > 0 ? { seedUrls } : {}),
        ...(seedPaths.length > 0 ? { seedPaths } : {}),
      });
      onAssessmentStarted(result, cleaned);
    } catch (err) {
      if (err instanceof V2ApiError) {
        if (err.reasonCode === "ssrf_target_blocked") {
          setError(
            `SSRF egress: '${cleaned}' resuelve a IP restringida. Assessment abortado.`
          );
        } else if (
          err.errorType === "V2GatewayUnreachable" ||
          err.status === 0
        ) {
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
        {error && (
          <div className="flex items-start gap-2.5 rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-300">
            <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        <div>
          <label
            htmlFor="targetDomain"
            className="block text-sm font-medium text-zinc-200"
          >
            Target
          </label>
          <div className="mt-2 flex flex-col gap-3 sm:flex-row sm:items-stretch">
            <div className="relative flex min-w-0 flex-1">
              <Globe className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-500" />
              <input
                id="targetDomain"
                type="text"
                value={domainInput}
                onChange={(e) => {
                  setDomainInput(e.target.value);
                  if (error) setError(null);
                }}
                placeholder="https://tu-aplicacion.com"
                disabled={loading || isRunning}
                autoFocus
                className="w-full rounded-lg border border-zinc-800 bg-zinc-900/80 py-3 pl-10 pr-4 text-base font-mono text-white placeholder-zinc-600 focus:border-emerald-500/60 focus:outline-none focus:ring-2 focus:ring-emerald-500/20 transition disabled:opacity-50"
              />
            </div>
            <button
              type="submit"
              disabled={loading || isRunning || !isValidFormat}
              className="inline-flex shrink-0 items-center justify-center gap-2 rounded-lg bg-emerald-500 px-8 py-3 text-sm font-semibold text-zinc-950 shadow-lg shadow-emerald-500/20 transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-40"
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
                  disabled={loading || isRunning}
                  className="mt-1.5 w-full rounded-lg border border-zinc-800 bg-zinc-950 py-2 px-3 text-xs font-mono text-white placeholder-zinc-600 focus:border-emerald-500/60 focus:outline-none"
                />
              </div>

              <div className="rounded-lg border border-zinc-800/80 bg-zinc-950/50 overflow-hidden">
                <div className="flex items-center gap-2 px-3 py-2 text-xs text-zinc-400">
                  <Key className="h-3.5 w-3.5 text-emerald-500/80" />
                  <span>Sesión del target (opcional)</span>
                </div>
                <div className="space-y-3 border-t border-zinc-800/60 p-3">
                  <p className="text-[11px] text-zinc-500 leading-relaxed">
                    Si tenés una cuenta de prueba, pegá usuario y cookie/token
                    para revisar como usuario autenticado.
                  </p>
                  <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
                    <input
                      type="text"
                      value={byotUsuario}
                      onChange={(e) => setByotUsuario(e.target.value)}
                      placeholder="Usuario (email / nombre)"
                      disabled={loading || isRunning}
                      className="rounded-md border border-zinc-800 bg-zinc-950 px-2 py-1.5 text-xs text-white placeholder-zinc-600"
                    />
                    <input
                      type="password"
                      autoComplete="off"
                      value={byotTokenOrCookie}
                      onChange={(e) => setByotTokenOrCookie(e.target.value)}
                      placeholder="Cookie / Token"
                      disabled={loading || isRunning}
                      className="rounded-md border border-zinc-800 bg-zinc-950 px-2 py-1.5 text-xs font-mono text-white placeholder-zinc-600"
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
                    Segunda identidad (comparar dos usuarios)
                  </label>
                  {enableIdentityB && (
                    <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
                      <input
                        type="text"
                        value={byotUsuarioB}
                        onChange={(e) => setByotUsuarioB(e.target.value)}
                        placeholder="Usuario B"
                        disabled={loading || isRunning}
                        className="rounded-md border border-zinc-800 bg-zinc-950 px-2 py-1.5 text-xs text-white placeholder-zinc-600"
                      />
                      <input
                        type="password"
                        autoComplete="off"
                        value={byotTokenOrCookieB}
                        onChange={(e) =>
                          setByotTokenOrCookieB(e.target.value)
                        }
                        placeholder="Cookie / Token B"
                        disabled={loading || isRunning}
                        className="rounded-md border border-zinc-800 bg-zinc-950 px-2 py-1.5 text-xs font-mono text-white placeholder-zinc-600"
                      />
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      </form>
    </div>
  );
}
