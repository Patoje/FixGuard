"use client";

import React, { useState, useMemo } from "react";
import {
  Globe,
  Terminal,
  ExternalLink,
  Search,
  Copy,
  Check,
  Cpu,
  Layers,
  ShieldCheck,
  CornerDownLeft,
  Sparkles,
} from "lucide-react";
import type { TargetProfileDto, ProfileEndpointDto, DetectedTechnologyDto } from "@/lib/v2Api";

interface DiscoveredSurfaceViewerProps {
  readonly profile: TargetProfileDto | null;
  readonly targetDomain?: string;
  readonly onSendCurlToTerminal?: (curlCommand: string) => void;
}

export function DiscoveredSurfaceViewer({
  profile,
  targetDomain,
  onSendCurlToTerminal,
}: DiscoveredSurfaceViewerProps) {
  const [searchTerm, setSearchTerm] = useState("");
  const [filterType, setFilterType] = useState<"all" | "api" | "page" | "asset">("all");
  const [copiedUrl, setCopiedUrl] = useState<string | null>(null);

  const endpoints = useMemo(() => profile?.endpoints ?? [], [profile?.endpoints]);
  const technologies = useMemo(() => profile?.technologies ?? [], [profile?.technologies]);
  const detectedTechnologies = useMemo(
    () => profile?.detectedTechnologies ?? [],
    [profile?.detectedTechnologies]
  );
  const ecosystem = profile?.ecosystemProfile;

  const filteredEndpoints = useMemo(() => {
    return endpoints.filter((ep) => {
      const matchesSearch =
        ep.path.toLowerCase().includes(searchTerm.toLowerCase()) ||
        ep.url.toLowerCase().includes(searchTerm.toLowerCase()) ||
        (ep.parameters && ep.parameters.some((p) => p.toLowerCase().includes(searchTerm.toLowerCase())));

      if (!matchesSearch) return false;

      if (filterType === "api") {
        return (
          ep.path.includes("/api/") ||
          ep.path.includes("/rest/") ||
          ep.path.includes("/v1/") ||
          ep.path.includes("/graphql") ||
          ep.method !== "GET"
        );
      }
      if (filterType === "asset") {
        return (
          ep.path.endsWith(".js") ||
          ep.path.endsWith(".css") ||
          ep.path.endsWith(".json") ||
          ep.path.includes("/_next/") ||
          ep.path.includes("/assets/")
        );
      }
      if (filterType === "page") {
        return (
          !ep.path.includes("/api/") &&
          !ep.path.endsWith(".js") &&
          !ep.path.endsWith(".css") &&
          !ep.path.includes("/_next/")
        );
      }
      return true;
    });
  }, [endpoints, searchTerm, filterType]);

  const handleCopy = async (url: string) => {
    try {
      await navigator.clipboard.writeText(url);
      setCopiedUrl(url);
      setTimeout(() => setCopiedUrl(null), 2000);
    } catch {
      // ignore
    }
  };

  const handleLoadInTerminal = (ep: ProfileEndpointDto) => {
    const method = ep.method || "GET";
    const cmd =
      method === "GET"
        ? `curl -s -i "${ep.url}"`
        : `curl -s -i -X ${method} "${ep.url}" -H "Content-Type: application/json" -d '{}'`;
    onSendCurlToTerminal?.(cmd);
  };

  if (!profile && endpoints.length === 0) {
    return (
      <div className="rounded-xl border border-zinc-900 bg-zinc-950/60 p-6 text-center">
        <Globe className="h-8 w-8 text-zinc-600 mx-auto mb-2" />
        <p className="text-xs font-mono text-zinc-400">
          No se ha cargado el Target Profile para {targetDomain || "este assessment"}.
        </p>
        <p className="text-[11px] text-zinc-600 mt-1">
          Asegurate de que las etapas de Active Recon se hayan completado para indexar las rutas y tecnologías.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Top Banner: Detected Tech & Surface Summary */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {/* Metric: Endpoints */}
        <div className="rounded-xl border border-zinc-800/80 bg-zinc-900/40 p-3.5 flex items-center justify-between">
          <div>
            <span className="block text-[11px] font-mono uppercase tracking-wider text-zinc-400">
              Rutas Indexadas
            </span>
            <span className="text-2xl font-mono font-bold text-emerald-400">
              {endpoints.length}
            </span>
            <span className="block text-[10px] text-zinc-500 mt-0.5">
              Descubiertas en crawling & AST
            </span>
          </div>
          <div className="h-10 w-10 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
            <Globe className="h-5 w-5 text-emerald-400" />
          </div>
        </div>

        {/* Metric: Framework / Architecture */}
        <div className="rounded-xl border border-zinc-800/80 bg-zinc-900/40 p-3.5 flex items-center justify-between">
          <div>
            <span className="block text-[11px] font-mono uppercase tracking-wider text-zinc-400">
              Arquitectura / Stack
            </span>
            <div className="flex items-center gap-1.5 mt-0.5">
              <span className="text-sm font-semibold text-zinc-100">
                {ecosystem?.spaFramework ? ecosystem.spaFramework.toUpperCase() : ecosystem?.hasSpa ? "SPA / JAMstack" : "Web Application"}
              </span>
              {ecosystem?.hasSupabase && (
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                  Supabase
                </span>
              )}
              {ecosystem?.hasGraphQL && (
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-pink-500/20 text-pink-300 border border-pink-500/40">
                  GraphQL
                </span>
              )}
            </div>
            <span className="block text-[10px] text-zinc-500 mt-0.5">
              {ecosystem?.hasCms ? `CMS: ${ecosystem.cmsType || "detectado"}` : "Sin CMS legacy"}
            </span>
          </div>
          <div className="h-10 w-10 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center">
            <Cpu className="h-5 w-5 text-blue-400" />
          </div>
        </div>

        {/* Metric: Tech Signatures */}
        <div className="rounded-xl border border-zinc-800/80 bg-zinc-900/40 p-3.5 flex items-center justify-between">
          <div>
            <span className="block text-[11px] font-mono uppercase tracking-wider text-zinc-400">
              Tecnologías Identificadas
            </span>
            <span className="text-2xl font-mono font-bold text-purple-400">
              {technologies.length}
            </span>
            <span className="block text-[10px] text-zinc-500 mt-0.5">
              Firmas de headers y scripts
            </span>
          </div>
          <div className="h-10 w-10 rounded-lg bg-purple-500/10 border border-purple-500/20 flex items-center justify-center">
            <Layers className="h-5 w-5 text-purple-400" />
          </div>
        </div>
      </div>

      {/* Technology Pills */}
      {technologies.length > 0 && (
        <div className="rounded-xl border border-zinc-800/70 bg-zinc-950/60 p-3">
          <div className="flex items-center gap-2 mb-2 text-xs font-semibold text-zinc-300">
            <Sparkles className="h-3.5 w-3.5 text-amber-400" />
            <span>Firmas de Software & Infraestructura:</span>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {technologies.map((tech) => (
              <span
                key={tech}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md border border-zinc-700/70 bg-zinc-900/90 text-xs font-mono text-zinc-200"
              >
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                {tech}
              </span>
            ))}
            {detectedTechnologies.map((dt) => (
              <span
                key={`${dt.name}-${dt.version || ""}`}
                className="inline-flex items-center gap-1 px-2 py-0.5 rounded border border-blue-500/30 bg-blue-500/10 text-[11px] font-mono text-blue-300"
                title={`Categoría: ${dt.category} | Detección: ${dt.detectionSignal}`}
              >
                <span>{dt.name}</span>
                {dt.version && <span className="text-blue-400/70">v{dt.version}</span>}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-2.5 pt-1">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-zinc-500" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Filtrar por ruta, URL o parámetro (ej. /api, id, auth)..."
            className="w-full rounded-lg border border-zinc-800 bg-zinc-900/90 pl-9 pr-3 py-1.5 text-xs text-zinc-100 placeholder:text-zinc-500 focus:border-zinc-600 focus:outline-none focus:ring-1 focus:ring-zinc-600 font-mono"
          />
        </div>

        <div className="flex items-center gap-1 bg-zinc-900/90 p-1 rounded-lg border border-zinc-800">
          <button
            type="button"
            onClick={() => setFilterType("all")}
            className={`px-2.5 py-1 rounded text-xs font-mono transition ${
              filterType === "all"
                ? "bg-zinc-800 text-white font-medium shadow-sm"
                : "text-zinc-400 hover:text-zinc-200"
            }`}
          >
            Todas ({endpoints.length})
          </button>
          <button
            type="button"
            onClick={() => setFilterType("page")}
            className={`px-2.5 py-1 rounded text-xs font-mono transition ${
              filterType === "page"
                ? "bg-zinc-800 text-white font-medium shadow-sm"
                : "text-zinc-400 hover:text-zinc-200"
            }`}
          >
            Vistas / Páginas
          </button>
          <button
            type="button"
            onClick={() => setFilterType("api")}
            className={`px-2.5 py-1 rounded text-xs font-mono transition ${
              filterType === "api"
                ? "bg-zinc-800 text-white font-medium shadow-sm"
                : "text-zinc-400 hover:text-zinc-200"
            }`}
          >
            APIs / Dinámicas
          </button>
          <button
            type="button"
            onClick={() => setFilterType("asset")}
            className={`px-2.5 py-1 rounded text-xs font-mono transition ${
              filterType === "asset"
                ? "bg-zinc-800 text-white font-medium shadow-sm"
                : "text-zinc-400 hover:text-zinc-200"
            }`}
          >
            Assets JS
          </button>
        </div>
      </div>

      {/* Endpoints Table */}
      {filteredEndpoints.length === 0 ? (
        <div className="rounded-xl border border-zinc-900 bg-zinc-950/40 p-8 text-center text-xs text-zinc-500 font-mono">
          {searchTerm
            ? "No se encontraron rutas que coincidan con la búsqueda."
            : "No hay rutas indexadas bajo este filtro."}
        </div>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-zinc-800/80 bg-zinc-950/40">
          <table className="w-full text-left text-xs font-mono">
            <thead className="border-b border-zinc-800 bg-zinc-900/80 text-zinc-400">
              <tr>
                <th className="py-2.5 px-3 w-16">Método</th>
                <th className="py-2.5 px-3">Ruta / Path</th>
                <th className="py-2.5 px-3 w-28">Autenticación</th>
                <th className="py-2.5 px-3">Parámetros</th>
                <th className="py-2.5 px-3 text-right w-40">Acción Táctica</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-900/90">
              {filteredEndpoints.map((ep, idx) => {
                const methodColor =
                  ep.method === "GET"
                    ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                    : ep.method === "POST"
                    ? "bg-blue-500/10 text-blue-400 border-blue-500/30"
                    : ep.method === "OPTIONS"
                    ? "bg-purple-500/10 text-purple-400 border-purple-500/30"
                    : "bg-zinc-800 text-zinc-300 border-zinc-700";

                return (
                  <tr
                    key={`${ep.method}-${ep.path}-${idx}`}
                    className="hover:bg-zinc-900/40 transition group"
                  >
                    <td className="py-2.5 px-3">
                      <span
                        className={`inline-block rounded px-1.5 py-0.5 text-[10px] font-bold border ${methodColor}`}
                      >
                        {ep.method}
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      <div className="flex items-center gap-1.5">
                        <span className="text-zinc-100 font-medium group-hover:text-emerald-300 transition">
                          {ep.path}
                        </span>
                        <a
                          href={ep.url}
                          target="_blank"
                          rel="noreferrer"
                          className="opacity-0 group-hover:opacity-100 text-zinc-500 hover:text-zinc-300 transition"
                          title="Abrir URL en pestaña nueva"
                        >
                          <ExternalLink className="h-3 w-3" />
                        </a>
                      </div>
                      <div className="text-[10px] text-zinc-500 truncate max-w-md">
                        {ep.url}
                      </div>
                    </td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] ${
                          ep.authRequirement === "session" || ep.authRequirement === "token"
                            ? "bg-amber-500/10 text-amber-300 border border-amber-500/30"
                            : ep.authRequirement === "none"
                            ? "bg-zinc-900 text-zinc-400 border border-zinc-800"
                            : "bg-zinc-900/60 text-zinc-500"
                        }`}
                      >
                        {ep.authRequirement === "session" || ep.authRequirement === "token" ? (
                          <ShieldCheck className="h-2.5 w-2.5 text-amber-400" />
                        ) : null}
                        <span>{ep.authRequirement || "unknown"}</span>
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      {ep.parameters && ep.parameters.length > 0 ? (
                        <div className="flex flex-wrap gap-1">
                          {ep.parameters.map((p) => (
                            <span
                              key={p}
                              className="rounded bg-zinc-900 border border-zinc-800 px-1.5 py-0.5 text-[10px] text-zinc-300 font-mono"
                            >
                              {p}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span className="text-zinc-600 text-[11px]">—</span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        <button
                          type="button"
                          onClick={() => handleCopy(ep.url)}
                          className="inline-flex items-center gap-1 rounded border border-zinc-800 bg-zinc-900/80 px-2 py-1 text-[11px] text-zinc-400 hover:text-zinc-200 hover:border-zinc-700 transition"
                          title="Copiar URL"
                        >
                          {copiedUrl === ep.url ? (
                            <Check className="h-3 w-3 text-emerald-400" />
                          ) : (
                            <Copy className="h-3 w-3" />
                          )}
                        </button>
                        <button
                          type="button"
                          onClick={() => handleLoadInTerminal(ep)}
                          className="inline-flex items-center gap-1 rounded border border-emerald-500/30 bg-emerald-500/10 px-2 py-1 text-[11px] font-medium text-emerald-300 hover:bg-emerald-500/20 transition"
                          title="Cargar curl en consola interactiva"
                        >
                          <Terminal className="h-3 w-3 text-emerald-400" />
                          <span>Probar</span>
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
