"use client";

import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Scan, ShieldAlert, Zap, Code, ShieldCheck, ArrowRight, Key, CheckCircle2, Globe, AlertTriangle } from "lucide-react";
import { ScanMode } from "../types";

interface HeroScannerProps {
  onScan: (url: string, mode: ScanMode) => void;
  isScanning: boolean;
}

interface Authorization {
  id: number;
  userId: number;
  targetDomain: string;
  authorizedAt: string;
}

const MODES: { id: ScanMode; label: string; icon: any; color: string; desc: string }[] = [
  { id: "passive", label: "Pasivo (OSINT)", icon: ShieldCheck, color: "text-emerald-500", desc: "Análisis silencioso sin romper nada." },
  { id: "active", label: "Activo", icon: Zap, color: "text-blue-500", desc: "Payloads seguros. Descubre fallas obvias." },
  { id: "aggressive", label: "Agresivo", icon: ShieldAlert, color: "text-rose-500", desc: "Escaneo profundo y ruidoso." },
  { id: "sast", label: "Código Fuente", icon: Code, color: "text-violet-500", desc: "Análisis interno (Caja Blanca)." },
];

export default function HeroScanner({ onScan, isScanning }: HeroScannerProps) {
  const [url, setUrl] = useState("");
  const [step, setStep] = useState<"input" | "auth" | "mode">("input");
  const [mode, setMode] = useState<ScanMode>("passive");
  const [authType, setAuthType] = useState<"none" | "cookie" | "jwt">("none");
  const [authToken, setAuthToken] = useState("");
  const [isSavingAuth, setIsSavingAuth] = useState(false);

  // --- Authorization state ---
  const [aggressiveConsent, setAggressiveConsent] = useState(false);
  const [isSavingConsent, setIsSavingConsent] = useState(false);
  const [consentSaved, setConsentSaved] = useState(false);
  const [authorizedDomains, setAuthorizedDomains] = useState<Authorization[]>([]);
  const [loadingDomains, setLoadingDomains] = useState(false);
  const [urlAlreadyAuthorized, setUrlAlreadyAuthorized] = useState(false);

  const fetchAuthorizedDomains = useCallback(async () => {
    setLoadingDomains(true);
    try {
      const res = await fetch("/api/authorizations");
      if (res.ok) {
        const data = await res.json();
        setAuthorizedDomains(data.authorizations || []);
      }
    } catch {
      // silent
    } finally {
      setLoadingDomains(false);
    }
  }, []);

  // When stepping to "mode", fetch authorized domains
  useEffect(() => {
    if (step === "mode") {
      fetchAuthorizedDomains();
    }
  }, [step, fetchAuthorizedDomains]);

  // Check if current URL domain is already authorized
  useEffect(() => {
    if (!url || authorizedDomains.length === 0) {
      setUrlAlreadyAuthorized(false);
      return;
    }
    try {
      let normalized = url.trim();
      if (!normalized.startsWith("http://") && !normalized.startsWith("https://")) {
        normalized = `https://${normalized}`;
      }
      const hostname = new URL(normalized).hostname;
      const isAuth = authorizedDomains.some(
        (r) => r.targetDomain === hostname || hostname.endsWith(`.${r.targetDomain}`)
      );
      setUrlAlreadyAuthorized(isAuth);
    } catch {
      setUrlAlreadyAuthorized(false);
    }
  }, [url, authorizedDomains]);

  // Reset consent when mode changes away from aggressive
  useEffect(() => {
    if (mode !== "aggressive") {
      setAggressiveConsent(false);
      setConsentSaved(false);
    }
  }, [mode]);

  const handleContinue = (e: React.FormEvent) => {
    e.preventDefault();
    if (url.trim()) {
      setStep("auth");
    }
  };

  const handleAuthSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (authType !== "none" && authToken.trim()) {
      setIsSavingAuth(true);
      try {
        await fetch("/api/auth-session", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ targetUrl: url, authType, tokenOrCookie: authToken }),
        });
      } catch (err) {
        console.error("Error saving auth:", err);
      } finally {
        setIsSavingAuth(false);
      }
    }
    setStep("mode");
  };

  const handleAggressiveConsent = async (checked: boolean) => {
    setAggressiveConsent(checked);
    if (!checked) {
      setConsentSaved(false);
      return;
    }

    // Auto-register domain when consent is checked
    setIsSavingConsent(true);
    try {
      const res = await fetch("/api/authorizations", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: url }),
      });
      if (res.ok || res.status === 200) {
        setConsentSaved(true);
        await fetchAuthorizedDomains();
      }
    } catch {
      // If network error, still allow (UI consent is registered)
    } finally {
      setIsSavingConsent(false);
    }
  };

  const handleScan = (e: React.FormEvent) => {
    e.preventDefault();
    if (url.trim()) {
      // Normalize: if the user typed a bare hostname (no protocol), add https://
      let normalizedUrl = url.trim();
      if (!normalizedUrl.startsWith('http://') && !normalizedUrl.startsWith('https://') && !normalizedUrl.startsWith('/')) {
        normalizedUrl = `https://${normalizedUrl}`;
      }
      onScan(normalizedUrl, mode);
    }
  };

  const isAggressiveBlocked = mode === "aggressive" && !aggressiveConsent && !urlAlreadyAuthorized;

  return (
    <div className="w-full max-w-4xl mx-auto flex flex-col items-center justify-center pt-20 pb-10">
      <div className="text-center mb-10 space-y-4">
        <h1 className="text-5xl md:text-7xl font-bold tracking-tight">
          Fix<span className="text-zinc-500">Guard</span>
        </h1>
        <p className="text-zinc-400 text-lg max-w-xl mx-auto font-mono">
          Plataforma Híbrida de Auditoría de Seguridad. Analiza infraestructura moderna y descubre vulnerabilidades lógicas.
        </p>
      </div>

      <div className="w-full space-y-8 flex flex-col items-center">
        <AnimatePresence mode="wait">
          {step === "input" && (
            <motion.form
              key="input-form"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              transition={{ duration: 0.3 }}
              onSubmit={handleContinue}
              className="w-full flex flex-col items-center gap-8"
            >
              <div className="w-full max-w-2xl relative group">
                <div className="absolute -inset-0.5 bg-gradient-to-r from-zinc-800 to-zinc-700 rounded-xl blur opacity-30 group-hover:opacity-50 transition duration-500"></div>
                <input
                  type="text"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://ejemplo.com o ruta local"
                  className="relative w-full bg-zinc-950 border border-zinc-800 rounded-xl px-6 py-4 text-xl font-mono text-zinc-100 placeholder-zinc-600 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/50 transition-all disabled:opacity-50"
                  autoFocus
                />
              </div>

              <button
                type="submit"
                disabled={!url.trim()}
                className="relative bg-zinc-900 border border-zinc-800 px-10 py-3 text-zinc-300 hover:text-white rounded-full flex items-center gap-2 hover:bg-zinc-800 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <span className="text-lg font-bold font-mono tracking-widest uppercase">Continuar</span>
                <ArrowRight className="w-5 h-5" />
              </button>
            </motion.form>
          )}

          {step === "auth" && (
            <motion.form
              key="auth-form"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              transition={{ duration: 0.3 }}
              onSubmit={handleAuthSubmit}
              className="w-full flex flex-col items-center gap-6"
            >
              <div className="bg-zinc-900/50 border border-zinc-800 rounded-xl px-6 py-3 font-mono text-zinc-400 flex items-center gap-4 w-full max-w-2xl justify-between">
                <div className="flex gap-4">
                  <span className="text-zinc-500 text-sm">Objetivo:</span>
                  <span className="text-zinc-200 truncate max-w-[200px] sm:max-w-xs">{url}</span>
                </div>
                <button 
                  type="button" 
                  onClick={() => setStep("input")}
                  className="text-blue-500 text-sm hover:underline"
                >
                  Cambiar
                </button>
              </div>

              <div className="w-full max-w-2xl bg-zinc-900 border border-zinc-800 rounded-xl p-6">
                <div className="flex items-center gap-3 mb-6">
                  <Key className="w-6 h-6 text-emerald-500" />
                  <h2 className="text-xl font-bold text-zinc-100">Configurar Autenticación</h2>
                </div>
                <p className="text-zinc-400 mb-6 text-sm">
                  Proveer credenciales permite al motor escanear rutas protegidas, encontrando el 80% de los fallos (BOLA, BFLA, Mass Assignment) que requieren un usuario logueado.
                </p>

                <div className="flex gap-4 mb-6">
                  <button type="button" onClick={() => setAuthType('none')} className={`flex-1 py-2 rounded-lg border text-sm font-bold transition-all ${authType === 'none' ? 'bg-zinc-800 border-zinc-600 text-white' : 'bg-zinc-950 border-zinc-800 text-zinc-500 hover:text-zinc-300'}`}>Sin Autenticación</button>
                  <button type="button" onClick={() => setAuthType('cookie')} className={`flex-1 py-2 rounded-lg border text-sm font-bold transition-all ${authType === 'cookie' ? 'bg-emerald-900/30 border-emerald-500/50 text-emerald-400' : 'bg-zinc-950 border-zinc-800 text-zinc-500 hover:text-zinc-300'}`}>Cookie</button>
                  <button type="button" onClick={() => setAuthType('jwt')} className={`flex-1 py-2 rounded-lg border text-sm font-bold transition-all ${authType === 'jwt' ? 'bg-blue-900/30 border-blue-500/50 text-blue-400' : 'bg-zinc-950 border-zinc-800 text-zinc-500 hover:text-zinc-300'}`}>JWT Bearer</button>
                </div>

                {authType !== 'none' && (
                  <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} className="mb-6">
                    <textarea 
                      value={authToken}
                      onChange={(e) => setAuthToken(e.target.value)}
                      placeholder={authType === 'cookie' ? "session_id=12345; user_id=987..." : "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}
                      className="w-full bg-zinc-950 border border-zinc-800 rounded-lg p-4 text-sm font-mono text-zinc-300 placeholder-zinc-600 focus:outline-none focus:border-emerald-500/50 min-h-[100px]"
                      autoFocus
                    />
                  </motion.div>
                )}

                <button
                  type="submit"
                  disabled={isSavingAuth || (authType !== 'none' && !authToken.trim())}
                  className="w-full bg-zinc-100 hover:bg-white text-zinc-900 px-6 py-3 rounded-lg font-bold flex items-center justify-center gap-2 transition-colors disabled:opacity-50"
                >
                  {isSavingAuth ? "Guardando Sesión..." : "Confirmar Autenticación"}
                  <ArrowRight className="w-5 h-5" />
                </button>
              </div>
            </motion.form>
          )}

          {step === "mode" && (
            <motion.form
              key="mode-form"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              transition={{ duration: 0.3 }}
              onSubmit={handleScan}
              className="w-full flex flex-col items-center gap-8"
            >
              <div className="bg-zinc-900/50 border border-zinc-800 rounded-xl px-6 py-3 font-mono text-zinc-400 flex items-center gap-4">
                <span className="text-zinc-500 text-sm">Objetivo:</span>
                <span className="text-zinc-200">{url}</span>
                <button 
                  type="button" 
                  onClick={() => setStep("auth")}
                  className="text-blue-500 text-sm hover:underline ml-4"
                  disabled={isScanning}
                >
                  Cambiar
                </button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 w-full">
                {MODES.map((m) => {
                  const Icon = m.icon;
                  const isSelected = mode === m.id;
                  return (
                    <button
                      key={m.id}
                      type="button"
                      disabled={isScanning}
                      onClick={() => setMode(m.id)}
                      className={`relative p-4 rounded-xl text-left transition-all border flex flex-col gap-2 ${
                        isSelected
                          ? "bg-zinc-900 border-zinc-700 shadow-lg shadow-black/50"
                          : "bg-zinc-950/50 border-zinc-900 hover:border-zinc-800 opacity-70 hover:opacity-100"
                      } disabled:opacity-50 disabled:cursor-not-allowed`}
                    >
                      <div className="flex items-center gap-2">
                        <Icon className={`w-5 h-5 ${isSelected ? m.color : "text-zinc-500"}`} />
                        <span className="font-semibold text-zinc-200">{m.label}</span>
                      </div>
                      <p className="text-xs text-zinc-500">{m.desc}</p>
                      {isSelected && (
                        <motion.div
                          layoutId="mode-indicator"
                          className={`absolute inset-x-0 bottom-0 h-0.5 ${m.color.replace("text-", "bg-")}`}
                        />
                      )}
                    </button>
                  );
                })}
              </div>

              {/* ─── Aggressive consent block ─── */}
              <AnimatePresence>
                {mode === "aggressive" && (
                  <motion.div
                    key="aggressive-consent"
                    initial={{ opacity: 0, height: 0, marginTop: 0 }}
                    animate={{ opacity: 1, height: "auto", marginTop: 0 }}
                    exit={{ opacity: 0, height: 0, marginTop: 0 }}
                    transition={{ duration: 0.3 }}
                    className="w-full overflow-hidden"
                  >
                    {/* Consent checkbox */}
                    <div className="bg-rose-950/30 border border-rose-500/25 rounded-xl p-5 mb-4">
                      <div className="flex items-start gap-3 mb-4">
                        <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
                        <div>
                          <h3 className="text-sm font-bold text-rose-300 mb-1">Modo Agresivo — Autorización Requerida</h3>
                          <p className="text-xs text-zinc-400 leading-relaxed">
                            Este modo ejecuta ataques reales: inyección de payloads masiva, SSRF, IDOR, crawling agresivo y herramientas CLI ofensivas. Solo úsalo en entornos que controlás o tenés permiso explícito de auditar.
                          </p>
                        </div>
                      </div>

                      <label
                        htmlFor="aggressive-consent-checkbox"
                        className={`flex items-start gap-3 cursor-pointer p-3 rounded-lg border transition-all ${
                          aggressiveConsent || urlAlreadyAuthorized
                            ? "bg-rose-500/10 border-rose-500/40"
                            : "bg-zinc-950/50 border-zinc-800 hover:border-zinc-700"
                        }`}
                      >
                        <div className="relative mt-0.5 shrink-0">
                          <input
                            id="aggressive-consent-checkbox"
                            type="checkbox"
                            checked={aggressiveConsent || urlAlreadyAuthorized}
                            onChange={(e) => !urlAlreadyAuthorized && handleAggressiveConsent(e.target.checked)}
                            disabled={isSavingConsent || urlAlreadyAuthorized}
                            className="sr-only"
                          />
                          <div
                            className={`w-5 h-5 rounded border-2 flex items-center justify-center transition-all ${
                              aggressiveConsent || urlAlreadyAuthorized
                                ? "bg-rose-500 border-rose-500"
                                : "border-zinc-600 bg-zinc-900"
                            }`}
                          >
                            {(aggressiveConsent || urlAlreadyAuthorized) && (
                              <svg className="w-3 h-3 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                              </svg>
                            )}
                            {isSavingConsent && (
                              <div className="w-3 h-3 border-2 border-white/50 border-t-white rounded-full animate-spin" />
                            )}
                          </div>
                        </div>
                        <div>
                          <p className="text-sm font-semibold text-zinc-200">
                            {urlAlreadyAuthorized
                              ? "✓ Dominio ya autorizado previamente"
                              : "Confirmo que estoy explícitamente autorizado a realizar ataques y escaneos agresivos sobre esta URL"}
                          </p>
                          <p className="text-xs text-zinc-500 mt-0.5">
                            {urlAlreadyAuthorized
                              ? "Este dominio ya está registrado en tu lista de dominios autorizados."
                              : "Al marcar esta opción, el dominio quedará registrado en la base de datos como autorizado."}
                          </p>
                        </div>
                      </label>

                      {consentSaved && (
                        <motion.div
                          initial={{ opacity: 0, y: 4 }}
                          animate={{ opacity: 1, y: 0 }}
                          className="mt-3 flex items-center gap-2 text-xs text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 rounded-lg px-3 py-2"
                        >
                          <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                          Autorización registrada en la base de datos correctamente.
                        </motion.div>
                      )}
                    </div>

                    {/* Authorized domains list (inline) */}
                    <div className="bg-zinc-900/40 border border-zinc-800 rounded-xl p-4">
                      <div className="flex items-center justify-between mb-3">
                        <div className="flex items-center gap-2">
                          <ShieldCheck className="w-4 h-4 text-emerald-500" />
                          <span className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">
                            Dominios con permiso de auditoría
                          </span>
                        </div>
                        <span className="text-xs font-mono text-zinc-600">
                          {loadingDomains ? "..." : `${authorizedDomains.length} registros`}
                        </span>
                      </div>

                      {loadingDomains ? (
                        <div className="flex items-center gap-2 text-zinc-500 text-xs py-3">
                          <div className="w-3 h-3 border border-zinc-600 border-t-zinc-400 rounded-full animate-spin" />
                          Cargando...
                        </div>
                      ) : authorizedDomains.length === 0 ? (
                        <p className="text-xs text-zinc-600 py-3 text-center">
                          Aún no hay dominios autorizados. Marcá la casilla arriba para registrar este.
                        </p>
                      ) : (
                        <div className="space-y-1.5 max-h-40 overflow-y-auto pr-1">
                          {authorizedDomains.map((auth) => {
                            let isCurrentUrl = false;
                            try {
                              let normalized = url.trim();
                              if (!normalized.startsWith("http://") && !normalized.startsWith("https://")) {
                                normalized = `https://${normalized}`;
                              }
                              const hostname = new URL(normalized).hostname;
                              isCurrentUrl = auth.targetDomain === hostname || hostname.endsWith(`.${auth.targetDomain}`);
                            } catch {}

                            return (
                              <div
                                key={auth.id}
                                className={`flex items-center gap-3 rounded-lg px-3 py-2 text-xs font-mono transition-colors ${
                                  isCurrentUrl
                                    ? "bg-emerald-500/10 border border-emerald-500/20 text-emerald-300"
                                    : "bg-zinc-950/50 border border-zinc-800/50 text-zinc-400"
                                }`}
                              >
                                <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${isCurrentUrl ? "bg-emerald-400 shadow-[0_0_4px_rgba(52,211,153,0.8)]" : "bg-zinc-600"}`} />
                                <Globe className="w-3 h-3 shrink-0" />
                                <span className="flex-1 truncate">{auth.targetDomain}</span>
                                {isCurrentUrl && (
                                  <span className="text-emerald-500 font-bold text-[10px] bg-emerald-500/10 px-1.5 py-0.5 rounded">
                                    ACTUAL
                                  </span>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>

              <div className="pt-4">
                <button
                  type="submit"
                  disabled={isScanning || isAggressiveBlocked}
                  title={isAggressiveBlocked ? "Debes confirmar la autorización para ejecutar el modo agresivo" : undefined}
                  className="relative group disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <div
                    className={`absolute -inset-1 rounded-full blur-sm opacity-70 group-hover:opacity-100 transition duration-500 overflow-hidden ${
                      isScanning ? "animate-radar" : ""
                    }`}
                  >
                    <div
                      className="absolute inset-0 w-full h-full"
                      style={{
                        background: "conic-gradient(from 0deg, transparent 0%, transparent 60%, var(--color-brand-scanning) 100%)",
                      }}
                    ></div>
                  </div>
                  
                  <div className="relative bg-zinc-950 border border-zinc-800 px-12 py-4 rounded-full flex items-center gap-3 hover:bg-zinc-900 transition-colors">
                    <Scan className={`w-6 h-6 ${isScanning ? "animate-pulse text-blue-500" : "text-zinc-300"}`} />
                    <span className="text-lg font-bold font-mono tracking-widest uppercase">
                      {isScanning ? "Escaneando..." : "Iniciar Escaneo"}
                    </span>
                  </div>
                </button>

                {isAggressiveBlocked && (
                  <motion.p
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    className="mt-3 text-xs text-rose-400/80 text-center font-mono"
                  >
                    ⚠ Confirmá la autorización para habilitar el escaneo agresivo
                  </motion.p>
                )}
              </div>
            </motion.form>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
