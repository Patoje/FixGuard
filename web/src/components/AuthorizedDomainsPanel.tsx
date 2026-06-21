"use client";

import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { ShieldCheck, Plus, Globe, AlertTriangle, Loader2, CheckCircle2, X } from "lucide-react";

interface Authorization {
  id: number;
  userId: number;
  targetDomain: string;
  authorizedAt: string;
  expiresAt: string | null;
  signature: string | null;
}

interface AuthorizedDomainsPanelProps {
  onClose?: () => void;
}

export default function AuthorizedDomainsPanel({ onClose }: AuthorizedDomainsPanelProps) {
  const [authorizations, setAuthorizations] = useState<Authorization[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [newDomain, setNewDomain] = useState("");
  const [isAdding, setIsAdding] = useState(false);
  const [feedback, setFeedback] = useState<{ type: "success" | "error"; message: string } | null>(null);

  const fetchAuthorizations = useCallback(async () => {
    setIsLoading(true);
    try {
      const res = await fetch("/api/authorizations");
      if (res.ok) {
        const data = await res.json();
        setAuthorizations(data.authorizations || []);
      }
    } catch (err) {
      console.error("Error fetching authorizations:", err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAuthorizations();
  }, [fetchAuthorizations]);

  const handleAddDomain = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDomain.trim()) return;

    setIsAdding(true);
    setFeedback(null);

    try {
      const res = await fetch("/api/authorizations", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: newDomain.trim() }),
      });

      const data = await res.json();

      if (res.ok || res.status === 200) {
        setFeedback({ type: "success", message: data.message || "Dominio autorizado correctamente." });
        setNewDomain("");
        await fetchAuthorizations();
      } else {
        setFeedback({ type: "error", message: data.error || "Error al registrar el dominio." });
      }
    } catch (err) {
      setFeedback({ type: "error", message: "Error de red. Intenta de nuevo." });
    } finally {
      setIsAdding(false);
      setTimeout(() => setFeedback(null), 4000);
    }
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString("es-AR", {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: -10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -10 }}
      transition={{ duration: 0.25 }}
      className="w-full max-w-3xl mx-auto"
    >
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-zinc-100">Dominios Autorizados</h2>
            <p className="text-xs text-zinc-500 font-mono">
              Registros de consentimiento explícito para ataques agresivos
            </p>
          </div>
        </div>
        {onClose && (
          <button
            onClick={onClose}
            className="w-8 h-8 rounded-lg bg-zinc-900 border border-zinc-800 flex items-center justify-center hover:bg-zinc-800 transition-colors text-zinc-400 hover:text-zinc-200"
          >
            <X className="w-4 h-4" />
          </button>
        )}
      </div>

      {/* Legal notice */}
      <div className="flex items-start gap-3 bg-amber-500/5 border border-amber-500/20 rounded-xl p-4 mb-6">
        <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
        <p className="text-xs text-amber-300/80 leading-relaxed">
          Solo registra dominios sobre los que tenés autorización legal explícita para realizar pruebas de penetración.
          El motor bloqueará cualquier ataque agresivo sobre dominios no registrados aquí.
        </p>
      </div>

      {/* Add new domain form */}
      <div className="bg-zinc-900/60 border border-zinc-800 rounded-xl p-5 mb-6">
        <h3 className="text-sm font-semibold text-zinc-300 mb-3 flex items-center gap-2">
          <Plus className="w-4 h-4 text-emerald-400" />
          Agregar dominio manualmente
        </h3>
        <form onSubmit={handleAddDomain} className="flex gap-3">
          <div className="relative flex-1">
            <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
            <input
              type="text"
              value={newDomain}
              onChange={(e) => setNewDomain(e.target.value)}
              placeholder="ejemplo.com o https://ejemplo.com"
              className="w-full bg-zinc-950 border border-zinc-800 rounded-lg pl-9 pr-4 py-2.5 text-sm font-mono text-zinc-200 placeholder-zinc-600 focus:outline-none focus:ring-1 focus:ring-emerald-500/50 focus:border-emerald-500/50 transition-all"
              disabled={isAdding}
            />
          </div>
          <button
            type="submit"
            disabled={isAdding || !newDomain.trim()}
            className="px-4 py-2.5 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg font-bold text-sm flex items-center gap-2 transition-colors shadow-lg shadow-emerald-500/10"
          >
            {isAdding ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Plus className="w-4 h-4" />
            )}
            {isAdding ? "Guardando..." : "Autorizar"}
          </button>
        </form>

        <AnimatePresence>
          {feedback && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              exit={{ opacity: 0, height: 0 }}
              className={`mt-3 flex items-center gap-2 text-sm rounded-lg px-3 py-2 ${
                feedback.type === "success"
                  ? "bg-emerald-500/10 border border-emerald-500/20 text-emerald-400"
                  : "bg-rose-500/10 border border-rose-500/20 text-rose-400"
              }`}
            >
              {feedback.type === "success" ? (
                <CheckCircle2 className="w-4 h-4 shrink-0" />
              ) : (
                <AlertTriangle className="w-4 h-4 shrink-0" />
              )}
              {feedback.message}
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Authorized domains list */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-semibold text-zinc-400">
            Dominios registrados
          </h3>
          <span className="text-xs font-mono text-zinc-600 bg-zinc-900 border border-zinc-800 px-2 py-1 rounded-full">
            {authorizations.length} dominios
          </span>
        </div>

        {isLoading ? (
          <div className="flex items-center justify-center py-12 gap-2 text-zinc-500">
            <Loader2 className="w-5 h-5 animate-spin" />
            <span className="text-sm">Cargando...</span>
          </div>
        ) : authorizations.length === 0 ? (
          <div className="text-center py-12 bg-zinc-950/50 border border-zinc-800 border-dashed rounded-xl">
            <ShieldCheck className="w-10 h-10 text-zinc-700 mx-auto mb-3" />
            <p className="text-zinc-500 text-sm">No hay dominios autorizados aún.</p>
            <p className="text-zinc-600 text-xs mt-1">
              Agregá uno arriba o seleccioná el modo agresivo al escanear.
            </p>
          </div>
        ) : (
          <div className="space-y-2">
            <AnimatePresence>
              {authorizations.map((auth, i) => (
                <motion.div
                  key={auth.id}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.05 }}
                  className="flex items-center gap-4 bg-zinc-900/50 border border-zinc-800 rounded-xl px-4 py-3 hover:border-zinc-700 transition-colors group"
                >
                  {/* Status indicator */}
                  <div className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.6)] shrink-0" />

                  {/* Domain */}
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-mono text-zinc-200 truncate">{auth.targetDomain}</p>
                    <p className="text-xs text-zinc-600 mt-0.5">
                      Autorizado el {formatDate(auth.authorizedAt)}
                    </p>
                  </div>

                  {/* Signature badge */}
                  {auth.signature && (
                    <div className="hidden sm:flex items-center gap-1.5 bg-zinc-800/80 border border-zinc-700 rounded-lg px-2 py-1">
                      <div className="w-1.5 h-1.5 rounded-full bg-blue-400" />
                      <span className="text-xs font-mono text-zinc-500 max-w-[120px] truncate">
                        {auth.signature}
                      </span>
                    </div>
                  )}

                  {/* User ID badge */}
                  <div className="text-xs font-mono text-zinc-600 bg-zinc-900 border border-zinc-800 rounded-md px-2 py-1 shrink-0">
                    uid:{auth.userId}
                  </div>
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        )}
      </div>
    </motion.div>
  );
}
