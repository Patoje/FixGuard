"use client";

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Scan, ShieldAlert, Zap, Code, ShieldCheck, ArrowRight } from "lucide-react";
import { ScanMode } from "../types";

interface HeroScannerProps {
  onScan: (url: string, mode: ScanMode) => void;
  isScanning: boolean;
}

const MODES: { id: ScanMode; label: string; icon: any; color: string; desc: string }[] = [
  { id: "passive", label: "Pasivo (OSINT)", icon: ShieldCheck, color: "text-emerald-500", desc: "Análisis silencioso sin romper nada." },
  { id: "active", label: "Activo", icon: Zap, color: "text-blue-500", desc: "Payloads seguros. Descubre fallas obvias." },
  { id: "aggressive", label: "Agresivo", icon: ShieldAlert, color: "text-rose-500", desc: "Escaneo profundo y ruidoso." },
  { id: "sast", label: "Código Fuente", icon: Code, color: "text-violet-500", desc: "Análisis interno (Caja Blanca)." },
];

export default function HeroScanner({ onScan, isScanning }: HeroScannerProps) {
  const [url, setUrl] = useState("");
  const [step, setStep] = useState<"input" | "mode">("input");
  const [mode, setMode] = useState<ScanMode>("passive");

  const handleContinue = (e: React.FormEvent) => {
    e.preventDefault();
    if (url.trim()) {
      setStep("mode");
    }
  };

  const handleScan = (e: React.FormEvent) => {
    e.preventDefault();
    if (url.trim()) {
      onScan(url, mode);
    }
  };

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
                  onClick={() => setStep("input")}
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

              <div className="pt-4">
                <button
                  type="submit"
                  disabled={isScanning}
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
              </div>
            </motion.form>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
