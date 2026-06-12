"use client";

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { ArrowLeft, GitCompare, CheckCircle2, AlertTriangle, AlertCircle } from "lucide-react";
import Link from "next/link";

interface Scan {
  id: number;
  targetUrl: string;
  createdAt: string;
  mode: string;
  status: string;
}

export default function DiffPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [targetFilter, setTargetFilter] = useState<string>("");
  const [scanA, setScanA] = useState<number | "">("");
  const [scanB, setScanB] = useState<number | "">("");
  const [diffResult, setDiffResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetch("/api/scans")
      .then((res) => res.json())
      .then((data) => {
        // Sort newest first
        const sorted = (data || []).sort((a: Scan, b: Scan) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
        setScans(sorted);
        // Autoselect target if there are scans
        if (sorted.length > 0) {
          setTargetFilter(sorted[0].targetUrl);
        }
      });
  }, []);

  const targets = Array.from(new Set(scans.map((s) => s.targetUrl)));
  const filteredScans = scans.filter((s) => s.targetUrl === targetFilter && s.status === 'completed');

  const handleCompare = async () => {
    if (!scanA || !scanB) return;
    setLoading(true);
    try {
      const res = await fetch(`/api/diff?scanA=${scanA}&scanB=${scanB}`);
      const data = await res.json();
      setDiffResult(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-black text-white p-8 font-sans">
      <div className="max-w-6xl mx-auto space-y-8">
        <div className="flex items-center gap-4">
          <Link href="/">
            <button className="p-2 hover:bg-zinc-800 rounded-full transition-colors">
              <ArrowLeft className="w-6 h-6 text-zinc-400" />
            </button>
          </Link>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <GitCompare className="w-8 h-8 text-blue-500" />
            Scan Diffing (Histórico)
          </h1>
        </div>

        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6 items-end">
            <div>
              <label className="block text-sm font-bold text-zinc-400 mb-2">Objetivo</label>
              <select
                className="w-full bg-zinc-950 border border-zinc-800 rounded-lg p-3 text-zinc-300"
                value={targetFilter}
                onChange={(e) => {
                  setTargetFilter(e.target.value);
                  setScanA("");
                  setScanB("");
                  setDiffResult(null);
                }}
              >
                <option value="">Seleccionar Objetivo</option>
                {targets.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm font-bold text-zinc-400 mb-2">Escaneo Base (A)</label>
              <select
                className="w-full bg-zinc-950 border border-zinc-800 rounded-lg p-3 text-zinc-300"
                value={scanA}
                onChange={(e) => setScanA(Number(e.target.value))}
                disabled={!targetFilter}
              >
                <option value="">Seleccionar Escaneo Antiguo</option>
                {filteredScans.map((s) => (
                  <option key={s.id} value={s.id}>
                    #{s.id} - {new Date(s.createdAt).toLocaleString()}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm font-bold text-zinc-400 mb-2">Escaneo Nuevo (B)</label>
              <select
                className="w-full bg-zinc-950 border border-zinc-800 rounded-lg p-3 text-zinc-300"
                value={scanB}
                onChange={(e) => setScanB(Number(e.target.value))}
                disabled={!targetFilter}
              >
                <option value="">Seleccionar Escaneo Reciente</option>
                {filteredScans.map((s) => (
                  <option key={s.id} value={s.id}>
                    #{s.id} - {new Date(s.createdAt).toLocaleString()}
                  </option>
                ))}
              </select>
            </div>

            <button
              onClick={handleCompare}
              disabled={!scanA || !scanB || loading}
              className="bg-blue-600 hover:bg-blue-500 text-white font-bold py-3 px-6 rounded-lg disabled:opacity-50 transition-colors h-[50px]"
            >
              {loading ? "Calculando..." : "Comparar"}
            </button>
          </div>
        </div>

        {diffResult && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-8"
          >
            {/* Metricas */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="bg-rose-950/30 border border-rose-500/20 p-6 rounded-xl flex items-center gap-4">
                <AlertTriangle className="w-12 h-12 text-rose-500" />
                <div>
                  <h3 className="text-rose-500 font-bold uppercase text-sm tracking-wider">Nuevas Vulnerabilidades</h3>
                  <p className="text-4xl font-bold text-white">{diffResult.new.length}</p>
                </div>
              </div>

              <div className="bg-emerald-950/30 border border-emerald-500/20 p-6 rounded-xl flex items-center gap-4">
                <CheckCircle2 className="w-12 h-12 text-emerald-500" />
                <div>
                  <h3 className="text-emerald-500 font-bold uppercase text-sm tracking-wider">Vulnerabilidades Resueltas</h3>
                  <p className="text-4xl font-bold text-white">{diffResult.resolved.length}</p>
                </div>
              </div>

              <div className="bg-zinc-900 border border-zinc-800 p-6 rounded-xl flex items-center gap-4">
                <AlertCircle className="w-12 h-12 text-zinc-500" />
                <div>
                  <h3 className="text-zinc-500 font-bold uppercase text-sm tracking-wider">Regresiones / Persistentes</h3>
                  <p className="text-4xl font-bold text-white">{diffResult.persisted.length}</p>
                </div>
              </div>
            </div>

            {/* Listas */}
            <div className="space-y-6">
              {diffResult.new.length > 0 && (
                <div className="bg-zinc-900 border border-rose-500/20 rounded-xl overflow-hidden">
                  <div className="bg-rose-950/30 px-6 py-4 border-b border-rose-500/20">
                    <h2 className="font-bold text-rose-400">Introducidas en el Escaneo B (Nuevas)</h2>
                  </div>
                  <div className="p-6 space-y-4">
                    {diffResult.new.map((f: any) => (
                      <div key={f.id} className="bg-black border border-zinc-800 p-4 rounded-lg">
                        <div className="flex items-center justify-between mb-2">
                          <h4 className="font-bold text-white">{f.title}</h4>
                          <span className={`px-2 py-1 text-xs font-bold rounded ${f.severity === 'critical' ? 'bg-rose-500/20 text-rose-400' : 'bg-orange-500/20 text-orange-400'}`}>
                            {f.severity}
                          </span>
                        </div>
                        <code className="text-sm text-zinc-500">{f.method || 'GET'} {f.endpoint || 'Global'}</code>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {diffResult.resolved.length > 0 && (
                <div className="bg-zinc-900 border border-emerald-500/20 rounded-xl overflow-hidden">
                  <div className="bg-emerald-950/30 px-6 py-4 border-b border-emerald-500/20">
                    <h2 className="font-bold text-emerald-400">Arregladas (Ya no aparecen en el Escaneo B)</h2>
                  </div>
                  <div className="p-6 space-y-4">
                    {diffResult.resolved.map((f: any) => (
                      <div key={f.id} className="bg-black border border-emerald-900/50 p-4 rounded-lg opacity-70">
                        <div className="flex items-center justify-between mb-2">
                          <h4 className="font-bold text-white line-through decoration-emerald-500">{f.title}</h4>
                        </div>
                        <code className="text-sm text-zinc-500">{f.method || 'GET'} {f.endpoint || 'Global'}</code>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              
              {diffResult.persisted.length > 0 && (
                <div className="bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden">
                  <div className="bg-zinc-950 px-6 py-4 border-b border-zinc-800">
                    <h2 className="font-bold text-zinc-400">Persistentes (Aún sin solucionar)</h2>
                  </div>
                  <div className="p-6 space-y-4">
                    {diffResult.persisted.map((pair: any) => (
                      <div key={pair.current.id} className="bg-black border border-zinc-800 p-4 rounded-lg">
                        <div className="flex items-center justify-between mb-2">
                          <h4 className="font-bold text-white">{pair.current.title}</h4>
                        </div>
                        <code className="text-sm text-zinc-500">{pair.current.method || 'GET'} {pair.current.endpoint || 'Global'}</code>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </div>
    </div>
  );
}
