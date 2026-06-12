"use client";

import { motion, AnimatePresence } from "framer-motion";
import { Terminal, Crosshair, ShieldAlert, Zap, Search, Network, Code, ChevronRight, Copy, Check } from "lucide-react";
import { useState, useRef, useEffect } from "react";
import type { ReconProfile } from "../types";

interface OffensiveArsenalProps {
  targetUrl: string;
  scanId: number;
  profile: ReconProfile;
  onAttackComplete?: () => void;
}

type AttackCategory = 'ALL' | 'BOLA' | 'Mass Assignment' | 'Recon' | 'Injection';

const CATEGORY_META: Record<AttackCategory, { label: string; color: string; bg: string; border: string; icon: any }> = {
  ALL:              { label: 'Todos',          color: 'text-zinc-300',   bg: 'bg-zinc-800',        border: 'border-zinc-700',    icon: Crosshair },
  BOLA:             { label: 'BOLA / IDOR',    color: 'text-rose-400',   bg: 'bg-rose-500/10',     border: 'border-rose-500/30', icon: ShieldAlert },
  'Mass Assignment':{ label: 'Mass Assign.',   color: 'text-orange-400', bg: 'bg-orange-500/10',   border: 'border-orange-500/30',icon: Zap },
  Recon:            { label: 'Recon',          color: 'text-cyan-400',   bg: 'bg-cyan-500/10',     border: 'border-cyan-500/30', icon: Search },
  Injection:        { label: 'Injection',      color: 'text-purple-400', bg: 'bg-purple-500/10',   border: 'border-purple-500/30',icon: Code },
};

function getCategory(attackType: string): AttackCategory {
  const t = attackType.toLowerCase();
  if (t.includes('bola') || t.includes('idor')) return 'BOLA';
  if (t.includes('mass')) return 'Mass Assignment';
  if (t.includes('sqli') || t.includes('injection') || t.includes('xss') || t.includes('prototype')) return 'Injection';
  return 'Recon';
}

function getLogColor(log: string): string {
  if (log.includes('🚨') || log.includes('VULNERABILIDAD') || log.includes('❌')) return 'text-rose-400';
  if (log.includes('✅') || log.includes('seguro')) return 'text-emerald-400';
  if (log.includes('HTTP/2') || log.includes('HTTP/1')) return 'text-sky-300';
  if (log.includes('set-cookie') || log.includes('cookie')) return 'text-yellow-400 font-bold';
  if (log.includes('content-type') || log.includes('server:') || log.includes('age:') || log.includes('cache')) return 'text-zinc-400';
  if (log.includes('[Worker]') || log.includes('[Offensive]')) return 'text-blue-400';
  if (log.includes('[System]')) return 'text-zinc-500';
  if (log.includes('Endpoint:') || log.includes('Herramienta:') || log.includes('Veredicto:')) return 'text-amber-300';
  if (log.includes('---')) return 'text-zinc-600';
  if (log.startsWith('  {') || log.startsWith('  }') || log.startsWith('  "')) return 'text-green-300 font-mono';
  return 'text-emerald-400/80';
}

export default function OffensiveArsenal({ targetUrl, scanId, profile, onAttackComplete }: OffensiveArsenalProps) {
  const [logs, setLogs] = useState<string[]>([
    "[System] FixGuard Offensive Arsenal inicializado",
    `[System] Target locked: ${targetUrl}`,
    `[System] Scan ID: ${scanId} | Vectores cargados: ${profile.smartVectors?.length ?? 0}`,
    "[System] Seleccioná una categoría y lanzá un módulo ▼",
  ]);
  const [isAttacking, setIsAttacking] = useState(false);
  const [activeCategory, setActiveCategory] = useState<AttackCategory>('ALL');
  const [copied, setCopied] = useState(false);
  const logEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  const vectors = profile.smartVectors ?? [];
  const categories = Array.from(new Set<AttackCategory>(['ALL', ...vectors.map(v => getCategory(v.attackType))]));
  const filtered = activeCategory === 'ALL' ? vectors : vectors.filter(v => getCategory(v.attackType) === activeCategory);

  const copyLogs = async () => {
    await navigator.clipboard.writeText(logs.join('\n'));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const launchModule = async (vectorId: string, moduleName: string, vectorTargetUrl: string, cliCommand?: string) => {
    if (cliCommand && (cliCommand.includes('commix') || cliCommand.includes('nosqlmap') || cliCommand.includes('sqlmap'))) {
      const finalCommand = cliCommand.replace('<TARGET>', vectorTargetUrl);
      setLogs(prev => [
        ...prev,
        `[System] ⚠️ Herramienta interactiva: ${moduleName}`,
        `[Terminal] Copia y pegá en tu terminal:`,
        `>> ${finalCommand}`,
      ]);
      try {
        await navigator.clipboard.writeText(finalCommand);
        setLogs(prev => [...prev, `[System] ✅ Comando copiado al portapapeles.`]);
      } catch(e) {}
      return;
    }

    setIsAttacking(true);
    setLogs(prev => [
      ...prev,
      ``,
      `[Offensive] ══════════════════════════════`,
      `[Offensive] Lanzando: ${moduleName}`,
      `[Offensive] Target: ${vectorTargetUrl}`,
      `[Offensive] ══════════════════════════════`,
    ]);

    try {
      const res = await fetch('/api/attack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetUrl: vectorTargetUrl, vectorId, parentScanId: scanId })
      });

      if (!res.ok) throw new Error(`API error: ${res.statusText}`);

      const data = await res.json();
      const output = data.workerOutput?.output || data.workerOutput?.error || 'Sin respuesta del servidor.';
      const outputLines = output.split('\n').filter((l: string) => l.trim().length > 0);

      setLogs(prev => [
        ...prev,
        `[Worker] Respuesta recibida:`,
        ...outputLines.map((line: string) => `  ${line}`)
      ]);

      // Trigger parent refresh so new findings appear in Audit & Recon
      onAttackComplete?.();

    } catch (error: any) {
      setLogs(prev => [...prev, `[System] ❌ Error: ${error.message}`]);
    } finally {
      setIsAttacking(false);
    }
  };

  return (
    <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="space-y-4">

      {/* Header */}
      <div className="flex items-center justify-between border-b border-rose-500/20 pb-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-rose-500/10 rounded-xl flex items-center justify-center border border-rose-500/30 shadow-[0_0_12px_rgba(244,63,94,0.25)]">
            <Crosshair className="w-5 h-5 text-rose-500" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-rose-100">Offensive Arsenal</h2>
            <p className="text-rose-400/60 text-xs">{vectors.length} vectores inteligentes · Target: {targetUrl.replace('https://', '').split('/')[0]}</p>
          </div>
        </div>
        {isAttacking && (
          <div className="flex items-center gap-2 px-3 py-1.5 bg-rose-500/10 border border-rose-500/30 rounded-full">
            <div className="w-2 h-2 bg-rose-500 rounded-full animate-pulse" />
            <span className="text-rose-400 text-xs font-mono font-bold">ATACANDO...</span>
          </div>
        )}
      </div>

      {/* Main Layout: vectors top, terminal bottom full-width */}
      <div className="flex flex-col gap-4">

        {/* Top: Category filter + Vector cards */}
        <div className="flex flex-col gap-3">

          {/* Category Pills */}
          <div className="flex flex-wrap gap-2">
            {categories.map(cat => {
              const meta = CATEGORY_META[cat];
              const Icon = meta.icon;
              const isActive = activeCategory === cat;
              const count = cat === 'ALL' ? vectors.length : vectors.filter(v => getCategory(v.attackType) === cat).length;
              return (
                <button
                  key={cat}
                  onClick={() => setActiveCategory(cat)}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold border transition-all ${
                    isActive
                      ? `${meta.bg} ${meta.color} ${meta.border} shadow-sm`
                      : 'bg-zinc-900 text-zinc-500 border-zinc-800 hover:border-zinc-600 hover:text-zinc-300'
                  }`}
                >
                  <Icon className="w-3 h-3" />
                  {meta.label}
                  <span className={`ml-0.5 px-1.5 py-0.5 rounded-full text-[9px] font-bold ${isActive ? 'bg-black/30' : 'bg-zinc-800'}`}>
                    {count}
                  </span>
                </button>
              );
            })}
          </div>

          {/* Vectors Grid */}
          <AnimatePresence mode="wait">
            {filtered.length === 0 ? (
              <motion.div
                key="empty"
                initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                className="flex flex-col items-center justify-center h-32 text-center"
              >
                <ShieldAlert className="w-8 h-8 text-zinc-700 mb-2" />
                <p className="text-zinc-500 text-sm">Sin vectores en esta categoría</p>
              </motion.div>
            ) : (
              <motion.div
                key={activeCategory}
                initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
                className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-3"
              >
                {filtered.map((vector, i) => {
                  const cat = getCategory(vector.attackType);
                  const meta = CATEGORY_META[cat];
                  const Icon = meta.icon;
                  const path = String(vector.endpoint || (vector as any).targetUrl || '');
                  const method = vector.method || 'GET';
                  return (
                    <motion.div
                      key={i}
                      initial={{ opacity: 0, scale: 0.97 }}
                      animate={{ opacity: 1, scale: 1 }}
                      transition={{ delay: i * 0.03 }}
                      className={`group relative flex flex-col p-3 rounded-xl border bg-zinc-950/80 transition-all hover:shadow-lg ${meta.border}`}
                    >
                      {/* Card header */}
                      <div className="flex items-center gap-2 mb-2">
                        <div className={`p-1.5 rounded-lg ${meta.bg} border ${meta.border}`}>
                          <Icon className={`w-3 h-3 ${meta.color}`} />
                        </div>
                        <span className={`text-[10px] font-bold uppercase tracking-wide ${meta.color} truncate`}>{vector.attackType}</span>
                      </div>

                      {/* Target info */}
                      <div className="flex items-center gap-1 mb-2 bg-black/40 rounded px-1.5 py-1 font-mono">
                        <span className="text-zinc-600 text-[8px] font-bold uppercase shrink-0">{method}</span>
                        <span className="text-zinc-400 text-[9px] truncate">{path || targetUrl}</span>
                      </div>

                      {/* Launch button */}
                      <button
                        onClick={() => {
                          const fullUrl = path.startsWith('http') ? path : `${targetUrl.replace(/\/+$/, '')}${path}`;
                          launchModule(vector.id || `vector-${i}`, vector.attackType, fullUrl, (vector as any).cliCommand);
                        }}
                        disabled={isAttacking}
                        className={`w-full py-1.5 mt-auto rounded-lg text-[10px] font-bold border transition-all disabled:opacity-40 disabled:cursor-not-allowed bg-zinc-900 text-zinc-400 border-zinc-800 hover:bg-rose-600/20 hover:text-rose-300 hover:border-rose-500/50`}
                      >
                        {isAttacking ? '⏳' : '▶ Lanzar'}
                      </button>
                    </motion.div>
                  );
                })}
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Bottom: Tactical Console — full width */}
        <div className="flex flex-col rounded-xl border border-rose-500/25 bg-[#030303] overflow-hidden shadow-xl shadow-rose-900/10">

          {/* Console header */}
          <div className="flex items-center justify-between px-4 py-2.5 border-b border-rose-500/20 bg-rose-950/20 shrink-0">
            <div className="flex items-center gap-2">
              <div className="flex gap-1.5">
                <div className="w-2.5 h-2.5 rounded-full bg-zinc-700" />
                <div className="w-2.5 h-2.5 rounded-full bg-zinc-700" />
                <div className="w-2.5 h-2.5 rounded-full bg-rose-500/60" />
              </div>
              <Terminal className="w-3.5 h-3.5 text-rose-500 ml-1" />
              <span className="text-xs font-mono text-rose-400 font-bold tracking-widest uppercase">Tactical Console</span>
              <span className="text-[10px] text-zinc-600 ml-2 font-mono">{logs.length} líneas</span>
            </div>
            <button
              onClick={copyLogs}
              className="flex items-center gap-1 text-[10px] text-zinc-600 hover:text-zinc-300 transition-colors px-2 py-1 rounded border border-zinc-800 hover:border-zinc-600"
            >
              {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              {copied ? 'Copiado' : 'Copiar todo'}
            </button>
          </div>

          {/* Console body — tall and wide */}
          <div className="overflow-y-auto p-4 font-mono text-[11px] space-y-0.5 leading-relaxed" style={{ height: '420px' }}>
            {logs.map((log, i) => (
              <div key={i} className={`whitespace-pre-wrap break-all ${getLogColor(log)}`}>
                {log}
              </div>
            ))}
            {isAttacking && (
              <div className="flex items-center gap-2 text-rose-500 mt-2">
                <div className="w-1.5 h-1.5 bg-rose-500 rounded-full animate-ping" />
                <span className="animate-pulse">Ejecutando ataque...</span>
              </div>
            )}
            <div ref={logEndRef} />
          </div>
        </div>

      </div>
    </motion.div>
  );
}

