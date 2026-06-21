"use client";

import { motion, AnimatePresence } from "framer-motion";
import { Terminal, Crosshair, ShieldAlert, Zap, Search, Network, Code, ChevronRight, Copy, Check } from "lucide-react";
import { useState, useRef, useEffect } from "react";
import type { ReconProfile } from "../types";

interface OffensiveArsenalProps {
  targetUrl: string;
  scanId: number;
  profile: ReconProfile;
  initialTargetUrl?: string;
  initialAttackVector?: string;
  onAttackComplete?: () => void;
}

type AttackCategory = 'ALL' | 'BOLA' | 'Mass Assignment' | 'Recon' | 'Injection' | 'JWT & Auth';

const CATEGORY_META: Record<AttackCategory, { label: string; color: string; bg: string; border: string; icon: any }> = {
  ALL:              { label: 'Todos',          color: 'text-zinc-300',   bg: 'bg-zinc-800',        border: 'border-zinc-700',    icon: Crosshair },
  BOLA:             { label: 'BOLA / IDOR',    color: 'text-rose-400',   bg: 'bg-rose-500/10',     border: 'border-rose-500/30', icon: ShieldAlert },
  'Mass Assignment':{ label: 'Mass Assign.',   color: 'text-orange-400', bg: 'bg-orange-500/10',   border: 'border-orange-500/30',icon: Zap },
  Recon:            { label: 'Recon',          color: 'text-cyan-400',   bg: 'bg-cyan-500/10',     border: 'border-cyan-500/30', icon: Search },
  Injection:        { label: 'Injection',      color: 'text-purple-400', bg: 'bg-purple-500/10',   border: 'border-purple-500/30',icon: Code },
  'JWT & Auth':     { label: 'JWT & Auth',     color: 'text-amber-400',  bg: 'bg-amber-500/10',    border: 'border-amber-500/30', icon: Network },
};

// Canonical vector shape used throughout the Arsenal
interface ArsenalVector {
  id: string;
  attackType: string;
  description: string;
  severity: string;
  method: string;
  endpoint?: string;
  targetUrl?: string;
  cliCommand?: string;
  framework?: string;
}

function getCategory(attackType: string): AttackCategory {
  const t = attackType.toLowerCase();
  if (t.includes('bola') || t.includes('idor')) return 'BOLA';
  if (t.includes('mass')) return 'Mass Assignment';
  if (t.includes('sql') || t.includes('inject') || t.includes('xss') || t.includes('prototype') || t.includes('crlf') || t.includes('dos') || t.includes('os injection') || t.includes('commix')) return 'Injection';
  if (t.includes('jwt') || t.includes('auth') || t.includes('session') || t.includes('oauth') || t.includes('clerk')) return 'JWT & Auth';
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

export default function OffensiveArsenal({ targetUrl, scanId, profile, initialTargetUrl, initialAttackVector, onAttackComplete }: OffensiveArsenalProps) {

  // ── Build unified vector list ─────────────────────────────────────────────
  // 1. SmartVectors: BOLA/MassAssign/Workflow vectors discovered by the recon engines
  const smartVecs: ArsenalVector[] = (profile.smartVectors ?? []).map(v => ({
    id: v.id ?? `smart-${v.attackType}`,
    attackType: v.attackType,
    description: v.description,
    severity: v.severity,
    method: v.method,
    endpoint: v.endpoint,
    targetUrl: v.targetUrl,
    cliCommand: v.cliCommand,
  }));

  // 2. FrameworkIntelligence vectors: SQLi, XSS, JWT, Nuclei CVEs, etc.
  //    These are always present and derived from the detected tech stack.
  const frameworkVecs: ArsenalVector[] = (profile.frameworkIntelligence ?? []).flatMap(fw =>
    fw.vectors.map(v => ({
      id: v.id,
      attackType: v.name,
      description: `[${fw.framework}] ${v.name}`,
      severity: v.name.toLowerCase().includes('sql') || v.name.toLowerCase().includes('xss') ? 'high' : 'medium',
      method: 'GET',
      endpoint: undefined,
      targetUrl: targetUrl,
      cliCommand: v.cliCommand,
      framework: fw.framework,
    }))
  );

  // Merge: smart vectors first (they have specific endpoints), then framework vectors.
  // Deduplicate by id so we don't show the same vector twice.
  const seenIds = new Set<string>();
  const vectors: ArsenalVector[] = [...smartVecs, ...frameworkVecs].filter(v => {
    if (seenIds.has(v.id)) return false;
    seenIds.add(v.id);
    return true;
  });
  // ─────────────────────────────────────────────────────────────────────────

  const [logs, setLogs] = useState<string[]>([
    "[System] FixGuard Offensive Arsenal inicializado",
    `[System] Target locked: ${targetUrl}`,
    `[System] Scan ID: ${scanId} | Vectores cargados: ${vectors.length} (${smartVecs.length} inteligentes + ${frameworkVecs.length} framework)`,
    "[System] Seleccioná una categoría y lanzá un módulo ▼",
  ]);
  const [isAttacking, setIsAttacking] = useState(false);
  const [activeCategory, setActiveCategory] = useState<AttackCategory>('ALL');
  const [copied, setCopied] = useState(false);
  
  // Preview state
  const [previewData, setPreviewData] = useState<{ command: string, vectorId: string, targetUrl: string, moduleName: string } | null>(null);
  const [previewFetchedFor, setPreviewFetchedFor] = useState<string>('');

  const logEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs, previewData]);

  // Manejar pre-selección desde Recon Dashboard
  useEffect(() => {
    const combo = `${initialTargetUrl}-${initialAttackVector}`;
    if (initialTargetUrl && initialAttackVector && !isAttacking && previewFetchedFor !== combo) {
       setPreviewFetchedFor(combo);
       const vector = vectors.find(v => v.id === initialAttackVector);
       const moduleName = vector ? (vector.description || vector.attackType) : initialAttackVector;
       
       setLogs(prev => [
         ...prev,
         ``,
         `[System] Solicitud de ataque quirúrgico recibida para: ${initialTargetUrl}`,
         `[System] Calculando mutaciones de PipelineSelector...`
       ]);

       fetch('/api/attack', {
         method: 'POST',
         headers: { 'Content-Type': 'application/json' },
         body: JSON.stringify({
           targetUrl: initialTargetUrl,
           vectorId: initialAttackVector,
           parentScanId: scanId,
           action: 'preview'
         })
       }).then(res => res.json()).then(data => {
         if (data.command) {
            setPreviewData({
              command: data.command,
              vectorId: initialAttackVector,
              targetUrl: initialTargetUrl,
              moduleName
            });
            setLogs(prev => [...prev, `[System] Mutaciones calculadas exitosamente.`]);
         } else if (data.error) {
            setLogs(prev => [...prev, `[System] ❌ Error obteniendo preview: ${data.error}`]);
         } else {
            setLogs(prev => [...prev, `[System] ❌ Error desconocido: no se recibió comando.`]);
         }
       }).catch(err => {
         setLogs(prev => [...prev, `[System] ❌ Error de red: ${err.message}`]);
       });
    }
  }, [initialTargetUrl, initialAttackVector, scanId, isAttacking, previewFetchedFor, vectors]);

  const categories = Array.from(new Set<AttackCategory>(['ALL', ...vectors.map(v => getCategory(v.attackType))]));
  const filtered = activeCategory === 'ALL' ? vectors : vectors.filter(v => getCategory(v.attackType) === activeCategory);

  const copyLogs = async () => {
    await navigator.clipboard.writeText(logs.join('\n'));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const launchModule = async (vectorId: string, moduleName: string, vectorTargetUrl: string, cliCommand?: string) => {
    // Only truly interactive tools (those that require stdin/TTY) get the copy-to-clipboard treatment.
    // sqlmap runs via the worker with --batch so it's fine to send it there.
    if (cliCommand && (cliCommand.includes('commix') || cliCommand.includes('nosqlmap'))) {
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

  const launchAllModules = async () => {
    if (vectors.length === 0) return;
    
    setIsAttacking(true);
    setLogs(prev => [
      ...prev,
      ``,
      `[System] ⚡ INICIANDO AUTO-ATAQUE TOTAL`,
      `[System] Se ejecutarán ${vectors.length} módulos secuencialmente...`,
      `══════════════════════════════════════════`
    ]);

    for (let i = 0; i < vectors.length; i++) {
      const vector = vectors[i];
      // Skip truly interactive tools that require a TTY
      const cli = vector.cliCommand;
      if (cli && (cli.includes('commix') || cli.includes('nosqlmap'))) {
        setLogs(prev => [...prev, `[System] ⏭️ Saltando ${vector.attackType} (herramienta interactiva — TTY requerida)`]);
        continue;
      }

      const path = String(vector.endpoint || vector.targetUrl || '');
      const fullUrl = path.startsWith('http') ? path : `${targetUrl.replace(/\/+$/, '')}${path || ''}`;
      
      setLogs(prev => [
        ...prev,
        `\n[Offensive] [${i+1}/${vectors.length}] Lanzando: ${vector.attackType}`,
        `[Offensive] Target: ${fullUrl}`,
      ]);

      try {
        const res = await fetch('/api/attack', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ targetUrl: fullUrl || targetUrl, vectorId: vector.id || `vector-${i}`, parentScanId: scanId })
        });

        if (!res.ok) throw new Error(`API error: ${res.statusText}`);

        const data = await res.json();
        const output = data.workerOutput?.output || data.workerOutput?.error || 'Sin respuesta del servidor.';
        const outputLines = output.split('\n').filter((l: string) => l.trim().length > 0);

        setLogs(prev => [
          ...prev,
          ...outputLines.map((line: string) => `  ${line}`)
        ]);

      } catch (error: any) {
        setLogs(prev => [...prev, `[System] ❌ Error en módulo ${i+1}: ${error.message}`]);
      }
      
      // Small delay between attacks to avoid hammering the server too hard and fast
      await new Promise(r => setTimeout(r, 1000));
    }

    setLogs(prev => [
      ...prev,
      `\n[System] ✅ AUTO-ATAQUE TOTAL FINALIZADO`,
      `══════════════════════════════════════════`
    ]);
    setIsAttacking(false);
    onAttackComplete?.();
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
            <p className="text-rose-400/60 text-xs">{vectors.length} vectores · <span className="text-zinc-600">{smartVecs.length} inteligentes · {frameworkVecs.length} framework</span> · Target: {targetUrl.replace('https://', '').replace('http://', '').split('/')[0]}</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {isAttacking && (
            <div className="flex items-center gap-2 px-3 py-1.5 bg-rose-500/10 border border-rose-500/30 rounded-full">
              <div className="w-2 h-2 bg-rose-500 rounded-full animate-pulse" />
              <span className="text-rose-400 text-xs font-mono font-bold">ATACANDO...</span>
            </div>
          )}
          <button
            onClick={launchAllModules}
            disabled={isAttacking || vectors.length === 0}
            className="flex items-center gap-2 px-4 py-2 bg-rose-600 hover:bg-rose-500 disabled:bg-rose-900/50 disabled:text-rose-500/50 text-white rounded-lg font-bold transition-all shadow-[0_0_15px_rgba(244,63,94,0.3)] hover:shadow-[0_0_25px_rgba(244,63,94,0.5)] border border-rose-400/50"
          >
            <Zap className="w-4 h-4" />
            ⚡ Auto Attack Total
          </button>
        </div>
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
                  const path = String(vector.endpoint || vector.targetUrl || '');
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

                      {/* Framework badge */}
                      {vector.framework && (
                        <div className="text-[8px] font-bold uppercase tracking-wider text-zinc-600 mb-1 truncate">{vector.framework}</div>
                      )}

                      {/* Launch button */}
                      <button
                        onClick={() => {
                          const fullUrl = path.startsWith('http') ? path : `${targetUrl.replace(/\/+$/, '')}${path || ''}`;
                          launchModule(vector.id || `vector-${i}`, vector.attackType, fullUrl || targetUrl, vector.cliCommand);
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
        <div className="flex flex-col h-96 lg:h-[500px] rounded-xl border border-rose-500/25 bg-[#030303] overflow-hidden shadow-xl shadow-rose-900/10 shrink-0">

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
            
            {/* Command Preview UI */}
            {previewData && !isAttacking && (
              <motion.div 
                initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
                className="mt-4 p-4 rounded-lg bg-black/60 border border-amber-500/30 shadow-lg"
              >
                <div className="text-amber-400 font-bold mb-2 flex items-center gap-2 text-xs uppercase tracking-wider">
                  <Zap className="w-3.5 h-3.5" /> Comando mutado final generado por PipelineSelector
                </div>
                <div className="text-emerald-400 font-mono text-xs whitespace-pre-wrap break-all mb-4 bg-zinc-950 p-3 rounded border border-white/5 shadow-inner">
                  {previewData.command.split(/(?= -[A-Za-z-]| --[A-Za-z])/).join('\n ')}
                </div>
                <div className="flex gap-3">
                  <button 
                    onClick={() => { 
                      launchModule(previewData.vectorId, previewData.moduleName, previewData.targetUrl); 
                      setPreviewData(null); 
                    }} 
                    className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded font-bold text-[10px] uppercase tracking-wider transition-colors"
                  >
                    [ Ejecutar ]
                  </button>
                  <button 
                    onClick={() => {
                      setPreviewData(null);
                      setLogs(prev => [...prev, `[System] Ataque quirúrgico cancelado por el usuario.`]);
                    }} 
                    className="px-4 py-2 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded font-bold text-[10px] uppercase tracking-wider transition-colors"
                  >
                    [ Cancelar ]
                  </button>
                </div>
              </motion.div>
            )}

            <div ref={logEndRef} />
          </div>
        </div>

      </div>
    </motion.div>
  );
}

