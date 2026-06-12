"use client";

import { motion } from "framer-motion";
import { Terminal, Crosshair, ShieldAlert, Zap, Cpu, ScanLine, Play, FileJson } from "lucide-react";
import { useState } from "react";

import type { ReconProfile } from "../types";

interface OffensiveArsenalProps {
  targetUrl: string;
  scanId: number;
  profile: ReconProfile;
}

export default function OffensiveArsenal({ targetUrl, scanId, profile }: OffensiveArsenalProps) {
  const [logs, setLogs] = useState<string[]>([
    "[System] Initializing Offensive Arsenal...", 
    `[System] Target locked: ${targetUrl} (Scan ID: ${scanId})`
  ]);
  const [isAttacking, setIsAttacking] = useState(false);
  const [activeTab, setActiveTab] = useState<'modules'>('modules');

  const launchModule = async (vectorId: string, moduleName: string, vectorTargetUrl: string, cliCommand?: string) => {
    // Para herramientas pesadas o interactivas (Fase 5), mostrar el comando directamente
    if (cliCommand && (
        cliCommand.includes('commix') || 
        cliCommand.includes('nosqlmap') || 
        cliCommand.includes('sqlmap')
    )) {
      const finalCommand = cliCommand.replace('<TARGET>', vectorTargetUrl);
      setLogs(prev => [
        ...prev, 
        `[System] ⚠️ La herramienta ${moduleName} es interactiva o pesada.`,
        `[Terminal] Ejecuta manualmente este comando en tu terminal:`,
        `>> ${finalCommand}`,
      ]);
      // Copiar al portapapeles
      try {
        await navigator.clipboard.writeText(finalCommand);
        setLogs(prev => [...prev, `[System] ✅ Comando copiado al portapapeles.`]);
      } catch(e) {}
      return;
    }

    setIsAttacking(true);
    setLogs(prev => [
      ...prev, 
      `[Offensive] Encolando vector: ${moduleName} contra ${vectorTargetUrl}...`
    ]);
    
    try {
      const res = await fetch('/api/attack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetUrl: vectorTargetUrl,
          vectorId: vectorId,
          parentScanId: scanId
        })
      });

      if (!res.ok) {
        throw new Error(`API error: ${res.statusText}`);
      }

      setLogs(prev => [
        ...prev, 
        `[System] ✅ Ataque encolado. El Worker ejecutará ${moduleName} en segundo plano.`,
        `[System] Revisa la pestaña de 'Vulnerabilidades' para ver los resultados.`
      ]);

    } catch (error: any) {
      setLogs(prev => [
        ...prev, 
        `[System] ❌ Error conectando con el orquestador: ${error.message}`
      ]);
    } finally {
      setIsAttacking(false);
    }
  };

  return (
    <motion.div 
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="space-y-6"
    >
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b border-rose-500/20 pb-6">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 bg-rose-500/10 rounded-xl flex items-center justify-center border border-rose-500/30 shadow-[0_0_15px_rgba(244,63,94,0.3)]">
            <Crosshair className="w-6 h-6 text-rose-500" />
          </div>
          <div>
            <h2 className="text-2xl font-bold text-rose-100">FixGuard Offensive Arsenal</h2>
            <p className="text-rose-400/70 text-sm">Auditoría manual profunda y Fuzzing Avanzado.</p>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex bg-zinc-900 border border-zinc-800 rounded-lg p-1">
          <button 
            onClick={() => setActiveTab('modules')}
            className={`px-4 py-1.5 rounded-md text-sm font-bold transition-all ${activeTab === 'modules' ? 'bg-rose-500/20 text-rose-400' : 'text-zinc-500 hover:text-zinc-300'}`}
          >
            Smart Attack Vectors
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        
        {/* Columna Izquierda: Arsenal o Repeater */}
        <div className="xl:col-span-2 space-y-6">
          
          {activeTab === 'modules' && (
            <div className="space-y-4">
              {(!profile.smartVectors || profile.smartVectors.length === 0) ? (
                <div className="glass-panel border-zinc-500/20 bg-zinc-900/50 p-8 text-center flex flex-col items-center justify-center h-full min-h-[300px]">
                  <ShieldAlert className="w-12 h-12 text-zinc-600 mb-4" />
                  <h3 className="text-xl font-bold text-zinc-400 mb-2">Sin Superficie Ofensiva Detectada</h3>
                  <p className="text-zinc-500 max-w-md">Los motores de inteligencia de FixGuard no han encontrado vectores de ataque de lógica de negocio viables en este objetivo durante el reconocimiento pasivo.</p>
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {profile.smartVectors.map((vector, i) => (
                    <ModuleCard 
                      key={i}
                      title={vector.attackType} 
                      desc={vector.description}
                      icon={
                        vector.attackType.includes('BOLA') ? <ShieldAlert className="w-5 h-5 text-rose-400" /> : 
                        vector.attackType.includes('Workflow') ? <Cpu className="w-5 h-5 text-rose-400" /> :
                        <Zap className="w-5 h-5 text-rose-400" />
                      }
                      targetInfo={`${vector.method || 'CLI'} ${vector.targetUrl.split('?')[0].slice(0, 40)}${vector.targetUrl.length > 40 ? '...' : ''}`}
                      onClick={() => launchModule(vector.id || `vector-${i}`, vector.attackType, vector.targetUrl, (vector as any).cliCommand)}
                      disabled={isAttacking}
                    />
                  ))}
                </div>
              )}
            </div>
          )}

        </div>

        {/* Columna Derecha: Terminal Tactica */}
        <div className="xl:col-span-1">
          <div className={`glass-panel h-full min-h-[500px] border-rose-500/30 bg-[#050505] flex flex-col shadow-lg shadow-rose-900/10`}>
            <div className={`p-3 border-b border-rose-500/20 flex items-center gap-2 bg-rose-950/20`}>
              <Terminal className={`w-4 h-4 text-rose-500`} />
              <span className={`text-xs font-mono text-rose-400 font-bold uppercase tracking-wider`}>Tactical Console</span>
            </div>
            <div className="p-4 flex-1 overflow-y-auto font-mono text-xs space-y-1">
              {logs.map((log, i) => (
                <div key={i} className={`${log.includes('[Error]') || log.includes('❌') ? 'text-red-400' : log.includes('Executing') || log.includes('Repeater') ? 'text-blue-400' : 'text-emerald-400'}`}>
                  {log}
                </div>
              ))}
              {isAttacking && (
                <div className="text-zinc-500 animate-pulse mt-2">_</div>
              )}
            </div>
          </div>
        </div>

      </div>
    </motion.div>
  );
}

function ModuleCard({ title, desc, icon, onClick, disabled, targetInfo }: { title: string, desc: string, icon: any, onClick: () => void, disabled: boolean, targetInfo?: string }) {
  return (
    <div className="glass-panel p-5 border-white/5 hover:border-rose-500/50 hover:bg-rose-950/10 transition-colors group">
      <div className="flex items-center gap-3 mb-3">
        <div className="p-2 bg-rose-500/10 rounded-lg group-hover:bg-rose-500/20 transition-colors border border-rose-500/20">
          {icon}
        </div>
        <h3 className="font-bold text-zinc-200">{title}</h3>
      </div>
      {targetInfo && (
        <div className="mb-3">
          <span className="inline-block bg-zinc-950 border border-zinc-800 text-zinc-300 font-mono text-[10px] px-2 py-1 rounded w-full truncate">
            {targetInfo}
          </span>
        </div>
      )}
      <p className="text-xs text-zinc-400 mb-4 h-16 overflow-y-auto">{desc}</p>
      <button 
        onClick={onClick}
        disabled={disabled}
        className="w-full py-2 bg-zinc-800 hover:bg-rose-600 text-white rounded font-bold transition-colors text-sm disabled:opacity-50 disabled:cursor-not-allowed border border-white/5 hover:border-rose-500"
      >
        Lanzar Módulo
      </button>
    </div>
  );
}
