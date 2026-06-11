"use client";

import { motion } from "framer-motion";
import { Terminal, Crosshair, ShieldAlert, Zap, Cpu, ScanLine } from "lucide-react";
import { useState } from "react";

interface OffensiveArsenalProps {
  targetUrl: string;
  scanId: number;
}

export default function OffensiveArsenal({ targetUrl, scanId }: OffensiveArsenalProps) {
  const [logs, setLogs] = useState<string[]>([
    "[System] Initializing Offensive Arsenal...", 
    `[System] Target locked: ${targetUrl} (Scan ID: ${scanId})`
  ]);
  const [isAttacking, setIsAttacking] = useState(false);

  const launchModule = (moduleName: string) => {
    setIsAttacking(true);
    setLogs(prev => [...prev, `[Offensive] Launching ${moduleName} module against ${targetUrl}...`]);
    
    // Simulate attack
    setTimeout(() => {
      setLogs(prev => [...prev, `[${moduleName}] Executing initial probing payloads...`]);
    }, 1000);
    setTimeout(() => {
      setLogs(prev => [...prev, `[${moduleName}] Analyzing responses and WAF rules...`]);
    }, 2500);
    setTimeout(() => {
      setLogs(prev => [...prev, `[${moduleName}] Module execution completed. Check vulnerabilities tab.`]);
      setIsAttacking(false);
    }, 4500);
  };

  return (
    <motion.div 
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="space-y-6"
    >
      <div className="flex items-center gap-4 border-b border-rose-500/20 pb-6">
        <div className="w-12 h-12 bg-rose-500/10 rounded-xl flex items-center justify-center border border-rose-500/30 shadow-[0_0_15px_rgba(244,63,94,0.3)]">
          <Crosshair className="w-6 h-6 text-rose-500" />
        </div>
        <div>
          <h2 className="text-2xl font-bold text-rose-100">FixGuard Offensive Arsenal</h2>
          <p className="text-rose-400/70 text-sm">Ejecuta módulos ofensivos especializados sobre la superficie descubierta.</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Columna Izquierda: Arsenal */}
        <div className="lg:col-span-2 space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <ModuleCard 
              title="SQLi Auto-Exploit" 
              desc="Inyección basada en tiempo, error y booleanos. (SQLmap wrapper)"
              icon={<Zap className="w-5 h-5 text-rose-400" />}
              onClick={() => launchModule("SQLi Fuzzer")}
              disabled={isAttacking}
            />
            <ModuleCard 
              title="Cross-Site Scripting (XSS)" 
              desc="Fuzzer mutacional avanzado para DOM y Reflected. (XSStrike wrapper)"
              icon={<ScanLine className="w-5 h-5 text-rose-400" />}
              onClick={() => launchModule("XSS Fuzzer")}
              disabled={isAttacking}
            />
            <ModuleCard 
              title="BOLA / IDOR Fuzzer" 
              desc="Intercambio de tokens JWT y manipulación paramétrica predictiva."
              icon={<ShieldAlert className="w-5 h-5 text-rose-400" />}
              onClick={() => launchModule("BOLA Analyzer")}
              disabled={isAttacking}
            />
            <ModuleCard 
              title="GraphQL Introspection" 
              desc="Descarga y parseo del esquema completo, búsqueda de queries sin Auth."
              icon={<Cpu className="w-5 h-5 text-rose-400" />}
              onClick={() => launchModule("GraphQL Dump")}
              disabled={isAttacking}
            />
          </div>
        </div>

        {/* Columna Derecha: Terminal Tactica */}
        <div className="lg:col-span-1">
          <div className="glass-panel h-full min-h-[400px] border-rose-500/30 bg-[#050505] flex flex-col shadow-lg shadow-rose-900/10">
            <div className="p-3 border-b border-rose-500/20 flex items-center gap-2 bg-rose-950/20">
              <Terminal className="w-4 h-4 text-rose-500" />
              <span className="text-xs font-mono text-rose-400 font-bold uppercase tracking-wider">Tactical Console</span>
            </div>
            <div className="p-4 flex-1 overflow-y-auto font-mono text-sm space-y-1">
              {logs.map((log, i) => (
                <div key={i} className={`${log.includes('[Error]') ? 'text-red-400' : log.includes('Executing') ? 'text-blue-400' : 'text-emerald-400'}`}>
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

function ModuleCard({ title, desc, icon, onClick, disabled }: { title: string, desc: string, icon: any, onClick: () => void, disabled: boolean }) {
  return (
    <div className="glass-panel p-5 border-white/5 hover:border-rose-500/50 hover:bg-rose-950/10 transition-colors group">
      <div className="flex items-center gap-3 mb-3">
        <div className="p-2 bg-rose-500/10 rounded-lg group-hover:bg-rose-500/20 transition-colors border border-rose-500/20">
          {icon}
        </div>
        <h3 className="font-bold text-zinc-200">{title}</h3>
      </div>
      <p className="text-xs text-zinc-400 mb-4 h-10">{desc}</p>
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
