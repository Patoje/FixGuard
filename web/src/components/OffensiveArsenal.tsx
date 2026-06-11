"use client";

import { motion } from "framer-motion";
import { Terminal, Crosshair, ShieldAlert, Zap, Cpu, ScanLine, Play, FileJson } from "lucide-react";
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
  const [activeTab, setActiveTab] = useState<'modules' | 'repeater'>('modules');
  
  // Repeater State
  const [reqMethod, setReqMethod] = useState('GET');
  const [reqPath, setReqPath] = useState('/');
  const [reqHeaders, setReqHeaders] = useState('Host: target.com\nUser-Agent: FixGuard-Replayer/1.0\nAccept: */*');
  const [reqBody, setReqBody] = useState('');
  const [resData, setResData] = useState<string>('');

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

  const executeRepeater = async () => {
    setIsAttacking(true);
    setResData('Waiting for server response...');
    setLogs(prev => [...prev, `[Repeater] Enrutando petición manual: ${reqMethod} ${reqPath}`]);
    
    try {
      // Parse headers
      const headerLines = reqHeaders.split('\n').filter(l => l.trim().length > 0);
      const headersObj: Record<string, string> = {};
      headerLines.forEach(line => {
        const [k, ...v] = line.split(':');
        if (k && v.length > 0) {
          headersObj[k.trim()] = v.join(':').trim();
        }
      });

      // Since we don't have the actual backend running here, we simulate the fetch 
      // or we can call the Next.js API route that would call the worker (assuming API exists)
      // For this implementation, we simulate the latency and response of the orchestrator.
      setTimeout(() => {
        setLogs(prev => [...prev, `[Repeater] 📩 Respuesta recibida (Status: 200 OK)`]);
        setResData(`HTTP/1.1 200 OK\nDate: ${new Date().toUTCString()}\nContent-Type: application/json\n\n{\n  "success": true,\n  "data": "Simulated interactive response from target"\n}`);
        setIsAttacking(false);
      }, 1200);

    } catch (e) {
      setLogs(prev => [...prev, `[Repeater] ❌ Error in request: ${e}`]);
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
            Auto Modules
          </button>
          <button 
            onClick={() => setActiveTab('repeater')}
            className={`px-4 py-1.5 rounded-md text-sm font-bold transition-all flex items-center gap-2 ${activeTab === 'repeater' ? 'bg-blue-500/20 text-blue-400' : 'text-zinc-500 hover:text-zinc-300'}`}
          >
            <FileJson className="w-4 h-4" /> Interactive Replayer
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        
        {/* Columna Izquierda: Arsenal o Repeater */}
        <div className="xl:col-span-2 space-y-6">
          
          {activeTab === 'modules' && (
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
          )}

          {activeTab === 'repeater' && (
            <div className="glass-panel border-blue-500/20 bg-[#050505] flex flex-col shadow-lg shadow-blue-900/5 h-[500px]">
              <div className="p-3 border-b border-blue-500/20 flex gap-2 items-center bg-blue-950/10">
                <select 
                  value={reqMethod} 
                  onChange={e => setReqMethod(e.target.value)}
                  className="bg-blue-900/20 text-blue-400 border border-blue-500/30 rounded px-3 py-1 font-bold text-sm outline-none"
                >
                  {['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'].map(m => <option key={m} value={m}>{m}</option>)}
                </select>
                <input 
                  type="text" 
                  value={reqPath}
                  onChange={e => setReqPath(e.target.value)}
                  className="flex-1 bg-black/50 border border-zinc-800 rounded px-3 py-1 text-sm font-mono text-zinc-300 focus:border-blue-500/50 outline-none"
                  placeholder="/api/v1/users/1"
                />
                <button 
                  onClick={executeRepeater}
                  disabled={isAttacking}
                  className="bg-blue-600 hover:bg-blue-500 text-white px-4 py-1 rounded font-bold text-sm flex items-center gap-1 disabled:opacity-50"
                >
                  <Play className="w-4 h-4 fill-current" /> Send
                </button>
              </div>
              <div className="flex-1 flex flex-col lg:flex-row divide-y lg:divide-y-0 lg:divide-x divide-zinc-800/50">
                <div className="flex-1 flex flex-col">
                  <div className="text-xs font-mono px-3 py-1 bg-zinc-900 text-zinc-500 border-b border-zinc-800/50">Request</div>
                  <textarea 
                    value={reqHeaders}
                    onChange={e => setReqHeaders(e.target.value)}
                    className="h-1/2 w-full bg-transparent resize-none border-b border-zinc-800/50 p-3 font-mono text-xs text-blue-200 focus:outline-none"
                    placeholder="Headers..."
                  />
                  <textarea 
                    value={reqBody}
                    onChange={e => setReqBody(e.target.value)}
                    className="h-1/2 w-full bg-transparent resize-none p-3 font-mono text-xs text-amber-200 focus:outline-none"
                    placeholder="Body payload..."
                  />
                </div>
                <div className="flex-1 flex flex-col bg-zinc-950">
                  <div className="text-xs font-mono px-3 py-1 bg-zinc-900 text-zinc-500 border-b border-zinc-800/50">Response</div>
                  <pre className="flex-1 p-3 overflow-auto font-mono text-xs text-zinc-300">
                    {resData}
                  </pre>
                </div>
              </div>
            </div>
          )}

        </div>

        {/* Columna Derecha: Terminal Tactica */}
        <div className="xl:col-span-1">
          <div className={`glass-panel h-full min-h-[500px] border-${activeTab === 'repeater' ? 'blue' : 'rose'}-500/30 bg-[#050505] flex flex-col shadow-lg shadow-${activeTab === 'repeater' ? 'blue' : 'rose'}-900/10`}>
            <div className={`p-3 border-b border-${activeTab === 'repeater' ? 'blue' : 'rose'}-500/20 flex items-center gap-2 bg-${activeTab === 'repeater' ? 'blue' : 'rose'}-950/20`}>
              <Terminal className={`w-4 h-4 text-${activeTab === 'repeater' ? 'blue' : 'rose'}-500`} />
              <span className={`text-xs font-mono text-${activeTab === 'repeater' ? 'blue' : 'rose'}-400 font-bold uppercase tracking-wider`}>Tactical Console</span>
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
