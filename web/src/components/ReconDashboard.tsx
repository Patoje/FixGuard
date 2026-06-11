"use client";

import { motion, AnimatePresence } from "framer-motion";
import { Server, Database, Layers, Shield, Network, Activity, Zap, Code, Link2, BookOpen, Cloud, Key } from "lucide-react";
import { useState, useEffect } from "react";
import { ReconProfile, ArchitectureNode } from "../types";
import ApplicationBlueprint from "./ApplicationBlueprint";

interface Props {
  profile: ReconProfile;
  targetUrl: string;
  onLaunchAttack?: (vectorId: string) => void;
}

export default function ReconDashboard({ profile, targetUrl, onLaunchAttack }: Props) {
  const [isAttacking, setIsAttacking] = useState<Record<string, boolean>>({});
  const [toast, setToast] = useState<{message: string, type: 'success' | 'error'} | null>(null);

  // Auto-hide toast after 3 seconds
  useEffect(() => {
    if (toast) {
      const timer = setTimeout(() => setToast(null), 3000);
      return () => clearTimeout(timer);
    }
  }, [toast]);

  const handlePivotAttack = async (path: string, tool: 'sqlmap' | 'xsstrike') => {
    const fullUrl = path.startsWith('http') ? path : `${new URL(targetUrl).origin}${path.startsWith('/') ? path : '/' + path}`;
    const key = `${tool}-${path}`;
    
    setIsAttacking(prev => ({ ...prev, [key]: true }));
    try {
      await fetch('/api/scans/attack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scanId: profile.scanId,
          targetUrl: fullUrl,
          vectorId: tool,
          parentId: null // Starts as a new root node from the surface
        })
      });
      setToast({ message: `Ataque [${tool.toUpperCase()}] lanzado en segundo plano.`, type: 'success' });
    } catch (e) {
      console.error("Error launching pivot attack:", e);
      setToast({ message: `Error al lanzar el ataque ${tool.toUpperCase()}.`, type: 'error' });
    } finally {
      setIsAttacking(prev => ({ ...prev, [key]: false }));
    }
  };

  if (!profile) return null;

  return (
    <div className="space-y-8 mt-12 mb-16 relative">
      
      {/* Toast Notification */}
      <AnimatePresence>
        {toast && (
          <motion.div
            initial={{ opacity: 0, y: 50, x: '-50%' }}
            animate={{ opacity: 1, y: 0, x: '-50%' }}
            exit={{ opacity: 0, y: 20, x: '-50%' }}
            className={`fixed bottom-8 left-1/2 z-50 flex items-center gap-3 px-6 py-3 rounded-full border shadow-2xl backdrop-blur-md ${
              toast.type === 'success' 
                ? 'bg-emerald-500/20 border-emerald-500/50 text-emerald-100 shadow-emerald-500/20' 
                : 'bg-rose-500/20 border-rose-500/50 text-rose-100 shadow-rose-500/20'
            }`}
          >
            {toast.type === 'success' ? <Zap className="w-5 h-5 text-emerald-400" /> : <Shield className="w-5 h-5 text-rose-400" />}
            <span className="font-medium text-sm">{toast.message}</span>
          </motion.div>
        )}
      </AnimatePresence>

      <div className="text-center">
        <h2 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-emerald-400">
          Intelligence & Attack Surface
        </h2>
        <p className="text-zinc-400 mt-2">Perfil de reconocimiento y arquitectura estimada del objetivo</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Architecture Tree - Digital Twin Blueprint */}
        <motion.div 
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="glass-panel p-6 border-blue-500/20 lg:col-span-2"
        >
          <div className="flex items-center justify-between mb-6 border-b border-white/5 pb-4">
            <div className="flex items-center gap-3">
              <Network className="w-5 h-5 text-blue-400" />
              <h3 className="text-xl font-semibold text-zinc-100">Application Blueprint (Gemelo Arquitectónico)</h3>
            </div>
            <div className="px-3 py-1 bg-blue-500/10 text-blue-400 rounded-full text-xs font-bold border border-blue-500/20">
              Interactive
            </div>
          </div>
          <div className="bg-zinc-950 rounded-xl border border-white/5">
            <ApplicationBlueprint profile={profile} />
          </div>
        </motion.div>

        {/* Tech Stack Profiler */}
        <motion.div 
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.1 }}
          className="glass-panel p-6 border-violet-500/20"
        >
          <div className="flex items-center gap-3 mb-6 border-b border-white/5 pb-4">
            <Layers className="w-5 h-5 text-violet-400" />
            <h3 className="text-xl font-semibold text-zinc-100">Tech Stack Detectado</h3>
          </div>
          <div className="space-y-4">
            {profile.techStack.map((tech, i) => (
              <div key={i} className="flex justify-between items-center bg-zinc-900/50 p-3 rounded-lg border border-white/5">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-zinc-200">{tech.name}</span>
                    <span className="text-xs px-2 py-0.5 rounded-full bg-violet-500/20 text-violet-300">
                      {tech.category}
                    </span>
                  </div>
                  <p className="text-xs text-zinc-500 mt-1">{tech.role}</p>
                </div>
                <div className="text-right">
                  <div className="text-sm font-mono text-emerald-400">{tech.confidence}% Confianza</div>
                  <div className="w-24 h-1.5 bg-zinc-800 rounded-full mt-1 overflow-hidden">
                    <div className="h-full bg-emerald-500" style={{ width: `${tech.confidence}%` }} />
                  </div>
                </div>
              </div>
            ))}
          </div>
        </motion.div>

        {/* Third Party Integrations */}
        <motion.div 
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.15 }}
          className="glass-panel p-6 border-pink-500/20"
        >
          <div className="flex items-center gap-3 mb-6 border-b border-white/5 pb-4">
            <Link2 className="w-5 h-5 text-pink-400" />
            <h3 className="text-xl font-semibold text-zinc-100">Integraciones y Terceros</h3>
          </div>
          <div className="space-y-4">
            {profile.techStack.filter(t => t.category === 'External Services').length === 0 && (
              <p className="text-zinc-500 text-sm">No se detectaron integraciones de terceros.</p>
            )}
            {profile.techStack.filter(t => t.category === 'External Services').map((tech, i) => (
              <div key={i} className="flex justify-between items-center bg-pink-950/20 p-3 rounded-lg border border-pink-500/10">
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded bg-pink-500/10 flex items-center justify-center text-pink-400 font-bold text-xs">
                    {tech.name.substring(0, 2).toUpperCase()}
                  </div>
                  <div>
                    <span className="font-bold text-zinc-200 block leading-tight">{tech.name}</span>
                    <span className="text-xs text-zinc-500">{tech.role}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </motion.div>

        {/* JS Knowledge Graph / Business Dictionary */}
        {profile.businessDictionary && (
          <motion.div 
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.18 }}
            className="glass-panel p-6 border-amber-500/20 lg:col-span-2"
          >
            <div className="flex items-center gap-3 mb-6 border-b border-white/5 pb-4">
              <BookOpen className="w-5 h-5 text-amber-400" />
              <h3 className="text-xl font-semibold text-zinc-100">Diccionario de Negocio (Mapeo JS)</h3>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="bg-amber-950/20 p-4 rounded-xl border border-amber-500/10">
                <h4 className="font-bold text-amber-300 mb-2 text-sm">Roles ({profile.businessDictionary.roles.length})</h4>
                <div className="flex flex-wrap gap-2">
                  {profile.businessDictionary.roles.map((r, i) => <span key={i} className="text-xs bg-amber-500/10 text-amber-400 px-2 py-1 rounded">{r}</span>)}
                </div>
              </div>
              <div className="bg-amber-950/20 p-4 rounded-xl border border-amber-500/10">
                <h4 className="font-bold text-amber-300 mb-2 text-sm">Entidades ({profile.businessDictionary.entities.length})</h4>
                <div className="flex flex-wrap gap-2">
                  {profile.businessDictionary.entities.map((e, i) => <span key={i} className="text-xs bg-amber-500/10 text-amber-400 px-2 py-1 rounded">{e}</span>)}
                </div>
              </div>
              <div className="bg-amber-950/20 p-4 rounded-xl border border-amber-500/10">
                <h4 className="font-bold text-amber-300 mb-2 text-sm">Permisos ({profile.businessDictionary.permissions.length})</h4>
                <div className="flex flex-wrap gap-2">
                  {profile.businessDictionary.permissions.map((p, i) => <span key={i} className="text-xs bg-amber-500/10 text-amber-400 px-2 py-1 rounded">{p}</span>)}
                </div>
              </div>
              <div className="bg-amber-950/20 p-4 rounded-xl border border-amber-500/10">
                <h4 className="font-bold text-amber-300 mb-2 text-sm">Feature Flags ({profile.businessDictionary.configFlags.length})</h4>
                <div className="flex flex-wrap gap-2">
                  {profile.businessDictionary.configFlags.map((f, i) => <span key={i} className="text-xs bg-amber-500/10 text-amber-400 px-2 py-1 rounded">{f}</span>)}
                </div>
              </div>
            </div>
          </motion.div>
        )}

        {/* Cloud & Auth Intelligence */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 lg:col-span-2">
          {profile.cloudIntelligence && profile.cloudIntelligence.provider !== 'Unknown' && (
            <motion.div 
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.2 }}
              className="glass-panel p-6 border-cyan-500/20"
            >
              <div className="flex items-center gap-3 mb-6 border-b border-white/5 pb-4">
                <Cloud className="w-5 h-5 text-cyan-400" />
                <h3 className="text-xl font-semibold text-zinc-100">Cloud Intelligence ({profile.cloudIntelligence.provider})</h3>
              </div>
              <div className="space-y-4">
                {profile.cloudIntelligence.services.length > 0 && (
                  <div>
                    <h4 className="text-sm font-bold text-cyan-300 mb-2">Servicios Detectados</h4>
                    <div className="flex flex-wrap gap-2">
                      {profile.cloudIntelligence.services.map((s, i) => <span key={i} className="text-xs bg-cyan-500/10 text-cyan-400 px-2 py-1 rounded">{s}</span>)}
                    </div>
                  </div>
                )}
                {profile.cloudIntelligence.buckets.length > 0 && (
                  <div>
                    <h4 className="text-sm font-bold text-cyan-300 mb-2">Buckets de Almacenamiento</h4>
                    <div className="flex flex-wrap gap-2">
                      {profile.cloudIntelligence.buckets.map((b, i) => <span key={i} className="text-xs font-mono bg-zinc-800 text-zinc-300 px-2 py-1 rounded">{b}</span>)}
                    </div>
                  </div>
                )}
                {profile.cloudIntelligence.misconfigurations.length > 0 && (
                  <div>
                    <h4 className="text-sm font-bold text-rose-400 mb-2">Riesgos Cloud</h4>
                    <ul className="list-disc pl-5">
                      {profile.cloudIntelligence.misconfigurations.map((m, i) => <li key={i} className="text-xs text-rose-300">{m}</li>)}
                    </ul>
                  </div>
                )}
              </div>
            </motion.div>
          )}

          {profile.authIntelligence && (
            <motion.div 
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.22 }}
              className="glass-panel p-6 border-indigo-500/20"
            >
              <div className="flex items-center gap-3 mb-6 border-b border-white/5 pb-4">
                <Key className="w-5 h-5 text-indigo-400" />
                <h3 className="text-xl font-semibold text-zinc-100">Authentication Intelligence</h3>
              </div>
              <div className="space-y-4">
                {profile.authIntelligence.mechanisms.length > 0 && (
                  <div>
                    <h4 className="text-sm font-bold text-indigo-300 mb-2">Mecanismos</h4>
                    <div className="flex flex-wrap gap-2">
                      {profile.authIntelligence.mechanisms.map((m, i) => <span key={i} className="text-xs bg-indigo-500/10 text-indigo-400 px-2 py-1 rounded">{m}</span>)}
                    </div>
                  </div>
                )}
                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-zinc-900/50 p-3 rounded border border-white/5">
                    <span className="text-xs text-zinc-400 block mb-1">Local Storage</span>
                    <span className={`text-sm font-bold ${profile.authIntelligence.localStorage ? 'text-rose-400' : 'text-zinc-300'}`}>
                      {profile.authIntelligence.localStorage ? 'SI (Riesgo XSS)' : 'NO'}
                    </span>
                  </div>
                  <div className="bg-zinc-900/50 p-3 rounded border border-white/5">
                    <span className="text-xs text-zinc-400 block mb-1">Session Storage</span>
                    <span className={`text-sm font-bold ${profile.authIntelligence.sessionStorage ? 'text-amber-400' : 'text-zinc-300'}`}>
                      {profile.authIntelligence.sessionStorage ? 'SI' : 'NO'}
                    </span>
                  </div>
                </div>
                {profile.authIntelligence.cookieNames.length > 0 && (
                  <div>
                    <h4 className="text-sm font-bold text-indigo-300 mb-2">Cookies Relevantes</h4>
                    <div className="flex flex-wrap gap-2">
                      {profile.authIntelligence.cookieNames.map((c, i) => <span key={i} className="text-xs font-mono bg-zinc-800 text-zinc-300 px-2 py-1 rounded">{c}</span>)}
                    </div>
                  </div>
                )}
              </div>
            </motion.div>
          )}
        </div>

        {/* Framework Intelligence */}
        <motion.div 
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.2 }}
          className="glass-panel p-6 border-emerald-500/20 lg:col-span-2"
        >
          <div className="flex items-center gap-3 mb-6 border-b border-white/5 pb-4">
            <Zap className="w-5 h-5 text-emerald-400" />
            <h3 className="text-xl font-semibold text-zinc-100">Vectores de Framework</h3>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {profile.frameworkIntelligence.map((fw, i) => (
              <div key={i} className="bg-emerald-950/20 p-4 rounded-xl border border-emerald-500/10">
                <h4 className="font-bold text-emerald-300 mb-3 flex items-center gap-2">
                  <Server className="w-4 h-4" /> {fw.framework}
                </h4>
                <ul className="space-y-2">
                  {fw.vectors.map((vec, j) => (
                    <li key={j} className="text-sm text-zinc-400 flex flex-col gap-2 p-3 bg-white/5 rounded-lg border border-white/5 group hover:bg-white/10 transition-colors">
                      <div className="flex items-start gap-2 justify-between">
                        <div className="flex items-center gap-2">
                          <span className="text-emerald-500 mt-0.5">✓</span>
                          <span className="font-medium text-zinc-200">{vec.name}</span>
                        </div>
                        <button 
                          onClick={() => {
                            if (onLaunchAttack) {
                              onLaunchAttack(vec.id);
                            } else {
                              window.location.href = `/?targetUrl=${encodeURIComponent(targetUrl)}&mode=targeted&vectorId=${vec.id}`;
                            }
                          }}
                          className="px-3 py-1 bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-400 rounded-md text-xs font-bold transition-colors opacity-0 group-hover:opacity-100"
                        >
                          Lanzar Ataque
                        </button>
                      </div>
                      {vec.cliCommand && (
                        <div className="bg-black/50 p-2 rounded flex justify-between items-center group/cmd">
                          <code className="text-xs font-mono text-zinc-500">{vec.cliCommand}</code>
                          <button 
                            onClick={() => navigator.clipboard.writeText(vec.cliCommand)}
                            className="text-zinc-600 hover:text-zinc-300 opacity-0 group-hover/cmd:opacity-100 transition-opacity p-1"
                            title="Copiar Comando"
                          >
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" /></svg>
                          </button>
                        </div>
                      )}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </motion.div>

        {/* Attack Surface Map */}
        <motion.div 
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.3 }}
          className="glass-panel p-6 border-rose-500/20 lg:col-span-2"
        >
          <div className="flex items-center gap-3 mb-6 border-b border-white/5 pb-4">
            <Activity className="w-5 h-5 text-rose-400" />
            <h3 className="text-xl font-semibold text-zinc-100">Superficie de Ataque ({profile.attackSurface.length} Endpoints)</h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-zinc-900/80 text-zinc-400">
                <tr>
                    <th className="p-3 text-left font-medium text-gray-400">Endpoint / Params</th>
                    <th className="p-3 text-left font-medium text-gray-400">Método</th>
                    <th className="p-3 text-left font-medium text-gray-400">Tipo</th>
                    <th className="p-3 text-left font-medium text-gray-400">Contexto</th>
                    <th className="p-3 text-left font-medium text-gray-400">Riesgo</th>
                    <th className="p-3 text-right font-medium text-gray-400">Ofensiva</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {profile.attackSurface.map((ep, idx) => {
                  const riskColors = {
                    'CRÍTICO': 'bg-rose-500/20 text-rose-400 border-rose-500/30',
                    'ALTO': 'bg-orange-500/20 text-orange-400 border-orange-500/30',
                    'MEDIO': 'bg-amber-500/20 text-amber-400 border-amber-500/30',
                    'BAJO': 'bg-blue-500/20 text-blue-400 border-blue-500/30'
                  };
                  return (
                    <tr key={idx} className="border-b border-gray-800/50 hover:bg-gray-800/20 transition-colors">
                      <td className="p-3">
                        <code className="text-xs text-blue-300 font-mono break-all">{ep.path}</code>
                        {ep.params && ep.params.length > 0 && (
                          <div className="text-[10px] text-zinc-500 mt-1">
                            Params: {ep.params.join(', ')}
                          </div>
                        )}
                        {ep.aiExplanation && (
                          <div className="mt-2 text-xs text-amber-300/80 bg-amber-500/10 p-2 rounded-md border border-amber-500/20 italic flex items-start gap-2">
                            <span>🧠</span> <span>{ep.aiExplanation}</span>
                          </div>
                        )}
                      </td>
                      <td className="p-3 text-xs text-gray-400 font-mono">{ep.method}</td>
                      <td className="p-3 text-xs text-gray-400">{ep.type}</td>
                      <td className="p-3 text-xs text-gray-400">
                        {ep.framework && <span className="bg-purple-500/10 text-purple-400 px-1.5 py-0.5 rounded mr-1">{ep.framework}</span>}
                        {ep.authType && <span className="bg-emerald-500/10 text-emerald-400 px-1.5 py-0.5 rounded">{ep.authType}</span>}
                      </td>
                      <td className="p-3">
                        <span className={`px-2 py-1 text-xs font-bold rounded-md border ${riskColors[ep.riskLevel]}`}>
                          {ep.riskLevel}
                        </span>
                      </td>
                      <td className="p-3 text-right">
                        <div className="flex gap-2 justify-end opacity-20 hover:opacity-100 transition-opacity">
                          <button
                            onClick={() => handlePivotAttack(ep.path, 'sqlmap')}
                            disabled={isAttacking[`sqlmap-${ep.path}`]}
                            className="flex items-center gap-1 px-2 py-1 bg-rose-500/10 text-rose-400 border border-rose-500/20 hover:bg-rose-500/20 rounded text-[10px] font-bold transition-colors disabled:opacity-50"
                            title="Lanzar SQLMap"
                          >
                            <Database className="w-3 h-3" /> {isAttacking[`sqlmap-${ep.path}`] ? '...' : 'SQLi'}
                          </button>
                          <button
                            onClick={() => handlePivotAttack(ep.path, 'xsstrike')}
                            disabled={isAttacking[`xsstrike-${ep.path}`]}
                            className="flex items-center gap-1 px-2 py-1 bg-amber-500/10 text-amber-400 border border-amber-500/20 hover:bg-amber-500/20 rounded text-[10px] font-bold transition-colors disabled:opacity-50"
                            title="Lanzar XSStrike"
                          >
                            <Code className="w-3 h-3" /> {isAttacking[`xsstrike-${ep.path}`] ? '...' : 'XSS'}
                          </button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </motion.div>

      </div>
    </div>
  );
}


