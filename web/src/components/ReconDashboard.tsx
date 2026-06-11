"use client";

import { motion, AnimatePresence } from "framer-motion";
import { Server, Database, Layers, Shield, Network, Activity, Zap, Code, Link2, BookOpen, Cloud, Key, Workflow, Radio, Globe, PackageSearch, DatabaseZap, ClipboardCheck } from "lucide-react";
import { useState, useEffect } from "react";
import { ReconProfile, ArchitectureNode } from "../types";
import ApplicationBlueprint from "./ApplicationBlueprint";
import FunctionalBlueprint from "./FunctionalBlueprint";

interface Props {
  profile: ReconProfile;
  targetUrl: string;
  onLaunchAttack?: (vectorId: string) => void;
}

export default function ReconDashboard({ profile, targetUrl, onLaunchAttack }: Props) {
  const [isAttacking, setIsAttacking] = useState<Record<string, boolean>>({});
  const [toast, setToast] = useState<{message: string, type: 'success' | 'error'} | null>(null);
  const [blueprintView, setBlueprintView] = useState<'architecture' | 'functional'>('architecture');

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

      {/* --- NUEVO: Executive Audit Report --- */}
      {profile.auditReport && profile.auditReport.contexts.length > 0 && (
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="glass-panel p-6 border-emerald-500/30 bg-emerald-950/10 mb-8"
        >
          <div className="flex items-center gap-3 mb-4 border-b border-emerald-500/20 pb-4">
            <ClipboardCheck className="w-6 h-6 text-emerald-400" />
            <h2 className="text-2xl font-bold text-zinc-100">Executive Audit Report</h2>
          </div>
          <p className="text-zinc-300 text-sm mb-6">{profile.auditReport.summary}</p>
          
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6">
            {profile.auditReport.contexts.map((ctx, idx) => (
              <div key={idx} className="bg-zinc-900/50 p-4 rounded-xl border border-white/5 relative overflow-hidden group">
                <div className={`absolute top-0 left-0 w-1 h-full ${
                  ctx.confidence === 'HIGH' ? 'bg-rose-500' :
                  ctx.confidence === 'MEDIUM' ? 'bg-amber-500' : 'bg-blue-500'
                }`} />
                <h3 className="font-bold text-zinc-200 mb-1 pl-2">{ctx.name}</h3>
                <p className="text-xs text-zinc-400 mb-4 pl-2 h-10">{ctx.description}</p>
                
                <div className="space-y-3 pl-2">
                  <div>
                    <h4 className="text-[10px] uppercase text-zinc-500 font-bold mb-1 tracking-wider">Evidencia Correlacionada</h4>
                    <ul className="space-y-1">
                      {ctx.evidences.map((ev, i) => (
                        <li key={i} className="text-xs text-zinc-300 bg-black/40 p-1.5 rounded border border-white/5">
                          • {ev}
                        </li>
                      ))}
                    </ul>
                  </div>
                  
                  {ctx.inferredTechnologies.length > 0 && (
                    <div>
                      <h4 className="text-[10px] uppercase text-zinc-500 font-bold mb-1 tracking-wider">Tecnologías Inferidas</h4>
                      <div className="flex flex-wrap gap-1">
                        {ctx.inferredTechnologies.map((tech, i) => (
                          <span key={i} className="text-[10px] bg-emerald-500/10 text-emerald-400 px-1.5 py-0.5 rounded font-mono">
                            {tech}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </motion.div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Blueprint Section (Technical vs Functional) */}
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="glass-panel p-6 mb-6 lg:col-span-2"
        >
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              <Network className="w-6 h-6 text-blue-400" />
              <h2 className="text-2xl font-bold text-zinc-100">
                {blueprintView === 'architecture' ? 'Application Blueprint (Arquitectura)' : 'Functional Blueprint (Lógica de Negocio)'}
              </h2>
            </div>
            <div className="flex bg-black/40 rounded-lg p-1 border border-white/5">
              <button 
                onClick={() => setBlueprintView('architecture')}
                className={`px-4 py-1.5 text-sm font-medium rounded-md transition-colors ${blueprintView === 'architecture' ? 'bg-blue-600 text-white' : 'text-zinc-400 hover:text-white hover:bg-white/5'}`}
              >
                Técnico
              </button>
              <button 
                onClick={() => setBlueprintView('functional')}
                className={`px-4 py-1.5 text-sm font-medium rounded-md transition-colors ${blueprintView === 'functional' ? 'bg-purple-600 text-white' : 'text-zinc-400 hover:text-white hover:bg-white/5'}`}
              >
                Funcional
              </button>
            </div>
          </div>
          
          <div className="h-[500px] w-full rounded-xl overflow-hidden border border-white/5 bg-black/20">
            {blueprintView === 'architecture' ? (
              <ApplicationBlueprint profile={profile} />
            ) : (
              <FunctionalBlueprint profile={profile} />
            )}
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
                    {tech.version && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400 font-mono border border-white/10">
                        v{tech.version}
                      </span>
                    )}
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

        {/* --- NUEVO: OSINT y Funcionalidad --- */}
        {(profile.subdomainIntelligence || profile.artifactIntelligence || profile.parameterIntelligence) && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 lg:col-span-2">
            
            {/* Subdomain Intelligence */}
            {profile.subdomainIntelligence && (
              <motion.div 
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: 0.3 }}
                className="glass-panel p-6 border-indigo-500/20"
              >
                <div className="flex items-center gap-3 mb-6 border-b border-white/5 pb-4">
                  <Globe className="w-5 h-5 text-indigo-400" />
                  <h3 className="text-xl font-semibold text-zinc-100">Hidden Assets (OSINT)</h3>
                </div>
                <div className="space-y-4">
                  <div className="flex justify-between items-center bg-indigo-500/10 p-3 rounded border border-indigo-500/20">
                    <span className="text-sm text-indigo-200">Subdominios Descubiertos</span>
                    <span className="text-xl font-bold text-indigo-400">{profile.subdomainIntelligence.discoveredCount}</span>
                  </div>
                  
                  {profile.subdomainIntelligence.interestingSubdomains.length > 0 && (
                    <div>
                      <h4 className="text-sm font-bold text-indigo-300 mb-2">Entornos Críticos</h4>
                      <div className="space-y-2 max-h-40 overflow-y-auto custom-scrollbar">
                        {profile.subdomainIntelligence.interestingSubdomains.map((sub, i) => (
                          <div key={i} className="flex justify-between items-center text-xs p-2 bg-zinc-800/50 rounded border border-zinc-700/50">
                            <span className="font-mono text-zinc-300 truncate w-3/4">{sub.subdomain}</span>
                            <span className={`px-2 py-1 rounded font-bold ${
                              sub.type === 'STAGING' || sub.type === 'DEV' ? 'bg-orange-500/20 text-orange-400' :
                              sub.type === 'ADMIN' || sub.type === 'INTERNAL' ? 'bg-rose-500/20 text-rose-400' :
                              'bg-blue-500/20 text-blue-400'
                            }`}>{sub.type}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </motion.div>
            )}

            {/* Artifact Intelligence */}
            {profile.artifactIntelligence && (
              <motion.div 
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: 0.35 }}
                className="glass-panel p-6 border-cyan-500/20"
              >
                <div className="flex items-center gap-3 mb-6 border-b border-white/5 pb-4">
                  <PackageSearch className="w-5 h-5 text-cyan-400" />
                  <h3 className="text-xl font-semibold text-zinc-100">Artifact Intelligence</h3>
                </div>
                <div className="space-y-4">
                  {profile.artifactIntelligence.manifestType && (
                    <div className="text-xs bg-cyan-500/10 text-cyan-300 p-2 rounded text-center border border-cyan-500/20">
                      Detectado: <strong>{profile.artifactIntelligence.manifestType}</strong>
                    </div>
                  )}
                  
                  {profile.artifactIntelligence.hiddenRoutes.length > 0 ? (
                    <div>
                      <h4 className="text-sm font-bold text-cyan-300 mb-2">Rutas Ocultas Extraídas</h4>
                      <ul className="space-y-1 max-h-40 overflow-y-auto custom-scrollbar">
                        {profile.artifactIntelligence.hiddenRoutes.map((r, i) => (
                          <li key={i} className="text-xs font-mono text-cyan-100 bg-zinc-800 p-1.5 rounded truncate">
                            {r}
                          </li>
                        ))}
                      </ul>
                    </div>
                  ) : (
                    <div className="text-xs text-zinc-500 italic text-center py-4">No se extrajeron rutas ocultas del manifiesto.</div>
                  )}
                </div>
              </motion.div>
            )}

            {/* Parameter Intelligence Catalog */}
            {profile.parameterIntelligence && (
              <motion.div 
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: 0.4 }}
                className="glass-panel p-6 border-violet-500/20"
              >
                <div className="flex items-center gap-3 mb-6 border-b border-white/5 pb-4">
                  <DatabaseZap className="w-5 h-5 text-violet-400" />
                  <h3 className="text-xl font-semibold text-zinc-100">Data Model Recon</h3>
                </div>
                <div className="space-y-4">
                  <div className="text-xs text-zinc-400">
                    Se infirió el modelo de datos a partir de <strong>{profile.parameterIntelligence.totalParameters}</strong> parámetros únicos.
                  </div>
                  
                  <div className="flex flex-wrap gap-2 max-h-48 overflow-y-auto custom-scrollbar content-start">
                    {profile.parameterIntelligence.topParameters.map((p, i) => (
                      <div key={i} className="flex items-center text-xs bg-violet-500/10 border border-violet-500/20 rounded-full overflow-hidden">
                        <span className="px-2 py-1 text-violet-300 font-mono">{p.name}</span>
                        <span className="px-2 py-1 bg-violet-500/20 text-violet-200 font-bold border-l border-violet-500/20">{p.frequency}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </motion.div>
            )}

          </div>
        )}

        {/* Communication Intelligence (GraphQL & WebSockets) */}
        {profile.communicationIntelligence && (profile.communicationIntelligence.graphql.enabled || profile.communicationIntelligence.websockets.detected) && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 lg:col-span-2">
            {profile.communicationIntelligence.graphql.enabled && (
              <motion.div 
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: 0.24 }}
                className="glass-panel p-6 border-pink-500/20"
              >
                <div className="flex items-center gap-3 mb-6 border-b border-white/5 pb-4">
                  <Workflow className="w-5 h-5 text-pink-400" />
                  <h3 className="text-xl font-semibold text-zinc-100">GraphQL Intelligence</h3>
                </div>
                <div className="space-y-4">
                  <div>
                    <h4 className="text-sm font-bold text-pink-300 mb-2">Endpoint de Introspección</h4>
                    <span className="text-xs font-mono bg-zinc-800 text-zinc-300 px-2 py-1 rounded break-all">{profile.communicationIntelligence.graphql.endpoint}</span>
                  </div>
                  {profile.communicationIntelligence.graphql.queries.length > 0 && (
                    <div>
                      <h4 className="text-sm font-bold text-pink-300 mb-2">Queries Expuestas</h4>
                      <div className="flex flex-wrap gap-2">
                        {profile.communicationIntelligence.graphql.queries.slice(0, 10).map((q, i) => <span key={i} className="text-xs bg-pink-500/10 text-pink-400 px-2 py-1 rounded">{q}</span>)}
                        {profile.communicationIntelligence.graphql.queries.length > 10 && <span className="text-xs text-zinc-500 py-1">+{profile.communicationIntelligence.graphql.queries.length - 10} más</span>}
                      </div>
                    </div>
                  )}
                  {profile.communicationIntelligence.graphql.mutations.length > 0 && (
                    <div>
                      <h4 className="text-sm font-bold text-pink-300 mb-2">Mutations (Crítico)</h4>
                      <div className="flex flex-wrap gap-2">
                        {profile.communicationIntelligence.graphql.mutations.slice(0, 5).map((m, i) => <span key={i} className="text-xs bg-rose-500/20 text-rose-400 px-2 py-1 rounded font-bold border border-rose-500/30">{m}</span>)}
                      </div>
                    </div>
                  )}
                  {profile.communicationIntelligence.graphql.types.length > 0 && (
                    <div>
                      <h4 className="text-sm font-bold text-pink-300 mb-2">Tipos de Datos (Entities)</h4>
                      <div className="flex flex-wrap gap-2">
                        {profile.communicationIntelligence.graphql.types.slice(0, 8).map((t, i) => <span key={i} className="text-xs bg-purple-500/10 text-purple-400 px-2 py-1 rounded">{t}</span>)}
                      </div>
                    </div>
                  )}
                </div>
              </motion.div>
            )}

            {profile.communicationIntelligence.websockets.detected && (
              <motion.div 
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: 0.25 }}
                className="glass-panel p-6 border-emerald-500/20"
              >
                <div className="flex items-center gap-3 mb-6 border-b border-white/5 pb-4">
                  <Radio className="w-5 h-5 text-emerald-400 animate-pulse" />
                  <h3 className="text-xl font-semibold text-zinc-100">WebSocket Intelligence</h3>
                </div>
                <div className="space-y-4">
                  {profile.communicationIntelligence.websockets.urls.length > 0 && (
                    <div>
                      <h4 className="text-sm font-bold text-emerald-300 mb-2">Conexiones Activas Detectadas</h4>
                      <ul className="list-disc pl-5">
                        {profile.communicationIntelligence.websockets.urls.map((u, i) => <li key={i} className="text-xs text-zinc-300 font-mono break-all">{u}</li>)}
                      </ul>
                    </div>
                  )}
                  {profile.communicationIntelligence.websockets.namespaces.length > 0 && (
                    <div>
                      <h4 className="text-sm font-bold text-emerald-300 mb-2">Socket.io Namespaces</h4>
                      <div className="flex flex-wrap gap-2">
                        {profile.communicationIntelligence.websockets.namespaces.map((ns, i) => <span key={i} className="text-xs font-mono bg-emerald-500/10 text-emerald-400 px-2 py-1 rounded">{ns}</span>)}
                      </div>
                    </div>
                  )}
                  {profile.communicationIntelligence.websockets.urls.length === 0 && profile.communicationIntelligence.websockets.namespaces.length === 0 && (
                    <div className="text-xs text-emerald-400/80 italic">Se detectó uso de librerías en tiempo real (Socket.io / Websockets), pero los endpoints se construyen dinámicamente.</div>
                  )}
                </div>
              </motion.div>
            )}
          </div>
        )}

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
            <table className="w-full text-left text-sm border-separate border-spacing-0">
              <thead>
                <tr className="text-zinc-400 border-b border-zinc-800 bg-zinc-900/50">
                  <th className="p-4 font-medium border-b border-zinc-800 rounded-tl-lg">Endpoint / Params</th>
                  <th className="p-4 font-medium border-b border-zinc-800">Método</th>
                  <th className="p-4 font-medium border-b border-zinc-800">Tipo</th>
                  <th className="p-4 font-medium border-b border-zinc-800">Contexto</th>
                  <th className="p-4 font-medium border-b border-zinc-800 rounded-tr-lg">Riesgo</th>
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
                        <span className={`px-2 py-1 text-xs font-bold rounded-md border ${riskColors[ep.riskLevel as keyof typeof riskColors] || 'bg-blue-500/20 text-blue-400 border-blue-500/30'}`}>
                          {ep.riskLevel}
                        </span>
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


