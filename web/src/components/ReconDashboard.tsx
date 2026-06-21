"use client";

import { motion, AnimatePresence } from "framer-motion";
import { Server, Database, Layers, Shield, Network, Activity, Zap, Code, Link2, BookOpen, Cloud, Key, Workflow, Radio, Globe, PackageSearch, DatabaseZap, ClipboardCheck, Compass, Eye, Map, Box, Lock, FileJson, Search } from "lucide-react";
import { useState, useEffect, useMemo } from "react";
import { ReconProfile, AttackSurfaceItem } from "../types";
import ApplicationBlueprint from "./ApplicationBlueprint";
import FunctionalBlueprint from "./FunctionalBlueprint";
import EntityGraphViewer from "./EntityGraphViewer";
import WorkflowVisualizer from "./WorkflowVisualizer";

interface Props {
  profile: ReconProfile;
  targetUrl: string;
  onLaunchAttack?: (endpointUrl: string, vectorId: string) => void;
}

// Helper to group endpoints into functional entities
function groupEndpoints(endpoints: AttackSurfaceItem[]) {
  const groups: Record<string, AttackSurfaceItem[]> = {
    Auth: [],
    Users: [],
    Billing: [],
    Projects: [],
    Admin: [],
    GraphQL: [],
    Other: []
  };

  endpoints.forEach(ep => {
    const path = ep.path.toLowerCase();
    if (ep.type === 'GraphQL' || path.includes('graphql')) {
      groups.GraphQL.push(ep);
    } else if (path.includes('auth') || path.includes('login') || path.includes('register') || path.includes('oauth') || path.includes('session')) {
      groups.Auth.push(ep);
    } else if (path.includes('user') || path.includes('profile') || path.includes('account')) {
      groups.Users.push(ep);
    } else if (path.includes('bill') || path.includes('pay') || path.includes('invoice') || path.includes('stripe') || path.includes('checkout') || path.includes('subscription')) {
      groups.Billing.push(ep);
    } else if (path.includes('project') || path.includes('workspace') || path.includes('team') || path.includes('org')) {
      groups.Projects.push(ep);
    } else if (path.includes('admin') || path.includes('dashboard') || path.includes('config') || path.includes('setting')) {
      groups.Admin.push(ep);
    } else {
      groups.Other.push(ep);
    }
  });

  const riskScore: Record<string, number> = { 'ALTO': 3, 'MEDIO': 2, 'BAJO': 1 };
  Object.values(groups).forEach(group => {
    group.sort((a, b) => (riskScore[b.riskLevel || 'BAJO'] || 0) - (riskScore[a.riskLevel || 'BAJO'] || 0));
  });

  return groups;
}

export default function ReconDashboard({ profile, targetUrl, onLaunchAttack }: Props) {
  const [toast, setToast] = useState<{message: string, type: 'success' | 'error'} | null>(null);
  const [openEntity, setOpenEntity] = useState<string | null>(null);
  const [openDropdownIdx, setOpenDropdownIdx] = useState<string | null>(null);
  const [revealedSecrets, setRevealedSecrets] = useState<Set<number>>(new Set());

  const toggleSecret = (idx: number) => {
    const newSet = new Set(revealedSecrets);
    if (newSet.has(idx)) {
      newSet.delete(idx);
    } else {
      newSet.add(idx);
    }
    setRevealedSecrets(newSet);
  };

  useEffect(() => {
    if (toast) {
      const timer = setTimeout(() => setToast(null), 3000);
      return () => clearTimeout(timer);
    }
  }, [toast]);

  if (!profile) return null;

  const externalServices = profile.techStack.filter(t => t.category === 'External Services');
  let mainFrameworks = profile.techStack.filter(t => ['Frontend', 'Backend'].includes(t.category));
  
  // Si no encontró React/Next/Backend moderno, hace fallback a infraestructura o lenguajes
  if (mainFrameworks.length === 0) {
    mainFrameworks = profile.techStack.filter(t => ['Hosting / Infrastructure', 'Language', 'Web Server', 'Programming Language'].includes(t.category));
  }
  const hiddenAssetsCount = (profile.subdomainIntelligence?.discoveredCount || 0) + (profile.artifactIntelligence?.hiddenRoutes.length || 0);
  
  const endpointGroups = useMemo(() => groupEndpoints(profile.attackSurface), [profile.attackSurface]);
  
  const topAssets = useMemo(() => {
    return [...profile.attackSurface]
      .filter(ep => (ep.businessImpactScore || 0) > 0)
      .sort((a, b) => (b.businessImpactScore || 0) - (a.businessImpactScore || 0))
      .slice(0, 5);
  }, [profile.attackSurface]);

  return (
    <div className="space-y-12 mt-12 mb-16 relative">
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
        <h2 className="text-4xl font-black uppercase tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-indigo-400 via-purple-400 to-pink-400">
          Actionable Knowledge Report
        </h2>
        <p className="text-zinc-400 mt-3 text-lg max-w-2xl mx-auto">De hallazgos aislados a un mapa relacional y de inteligencia completa de la aplicación objetivo.</p>
      </div>

      {/* SECTION 1: EXECUTIVE SUMMARY */}
      <motion.section initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="space-y-4">
        <h3 className="text-2xl font-bold flex items-center gap-2 border-b border-white/10 pb-2"><Compass className="text-blue-400" /> Executive Summary</h3>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="glass-panel p-6 border-blue-500/20">
            <p className="text-zinc-400 text-sm uppercase font-bold tracking-wider mb-2">Stack Principal</p>
            <div className="flex flex-wrap gap-2">
              {mainFrameworks.length > 0 ? mainFrameworks.map(f => <span key={f.name} className="bg-blue-500/20 text-blue-300 px-2 py-1 rounded text-sm font-bold">{f.name}</span>) : <span className="text-zinc-500 text-sm">Unknown</span>}
            </div>
          </div>
          <div className="glass-panel p-6 border-fuchsia-500/20">
            <p className="text-zinc-400 text-sm uppercase font-bold tracking-wider mb-2">Total Endpoints</p>
            <div className="text-4xl font-black text-fuchsia-400">{profile.attackSurface.length}</div>
          </div>
          <div className="glass-panel p-6 border-amber-500/20">
            <p className="text-zinc-400 text-sm uppercase font-bold tracking-wider mb-2">Activos Ocultos (OSINT)</p>
            <div className="text-4xl font-black text-amber-400">{hiddenAssetsCount}</div>
          </div>
          <div className="glass-panel p-6 border-pink-500/20">
            <p className="text-zinc-400 text-sm uppercase font-bold tracking-wider mb-2">Servicios Externos</p>
            <div className="flex flex-wrap gap-2">
              {externalServices.length > 0 ? externalServices.map(s => <span key={s.name} className="bg-pink-500/20 text-pink-300 px-2 py-1 rounded text-sm font-bold">{s.name}</span>) : <span className="text-zinc-500 text-sm">Ninguno Detectado</span>}
            </div>
          </div>
        </div>

        {topAssets.length > 0 && (
          <div className="mt-6 glass-panel p-6 border-red-500/30 bg-red-950/10">
            <h4 className="text-red-400 font-bold text-lg mb-4 flex items-center gap-2"><Map className="w-5 h-5" /> Top 5 Critical Business Assets</h4>
            <div className="space-y-3">
              {topAssets.map((asset, i) => (
                <div key={i} className="flex flex-col md:flex-row md:items-center justify-between p-3 bg-black/40 border border-red-500/20 rounded-lg">
                  <div className="flex items-center gap-3">
                    <span className="text-xs font-mono bg-red-500/20 text-red-300 px-2 py-1 rounded border border-red-500/30">{asset.method}</span>
                    <span className="font-mono text-sm text-zinc-200">{asset.path}</span>
                  </div>
                  <div className="flex items-center gap-4 mt-2 md:mt-0">
                    <span className="text-xs text-zinc-400">{asset.type}</span>
                    <span className="text-xs font-bold bg-zinc-800 px-2 py-1 rounded border border-zinc-600">Score: {asset.businessImpactScore}</span>
                  </div>
                </div>
              ))}
            </div>
            <p className="text-xs text-zinc-500 mt-4">Priorización basada en impacto de negocio (Billing, Users, Auth), no solo en vulnerabilidades genéricas.</p>
          </div>
        )}
      </motion.section>

      {/* SECTION 8: RUNTIME DISCOVERY (CRAWLER STATS) */}
      {profile.runtimeIntelligence && (
        <motion.section initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{delay: 0.1}}>
          <h3 className="text-2xl font-bold flex items-center gap-2 border-b border-white/10 pb-2"><Activity className="text-emerald-400" /> Runtime Discovery</h3>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mt-4">
            <div className="bg-emerald-950/20 p-4 rounded-xl border border-emerald-500/20 text-center">
              <div className="text-3xl font-black text-emerald-400">{profile.runtimeIntelligence.totalClicks}</div>
              <div className="text-xs text-emerald-200/50 uppercase mt-1">Clicks Automáticos</div>
            </div>
            <div className="bg-emerald-950/20 p-4 rounded-xl border border-emerald-500/20 text-center">
              <div className="text-3xl font-black text-emerald-400">{profile.runtimeIntelligence.totalScrolls}</div>
              <div className="text-xs text-emerald-200/50 uppercase mt-1">Scrolls (Lazy Load)</div>
            </div>
            <div className="bg-emerald-950/20 p-4 rounded-xl border border-emerald-500/20 text-center">
              <div className="text-3xl font-black text-emerald-400">{profile.runtimeIntelligence.totalFormsFilled}</div>
              <div className="text-xs text-emerald-200/50 uppercase mt-1">Formularios Inyectados</div>
            </div>
            <div className="bg-emerald-950/20 p-4 rounded-xl border border-emerald-500/20 text-center">
              <div className="text-3xl font-black text-emerald-400">{profile.runtimeIntelligence.requestsIntercepted}</div>
              <div className="text-xs text-emerald-200/50 uppercase mt-1">Requests Observadas</div>
            </div>
            <div className="bg-emerald-950/20 p-4 rounded-xl border border-emerald-500/20 text-center relative overflow-hidden">
              <div className="absolute inset-0 bg-emerald-500/10 animate-pulse"></div>
              <div className="text-3xl font-black text-white relative z-10">{profile.runtimeIntelligence.endpointsDiscovered}</div>
              <div className="text-xs text-emerald-200/80 uppercase mt-1 font-bold relative z-10">Rutas Interceptadas</div>
            </div>
          </div>
        </motion.section>
      )}

      {/* SECTION 2 & 3: ARCHITECTURE & FUNCTIONAL BLUEPRINT */}
      <section className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{delay: 0.2}}>
          <h3 className="text-xl font-bold flex items-center gap-2 border-b border-white/10 pb-2 mb-4"><Network className="text-indigo-400" /> Architecture Blueprint</h3>
          <div className="h-[400px] w-full rounded-xl overflow-hidden border border-white/5 bg-black/20">
             <ApplicationBlueprint profile={profile} />
          </div>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{delay: 0.3}}>
          <h3 className="text-xl font-bold flex items-center gap-2 border-b border-white/10 pb-2 mb-4"><Box className="text-purple-400" /> Functional Blueprint</h3>
          <div className="h-[400px] w-full rounded-xl overflow-hidden border border-white/5 bg-black/20">
             <FunctionalBlueprint profile={profile} />
          </div>
        </motion.div>
      </section>

      {/* SECTION 4 & 5: TECH PROFILE & ENTITY MAP */}
      <section className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{delay: 0.4}}>
          <h3 className="text-xl font-bold flex items-center gap-2 border-b border-white/10 pb-2 mb-4"><Layers className="text-violet-400" /> Technology Profile</h3>
          <div className="space-y-3 max-h-[400px] overflow-y-auto custom-scrollbar pr-2">
            {profile.techStack.map((tech, i) => (
              <div key={i} className="bg-zinc-900/50 p-4 rounded-xl border border-white/5">
                <div className="flex justify-between items-center mb-2">
                  <div className="font-bold text-zinc-200 flex items-center gap-2">{tech.name} <span className="text-[10px] bg-violet-500/20 text-violet-300 px-1.5 py-0.5 rounded">{tech.category}</span></div>
                  <div className="text-xs font-mono text-emerald-400">{tech.confidence}% Confianza</div>
                </div>
                <div className="text-xs text-zinc-500 mb-2">{tech.role}</div>
                {tech.evidence && tech.evidence.length > 0 && (
                  <div className="mt-2 bg-black/30 p-2 rounded border border-white/5">
                    <span className="text-[10px] uppercase text-zinc-600 font-bold">Evidencias:</span>
                    <ul className="mt-1 space-y-1">
                      {tech.evidence.map((ev, idx) => <li key={idx} className="text-[10px] text-zinc-400 font-mono">• {ev}</li>)}
                    </ul>
                  </div>
                )}
              </div>
            ))}
          </div>
        </motion.div>
        
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{delay: 0.5}}>
          <h3 className="text-xl font-bold flex items-center gap-2 border-b border-white/10 pb-2 mb-4"><DatabaseZap className="text-amber-400" /> Entity Map</h3>
          <div className="flex flex-col gap-4">
             {profile.entityGraph && profile.entityGraph.nodes.length > 0 ? (
               <div className="h-[300px] w-full rounded-xl overflow-hidden border border-white/5 bg-black/20">
                 <EntityGraphViewer entityGraph={profile.entityGraph} />
               </div>
             ) : (
               <div className="text-zinc-500 text-sm p-4 text-center border border-dashed border-white/10 rounded-xl">No Entity Graph could be reconstructed.</div>
             )}
             
             {profile.businessDictionary && (
               <div className="grid grid-cols-2 gap-4">
                 <div className="bg-orange-950/10 p-4 rounded-xl border border-orange-500/20">
                   <h4 className="text-orange-400 font-bold text-sm mb-3">Roles / Actors</h4>
                   <div className="flex flex-wrap gap-2">
                     {profile.businessDictionary.roles.map((e, i) => <span key={i} className="text-xs bg-orange-500/20 text-orange-200 px-2 py-1 rounded-full border border-orange-500/30">{e}</span>)}
                   </div>
                 </div>
                 <div className="bg-yellow-950/10 p-4 rounded-xl border border-yellow-500/20">
                   <h4 className="text-yellow-400 font-bold text-sm mb-3">Feature Flags</h4>
                   <div className="flex flex-wrap gap-2">
                     {profile.businessDictionary.configFlags.map((e, i) => <span key={i} className="text-[10px] font-mono bg-yellow-500/10 text-yellow-500/80 px-1.5 py-0.5 rounded border border-yellow-500/20">{e}</span>)}
                   </div>
                 </div>
               </div>
             )}
          </div>
        </motion.div>
      </section>

      {/* SECTION 5.5: WORKFLOW RECONSTRUCTION */}
      <motion.section initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{delay: 0.55}} className="mt-8">
        <h3 className="text-2xl font-bold flex items-center gap-2 border-b border-white/10 pb-2 mb-4">
          <Workflow className="text-emerald-400" /> Workflow Reconstruction
        </h3>
        <p className="text-sm text-zinc-400 mb-6">
          Flujos de usuario inferidos lógicamente a partir de las rutas descubiertas.
        </p>
        
        <WorkflowVisualizer workflows={profile.workflowIntelligence || []} />
      </motion.section>

      {/* SECTION 6: ENDPOINT CATALOG */}
      <motion.section initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{delay: 0.6}}>
        <h3 className="text-2xl font-bold flex items-center gap-2 border-b border-white/10 pb-2"><Map className="text-cyan-400" /> Endpoint Catalog</h3>
        <p className="text-sm text-zinc-400 mb-4">Endpoints descubiertos agrupados por módulo funcional (Reconstrucción Semántica).</p>
        <div className="space-y-3">
          {Object.entries(endpointGroups).filter(([_, eps]) => eps.length > 0).map(([groupName, eps]) => (
            <div key={groupName} className="glass-panel border-cyan-500/20 overflow-hidden">
              <button 
                onClick={() => setOpenEntity(openEntity === groupName ? null : groupName)}
                className="w-full p-4 flex justify-between items-center hover:bg-white/5 transition-colors"
              >
                <div className="flex items-center gap-3">
                  <span className="font-bold text-zinc-100">{groupName}</span>
                  <span className="bg-cyan-500/20 text-cyan-300 text-xs px-2 py-1 rounded-full">{eps.length} endpoints</span>
                </div>
                <span className="text-zinc-500 text-sm">{openEntity === groupName ? 'Contraer' : 'Expandir'}</span>
              </button>
              
              <AnimatePresence>
                {openEntity === groupName && (
                  <motion.div 
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: 'auto', opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    className="border-t border-white/5 bg-black/20"
                  >
                    <div className="p-2">
                      <table className="w-full text-left text-sm">
                        <tbody className="divide-y divide-white/5">
                          {eps.map((ep, idx) => {
                            const riskColors: Record<string, string> = {
                              'CRÍTICO': 'bg-rose-500/20 text-rose-400 border-rose-500/30',
                              'ALTO': 'bg-orange-500/20 text-orange-400 border-orange-500/30',
                              'MEDIO': 'bg-amber-500/20 text-amber-400 border-amber-500/30',
                              'BAJO': 'bg-blue-500/20 text-blue-400 border-blue-500/30'
                            };
                            return (
                              <tr key={idx} className="hover:bg-white/5 group">
                                <td className="p-2 text-xs text-zinc-400 font-mono w-20">{ep.method}</td>
                                <td className="p-2 text-xs text-blue-300 font-mono break-all">{ep.path}</td>
                                <td className="p-2 w-24">
                                  <span className={`px-2 py-0.5 text-[10px] font-bold rounded border ${riskColors[ep.riskLevel] || 'bg-zinc-800 text-zinc-400'}`}>
                                    {ep.riskLevel}
                                  </span>
                                </td>
                                <td className="p-2 w-12 relative text-right">
                                  {/* Mostrar el rayito si hay onLaunchAttack. Lo hacemos siempre visible en baja opacidad y full opacity al hover, o siempre encendido si el menú está abierto */}
                                  {onLaunchAttack && (
                                    <button 
                                      onClick={() => setOpenDropdownIdx(openDropdownIdx === `${groupName}-${idx}` ? null : `${groupName}-${idx}`)}
                                      className={`p-1.5 rounded transition-all ${openDropdownIdx === `${groupName}-${idx}` ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40 opacity-100' : 'bg-zinc-800 text-cyan-400 border-cyan-500/20 opacity-30 hover:opacity-100 hover:bg-zinc-700'} border`}
                                      title="Ataque Táctico"
                                    >
                                      <Zap className="w-3.5 h-3.5" />
                                    </button>
                                  )}
                                  
                                  {openDropdownIdx === `${groupName}-${idx}` && (
                                    <div className="absolute right-0 top-full mt-1 w-56 bg-zinc-900 border border-white/10 rounded-lg shadow-2xl z-[100] overflow-hidden text-left">
                                      <div className="px-3 py-2 border-b border-white/5 text-[10px] font-mono text-zinc-500 uppercase tracking-widest bg-black/40">
                                        Menú Táctico
                                      </div>
                                      
                                      {(() => {
                                         // Logic for dropdown relevance
                                         const hasParams = ep.path.includes('?');
                                         let isNumeric = false;
                                         if (hasParams) {
                                           const paramVal = ep.path.split('=')[1];
                                           if (paramVal && !isNaN(Number(paramVal))) {
                                              isNumeric = true;
                                           }
                                         }
                                         
                                         const hasJwt = profile.credentials?.some(c => c.type === 'jwt_secret') ?? false;

                                         // Asegurarnos de que endpointPath sea una URL completa para que `new URL()` no falle en el backend
                                         const cleanTarget = targetUrl.endsWith('/') ? targetUrl.slice(0, -1) : targetUrl;
                                         const cleanPath = ep.path.startsWith('/') ? ep.path : `/${ep.path}`;
                                         const fullEndpointUrl = ep.path.startsWith('http') ? ep.path : `${cleanTarget}${cleanPath}`;

                                         return (
                                           <div className="flex flex-col text-xs">
                                              {isNumeric && (
                                                <button onClick={() => { onLaunchAttack?.(fullEndpointUrl, 'sqli_time'); setOpenDropdownIdx(null); }} className="px-3 py-2 hover:bg-white/5 flex items-center gap-2 text-zinc-300">
                                                  <DatabaseZap className="w-3.5 h-3.5 text-orange-400" /> Inyectar SQL
                                                </button>
                                              )}
                                              {hasParams && !isNumeric && (
                                                <button onClick={() => { onLaunchAttack?.(fullEndpointUrl, 'xss_dalfox'); setOpenDropdownIdx(null); }} className="px-3 py-2 hover:bg-white/5 flex items-center gap-2 text-zinc-300">
                                                  <Shield className="w-3.5 h-3.5 text-rose-400" /> Cazar XSS
                                                </button>
                                              )}
                                              <button onClick={() => { onLaunchAttack?.(fullEndpointUrl, 'ffuf_dir'); setOpenDropdownIdx(null); }} className="px-3 py-2 hover:bg-white/5 flex items-center gap-2 text-zinc-300">
                                                <Search className="w-3.5 h-3.5 text-blue-400" /> Fuzzear Rutas
                                              </button>
                                              {hasJwt && (
                                                <button onClick={() => { onLaunchAttack?.(fullEndpointUrl, 'jwt_tool'); setOpenDropdownIdx(null); }} className="px-3 py-2 hover:bg-white/5 flex items-center gap-2 text-zinc-300">
                                                  <Key className="w-3.5 h-3.5 text-amber-400" /> Testear JWT
                                                </button>
                                              )}
                                              <button onClick={() => { onLaunchAttack?.(fullEndpointUrl, 'nuclei_cve'); setOpenDropdownIdx(null); }} className="px-3 py-2 hover:bg-white/5 flex items-center gap-2 text-zinc-300">
                                                <Radio className="w-3.5 h-3.5 text-cyan-400" /> Scan CVEs
                                              </button>
                                           </div>
                                         );
                                      })()}
                                    </div>
                                  )}
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          ))}
        </div>
      </motion.section>

      {/* SECTION 7: DATA EXPOSURE */}
      <motion.section initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{delay: 0.7}}>
        <h3 className="text-2xl font-bold flex items-center gap-2 border-b border-white/10 pb-2"><Eye className="text-rose-400" /> Data Exposure</h3>
        <p className="text-sm text-zinc-400 mb-4">Centralización de activos críticos expuestos que representan riesgo de fuga de datos.</p>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* JWT / Tokens / Auth */}
          {profile.authIntelligence && profile.authIntelligence.localStorage && (
            <div className="bg-rose-950/20 p-5 rounded-xl border border-rose-500/30 relative overflow-hidden">
              <div className="absolute top-0 right-0 p-3 opacity-10"><Lock className="w-16 h-16" /></div>
              <h4 className="font-bold text-rose-400 mb-2 flex items-center gap-2">Token Storage Exposure</h4>
              <p className="text-xs text-rose-200/70 mb-4">La aplicación almacena tokens de sesión en el LocalStorage. Si existe vulnerabilidad XSS, un atacante puede robar las sesiones mediante Javascript.</p>
              <div className="bg-black/50 p-2 rounded text-xs font-mono text-zinc-400 border border-white/5">Storage: LocalStorage</div>
            </div>
          )}

          {/* GraphQL */}
          {profile.communicationIntelligence?.graphql.enabled && (
            <div className="bg-pink-950/20 p-5 rounded-xl border border-pink-500/30 relative overflow-hidden">
               <div className="absolute top-0 right-0 p-3 opacity-10"><Workflow className="w-16 h-16" /></div>
               <h4 className="font-bold text-pink-400 mb-2 flex items-center gap-2">GraphQL Introspection</h4>
               <p className="text-xs text-pink-200/70 mb-4">El servidor expone su esquema completo de base de datos a través de GraphQL. Permite a un atacante mapear todas las consultas y tipos de datos posibles.</p>
               <div className="bg-black/50 p-2 rounded text-xs font-mono text-zinc-400 border border-white/5 truncate">{profile.communicationIntelligence.graphql.endpoint}</div>
            </div>
          )}

          {/* Server Actions / Source Maps */}
          {profile.serverActionsIntelligence && profile.serverActionsIntelligence.extractedActionsCount > 0 && (
            <div className="bg-orange-950/20 p-5 rounded-xl border border-orange-500/30 relative overflow-hidden">
              <div className="absolute top-0 right-0 p-3 opacity-10"><Code className="w-16 h-16" /></div>
              <h4 className="font-bold text-orange-400 mb-2 flex items-center gap-2">Server Actions (Next.js)</h4>
              <p className="text-xs text-orange-200/70 mb-4">Se extrajeron hashes RPC de Next.js. Esto permite bypass de UI e inyecciones directas a la base de datos backend.</p>
              <div className="bg-black/50 p-2 rounded text-xs font-mono text-zinc-400 border border-white/5">{profile.serverActionsIntelligence.extractedActionsCount} Acciones Críticas</div>
            </div>
          )}

          {/* Source Code Exposed Secrets */}
          {profile.artifactIntelligence?.exposedSecrets && profile.artifactIntelligence.exposedSecrets.length > 0 && (
            <div className="bg-amber-950/20 p-5 rounded-xl border border-amber-500/30 relative overflow-hidden col-span-1 md:col-span-3">
              <div className="absolute top-0 right-0 p-3 opacity-10"><Key className="w-16 h-16" /></div>
              <h4 className="font-bold text-amber-400 mb-2 flex items-center gap-2">Secretos Expuestos en Código Cliente</h4>
              <p className="text-xs text-amber-200/70 mb-4">API Keys, Tokens o contraseñas encontrados directamente en los bundles de Javascript.</p>
              <div className="space-y-2 max-h-48 overflow-y-auto custom-scrollbar pr-2">
                 {profile.artifactIntelligence.exposedSecrets.map((secret, idx) => {
                    const isGeneric = secret.type.includes('Generic');
                    let displayName = secret.type;
                    let displayValue = secret.value;

                    if (isGeneric) {
                       const parts = secret.value.split(/[:=]/);
                       if (parts.length >= 2) {
                          // Extraemos el prefijo (ej: api_key, TOKEN, secret) y le limpiamos las comillas
                          displayName = parts[0].trim().replace(/['"]/g, '');
                          // Extraemos el valor real (la key en sí)
                          displayValue = parts.slice(1).join('=').trim().replace(/^["']|["']$/g, '');
                       }
                    }

                    let maskedValue = displayValue.length > 10 
                       ? `${displayValue.substring(0, 6)}***${displayValue.substring(displayValue.length - 4)}`
                       : `${displayValue.substring(0, Math.floor(displayValue.length/2))}***`;

                    return (
                    <div key={idx} className="flex flex-col md:flex-row md:items-center justify-between p-3 bg-black/40 border border-amber-500/20 rounded-lg">
                       <div className="flex flex-col gap-1">
                         <div className="flex items-center gap-3">
                           <span className="text-xs font-mono bg-amber-500/20 text-amber-300 px-2 py-1 rounded border border-amber-500/30 truncate max-w-[150px]" title={secret.type}>{displayName}</span>
                           <span className="font-mono text-sm text-zinc-200 max-w-[400px] break-all">
                             {revealedSecrets.has(idx) ? displayValue : maskedValue}
                           </span>
                         </div>
                         {(secret.url || secret.source) && (
                           <div className="flex items-center gap-2 text-[10px] text-zinc-500 mt-1">
                             {secret.source && <span className="uppercase font-bold text-zinc-400 bg-zinc-800 px-1.5 rounded">{secret.source}</span>}
                             {secret.url && <span className="truncate max-w-[300px]" title={secret.url}>{secret.url.replace(/^https?:\/\/[^\/]+/, '') || secret.url}</span>}
                           </div>
                         )}
                       </div>
                       <div className="flex items-center gap-4 mt-2 md:mt-0">
                         <button onClick={() => toggleSecret(idx)} className="p-1.5 hover:bg-white/10 rounded text-zinc-400 hover:text-zinc-200 transition-colors" title={revealedSecrets.has(idx) ? "Ocultar" : "Mostrar"}>
                            <Eye className="w-4 h-4" />
                         </button>
                         {secret.isLikelyFalsePositive ? (
                            <span className="text-[10px] font-bold bg-amber-500/80 text-black px-2 py-1 rounded cursor-help" title={secret.falsePositiveReason || "Posible falso positivo"}>POSIBLE FALSO POSITIVO</span>
                         ) : secret.type.includes('Peligro') || secret.type.includes('API Key') || secret.type.includes('Secret') || secret.type.includes('Token') ? (
                            <span className="text-xs font-bold bg-rose-500 text-white px-2 py-1 rounded">ALTO RIESGO</span> 
                         ) : (
                            <span className="text-xs font-bold bg-amber-500 text-white px-2 py-1 rounded">INVESTIGAR</span>
                         )}
                       </div>
                    </div>
                    );
                 })}
              </div>
            </div>
          )}

          {/* Breaches & Exposed Credentials */}
          {profile.normalizedData?.credentials && profile.normalizedData.credentials.length > 0 && (
            <div className="bg-fuchsia-950/20 p-5 rounded-xl border border-fuchsia-500/30 relative overflow-hidden col-span-1 md:col-span-3">
              <div className="absolute top-0 right-0 p-3 opacity-10"><Database className="w-16 h-16" /></div>
              <h4 className="font-bold text-fuchsia-400 mb-2 flex items-center gap-2">Inteligencia de Breaches OSINT</h4>
              <p className="text-xs text-fuchsia-200/70 mb-4">Credenciales y correos expuestos encontrados en filtraciones de datos o repositorios de código.</p>
              <div className="space-y-2 max-h-48 overflow-y-auto custom-scrollbar pr-2">
                 {profile.normalizedData.credentials.map((cred, idx) => (
                    <div key={idx} className="flex flex-col md:flex-row md:items-center justify-between p-3 bg-black/40 border border-fuchsia-500/20 rounded-lg">
                       <div className="flex items-center gap-3">
                         <span className="text-xs font-mono bg-fuchsia-500/20 text-fuchsia-300 px-2 py-1 rounded border border-fuchsia-500/30">{cred.type}</span>
                         <span className="font-mono text-sm text-zinc-200">{cred.email}</span>
                       </div>
                       <div className="flex items-center gap-4 mt-2 md:mt-0">
                         {cred.has_plaintext && <span className="text-[10px] uppercase text-rose-400 font-bold tracking-wider">Texto Plano Expuesto</span>}
                         {cred.high_risk && <span className="text-xs font-bold bg-rose-500 text-white px-2 py-1 rounded">ALTO RIESGO</span>}
                         <span className="text-xs font-bold bg-zinc-800 px-2 py-1 rounded border border-zinc-600">{cred.breach_count} Breaches</span>
                       </div>
                       {cred.breach_names && cred.breach_names.length > 0 && (
                         <div className="w-full mt-2 text-xs text-zinc-500 truncate md:w-auto md:mt-0" title={cred.breach_names.join(', ')}>
                           Sources: {cred.breach_names.slice(0, 2).join(', ')}{cred.breach_names.length > 2 ? ', ...' : ''}
                         </div>
                       )}
                    </div>
                 ))}
              </div>
            </div>
          )}
        </div>
      </motion.section>

      {/* SECTION 10: CORRELATION CENTER */}
      <motion.section initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{delay: 0.8}} className="glass-panel p-8 border-indigo-500/30 bg-indigo-950/10">
        <h3 className="text-2xl font-bold flex items-center gap-2 border-b border-indigo-500/20 pb-2 mb-6"><ClipboardCheck className="text-indigo-400" /> Correlation Center</h3>
        <p className="text-sm text-zinc-300 mb-8 max-w-3xl">Auditoría inteligente. FixGuard cruza Tecnologías, Entidades y Endpoints para reconstruir la lógica de la aplicación completa.</p>
        
        {profile.auditReport && profile.auditReport.contexts.length > 0 ? (
           <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
             {profile.auditReport.contexts.map((ctx, idx) => (
               <div key={idx} className="bg-zinc-950/50 p-5 rounded-xl border border-indigo-500/20">
                 <h4 className="font-bold text-indigo-300 text-lg mb-2">{ctx.name}</h4>
                 <p className="text-xs text-zinc-400 mb-4 min-h-[40px]">{ctx.description}</p>
                 
                 <div className="space-y-4">
                   <div>
                     <span className="text-[10px] uppercase text-zinc-500 font-bold mb-1 block">Ruta Relacional:</span>
                     <div className="flex flex-col gap-2 relative">
                        <div className="absolute left-2.5 top-2 bottom-2 w-0.5 bg-indigo-500/20"></div>
                        {ctx.inferredTechnologies.length > 0 && (
                          <div className="flex items-center gap-3 relative z-10">
                            <div className="w-5 h-5 rounded-full bg-indigo-500/20 flex items-center justify-center border border-indigo-500/50 text-[10px]">T</div>
                            <span className="text-xs font-mono text-indigo-200">{ctx.inferredTechnologies[0]}</span>
                          </div>
                        )}
                        <div className="flex items-center gap-3 relative z-10">
                           <div className="w-5 h-5 rounded-full bg-purple-500/20 flex items-center justify-center border border-purple-500/50 text-[10px]">E</div>
                           <span className="text-xs font-mono text-purple-200">Entidad de Negocio</span>
                        </div>
                        {ctx.evidences.length > 0 && (
                          <div className="flex items-center gap-3 relative z-10">
                            <div className="w-5 h-5 rounded-full bg-rose-500/20 flex items-center justify-center border border-rose-500/50 text-[10px]">A</div>
                            <span className="text-xs font-mono text-rose-200 truncate" title={ctx.evidences[0]}>{ctx.evidences[0]}</span>
                          </div>
                        )}
                     </div>
                   </div>
                 </div>
               </div>
             ))}
           </div>
        ) : (
           <div className="text-center p-8 bg-black/20 rounded-xl border border-white/5 text-zinc-500">
             No se pudo generar suficiente correlación cruzada en este objetivo.
           </div>
        )}
      </motion.section>

    </div>
  );
}
