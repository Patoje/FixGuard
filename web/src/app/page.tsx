"use client";

import { useState, useEffect, useRef } from "react";
import HeroScanner from "@/components/HeroScanner";
import ScanningState from "@/components/ScanningState";
import VulnerabilityCard from "@/components/VulnerabilityCard";
import ReconDashboard from "@/components/ReconDashboard";
import OffensiveArsenal from "@/components/OffensiveArsenal";

import { ScanMode, TerminalLog, Vulnerability, ReconProfile, ScanStatus } from "@/types";
import { AnimatePresence, motion } from "framer-motion";

type FlowStep = "setup" | "scanning" | "results";

const ENGINES = {
  passive: ["Headers (OWASP)", "TLS/SSL", "DNS Records", "Ports", "Directories", "WAF Detection", "Fingerprint", "Security.txt", "JSRecon", "Next.js Data", "Cloud Exposure", "WebSockets", "Uploads"],
  active: ["SQLi (Time-Based)", "XSS (Reflected/DOM)", "CORS Misconfig", "GraphQL Introspection", "SourceMaps Leak", "API Discovery", "Secrets Extraction", "JWT (alg: none)", "Path Traversal", "Parameter Pollution", "Rate Limiting", "Server Actions Exposed"],
  aggressive: ["Intelligent Crawler", "BOLA / IDOR", "SSRF", "Open Redirect"],
  sast: ["Client-Side Auth", "Dependency Confusion", "DOM XSS (React)", "Mass Assignment", "ORM Injection (Drizzle/Prisma)", "Server Actions (BFLA)"]
};

export default function Home() {
  const [step, setStep] = useState<FlowStep>("setup");
  const [logs, setLogs] = useState<TerminalLog[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [reconProfile, setReconProfile] = useState<ReconProfile | null>(null);
  const [scanId, setScanId] = useState<number | null>(null);
  const [scanStatus, setScanStatus] = useState<ScanStatus>("pending");
  const [targetUrl, setTargetUrl] = useState<string>("");
  const [resultsTab, setResultsTab] = useState<"recon" | "offensive">("recon");
  
  // Ref to track if simulation is running
  const simulationRef = useRef<boolean>(false);

  const addLog = (message: string, type: TerminalLog["type"] = "info") => {
    setLogs((prev) => [
      ...prev,
      {
        id: Math.random().toString(36).substring(7),
        timestamp: new Date().toLocaleTimeString(),
        message,
        type,
      },
    ]);
  };

  const simulateTerminalLogs = async (mode: ScanMode) => {
    simulationRef.current = true;
    
    const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
    
    let enginesToRun: string[] = [];
    if (mode === "sast") {
      enginesToRun = [...ENGINES.sast];
    } else {
      enginesToRun = [...ENGINES.passive];
      if (mode === "active" || mode === "aggressive") {
        enginesToRun = [...enginesToRun, ...ENGINES.active];
      }
      if (mode === "aggressive") {
        enginesToRun = [...enginesToRun, ...ENGINES.aggressive];
      }
    }

    addLog(`[System] Cargando ${enginesToRun.length} motores de escaneo...`, "info");
    await delay(1000);

    for (const engine of enginesToRun) {
      if (!simulationRef.current) break; // Detener si salimos de la pantalla
      addLog(`Ejecutando motor: ${engine}...`, "info");
      
      // Simular tiempo de ejecución aleatorio entre 500ms y 1500ms
      await delay(Math.floor(Math.random() * 1000) + 500);
      
      // Simular que algunos motores encuentran cosas raras (advertencias)
      if (Math.random() > 0.8) {
        addLog(`[${engine}] Detectado comportamiento inusual o puerto abierto.`, "warning");
      } else {
        addLog(`[${engine}] Escaneo limpio.`, "success");
      }
    }
  };

  const handleScan = async (url: string, mode: ScanMode, vectorId?: string) => {
    setStep("scanning");
    setLogs([]);
    setVulnerabilities([]);
    setReconProfile(null);
    setScanStatus("pending");
    setTargetUrl(url);
    
    addLog(`Iniciando motor FixGuard en modo: ${mode.toUpperCase()}`, "info");
    addLog(`Objetivo fijado: ${url}`, "warning");
    if (vectorId) {
      addLog(`Ejecutando Ataque Dirigido: [${vectorId}]`, "warning");
    }

    try {
      // 1. Crear el escaneo en la base de datos local (Next.js API)
      addLog("Inicializando base de datos local...", "info");
      const initRes = await fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ targetUrl: url, mode }),
      });
      
      if (!initRes.ok) throw new Error("Fallo al crear el escaneo en DB");
      const { scanId: newScanId } = await initRes.json();
      setScanId(newScanId);
      addLog(`ID de escaneo registrado: ${newScanId}`, "success");

      // Iniciar simulación visual de la terminal mientras el worker hace el trabajo real
      simulateTerminalLogs(mode);

      // 2. Enviar el trabajo al Worker de Node.js
      addLog("Contactando al worker en http://localhost:4000...", "info");
      
      let endpoint = "/api/scan";
      let bodyData: any = { targetUrl: url, scanId: newScanId, mode };
      
      if (mode === "sast") {
        endpoint = "/api/sast";
        bodyData = { targetDir: url, scanId: newScanId, mode };
      } else if (mode === "targeted") {
        endpoint = "/api/attack/targeted";
        bodyData = { targetUrl: url, scanId: newScanId, vectorId };
      }
      
      const workerRes = await fetch(`http://localhost:4000${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(bodyData),
      });

      if (!workerRes.ok) {
        throw new Error("Worker no responde o devolvió error.");
      }
      
      addLog(`Worker aceptó el trabajo. Esperando resultados...`, "success");
      setScanStatus("in_progress");
      
    } catch (error) {
      addLog(`Error al conectar con el worker: ${(error as Error).message}`, "error");
      addLog("El backend no está encendido o falló.", "error");
      setScanStatus("error");
      // Detener simulación
      simulationRef.current = false;
      setTimeout(() => {
        setStep("results");
      }, 2000);
    }
  };

  const handleResumeAttack = async (decision: 'attack_all' | 'skip') => {
    addLog(`Enviando decisión: ${decision}...`, "info");
    setScanStatus("in_progress"); // Esto reiniciará el polling
    if (decision === 'attack_all') {
      simulateTerminalLogs('aggressive'); // Reanudamos simulación
    } else {
      addLog("Saltando fase ofensiva. Generando reporte...", "warning");
    }

    try {
      await fetch(`http://localhost:4000/api/scan/resume`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scanId, targetUrl, decision }),
      });
    } catch (error) {
      addLog(`Error al reanudar el escaneo: ${(error as Error).message}`, "error");
    }
  };

  const handleTargetedAttack = async (vectorId: string) => {
    addLog(`Ejecutando Ataque Dirigido Inline: [${vectorId}]...`, "warning");
    setStep("scanning");
    setScanStatus("pending");
    simulationRef.current = true;
    
    try {
      addLog("Contactando al worker para inyección manual...", "info");
      const workerRes = await fetch(`http://localhost:4000/api/attack/targeted`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ targetUrl, scanId, vectorId }),
      });

      if (!workerRes.ok) {
        throw new Error("Worker no responde o devolvió error.");
      }
      
      addLog(`Worker aceptó el trabajo dirigido. Esperando resultados...`, "success");
      setScanStatus("in_progress");
      
    } catch (error) {
      addLog(`Error al conectar con el worker: ${(error as Error).message}`, "error");
      setScanStatus("error");
      simulationRef.current = false;
      setTimeout(() => {
        setStep("results");
      }, 2000);
    }
  };

  // Polling Effect
  useEffect(() => {
    let interval: NodeJS.Timeout;

    if (step === "scanning" && scanId && scanStatus !== "paused_for_approval") {
      interval = setInterval(async () => {
        try {
          const res = await fetch(`/api/scans/${scanId}`);
          if (res.ok) {
            const data = await res.json();
            
            if (data.scan.status === "paused_for_approval") {
              simulationRef.current = false; // Parar la terminal falsa
              setScanStatus("paused_for_approval");
              clearInterval(interval);
            } else if (data.scan.status === "completed" || data.scan.status === "failed") {
              simulationRef.current = false; // Parar la terminal falsa
              addLog(`Escaneo finalizado con estado: ${data.scan.status}`, data.scan.status === "completed" ? "success" : "error");
              setVulnerabilities(data.vulnerabilities || []);
              if (data.reconProfile) setReconProfile(data.reconProfile);
              setScanStatus(data.scan.status);
              clearInterval(interval);
              
              // Pasar a la pantalla de resultados
              setTimeout(() => {
                setStep("results");
              }, 1500);
            }
          }
        } catch (e) {
          console.error("Error polling", e);
        }
      }, 2000);
    }

    return () => {
      if (interval) clearInterval(interval);
    };
  }, [step, scanId, scanStatus]);

  const resetScan = () => {
    setStep("setup");
    setScanId(null);
    setLogs([]);
    setVulnerabilities([]);
    setReconProfile(null);
    setResultsTab("recon");
    simulationRef.current = false;
  };

  // Refresh findings after a targeted attack completes
  const refreshFindings = async () => {
    if (!scanId) return;
    try {
      const res = await fetch(`/api/scans/${scanId}`);
      if (res.ok) {
        const data = await res.json();
        if (data.vulnerabilities) setVulnerabilities(data.vulnerabilities);
        if (data.reconProfile) setReconProfile(data.reconProfile);
      }
    } catch (e) {
      console.error('Error refreshing findings', e);
    }
  };

  return (
    <main className="min-h-screen relative p-4 pb-20">
      {/* Background decorations */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden z-[-1]">
        <div className="absolute top-[-20%] left-[-10%] w-[50%] h-[50%] bg-blue-900/10 blur-[120px] rounded-full mix-blend-screen"></div>
        <div className="absolute bottom-[-20%] right-[-10%] w-[50%] h-[50%] bg-rose-900/10 blur-[120px] rounded-full mix-blend-screen"></div>
      </div>

      <AnimatePresence mode="wait">
        {step === "setup" && (
          <motion.div
            key="setup-view"
            initial={{ opacity: 0, x: -50 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: 50 }}
            transition={{ duration: 0.5 }}
          >
            <HeroScanner onScan={handleScan} isScanning={false} />
          </motion.div>
        )}

        {step === "scanning" && (
          <motion.div
            key="scanning-view"
            initial={{ opacity: 0, y: 50 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -50 }}
            transition={{ duration: 0.5 }}
            className="pt-20"
          >
            <div className="text-center mb-8">
              <h2 className="text-3xl font-bold text-zinc-100 mb-2 flex items-center justify-center gap-3">
                {scanStatus === "paused_for_approval" ? (
                  <span className="text-orange-400">⚠️ Confirmación Requerida</span>
                ) : (
                  <>
                    <div className="w-4 h-4 bg-blue-500 rounded-full animate-pulse"></div>
                    Ejecutando FixGuard
                  </>
                )}
              </h2>
              <p className="text-zinc-400 font-mono">
                {scanStatus === "paused_for_approval" ? "El escaneo pasivo finalizó. Esperando tu instrucción para proceder..." : "Realizando auditoría. Por favor, espere..."}
              </p>
            </div>

            {scanStatus === "paused_for_approval" && (
              <motion.div 
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                className="max-w-2xl mx-auto mb-8 bg-orange-500/10 border border-orange-500/20 p-6 rounded-xl text-center backdrop-blur-md"
              >
                <h3 className="text-xl font-bold text-orange-400 mb-4">¿Desea iniciar la inyección de payloads en todos los endpoints descubiertos?</h3>
                <p className="text-sm text-zinc-300 mb-6">
                  Se ha descubierto la superficie de ataque completa. Proceder con el ataque agresivo inyectará masivamente código en todas las rutas encontradas (decenas o cientos de peticiones por segundo).
                </p>
                <div className="flex gap-4 justify-center">
                  <button 
                    onClick={() => handleResumeAttack('skip')}
                    className="px-6 py-3 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded-lg font-bold transition-colors border border-zinc-700"
                  >
                    Omitir Fase Ofensiva
                  </button>
                  <button 
                    onClick={() => handleResumeAttack('attack_all')}
                    className="px-6 py-3 bg-rose-600 hover:bg-rose-500 text-white rounded-lg font-bold transition-colors shadow-lg shadow-rose-500/20"
                  >
                    Lanzar Ataque Masivo
                  </button>
                </div>
              </motion.div>
            )}

            <ScanningState logs={logs} isActive={scanStatus !== "paused_for_approval"} />
          </motion.div>
        )}

        {step === "results" && (
          <motion.div
            key="results-view"
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="w-full max-w-4xl mx-auto mt-12 space-y-8 pt-10"
          >
            <div className="flex items-center justify-between border-b border-zinc-800 pb-6">
              <div className="flex gap-4">
                <button
                  onClick={() => setResultsTab("recon")}
                  className={`px-4 py-2 rounded-lg font-bold transition-colors ${
                    resultsTab === "recon" 
                      ? "bg-blue-600 text-white shadow-[0_0_15px_rgba(37,99,235,0.3)]" 
                      : "bg-zinc-900 text-zinc-400 hover:text-white"
                  }`}
                >
                  Audit & Recon (Digital Twin)
                </button>
                <button
                  onClick={() => setResultsTab("offensive")}
                  className={`px-4 py-2 rounded-lg font-bold transition-colors border ${
                    resultsTab === "offensive" 
                      ? "bg-rose-600 text-white border-rose-500 shadow-[0_0_15px_rgba(244,63,94,0.3)]" 
                      : "bg-zinc-900/50 text-rose-400/50 border-rose-500/20 hover:text-rose-300 hover:bg-rose-950/30"
                  }`}
                >
                  Offensive Hub (Arsenal)
                </button>
              </div>
              <div className="flex gap-4">
                {scanId && (
                  <button
                    onClick={() => window.open(`/api/export/${scanId}`, '_blank')}
                    className="bg-emerald-600/20 text-emerald-400 border border-emerald-500/50 px-6 py-2 rounded-full font-mono hover:bg-emerald-600/40 transition-colors flex items-center gap-2"
                  >
                    <span>↓ Exportar Reporte</span>
                  </button>
                )}
                <button
                  onClick={resetScan}
                  className="bg-zinc-900 border border-zinc-700 px-6 py-2 rounded-full font-mono text-zinc-300 hover:text-white hover:bg-zinc-800 transition-colors"
                >
                  Escanear otro objetivo
                </button>
              </div>
            </div>
            
            {resultsTab === "recon" ? (
              <>
                {reconProfile ? (
                  <ReconDashboard profile={reconProfile} targetUrl={targetUrl} onLaunchAttack={handleTargetedAttack} />
                ) : (
                  <div className="bg-blue-500/10 border border-blue-500/20 p-6 rounded-xl text-center mb-8 mt-8">
                    <h3 className="text-xl font-bold text-blue-400 mb-2">Ataque Dirigido Finalizado</h3>
                    <p className="text-zinc-400">Este reporte corresponde a la ejecución individual de una herramienta CLI profesional. No se realizó recolección de inteligencia de superficie (OSINT) al ser un ataque directo.</p>
                  </div>
                )}

                {vulnerabilities.length === 0 ? (
                  <div className="text-center p-12 glass-panel border-emerald-500/20 bg-emerald-500/5 mt-8">
                    <h3 className="text-2xl font-bold text-emerald-400 mb-2">¡Todo se ve seguro!</h3>
                    <p className="text-zinc-400">No se encontraron vulnerabilidades para el objetivo seleccionado.</p>
                  </div>
                ) : (
                  <>

                    
                    <div className="space-y-4 mt-8">
                      <h3 className="text-2xl font-bold text-zinc-100 flex items-center gap-3 border-b border-white/5 pb-4 mb-6">
                        <span className="w-2 h-8 bg-rose-500 rounded-full inline-block"></span>
                        Vulnerabilidades Detectadas
                      </h3>
                      {vulnerabilities.map((vuln, index) => (
                        <VulnerabilityCard key={vuln.id} vuln={vuln} index={index} />
                      ))}
                    </div>
                  </>
                )}
              </>
            ) : (
              <div className="mt-8">
                {scanId && reconProfile ? (
                  <OffensiveArsenal targetUrl={targetUrl} scanId={scanId} profile={reconProfile} onAttackComplete={refreshFindings} />
                ) : (
                  <div className="text-center p-12 glass-panel border-rose-500/20 bg-rose-500/5">
                    <h3 className="text-2xl font-bold text-rose-400 mb-2">Arsenal Desactivado</h3>
                    <p className="text-zinc-400">Debes realizar un escaneo completo primero para habilitar el arsenal ofensivo en este objetivo.</p>
                  </div>
                )}
              </div>
            )}

            <div className="flex justify-center pt-8 gap-4">
              <button
                onClick={async () => {
                  if (!scanId) return;
                  try {
                    const res = await fetch(`/api/export/markdown?scanId=${scanId}`);
                    const data = await res.json();
                    if (data.markdown) {
                      const blob = new Blob([data.markdown], { type: 'text/markdown' });
                      const url = window.URL.createObjectURL(blob);
                      const a = document.createElement('a');
                      a.href = url;
                      a.download = `FixGuard_Report_${scanId}.md`;
                      a.click();
                      window.URL.revokeObjectURL(url);
                    }
                  } catch(e) { console.error('Error exporting', e); }
                }}
                className="bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-400 border border-emerald-500/50 px-8 py-3 rounded-full font-bold transition-colors"
              >
                Exportar a Markdown
              </button>

              <button
                onClick={resetScan}
                className="bg-blue-600 hover:bg-blue-500 text-white px-8 py-3 rounded-full font-bold transition-colors shadow-lg shadow-blue-500/20"
              >
                Volver al Inicio
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </main>
  );
}
