import { motion } from 'framer-motion';
import { useEffect, useState } from 'react';

export default function ScanningState({ mode = 'passive' }: { mode?: 'passive' | 'active' | 'aggressive' | 'sast' }) {
  const [stepIndex, setStepIndex] = useState(0);

  let themeColor = '';
  let themeTitle = '';
  let terminalSteps: string[] = [];

  if (mode === 'passive') {
    themeColor = '#3b82f6'; // Blue
    themeTitle = 'Analyzing Target Security (OSINT)...';
    terminalSteps = [
      'Initializing OSINT passive scan...',
      'Resolving target DNS...',
      'Probing HTTP ports 80/443...',
      'Fetching response headers...',
      'Analyzing OWASP Top 10 configurations...',
      'Realizando JS Recon y buscando endpoints ocultos...',
      'Extrayendo Build IDs de Next.js...',
      'Buscando Buckets de S3/Cloud expuestos...',
      'Generating final compliance report...',
    ];
  } else if (mode === 'active') {
    themeColor = '#f59e0b'; // Orange
    themeTitle = 'Lanzando Ataque Controlado (Active)...';
    terminalSteps = [
      'Initializing ACTIVE PENTESTING suite...',
      'Fuzzing input parameters (SQLi / XSS)...',
      'Falsificando Origen HTTP (CORS Bypass)...',
      'Forzando vulnerabilidades JWT (alg: none)...',
      'Intentando Directory Traversal...',
      'Contaminando parámetros (HPP)...',
      'Bombardeando API (Rate Limiting check)...',
      'Generating final vulnerability report...',
    ];
  } else if (mode === 'sast') {
    themeColor = '#10b981'; // Emerald
    themeTitle = 'Análisis Estático de Código Fuente (SAST)...';
    terminalSteps = [
      'Inicializando Motor SAST (Whitebox)...',
      'Leyendo árbol de directorios locales...',
      'Construyendo AST de archivos .ts y .tsx...',
      'Buscando Server Actions ("use server")...',
      'Validando Auth en mutaciones de Base de Datos...',
      'Rastreando Raw SQL Injection (Prisma/Drizzle)...',
      'Buscando DOM XSS (dangerouslySetInnerHTML)...',
      'Verificando dependencias en package.json...',
      'Generating final code security report...',
    ];
  } else {
    themeColor = '#f43f5e'; // Red (Aggressive)
    themeTitle = 'INICIANDO BOMBARDEO AGRESIVO...';
    terminalSteps = [
      'Initializing AGGRESSIVE suite...',
      'Lanzando Crawler Inteligente (Mapeando SPA)...',
      'Descubriendo rutas ocultas (/dashboard, /api)...',
      'Atacando TODAS las rutas descubiertas...',
      'Probando incrementos de IDs numéricos (BOLA Real)...',
      'Inyectando payloads SSRF en parámetros...',
      'Envenenando variables de redirección (Open Redirect)...',
      'Fuzzing profundo y exhaustivo...',
      'Generating final critical report...',
    ];
  }

  useEffect(() => {
    const interval = setInterval(() => {
      setStepIndex((prev) => (prev < terminalSteps.length - 1 ? prev + 1 : prev));
    }, 800);
    return () => clearInterval(interval);
  }, [terminalSteps.length]);

  return (
    <motion.div 
      initial={{ opacity: 0, height: 0 }}
      animate={{ opacity: 1, height: 'auto' }}
      className="w-full max-w-3xl mx-auto p-8 rounded-2xl bg-[#ffffff08] border border-white/10 backdrop-blur-md relative overflow-hidden mt-10"
    >
      {/* Radar sweep background effect */}
      <div className="absolute inset-0 opacity-20 pointer-events-none flex items-center justify-center overflow-hidden">
         <div 
           className={`w-[800px] h-[800px] rounded-full border relative flex items-center justify-center`}
           style={{ borderColor: `${themeColor}33` }}
         >
            <div 
              className={`absolute w-[400px] h-[400px] rounded-full border`}
              style={{ borderColor: `${themeColor}1A` }}
            ></div>
            <div 
              className={`absolute inset-0 rounded-full border-t animate-radar-sweep origin-center`} 
              style={{ 
                borderColor: themeColor,
                background: `conic-gradient(from 0deg, transparent 0%, transparent 70%, ${themeColor}66 100%)` 
              }}
            ></div>
         </div>
      </div>

      <div className="relative z-10 flex flex-col items-center">
        <div 
          className={`h-16 w-16 mb-6 rounded-full border-4 border-zinc-800 animate-spin`}
          style={{ borderTopColor: themeColor }}
        ></div>
        
        <h3 className="text-xl text-zinc-200 font-medium mb-8 tracking-wide">
          {themeTitle}
        </h3>

        <div className="w-full bg-[#09090b]/80 backdrop-blur-md rounded-lg border border-white/10 p-4 font-mono text-sm text-zinc-400 h-48 overflow-hidden relative shadow-inner">
           <div className="absolute top-3 left-4 text-zinc-600 animate-pulse">_</div>
           <div className="flex flex-col gap-3 mt-4 px-2">
             {terminalSteps.slice(Math.max(0, stepIndex - 4), stepIndex + 1).map((step, i) => {
                const isLatest = i === Math.min(stepIndex, 4);
                return (
                  <motion.div 
                    key={step} 
                    initial={{ opacity: 0, x: -10 }} 
                    animate={{ opacity: 1, x: 0 }}
                    className="flex items-center gap-3"
                  >
                    <span style={{ color: themeColor }} className="font-bold">{'>'}</span>
                    <span className={isLatest ? 'text-zinc-100' : 'text-zinc-500'}>{step}</span>
                  </motion.div>
                )
             })}
           </div>
        </div>
      </div>
    </motion.div>
  );
}
