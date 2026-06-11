'use client';

import { motion } from 'framer-motion';
import { Search } from 'lucide-react';
import { useState } from 'react';

interface HeroScannerProps {
  onScanStart: (url: string, mode: 'passive' | 'active' | 'aggressive' | 'sast') => void;
}

export default function HeroScanner({ onScanStart }: HeroScannerProps) {
  const [step, setStep] = useState<1 | 2>(1);
  const [url, setUrl] = useState('');
  const [mode, setMode] = useState<'passive' | 'active' | 'aggressive' | 'sast'>('passive');
  const [legalAccepted, setLegalAccepted] = useState(false);

  const handleNextStep = (e: React.FormEvent) => {
    e.preventDefault();
    if (url.trim()) {
      setStep(2);
    }
  };

  const handleSubmit = () => {
    if ((mode === 'active' || mode === 'aggressive') && !legalAccepted) return;
    onScanStart(url, mode);
  };

  return (
    <motion.div 
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -20, scale: 0.95 }}
      transition={{ duration: 0.5, ease: "easeOut" }}
      className="flex flex-col items-center w-full max-w-5xl mx-auto min-h-[50vh] px-4"
    >
      <div className="text-center mb-10 space-y-4">
        <h1 className="text-5xl md:text-6xl font-bold tracking-tight text-white">
          Auditoría de Seguridad <span className="text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 to-electric-blue-500" style={{ backgroundImage: 'linear-gradient(to right, #10b981, #3b82f6)' }}>Profesional.</span>
        </h1>
        <p className="text-zinc-400 text-lg md:text-xl font-light">
          Escáner DAST Avanzado y OSINT para infraestructura web moderna.
        </p>
      </div>

      {step === 1 ? (
        <form onSubmit={handleNextStep} className="w-full max-w-3xl relative group">
          <div className="absolute -inset-0.5 bg-gradient-to-r from-zinc-800 to-zinc-700 rounded-2xl blur opacity-30 group-hover:opacity-50 transition duration-500"></div>
          
          <div className="relative flex items-center bg-[#09090b] rounded-2xl border border-white/10 shadow-2xl overflow-hidden p-2">
            <div className="pl-4 pr-2 text-zinc-500">
              <Search size={24} />
            </div>
            <input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://tu-aplicacion.com"
              required
              className="flex-1 bg-transparent border-none outline-none text-zinc-100 font-mono text-lg md:text-xl py-4 placeholder:text-zinc-600 w-full"
            />
            
            <div className="relative p-[1px] rounded-xl overflow-hidden ml-2 flex-shrink-0">
              <div className="absolute inset-0 bg-[conic-gradient(from_90deg_at_50%_50%,#09090b_0%,#09090b_50%,#3b82f6_100%)] animate-border-spin mix-blend-screen opacity-100"></div>
              <button
                type="submit"
                className="relative px-8 py-4 bg-[#09090b] text-white font-medium rounded-xl hover:bg-zinc-900 transition-colors z-10 w-full h-full border border-white/5 shadow-[inset_0_1px_0_0_rgba(255,255,255,0.1)]"
              >
                Continuar
              </button>
            </div>
          </div>
        </form>
      ) : (
        <motion.div 
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          className="w-full space-y-8"
        >
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {/* Modalidad Pasiva */}
            <div 
              onClick={() => setMode('passive')}
              className={`p-5 rounded-2xl border cursor-pointer transition-all ${mode === 'passive' ? 'bg-[#3b82f6]/10 border-[#3b82f6] shadow-[0_0_20px_rgba(59,130,246,0.15)]' : 'bg-[#ffffff05] border-white/10 hover:border-white/20'}`}
            >
              <h3 className="text-lg font-bold text-white mb-2 flex items-center gap-2">
                PASIVO (OSINT)
                {mode === 'passive' && <span className="w-2 h-2 rounded-full bg-[#3b82f6] shadow-[0_0_8px_#3b82f6]"></span>}
              </h3>
              <p className="text-xs text-zinc-400 mb-3">Análisis silencioso. Evalúa configuraciones.</p>
              <ul className="text-[11px] text-zinc-500 space-y-1 font-mono">
                <li>✓ DNS, TLS, Cabeceras</li>
                <li>✓ JS Recon & Endpoints</li>
              </ul>
            </div>

            {/* Modalidad Activa */}
            <div 
              onClick={() => setMode('active')}
              className={`p-5 rounded-2xl border cursor-pointer transition-all ${mode === 'active' ? 'bg-[#f59e0b]/10 border-[#f59e0b] shadow-[0_0_20px_rgba(245,158,11,0.15)]' : 'bg-[#ffffff05] border-white/10 hover:border-white/20'}`}
            >
              <h3 className="text-lg font-bold text-white mb-2 flex items-center gap-2">
                ACTIVO
                {mode === 'active' && <span className="w-2 h-2 rounded-full bg-[#f59e0b] shadow-[0_0_8px_#f59e0b]"></span>}
              </h3>
              <p className="text-xs text-zinc-400 mb-3">Pruebas de penetración controladas (DAST).</p>
              <ul className="text-[11px] text-zinc-500 space-y-1 font-mono">
                <li>✓ SQLi & XSS básico</li>
                <li>✓ CORS & JWT Forging</li>
              </ul>
            </div>

            {/* Modalidad Agresiva */}
            <div 
              onClick={() => {
                setMode('aggressive');
                setLegalAccepted(false);
              }}
              className={`p-5 rounded-2xl border cursor-pointer transition-all ${mode === 'aggressive' ? 'bg-[#f43f5e]/10 border-[#f43f5e] shadow-[0_0_20px_rgba(244,63,94,0.15)]' : 'bg-[#ffffff05] border-white/10 hover:border-white/20'}`}
            >
              <h3 className="text-lg font-bold text-white mb-2 flex items-center gap-2">
                AGRESIVO
                {mode === 'aggressive' && <span className="w-2 h-2 rounded-full bg-[#f43f5e] shadow-[0_0_8px_#f43f5e]"></span>}
              </h3>
              <p className="text-xs text-zinc-400 mb-3">Mapea la web e inyecta payloads.</p>
              <ul className="text-[11px] text-zinc-500 space-y-1 font-mono">
                <li>✓ Crawling Inteligente</li>
                <li>✓ SSRF & Open Redirect</li>
              </ul>
            </div>

            {/* Modalidad SAST / Whitebox */}
            <div 
              onClick={() => setMode('sast')}
              className={`p-5 rounded-2xl border cursor-pointer transition-all ${mode === 'sast' ? 'bg-[#10b981]/10 border-[#10b981] shadow-[0_0_20px_rgba(16,185,129,0.15)]' : 'bg-[#ffffff05] border-white/10 hover:border-white/20'}`}
            >
              <h3 className="text-lg font-bold text-white mb-2 flex items-center gap-2">
                SAST (Código)
                {mode === 'sast' && <span className="w-2 h-2 rounded-full bg-[#10b981] shadow-[0_0_8px_#10b981]"></span>}
              </h3>
              <p className="text-xs text-zinc-400 mb-3">Lee archivos locales para cazar BOLA/IDOR.</p>
              <ul className="text-[11px] text-zinc-500 space-y-1 font-mono">
                <li>✓ Server Actions</li>
                <li>✓ Raw SQL Injection</li>
              </ul>
            </div>
          </div>

          {/* Advertencia Legal si es Activo, Agresivo o SAST */}
          {((mode === 'active' || mode === 'aggressive' || mode === 'sast')) && (
            <motion.div 
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              className={`${mode === 'aggressive' ? 'bg-rose-950/40 border-rose-600/50' : 'bg-orange-950/30 border-orange-900/50'} border rounded-xl p-4 flex items-start gap-4`}
            >
              <input 
                type="checkbox" 
                id="legal" 
                checked={legalAccepted}
                onChange={(e) => setLegalAccepted(e.target.checked)}
                className={`mt-1 w-5 h-5 rounded cursor-pointer ${mode === 'aggressive' ? 'border-rose-500 text-rose-600 bg-rose-950/50 focus:ring-rose-500/50' : 'border-orange-500 text-orange-600 bg-orange-950/50 focus:ring-orange-500/50'}`}
              />
              <label htmlFor="legal" className={`text-sm cursor-pointer select-none ${mode === 'aggressive' ? 'text-rose-200/90' : 'text-orange-200/80'}`}>
                <span className={`font-bold block mb-1 ${mode === 'aggressive' ? 'text-rose-400 text-base' : mode === 'sast' ? 'text-emerald-400' : 'text-orange-400'}`}>
                  {mode === 'aggressive' ? '⚠ ALERTA CRÍTICA: MODO AGRESIVO' : mode === 'sast' ? 'Análisis Estático (Local)' : 'Aviso Legal de Pentesting'}
                </span>
                {mode === 'aggressive' 
                  ? 'Este modo lanzará CIENTOS de peticiones, utilizará crawlers para descubrir rutas ocultas, e intentará forzar conexiones servidor a servidor (SSRF). Esto generará alertas masivas en los firewalls y puede degradar el rendimiento del objetivo. Confirmo que tengo autorización EXPLÍCITA para este bombardeo.'
                  : mode === 'sast'
                  ? 'Este modo leerá los archivos de código fuente localmente. Asegúrate de ingresar la ruta absoluta a tu proyecto (ej: d:\\Charmarket\\src).'
                  : `Confirmo que soy el propietario de ${url} o tengo autorización explícita para realizar pruebas de penetración activas contra esta infraestructura.`
                }
              </label>
            </motion.div>
          )}

          <div className="flex justify-between items-center pt-4 border-t border-white/10">
            <button 
              onClick={() => setStep(1)}
              className="px-6 py-2.5 text-zinc-400 hover:text-white transition-colors"
            >
              ← Volver
            </button>
            <button
              onClick={handleSubmit}
              disabled={((mode === 'active' || mode === 'aggressive' || mode === 'sast') && !legalAccepted)}
              className={`px-8 py-3 rounded-xl font-bold text-white transition-all shadow-lg
                ${((mode === 'active' || mode === 'aggressive' || mode === 'sast') && !legalAccepted) 
                  ? 'bg-zinc-800 text-zinc-500 cursor-not-allowed border border-zinc-700' 
                  : mode === 'aggressive' 
                    ? 'bg-gradient-to-r from-rose-600 to-rose-500 hover:from-rose-500 hover:to-rose-400 shadow-rose-500/25 border border-rose-400/50' 
                  : mode === 'active'
                    ? 'bg-gradient-to-r from-orange-600 to-orange-500 hover:from-orange-500 hover:to-orange-400 shadow-orange-500/25 border border-orange-400/50'
                  : mode === 'sast'
                    ? 'bg-gradient-to-r from-emerald-600 to-emerald-500 hover:from-emerald-500 hover:to-emerald-400 shadow-emerald-500/25 border border-emerald-400/50'
                    : 'bg-gradient-to-r from-blue-600 to-blue-500 hover:from-blue-500 hover:to-blue-400 shadow-blue-500/25 border border-blue-400/50'
                }
              `}
            >
              {mode === 'aggressive' ? 'INICIAR BOMBARDEO' : mode === 'sast' as any ? 'Escanear Código' : mode === 'active' ? 'Iniciar Ataque Autorizado' : 'Iniciar Escaneo Pasivo'}
            </button>
          </div>
        </motion.div>
      )}
    </motion.div>
  );
}
