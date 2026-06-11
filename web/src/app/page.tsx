'use client';

import { useState, useEffect } from 'react';
import { Shield } from 'lucide-react';
import HeroScanner from '@/components/scanner/HeroScanner';
import ScanningState from '@/components/scanner/ScanningState';
import VulnerabilityCard from '@/components/scanner/VulnerabilityCard';
import { ScanState, Vulnerability } from '@/types/scanner';
import { AnimatePresence, motion } from 'framer-motion';
import { startScan, checkScanStatus, startSastScan } from '@/app/actions';

export default function Home() {
  const [scanState, setScanState] = useState<ScanState>('idle');
  const [targetUrl, setTargetUrl] = useState('');
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [currentScanId, setCurrentScanId] = useState<number | null>(null);
  const [scanMode, setScanMode] = useState<'passive' | 'active' | 'aggressive' | 'sast'>('passive');

  const handleScanStart = async (url: string, mode: 'passive' | 'active' | 'aggressive' | 'sast') => {
    setTargetUrl(url);
    setScanMode(mode);
    setScanState('scanning');
    
    let res;
    if (mode === 'sast') {
      res = await startSastScan(url);
    } else {
      res = await startScan(url, mode);
    }
    
    if (res.success && res.scanId) {
      setCurrentScanId(res.scanId);
    } else {
      console.error(res.error);
      alert(res.error);
      setScanState('failed');
    }
  };

  // Polling para revisar el estado en la base de datos
  useEffect(() => {
    let interval: NodeJS.Timeout;

    if (scanState === 'scanning' && currentScanId) {
      interval = setInterval(async () => {
        const res = await checkScanStatus(currentScanId);
        
        if (res.status === 'completed' || res.status === 'failed') {
          clearInterval(interval);
          if (res.vulnerabilities) {
            const severityWeight = {
              'CRITICAL': 4,
              'HIGH': 3,
              'MEDIUM': 2,
              'LOW': 1
            };
            const sortedVulns = (res.vulnerabilities as Vulnerability[]).sort((a, b) => {
              return (severityWeight[b.severity as keyof typeof severityWeight] || 0) - (severityWeight[a.severity as keyof typeof severityWeight] || 0);
            });
            setVulnerabilities(sortedVulns);
          }
          setScanState(res.status as ScanState);
        }
      }, 2000); // Consultar cada 2 segundos
    }

    return () => {
      if (interval) clearInterval(interval);
    };
  }, [scanState, currentScanId]);

  return (
    <main className="min-h-screen bg-[#09090b] text-white selection:bg-[#3b82f6]/30 overflow-x-hidden">
      {/* Top Navbar */}
      <nav className="fixed top-0 left-0 right-0 h-20 border-b border-white/5 bg-[#09090b]/70 backdrop-blur-xl z-50 flex items-center justify-between px-6 md:px-12">
        <div className="flex items-center gap-3">
          <Shield className="text-[#3b82f6]" size={32} strokeWidth={2.5} />
          <span className="font-bold text-2xl tracking-tighter">FixGuard</span>
          <span className="hidden md:inline-block ml-3 px-2.5 py-0.5 rounded-full bg-[#10b981]/10 text-xs font-semibold text-[#10b981] border border-[#10b981]/20">
            DAST LITE
          </span>
        </div>
        <div className="flex items-center gap-4 text-sm font-medium text-zinc-400">
           <span className="hover:text-white cursor-pointer transition-colors">Documentation</span>
           <span className="hover:text-white cursor-pointer transition-colors">Dashboard</span>
        </div>
      </nav>

      {/* Main Content */}
      <div className="pt-32 pb-32 px-4 md:px-8 w-full">
        <AnimatePresence mode="wait">
          {scanState === 'idle' && (
            <HeroScanner key="hero" onScanStart={handleScanStart} />
          )}

          {scanState === 'scanning' && (
            <ScanningState key="scanning" mode={scanMode} />
          )}

          {scanState === 'completed' && (
            <motion.div 
              key="results"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              className="w-full max-w-4xl mx-auto pt-8"
            >
              <div className="mb-12 text-center">
                <h2 className="text-4xl font-bold mb-4 tracking-tight">Scan Results</h2>
                <p className="text-zinc-400 text-lg">
                  Target: <span className="text-white font-mono bg-white/5 px-3 py-1.5 rounded-lg border border-white/10 inline-block mt-2 md:mt-0 md:ml-2">{targetUrl}</span>
                </p>
              </div>

              {vulnerabilities.length === 0 ? (
                <div className="text-center p-12 border border-white/10 rounded-2xl bg-[#ffffff08] backdrop-blur-xl">
                  <h3 className="text-2xl text-emerald-400 font-semibold mb-2">Resultados Limpios</h3>
                  <p className="text-zinc-400">No se detectaron vulnerabilidades, o el objetivo rechazó las peticiones del escáner (Timeouts/WAF).</p>
                </div>
              ) : (
                <div className="space-y-8">
                  {vulnerabilities.map((vuln, i) => (
                    <VulnerabilityCard key={vuln.id} vulnerability={vuln} index={i} />
                  ))}
                </div>
              )}

              <div className="mt-16 flex justify-center">
                <button 
                  onClick={() => {
                    setScanState('idle');
                    setVulnerabilities([]);
                    setCurrentScanId(null);
                  }}
                  className="px-8 py-4 bg-white/5 hover:bg-white/10 border border-white/10 rounded-xl transition-colors font-medium text-zinc-300 flex items-center gap-2 hover:shadow-xl"
                >
                  Start New Scan
                </button>
              </div>
            </motion.div>
          )}

          {scanState === 'failed' && (
             <div className="text-center pt-20">
                <h2 className="text-2xl font-bold text-rose-500 mb-4">Scan Failed</h2>
                <p className="text-zinc-400 mb-8">Hubo un error al intentar comunicar con el Worker. Verifica la terminal.</p>
                <button 
                  onClick={() => setScanState('idle')}
                  className="px-6 py-3 bg-white/10 rounded-xl"
                >
                  Intentar de nuevo
                </button>
             </div>
          )}
        </AnimatePresence>
      </div>
    </main>
  );
}
