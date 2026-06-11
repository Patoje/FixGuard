"use client";

import { motion } from "framer-motion";
import { ArrowRight, Route, Activity } from "lucide-react";

interface WorkflowStep {
  name: string;
  endpoint: string;
  method: string;
  description: string;
}

interface WorkflowJourney {
  name: string;
  category: string;
  steps: WorkflowStep[];
  confidence: number;
}

interface Props {
  journeys: WorkflowJourney[];
}

export default function WorkflowTimeline({ journeys }: Props) {
  if (!journeys || journeys.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center p-12 text-zinc-500 border border-zinc-800 border-dashed rounded-xl">
        <Route className="w-12 h-12 mb-4 opacity-50" />
        <p>No se descubrieron secuencias funcionales aún.</p>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {journeys.map((journey, jIdx) => (
        <div key={jIdx} className="glass-panel p-6 border border-zinc-800 rounded-xl bg-zinc-900/40 relative overflow-hidden">
          {/* Header */}
          <div className="flex items-center justify-between mb-8 border-b border-zinc-800/50 pb-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-blue-500/10 flex items-center justify-center border border-blue-500/20">
                <Activity className="w-5 h-5 text-blue-400" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-zinc-100">{journey.name}</h3>
                <span className="text-xs font-mono text-zinc-500">Categoría: {journey.category}</span>
              </div>
            </div>
            <div className="text-right">
              <div className="text-xs text-zinc-400">Confianza Algorítmica</div>
              <div className="text-sm font-bold font-mono text-blue-400">{(journey.confidence * 100).toFixed(0)}%</div>
            </div>
          </div>

          {/* Timeline */}
          <div className="relative">
            {/* Línea conectora */}
            <div className="absolute top-1/2 left-0 w-full h-[2px] bg-zinc-800 -translate-y-1/2 z-0 hidden md:block"></div>
            
            <div className="flex flex-col md:flex-row gap-6 relative z-10">
              {journey.steps.map((step, sIdx) => (
                <motion.div 
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: sIdx * 0.1 }}
                  key={sIdx} 
                  className="flex-1 min-w-[200px]"
                >
                  <div className="bg-zinc-950 border border-zinc-700/50 rounded-xl p-4 shadow-lg hover:border-blue-500/30 transition-colors">
                    <div className="flex items-center justify-between mb-2">
                      <div className="text-xs font-bold font-mono px-2 py-1 bg-zinc-800 rounded text-zinc-300">
                        Paso {sIdx + 1}
                      </div>
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                        step.method === 'POST' ? 'bg-green-500/20 text-green-400' :
                        step.method === 'GET' ? 'bg-blue-500/20 text-blue-400' : 'bg-zinc-800 text-zinc-400'
                      }`}>
                        {step.method}
                      </span>
                    </div>
                    <h4 className="font-bold text-zinc-200 text-sm mb-1">{step.name}</h4>
                    <p className="text-xs text-zinc-500 mb-2 truncate" title={step.endpoint}>{step.endpoint}</p>
                    <p className="text-[11px] text-zinc-400 leading-relaxed border-t border-zinc-800/50 pt-2">
                      {step.description}
                    </p>
                  </div>
                </motion.div>
              ))}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
