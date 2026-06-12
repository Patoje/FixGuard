"use client";

import { motion } from "framer-motion";
import { WorkflowJourney } from "../types";
import { GitCommit, ArrowRight, ShieldCheck, CreditCard, Activity } from "lucide-react";

interface Props {
  workflows: WorkflowJourney[];
}

export default function WorkflowVisualizer({ workflows }: Props) {
  if (!workflows || workflows.length === 0) {
    return (
      <div className="text-zinc-500 text-sm p-4 text-center border border-dashed border-white/10 rounded-xl">
        No se pudieron inferir Workflows.
      </div>
    );
  }

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'Auth': return <ShieldCheck className="text-emerald-400 w-5 h-5" />;
      case 'Billing': return <CreditCard className="text-purple-400 w-5 h-5" />;
      default: return <Activity className="text-blue-400 w-5 h-5" />;
    }
  };

  const getCategoryColor = (category: string) => {
    switch (category) {
      case 'Auth': return 'border-emerald-500/30 bg-emerald-950/20';
      case 'Billing': return 'border-purple-500/30 bg-purple-950/20';
      default: return 'border-blue-500/30 bg-blue-950/20';
    }
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 w-full">
      {workflows.map((workflow, idx) => (
        <motion.div 
          key={idx}
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: idx * 0.1 }}
          className={`flex flex-col p-5 rounded-2xl border ${getCategoryColor(workflow.category)}`}
        >
          <div className="flex items-center justify-between mb-6 border-b border-white/5 pb-3">
            <h4 className="font-bold flex items-center gap-2 text-white">
              {getCategoryIcon(workflow.category)}
              {workflow.name}
            </h4>
            <span className="text-xs px-2 py-1 bg-black/40 rounded-full font-mono text-zinc-400 border border-white/5">
              Confianza: {Math.round(workflow.confidence * 100)}%
            </span>
          </div>

          <div className="flex flex-col relative pl-4 border-l-2 border-white/10 space-y-6">
            {workflow.steps.map((step, sIdx) => (
              <motion.div 
                key={sIdx}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: (idx * 0.1) + (sIdx * 0.1) + 0.2 }}
                className="relative"
              >
                {/* Indicador de Nodo en el árbol */}
                <div className="absolute -left-[25px] top-1 bg-black border-2 border-zinc-500 rounded-full w-3 h-3 z-10" />
                
                <div className="bg-black/40 border border-white/5 p-3 rounded-lg hover:border-white/20 transition-colors cursor-default">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300">
                      PASO {sIdx + 1}
                    </span>
                    <span className="font-semibold text-sm text-zinc-200">{step.name}</span>
                  </div>
                  
                  <div className="text-xs font-mono text-zinc-500 mb-2 mt-2 bg-black/30 p-1.5 rounded truncate">
                    <span className="text-cyan-400/70 mr-2">{step.method}</span>
                    {step.endpoint}
                  </div>
                  
                  <p className="text-xs text-zinc-400">{step.description}</p>
                </div>
              </motion.div>
            ))}
          </div>
        </motion.div>
      ))}
    </div>
  );
}
