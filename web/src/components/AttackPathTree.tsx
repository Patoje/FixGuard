"use client";

import { Vulnerability } from "../types";
import { GitMerge, Database, ShieldAlert, Code } from "lucide-react";
import { motion } from "framer-motion";

interface Props {
  vulnerabilities: Vulnerability[];
}

export default function AttackPathTree({ vulnerabilities }: Props) {
  // Build a tree from flat vulnerabilities
  const rootVulns = vulnerabilities.filter(v => !v.parentId);
  const getChildren = (parentId: number) => vulnerabilities.filter(v => v.parentId === parentId);

  if (vulnerabilities.length === 0 || rootVulns.length === 0) return null;

  const renderNode = (vuln: Vulnerability, level: number = 0) => {
    const children = getChildren(vuln.id);
    const isRoot = level === 0;

    let Icon = ShieldAlert;
    if (vuln.type.toLowerCase().includes('sql')) Icon = Database;
    if (vuln.type.toLowerCase().includes('xss')) Icon = Code;

    return (
      <div key={vuln.id} className="relative">
        <div className="flex items-start">
          {level > 0 && (
            <div className="flex">
              {Array(level - 1).fill(0).map((_, i) => (
                <div key={i} className="w-8 border-l border-zinc-700/50 -ml-[1px]" />
              ))}
              <div className="w-8 h-6 border-l border-b border-zinc-700/50 rounded-bl-xl -ml-[1px] mb-auto" />
            </div>
          )}
          
          <motion.div 
            initial={{ opacity: 0, x: -10 }}
            animate={{ opacity: 1, x: 0 }}
            className={`
              relative flex items-center gap-3 p-3 rounded-lg border my-1
              ${isRoot ? 'bg-zinc-900/80 border-blue-500/30 w-full max-w-xl' : 'bg-zinc-900/40 border-zinc-800/80'}
            `}
          >
            <div className={`p-2 rounded-md ${isRoot ? 'bg-blue-500/20 text-blue-400' : 'bg-rose-500/10 text-rose-400'}`}>
              <Icon className="w-4 h-4" />
            </div>
            <div>
              <div className="text-sm font-bold text-zinc-200">{vuln.type}</div>
              <div className="text-xs text-zinc-500 font-mono truncate max-w-sm">
                {vuln.description.split('\n')[0].substring(0, 60)}...
              </div>
            </div>
          </motion.div>
        </div>

        {/* Render children recursively */}
        {children.length > 0 && (
          <div className="mt-1">
            {children.map(child => renderNode(child, level + 1))}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="glass-panel p-6 border-zinc-800/50 mt-8 mb-8">
      <div className="flex items-center gap-3 mb-6 border-b border-white/5 pb-4">
        <GitMerge className="w-5 h-5 text-zinc-400" />
        <h3 className="text-xl font-semibold text-zinc-100">Caminos de Ataque (Attack Paths)</h3>
      </div>
      
      <div className="bg-zinc-950/50 p-6 rounded-xl border border-white/5 overflow-x-auto">
        {rootVulns.map(root => renderNode(root, 0))}
      </div>
    </div>
  );
}
