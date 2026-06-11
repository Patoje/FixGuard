"use client";

import { useEffect, useRef } from "react";
import { motion } from "framer-motion";
import { TerminalLog } from "../types";
import { Radar } from "lucide-react";

interface ScanningStateProps {
  logs: TerminalLog[];
  isActive: boolean;
}

export default function ScanningState({ logs, isActive }: ScanningStateProps) {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  if (!isActive && logs.length === 0) return null;

  return (
    <motion.div
      initial={{ opacity: 0, height: 0 }}
      animate={{ opacity: 1, height: "auto" }}
      exit={{ opacity: 0, height: 0 }}
      className="w-full max-w-4xl mx-auto mt-8"
    >
      <div className="glass-panel overflow-hidden border border-zinc-800/50 bg-zinc-950/80 shadow-2xl">
        {/* Terminal Header */}
        <div className="bg-zinc-900 border-b border-zinc-800 px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-rose-500"></div>
            <div className="w-3 h-3 rounded-full bg-amber-500"></div>
            <div className="w-3 h-3 rounded-full bg-emerald-500"></div>
          </div>
          <div className="flex items-center gap-2 text-zinc-400 font-mono text-sm">
            <Radar className={`w-4 h-4 ${isActive ? "animate-spin text-blue-500" : ""}`} />
            <span>FixGuard Engine v2.0</span>
          </div>
        </div>

        {/* Terminal Body */}
        <div 
          ref={scrollRef}
          className="p-4 h-64 overflow-y-auto font-mono text-sm space-y-2"
        >
          {logs.map((log) => (
            <div key={log.id} className="flex items-start gap-3">
              <span className="text-zinc-500 shrink-0">[{log.timestamp}]</span>
              <span
                className={`
                  ${log.type === "info" ? "text-zinc-300" : ""}
                  ${log.type === "warning" ? "text-amber-400" : ""}
                  ${log.type === "error" ? "text-rose-500" : ""}
                  ${log.type === "success" ? "text-emerald-400" : ""}
                `}
              >
                {log.message}
              </span>
            </div>
          ))}
          {isActive && (
            <div className="flex items-center gap-2 text-zinc-500 mt-4">
              <span className="animate-pulse">_</span>
            </div>
          )}
        </div>
      </div>
    </motion.div>
  );
}
