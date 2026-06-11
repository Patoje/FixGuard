import { Check, Copy } from 'lucide-react';
import { useState } from 'react';

interface CodeBlockProps {
  code: string;
}

export default function CodeBlock({ code }: CodeBlockProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="relative rounded-xl overflow-hidden bg-[#1e1e1e] border border-white/10 mt-4 font-mono text-sm shadow-2xl">
      <div className="flex items-center justify-between px-4 py-3 bg-[#2d2d2d] border-b border-white/5">
        <div className="flex gap-2">
          <div className="w-3 h-3 rounded-full bg-[#f43f5e]/80"></div>
          <div className="w-3 h-3 rounded-full bg-amber-500/80"></div>
          <div className="w-3 h-3 rounded-full bg-[#10b981]/80"></div>
        </div>
        <button 
          onClick={handleCopy}
          className="text-zinc-400 hover:text-white transition-colors flex items-center gap-1.5 text-xs bg-white/5 hover:bg-white/10 px-3 py-1.5 rounded-md"
        >
          {copied ? <Check size={14} className="text-[#10b981]" /> : <Copy size={14} />}
          {copied ? 'Copied' : 'Copy fix'}
        </button>
      </div>
      <div className="p-5 overflow-x-auto text-zinc-300 max-h-[400px] overflow-y-auto">
        <pre className="m-0 whitespace-pre-wrap break-all leading-relaxed">{code}</pre>
      </div>
    </div>
  );
}
