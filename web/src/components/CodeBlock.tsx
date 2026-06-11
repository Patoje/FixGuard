"use client";

interface CodeBlockProps {
  code: string;
}

export default function CodeBlock({ code }: CodeBlockProps) {
  // Simple rendering of code, for a real app we'd use something like Prism or Highlight.js
  return (
    <div className="mt-4 rounded-md overflow-hidden border border-zinc-800 bg-[#1e1e1e]">
      <div className="bg-zinc-800/50 px-4 py-2 text-xs font-mono text-zinc-400 flex items-center justify-between">
        <span>Suggested Fix</span>
      </div>
      <pre className="p-4 overflow-x-auto text-sm font-mono text-zinc-300">
        <code>{code}</code>
      </pre>
    </div>
  );
}
