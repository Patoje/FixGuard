"use client";

import React from "react";
import { FileText } from "lucide-react";
import type {
  AssessmentTranscriptDto,
  AssessmentTranscriptInvocationDto,
  FindingDto,
} from "@/lib/v2Api";

interface AssessmentTranscriptPanelProps {
  readonly transcript?: AssessmentTranscriptDto;
}

function EmptyLine({ text }: { readonly text: string }) {
  return <p className="text-sm text-zinc-500">{text}</p>;
}

function invocationText(invocation: AssessmentTranscriptInvocationDto): string {
  if (invocation.kind === "process") {
    const args = invocation.args?.join(" ") ?? "";
    return `${invocation.binary ?? "process"} ${args}`.trim();
  }
  if (invocation.kind === "http") {
    return `${invocation.method ?? "GET"} ${invocation.url ?? ""}`.trim();
  }
  return "No invocation recorded";
}

function findingTitle(finding: FindingDto): string {
  return finding.title || finding.type || finding.id;
}

export function AssessmentTranscriptPanel({ transcript }: AssessmentTranscriptPanelProps) {
  const discoveries = transcript?.discoveries.entries ?? [];
  const findings = transcript?.findings ?? [];
  const executedSteps = transcript?.executedSteps ?? [];
  const withheldPlans = transcript?.withheldPlans ?? [];
  const stopReason = transcript?.stopReason ?? "Not recorded yet";

  return (
    <div className="rounded-2xl border border-zinc-800 bg-zinc-950/80 p-6 shadow-2xl backdrop-blur-xl space-y-6">
      <div className="flex items-center gap-3 border-b border-zinc-800/80 pb-5">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-zinc-700 bg-zinc-900 text-zinc-300">
          <FileText className="h-5 w-5" />
        </div>
        <div>
          <h2 className="text-sm font-semibold text-zinc-100">Assessment transcript</h2>
          <p className="text-xs text-zinc-500">Stored discoveries, findings, and read steps</p>
        </div>
      </div>

      <section aria-label="Discoveries" className="space-y-2">
        <h3 className="text-xs font-medium uppercase tracking-wide text-zinc-400">Discoveries</h3>
        {discoveries.length === 0 ? (
          <EmptyLine text="No discoveries recorded." />
        ) : (
          <ul className="space-y-1 font-mono text-xs text-zinc-300">
            {discoveries.map((entry) => (
              <li key={`${entry.origin}${entry.path}${entry.method}`}>
                {entry.method} {entry.origin}
                {entry.path}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section aria-label="Findings" className="space-y-2">
        <h3 className="text-xs font-medium uppercase tracking-wide text-zinc-400">Findings</h3>
        {findings.length === 0 ? (
          <EmptyLine text="No findings recorded." />
        ) : (
          <ul className="space-y-1 text-sm text-zinc-200">
            {findings.map((finding) => (
              <li key={finding.id}>{findingTitle(finding)}</li>
            ))}
          </ul>
        )}
      </section>

      <section aria-label="Executed steps" className="space-y-2">
        <h3 className="text-xs font-medium uppercase tracking-wide text-zinc-400">Executed steps</h3>
        {executedSteps.length === 0 ? (
          <EmptyLine text="No read steps recorded." />
        ) : (
          <ul className="space-y-3 text-sm text-zinc-200">
            {executedSteps.map((step, index) => (
              <li key={`${step.capability}${step.url}${index}`} className="space-y-1">
                <p>
                  {step.capability} · {step.blastRadiusClass} · {step.outcome}
                </p>
                <p className="font-mono text-xs text-zinc-400">{step.url}</p>
                <p className="font-mono text-xs text-zinc-500">{invocationText(step.invocation)}</p>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section aria-label="Withheld plans" className="space-y-2">
        <h3 className="text-xs font-medium uppercase tracking-wide text-zinc-400">Withheld plans</h3>
        {withheldPlans.length === 0 ? (
          <EmptyLine text="No withheld plans." />
        ) : (
          <ul className="space-y-1 text-sm text-zinc-200">
            {withheldPlans.map((plan) => (
              <li key={`${plan.capability}${plan.target}`}>
                {plan.capability} · {plan.target}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section aria-label="Stop reason" className="space-y-2">
        <h3 className="text-xs font-medium uppercase tracking-wide text-zinc-400">Stop reason</h3>
        <p className="font-mono text-sm text-zinc-200">{stopReason}</p>
      </section>
    </div>
  );
}
