/**
 * Deterministic console-line tone for Stage 2 / Attack Mode terminals.
 * Classification is content-based (case-insensitive keyword match).
 * Priority: red > yellow > green > neutral.
 *
 * Underscore-compound tokens (e.g. degraded_mode) are matched deliberately —
 * plain \bWORD\b fails when WORD is followed by `_`.
 */

export type ConsoleLineTone = "error" | "warning" | "success" | "neutral";

/** Keyword as its own token, or as the head of an underscore-compound token. */
function token(word: string): RegExp {
  return new RegExp(`(?:^|[^A-Za-z0-9])${word}(?:[^A-Za-z0-9]|_|$)`, "i");
}

const RED_PATTERNS: readonly RegExp[] = [
  token("error"),
  /(?:^|[^A-Za-z0-9])fail(?:ed|ure)(?:[^A-Za-z0-9]|_|$)/i,
  token("econnrefused"),
  /\b5xx\b/i,
  /\bHTTP[/ ]*5\d{2}\b/i,
  /\bstatus[=:\s]+5\d{2}\b/i,
  token("denied"),
  token("aborted"),
  token("exception"),
];

const YELLOW_PATTERNS: readonly RegExp[] = [
  /\bwarnings?\b/i,
  token("degraded"),
  token("interfered"),
  /rate[_ ]?limit/i,
  token("challenge"),
  token("skipped"),
  token("pending"),
];

const GREEN_PATTERNS: readonly RegExp[] = [
  token("completed"),
  token("success"),
  token("finding"),
  /draft\s+created/i,
  /stage\s+done/i,
  token("validated"),
  token("ok"),
  /continue-ready/i,
];

/** Final pipeline summary line: green if errors=0; amber/red when errors or hard failure. */
function classifyPipelineCompletedLine(text: string): ConsoleLineTone | null {
  if (!/pipeline\s+completed/i.test(text)) return null;
  const errorsMatch = text.match(/errors?\s*=\s*(\d+)/i);
  const errors = errorsMatch ? Number(errorsMatch[1]) : 0;
  if (errors > 0 || /\b(hard[_ ]?fail|fatal|aborted)\b/i.test(text)) {
    return "error";
  }
  if (/\bwarnings?\s*=\s*[1-9]/i.test(text) || /\bpartial_failure\b/i.test(text)) {
    return "warning";
  }
  return "success";
}

export function classifyConsoleLineTone(text: string): ConsoleLineTone {
  const pipelineTone = classifyPipelineCompletedLine(text);
  if (pipelineTone) return pipelineTone;
  if (RED_PATTERNS.some((re) => re.test(text))) return "error";
  if (YELLOW_PATTERNS.some((re) => re.test(text))) return "warning";
  if (GREEN_PATTERNS.some((re) => re.test(text))) return "success";
  return "neutral";
}

/** Tailwind + semantic classes applied to each console line element. */
export function consoleLineToneClass(tone: ConsoleLineTone): string {
  switch (tone) {
    case "error":
      return "console-line-error text-rose-400";
    case "warning":
      return "console-line-warning text-amber-300";
    case "success":
      return "console-line-success text-emerald-400";
    case "neutral":
    default:
      return "console-line-neutral text-zinc-400";
  }
}

export function consoleLineClassFromText(text: string): string {
  return consoleLineToneClass(classifyConsoleLineTone(text));
}
