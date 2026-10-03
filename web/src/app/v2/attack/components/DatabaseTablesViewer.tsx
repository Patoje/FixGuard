"use client";

import { useState } from "react";
import {
  Database,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  Clock,
  Terminal,
  Copy,
  Check,
  ChevronDown,
  ChevronRight,
  Play,
  FileCode,
  Flame,
  Layers,
  AlertCircle,
  HelpCircle,
} from "lucide-react";
import type { AttackChain, AttackPlan } from "@/lib/v2AttackApi";

export type TableProbeStatus =
  | "not_executed"
  | "executed_unconfirmed"
  | "vulnerable"
  | "protected"
  | "failed"
  | "inconclusive";

export interface DiscoveredDatabaseTable {
  readonly tableName: string;
  readonly tableUrl: string;
  readonly readStatus: TableProbeStatus;
  readonly readMessage?: string;
  readonly writeStatus: TableProbeStatus;
  readonly writeMessage?: string;
  readonly observedColumns: readonly string[];
  readonly observedJson?: string;
  readonly observedRowCount: number;
  readonly readPlan?: AttackPlan;
  readonly writePlan?: AttackPlan;
  readonly rawStdout?: string;
}

interface DatabaseTablesViewerProps {
  readonly plans: readonly AttackPlan[];
  readonly chains: readonly AttackChain[];
  readonly completedPlanIds: ReadonlySet<string>;
  readonly executionRecord?: any;
  readonly onSelectPlanToRun?: (plan: AttackPlan) => void;
  readonly onSendCurlToTerminal?: (curlCommand: string) => void;
}

/**
 * Parses real JSON response body captured during live authorized probe execution.
 * Extracts authentic column names and row counts directly from target response.
 * Never invents columns from table names or hardcoded dictionaries.
 */
function parseObservedTableData(rawStdout?: string): {
  observedColumns: string[];
  observedRowCount: number;
  formattedJson?: string;
} {
  if (!rawStdout || rawStdout.trim().length === 0) {
    return { observedColumns: [], observedRowCount: 0 };
  }

  try {
    const parsed = JSON.parse(rawStdout);
    let columns: string[] = [];
    let rowCount = 0;

    if (Array.isArray(parsed)) {
      rowCount = parsed.length;
      if (parsed.length > 0 && typeof parsed[0] === "object" && parsed[0] !== null) {
        columns = Object.keys(parsed[0]);
      }
    } else if (typeof parsed === "object" && parsed !== null) {
      rowCount = 1;
      columns = Object.keys(parsed);
    }

    return {
      observedColumns: columns,
      observedRowCount: rowCount,
      formattedJson: JSON.stringify(parsed, null, 2),
    };
  } catch {
    return {
      observedColumns: [],
      observedRowCount: rawStdout.trim().length > 0 ? 1 : 0,
      formattedJson: rawStdout,
    };
  }
}

/**
 * Extracts tables discovered from real attack plans and execution chains.
 * Table URLs and statuses are derived strictly from active plans and telemetry.
 */
export function extractDiscoveredTables(
  plans: readonly AttackPlan[],
  chains: readonly AttackChain[],
  completedPlanIds: ReadonlySet<string>,
  executionRecord?: any
): readonly DiscoveredDatabaseTable[] {
  const tableMap = new Map<
    string,
    {
      tableName: string;
      tableUrl: string;
      readStatus: TableProbeStatus;
      readMessage?: string;
      writeStatus: TableProbeStatus;
      writeMessage?: string;
      readPlan?: AttackPlan;
      writePlan?: AttackPlan;
      rawStdout?: string;
    }
  >();

  // 1. Discover from active attack plans
  for (const plan of plans) {
    let tableName: string | null = null;
    let tableUrl = plan.targetUrl ? plan.targetUrl.split("?")[0] : "";

    const urlMatch = tableUrl.match(/\/rest\/v1\/([^?/#]+)/i);
    if (urlMatch) {
      tableName = urlMatch[1];
    } else {
      const titleMatch =
        plan.title.match(/on '([^']+)'/i) || plan.title.match(/table '([^']+)'/i);
      if (titleMatch) {
        tableName = titleMatch[1];
      }
    }

    if (!tableName) continue;

    if (!tableMap.has(tableName)) {
      tableMap.set(tableName, {
        tableName,
        tableUrl: tableUrl || `/rest/v1/${tableName}`,
        readStatus: "not_executed",
        writeStatus: "not_executed",
      });
    }

    const entry = tableMap.get(tableName)!;
    if (tableUrl && (!entry.tableUrl || entry.tableUrl.startsWith("/"))) {
      entry.tableUrl = tableUrl;
    }

    if (plan.capability === "supabase_rls_read_confirm") {
      entry.readPlan = plan;
      // Plan completion alone only indicates execution happened, NEVER vulnerability or HTTP 200
      if (completedPlanIds.has(plan.planId) && entry.readStatus === "not_executed") {
        entry.readStatus = "executed_unconfirmed";
        entry.readMessage = "Prueba ejecutada — estado HTTP de respuesta no observado aún";
      }
    } else if (plan.capability === "supabase_rls_write_probe") {
      entry.writePlan = plan;
      if (completedPlanIds.has(plan.planId) && entry.writeStatus === "not_executed") {
        entry.writeStatus = "executed_unconfirmed";
        entry.writeMessage = "Prueba ejecutada — estado de respuesta no observado aún";
      }
    }
  }

  // 2. Discover / enrich from real execution chains and step telemetry
  for (const chain of chains) {
    for (const step of chain.steps) {
      const msg = step.evidence?.safeMessage || "";
      const reasonCode = step.evidence?.reasonCode || "";
      const readMatch = msg.match(/read on '([^']+)'/i);
      const writeMatch =
        msg.match(/write on '([^']+)'/i) ||
        msg.match(/write rejected.*on '([^']+)'/i);

      let table = readMatch?.[1] || writeMatch?.[1];
      if (!table && step.hypothesisRef) {
        for (const [tblName, entry] of tableMap.entries()) {
          if (
            entry.readPlan?.planId === step.hypothesisRef ||
            entry.writePlan?.planId === step.hypothesisRef
          ) {
            table = tblName;
            break;
          }
        }
      }

      if (table) {
        if (!tableMap.has(table)) {
          tableMap.set(table, {
            tableName: table,
            tableUrl: `/rest/v1/${table}`,
            readStatus: "not_executed",
            writeStatus: "not_executed",
          });
        }

        const entry = tableMap.get(table)!;
        const isReadStep =
          step.capabilityKind === "supabase_rls_read_confirm" ||
          Boolean(readMatch) ||
          entry.readPlan?.planId === step.hypothesisRef;
        const isWriteStep =
          step.capabilityKind === "supabase_rls_write_probe" ||
          Boolean(writeMatch) ||
          entry.writePlan?.planId === step.hypothesisRef;

        if (isReadStep) {
          const isInconclusive =
            reasonCode === "inconclusive_empty_table" ||
            reasonCode === "supabase_rls_no_records_observed" ||
            /inconclus/i.test(msg) ||
            /0 records observed/i.test(msg) ||
            /0 registros observados/i.test(msg);

          if (step.outcome === "refuted" || step.epistemicStatus === "REFUTED") {
            if (isInconclusive) {
              entry.readStatus = "inconclusive";
              entry.readMessage = msg || "Respuesta vacía (0 registros) — inconcluso sobre RLS";
            } else {
              entry.readStatus = "protected";
              entry.readMessage = msg || "Lectura denegada por política RLS (HTTP 401/403)";
            }
          } else if (step.outcome === "failed") {
            if (entry.readStatus !== "protected") {
              entry.readStatus = "failed";
              entry.readMessage = msg || "Fallo en la ejecución de la prueba";
            }
          } else if (step.outcome === "succeeded") {
            // MONOTONIC: A refuted/protected status must NEVER be downgraded into vulnerable
            if (entry.readStatus !== "protected") {
              const rawTrimmed = entry.rawStdout ? entry.rawStdout.trim() : "";
              const isEmptyArrayStdout = rawTrimmed === "[]" || /^\s*\[\s*\]\s*$/.test(rawTrimmed);
              const hasHttp200Evidence =
                !isEmptyArrayStdout &&
                !isInconclusive &&
                (reasonCode === "supabase_rls_world_readable_observed" ||
                  /HTTP (?:1\.[01] )?200/i.test(msg) ||
                  /200 OK/i.test(msg) ||
                  /world-readable/i.test(msg));

              if (hasHttp200Evidence) {
                entry.readStatus = "vulnerable";
                entry.readMessage = msg || "Lectura anónima confirmada (HTTP 200 JSON)";
              } else if (isEmptyArrayStdout || isInconclusive) {
                entry.readStatus = "inconclusive";
                entry.readMessage = "Respuesta vacía (0 registros) — inconcluso sobre RLS";
              } else if (entry.readStatus !== "vulnerable") {
                entry.readStatus = "executed_unconfirmed";
                entry.readMessage = "Prueba ejecutada — estado de respuesta HTTP no observado";
              }
            }
          }
        }

        if (isWriteStep) {
          if (step.outcome === "refuted" || step.epistemicStatus === "REFUTED") {
            entry.writeStatus = "protected";
            entry.writeMessage = msg || "Escritura denegada por política RLS (HTTP 401/403)";
          } else if (step.outcome === "failed") {
            if (entry.writeStatus !== "protected") {
              entry.writeStatus = "failed";
              entry.writeMessage = msg || "Fallo en la ejecución de la prueba";
            }
          } else if (step.outcome === "succeeded") {
            if (entry.writeStatus !== "protected") {
              const hasWriteEvidence =
                /escritura anónima comprobada/i.test(msg) ||
                /INSERT\/POST permitido/i.test(msg) ||
                /write allowed/i.test(msg);

              if (hasWriteEvidence) {
                entry.writeStatus = "vulnerable";
                entry.writeMessage = msg || "Escritura anónima comprobada (INSERT/POST permitido)";
              } else if (entry.writeStatus !== "vulnerable") {
                entry.writeStatus = "executed_unconfirmed";
                entry.writeMessage = "Prueba ejecutada — estado de respuesta no observado";
              }
            }
          }
        }
      }
    }
  }

  // 3. Correlate with fresh executionRecord stepRecords if present
  if (executionRecord?.stepRecords && Array.isArray(executionRecord.stepRecords)) {
    for (const step of executionRecord.stepRecords) {
      let matchedEntry: (typeof tableMap extends Map<any, infer V> ? V : never) | undefined;
      for (const [tblName, entry] of tableMap.entries()) {
        if (
          step.safeMessage?.includes(`'${tblName}'`) ||
          entry.readPlan?.planId === executionRecord.planId ||
          entry.writePlan?.planId === executionRecord.planId
        ) {
          matchedEntry = entry;
          break;
        }
      }

      if (step.consoleLines && Array.isArray(step.consoleLines) && matchedEntry) {
        for (const line of step.consoleLines) {
          if (line.stream === "stdout" && line.text && line.text.trim().length > 0) {
            matchedEntry.rawStdout = line.text;
          } else if (line.stream === "command" && line.text) {
            const urlCmdMatch = line.text.match(/curl[^\n]+"(https?:\/\/[^"?\s]+)/i);
            if (urlCmdMatch) {
              matchedEntry.tableUrl = urlCmdMatch[1];
            }
          }
        }
      }

      if (matchedEntry) {
        const isRead =
          matchedEntry.readPlan?.planId === executionRecord.planId ||
          step.capabilityKind === "supabase_rls_read_confirm";
        const isWrite =
          matchedEntry.writePlan?.planId === executionRecord.planId ||
          step.capabilityKind === "supabase_rls_write_probe";

        if (isRead) {
          const isInconclusive =
            step.reasonCode === "inconclusive_empty_table" ||
            step.reasonCode === "supabase_rls_no_records_observed" ||
            /inconclus/i.test(step.safeMessage || "") ||
            /0 records observed/i.test(step.safeMessage || "") ||
            /0 registros observados/i.test(step.safeMessage || "");

          if (step.outcome === "refuted") {
            if (isInconclusive) {
              matchedEntry.readStatus = "inconclusive";
              matchedEntry.readMessage = step.safeMessage || "Respuesta vacía (0 registros) — inconcluso sobre RLS";
            } else {
              matchedEntry.readStatus = "protected";
              matchedEntry.readMessage = step.safeMessage || "Lectura denegada por política RLS (HTTP 401/403)";
            }
          } else if (step.outcome === "failed") {
            if (matchedEntry.readStatus !== "protected") {
              matchedEntry.readStatus = "failed";
              matchedEntry.readMessage = step.safeMessage || "Fallo en la ejecución de la prueba";
            }
          } else if (step.outcome === "succeeded") {
            if (matchedEntry.readStatus !== "protected") {
              const rawTrimmed = matchedEntry.rawStdout ? matchedEntry.rawStdout.trim() : "";
              const isEmptyArray = rawTrimmed === "[]" || /^\s*\[\s*\]\s*$/.test(rawTrimmed);
              const hasRows =
                rawTrimmed.startsWith("[") &&
                rawTrimmed.length > 2 &&
                !isEmptyArray;
              const has200 =
                !isEmptyArray &&
                !isInconclusive &&
                (step.reasonCode === "supabase_rls_world_readable_observed" ||
                  /HTTP (?:1\.[01] )?200/i.test(step.safeMessage || "") ||
                  /200 OK/i.test(step.safeMessage || "") ||
                  hasRows);

              if (has200) {
                matchedEntry.readStatus = "vulnerable";
                matchedEntry.readMessage = step.safeMessage || "Lectura anónima confirmada (HTTP 200 JSON)";
              } else if (isEmptyArray || isInconclusive) {
                matchedEntry.readStatus = "inconclusive";
                matchedEntry.readMessage = "Respuesta vacía (0 registros) — inconcluso sobre RLS";
              } else if (matchedEntry.readStatus !== "vulnerable") {
                matchedEntry.readStatus = "executed_unconfirmed";
                matchedEntry.readMessage = "Prueba ejecutada — estado de respuesta HTTP no observado";
              }
            }
          }
        }

        if (isWrite) {
          if (step.outcome === "refuted") {
            matchedEntry.writeStatus = "protected";
            matchedEntry.writeMessage = step.safeMessage || "Escritura denegada por política RLS (HTTP 401/403)";
          } else if (step.outcome === "failed") {
            if (matchedEntry.writeStatus !== "protected") {
              matchedEntry.writeStatus = "failed";
              matchedEntry.writeMessage = step.safeMessage || "Fallo en la ejecución de la prueba";
            }
          } else if (step.outcome === "succeeded") {
            if (matchedEntry.writeStatus !== "protected") {
              const hasWriteEvidence =
                /escritura anónima comprobada/i.test(step.safeMessage || "") ||
                /INSERT\/POST permitido/i.test(step.safeMessage || "");

              if (hasWriteEvidence) {
                matchedEntry.writeStatus = "vulnerable";
                matchedEntry.writeMessage = step.safeMessage || "Escritura anónima comprobada (INSERT/POST permitido)";
              } else if (matchedEntry.writeStatus !== "vulnerable") {
                matchedEntry.writeStatus = "executed_unconfirmed";
                matchedEntry.writeMessage = "Prueba ejecutada — estado de respuesta no observado";
              }
            }
          }
        }
      }
    }
  }

  return Array.from(tableMap.values()).map((e) => {
    const parsed = parseObservedTableData(e.rawStdout);
    return {
      tableName: e.tableName,
      tableUrl: e.tableUrl,
      readStatus: e.readStatus,
      readMessage: e.readMessage,
      writeStatus: e.writeStatus,
      writeMessage: e.writeMessage,
      observedColumns: parsed.observedColumns,
      observedJson: parsed.formattedJson,
      observedRowCount: parsed.observedRowCount,
      readPlan: e.readPlan,
      writePlan: e.writePlan,
      rawStdout: e.rawStdout,
    };
  });
}

export function DatabaseTablesViewer({
  plans,
  chains,
  completedPlanIds,
  executionRecord,
  onSelectPlanToRun,
  onSendCurlToTerminal,
}: DatabaseTablesViewerProps) {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const tables = extractDiscoveredTables(
    plans,
    chains,
    completedPlanIds,
    executionRecord
  );

  // Default: all tables expanded so the user sees the data immediately
  const [collapsedTables, setCollapsedTables] = useState<Set<string>>(new Set());

  const toggleTable = (tableName: string) => {
    setCollapsedTables((prev) => {
      const next = new Set(prev);
      if (next.has(tableName)) {
        next.delete(tableName);
      } else {
        next.add(tableName);
      }
      return next;
    });
  };

  const handleCopy = (text: string, key: string) => {
    void navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  if (tables.length === 0) {
    return (
      <div className="rounded-xl border border-zinc-800 bg-zinc-950/60 p-5 text-xs text-zinc-500 flex items-center gap-3">
        <Database className="h-5 w-5 text-zinc-600 shrink-0" />
        <div>
          <span className="font-semibold text-zinc-400 block mb-0.5">
            Sin tablas de base de datos detectadas
          </span>
          <p className="text-zinc-500">
            No se observaron endpoints de PostgREST / Supabase en las rutas descubiertas del target.
          </p>
        </div>
      </div>
    );
  }

  const vulnerableTablesCount = tables.filter(
    (t) => t.readStatus === "vulnerable" || t.writeStatus === "vulnerable"
  ).length;

  return (
    <div className="space-y-4">
      {/* Overview Banner */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-zinc-800 bg-zinc-950 p-4 shadow-lg">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-emerald-500/30 bg-emerald-950/30 text-emerald-400 shrink-0">
            <Database className="h-5 w-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-semibold text-zinc-100">
                Tablas de Base de Datos Detectadas en el Target
              </span>
              <span className="rounded-full border border-zinc-700 bg-zinc-800 px-2 py-0.5 text-[10px] font-mono text-zinc-300">
                {tables.length} {tables.length === 1 ? "tabla" : "tablas"}
              </span>
            </div>
            <p className="text-[11px] text-zinc-400">
              Endpoints descubiertos durante reconocimiento activo y comprobación de controles Row Level Security (RLS).
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {vulnerableTablesCount > 0 ? (
            <div className="flex items-center gap-1.5 rounded-full border border-rose-500/40 bg-rose-950/30 px-3 py-1 text-xs font-semibold text-rose-300">
              <Flame className="h-3.5 w-3.5 text-rose-400 animate-pulse" />
              <span>
                {vulnerableTablesCount}{" "}
                {vulnerableTablesCount === 1 ? "tabla expuesta" : "tablas expuestas"}{" "}
                públicamente
              </span>
            </div>
          ) : (
            <div className="flex items-center gap-1.5 rounded-full border border-zinc-800 bg-zinc-900 px-3 py-1 text-xs text-zinc-400">
              <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
              <span>Sin tablas expuestas confirmadas</span>
            </div>
          )}
        </div>
      </div>

      {/* Tables Grid */}
      <div className="space-y-4">
        {tables.map((table) => {
          const isCollapsed = collapsedTables.has(table.tableName);
          const curlRead = `curl -s -X GET "${table.tableUrl}?select=*&limit=1" -H "apikey: anon"`;
          const curlWrite = `curl -s -X POST "${table.tableUrl}" -H "apikey: anon" -H "Content-Type: application/json" -d '{"fixguard_probe":true}'`;

          return (
            <div
              key={table.tableName}
              className={`rounded-xl border transition-all overflow-hidden ${
                table.readStatus === "vulnerable"
                  ? "border-rose-800/80 bg-gradient-to-b from-rose-950/20 via-zinc-950 to-zinc-950 shadow-lg shadow-rose-950/10"
                  : table.readStatus === "protected"
                  ? "border-emerald-900/60 bg-zinc-950/80"
                  : "border-zinc-800 bg-zinc-950/70"
              }`}
            >
              {/* Header row */}
              <div className="p-4 space-y-3 bg-zinc-950/90 border-b border-zinc-900/80">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2.5 min-w-0">
                    <button
                      type="button"
                      onClick={() => toggleTable(table.tableName)}
                      className="text-zinc-400 hover:text-zinc-200 transition"
                      title={isCollapsed ? "Desplegar detalles" : "Plegar detalles"}
                    >
                      {isCollapsed ? (
                        <ChevronRight className="h-4 w-4" />
                      ) : (
                        <ChevronDown className="h-4 w-4" />
                      )}
                    </button>
                    <span className="font-mono text-base font-bold text-emerald-400 flex items-center gap-1.5">
                      <Database className="h-4 w-4 text-emerald-500" />
                      {table.tableName}
                    </span>
                    <span className="rounded border border-zinc-800 bg-zinc-900 px-2 py-0.5 text-[11px] font-mono text-zinc-400 truncate max-w-sm">
                      {table.tableUrl.split("?")[0]}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => handleCopy(curlRead, `curl-${table.tableName}`)}
                      className="flex items-center gap-1.5 rounded border border-zinc-700 bg-zinc-900 px-2.5 py-1 text-xs text-zinc-300 hover:bg-zinc-800 hover:text-zinc-100 transition"
                      title="Copiar comando cURL reproducible"
                    >
                      {copiedKey === `curl-${table.tableName}` ? (
                        <Check className="h-3 w-3 text-emerald-400" />
                      ) : (
                        <Copy className="h-3 w-3 text-zinc-400" />
                      )}
                      <span>Copiar cURL</span>
                    </button>

                    {onSendCurlToTerminal && (
                      <button
                        type="button"
                        onClick={() => onSendCurlToTerminal(curlRead)}
                        className="flex items-center gap-1.5 rounded border border-emerald-500/40 bg-emerald-950/40 px-2.5 py-1 text-xs font-medium text-emerald-300 hover:bg-emerald-900/50 transition"
                        title="Cargar y ejecutar este comando en la terminal interactiva"
                      >
                        <Terminal className="h-3.5 w-3.5" />
                        <span>Cargar en Terminal</span>
                      </button>
                    )}
                  </div>
                </div>

                {/* Status Badges Row: Read vs Write */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
                  {/* SELECT / READ Status Card */}
                  <div className="rounded-lg border border-zinc-800/80 bg-zinc-900/50 p-3 space-y-1.5">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-semibold text-zinc-300 flex items-center gap-1.5">
                        <FileCode className="h-3.5 w-3.5 text-zinc-400" />
                        Lectura Anónima (SELECT / GET)
                      </span>
                      {table.readStatus === "vulnerable" ? (
                        <span className="flex items-center gap-1 rounded bg-rose-950 border border-rose-500/50 px-2 py-0.5 text-[10px] font-bold text-rose-300 animate-pulse">
                          <ShieldAlert className="h-3 w-3 text-rose-400" />
                          VULNERABLE (HTTP 200)
                        </span>
                      ) : table.readStatus === "protected" ? (
                        <span className="flex items-center gap-1 rounded bg-emerald-950/60 border border-emerald-500/40 px-2 py-0.5 text-[10px] font-semibold text-emerald-300">
                          <ShieldCheck className="h-3 w-3 text-emerald-400" />
                          PROTEGIDA (HTTP 401/403)
                        </span>
                      ) : table.readStatus === "executed_unconfirmed" ? (
                        <span className="flex items-center gap-1 rounded bg-zinc-800/90 border border-zinc-700 px-2 py-0.5 text-[10px] font-medium text-zinc-300">
                          <Clock className="h-3 w-3 text-zinc-400" />
                          EJECUTADO (ESTADO NO OBSERVADO)
                        </span>
                      ) : table.readStatus === "failed" ? (
                        <span className="flex items-center gap-1 rounded bg-amber-950/60 border border-amber-500/40 px-2 py-0.5 text-[10px] font-semibold text-amber-300">
                          <AlertCircle className="h-3 w-3 text-amber-400" />
                          ERROR / FALLO
                        </span>
                      ) : table.readStatus === "inconclusive" ? (
                        <span className="flex items-center gap-1 rounded bg-zinc-800 border border-zinc-700 px-2 py-0.5 text-[10px] font-medium text-zinc-400">
                          <HelpCircle className="h-3 w-3 text-zinc-400" />
                          INCONCLUSO
                        </span>
                      ) : (
                        <span className="flex items-center gap-1 rounded bg-zinc-800 border border-zinc-700 px-2 py-0.5 text-[10px] text-zinc-400">
                          <Clock className="h-3 w-3" />
                          Sin probar aún
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-zinc-300">
                      {table.readStatus === "vulnerable"
                        ? "Confirmado: La tabla no tiene RLS o cuenta con política pública. Cualquier usuario anónimo en internet puede descargar los datos."
                        : table.readStatus === "protected"
                        ? "Supabase RLS bloqueó la consulta anónima correctamente (HTTP 401/403)."
                        : table.readStatus === "executed_unconfirmed"
                        ? "La prueba fue ejecutada en el objetivo, pero no se capturó telemetría de respuesta HTTP para verificar si retornó 200 OK o fue denegada."
                        : table.readStatus === "failed"
                        ? table.readMessage || "La prueba no pudo completarse con éxito."
                        : table.readStatus === "inconclusive"
                        ? "El resultado de la prueba no es concluyente para determinar si el control de seguridad aplica."
                        : "No se ha ejecutado la prueba en el target para verificar si RLS está activo."}
                    </p>
                    {table.readPlan && table.readStatus === "not_executed" && onSelectPlanToRun && (
                      <button
                        type="button"
                        onClick={() => onSelectPlanToRun(table.readPlan!)}
                        className="mt-1 flex items-center gap-1 text-xs text-cyan-400 hover:underline font-medium"
                      >
                        <Play className="h-3 w-3" />
                        Ejecutar prueba de lectura ahora
                      </button>
                    )}
                  </div>

                  {/* INSERT / WRITE Status Card */}
                  <div className="rounded-lg border border-zinc-800/80 bg-zinc-900/50 p-3 space-y-1.5">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-semibold text-zinc-300 flex items-center gap-1.5">
                        <Terminal className="h-3.5 w-3.5 text-zinc-400" />
                        Escritura Anónima (INSERT / POST)
                      </span>
                      {table.writeStatus === "vulnerable" ? (
                        <span className="flex items-center gap-1 rounded bg-red-950 border border-red-500 px-2 py-0.5 text-[10px] font-bold text-red-200 animate-pulse">
                          <Flame className="h-3 w-3 text-red-400" />
                          CRÍTICO: ESCRITURA ABIERTA
                        </span>
                      ) : table.writeStatus === "protected" ? (
                        <span className="flex items-center gap-1 rounded bg-emerald-950/60 border border-emerald-500/40 px-2 py-0.5 text-[10px] font-semibold text-emerald-300">
                          <CheckCircle2 className="h-3 w-3 text-emerald-400" />
                          BLOQUEADA POR RLS
                        </span>
                      ) : table.writeStatus === "executed_unconfirmed" ? (
                        <span className="flex items-center gap-1 rounded bg-zinc-800/90 border border-zinc-700 px-2 py-0.5 text-[10px] font-medium text-zinc-300">
                          <Clock className="h-3 w-3 text-zinc-400" />
                          EJECUTADO (ESTADO NO OBSERVADO)
                        </span>
                      ) : table.writeStatus === "failed" ? (
                        <span className="flex items-center gap-1 rounded bg-amber-950/60 border border-amber-500/40 px-2 py-0.5 text-[10px] font-semibold text-amber-300">
                          <AlertCircle className="h-3 w-3 text-amber-400" />
                          ERROR / FALLO
                        </span>
                      ) : table.writeStatus === "inconclusive" ? (
                        <span className="flex items-center gap-1 rounded bg-zinc-800 border border-zinc-700 px-2 py-0.5 text-[10px] font-medium text-zinc-400">
                          <HelpCircle className="h-3 w-3 text-zinc-400" />
                          INCONCLUSO
                        </span>
                      ) : (
                        <span className="flex items-center gap-1 rounded bg-zinc-800 border border-zinc-700 px-2 py-0.5 text-[10px] text-zinc-400">
                          <Clock className="h-3 w-3" />
                          Sin probar aún
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-zinc-300">
                      {table.writeStatus === "vulnerable"
                        ? "Se pudieron insertar registros anónimos sin autorización en esta tabla."
                        : table.writeStatus === "protected"
                        ? "Las escrituras anónimas fueron rechazadas por las políticas de seguridad."
                        : table.writeStatus === "executed_unconfirmed"
                        ? "La prueba de escritura fue ejecutada en el objetivo, pero no se capturó estado de respuesta verificable."
                        : table.writeStatus === "failed"
                        ? table.writeMessage || "Fallo en la prueba de escritura."
                        : table.writeStatus === "inconclusive"
                        ? "El resultado de la prueba de escritura no es concluyente."
                        : "Comprueba si un atacante puede alterar o inyectar registros en la base de datos."}
                    </p>
                    {table.writePlan && table.writeStatus === "not_executed" ? (
                      <button
                        type="button"
                        onClick={() => onSelectPlanToRun?.(table.writePlan!)}
                        className="mt-1 flex items-center gap-1 text-xs text-amber-400 hover:underline font-medium"
                      >
                        <Play className="h-3 w-3" />
                        ⚡ Probar si permite escribir datos (INSERT/POST)
                      </button>
                    ) : onSendCurlToTerminal && table.writeStatus === "not_executed" ? (
                      <button
                        type="button"
                        onClick={() => onSendCurlToTerminal(curlWrite)}
                        className="mt-1 flex items-center gap-1 text-xs text-amber-400 hover:underline font-medium"
                      >
                        <Play className="h-3 w-3" />
                        ⚡ Cargar prueba de escritura POST en Terminal
                      </button>
                    ) : null}
                  </div>
                </div>

                {/* Columns detected badges — ONLY REAL COLUMNS */}
                <div className="flex flex-wrap items-center gap-1.5 pt-1">
                  <span className="text-[11px] font-medium text-zinc-400 flex items-center gap-1 mr-1">
                    <Layers className="h-3 w-3 text-zinc-500" />
                    Columnas observadas:
                  </span>
                  {table.observedColumns.length > 0 ? (
                    table.observedColumns.map((col) => (
                      <span
                        key={col}
                        className="rounded border border-zinc-800 bg-zinc-900 px-2 py-0.5 text-[10px] font-mono text-zinc-300"
                      >
                        {col}
                      </span>
                    ))
                  ) : (
                    <span className="text-[11px] text-zinc-500 italic">
                      No observadas aún (se extraen tras ejecutar la prueba de lectura)
                    </span>
                  )}
                </div>
              </div>

              {/* Data Sample Block */}
              {!isCollapsed && (
                <div className="p-4 space-y-2.5 bg-black/80">
                  {table.readStatus === "vulnerable" ? (
                    <>
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-mono font-semibold text-emerald-400 flex items-center gap-2">
                          <FileCode className="h-4 w-4 text-emerald-400" />
                          Datos Extraídos del Target — Respuesta HTTP 200 JSON ({table.tableName})
                        </span>
                        {table.observedJson && (
                          <button
                            type="button"
                            onClick={() =>
                              handleCopy(table.observedJson!, `json-${table.tableName}`)
                            }
                            className="flex items-center gap-1 rounded border border-zinc-800 bg-zinc-900 px-2 py-1 text-[11px] text-zinc-400 hover:text-zinc-200 transition"
                            title="Copiar JSON de muestra"
                          >
                            {copiedKey === `json-${table.tableName}` ? (
                              <Check className="h-3 w-3 text-emerald-400" />
                            ) : (
                              <Copy className="h-3 w-3" />
                            )}
                            <span>Copiar JSON</span>
                          </button>
                        )}
                      </div>

                      <div className="relative rounded-lg border border-zinc-800 bg-zinc-950 p-3.5 font-mono text-xs leading-relaxed overflow-x-auto shadow-inner">
                        <div className="text-[11px] text-zinc-500 mb-1 border-b border-zinc-900 pb-1 flex justify-between">
                          <span>GET {table.tableUrl}?select=*&limit=1</span>
                          <span className="text-emerald-400 font-semibold">
                            Status: 200 OK ({table.observedRowCount} registro{table.observedRowCount === 1 ? "" : "s"})
                          </span>
                        </div>
                        {table.observedJson ? (
                          <pre className="text-emerald-300 font-mono whitespace-pre text-[11px]">
                            {table.observedJson}
                          </pre>
                        ) : (
                          <p className="text-zinc-500 text-xs italic py-2">
                            Ejecución confirmada con respuesta HTTP 200 OK, pero el cuerpo de telemetría no fue almacenado.
                          </p>
                        )}
                      </div>

                      <p className="text-[11px] text-zinc-500">
                        * Registro real observado de la API REST del objetivo al ejecutar la consulta anónima. La tabla está expuesta sin autenticación.
                      </p>
                    </>
                  ) : table.readStatus === "executed_unconfirmed" ? (
                    <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-4 text-xs text-zinc-400 space-y-2">
                      <div className="flex items-center gap-2 text-zinc-300 font-medium">
                        <Clock className="h-4 w-4 text-zinc-400" />
                        <span>Ejecutado — estado de respuesta HTTP no observado</span>
                      </div>
                      <p className="text-zinc-500">
                        El plan se ejecutó a nivel de proceso o aplicación, pero no se capturó telemetría de respuesta HTTP (código 200 ni 401/403). No se infiere vulnerabilidad sin evidencia verificable.
                      </p>
                      <div className="flex flex-wrap items-center gap-2 pt-1 font-mono text-[11px] text-zinc-400">
                        <span className="text-zinc-600">Comando reproducible:</span>
                        <code className="text-zinc-300 bg-zinc-900 px-2 py-0.5 rounded border border-zinc-800">
                          {curlRead}
                        </code>
                      </div>
                    </div>
                  ) : table.readStatus === "protected" ? (
                    <div className="rounded-lg border border-emerald-950/60 bg-emerald-950/20 p-4 text-xs text-emerald-300 space-y-1.5">
                      <div className="flex items-center gap-2 font-semibold text-emerald-400">
                        <ShieldCheck className="h-4 w-4" />
                        <span>Acceso Denegado por Política RLS</span>
                      </div>
                      <p className="text-zinc-400 text-xs">
                        La consulta HTTP hacia <code className="text-emerald-300 font-mono">{table.tableUrl}?select=*&limit=1</code> fue rechazada con código 401/403.
                        No se extrajeron datos de esta tabla porque los controles de seguridad están activos.
                      </p>
                    </div>
                  ) : table.readStatus === "failed" ? (
                    <div className="rounded-lg border border-amber-950/40 bg-amber-950/10 p-4 text-xs text-amber-300 space-y-1.5">
                      <div className="flex items-center gap-2 font-semibold text-amber-400">
                        <AlertCircle className="h-4 w-4" />
                        <span>Fallo en la Ejecución</span>
                      </div>
                      <p className="text-zinc-400 text-xs">
                        {table.readMessage || "La ejecución de la prueba falló. No se pudo verificar la seguridad de la tabla."}
                      </p>
                    </div>
                  ) : (
                    <div className="rounded-lg border border-zinc-800/80 bg-zinc-950 p-4 text-xs text-zinc-400 space-y-2">
                      <div className="flex items-center gap-2 text-zinc-300 font-medium">
                        <Clock className="h-4 w-4 text-amber-400" />
                        <span>Prueba de lectura no ejecutada</span>
                      </div>
                      <p className="text-zinc-500">
                        Aún no se ha obtenido ningún registro de esta tabla porque no se ha ejecutado una petición hacia ella.
                        Podés verificar si es accesible anónimamente ejecutando la prueba desde la terminal o con el botón superior.
                      </p>
                      <div className="flex flex-wrap items-center gap-2 pt-1 font-mono text-[11px] text-zinc-400">
                        <span className="text-zinc-600">Comando reproducible:</span>
                        <code className="text-zinc-300 bg-zinc-900 px-2 py-0.5 rounded border border-zinc-800">
                          {curlRead}
                        </code>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
