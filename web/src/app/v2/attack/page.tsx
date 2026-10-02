"use client";

import React, { useCallback, useEffect, useMemo, useState, useRef, Suspense } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
  Crosshair,
  ArrowLeft,
  AlertCircle,
  ChevronDown,
  ChevronRight,
  Copy,
  Check,
  Play,
  Terminal as TerminalIcon,
  Trash2,
  ExternalLink,
  ShieldAlert,
  Globe,
  Database,
  RefreshCw,
  CornerDownLeft,
  Sparkles,
} from "lucide-react";
import {
  v2AttackApi,
  V2ApiError,
  buildWorkbenchScopeGrant,
  type AttackPlan,
  type AttackCapabilityKind,
  type AttackChain,
  type AttackExecutionRecordDto,
  type PostExploitationState,
  type LateralMovementSnapshot,
  type ImpactAssessment,
  type BlastRadiusClass,
  type LateralMovementMechanism,
  type AuthorizeAttackPlanResponse,
  type ActiveInvestigationSnapshotDto,
} from "@/lib/v2AttackApi";
import {
  getOrchestratedAssessmentSummary,
  getOrchestratedAssessmentStatus,
  type LineageTuple,
} from "@/lib/v2Api";
import { isStrictSafeId } from "@/lib/v2/idGenerator";
import { AttackAuthorizationModal } from "./components/AttackAuthorizationModal";
import { AttackChainViewer } from "./components/AttackChainViewer";
import { PostExploitationPanel } from "./components/PostExploitationPanel";
import { ImpactAssessmentView } from "./components/ImpactAssessmentView";
import type { OperatorAttackRecommendation } from "@/lib/v2AttackApi";

type ResultsPanel = "chains" | "impact" | "post_exploit" | null;

export type AttackModeContentProps = {
  readonly forcedAssessmentId?: string;
  readonly embedded?: boolean;
  readonly onContinueToReport?: () => void;
};

const LATERAL_MECHANISMS: ReadonlySet<string> = new Set([
  "credential_reuse",
  "session_token_reuse",
  "api_key_reuse",
  "oauth_token_scope",
  "shared_auth_backend",
  "cors_credential_relay",
  "trust_relationship",
  "subdomain_session_share",
]);

function asLateralMechanism(value: string): LateralMovementMechanism {
  if (LATERAL_MECHANISMS.has(value)) {
    return value as LateralMovementMechanism;
  }
  return "credential_reuse";
}

function formatPlanCommand(plan: AttackPlan, rec?: OperatorAttackRecommendation): string {
  if (rec?.commandSummary) return rec.commandSummary;
  const parts = ["fixguard", "attack", `--plan=${plan.planId}`, `--cap=${plan.capability}`];
  if (plan.targetUrl) parts.push(`--target="${plan.targetUrl}"`);
  if (plan.parameterName) parts.push(`--param="${plan.parameterName}"`);
  return parts.join(" ");
}

function getLogColorClass(log: string): string {
  if (log.startsWith("fixguard@v2:~$")) return "text-emerald-400 font-semibold";
  if (log.includes("[✔ SUCCESS]") || log.includes("[✔ AUTHORIZED]")) return "text-emerald-400";
  if (log.includes("[✖ ERROR]") || log.includes("[✖ EXECUTION FAILED]") || log.includes("Error:")) return "text-rose-400";
  if (log.includes("[!]") || log.includes("[WARNING]")) return "text-amber-300";
  if (log.includes("[+] Hechos descubiertos") || log.includes("[⚡ Epistemic Engine]")) return "text-cyan-300 font-semibold";
  if (log.includes("[*] Iniciando") || log.includes("[*] Autorizando")) return "text-sky-300";
  if (log.startsWith("    ↳") || log.startsWith("    •")) return "text-zinc-300";
  if (log.startsWith("---") || log.startsWith("===")) return "text-zinc-600";
  return "text-zinc-400";
}

function AttackModeContent({
  forcedAssessmentId,
  embedded = false,
  onContinueToReport,
}: AttackModeContentProps) {
  const searchParams = useSearchParams();
  const assessmentIdFromQuery =
    forcedAssessmentId || searchParams.get("assessmentId") || "";

  const [assessmentId, setAssessmentId] = useState(assessmentIdFromQuery);
  const [operatorId] = useState("usr_secops_lead");
  const [targetDomain, setTargetDomain] = useState("");
  const [lineage, setLineage] = useState<LineageTuple | null>(null);
  const [pendingDraftsCount, setPendingDraftsCount] = useState<number>(0);

  useEffect(() => {
    if (assessmentIdFromQuery && assessmentIdFromQuery !== assessmentId) {
      setAssessmentId(assessmentIdFromQuery);
    }
  }, [assessmentIdFromQuery, assessmentId]);

  const [plans, setPlans] = useState<readonly AttackPlan[]>([]);
  const [chains, setChains] = useState<readonly AttackChain[]>([]);
  const [postExploit, setPostExploit] = useState<PostExploitationState | null>(null);
  const [lateral, setLateral] = useState<LateralMovementSnapshot | null>(null);
  const [impacts, setImpacts] = useState<readonly ImpactAssessment[]>([]);

  const [selectedPlanId, setSelectedPlanId] = useState<string | null>(null);
  const [authModalPlan, setAuthModalPlan] = useState<AttackPlan | null>(null);
  const [completedPlanIds, setCompletedPlanIds] = useState<ReadonlySet<string>>(
    () => new Set()
  );
  const [authorizedPlanIds, setAuthorizedPlanIds] = useState<ReadonlySet<string>>(
    () => new Set()
  );
  const [lastAuthMeta, setLastAuthMeta] = useState<AuthorizeAttackPlanResponse["token"] | null>(
    null
  );
  const [executionRecord, setExecutionRecord] = useState<AttackExecutionRecordDto | null>(null);
  const [executionError, setExecutionError] = useState<string | null>(null);
  const [recommendations, setRecommendations] = useState<readonly OperatorAttackRecommendation[]>(
    []
  );
  const [rulesApplied, setRulesApplied] = useState<readonly string[]>([]);
  const [selectedRecRank, setSelectedRecRank] = useState<"A" | "B" | null>(null);
  const [investigationId, setInvestigationId] = useState("");
  const [investigationSnapshot, setInvestigationSnapshot] =
    useState<ActiveInvestigationSnapshotDto | null>(null);
  const [authorizeThenExecute, setAuthorizeThenExecute] = useState(false);
  const [resultsPanel, setResultsPanel] = useState<ResultsPanel>(null);

  const [isLoading, setIsLoading] = useState(false);
  const [busyPlanId, setBusyPlanId] = useState<string | null>(null);
  const [isAuthorizing, setIsAuthorizing] = useState(false);
  const [lateralBusy, setLateralBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Terminal state
  const [terminalLogs, setTerminalLogs] = useState<string[]>([
    "=== FixGuard V2 Tactical Attack Terminal ===",
    "[+] Inicializado con Human-in-the-Loop y boundaries de verificación epistémica.",
    "[*] Escribí 'help' para comandos, 'status' para telemetría, o cargá un comando recomendado desde la izquierda.",
  ]);
  const [terminalInput, setTerminalInput] = useState<string>("");
  const [commandHistory, setCommandHistory] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState<number>(-1);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [copiedTerminalLogs, setCopiedTerminalLogs] = useState(false);

  const terminalEndRef = useRef<HTMLDivElement>(null);
  const terminalInputRef = useRef<HTMLInputElement>(null);

  const addTerminalLog = useCallback((line: string) => {
    setTerminalLogs((prev) => [...prev, line]);
  }, []);

  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [terminalLogs]);

  const displayPlans = useMemo(() => {
    return plans.map((p) => {
      if (authorizedPlanIds.has(p.planId) && p.status === "ready_for_authorization") {
        return { ...p, status: "authorized" as const };
      }
      return p;
    });
  }, [plans, authorizedPlanIds]);

  const loadAll = useCallback(async (id: string) => {
    if (!id || !isStrictSafeId(id)) {
      setError("Assessment ID inválido");
      return;
    }

    setIsLoading(true);
    setError(null);
    try {
      const [plansRes, chainsRes, peRes, latRes, impactRes] = await Promise.all([
        v2AttackApi.getAttackPlans(id),
        v2AttackApi.getAttackChains(id),
        v2AttackApi.getPostExploitation(id),
        v2AttackApi.getLateralMovement(id),
        v2AttackApi.getImpactAssessments(id),
      ]);

      setPlans(plansRes.plans);
      setChains(chainsRes.chains);
      setPostExploit(peRes.state);
      setLateral(latRes.snapshot);
      setImpacts(impactRes.impactAssessments);
      if (plansRes.lineage) {
        setLineage(plansRes.lineage);
      }

      try {
        const recRes = await v2AttackApi.getAttackRecommendations(id, {
          ...(investigationId && isStrictSafeId(investigationId)
            ? { investigationId }
            : {}),
        });
        setRecommendations(recRes.recommendations);
        setRulesApplied(recRes.rulesApplied);
      } catch {
        setRecommendations([]);
        setRulesApplied([]);
      }

      try {
        const summary = await getOrchestratedAssessmentSummary(id);
        if (summary.targetDomain) {
          setTargetDomain(summary.targetDomain);
        }
      } catch {
        // Summary optional
      }

      try {
        const statusRes = await getOrchestratedAssessmentStatus(id);
        if (statusRes.targetDomain && !targetDomain) {
          setTargetDomain(statusRes.targetDomain);
        }
        if (statusRes.lineage && !lineage) {
          setLineage(statusRes.lineage);
        }
        if (statusRes.pendingEvidenceDraftCount !== undefined) {
          setPendingDraftsCount(statusRes.pendingEvidenceDraftCount);
        }
      } catch {
        // Status fallback optional
      }

      if (investigationId && isStrictSafeId(investigationId)) {
        try {
          const invRes = await v2AttackApi.getActiveInvestigation(id, investigationId);
          setInvestigationSnapshot(invRes.snapshot);
        } catch {
          setInvestigationSnapshot(null);
        }
      }

      if (plansRes.plans.length > 0) {
        setSelectedPlanId((prev) => prev ?? plansRes.plans[0].planId);
      }
    } catch (err) {
      if (err instanceof V2ApiError) {
        setError(`[${err.errorType}] ${err.message}${err.reasonCode ? ` (${err.reasonCode})` : ""}`);
      } else {
        setError(err instanceof Error ? err.message : "Error al cargar Attack Mode");
      }
    } finally {
      setIsLoading(false);
    }
  }, [investigationId, targetDomain, lineage]);

  useEffect(() => {
    if (!assessmentIdFromQuery) return;
    const handle = window.setTimeout(() => {
      void loadAll(assessmentIdFromQuery);
    }, 0);
    return () => window.clearTimeout(handle);
  }, [assessmentIdFromQuery, loadAll]);

  const resolveScopeGrant = useCallback(
    (extraHosts?: readonly string[], planTargetUrl?: string) => {
      let domain = targetDomain.trim();
      if (!domain && planTargetUrl) {
        try {
          domain = new URL(planTargetUrl).hostname;
        } catch {
          // ignore
        }
      }
      if (!domain) {
        domain = "target.local";
      }
      const grantId = lineage?.authorizationGrantId || `grant_${assessmentId || "active"}`;
      const scanId = lineage?.scanId || `scan_${assessmentId || "active"}`;
      return buildWorkbenchScopeGrant({
        grantId,
        scanId,
        targetDomain: domain,
        extraHosts,
        allowCredentialUse: true,
      });
    },
    [lineage, targetDomain, assessmentId]
  );

  const handleExecute = async (plan: AttackPlan, customCmdText?: string) => {
    if (!isStrictSafeId(operatorId)) {
      addTerminalLog(`[✖ ERROR] Operator ID '${operatorId}' inválido`);
      return;
    }

    setBusyPlanId(plan.planId);
    setExecutionError(null);
    setError(null);
    setSuccessMsg(null);

    const planTitle = plan.title || plan.capability;
    const cmdRun = customCmdText || formatPlanCommand(plan);
    addTerminalLog(`fixguard@v2:~$ ${cmdRun}`);
    addTerminalLog(`[*] Iniciando ejecución de plan: ${planTitle} (${plan.planId})...`);

    try {
      let extraHosts: string[] | undefined;
      if (plan.targetUrl) {
        try {
          extraHosts = [new URL(plan.targetUrl).hostname];
        } catch {
          extraHosts = undefined;
        }
      }
      const scopeGrant = resolveScopeGrant(extraHosts, plan.targetUrl);
      const res = await v2AttackApi.executeAttackPlan(assessmentId, plan.planId, {
        operatorId,
        scopeGrant,
        ...(investigationId && isStrictSafeId(investigationId)
          ? { investigationId }
          : {}),
      });

      setExecutionRecord(res.record);
      setCompletedPlanIds((prev) => new Set([...prev, plan.planId]));

      if (res.record.status === "completed") {
        addTerminalLog(`[✔ SUCCESS] Plan ${plan.planId} ejecutado con éxito.`);
        if (res.record.stepRecords && res.record.stepRecords.length > 0) {
          for (const step of res.record.stepRecords) {
            addTerminalLog(`    ↳ Paso: ${step.stepId} · outcome: ${step.outcome} (${step.reasonCode})`);
            if (step.safeMessage) {
              addTerminalLog(`      msg: ${step.safeMessage}`);
            }
          }
        }
      } else {
        addTerminalLog(
          `[✖ EXECUTION FAILED] Status: ${res.record.status}`
        );
      }

      if (res.refresh) {
        setChains(res.refresh.attackChains);
        setPostExploit(res.refresh.postExploitationState);
        setLateral(res.refresh.lateralMovementSnapshot);
        setImpacts(res.refresh.impactAssessments);
        if (res.refresh.nextRecommendations && res.refresh.nextRecommendations.length > 0) {
          addTerminalLog(
            `[⚡ Epistemic Engine] ${res.refresh.nextRecommendations.length} nueva(s) recomendación(es) generada(s) por el bucle epistémico.`
          );
          setRecommendations(res.refresh.nextRecommendations);
        }
      }

      void loadAll(assessmentId);
      setSuccessMsg(`Ejecución: ${res.record.status}`);
    } catch (err) {
      const msg =
        err instanceof V2ApiError
          ? `[${err.errorType}] ${err.message}${err.reasonCode ? ` (${err.reasonCode})` : ""}`
          : err instanceof Error
            ? err.message
            : "Execution failed";
      setExecutionError(msg);
      setError(msg);
      addTerminalLog(`[✖ ERROR] Falló la ejecución: ${msg}`);
    } finally {
      setBusyPlanId(null);
    }
  };

  const handleAuthorize = async (blastRadiusClass: BlastRadiusClass) => {
    if (!authModalPlan) return;
    if (!isStrictSafeId(operatorId)) {
      setError("Operator ID inválido");
      addTerminalLog(`[✖ ERROR] Operator ID '${operatorId}' inválido`);
      return;
    }

    const planToAuth = authModalPlan;
    const shouldExecute = authorizeThenExecute;
    setIsAuthorizing(true);
    setError(null);
    setSuccessMsg(null);
    addTerminalLog(`[*] Autorizando plan: ${planToAuth.title} [Blast Radius: ${blastRadiusClass}]...`);

    try {
      const res = await v2AttackApi.authorizeAttackPlan(
        assessmentId,
        planToAuth.planId,
        { operatorId, blastRadiusClass }
      );
      setLastAuthMeta(res.token);
      setAuthorizedPlanIds((prev) => new Set([...prev, planToAuth.planId]));
      addTerminalLog(
        `[✔ AUTHORIZED] Plan ${planToAuth.planId} autorizado exitosamente por ${operatorId} [Blast: ${blastRadiusClass}].`
      );
      setSuccessMsg(`Autorizado · ${planToAuth.title}`);

      // Load command into interactive terminal prompt without auto-sending
      const cmdStr = formatPlanCommand(planToAuth);
      setTerminalInput(cmdStr);
      setTimeout(() => {
        terminalInputRef.current?.focus();
      }, 50);

      addTerminalLog(`[👉 CARGADO EN PROMPT] $ ${cmdStr}`);
      addTerminalLog(
        `[!] Presioná Enter en el teclado o hacé clic en 'Ejecutar' para iniciar la prueba.`
      );

      setAuthModalPlan(null);
      setAuthorizeThenExecute(false);
    } catch (err) {
      const msg =
        err instanceof V2ApiError
          ? `[${err.errorType}] ${err.message}${err.reasonCode ? ` (${err.reasonCode})` : ""}`
          : err instanceof Error
            ? err.message
            : "Authorization failed";
      setError(msg);
      addTerminalLog(`[✖ ERROR] Autorización falló: ${msg}`);
    } finally {
      setIsAuthorizing(false);
    }
  };

  const handleRecommendAuthorizeRun = async (rec: OperatorAttackRecommendation) => {
    if (!rec.planId) {
      addTerminalLog(`[!] La recomendación no tiene plan vinculado.`);
      return;
    }
    const plan = displayPlans.find((p) => p.planId === rec.planId);
    if (!plan) {
      addTerminalLog(`[!] Plan ${rec.planId} no encontrado en este assessment.`);
      return;
    }
    setSelectedRecRank(rec.rank);
    setSelectedPlanId(plan.planId);

    // Always open modal so operator can review and select their preferred blast radius
    setAuthorizeThenExecute(true);
    setAuthModalPlan(plan);
  };

  const handleCopyCommand = async (cmd: string, id: string) => {
    try {
      await navigator.clipboard.writeText(cmd);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2000);
    } catch {
      // ignore
    }
  };

  const handleLoadPrompt = (cmd: string) => {
    setTerminalInput(cmd);
    terminalInputRef.current?.focus();
  };

  const handleTerminalSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const rawCmd = terminalInput.trim();
    if (!rawCmd) return;

    // Save to history
    setCommandHistory((prev) => [...prev, rawCmd]);
    setHistoryIndex(-1);
    setTerminalInput("");

    // Command handling
    if (rawCmd === "clear") {
      setTerminalLogs([]);
      return;
    }

    if (rawCmd === "help") {
      addTerminalLog(`fixguard@v2:~$ help`);
      addTerminalLog(`Comandos disponibles:`);
      addTerminalLog(`  status          - Muestra estado del assessment, target y telemetría`);
      addTerminalLog(`  plans           - Lista todos los planes de ataque autorizables`);
      addTerminalLog(`  run <planId>    - Ejecuta un plan de ataque por ID`);
      addTerminalLog(`  auth <planId>   - Abre el modal de autorización para un plan`);
      addTerminalLog(`  clear           - Limpia la pantalla de la terminal`);
      addTerminalLog(`  help            - Muestra este menú`);
      return;
    }

    if (rawCmd === "status") {
      addTerminalLog(`fixguard@v2:~$ status`);
      addTerminalLog(`Target: ${targetDomain || "(sin target)"}`);
      addTerminalLog(`Assessment ID: ${assessmentId || "(ninguno)"}`);
      addTerminalLog(`Planes disponibles: ${displayPlans.length}`);
      addTerminalLog(`Recomendaciones activas: ${recommendations.length}`);
      addTerminalLog(`Borradores pendientes en Triage: ${pendingDraftsCount}`);
      return;
    }

    if (rawCmd === "plans") {
      addTerminalLog(`fixguard@v2:~$ plans`);
      if (displayPlans.length === 0) {
        addTerminalLog(`No hay planes generados todavía. Revisá Stage 3 (Evidence Triage).`);
      } else {
        displayPlans.forEach((p, idx) => {
          addTerminalLog(`  [${idx + 1}] ${p.planId} · ${p.capability} · ${p.status} · ${p.title}`);
        });
      }
      return;
    }

    if (rawCmd.startsWith("run ") || rawCmd.startsWith("execute ")) {
      const planId = rawCmd.split(" ")[1]?.trim();
      const plan = displayPlans.find((p) => p.planId === planId);
      if (!plan) {
        addTerminalLog(`fixguard@v2:~$ ${rawCmd}`);
        addTerminalLog(`[✖ ERROR] Plan ID '${planId}' no encontrado.`);
        return;
      }
      await handleExecute(plan, rawCmd);
      return;
    }

    if (rawCmd.startsWith("auth ")) {
      const planId = rawCmd.split(" ")[1]?.trim();
      const plan = displayPlans.find((p) => p.planId === planId);
      if (!plan) {
        addTerminalLog(`fixguard@v2:~$ ${rawCmd}`);
        addTerminalLog(`[✖ ERROR] Plan ID '${planId}' no encontrado.`);
        return;
      }
      setAuthorizeThenExecute(false);
      setAuthModalPlan(plan);
      return;
    }

    // Try matching if the operator ran a synthesized fixguard attack command
    const planMatch = /--plan=([a-zA-Z0-9_-]+)/.exec(rawCmd);
    const capMatch = /--cap=([a-zA-Z0-9_-]+)/.exec(rawCmd);
    let targetPlan: AttackPlan | undefined;

    if (planMatch?.[1]) {
      const pByPlanId = displayPlans.find((p) => p.planId === planMatch[1]);
      if (capMatch?.[1] && pByPlanId && pByPlanId.capability !== capMatch[1]) {
        // Operator changed --cap in prompt: find plan with that capability for the same target
        const pByCap = displayPlans.find(
          (p) =>
            p.capability === capMatch[1] &&
            (p.targetUrl === pByPlanId.targetUrl || !pByPlanId.targetUrl)
        );
        if (pByCap) {
          targetPlan = pByCap;
        } else {
          // Synthesize an ad-hoc plan on the fly for the requested capability
          const adHocCap = capMatch[1] as AttackCapabilityKind;
          const targetUrl = pByPlanId.targetUrl || (targetDomain ? `https://${targetDomain}` : undefined);
          targetPlan = {
            contractVersion: "fixguard-attack-planning/v0",
            kind: "attack_plan",
            planId: `apl_adhoc_${adHocCap}_${Date.now().toString(36)}`,
            assessmentId,
            scanId: lineage?.scanId || `scan_${assessmentId}`,
            capability: adHocCap,
            title: `Ad-Hoc Manual Probe: ${adHocCap}`,
            reasoning: `Prueba manual solicitada por el operador en terminal para la capacidad '${adHocCap}'.`,
            status: "ready_for_authorization",
            blastRadius: "single_resource",
            capabilityGained: "active_validation",
            sourceFindingIds: [],
            sourceFindingTypes: [],
            prerequisites: [
              {
                kind: "host_in_scope",
                description: "Host en alcance autorizado",
                satisfied: true,
              },
            ],
            steps: [
              {
                stepId: `step_adhoc_${adHocCap}_1`,
                ordinal: 1,
                title: `Ejecutar probe ${adHocCap}`,
                description: `Invocar probe manual para '${adHocCap}' sobre el objetivo.`,
                status: "ready",
                requiredPermissions: ["active_http_get", "active_http_post"],
              },
            ],
            targetUrl,
            lineage: lineage || {
              assessmentId,
              scanId: `scan_${assessmentId}`,
              authorizationGrantId: `grant_${assessmentId}`,
              authorizationDecisionId: `dec_${assessmentId}`,
              actorId: operatorId,
            },
            createdAt: new Date().toISOString(),
            executable: false,
          };

          addTerminalLog(
            `[⚡ PLAN SINTETIZADO] Se creó un plan ad-hoc dinámico para la capacidad '${adHocCap}' sobre ${targetUrl || targetDomain}.`
          );
        }
      } else {
        targetPlan = pByPlanId;
      }
    } else if (capMatch?.[1]) {
      const pByCap = displayPlans.find((p) => p.capability === capMatch[1]);
      if (pByCap) {
        targetPlan = pByCap;
      } else {
        const adHocCap = capMatch[1] as AttackCapabilityKind;
        const targetUrl = targetDomain ? `https://${targetDomain}` : undefined;
        targetPlan = {
          contractVersion: "fixguard-attack-planning/v0",
          kind: "attack_plan",
          planId: `apl_adhoc_${adHocCap}_${Date.now().toString(36)}`,
          assessmentId,
          scanId: lineage?.scanId || `scan_${assessmentId}`,
          capability: adHocCap,
          title: `Ad-Hoc Manual Probe: ${adHocCap}`,
          reasoning: `Prueba manual solicitada por el operador en terminal para la capacidad '${adHocCap}'.`,
          status: "ready_for_authorization",
          blastRadius: "single_resource",
          capabilityGained: "active_validation",
          sourceFindingIds: [],
          sourceFindingTypes: [],
          prerequisites: [
            {
              kind: "host_in_scope",
              description: "Host en alcance autorizado",
              satisfied: true,
            },
          ],
          steps: [
            {
              stepId: `step_adhoc_${adHocCap}_1`,
              ordinal: 1,
              title: `Ejecutar probe ${adHocCap}`,
              description: `Invocar probe manual para '${adHocCap}' sobre el objetivo.`,
              status: "ready",
              requiredPermissions: ["active_http_get", "active_http_post"],
            },
          ],
          targetUrl,
          lineage: lineage || {
            assessmentId,
            scanId: `scan_${assessmentId}`,
            authorizationGrantId: `grant_${assessmentId}`,
            authorizationDecisionId: `dec_${assessmentId}`,
            actorId: operatorId,
          },
          createdAt: new Date().toISOString(),
          executable: false,
        };

        addTerminalLog(
          `[⚡ PLAN SINTETIZADO] Se creó un plan ad-hoc dinámico para la capacidad '${adHocCap}' sobre ${targetUrl || targetDomain}.`
        );
      }
    }

    if (targetPlan) {
      if (!authorizedPlanIds.has(targetPlan.planId) && targetPlan.status !== "authorized") {
        setAuthorizeThenExecute(true);
        setAuthModalPlan(targetPlan);
      } else {
        await handleExecute(targetPlan, rawCmd);
      }
      return;
    }

    // Unknown command
    addTerminalLog(`fixguard@v2:~$ ${rawCmd}`);
    addTerminalLog(`[!] Comando no reconocido o plan no vinculado. Escribí 'help' o 'plans'.`);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowUp") {
      e.preventDefault();
      if (commandHistory.length === 0) return;
      const nextIdx = historyIndex === -1 ? commandHistory.length - 1 : Math.max(0, historyIndex - 1);
      setHistoryIndex(nextIdx);
      setTerminalInput(commandHistory[nextIdx]);
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      if (historyIndex === -1) return;
      const nextIdx = historyIndex + 1;
      if (nextIdx >= commandHistory.length) {
        setHistoryIndex(-1);
        setTerminalInput("");
      } else {
        setHistoryIndex(nextIdx);
        setTerminalInput(commandHistory[nextIdx]);
      }
    }
  };

  const copyTerminalLogs = async () => {
    try {
      await navigator.clipboard.writeText(terminalLogs.join("\n"));
      setCopiedTerminalLogs(true);
      setTimeout(() => setCopiedTerminalLogs(false), 2000);
    } catch {
      // ignore
    }
  };

  const clearTerminal = () => {
    setTerminalLogs([
      "=== FixGuard V2 Tactical Attack Terminal ===",
      "[*] Pantalla limpiada por el operador.",
    ]);
  };

  const triageHref = assessmentId
    ? `/v2?assessmentId=${encodeURIComponent(assessmentId)}`
    : "/v2";

  const toggleResults = (panel: ResultsPanel) => {
    setResultsPanel((prev) => (prev === panel ? null : panel));
  };

  // Combine recommendations + any standalone plans
  const combinedCards = useMemo(() => {
    const list: Array<{
      id: string;
      title: string;
      capability: string;
      targetUrl?: string;
      rank?: "A" | "B";
      whyPreferred?: string;
      reason?: string;
      commandSummary: string;
      plan?: AttackPlan;
      recommendation?: OperatorAttackRecommendation;
    }> = [];

    // 1. Add recommendations
    for (const rec of recommendations) {
      const plan = rec.planId ? displayPlans.find((p) => p.planId === rec.planId) : undefined;
      list.push({
        id: rec.recommendationId,
        title: rec.humanLabel,
        capability: rec.capabilityKind,
        targetUrl: plan?.targetUrl || (rec.suggestedFlags.targetUrl as string) || (rec.suggestedFlags.url as string),
        rank: rec.rank,
        whyPreferred: rec.whyPreferred,
        reason: rec.reason,
        commandSummary: rec.commandSummary || (plan ? formatPlanCommand(plan, rec) : `fixguard probe --cap=${rec.capabilityKind}`),
        plan,
        recommendation: rec,
      });
    }

    // 2. Add plans not covered by recommendations
    for (const p of displayPlans) {
      if (!list.some((item) => item.plan?.planId === p.planId)) {
        list.push({
          id: p.planId,
          title: p.title,
          capability: p.capability,
          targetUrl: p.targetUrl,
          reason: p.reasoning,
          commandSummary: formatPlanCommand(p),
          plan: p,
        });
      }
    }

    return list;
  }, [recommendations, displayPlans]);

  return (
    <div className={`${embedded ? "" : "min-h-screen"} bg-black text-zinc-100 font-sans ${embedded ? "pb-6" : "pb-24"}`}>
      {!embedded && (
        <header className="border-b border-zinc-900 bg-zinc-950/70 backdrop-blur-xl sticky top-14 z-40">
          <div className="max-w-[1700px] w-full mx-auto px-4 sm:px-6 lg:px-8 py-4 flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <Link
                href={triageHref}
                className="flex h-9 w-9 items-center justify-center rounded-lg border border-zinc-800 bg-zinc-900 text-zinc-400 hover:text-white hover:border-zinc-700 transition"
                title="Volver al wizard / Triage"
              >
                <ArrowLeft className="h-4 w-4" />
              </Link>
              <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-orange-500/30 bg-orange-500/10 text-orange-400">
                <Crosshair className="h-5 w-5" />
              </div>
              <div>
                <h1 className="text-base font-bold tracking-tight text-white flex items-center gap-2">
                  Attack Mode
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded-full border border-orange-500/40 bg-orange-500/10 text-orange-300">
                    Split Tactical Console
                  </span>
                </h1>
                <p className="text-xs text-zinc-400">
                  Target: {targetDomain || "Assessment activo"} · Operador: {operatorId}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <button
                type="button"
                onClick={() => assessmentId && void loadAll(assessmentId)}
                className="inline-flex items-center gap-1.5 rounded-lg border border-zinc-800 bg-zinc-900/60 px-3 py-1.5 text-xs text-zinc-300 hover:bg-zinc-800 transition"
              >
                <RefreshCw className={`h-3.5 w-3.5 ${isLoading ? "animate-spin" : ""}`} />
                Recargar
              </button>
              <Link
                href={triageHref}
                className="rounded-lg border border-zinc-800 bg-zinc-900/60 hover:bg-zinc-900 px-3 py-1.5 text-xs text-zinc-400 hover:text-zinc-200 transition"
              >
                Triage
              </Link>
            </div>
          </div>
        </header>
      )}

      <main className={`${embedded ? "" : "max-w-[1700px] w-full mx-auto px-4 sm:px-6 lg:px-8 mt-6"} space-y-6`}>
        {embedded && (
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-orange-500/20 bg-orange-500/5 px-4 py-3">
            <div className="flex items-center gap-2">
              <Crosshair className="h-4 w-4 text-orange-400" />
              <div>
                <h2 className="text-sm font-semibold text-zinc-100 flex items-center gap-2">
                  Stage 4: Attack Mode
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded-full border border-orange-500/40 bg-orange-500/10 text-orange-300">
                    Consola Táctica Split
                  </span>
                </h2>
                <p className="text-[11px] text-zinc-500">
                  Comandos recomendados a la izquierda · Consola interactiva a la derecha
                </p>
              </div>
            </div>
            {onContinueToReport && (
              <button
                type="button"
                onClick={onContinueToReport}
                className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-emerald-500 shadow-md shadow-emerald-600/20 transition"
              >
                Continue to Report →
              </button>
            )}
          </div>
        )}

        {error && (
          <div className="flex items-start justify-between gap-3 rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-300">
            <div className="flex items-start gap-2">
              <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
            <button type="button" onClick={() => setError(null)} className="text-rose-400 hover:text-rose-200">
              Cerrar
            </button>
          </div>
        )}

        {successMsg && (
          <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-[11px] text-emerald-300">
            {successMsg}
          </div>
        )}

        {/* ── 2-COLUMN SPLIT LAYOUT ────────────────────────────────────────── */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          
          {/* LEFT COLUMN: Recomendaciones y Tarjetas de Vulnerabilidad (5 cols) */}
          <div className="lg:col-span-5 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-orange-400" />
                <h3 className="text-sm font-semibold text-zinc-100">
                  Vulnerabilidades & Recomendaciones
                </h3>
              </div>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded-full border border-zinc-800 bg-zinc-900 text-zinc-400">
                {combinedCards.length} disponibles
              </span>
            </div>

            {/* List of cards */}
            <div className="space-y-3 max-h-[640px] overflow-y-auto pr-1">
              {combinedCards.length === 0 ? (
                <div className="rounded-xl border border-zinc-800/80 bg-zinc-950/60 p-5 space-y-3 text-center">
                  <div className="flex justify-center">
                    <div className="flex h-10 w-10 items-center justify-center rounded-full bg-zinc-900 border border-zinc-800 text-zinc-500">
                      <ShieldAlert className="h-5 w-5" />
                    </div>
                  </div>
                  <div>
                    <h4 className="text-xs font-semibold text-zinc-200">
                      Sin planes de ataque promovidos todavía
                    </h4>
                    <p className="text-[11px] text-zinc-500 mt-1 leading-relaxed">
                      {pendingDraftsCount > 0
                        ? `Hay ${pendingDraftsCount} borrador(es) de evidencia detectados en Active Recon listos para ser revisados en Stage 3: Evidence Triage.`
                        : "Completá Stage 3 (Evidence Triage) para promover los hallazgos observados a planes de ataque ejecutables."}
                    </p>
                  </div>
                  {pendingDraftsCount > 0 && (
                    <Link
                      href={triageHref}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-1.5 text-xs font-medium text-amber-300 hover:bg-amber-500/20 transition"
                    >
                      Ir a Evidence Triage ({pendingDraftsCount} drafts) →
                    </Link>
                  )}
                </div>
              ) : (
                combinedCards.map((item) => {
                  const isPlanAuthorized =
                    item.plan &&
                    (authorizedPlanIds.has(item.plan.planId) ||
                      item.plan.status === "authorized");
                  const isBusy = busyPlanId === item.plan?.planId;

                  return (
                    <article
                      key={item.id}
                      className="rounded-xl border border-zinc-800/90 bg-zinc-950/80 p-4 space-y-3 hover:border-zinc-700 transition"
                    >
                      {/* Top Badges */}
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          {item.rank && (
                            <span
                              className={`inline-flex h-6 w-6 items-center justify-center rounded-md font-mono text-xs font-bold border ${
                                item.rank === "A"
                                  ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                                  : "border-sky-500/40 bg-sky-500/10 text-sky-300"
                              }`}
                              title={`Prioridad ${item.rank}`}
                            >
                              {item.rank}
                            </span>
                          )}
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-zinc-800 bg-zinc-900 text-purple-300">
                            {item.capability}
                          </span>
                        </div>

                        {item.plan && (
                          <span
                            className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                              isPlanAuthorized
                                ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                                : "border-zinc-800 bg-zinc-900 text-zinc-500"
                            }`}
                          >
                            {isPlanAuthorized ? "autorizado" : item.plan.status}
                          </span>
                        )}
                      </div>

                      {/* Title & Where Found */}
                      <div>
                        <h4 className="text-xs font-semibold text-zinc-100">
                          {item.title}
                        </h4>
                        {item.targetUrl && (
                          <div className="flex items-center gap-1.5 mt-1 text-[11px] font-mono text-zinc-400 break-all">
                            <Globe className="h-3 w-3 shrink-0 text-zinc-500" />
                            <span>{item.targetUrl}</span>
                          </div>
                        )}
                        {(item.whyPreferred || item.reason) && (
                          <p className="mt-1 text-[11px] text-zinc-400 line-clamp-2 leading-relaxed">
                            {item.whyPreferred || item.reason}
                          </p>
                        )}
                      </div>

                      {/* Monospace Command Box */}
                      <div className="relative group">
                        <div className="rounded-lg border border-zinc-900 bg-black/60 p-2.5 font-mono text-[11px] text-emerald-400/90 break-all select-all">
                          {item.commandSummary}
                        </div>
                      </div>

                      {/* Action Buttons: Copiar, Cargar Prompt, Lanzar */}
                      <div className="flex flex-wrap items-center gap-2 pt-1">
                        <button
                          type="button"
                          onClick={() => void handleCopyCommand(item.commandSummary, item.id)}
                          className="inline-flex items-center gap-1.5 rounded-lg border border-zinc-800 bg-zinc-900/80 px-2.5 py-1.5 text-xs text-zinc-300 hover:border-zinc-700 hover:text-white transition"
                          title="Copiar comando completo al portapapeles"
                        >
                          {copiedId === item.id ? (
                            <>
                              <Check className="h-3.5 w-3.5 text-emerald-400" />
                              <span className="text-emerald-400">Copiado</span>
                            </>
                          ) : (
                            <>
                              <Copy className="h-3.5 w-3.5 text-zinc-400" />
                              <span>Copiar</span>
                            </>
                          )}
                        </button>

                        <button
                          type="button"
                          onClick={() => handleLoadPrompt(item.commandSummary)}
                          className="inline-flex items-center gap-1.5 rounded-lg border border-blue-500/30 bg-blue-500/10 px-2.5 py-1.5 text-xs font-medium text-blue-300 hover:bg-blue-500/20 transition"
                          title="Cargar comando en la consola para editarlo"
                        >
                          <CornerDownLeft className="h-3.5 w-3.5 text-blue-400" />
                          <span>Cargar Prompt</span>
                        </button>

                        {item.plan && (
                          <div className="flex items-center gap-1.5 ml-auto">
                            {isPlanAuthorized && (
                              <button
                                type="button"
                                disabled={isBusy || isAuthorizing}
                                onClick={() => {
                                  const plan = item.plan;
                                  if (!plan) return;
                                  void handleExecute(plan);
                                }}
                                className="inline-flex items-center gap-1 rounded-lg border border-zinc-700 bg-zinc-900 px-2.5 py-1.5 text-xs font-medium text-zinc-300 hover:bg-zinc-800 disabled:opacity-50 transition"
                                title="Repetir ejecución inmediata con el alcance previamente autorizado"
                              >
                                Repetir
                              </button>
                            )}
                            <button
                              type="button"
                              disabled={isBusy || isAuthorizing}
                              onClick={() => {
                                const plan = item.plan;
                                if (!plan) return;
                                setAuthorizeThenExecute(true);
                                setAuthModalPlan(plan);
                              }}
                              className="inline-flex items-center gap-1.5 rounded-lg bg-orange-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-orange-500 disabled:opacity-50 transition shadow-md shadow-orange-600/20"
                              title="Elegir alcance y autorizar ejecución"
                            >
                              <Play className="h-3.5 w-3.5 fill-current" />
                              <span>{isPlanAuthorized ? "Opciones / Lanzar" : "Lanzar"}</span>
                            </button>
                          </div>
                        )}
                      </div>
                    </article>
                  );
                })
              )}
            </div>
          </div>

          {/* RIGHT COLUMN: Terminal Táctica Interactiva (7 cols) */}
          <div className="lg:col-span-7">
            <div className="rounded-xl border border-zinc-800 bg-zinc-950/90 shadow-2xl overflow-hidden flex flex-col h-[650px]">
              
              {/* Terminal Title Bar */}
              <div className="flex items-center justify-between px-4 py-2.5 border-b border-zinc-800/80 bg-zinc-900/60 select-none">
                <div className="flex items-center gap-2">
                  <div className="flex gap-1.5">
                    <div className="h-3 w-3 rounded-full bg-rose-500/70" />
                    <div className="h-3 w-3 rounded-full bg-amber-500/70" />
                    <div className="h-3 w-3 rounded-full bg-emerald-500/70" />
                  </div>
                  <div className="flex items-center gap-1.5 ml-2 font-mono text-xs text-zinc-400">
                    <TerminalIcon className="h-3.5 w-3.5 text-emerald-400" />
                    <span>fixguard-v2-terminal</span>
                    <span className="text-zinc-600">::</span>
                    <span className="text-zinc-500">
                      session@{targetDomain || "localhost"}
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={copyTerminalLogs}
                    className="inline-flex items-center gap-1 text-[11px] font-mono text-zinc-400 hover:text-white px-2 py-1 rounded hover:bg-zinc-800 transition"
                    title="Copiar salida de terminal"
                  >
                    {copiedTerminalLogs ? (
                      <Check className="h-3 w-3 text-emerald-400" />
                    ) : (
                      <Copy className="h-3 w-3" />
                    )}
                    <span>{copiedTerminalLogs ? "Copiado" : "Copiar"}</span>
                  </button>

                  <button
                    type="button"
                    onClick={clearTerminal}
                    className="inline-flex items-center gap-1 text-[11px] font-mono text-zinc-400 hover:text-white px-2 py-1 rounded hover:bg-zinc-800 transition"
                    title="Limpiar pantalla"
                  >
                    <Trash2 className="h-3 w-3" />
                    <span>Limpiar</span>
                  </button>
                </div>
              </div>

              {/* Terminal Logs Window */}
              <div className="flex-1 p-4 overflow-y-auto space-y-1.5 font-mono text-xs select-text bg-black/90">
                {terminalLogs.map((log, idx) => (
                  <div
                    key={idx}
                    className={`leading-relaxed break-all ${getLogColorClass(log)}`}
                  >
                    {log}
                  </div>
                ))}
                <div ref={terminalEndRef} />
              </div>

              {/* Interactive Prompt Input Bar */}
              <form
                onSubmit={handleTerminalSubmit}
                className="flex items-center gap-2 p-3 border-t border-zinc-800 bg-zinc-950 font-mono text-xs"
              >
                <div className="flex items-center gap-1 shrink-0 text-emerald-400 font-semibold select-none">
                  <span>fixguard@v2</span>
                  <span className="text-zinc-600">:</span>
                  <span className="text-blue-400">~</span>
                  <span className="text-zinc-400">$</span>
                </div>

                <input
                  ref={terminalInputRef}
                  type="text"
                  value={terminalInput}
                  onChange={(e) => setTerminalInput(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder="Escribí un comando o cargá uno desde la izquierda (ej. help, status, plans)..."
                  className="flex-1 bg-transparent text-zinc-100 placeholder-zinc-600 focus:outline-none font-mono text-xs"
                  autoFocus
                />

                <button
                  type="submit"
                  disabled={!terminalInput.trim()}
                  className="inline-flex items-center gap-1 px-3 py-1.5 rounded-md bg-emerald-600/80 hover:bg-emerald-500 text-zinc-950 font-semibold text-[11px] font-mono transition disabled:opacity-30 disabled:cursor-not-allowed"
                >
                  <span>Ejecutar</span>
                  <CornerDownLeft className="h-3 w-3" />
                </button>
              </form>
            </div>
          </div>
        </div>

        {/* ── ACCORDION BOTTOM: Results, Chains, Impact & Post-Exploitation ── */}
        <section className="rounded-xl border border-zinc-900 bg-zinc-950/60 overflow-hidden">
          <div className="border-b border-zinc-900 px-4 py-2.5">
            <h3 className="text-sm font-semibold text-zinc-100">
              Evidencia & Cadenas de Verificación
            </h3>
            <p className="text-[11px] text-zinc-500">
              Secuencia causal de pasos, evaluación de impacto y alcance lateral verificado
            </p>
          </div>

          <ResultsAccordion
            id="chains"
            title={`Cadenas de Explotación (${chains.length})`}
            subtitle="Secuencia de pasos OBSERVED / VERIFIED / REFUTED contra el objetivo"
            open={resultsPanel === "chains"}
            onToggle={() => toggleResults("chains")}
          >
            <AttackChainViewer chains={chains} />
          </ResultsAccordion>

          <ResultsAccordion
            id="impact"
            title={`Evaluación de Impacto (${impacts.length})`}
            subtitle="Qué se probó, resultado obtenido y qué implica para el target"
            open={resultsPanel === "impact"}
            onToggle={() => toggleResults("impact")}
          >
            <ImpactAssessmentView assessments={impacts} />
          </ResultsAccordion>

          <ResultsAccordion
            id="post_exploit"
            title="Post-explotación & Movimiento Lateral"
            subtitle="Alcance lateral y evaluación de credenciales (solo bajo autorización)"
            open={resultsPanel === "post_exploit"}
            onToggle={() => toggleResults("post_exploit")}
            last
          >
            <PostExploitationPanel
              state={postExploit}
              lateral={lateral}
              busy={lateralBusy}
              onPromote={() => {}}
              onCredentialReuse={() => {}}
            />
          </ResultsAccordion>
        </section>
      </main>

      {authModalPlan && (
        <AttackAuthorizationModal
          plan={authModalPlan}
          operatorId={operatorId}
          isSubmitting={isAuthorizing}
          onAuthorize={(c) => void handleAuthorize(c)}
          onDecline={() => {
            setAuthorizeThenExecute(false);
            setAuthModalPlan(null);
          }}
        />
      )}
    </div>
  );
}

function ResultsAccordion({
  title,
  subtitle,
  open,
  onToggle,
  children,
  last,
}: {
  readonly id: string;
  readonly title: string;
  readonly subtitle: string;
  readonly open: boolean;
  readonly onToggle: () => void;
  readonly children: React.ReactNode;
  readonly last?: boolean;
}) {
  return (
    <div className={last ? "" : "border-b border-zinc-900"}>
      <button
        type="button"
        onClick={onToggle}
        className="flex w-full items-start gap-2 px-4 py-3 text-left hover:bg-zinc-900/40 transition"
      >
        {open ? (
          <ChevronDown className="h-4 w-4 text-zinc-500 mt-0.5 shrink-0" />
        ) : (
          <ChevronRight className="h-4 w-4 text-zinc-500 mt-0.5 shrink-0" />
        )}
        <span className="min-w-0">
          <span className="block text-xs font-semibold text-zinc-200">{title}</span>
          <span className="block text-[10px] text-zinc-500">{subtitle}</span>
        </span>
      </button>
      {open && <div className="px-4 pb-4">{children}</div>}
    </div>
  );
}

export function EmbeddedAttackMode({
  assessmentId,
  onContinueToReport,
}: {
  readonly assessmentId: string;
  readonly onContinueToReport?: () => void;
}) {
  return (
    <Suspense
      fallback={
        <div className="rounded-xl border border-zinc-800 bg-zinc-950/60 p-8 text-center text-sm font-mono text-zinc-500">
          Cargando Attack Mode…
        </div>
      }
    >
      <AttackModeContent
        forcedAssessmentId={assessmentId}
        embedded
        onContinueToReport={onContinueToReport}
      />
    </Suspense>
  );
}

export default function AttackPage() {
  return (
    <Suspense
      fallback={
        <div className="rounded-xl border border-zinc-800 bg-zinc-950/60 p-8 text-center text-sm font-mono text-zinc-500">
          Cargando Attack Mode…
        </div>
      }
    >
      <AttackModeContent />
    </Suspense>
  );
}
