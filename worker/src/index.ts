import express from 'express';
import cors from 'cors';
import { runHeaderScan } from './scanner/headers';
import { runTlsScan } from './scanner/tls';
import { runDnsScan } from './scanner/dns';
import { runPortScan } from './scanner/ports';
import { runDirectoryScan } from './scanner/directories';
import { runWafScan } from './scanner/waf';
import { runFingerprintScan } from './scanner/fingerprint';
import { runSecurityTxtScan } from './scanner/securityTxt';
import { runRateLimitScan } from './scanner/ratelimit';
import { runApiDiscoveryScan } from './scanner/api-discovery';
import { runSecretsScan } from './scanner/secrets';
import { runJwtScan } from './scanner/jwt';
import { runTraversalScan } from './scanner/traversal';
import { runPollutionScan } from './scanner/pollution';

// Recon Motores
import { runTechStackProfiler } from './recon/TechStackProfiler';
import { runAttackSurfaceMapper } from './recon/AttackSurfaceMapper';
import { runFrameworkIntelligence } from './recon/FrameworkIntelligence';
import { buildArchitectureTree } from './recon/ArchitectureBuilder';
import { JsKnowledgeExtractor } from './recon/parsers/JsKnowledgeExtractor';
import { ExposureIntelligenceEngine } from './recon/ExposureIntelligenceEngine';
import { AuthIntelligenceEngine } from './recon/parsers/AuthIntelligenceEngine';
import { CloudIntelligenceEngine } from './recon/CloudIntelligenceEngine';
import { ServerActionsEngine } from './recon/ServerActionsEngine';
import { CommunicationIntelligenceEngine } from './recon/CommunicationIntelligenceEngine';
import { SubdomainIntelligenceEngine } from './recon/SubdomainIntelligenceEngine';
import { ArtifactIntelligenceEngine } from './recon/ArtifactIntelligenceEngine';
import { ParameterIntelligenceEngine } from './recon/ParameterIntelligenceEngine';
import { AIFingerprintEngine } from './recon/AIFingerprintEngine';
import { CorrelationEngine } from './recon/CorrelationEngine';
import { EntityRelationshipEngine } from './scanner/entityEngine';
import { WorkflowReconstructionEngine } from './recon/WorkflowReconstructionEngine';
import { BolaExploiter } from './scanner/logic/BolaExploiter';
import { MassAssignmentExploiter } from './scanner/logic/MassAssignmentExploiter';
import { WorkflowBypassExploiter } from './scanner/logic/WorkflowBypassExploiter';
import { AttackExecutor } from './scanner/AttackExecutor';
import { React2ShellVector } from './scanner/vectors/React2ShellVector';
import axios from 'axios';
// Nuevos Motores Pasivos
import { runSubfinderScan } from './scanner/subfinder';
import { runHttpxScan } from './scanner/httpx';
import { runGauScan } from './scanner/gau';
import type { NormalizedReconProfile } from './db/schema';

// Nuevos Motores Fase 6
import { runCrawler } from './scanner/crawler';
import { runJsReconScan } from './scanner/jsrecon';
import { runNextJsScan } from './scanner/nextjs';
import { runCloudExposureScan } from './scanner/cloud';
import { runUploadsScan } from './scanner/uploads';
import { runBolaScan } from './scanner/bola';
import { runSsrfScan } from './scanner/ssrf';
import { runRedirectScan } from './scanner/redirect';
import { runServerActionsScan } from './scanner/serveractions';

import { db } from './db/db';
import { scans, reconProfiles } from './db/schema';
import { eq } from 'drizzle-orm';
import 'dotenv/config';

const app = express();
app.use(cors());
app.use(express.json());

app.post('/api/scan', async (req, res) => {
  const { targetUrl, scanId, mode } = req.body;

  if (!targetUrl || !scanId) {
    return res.status(400).json({ error: 'Falta targetUrl o scanId' });
  }

  res.json({ message: 'Escaneo iniciado', scanId });

  try {
    await db.update(scans).set({ status: 'in_progress' }).where(eq(scans.id, scanId));

    console.log(`\n[Scan ${scanId}] Iniciando motores de escaneo (${mode || 'passive'}) para ${targetUrl}...`);
    
    if (mode === 'targeted') {
      const scan = await db.select().from(scans).where(eq(scans.id, scanId)).limit(1).then(res => res[0]);
      if (scan && scan.targetedVectorId) {
        console.log(`[Scan ${scanId}] 🎯 Ejecutando Ataque Dirigido: ${scan.targetedVectorId} contra ${targetUrl}`);
        const { runTargetedAttack } = await import('./targetedOrchestrator');
        await runTargetedAttack(scanId, scan.userId, targetUrl, scan.targetedVectorId, scan.parentScanId || undefined);
        
        await db.update(scans).set({ 
          status: 'completed', 
          completedAt: new Date() 
        }).where(eq(scans.id, scanId));
        return; // Salimos de la función principal
      }
    }
    
    // --- FASE 1: RECONOCIMIENTO INTELIGENTE ---
    console.log(`[Scan ${scanId}] Ejecutando Inteligencia de Superficie de Ataque...`);
    
    // 1. Perfil del Tech Stack
    const techStack = await runTechStackProfiler(targetUrl);
    
    // 2. Framework Intelligence basado en el Stack
    const frameworkIntelligence = runFrameworkIntelligence(techStack);
    
    const domain = new URL(targetUrl).hostname;

    // --- INTEGRACIÓN CASCADA PASIVA ---
    // 1. Subfinder
    const subdomains = await runSubfinderScan(domain);
    // Asegurar que el target actual también esté en la lista para no perderlo
    if (!subdomains.includes(domain)) subdomains.push(domain);
    
    // 2. HTTPX
    const httpxResults = await runHttpxScan(scanId, subdomains);
    const liveHosts = httpxResults.map(r => r.url);
    
    // 3. GAU
    const gauUrls = await runGauScan(scanId, liveHosts.length > 0 ? liveHosts : [domain]);
    const normalizedEndpoints: NormalizedReconProfile['endpoints'] = gauUrls.map(url => ({
      url,
      source: 'gau',
      lastSeen: new Date().toISOString()
    }));

    // Ejecutar OSINT y JS Recon en paralelo
    const passiveTasks = [
      runHeaderScan(scanId, targetUrl),
      runTlsScan(scanId, targetUrl),
      runDnsScan(scanId, targetUrl),
      runPortScan(scanId, targetUrl),
      runDirectoryScan(scanId, targetUrl),
      runWafScan(scanId, targetUrl),
      runFingerprintScan(scanId, targetUrl),
      runSecurityTxtScan(scanId, targetUrl),
      runNextJsScan(scanId, targetUrl),
      runCloudExposureScan(scanId, targetUrl),
      runUploadsScan(scanId, targetUrl)
    ];

    // JS Recon ahora retorna los endpoints encontrados
    const [jsEndpoints] = await Promise.all([
      runJsReconScan(scanId, targetUrl),
      ...passiveTasks
    ]);

    let urlsToAttack = [targetUrl];
    let jsFilesFromCrawler: string[] = [];
    let runtimeIntelligence = undefined;
    if (mode === 'aggressive') {
      const crawlerData = await runCrawler(scanId, targetUrl);
      urlsToAttack = Array.from(new Set([...urlsToAttack, ...crawlerData.endpoints]));
      jsFilesFromCrawler = crawlerData.jsFiles;
      runtimeIntelligence = crawlerData.runtimeIntelligence;
    }

    // Unir endpoints JS, Crawler, y GAU
    const allDiscoveredPaths = Array.from(new Set([...jsEndpoints, ...gauUrls, ...urlsToAttack.map(u => {
      try { return new URL(u).pathname; } catch { return u; }
    })]));

    // 4. Mapeo de Superficie y Ranking de Riesgo
    let attackSurface = runAttackSurfaceMapper(allDiscoveredPaths);

    // Extraer Conocimiento de JS (Módulo 3)
    const businessDictionary = await JsKnowledgeExtractor.extractFromJsFiles(jsFilesFromCrawler);

    // Módulo 10: Enriquecer con IA (solo endpoints críticos/altos)
    attackSurface = await ExposureIntelligenceEngine.enrichAttackSurface(attackSurface, businessDictionary, techStack);

    // Módulo 4: Auth Intelligence
    // Obtener headers de una peticion base
    let baseHeaders: Record<string, string | string[]> = {};
    let baseHtml = '';
    try {
      const resp = await axios.get(targetUrl, { timeout: 3000 });
      baseHeaders = resp.headers as unknown as Record<string, string | string[]>;
      baseHtml = typeof resp.data === 'string' ? resp.data : '';
    } catch(e) {}
    
    // Traer codigo fuente de JS
    const jsCodes: string[] = [];
    for (const u of jsFilesFromCrawler) {
       try {
         const {data} = await axios.get(u, {timeout: 3000});
         if (typeof data === 'string') jsCodes.push(data);
       } catch(e) {}
    }

    const authIntelligence = AuthIntelligenceEngine.analyze(jsCodes, baseHeaders);

    // Módulo 6: Cloud Intelligence
    const cloudIntelligence = await CloudIntelligenceEngine.analyze(targetUrl, baseHtml, jsCodes);

    // Módulos 8 y 9: GraphQL & WebSocket Intelligence
    const communicationIntelligence = await CommunicationIntelligenceEngine.analyze(targetUrl, baseHtml, jsCodes);

    // NUEVO: Motores Avanzados de Reconocimiento Funcional
    const subdomainIntelligence = await SubdomainIntelligenceEngine.discover(domain);
    // --- FASE 3: Análisis de Artefactos (NUEVO: Pasamos las URLs de los JS para detectar Source Maps) ---
    const artifactIntelligence = await ArtifactIntelligenceEngine.analyze(targetUrl, jsCodes, jsFilesFromCrawler);
    
    // --- FASE 3.5: Extracción de Acciones Remotas (Next.js, Remix, SvelteKit, etc.) ---
    const isNextJs = techStack.some(t => t.name.toLowerCase().includes('next.js'));
    // Ahora el engine soporta múltiples frameworks, lo corremos siempre para ver qué pilla
    const serverActionsIntelligence = ServerActionsEngine.analyze(jsCodes);

    const parameterIntelligence = ParameterIntelligenceEngine.analyze(attackSurface);
    const aiIntelligence = AIFingerprintEngine.analyze(jsCodes, baseHeaders);

    // 3. Reconstrucción de Arquitectura Avanzada (Módulo 1)
    const architectureTree = buildArchitectureTree(domain, techStack, attackSurface, businessDictionary);
    
    // NUEVO: Entity Relationship Engine (ERE)
    const entityGraph = await EntityRelationshipEngine.analyze(allDiscoveredPaths, jsCodes, businessDictionary);

    // NUEVO: Workflow Reconstruction
    const workflowIntelligence = WorkflowReconstructionEngine.analyze(allDiscoveredPaths);

    // NUEVO: Correlation Engine (Auditoría Inteligente)
    const auditReport = CorrelationEngine.analyze(
      authIntelligence,
      cloudIntelligence,
      parameterIntelligence,
      artifactIntelligence,
      communicationIntelligence,
      businessDictionary,
      attackSurface,
      aiIntelligence
    );

    // 4.5 Generar Vectores Inteligentes de Ataque Recomendados (Smart Vectors)
    const smartVectors = [
      ...BolaExploiter.generateVectors(targetUrl, attackSurface, entityGraph),
      ...MassAssignmentExploiter.generateVectors(targetUrl, attackSurface, businessDictionary),
      ...WorkflowBypassExploiter.generateVectors(targetUrl, workflowIntelligence)
    ];

    // 5. Normalizar Datos
    const normalizedData: NormalizedReconProfile = {
      scanId,
      target: targetUrl,
      stack: {
        frontend: techStack.find(t => t.category === 'Frontend Framework')?.name || null,
        runtime: techStack.find(t => t.category === 'Backend Framework')?.name || null,
        waf: httpxResults.find(r => r.url.includes(domain))?.technologies.find(t => t.toLowerCase().includes('cloudflare') || t.toLowerCase().includes('modsecurity')) || null,
        cdn: httpxResults.find(r => r.url.includes(domain))?.cdn || null,
        confidence: 0.9,
        database_hints: techStack.filter(t => t.category === 'Database').map(t => t.name)
      },
      endpoints: normalizedEndpoints,
      subdomains: subdomains.map(s => ({ domain: s, source: 'subfinder', takeover_candidate: false })),
      credentials: [], // Se poblará en la fase de credenciales
      vulnerabilities_hints: []
    };

    // 6. Guardar Perfil de Reconocimiento
    await db.insert(reconProfiles).values({
      scanId,
      techStack,
      attackSurface,
      frameworkIntelligence,
      architectureTree,
      businessDictionary,
      authIntelligence,
      cloudIntelligence,
      communicationIntelligence,
      subdomainIntelligence,
      artifactIntelligence,
      parameterIntelligence,
      serverActionsIntelligence,
      aiIntelligence,
      runtimeIntelligence,
      entityGraph,
      workflowIntelligence,
      auditReport,
      smartVectors,
      normalizedData
    }).returning({ id: reconProfiles.id });

    console.log(`[Scan ${scanId}] Análisis Pasivo y Reconocimiento completado. Guardado Perfil Tech Stack.`);

    // --- FASE 2: ATAQUE DIRIGIDO (Eliminada fase activa masiva obsoleta) ---
    // FixGuard ahora depende del orquestador dirigido en /api/attack/targeted
    // Este index solo procesa la fase de reconocimiento e inteligencia.

    await db.update(scans).set({ 
      status: 'completed', 
      completedAt: new Date() 
    }).where(eq(scans.id, scanId));
    console.log(`[Scan ${scanId}] 🎉 Todos los motores finalizaron exitosamente.`);

    // --- EXECUTE AUTO-EXPLOITS DE ALTA SEVERIDAD SI EL STACK ES VULNERABLE ---
    if (isNextJs) {
      console.log(`[Scan ${scanId}] ⚠️ Framework Next.js detectado. Lanzando ataque automático de verificación React2Shell (CVE-2025-55182)...`);
      const react2shell = React2ShellVector.generateVector(targetUrl, targetUrl); // Usamos targetUrl como raíz
      const success = await AttackExecutor.executeAndCompare(scanId, targetUrl, react2shell);
      if (success) {
        console.log(`[Scan ${scanId}] 🚨 CRÍTICO: Vulnerabilidad React2Shell (RCE) confirmada en el servidor de Next.js.`);
      }
    }

    // --- EJECUTAR VECTORES DE BUSINESS LOGIC ---
    if (smartVectors && smartVectors.length > 0) {
      console.log(`[Scan ${scanId}] ⚔️ Iniciando Attack Executor para ${smartVectors.length} vectores de lógica de negocio...`);
      for (const vector of smartVectors) {
        // En MVP no bloqueamos si uno falla, seguimos con el resto
        await AttackExecutor.executeAndCompare(scanId, targetUrl, vector);
      }
    }

  } catch (error: any) {
    console.error(`[Scan ${scanId}] Error global de orquestación:`, error);
    await db.update(scans).set({ 
      status: 'failed', 
      completedAt: new Date() 
    }).where(eq(scans.id, scanId));
  }
});

import { vulnerabilities } from './db/schema';
import { SemgrepEngine } from './scanner/sast/SemgrepEngine';

// El endpoint /api/scan/resume se ha eliminado porque la fase de escaneo 
// "agresivo" y masivo a ciegas ha sido reemplazada por el modelo de 
// Vectores Inteligentes dirigidos a través de la Consola Táctica.

app.post('/api/sast', async (req, res) => {
  const { targetDir, scanId } = req.body;

  if (!targetDir || !scanId) {
    return res.status(400).json({ error: 'Falta targetDir o scanId' });
  }

  res.json({ message: 'Escaneo SAST iniciado', scanId });

  try {
    await db.update(scans).set({ status: 'in_progress' }).where(eq(scans.id, scanId));
    console.log(`\n[Scan ${scanId}] Iniciando motor SAST (Semgrep) en directorio local: ${targetDir}...`);
    
    const findings = await SemgrepEngine.scanDirectory(targetDir);
    
    for (const finding of findings) {
       await db.insert(vulnerabilities).values({
         scanId,
         type: finding.type,
         severity: finding.severity,
         description: `${finding.description}\n\nArchivo: ${finding.file}`,
         autoFixCode: null,
       });
    }

    await db.update(scans).set({ 
      status: 'completed', 
      completedAt: new Date() 
    }).where(eq(scans.id, scanId));
    console.log(`[Scan ${scanId}] 🎉 Escaneo SAST completado. Se encontraron ${findings.length} problemas.`);

  } catch (error: any) {
    console.error(`[Scan ${scanId}] Error global SAST:`, error);
    await db.update(scans).set({ 
      status: 'failed', 
      completedAt: new Date() 
    }).where(eq(scans.id, scanId));
  }
});

import { runTargetedAttack } from './targetedOrchestrator';

app.post('/api/attack/targeted', async (req, res) => {
  const { targetUrl, scanId, vectorId, parentId } = req.body;

  if (!targetUrl || !scanId || !vectorId) {
    return res.status(400).json({ error: 'Falta targetUrl, scanId o vectorId' });
  }

  try {
    await db.update(scans).set({ status: 'in_progress', mode: 'targeted' }).where(eq(scans.id, scanId));
    
    // Obtenemos el userId asociado al scan
    const currentScan = await db.select().from(scans).where(eq(scans.id, scanId)).limit(1).then(res => res[0]);
    if (!currentScan) {
      throw new Error(`Scan ${scanId} no encontrado en base de datos`);
    }
    
    // Execute attack and get output to return to the frontend Tactical Console
    const attackOutput = await runTargetedAttack(scanId, currentScan.userId, targetUrl, vectorId, parentId);

    await db.update(scans).set({ 
      status: 'completed', 
      completedAt: new Date() 
    }).where(eq(scans.id, scanId));

    return res.json({ 
      message: 'Ataque completado', 
      scanId, 
      vectorId,
      output: attackOutput
    });
  } catch (error: any) {
    console.error(`[Scan ${scanId}] Error en ataque dirigido:`, error);
    await db.update(scans).set({ 
      status: 'failed', 
      completedAt: new Date() 
    }).where(eq(scans.id, scanId));
    return res.status(500).json({ error: error.message });
  }
});


import { DependencyChecker } from './utils/DependencyChecker';

const PORT = 4000;
app.listen(PORT, () => {
  console.log(`🚀 FixGuard OSINT Worker ejecutándose en http://localhost:${PORT}`);
  DependencyChecker.checkAll();
});
