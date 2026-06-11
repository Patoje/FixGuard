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
import { runSqliScan } from './scanner/sqli';
import { runXssScan } from './scanner/xss';
import { runCorsScan } from './scanner/cors';
import { runGraphqlScan } from './scanner/graphql';
import { runSourceMapScan } from './scanner/sourcemaps';
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
import { CommunicationIntelligenceEngine } from './recon/CommunicationIntelligenceEngine';
import { SubdomainIntelligenceEngine } from './recon/SubdomainIntelligenceEngine';
import { ArtifactIntelligenceEngine } from './recon/ArtifactIntelligenceEngine';
import { ParameterIntelligenceEngine } from './recon/ParameterIntelligenceEngine';
import { AIFingerprintEngine } from './recon/AIFingerprintEngine';
import { CorrelationEngine } from './recon/CorrelationEngine';
import axios from 'axios';

// Nuevos Motores Fase 6
import { runCrawler } from './scanner/crawler';
import { runJsReconScan } from './scanner/jsrecon';
import { runNextJsScan } from './scanner/nextjs';
import { runCloudExposureScan } from './scanner/cloud';
import { runWebSocketsScan } from './scanner/websockets';
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
    
    // --- FASE 1: RECONOCIMIENTO INTELIGENTE ---
    console.log(`[Scan ${scanId}] Ejecutando Inteligencia de Superficie de Ataque...`);
    
    // 1. Perfil del Tech Stack
    const techStack = await runTechStackProfiler(targetUrl);
    
    // 2. Framework Intelligence basado en el Stack
    const frameworkIntelligence = runFrameworkIntelligence(techStack);
    
    const domain = new URL(targetUrl).hostname;

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
      runWebSocketsScan(scanId, targetUrl),
      runUploadsScan(scanId, targetUrl)
    ];

    // JS Recon ahora retorna los endpoints encontrados
    const [jsEndpoints] = await Promise.all([
      runJsReconScan(scanId, targetUrl),
      ...passiveTasks
    ]);

    let urlsToAttack = [targetUrl];
    let jsFilesFromCrawler: string[] = [];
    if (mode === 'aggressive') {
      const crawlerData = await runCrawler(scanId, targetUrl);
      urlsToAttack = Array.from(new Set([...urlsToAttack, ...crawlerData.endpoints]));
      jsFilesFromCrawler = crawlerData.jsFiles;
    }

    // Unir endpoints JS y Crawler
    const allDiscoveredPaths = Array.from(new Set([...jsEndpoints, ...urlsToAttack.map(u => {
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
      baseHeaders = resp.headers;
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
    const parameterIntelligence = ParameterIntelligenceEngine.analyze(attackSurface);
    const aiIntelligence = AIFingerprintEngine.analyze(jsCodes, baseHeaders);

    // 3. Reconstrucción de Arquitectura Avanzada (Módulo 1)
    const architectureTree = buildArchitectureTree(domain, techStack, attackSurface, businessDictionary);

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

    // 5. Guardar Perfil de Reconocimiento
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
      aiIntelligence,
      auditReport
    });

    console.log(`[Scan ${scanId}] Análisis Pasivo y Reconocimiento completado. Guardado Perfil Tech Stack.`);

    // --- FASE 2: ATAQUE ACTIVO / AGRESIVO ---
    if (mode === 'active' || mode === 'aggressive') {
      if (mode === 'aggressive') {
        console.log(`[Scan ${scanId}] ⏸️ Escaneo Agresivo pausado esperando confirmación manual para explotar toda la superficie.`);
        await db.update(scans).set({ status: 'paused_for_approval' }).where(eq(scans.id, scanId));
        return; // Terminamos la ejecución por ahora. Se reanudará desde /api/scan/resume
      }

      console.log(`[Scan ${scanId}] ⚠️ ADVERTENCIA: Ejecutando suite de Ataque (${mode}) sobre TODA la superficie descubierta (${urlsToAttack.length} endpoints base)...`);

      // Ampliar la lista de ataques con los descubiertos en JS si son URLs completas
      const endpointsToAttack = Array.from(new Set([
        ...urlsToAttack,
        ...jsEndpoints.map(p => p.startsWith('http') ? p : `${new URL(targetUrl).origin}${p.startsWith('/') ? p : '/' + p}`)
      ]));

      const activeTaskFactories: (() => Promise<void>)[] = [];

      for (const url of endpointsToAttack) {
        // Ataques comunes a todas las URLs descubiertas
        activeTaskFactories.push(
          () => runSqliScan(scanId, url),
          () => runXssScan(scanId, url),
          () => runCorsScan(scanId, url),
          () => runGraphqlScan(scanId, url),
          () => runSourceMapScan(scanId, url),
          () => runApiDiscoveryScan(scanId, url),
          () => runSecretsScan(scanId, url),
          () => runJwtScan(scanId, url),
          () => runTraversalScan(scanId, url),
          () => runPollutionScan(scanId, url)
        );
      }

      // El Rate Limit lo corremos solo 1 vez a la URL principal para no saturar la red local
      const rateLimitTask = () => runRateLimitScan(scanId, targetUrl);

      // Helper para ejecutar tareas con concurrencia controlada y "Jitter" (retraso aleatorio)
      const runWithConcurrency = async (tasks: (() => Promise<void>)[], limit: number) => {
        const executing: Promise<void>[] = [];
        for (const task of tasks) {
          const jitterTask = async () => {
            // Retraso aleatorio (Jitter) entre 200ms y 600ms para parecer humano
            await new Promise(resolve => setTimeout(resolve, 200 + Math.random() * 400));
            await task();
          };
          
          const p = jitterTask().then(() => {
            executing.splice(executing.indexOf(p), 1);
          });
          executing.push(p);
          if (executing.length >= limit) {
            await Promise.race(executing);
          }
        }
        await Promise.all(executing);
      };

      // Limitar a 5 peticiones simultáneas
      await runWithConcurrency([rateLimitTask, ...activeTaskFactories], 5);
    }

    await db.update(scans).set({ 
      status: 'completed', 
      completedAt: new Date() 
    }).where(eq(scans.id, scanId));
    console.log(`[Scan ${scanId}] 🎉 Todos los motores finalizaron exitosamente.`);

  } catch (error: any) {
    console.error(`[Scan ${scanId}] Error global de orquestación:`, error);
    await db.update(scans).set({ 
      status: 'failed', 
      completedAt: new Date() 
    }).where(eq(scans.id, scanId));
  }
});

import { runSastScan } from './sast';
import { vulnerabilities } from './db/schema';

app.post('/api/scan/resume', async (req, res) => {
  const { scanId, targetUrl, decision } = req.body;

  if (!scanId || !targetUrl || !decision) {
    return res.status(400).json({ error: 'Falta scanId, targetUrl o decision' });
  }

  res.json({ message: 'Resumiendo escaneo', scanId });

  try {
    if (decision === 'skip') {
      console.log(`[Scan ${scanId}] ⏭️ Fase ofensiva masiva omitida por el usuario.`);
      await db.update(scans).set({ 
        status: 'completed', 
        completedAt: new Date() 
      }).where(eq(scans.id, scanId));
      return;
    }

    await db.update(scans).set({ status: 'in_progress' }).where(eq(scans.id, scanId));
    console.log(`[Scan ${scanId}] 🔫 Reanudando escaneo Agresivo Masivo aprobado por el usuario...`);

    const [profile] = await db.select().from(reconProfiles).where(eq(reconProfiles.scanId, scanId));
    if (!profile) throw new Error("No recon profile found to resume");

    const attackSurface = profile.attackSurface as any[];
    const endpointsToAttack = Array.from(new Set([
      targetUrl,
      ...attackSurface.map(ep => ep.path.startsWith('http') ? ep.path : `${new URL(targetUrl).origin}${ep.path.startsWith('/') ? ep.path : '/' + ep.path}`)
    ]));

    console.log(`[Scan ${scanId}] ⚠️ ADVERTENCIA: Ejecutando suite de Ataque (aggressive) sobre TODA la superficie descubierta (${endpointsToAttack.length} endpoints)...`);

    const activeTaskFactories: (() => Promise<void>)[] = [];

    for (const url of endpointsToAttack) {
      activeTaskFactories.push(
        () => runSqliScan(scanId, url),
        () => runXssScan(scanId, url),
        () => runCorsScan(scanId, url),
        () => runGraphqlScan(scanId, url),
        () => runSourceMapScan(scanId, url),
        () => runApiDiscoveryScan(scanId, url),
        () => runSecretsScan(scanId, url),
        () => runJwtScan(scanId, url),
        () => runTraversalScan(scanId, url),
        () => runPollutionScan(scanId, url),
        () => runBolaScan(scanId, url),
        () => runSsrfScan(scanId, url),
        () => runRedirectScan(scanId, url),
        () => runServerActionsScan(scanId, url)
      );
    }

    const rateLimitTask = () => runRateLimitScan(scanId, targetUrl);

    const runWithConcurrency = async (tasks: (() => Promise<void>)[], limit: number) => {
      const executing: Promise<void>[] = [];
      for (const task of tasks) {
        const jitterTask = async () => {
          await new Promise(resolve => setTimeout(resolve, 200 + Math.random() * 400));
          await task();
        };
        const p = jitterTask().then(() => {
          executing.splice(executing.indexOf(p), 1);
        });
        executing.push(p);
        if (executing.length >= limit) await Promise.race(executing);
      }
      await Promise.all(executing);
    };

    await runWithConcurrency([rateLimitTask, ...activeTaskFactories], 5);

    await db.update(scans).set({ 
      status: 'completed', 
      completedAt: new Date() 
    }).where(eq(scans.id, scanId));
    console.log(`[Scan ${scanId}] 🎉 Escaneo Agresivo Masivo finalizado exitosamente.`);

  } catch (error: any) {
    console.error(`[Scan ${scanId}] Error global al reanudar:`, error);
    await db.update(scans).set({ 
      status: 'failed', 
      completedAt: new Date() 
    }).where(eq(scans.id, scanId));
  }
});

app.post('/api/sast', async (req, res) => {
  const { targetDir, scanId } = req.body;

  if (!targetDir || !scanId) {
    return res.status(400).json({ error: 'Falta targetDir o scanId' });
  }

  res.json({ message: 'Escaneo SAST iniciado', scanId });

  try {
    await db.update(scans).set({ status: 'in_progress' }).where(eq(scans.id, scanId));
    console.log(`\n[Scan ${scanId}] Iniciando motor SAST (Whitebox) en directorio: ${targetDir}...`);
    
    const findings = await runSastScan(targetDir);
    
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

  res.json({ message: 'Ataque dirigido iniciado', scanId, vectorId });

  try {
    await db.update(scans).set({ status: 'in_progress', mode: 'targeted' }).where(eq(scans.id, scanId));
    
    // Execute just the single vector attack
    await runTargetedAttack(scanId, targetUrl, vectorId, parentId);

    await db.update(scans).set({ 
      status: 'completed', 
      completedAt: new Date() 
    }).where(eq(scans.id, scanId));
  } catch (error: any) {
    console.error(`[Scan ${scanId}] Error en ataque dirigido:`, error);
    await db.update(scans).set({ 
      status: 'failed', 
      completedAt: new Date() 
    }).where(eq(scans.id, scanId));
  }
});

const PORT = 4000;
app.listen(PORT, () => {
  console.log(`🚀 FixGuard OSINT Worker ejecutándose en http://localhost:${PORT}`);
});
