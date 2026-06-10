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

import { db } from './db/db';
import { scans } from './db/schema';
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
    
    // Nivel 1: Tareas Base (Pasivas / OSINT)
    const passiveTasks = [
      runHeaderScan(scanId, targetUrl),
      runTlsScan(scanId, targetUrl),
      runDnsScan(scanId, targetUrl),
      runPortScan(scanId, targetUrl),
      runDirectoryScan(scanId, targetUrl),
      runWafScan(scanId, targetUrl),
      runFingerprintScan(scanId, targetUrl),
      runSecurityTxtScan(scanId, targetUrl),
      // Reconocimiento Moderno
      runJsReconScan(scanId, targetUrl),
      runNextJsScan(scanId, targetUrl),
      runCloudExposureScan(scanId, targetUrl),
      runWebSocketsScan(scanId, targetUrl),
      runUploadsScan(scanId, targetUrl)
    ];

    await Promise.all(passiveTasks);
    console.log(`[Scan ${scanId}] Análisis Pasivo/OSINT completado.`);

    // Nivel 2 y 3: Tareas Activas / Agresivas
    if (mode === 'active' || mode === 'aggressive') {
      console.log(`[Scan ${scanId}] ⚠️ ADVERTENCIA: Ejecutando suite de Ataque (${mode})...`);
      
      let urlsToAttack = [targetUrl];

      // En modo agresivo, usamos el Crawler Inteligente para encontrar más rutas
      if (mode === 'aggressive') {
        urlsToAttack = await runCrawler(scanId, targetUrl);
      }

      const activeTasks: Promise<void>[] = [];

      for (const url of urlsToAttack) {
        // Ataques comunes a todas las URLs descubiertas
        activeTasks.push(
          runSqliScan(scanId, url),
          runXssScan(scanId, url),
          runCorsScan(scanId, url),
          runGraphqlScan(scanId, url),
          runSourceMapScan(scanId, url),
          runApiDiscoveryScan(scanId, url),
          runSecretsScan(scanId, url),
          runJwtScan(scanId, url),
          runTraversalScan(scanId, url),
          runPollutionScan(scanId, url)
        );

        // Ataques extremos solo en agresivo
        if (mode === 'aggressive') {
           activeTasks.push(
             runBolaScan(scanId, url),
             runSsrfScan(scanId, url),
             runRedirectScan(scanId, url)
           );
        }
      }

      // El Rate Limit lo corremos solo 1 vez a la URL principal para no saturar la red local
      activeTasks.push(runRateLimitScan(scanId, targetUrl));

      await Promise.all(activeTasks);
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

const PORT = 4000;
app.listen(PORT, () => {
  console.log(`🚀 FixGuard OSINT Worker ejecutándose en http://localhost:${PORT}`);
});
