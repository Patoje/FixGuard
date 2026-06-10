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

    console.log(`[Scan ${scanId}] Iniciando motores de escaneo (${mode || 'passive'}) para ${targetUrl}...`);
    
    // Tareas Base (Pasivas)
    const scanTasks = [
      runHeaderScan(scanId, targetUrl),
      runTlsScan(scanId, targetUrl),
      runDnsScan(scanId, targetUrl),
      runPortScan(scanId, targetUrl),
      runDirectoryScan(scanId, targetUrl),
      runWafScan(scanId, targetUrl),
      runFingerprintScan(scanId, targetUrl),
      runSecurityTxtScan(scanId, targetUrl),
    ];

    // Tareas Activas (Fuzzing y Modern Web)
    if (mode === 'active') {
      console.log(`[Scan ${scanId}] ⚠️ ADVERTENCIA: Ejecutando Fuzzing Activo (SQLi / XSS / APIs)...`);
      scanTasks.push(runSqliScan(scanId, targetUrl));
      scanTasks.push(runXssScan(scanId, targetUrl));
      scanTasks.push(runCorsScan(scanId, targetUrl));
      scanTasks.push(runGraphqlScan(scanId, targetUrl));
      scanTasks.push(runSourceMapScan(scanId, targetUrl));
      scanTasks.push(runRateLimitScan(scanId, targetUrl));
      scanTasks.push(runApiDiscoveryScan(scanId, targetUrl));
      scanTasks.push(runSecretsScan(scanId, targetUrl));
      scanTasks.push(runJwtScan(scanId, targetUrl));
      scanTasks.push(runTraversalScan(scanId, targetUrl));
      scanTasks.push(runPollutionScan(scanId, targetUrl));
    }

    await Promise.all(scanTasks);

    await db.update(scans).set({ 
      status: 'completed', 
      completedAt: new Date() 
    }).where(eq(scans.id, scanId));
    console.log(`[Scan ${scanId}] Todos los motores finalizaron exitosamente.`);

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
