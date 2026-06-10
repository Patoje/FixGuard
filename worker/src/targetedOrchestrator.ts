import { runSqliScan } from './scanner/sqli';
import { runXssScan } from './scanner/xss';
import { runBolaScan } from './scanner/bola';

import { runSsrfScan } from './scanner/ssrf';
import { runJsReconScan } from './scanner/jsrecon';
import { runPollutionScan } from './scanner/pollution';
import { runTraversalScan } from './scanner/traversal';

// Maps a vector ID to an orchestrator function that executes a specific attack
export async function runTargetedAttack(scanId: number, targetUrl: string, vectorId: string): Promise<void> {
  console.log(`[Scan ${scanId}] Iniciando ataque dirigido [${vectorId}] contra ${targetUrl}`);

  try {
    switch (vectorId) {
      // --- SQL INJECTION / POSTGRES ---
      case 'pg_sqli':
      case 'pg_blind_sqli':
      case 'pg_time_sqli':
        console.log(`[Scan ${scanId}] Ejecutando suite de inyección SQL especializada...`);
        await runSqliScan(scanId, targetUrl);
        break;

      // --- NODE.JS / EXPRESS ---
      case 'express_pollution':
        console.log(`[Scan ${scanId}] Ejecutando ataque de Prototype Pollution...`);
        await runPollutionScan(scanId, targetUrl);
        break;
      
      case 'express_routing':
        console.log(`[Scan ${scanId}] Ejecutando enumeración de rutas (BOLA/IDOR)...`);
        await runBolaScan(scanId, targetUrl);
        break;

      // --- NEXT.JS / REACT ---
      case 'nextjs_bfla':
      case 'nextjs_api':
        console.log(`[Scan ${scanId}] Ejecutando suite BFLA/IDOR para Server Actions y APIs...`);
        await runBolaScan(scanId, targetUrl);
        break;

      case 'nextjs_static':
      case 'nextjs_build_data':
      case 'nextjs_route_handlers':
      case 'react_sourcemaps':
        console.log(`[Scan ${scanId}] Ejecutando escáner de reconstrucción de JS y fuga de secretos...`);
        await runJsReconScan(scanId, targetUrl);
        await runTraversalScan(scanId, targetUrl);
        break;
      
      // --- CLERK / SUPABASE / AUTH ---
      case 'supabase_bucket':
      case 'supabase_edge':
      case 'supabase_rls':
      case 'supabase_anon_key':
        console.log(`[Scan ${scanId}] Iniciando ataque SSRF y Directory Traversal en infraestructura Cloud...`);
        await runSsrfScan(scanId, targetUrl);
        await runTraversalScan(scanId, targetUrl);
        break;

      case 'clerk_session':
      case 'clerk_oauth':
      case 'clerk_jwt':
        console.log(`[Scan ${scanId}] Iniciando suite de ataques XSS para secuestro de sesión y JWT...`);
        await runXssScan(scanId, targetUrl);
        break;

      default:
        console.log(`[Scan ${scanId}] Vector ${vectorId} no tiene un módulo específico asignado. Ejecutando BOLA y XSS genérico...`);
        await runBolaScan(scanId, targetUrl);
        await runXssScan(scanId, targetUrl);
        break;
    }

    console.log(`[Scan ${scanId}] Ataque dirigido [${vectorId}] completado exitosamente.`);
  } catch (error) {
    console.error(`[Scan ${scanId}] Error en ataque dirigido [${vectorId}]: ${error}`);
  }
}
