import { runCliCommand } from './scanner/cliRunner';
import { VECTOR_REGISTRY } from './recon/FrameworkIntelligence';
import { IssueManager } from './scanner/IssueManager';
import { SessionManager } from './scanner/SessionManager';
import { db } from './db/db';
import { reconProfiles, findings } from './db/schema';
import { eq } from 'drizzle-orm';
import { PipelineSelector } from './scanner/logic/PipelineSelector';
import type { NormalizedReconProfile } from './db/schema';
import { ActiveExploitationEngine } from './scanner/logic/ActiveExploitationEngine';
import fs from 'fs';

// Helper to parse the output and determine severity/findings
function parseCliOutput(command: string, output: string): { severity: 'low' | 'medium' | 'high' | 'critical', finding: string, metadata?: any } | null {
  const lowerOut = output.toLowerCase();
  
  if (command.includes('nuclei')) {
    if (lowerOut.includes('[critical]')) return { severity: 'critical', finding: 'Nuclei detectó una vulnerabilidad CRÍTICA.' };
    if (lowerOut.includes('[high]')) return { severity: 'high', finding: 'Nuclei detectó una vulnerabilidad ALTA.' };
    if (lowerOut.includes('[medium]')) return { severity: 'medium', finding: 'Nuclei detectó una vulnerabilidad MEDIA.' };
    if (lowerOut.includes('[low]')) return { severity: 'low', finding: 'Nuclei detectó una vulnerabilidad BAJA.' };
    return null;
  }
  
  if (command.includes('sqlmap')) {
    if (lowerOut.includes('is vulnerable') || lowerOut.includes('payload:')) {
      return { severity: 'critical', finding: 'SQLMap confirmó inyección SQL en los parámetros analizados.' };
    }
    return null;
  }

  if (command.includes('wpscan')) {
    if (lowerOut.includes('[!]')) {
      return { severity: 'high', finding: 'WPScan detectó vulnerabilidades conocidas o configuraciones expuestas en WordPress.' };
    }
    return null;
  }

  if (command.includes('nmap')) {
    if (lowerOut.includes('open')) {
      return { severity: 'medium', finding: 'Nmap descubrió puertos abiertos en el servidor.' };
    }
    return null;
  }

  if (command.includes('dalfox')) {
    // Dalfox v3 outputs. We must be careful to avoid matching "XSS found 0 XSS"
    // To be safe we look for "[poc]" or a regex match for XSS found with a number > 0.
    const xssFoundMatch = lowerOut.match(/xss found ([1-9][0-9]*) xss/);
    if (
      lowerOut.includes('[poc]') ||
      xssFoundMatch !== null ||
      lowerOut.includes('issue: xss')
    ) {
      return { severity: 'high', finding: 'Cross-Site Scripting (XSS) detectado y validado en el DOM/Reflected.' };
    }
    return null;
  }

  if (command.includes('xsstrike')) {
    if (lowerOut.includes('vulnerable') || lowerOut.includes('payload:')) {
      return { severity: 'high', finding: 'Cross-Site Scripting (XSS) detectado y validado en el DOM/Reflected.' };
    }
    return null;
  }

  if (command.includes('katana') || command.includes('gau') || command.includes('subfinder')) {
    const lines = output.trim().split('\n').filter(l => l.length > 0);
    const discoveredUrls: string[] = [];
    const vulnerableParameters: string[] = [];

    const urlRegex = /(https?:\/\/[^\s]+)/g;
    for (const line of lines) {
      const match = line.match(urlRegex);
      if (match) {
        const url = match[0];
        discoveredUrls.push(url);
        if (url.includes('?') || url.includes('=')) {
          vulnerableParameters.push(url);
        }
      } else if (line.includes('.') && !line.includes(' ')) {
        // Fallback for tools like subfinder which might output domains without http
        discoveredUrls.push(line);
      }
    }

    if (discoveredUrls.length > 0) {
      return { 
        severity: vulnerableParameters.length > 0 ? 'medium' : 'low', 
        finding: `Se descubrieron ${discoveredUrls.length} endpoints / subdominios en la superficie del objetivo. (${vulnerableParameters.length} de ellos contienen parámetros analizables).`,
        metadata: {
          discovered_urls: discoveredUrls,
          vulnerable_parameters: vulnerableParameters
        }
      };
    }
    return null;
  }
  
  if (command.includes('ffuf')) {
    // Si la salida es la pantalla de ayuda (faltan argumentos), ignorar
    if (output.includes('HTTP OPTIONS:') || output.includes('GENERAL OPTIONS:')) {
      return null;
    }

    const cleanOutput = output.replace(/Fuzz Faster U Fool.*/gi, '').trim();
    const lines = cleanOutput.split('\n').filter(line => {
      const trimmed = line.trim();
      return trimmed.length > 0 && 
             !trimmed.includes('::') && 
             !trimmed.toLowerCase().includes('calibration') &&
             !trimmed.toLowerCase().includes('warning') &&
             !trimmed.toLowerCase().includes('job') &&
             !trimmed.toLowerCase().includes('duration') &&
             !trimmed.toLowerCase().includes('req/sec') &&
             !trimmed.toLowerCase().includes('errors');
    });
    if (lines.length > 0) {
      return { severity: 'medium', finding: `ffuf descubrió ${lines.length} rutas/directorios accesibles: ${lines.slice(0, 3).join(', ')}` };
    }
    return null;
  }

  if (command.includes('curl') || command.includes('grep')) {
    // Parse HTTP response intelligently
    const statusMatch = output.match(/HTTP\/[12\.]+\s+(\d{3})/);
    const statusCode = statusMatch ? parseInt(statusMatch[1]) : 0;
    const body = output.split('\r\n\r\n').slice(1).join('\n').trim() ||
                 output.split('\n\n').slice(1).join('\n').trim();
    
    // 401/403 = Correctly protected → NOT a vulnerability
    if (statusCode === 401 || statusCode === 403) {
      return null;
    }
    
    // 405 Method Not Allowed → NOT a vulnerability for our purposes
    if (statusCode === 405) {
      return null;
    }

    // 400 → Rejected input → NOT a mass assignment success
    if (statusCode === 400) {
      return null;
    }

    // 302 redirect to login → Protected endpoint, NOT vulnerable
    const locationHeader = (output.match(/location:\s*(.+)/i) || [])[1] || '';
    if (statusCode === 302 && (locationHeader.includes('login') || locationHeader.includes('signin') || locationHeader.includes('auth'))) {
      return null;
    }
    
    // 302 to a non-login page → Potential open redirect
    if (statusCode === 302 && locationHeader && !locationHeader.includes('login')) {
      return { severity: 'medium', finding: `Redirección 302 a: ${locationHeader.trim()} — Posible Open Redirect o bypass de flujo.` };
    }

    // 200 with sensitive data in body
    if (statusCode === 200 && body.length > 2) {
      // Empty JSON {} or [] — endpoint exists but returns no data (OK)
      if (body === '{}' || body === '[]' || body === 'null') {
        // Still, if it's an unauthenticated endpoint that SHOULD require auth, flag it low
        if (command.includes('/api/') && !command.includes('/auth/')) {
          return { severity: 'low', finding: `Endpoint de API responde 200 sin autenticación con cuerpo vacío.` };
        }
        return null;
      }
      
      const lowerBody = body.toLowerCase();

      // Sensitive field detection in JSON
      const sensitivePatterns = [
        { rx: /"(password|passwd|secret|api_key|apikey|token|private_key)"\s*:/i, msg: 'Campo sensible expuesto en respuesta JSON' },
        { rx: /"(email|phone|address|credit_card|ssn)"\s*:/i, msg: 'Datos personales expuestos sin autenticación' },
        { rx: /"(admin|role|permissions|is_admin|isAdmin)"\s*:/i, msg: 'Campo de privilegios expuesto — posible Mass Assignment o BOLA' },
        { rx: /"id"\s*:\s*\d+/i, msg: 'ID numérico de objeto expuesto — verificar si es enumerable (BOLA)' },
      ];

      for (const { rx, msg } of sensitivePatterns) {
        if (rx.test(body)) {
          return { severity: 'high', finding: `${msg}. Respuesta: ${body.substring(0, 200)}` };
        }
      }

      // Auth providers list exposed — info disclosure
      if (lowerBody.includes('signinurl') || lowerBody.includes('callbackurl')) {
        return { severity: 'low', finding: `Auth providers expuestos sin autenticación: ${body.substring(0, 300)}` };
      }

      // CSRF token exposed
      if (lowerBody.includes('csrftoken')) {
        return { severity: 'medium', finding: `CSRF token expuesto sin autenticación. Token: ${body.substring(0, 150)}` };
      }

      // Generic 200 with meaningful JSON body on /api/ routes
      if (command.includes('/api/') && body.startsWith('{') && body.length > 10) {
        return { severity: 'low', finding: `Endpoint de API responde 200 sin autenticación. Respuesta: ${body.substring(0, 200)}` };
      }
    }

    return null;
  }
  
  return null;
}

export async function previewTargetedAttack(scanId: number, targetUrl: string, vectorId: string): Promise<string> {
  const cleanTargetUrl = targetUrl.replace(/\/+$/, '');
  
  let vector = VECTOR_REGISTRY[vectorId];
  if (!vector) {
    if (vectorId.startsWith('bola_')) {
      vector = { id: vectorId, name: 'BOLA Attack', cliCommand: `curl -i -s -k -X GET <TARGET>` };
    } else if (vectorId.startsWith('mass_assignment_')) {
      vector = { id: vectorId, name: 'Mass Assignment Attack', cliCommand: `curl -i -s -k -X POST -H "Content-Type: application/json" -d '{"role":"admin","isAdmin":true}' <TARGET>` };
    }
  }
  if (!vector || !vector.cliCommand) {
    throw new Error(`Vector ID ${vectorId} no encontrado en el registro o sin comando CLI.`);
  }
  
  // Obtener flags de autenticación
  const authFlags = await SessionManager.getCliAuthFlags(cleanTargetUrl, vector.cliCommand);
  let finalCommand = vector.cliCommand.replace('<TARGET>', cleanTargetUrl);
  
  if (authFlags) {
    finalCommand = `${finalCommand} ${authFlags}`;
  }

  // Pipeline Selector
  const profileRow = await db.select().from(reconProfiles).where(eq(reconProfiles.scanId, scanId)).limit(1).then(res => res[0]);
  
  if (profileRow && profileRow.normalizedData) {
     const reconData = profileRow.normalizedData as NormalizedReconProfile;
     const decision = PipelineSelector.selectPipeline(reconData, [{id: vectorId, command: finalCommand}]);
     
     if (decision.disabledModules.includes(vectorId)) {
        return `[BLOCKED] Pipeline Selector deshabilitó este vector para el stack actual.`;
     }

     const mutatedVector = decision.mutatedVectors.find(v => v.id === vectorId);
     if (mutatedVector) {
        finalCommand = mutatedVector.mutatedCommand;
     }
  }

  // Context Bridge: Parámetros SQLMap
  if (finalCommand.includes('sqlmap')) {
    const discoveryFindings = await db.select().from(findings).where(eq(findings.scanId, scanId));
    const discoveredParams = discoveryFindings
      .map(f => f.endpoint || '')
      .filter(url => url.includes('?'))
      .map(url => new URL(url).searchParams.keys())
      .flatMap(keys => Array.from(keys));
      
    const uniqueParams = [...new Set(discoveredParams)];
    
    if (uniqueParams.length > 0) {
      finalCommand += ` -p "${uniqueParams.join(',')}"`;
    }
  }

  return finalCommand;
}

export async function runTargetedAttack(scanId: number, userId: number, targetUrl: string, vectorId: string, parentId?: number): Promise<string> {
  console.log(`[Scan ${scanId}] Iniciando ataque dirigido REAL [${vectorId}] contra ${targetUrl}`);

  try {
    const cleanTargetUrl = targetUrl.replace(/\/+$/, '');
    const hostname = (() => { try { return new URL(cleanTargetUrl).hostname; } catch { return cleanTargetUrl; } })();
    
    let vector = VECTOR_REGISTRY[vectorId];
    if (!vector) {
      if (vectorId.startsWith('bola_')) {
        vector = { id: vectorId, name: 'BOLA Attack', cliCommand: `curl -i -s -k -X GET <TARGET>` };
      } else if (vectorId.startsWith('mass_assignment_')) {
        vector = { id: vectorId, name: 'Mass Assignment Attack', cliCommand: `curl -i -s -k -X POST -H "Content-Type: application/json" -d '{"role":"admin","isAdmin":true}' <TARGET>` };
      } else if (vectorId.startsWith('workflow_bypass_')) {
        // Inline command: try direct access to the last step endpoint bypassing intermediate auth steps
        vector = { id: vectorId, name: 'Business Logic Bypass', cliCommand: `curl -i -s -k -X POST -H "Content-Type: application/json" -d '{}' <TARGET>` };
      }
    }
    if (!vector || !vector.cliCommand) {
      throw new Error(`Vector ID ${vectorId} no encontrado en el registro o sin comando CLI.`);
    }
    
    // Obtener flags de autenticación
    const authFlags = await SessionManager.getCliAuthFlags(cleanTargetUrl, vector.cliCommand);
    // Replace both <TARGET> (full URL) and <HOSTNAME> (hostname only)
    let finalCommand = vector.cliCommand
      .replace(/<TARGET>/g, cleanTargetUrl)
      .replace(/<HOSTNAME>/g, hostname);
    
    if (authFlags) {
      finalCommand = `${finalCommand} ${authFlags}`;
    }

    // Context Bridge: Pipeline Selector
    // 1. Fetch normalized recon profile for this scan
    const profileRow = await db.select().from(reconProfiles).where(eq(reconProfiles.scanId, scanId)).limit(1).then(res => res[0]);
    
    if (profileRow && profileRow.normalizedData) {
       const reconData = profileRow.normalizedData as NormalizedReconProfile;
       const decision = PipelineSelector.selectPipeline(reconData, [{id: vectorId, command: finalCommand}]);
       
       if (decision.disabledModules.includes(vectorId)) {
          console.log(`[Scan ${scanId}] 🛡️ Pipeline Selector abortó la ejecución de ${vectorId} porque la tecnología subyacente no coincide.`);
          return `🛑 Ataque cancelado preventivamente por el Pipeline Inteligente.`;
       }

       const mutatedVector = decision.mutatedVectors.find(v => v.id === vectorId);
       if (mutatedVector) {
          finalCommand = mutatedVector.mutatedCommand;
          if (mutatedVector.tamperApplied) {
             console.log(`[Scan ${scanId}] 🕵️ WAF Evasion actived: Tampers applied: ${mutatedVector.tamperNames.join(', ')}`);
          }
       }
    } else {
       console.log(`[Scan ${scanId}] ⚠️ No NormalizedReconProfile found. Falling back to default command.`);
    }

    // Context Bridge: Extraer params de los findings previos de discovery para alimentar sqlmap
    if (finalCommand.includes('sqlmap')) {
      const discoveryFindings = await db.select().from(findings).where(eq(findings.scanId, scanId));
      const discoveredParams = discoveryFindings
        .map(f => f.endpoint || '')
        .filter(url => url.includes('?'))
        .map(url => new URL(url).searchParams.keys())
        .flatMap(keys => Array.from(keys));
        
      const uniqueParams = [...new Set(discoveredParams)];
      
      if (uniqueParams.length > 0) {
        finalCommand += ` -p "${uniqueParams.join(',')}"`;
        console.log(`[Context Bridge] Inyectando parámetros vulnerables a sqlmap: ${uniqueParams.join(', ')}`);
      }
    }

    console.log(`[Scan ${scanId}] ⚙️ Ejecutando herramienta profesional CLI mediante ActiveExploitationEngine: ${finalCommand}`);
    
    // Run the actual CLI tool using the secure active engine
    const output = await ActiveExploitationEngine.executeAuthorized(scanId, userId, cleanTargetUrl, finalCommand);
    
    console.log(`[Scan ${scanId}] 📄 Output recibido (Longitud: ${output.length} bytes)`);

    // Parse output for vulnerabilities
    const result = parseCliOutput(vector.cliCommand, output);

    // FFUF and Nuclei JSON Parsing & Cleanup
    try {
      if (finalCommand.includes('ffuf')) {
        const ffufFile = `/tmp/ffuf_${scanId}.json`;
        if (fs.existsSync(ffufFile)) {
          const content = fs.readFileSync(ffufFile, 'utf8');
          const data = JSON.parse(content);
          if (data.results && Array.isArray(data.results)) {
             for (const res of data.results) {
               if (res.status && res.status !== 404) {
                 await IssueManager.reportFinding({
                   scanId: parentId ?? scanId,
                   title: 'Ruta descubierta por FFUF',
                   severity: 'low',
                   endpoint: res.url,
                   method: 'GET',
                   payloadUsed: `Fuzzing de rutas`,
                   toolSource: 'ffuf'
                 });
                 // Inject into endpoint catalog directly so it shows up in UI
                 result!.metadata = result!.metadata || {};
                 result!.metadata.discovered_urls = result!.metadata.discovered_urls || [];
                 result!.metadata.discovered_urls.push(res.url);
               }
             }
          }
          fs.unlinkSync(ffufFile);
        }
      }

      if (finalCommand.includes('nuclei')) {
        const nucleiFile = `/tmp/nuclei_${scanId}.json`;
        if (fs.existsSync(nucleiFile)) {
          const content = fs.readFileSync(nucleiFile, 'utf8');
          const lines = content.split('\n').filter(l => l.trim().length > 0);
          for (const line of lines) {
             try {
                const data = JSON.parse(line);
                if (data.info) {
                  await IssueManager.reportFinding({
                    scanId: parentId ?? scanId,
                    title: data.info.name || 'Hallazgo de Nuclei',
                    severity: data.info.severity || 'info',
                    endpoint: data['matched-at'] || targetUrl,
                    method: 'GET',
                    payloadUsed: data.type || 'nuclei-template',
                    toolSource: 'nuclei'
                  });
                }
             } catch(e) {}
          }
          fs.unlinkSync(nucleiFile);
        }
      }
    } catch(err: any) {
      console.warn(`[Scan ${scanId}] Error procesando archivos JSON de FFUF/Nuclei:`, err.message);
    }

    if (result) {
      console.log(`[Scan ${scanId}] 🚨 VULNERABILIDAD CONFIRMADA: ${result.severity.toUpperCase()}`);
      
      // Save finding under the PARENT scan ID so it appears directly in the Recon
      // vulnerability list without needing child-scan lookup traversal.
      const newFinding = await IssueManager.reportFinding({
        scanId: parentId ?? scanId,
        title: result.finding,
        severity: result.severity,
        endpoint: targetUrl,
        method: 'GET',
        payloadUsed: vector.cliCommand,
        toolSource: vector.id
      });

      // ─── Lógica de Correlación Inteligente (Dalfox -> XSStrike) ─────────
      if (vectorId === 'dalfox' || vectorId === 'xss_dalfox') {
         if (newFinding && newFinding.detectedBy && newFinding.detectedBy.length === 1 && newFinding.detectedBy[0] === vector.id) {
             console.log(`[Correlation Engine] Inyectando confirmación secundaria con XSStrike para el hallazgo en: ${targetUrl}`);
             // Encolamos o ejecutamos XSStrike automáticamente de forma asíncrona pero sin bloquear la UI
             // Lo haremos directamente llamando a runTargetedAttack de forma recursiva
             setTimeout(() => {
                 runTargetedAttack(scanId, userId, targetUrl, 'xss_xsstrike', parentId).catch(err => {
                    console.error(`[Correlation Engine] Error ejecutando XSStrike de confirmación: ${err.message}`);
                 });
             }, 1000);
         } else if (newFinding && newFinding.detectedBy && newFinding.detectedBy.length >= 2) {
             console.log(`[Correlation Engine] Hallazgo XSS ya confirmado previamente. No se encola XSStrike para evitar loops.`);
         }
      }
      // ─────────────────────────────────────────────────────────────────────

      // ─── Endpoint Catalog enrichment ─────────────────────────────────────
      // If the tool discovered URLs (GAU, katana, subfinder), inject them
      // into the parent scan's attackSurface so the Endpoint Catalog updates.
      if (result.metadata?.discovered_urls && result.metadata.discovered_urls.length > 0 && (parentId ?? scanId)) {
        const targetScanId = parentId ?? scanId;
        const toolName = finalCommand.split(' ')[0];
        try {
          const profileRows = await db.select().from(reconProfiles)
            .where(eq(reconProfiles.scanId, targetScanId)).limit(1);
          
          if (profileRows[0]) {
            const currentSurface = (profileRows[0].attackSurface as any[]) ?? [];
            const existingPaths = new Set(currentSurface.map((e: any) => e.path));

            const newEndpoints = (result.metadata.discovered_urls as string[])
              .filter((url: string) => url.startsWith('http'))
              .slice(0, 300) // cap to avoid DB bloat
              .map((url: string) => {
                try {
                  const parsed = new URL(url);
                  const hasParams = parsed.search.length > 1;
                  const params = Array.from(parsed.searchParams.keys());
                  return {
                    path: parsed.pathname + parsed.search,
                    method: 'GET',
                    riskLevel: hasParams ? 'ALTO' : 'MEDIO',
                    type: `Discovered (${toolName})`,
                    params,
                    source: toolName
                  };
                } catch { return null; }
              })
              .filter((e: any) => e !== null && !existingPaths.has(e.path));

            if (newEndpoints.length > 0) {
              await db.update(reconProfiles)
                .set({ attackSurface: [...currentSurface, ...newEndpoints] })
                .where(eq(reconProfiles.scanId, targetScanId));
              console.log(`[Scan ${scanId}] 🗺️ Endpoint Catalog enriquecido: +${newEndpoints.length} rutas de ${toolName}`);
            }
          }
        } catch (enrichErr: any) {
          console.warn(`[Scan ${scanId}] ⚠️ No se pudo enriquecer el Endpoint Catalog:`, enrichErr.message);
        }
      }
      // ─────────────────────────────────────────────────────────────────────

      return `🚨 VULNERABILIDAD [${result.severity.toUpperCase()}] DETECTADA\n\nEndpoint: ${targetUrl}\nHerramienta: ${finalCommand.split(' ')[0]}\n\n--- Respuesta del servidor ---\n${output.substring(0, 2000)}\n\nVeredicto: ${result.finding}`;
    } else {
      console.log(`[Scan ${scanId}] ✅ El objetivo parece estar seguro contra este vector (Ninguna coincidencia crítica en la salida de la herramienta).`);
      return `✅ Sin vulnerabilidad detectada para este vector\n\nEndpoint: ${targetUrl}\nHerramienta: ${finalCommand.split(' ')[0]}\n\n--- Respuesta del servidor ---\n${output.substring(0, 2000)}`;
    }

    console.log(`[Scan ${scanId}] Ataque dirigido [${vectorId}] completado exitosamente.`);
    return `⚠️ Ataque completado sin resultado analizable.\nEndpoint: ${targetUrl}`;
  } catch (error: any) {
    console.error(`[Scan ${scanId}] Error en ataque dirigido [${vectorId}]: ${error.message}`);
    return `❌ Error ejecutando el ataque: ${error.message}`;
    // Opcionalmente podemos registrar el fallo como un log, pero no romper la app
  }
}

