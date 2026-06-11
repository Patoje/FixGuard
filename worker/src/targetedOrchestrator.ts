import { runCliCommand } from './scanner/cliRunner';
import { VECTOR_REGISTRY } from './recon/FrameworkIntelligence';
import { db } from './db/db';
import { vulnerabilities } from './db/schema';

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

  if (command.includes('xsstrike')) {
    if (lowerOut.includes('vulnerable') || lowerOut.includes('payload:')) {
      return { severity: 'high', finding: 'XSStrike encontró y validó un vector de inyección XSS.' };
    }
    return null;
  }

  if (command.includes('katana') || command.includes('waybackurls') || command.includes('subfinder')) {
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
  
  if (command.includes('ffuf') || command.includes('curl') || command.includes('grep')) {
    // If we use ffuf -s (silent), it only outputs the matched paths/words.
    // However, with -ac (auto-calibrate), it might print some calibration info even in silent mode.
    // We only want to alert if it actually found a valid word from the wordlist.
    // FFuf silent output for matches is usually just the word itself.
    const cleanOutput = output.replace(/Fuzz Faster U Fool.*/gi, '').trim();
    // Filter out potential calibration warnings that might slip through
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
      return { severity: 'medium', finding: 'Se descubrieron rutas, secretos o configuraciones expuestas en el escaneo manual.' };
    }
    return null;
  }
  
  return null;
}

export async function runTargetedAttack(scanId: number, targetUrl: string, vectorId: string, parentId?: number): Promise<void> {
  console.log(`[Scan ${scanId}] Iniciando ataque dirigido REAL [${vectorId}] contra ${targetUrl}`);

  try {
    const vector = VECTOR_REGISTRY[vectorId];
    if (!vector || !vector.cliCommand) {
      throw new Error(`Vector ID ${vectorId} no encontrado en el registro o sin comando CLI.`);
    }

    const cleanTargetUrl = targetUrl.replace(/\/+$/, '');
    console.log(`[Scan ${scanId}] ⚙️ Ejecutando herramienta profesional CLI: ${vector.cliCommand.replace('<TARGET>', cleanTargetUrl)}`);
    
    // Run the actual CLI tool using the runner
    const output = await runCliCommand(vector.cliCommand, cleanTargetUrl);
    
    console.log(`[Scan ${scanId}] 📄 Output recibido (Longitud: ${output.length} bytes)`);

    // Parse output for vulnerabilities
    const result = parseCliOutput(vector.cliCommand, output);

    if (result) {
      console.log(`[Scan ${scanId}] 🚨 VULNERABILIDAD CONFIRMADA: ${result.severity.toUpperCase()}`);
      
      // Save finding to database
      await db.insert(vulnerabilities).values({
        scanId,
        type: vector.name,
        severity: result.severity,
        description: `${result.finding}\n\nComando ejecutado: \`${vector.cliCommand}\`\n\n**Output parcial:**\n\`\`\`\n${output.substring(0, 500)}...\n\`\`\``,
        autoFixCode: null,
        metadata: result.metadata || null,
        parentId: parentId || null,
      });
    } else {
      console.log(`[Scan ${scanId}] ✅ El objetivo parece estar seguro contra este vector (Ninguna coincidencia crítica en la salida de la herramienta).`);
    }

    console.log(`[Scan ${scanId}] Ataque dirigido [${vectorId}] completado exitosamente.`);
  } catch (error: any) {
    console.error(`[Scan ${scanId}] Error en ataque dirigido [${vectorId}]: ${error.message}`);
    // Opcionalmente podemos registrar el fallo como un log, pero no romper la app
  }
}

/**
 * Execute a manual HTTP request from the Interactive Replayer (Kali Web mode).
 * Emits real-time logs simulating a Repeater tool.
 */
export async function runCustomAttackReplayer(scanId: number, targetUrl: string, method: string, headers: Record<string, string>, body: string): Promise<any> {
  console.log(`[Replayer ${scanId}] ---------------------------------------------------`);
  console.log(`[Replayer ${scanId}] ⚡ INICIANDO ATAQUE INTERACTIVO (REPEATER)`);
  console.log(`[Replayer ${scanId}] Objetivo: ${method.toUpperCase()} ${targetUrl}`);
  console.log(`[Replayer ${scanId}] Cabeceras inyectadas: ${Object.keys(headers).length}`);
  
  if (body) {
    console.log(`[Replayer ${scanId}] Payload Body (${body.length} bytes) cargado.`);
  }

  try {
    // Para simplificar la demo interactiva, usamos fetch nativo
    console.log(`[Replayer ${scanId}] ⚙️ Ejecutando petición cruda al socket...`);
    const startTime = Date.now();
    
    // Convert fetch Headers
    const reqHeaders = new Headers();
    for (const [k, v] of Object.entries(headers)) {
      reqHeaders.set(k, v);
    }
    
    // User-Agent por defecto si no existe
    if (!reqHeaders.has('User-Agent')) {
      reqHeaders.set('User-Agent', 'FixGuard-Tactical-Replayer/1.0');
    }

    const response = await fetch(targetUrl, {
      method,
      headers: reqHeaders,
      body: (method !== 'GET' && method !== 'HEAD' && body) ? body : undefined,
      // Evitamos seguir redirects automáticamente para ver la respuesta cruda del server
      redirect: 'manual' 
    });

    const elapsed = Date.now() - startTime;
    console.log(`[Replayer ${scanId}] 📩 Respuesta recibida en ${elapsed}ms`);
    console.log(`[Replayer ${scanId}] Status Code: ${response.status} ${response.statusText}`);
    
    const resHeaders: Record<string, string> = {};
    response.headers.forEach((v, k) => { resHeaders[k] = v; });
    console.log(`[Replayer ${scanId}] Server response headers: ${Object.keys(resHeaders).length} encontrados`);

    const text = await response.text();
    console.log(`[Replayer ${scanId}] Body Length: ${text.length} bytes`);
    
    if (response.status >= 500) {
      console.log(`[Replayer ${scanId}] 🚨 ALERTA: Error interno del servidor detectado (Posible vulnerabilidad)`);
    } else if (response.status === 200 && text.toLowerCase().includes('syntax error')) {
      console.log(`[Replayer ${scanId}] 🚨 ALERTA: Sintaxis de error expuesta en el cuerpo de la respuesta!`);
    }

    console.log(`[Replayer ${scanId}] ---------------------------------------------------`);

    return {
      status: response.status,
      statusText: response.statusText,
      headers: resHeaders,
      body: text,
      elapsed
    };
  } catch (error: any) {
    console.error(`[Replayer ${scanId}] ❌ Error crítico en ejecución: ${error.message}`);
    return { error: error.message };
  }
}

