import { runCliCommand } from './scanner/cliRunner';
import { VECTOR_REGISTRY } from './recon/FrameworkIntelligence';
import { db } from './db/db';
import { vulnerabilities } from './db/schema';

// Helper to parse the output and determine severity/findings
function parseCliOutput(command: string, output: string): { severity: 'low' | 'medium' | 'high' | 'critical', finding: string } | null {
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
  
  if (command.includes('ffuf') || command.includes('curl') || command.includes('grep')) {
    // If we use ffuf -s (silent), it only outputs the matched paths/words.
    // However, with -ac (auto-calibrate), it might print some calibration info even in silent mode.
    // We only want to alert if it actually found a valid word from the wordlist.
    // FFuf silent output for matches is usually just the word itself.
    const cleanOutput = output.replace(/Fuzz Faster U Fool.*/gi, '').trim();
    // Filter out potential calibration warnings that might slip through
    const lines = cleanOutput.split('\n').filter(line => line.trim().length > 0 && !line.includes('::') && !line.includes('Calibration'));
    
    if (lines.length > 0) {
      return { severity: 'medium', finding: 'Se descubrieron rutas, secretos o configuraciones expuestas en el escaneo manual.' };
    }
    return null;
  }
  
  return null;
}

export async function runTargetedAttack(scanId: number, targetUrl: string, vectorId: string): Promise<void> {
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

