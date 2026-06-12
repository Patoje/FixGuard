import { execSync } from 'child_process';
import path from 'path';

export interface SastFinding {
  type: string;
  severity: string;
  description: string;
  file: string;
  line: number;
}

export class SemgrepEngine {
  /**
   * Ejecuta Semgrep en un directorio local
   */
  static async scanDirectory(targetPath: string): Promise<SastFinding[]> {
    const findings: SastFinding[] = [];

    // Validar path (previene ejecución en rutas peligrosas o vacías)
    if (!targetPath || targetPath.trim() === '') {
      throw new Error('Ruta local no válida.');
    }

    try {
      console.log(`[SemgrepEngine] Ejecutando análisis estático (SAST) en: ${targetPath}`);
      
      // --json para parsear el resultado
      // --config auto usa las reglas por defecto (muy robustas para seguridad)
      const cmd = `semgrep scan --config auto --json "${targetPath}"`;
      
      // Semgrep devuelve exit code 1 si encuentra vulnerabilidades, así que hay que atrapar el error
      let output = '';
      try {
        output = execSync(cmd, { maxBuffer: 1024 * 1024 * 50 }).toString(); // 50MB buffer
      } catch (error: any) {
        if (error.stdout) {
          output = error.stdout.toString();
        } else {
          throw new Error('Semgrep falló al ejecutarse. Revisa la consola.');
        }
      }

      const parsed = JSON.parse(output);

      if (parsed && parsed.results) {
        for (const result of parsed.results) {
          findings.push({
            type: result.check_id || 'Static Analysis Finding',
            severity: mapSeverity(result.extra?.severity || 'INFO'),
            description: result.extra?.message || 'Problema de seguridad en el código fuente.',
            file: result.path || 'Unknown file',
            line: result.start?.line || 0
          });
        }
      }
      
      console.log(`[SemgrepEngine] Se encontraron ${findings.length} vulnerabilidades estáticas.`);

    } catch (e: any) {
      console.error(`[SemgrepEngine] Error al ejecutar semgrep: ${e.message}`);
    }

    return findings;
  }
}

function mapSeverity(semgrepSeverity: string): string {
  const s = semgrepSeverity.toUpperCase();
  if (s === 'ERROR') return 'high';
  if (s === 'WARNING') return 'medium';
  if (s === 'INFO') return 'low';
  return 'low';
}
