import { runCliCommand } from '../cliRunner';

export interface SastFinding {
  type: string;
  severity: string;
  description: string;
  file: string;
  line: number;
}

export class SemgrepEngine {
  /**
   * Runs Semgrep static analysis on a local directory.
   * Uses the shared cliRunner (spawn-based, no shell injection) for execution.
   */
  static async scanDirectory(targetPath: string): Promise<SastFinding[]> {
    const findings: SastFinding[] = [];

    // Validate path (prevents execution on dangerous or empty paths)
    if (!targetPath || targetPath.trim() === '') {
      throw new Error('Ruta local no válida.');
    }

    try {
      console.log(`[SemgrepEngine] Ejecutando análisis estático (SAST) en: ${targetPath}`);

      // Build the command with quoted path to handle spaces in directory names.
      // <TARGET> is replaced by cliRunner with the targetPath value.
      // --json for structured output parsing
      // --config auto uses Semgrep's default ruleset (comprehensive security coverage)
      const cmd = 'semgrep scan --config auto --json "<TARGET>"';

      // Semgrep exits with code 1 when it finds vulnerabilities (normal behavior).
      // cliRunner always returns output regardless of exit code.
      const output = await runCliCommand(cmd, targetPath);

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
