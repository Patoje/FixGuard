import { runCliCommand } from './cliRunner';

export async function runSubfinderScan(domain: string): Promise<string[]> {
  try {
    console.log(`[Subfinder] Iniciando búsqueda pasiva para: ${domain}`);

    // Use shared cliRunner (spawn-based, no shell injection)
    // subfinder matches the hostname pattern in resolveTarget, so <TARGET> becomes just the hostname
    const output = await runCliCommand('subfinder -d <TARGET> -all -silent', domain);

    const subdomains = output.split('\n').map(s => s.trim()).filter(s => s.length > 0 && !s.startsWith('['));
    console.log(`[Subfinder] Encontrados ${subdomains.length} subdominios.`);

    return subdomains;
  } catch (error: any) {
    console.error(`[Subfinder] Error ejecutando subfinder:`, error.message);
    return [];
  }
}
