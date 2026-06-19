import { exec } from 'child_process';
import util from 'util';
import path from 'path';
import os from 'os';
import { getGoPath } from './goPathHelper';

const execPromise = util.promisify(exec);

export async function runSubfinderScan(domain: string): Promise<string[]> {
  try {
    const goPath = await getGoPath();
    console.log(`[Subfinder] Iniciando búsqueda pasiva para: ${domain}`);
    
    const command = `subfinder -d ${domain} -all -silent`;
    
    const { stdout } = await execPromise(command, {
      timeout: 300000, // 5 mins
      env: { ...process.env, PATH: `${process.env.PATH}:${goPath}` }
    });

    const subdomains = stdout.split('\n').map(s => s.trim()).filter(s => s.length > 0);
    console.log(`[Subfinder] Encontrados ${subdomains.length} subdominios.`);
    
    return subdomains;
  } catch (error: any) {
    console.error(`[Subfinder] Error ejecutando subfinder:`, error.message);
    if (error.stdout) {
       const subdomains = error.stdout.split('\n').map((s: string) => s.trim()).filter((s: string) => s.length > 0);
       return subdomains;
    }
    return [];
  }
}
