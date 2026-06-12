import { execSync } from 'child_process';
import os from 'os';

interface Dependency {
  name: string;
  macInstall: string;
  winInstall: string;
  linuxInstall: string;
}

const DEPENDENCIES: Dependency[] = [
  {
    name: 'nuclei',
    macInstall: 'brew install nuclei',
    winInstall: 'choco install nuclei',
    linuxInstall: 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'
  },
  {
    name: 'dalfox',
    macInstall: 'brew install dalfox',
    winInstall: 'choco install dalfox', // o go install
    linuxInstall: 'go install github.com/hahwul/dalfox/v2@latest'
  },
  {
    name: 'gau',
    macInstall: 'brew install gau',
    winInstall: 'go install github.com/lc/gau/v2/cmd/gau@latest',
    linuxInstall: 'go install github.com/lc/gau/v2/cmd/gau@latest'
  },
  {
    name: 'sqlmap',
    macInstall: 'brew install sqlmap',
    winInstall: 'choco install sqlmap',
    linuxInstall: 'apt-get install sqlmap'
  },
  {
    name: 'nmap',
    macInstall: 'brew install nmap',
    winInstall: 'choco install nmap',
    linuxInstall: 'apt-get install nmap'
  },
  {
    name: 'semgrep',
    macInstall: 'brew install semgrep',
    winInstall: 'python -m pip install semgrep',
    linuxInstall: 'python3 -m pip install semgrep'
  }
];

export class DependencyChecker {
  static checkAll() {
    console.log('==========================================');
    console.log('   FixGuard Arsenal Readiness Checker     ');
    console.log('==========================================');

    const platform = os.platform();
    let isReady = true;

    for (const dep of DEPENDENCIES) {
      try {
        // En Windows el comando `which` puede no estar (a veces se usa `where`),
        // pero la forma más segura en Node es intentar ejecutar la herramienta con un flag de versión
        // o usar `where` en Windows y `which` en unix.
        const checkCmd = platform === 'win32' ? `where ${dep.name}` : `which ${dep.name}`;
        execSync(checkCmd, { stdio: 'ignore' });
        console.log(`[+] ${dep.name} ... OK`);
      } catch (error) {
        isReady = false;
        console.error(`[-] Falta ${dep.name}!`);
        
        let installCmd = dep.linuxInstall;
        if (platform === 'darwin') installCmd = dep.macInstall;
        if (platform === 'win32') installCmd = dep.winInstall;

        console.error(`    -> Ejecuta: ${installCmd}`);
      }
    }

    if (!isReady) {
      console.warn('\n[!] Advertencia: Algunas herramientas de tu arsenal no están instaladas.');
      console.warn('[!] FixGuard funcionará, pero algunos ataques o motores SAST fallarán si no instalas estas dependencias.\n');
    } else {
      console.log('\n[+] Todo el arsenal está instalado y listo para el ataque.\n');
    }
  }
}
