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
  },
  {
    name: 'amass',
    macInstall: 'brew tap owasp/amass && brew install amass',
    winInstall: 'go install -v github.com/owasp-amass/amass/v4/...@master',
    linuxInstall: 'snap install amass'
  },
  {
    name: 'shodan',
    macInstall: 'easy_install shodan',
    winInstall: 'pip install shodan',
    linuxInstall: 'pip install shodan'
  },
  {
    name: 'httpx',
    macInstall: 'brew install httpx',
    winInstall: 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest',
    linuxInstall: 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest'
  },
  {
    name: 'feroxbuster',
    macInstall: 'brew install feroxbuster',
    winInstall: 'cargo install feroxbuster',
    linuxInstall: 'apt install feroxbuster'
  },
  {
    name: 'gospider',
    macInstall: 'go install github.com/jaeles-project/gospider@latest',
    winInstall: 'go install github.com/jaeles-project/gospider@latest',
    linuxInstall: 'go install github.com/jaeles-project/gospider@latest'
  },
  {
    name: 'trufflehog',
    macInstall: 'brew install trufflehog',
    winInstall: 'go install github.com/trufflesecurity/trufflehog/v3@latest',
    linuxInstall: 'curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin'
  },
  {
    name: 'gitleaks',
    macInstall: 'brew install gitleaks',
    winInstall: 'go install github.com/gitleaks/gitleaks/v8@latest',
    linuxInstall: 'go install github.com/gitleaks/gitleaks/v8@latest'
  },
  {
    name: 'source-map-explorer',
    macInstall: 'npm install -g source-map-explorer',
    winInstall: 'npm install -g source-map-explorer',
    linuxInstall: 'npm install -g source-map-explorer'
  },
  {
    name: 'retire',
    macInstall: 'npm install -g retire',
    winInstall: 'npm install -g retire',
    linuxInstall: 'npm install -g retire'
  },
  {
    name: 'shcheck',
    macInstall: 'pip install shcheck',
    winInstall: 'pip install shcheck',
    linuxInstall: 'pip install shcheck'
  },
  {
    name: 'crlfuzz',
    macInstall: 'go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest',
    winInstall: 'go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest',
    linuxInstall: 'go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest'
  },
  {
    name: 'kxss',
    macInstall: 'go install github.com/Emoe/kxss@latest',
    winInstall: 'go install github.com/Emoe/kxss@latest',
    linuxInstall: 'go install github.com/Emoe/kxss@latest'
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
