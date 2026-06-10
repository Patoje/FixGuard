import * as net from 'net';
import { db } from '../db/db';
import { vulnerabilities } from '../db/schema';

// Puertos que no deberían estar expuestos a internet (BDs, SSH, FTP, etc)
const DANGEROUS_PORTS = [
  { port: 21, name: 'FTP', severity: 'HIGH', desc: 'Puerto FTP expuesto (transferencia de archivos sin cifrar).' },
  { port: 22, name: 'SSH', severity: 'MEDIUM', desc: 'Puerto SSH expuesto. Podría ser susceptible a ataques de fuerza bruta.' },
  { port: 3306, name: 'MySQL', severity: 'HIGH', desc: 'Base de datos MySQL expuesta directamente a internet.' },
  { port: 5432, name: 'PostgreSQL', severity: 'HIGH', desc: 'Base de datos PostgreSQL expuesta directamente a internet.' },
  { port: 27017, name: 'MongoDB', severity: 'HIGH', desc: 'Base de datos MongoDB expuesta directamente a internet.' },
];

function checkPort(host: string, port: number, timeoutMs = 2000): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let isOpen = false;

    socket.setTimeout(timeoutMs);

    socket.on('connect', () => {
      isOpen = true;
      socket.destroy();
    });

    socket.on('timeout', () => {
      socket.destroy();
    });

    socket.on('error', () => {
      socket.destroy();
    });

    socket.on('close', () => {
      resolve(isOpen);
    });

    socket.connect(port, host);
  });
}

export async function runPortScan(scanId: number, targetUrl: string) {
  try {
    const url = new URL(targetUrl);
    const host = url.hostname;

    // Escanear puertos en paralelo
    const checks = DANGEROUS_PORTS.map(async (p) => {
      const isOpen = await checkPort(host, p.port);
      if (isOpen) {
        await db.insert(vulnerabilities).values({
          scanId,
          type: `EXPOSED_PORT_${p.port}`,
          severity: p.severity as "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
          description: p.desc,
          autoFixCode: null,
        });
      }
    });

    await Promise.all(checks);
  } catch (error) {
    console.error(`[Scan ${scanId}] Port scan error:`, error);
  }
}
