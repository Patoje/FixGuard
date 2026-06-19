import * as tls from 'tls';
import { db } from '../db/db';
import { vulnerabilities } from '../db/schema';

export async function runTlsScan(scanId: number, targetUrl: string) {
  return new Promise<void>((resolve) => {
    try {
      const url = new URL(targetUrl);
      if (url.protocol !== 'https:') {
        resolve();
        return;
      }

      const host = url.hostname;
      
      const socket = tls.connect({
        host,
        port: 443,
        servername: host,
        rejectUnauthorized: false,
        timeout: 10000,
      }, async () => {
        const cert = socket.getPeerCertificate(true);
        if (cert && Object.keys(cert).length > 0) {
          const validTo = new Date(cert.valid_to);
          const now = new Date();
          
          if (validTo < now) {
            await db.insert(vulnerabilities).values({
              scanId,
              type: 'TLS_CERTIFICATE_EXPIRED',
              severity: 'HIGH',
              description: `El certificado SSL/TLS del servidor expiró el ${validTo.toISOString().split('T')[0]}. Esto interrumpe la conexión segura de los usuarios.`,
              autoFixCode: null,
            });
          }

          // Check for weak algorithms
          const sigalg = (cert as any).sigalg;
          if (sigalg && (sigalg.includes('md5') || sigalg.includes('sha1'))) {
            await db.insert(vulnerabilities).values({
              scanId,
              type: 'WEAK_TLS_SIGNATURE',
              severity: 'MEDIUM',
              description: `El certificado usa un algoritmo de firma débil u obsoleto: ${sigalg}. Se recomienda actualizar a SHA-256 o superior.`,
              autoFixCode: null,
            });
          }
        }
        socket.destroy();
        resolve();
      });

      socket.on('error', (err) => {
        console.error(`[Scan ${scanId}] TLS error:`, err.message);
        socket.destroy();
        resolve();
      });

      socket.on('timeout', () => {
        socket.destroy();
        resolve();
      });

    } catch (e) {
      resolve();
    }
  });
}
