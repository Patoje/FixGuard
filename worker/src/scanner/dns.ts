import { resolveTxt, resolveMx } from 'dns/promises';
import { db } from '../db/db';
import { vulnerabilities } from '../db/schema';

export async function runDnsScan(scanId: number, targetUrl: string) {
  try {
    const url = new URL(targetUrl);
    const domain = url.hostname.replace(/^www\./, ''); // Strip www to check root domain
    
    let hasMx = false;
    try {
      const mxRecords = await resolveMx(domain);
      hasMx = mxRecords && mxRecords.length > 0;
    } catch (e) {
      // Ignorar error si no hay registros MX
    }

    if (!hasMx) {
      return; // Si no recibe correos, SPF/DMARC no es crítico
    }

    let hasSpf = false;
    try {
      const txtRecords = await resolveTxt(domain);
      for (const chunk of txtRecords) {
        const txt = chunk.join('');
        if (txt.includes('v=spf1')) {
          hasSpf = true;
          break;
        }
      }
    } catch (e) {
      // Ignorar error
    }

    let hasDmarc = false;
    try {
      const dmarcRecords = await resolveTxt(`_dmarc.${domain}`);
      for (const chunk of dmarcRecords) {
        const txt = chunk.join('');
        if (txt.includes('v=DMARC1')) {
          hasDmarc = true;
          break;
        }
      }
    } catch (e) {
      // Ignorar error
    }

    if (!hasSpf) {
      await db.insert(vulnerabilities).values({
        scanId,
        type: 'MISSING_SPF_RECORD',
        severity: 'HIGH',
        description: `Falta el registro SPF en el DNS de ${domain}. Esto permite a atacantes suplantar la identidad (Email Spoofing) enviando correos falsos a nombre del dominio.`,
        autoFixCode: null,
      });
    }

    if (!hasDmarc) {
      await db.insert(vulnerabilities).values({
        scanId,
        type: 'MISSING_DMARC_RECORD',
        severity: 'MEDIUM',
        description: `Falta la política DMARC en _dmarc.${domain}. Sin esto, los servidores de correo no sabrán qué hacer si reciben un correo falso que suplanta tu dominio.`,
        autoFixCode: null,
      });
    }

  } catch (error) {
    console.error(`[Scan ${scanId}] DNS error:`, error);
  }
}
