import axios from 'axios';
import { db } from '../db/db';
import { vulnerabilities } from '../db/schema';

export async function runWafScan(scanId: number, targetUrl: string) {
  try {
    const response = await axios.get(targetUrl, { 
      timeout: 5000,
      validateStatus: () => true 
    });

    const headers = response.headers;
    const serverHeader = String(headers['server'] || '').toLowerCase();
    
    let hasWaf = false;
    let wafName = '';

    if (headers['cf-ray'] || serverHeader.includes('cloudflare')) {
      hasWaf = true;
      wafName = 'Cloudflare';
    } else if (headers['x-amz-cf-id'] || serverHeader.includes('awselb') || serverHeader.includes('amazon')) {
      hasWaf = true;
      wafName = 'AWS WAF / CloudFront';
    } else if (headers['x-sucuri-id'] || serverHeader.includes('sucuri')) {
      hasWaf = true;
      wafName = 'Sucuri';
    } else if (serverHeader.includes('akamai')) {
      hasWaf = true;
      wafName = 'Akamai';
    }

    if (!hasWaf) {
      await db.insert(vulnerabilities).values({
        scanId,
        type: 'MISSING_WAF_PROTECTION',
        severity: 'LOW',
        description: `No se detectó un Web Application Firewall (WAF) activo (como Cloudflare o AWS WAF). El servidor está directamente expuesto a ataques de Denegación de Servicio (DDoS) y ataques de fuerza bruta masivos.`,
        autoFixCode: null,
      });
    }

  } catch (error) {
    console.error(`[Scan ${scanId}] WAF scan error:`, error);
  }
}
