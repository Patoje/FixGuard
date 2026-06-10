import axios from 'axios';
import { db } from '../db/db';
import { vulnerabilities } from '../db/schema';

export async function runFingerprintScan(scanId: number, targetUrl: string) {
  try {
    const response = await axios.get(targetUrl, { 
      timeout: 5000,
      validateStatus: () => true 
    });

    const html = (typeof response.data === 'string' ? response.data : '').toLowerCase();
    
    // Detectar React/Next.js
    if (html.includes('__next_data__') || html.includes('_next/static')) {
      // Es Next.js, generalmente es moderno y seguro, pero podríamos reportarlo como info
      // Para mantener el ruido bajo, solo reportamos tecnologías problemáticas
    }

    // Detectar WordPress
    if (html.includes('wp-content/') || html.includes('<meta name="generator" content="wordpress')) {
      await db.insert(vulnerabilities).values({
        scanId,
        type: 'TECH_STACK_WORDPRESS',
        severity: 'MEDIUM',
        description: `Se detectó el uso de WordPress. WordPress es un objetivo frecuente de ataques; asegúrese de mantener el núcleo y todos los plugins rigurosamente actualizados.`,
        autoFixCode: null,
      });
    }

    // Detectar jQuery viejo
    if (html.includes('jquery.min.js') || html.includes('jquery.js')) {
      // Extraer la versión si es posible usando una regex simple
      const match = html.match(/jquery-([0-9]+\.[0-9]+\.[0-9]+)\.min\.js/);
      if (match && match[1]) {
        const version = match[1];
        if (version.startsWith('1.') || version.startsWith('2.')) {
          await db.insert(vulnerabilities).values({
            scanId,
            type: 'OUTDATED_JQUERY',
            severity: 'LOW',
            description: `Se detectó una versión antigua de jQuery (${version}). Las versiones 1.x y 2.x contienen múltiples vulnerabilidades XSS conocidas.`,
            autoFixCode: null,
          });
        }
      }
    }

  } catch (error) {
    console.error(`[Scan ${scanId}] Fingerprint scan error:`, error);
  }
}
