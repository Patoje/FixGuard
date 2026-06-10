import axios from 'axios';
import { db } from '../db/db';
import { vulnerabilities } from '../db/schema';
import * as cheerio from 'cheerio';

export async function runUploadsScan(scanId: number, targetUrl: string) {
  try {
    const response = await axios.get(targetUrl, { timeout: 5000, validateStatus: () => true });
    if (typeof response.data !== 'string') return;

    const $ = cheerio.load(response.data);
    
    if ($('input[type="file"]').length > 0) {
      await db.insert(vulnerabilities).values({
        scanId,
        type: 'FILE_UPLOAD_SURFACE',
        severity: 'LOW',
        description: `Vulnerabilidad BAJA (Superficie de Ataque). Se detectó un formulario de subida de archivos (<input type="file">). Se debe verificar manualmente que el servidor restrinja los tipos MIME, limite el tamaño del archivo y no permita la ejecución de scripts (Web Shells) en el directorio de destino.`,
        autoFixCode: null,
      });
    }
  } catch (error: any) {
    console.error(`[Scan ${scanId}] Uploads scan error:`, error?.message || String(error));
  }
}
