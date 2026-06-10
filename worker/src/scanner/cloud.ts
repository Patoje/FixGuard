import axios from 'axios';
import { db } from '../db/db';
import { vulnerabilities } from '../db/schema';

export async function runCloudExposureScan(scanId: number, targetUrl: string) {
  try {
    const response = await axios.get(targetUrl, { timeout: 5000, validateStatus: () => true });
    if (typeof response.data !== 'string') return;

    const html = response.data;
    
    const cloudPatterns = [
      { name: 'AWS S3 Bucket', regex: /([a-z0-9.-]+)\.s3\.amazonaws\.com/i },
      { name: 'Azure Blob Storage', regex: /([a-z0-9.-]+)\.blob\.core\.windows\.net/i },
      { name: 'Google Cloud Storage', regex: /storage\.googleapis\.com\/([a-z0-9.-]+)/i }
    ];

    for (const provider of cloudPatterns) {
      const match = html.match(provider.regex);
      if (match) {
        await db.insert(vulnerabilities).values({
          scanId,
          type: 'CLOUD_STORAGE_EXPOSURE',
          severity: 'HIGH',
          description: `Vulnerabilidad ALTA (Cloud Exposure). Se detectó una referencia a un bucket de almacenamiento en la nube de ${provider.name} en el código fuente: ${match[0]}. Los atacantes pueden intentar listar, leer o escribir archivos si el bucket está mal configurado como "Público".`,
          autoFixCode: null,
        });
      }
    }
  } catch (error: any) {
    console.error(`[Scan ${scanId}] Cloud Exposure error:`, error?.message || String(error));
  }
}
