import axios from 'axios';
import { db } from '../db/db';
import { vulnerabilities } from '../db/schema';

export async function runSecurityTxtScan(scanId: number, targetUrl: string) {
  try {
    const baseUrl = new URL(targetUrl).origin;
    const urlToTest = `${baseUrl}/.well-known/security.txt`;

    const response = await axios.get(urlToTest, { 
      timeout: 3000,
      validateStatus: () => true 
    });

    // Validar que realmente devolvió texto plano y que parece un archivo security.txt legítimo
    const contentType = String(response.headers['content-type'] || '');
    const isText = contentType.includes('text/plain');
    const content = typeof response.data === 'string' ? response.data : '';
    const hasContact = content.toLowerCase().includes('contact:');

    if (response.status !== 200 || !isText || !hasContact) {
      await db.insert(vulnerabilities).values({
        scanId,
        type: 'MISSING_SECURITY_TXT',
        severity: 'LOW',
        description: `No se encontró un archivo 'security.txt' válido en /.well-known/security.txt. (Estándar RFC 9116). Esto dificulta que investigadores éticos reporten vulnerabilidades de forma segura a la empresa.`,
        autoFixCode: null,
      });
    }

  } catch (error) {
    console.error(`[Scan ${scanId}] Security.txt scan error:`, error);
  }
}
