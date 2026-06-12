import { NextResponse } from 'next/server';
import { db } from '@/db/db';
import { findings, scans } from '@/db/schema';
import { eq } from 'drizzle-orm';

export async function GET(request: Request, { params }: { params: { scanId: string } }) {
  try {
    const scanId = parseInt(params.scanId, 10);
    if (isNaN(scanId)) {
      return new NextResponse('Invalid Scan ID', { status: 400 });
    }

    const [scan] = await db.select().from(scans).where(eq(scans.id, scanId));
    if (!scan) {
      return new NextResponse('Scan no encontrado', { status: 404 });
    }

    const scanFindings = await db.select().from(findings).where(eq(findings.scanId, scanId));

    // Generar un HTML simple pero limpio y corporativo
    const html = `
      <!DOCTYPE html>
      <html lang="es">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Reporte de Auditoría FixGuard - ${scan.targetUrl}</title>
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0a0a0a; color: #f4f4f5; margin: 0; padding: 40px; }
          .container { max-width: 900px; margin: 0 auto; }
          .header { text-align: center; margin-bottom: 50px; border-bottom: 1px solid #27272a; padding-bottom: 20px; }
          h1 { color: #fff; font-size: 32px; margin-bottom: 10px; }
          .subtitle { color: #a1a1aa; font-size: 16px; }
          .summary { display: flex; gap: 20px; margin-bottom: 40px; }
          .stat-card { background: #18181b; border: 1px solid #27272a; padding: 20px; border-radius: 8px; flex: 1; text-align: center; }
          .stat-card h3 { margin: 0 0 10px 0; font-size: 14px; color: #a1a1aa; text-transform: uppercase; letter-spacing: 1px; }
          .stat-card p { margin: 0; font-size: 28px; font-weight: bold; }
          
          .severity-critical { color: #f43f5e; }
          .severity-high { color: #f97316; }
          .severity-medium { color: #eab308; }
          .severity-low { color: #3b82f6; }
          .severity-info { color: #2dd4bf; }

          .finding { background: #18181b; border: 1px solid #27272a; border-radius: 8px; margin-bottom: 30px; overflow: hidden; }
          .finding-header { padding: 20px; border-bottom: 1px solid #27272a; display: flex; justify-content: space-between; align-items: center; }
          .finding-header h2 { margin: 0; font-size: 18px; }
          .finding-body { padding: 20px; }
          .section-title { font-size: 14px; color: #a1a1aa; text-transform: uppercase; margin-top: 0; margin-bottom: 10px; }
          pre { background: #09090b; padding: 15px; border-radius: 6px; overflow-x: auto; color: #d4d4d8; font-family: monospace; font-size: 13px; margin-top: 0; border: 1px solid #27272a; }
          .tag { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; text-transform: uppercase; }
          
          .bg-critical { background: rgba(244, 63, 94, 0.1); border: 1px solid rgba(244, 63, 94, 0.2); }
          .bg-high { background: rgba(249, 115, 22, 0.1); border: 1px solid rgba(249, 115, 22, 0.2); }
          .bg-medium { background: rgba(234, 179, 8, 0.1); border: 1px solid rgba(234, 179, 8, 0.2); }
          .bg-low { background: rgba(59, 130, 246, 0.1); border: 1px solid rgba(59, 130, 246, 0.2); }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Reporte de Auditoría de Seguridad</h1>
            <div class="subtitle">Generado por FixGuard DAST Agent</div>
            <p style="margin-top: 20px; color: #e4e4e7;"><strong>Objetivo:</strong> <a href="${scan.targetUrl}" style="color: #60a5fa;">${scan.targetUrl}</a></p>
            <p style="color: #a1a1aa; font-size: 14px;">Fecha: ${new Date().toLocaleDateString()}</p>
          </div>

          <div class="summary">
            <div class="stat-card">
              <h3>Críticas</h3>
              <p class="severity-critical">${scanFindings.filter(f => f.severity === 'critical').length}</p>
            </div>
            <div class="stat-card">
              <h3>Altas</h3>
              <p class="severity-high">${scanFindings.filter(f => f.severity === 'high').length}</p>
            </div>
            <div class="stat-card">
              <h3>Medias</h3>
              <p class="severity-medium">${scanFindings.filter(f => f.severity === 'medium').length}</p>
            </div>
            <div class="stat-card">
              <h3>Total</h3>
              <p>${scanFindings.length}</p>
            </div>
          </div>

          ${scanFindings.length === 0 ? '<div class="stat-card"><h3 style="color:#10b981;">Excelente</h3><p>No se descubrieron vulnerabilidades.</p></div>' : ''}

          ${scanFindings.map(f => `
            <div class="finding">
              <div class="finding-header">
                <h2>${f.title}</h2>
                <span class="tag severity-${f.severity} bg-${f.severity}">${f.severity}</span>
              </div>
              <div class="finding-body">
                <p style="margin-top:0;"><strong>Endpoint:</strong> <code style="background:#27272a;padding:2px 6px;border-radius:4px;">${f.method || 'GET'} ${f.endpoint || 'N/A'}</code></p>
                <p><strong>CWE:</strong> ${f.cweId || 'N/A'} | <strong>OWASP:</strong> ${f.owaspCategory || 'N/A'} | <strong>Motor:</strong> ${f.toolSource}</p>
                
                ${f.payloadUsed ? `
                  <h4 class="section-title">Payload inyectado</h4>
                  <pre>${escapeHtml(f.payloadUsed)}</pre>
                ` : ''}

                ${f.requestRaw ? `
                  <h4 class="section-title">Request Evidencia</h4>
                  <pre>${escapeHtml(f.requestRaw)}</pre>
                ` : ''}

                ${f.responseRaw ? `
                  <h4 class="section-title">Response (Fragmento)</h4>
                  <pre>${escapeHtml(f.responseRaw.substring(0, 1500))}${f.responseRaw.length > 1500 ? '\n... [truncado]' : ''}</pre>
                ` : ''}
              </div>
            </div>
          `).join('')}

        </div>
      </body>
      </html>
    `;

    return new NextResponse(html, {
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Disposition': `attachment; filename="FixGuard_Report_${scan.targetUrl.replace(/[^a-zA-Z0-9]/g, '_')}_${scanId}.html"`
      }
    });

  } catch (error) {
    console.error('Error exportando reporte:', error);
    return new NextResponse('Error Interno del Servidor', { status: 500 });
  }
}

function escapeHtml(unsafe: string) {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
