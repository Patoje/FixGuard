import { NextResponse } from 'next/server';
import { db } from '@/db/db';
import { scans, reconProfiles, findings, vulnerabilities } from '@/db/schema';
import { eq } from 'drizzle-orm';

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const scanIdParam = searchParams.get('scanId');

    if (!scanIdParam) {
      return NextResponse.json({ error: 'Falta parámetro scanId' }, { status: 400 });
    }

    const scanId = parseInt(scanIdParam, 10);

    const scanList = await db.select().from(scans).where(eq(scans.id, scanId));
    if (!scanList || scanList.length === 0) {
      return NextResponse.json({ error: 'Escaneo no encontrado' }, { status: 404 });
    }
    const scan = scanList[0];

    const profiles = await db.select().from(reconProfiles).where(eq(reconProfiles.scanId, scanId));
    const profile = profiles.length > 0 ? profiles[0] : null;

    const scanFindings = await db.select().from(findings).where(eq(findings.scanId, scanId));
    const scanVulns = await db.select().from(vulnerabilities).where(eq(vulnerabilities.scanId, scanId));

    let md = `# Reporte de Seguridad FixGuard\n\n`;
    md += `**Objetivo:** \`${scan.targetUrl}\`\n`;
    md += `**Fecha de Escaneo:** ${new Date(scan.createdAt).toLocaleString()}\n`;
    md += `**Modo:** ${scan.mode.toUpperCase()}\n`;
    md += `**Estado:** ${scan.status.toUpperCase()}\n\n`;
    md += `---\n\n`;

    if (profile) {
      md += `## Inteligencia del Objetivo (Recon)\n\n`;
      md += `### Stack Tecnológico Detectado\n`;
      if (profile.techStack && Array.isArray(profile.techStack)) {
        profile.techStack.forEach((tech: any) => {
           md += `- ${tech.name}\n`;
        });
      } else {
        md += `*No se detectó información clara del stack.*\n`;
      }
      md += `\n`;

      if (profile.subdomainIntelligence) {
        md += `### Subdominios Descubiertos\n`;
        const subs: any = profile.subdomainIntelligence;
        if (subs.active && Array.isArray(subs.active)) {
           subs.active.forEach((s: any) => { md += `- \`${s}\`\n`; });
        }
        md += `\n`;
      }

      md += `---\n\n`;
    }

    if (scanFindings.length > 0) {
      md += `## Hallazgos de Seguridad (DAST / Lógica de Negocio)\n\n`;
      scanFindings.forEach((f) => {
         md += `### [${f.severity.toUpperCase()}] ${f.title}\n`;
         md += `- **Endpoint:** \`${f.method || 'GET'} ${f.endpoint || 'N/A'}\`\n`;
         if (f.cweId) md += `- **CWE:** ${f.cweId}\n`;
         if (f.toolSource) md += `- **Motor:** ${f.toolSource}\n`;
         md += `\n`;
      });
      md += `---\n\n`;
    }

    if (scanVulns.length > 0) {
      md += `## Vulnerabilidades de Código (SAST)\n\n`;
      scanVulns.forEach((v) => {
         md += `### [${v.severity.toUpperCase()}] ${v.type}\n`;
         md += `${v.description}\n\n`;
      });
      md += `---\n\n`;
    }

    md += `*Reporte generado automáticamente por FixGuard Personal Arsenal Edition.*`;

    return NextResponse.json({ markdown: md });

  } catch (error) {
    console.error('Error generando markdown:', error);
    return NextResponse.json({ error: 'Error interno generando Markdown' }, { status: 500 });
  }
}
