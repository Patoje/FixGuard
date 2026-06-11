import { generateObject } from 'ai';
import { google } from '@ai-sdk/google';
import { z } from 'zod';
import { AttackSurfaceItem } from './AttackSurfaceMapper';
import { BusinessDictionary } from './parsers/JsKnowledgeExtractor';

export class ExposureIntelligenceEngine {
  static async enrichAttackSurface(
    surface: AttackSurfaceItem[], 
    businessDict: BusinessDictionary,
    techStack: any[]
  ): Promise<AttackSurfaceItem[]> {
    try {
      if (!process.env.GOOGLE_GENERATIVE_AI_API_KEY) {
        console.warn('⚠️ No GOOGLE_GENERATIVE_AI_API_KEY found, skipping AI Exposure Enrichment.');
        return surface;
      }

      // Filter only CRITICAL or HIGH risk endpoints to save tokens and time
      const highRiskEndpoints = surface.filter(item => item.riskLevel === 'CRÍTICO' || item.riskLevel === 'ALTO');
      
      if (highRiskEndpoints.length === 0) return surface;

      console.log(`[Exposure AI] Solicitando análisis de inteligencia a Gemini para ${highRiskEndpoints.length} endpoints críticos/altos...`);

      const prompt = `
        Eres un ingeniero de seguridad ofensiva avanzado (Red Team).
        He escaneado una aplicación web.
        Stack tecnológico detectado: ${techStack.map(t => t.name).join(', ')}.
        Diccionario de negocio inferido del cliente: 
        - Roles: ${businessDict.roles.join(', ')}
        - Entidades: ${businessDict.entities.join(', ')}
        
        Aquí hay una lista de Endpoints expuestos con alto riesgo:
        ${highRiskEndpoints.map(e => `- ${e.method} ${e.path} (Tipo: ${e.type})`).join('\n')}

        Para cada uno de estos endpoints, proporciona una corta descripción de 1 oración (máximo 15 palabras) 
        explicando qué impacto de negocio tendría si es vulnerado, usando el diccionario de negocio.
      `;

      const { object } = await generateObject({
        model: google('gemini-1.5-flash'),
        schema: z.object({
          enrichedEndpoints: z.array(z.object({
            path: z.string(),
            aiExplanation: z.string()
          }))
        }),
        prompt,
      });

      // Merge AI explanations back into the surface
      const enrichedSurface = surface.map(endpoint => {
        const aiMatch = object.enrichedEndpoints.find(e => e.path === endpoint.path);
        if (aiMatch) {
          return { ...endpoint, aiExplanation: aiMatch.aiExplanation };
        }
        return endpoint;
      });

      return enrichedSurface;
    } catch (error) {
      console.error('[Exposure AI] Error enriqueciendo superficie:', error);
      return surface; // Return original on error
    }
  }
}
