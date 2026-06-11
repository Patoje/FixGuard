import type { AuthIntelligence } from './parsers/AuthIntelligenceEngine';
import type { CloudIntelligence } from './CloudIntelligenceEngine';
import type { ParameterIntelligence } from './ParameterIntelligenceEngine';
import type { ArtifactIntelligence } from './ArtifactIntelligenceEngine';
import type { CommunicationIntelligence } from './CommunicationIntelligenceEngine';
import type { BusinessDictionary } from './parsers/JsKnowledgeExtractor';
import type { AttackSurfaceItem } from './AttackSurfaceMapper';
import type { AIFingerprint } from './AIFingerprintEngine';
import type { ServerActionsIntelligence } from './ServerActionsEngine';

export interface AuditContext {
  name: string;
  description: string;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  evidences: string[];
  inferredTechnologies: string[];
}

export interface AuditReport {
  summary: string;
  contexts: AuditContext[];
}

export class CorrelationEngine {
  static analyze(
    auth: AuthIntelligence,
    cloud: CloudIntelligence,
    params: ParameterIntelligence,
    artifacts: ArtifactIntelligence,
    comm: CommunicationIntelligence,
    business: BusinessDictionary,
    attackSurface: AttackSurfaceItem[],
    ai: AIFingerprint,
    serverActions?: ServerActionsIntelligence
  ): AuditReport {
    const report: AuditReport = {
      summary: "El motor de correlación ha inferido los siguientes contextos funcionales basándose en las evidencias técnicas extraídas.",
      contexts: []
    };

    // 1. IDENTITY & ACCESS (Auth)
    const identityEvidences: string[] = [];
    const identityTech: string[] = [];
    let identityConfidence: 'HIGH' | 'MEDIUM' | 'LOW' = 'LOW';

    if (auth.mechanisms.length > 0) {
      identityEvidences.push(`Mecanismos detectados: ${auth.mechanisms.join(', ')}`);
      identityConfidence = 'HIGH';
    }
    if (auth.cookieNames.length > 0) {
      identityEvidences.push(`Cookies sensibles usadas para sesión: ${auth.cookieNames.join(', ')}`);
    }
    if (auth.localStorage) {
      identityEvidences.push(`Utiliza LocalStorage para almacenar credenciales (Riesgo XSS)`);
    }
    if (business.roles && business.roles.length > 0) {
      identityEvidences.push(`Roles estáticos extraídos del código: ${business.roles.join(', ')}`);
    }
    if (business.permissions && business.permissions.length > 0) {
      identityEvidences.push(`Permisos granulares detectados (RBAC/ABAC): ${business.permissions.length} items encontrados`);
    }

    if (identityEvidences.length > 0) {
      report.contexts.push({
        name: 'Identity & Access Management',
        description: 'Gestión de autenticación, autorización y sesiones de usuario.',
        confidence: identityConfidence,
        evidences: identityEvidences,
        inferredTechnologies: identityTech
      });
    }

    // 2. DATA & STORAGE
    const dataEvidences: string[] = [];
    const dataTech: string[] = [];
    let dataConfidence: 'HIGH' | 'MEDIUM' | 'LOW' = 'LOW';

    if (cloud.provider !== 'Unknown') {
      dataTech.push(cloud.provider);
      dataConfidence = 'HIGH';
      if (cloud.buckets.length > 0) {
        dataEvidences.push(`Almacenamiento remoto detectado en ${cloud.provider}: ${cloud.buckets.join(', ')}`);
      }
    }
    if (params.topParameters.length > 0) {
      dataConfidence = 'HIGH';
      const pNames = params.topParameters.map(p => p.name).filter(p => p.toLowerCase().includes('id'));
      if (pNames.length > 0) {
        dataEvidences.push(`Entidades manipuladas en DB (inferidas por parámetros): ${pNames.slice(0, 5).join(', ')}`);
      }
    }

    if (dataEvidences.length > 0) {
      report.contexts.push({
        name: 'Data & Cloud Storage',
        description: 'Mecanismos de almacenamiento de datos, buckets públicos y modelado de base de datos.',
        confidence: dataConfidence,
        evidences: dataEvidences,
        inferredTechnologies: dataTech
      });
    }

    // 3. INTEGRATIONS & EXTERNAL APIS
    const intEvidences: string[] = [];
    const intTech: string[] = [];
    let intConfidence: 'HIGH' | 'MEDIUM' | 'LOW' = 'LOW';

    if (comm.graphql.enabled) {
      intConfidence = 'HIGH';
      intTech.push('GraphQL');
      intEvidences.push(`API GraphQL expuesta en: ${comm.graphql.endpoint}`);
      if (comm.graphql.types.length > 0) intEvidences.push(`Tipos GraphQL extraídos: ${comm.graphql.types.slice(0, 5).join(', ')}...`);
    }
    if (comm.websockets.detected) {
      intConfidence = 'HIGH';
      intTech.push('WebSockets / Socket.io');
      intEvidences.push(`Canales de comunicación en tiempo real detectados.`);
    }
    if (artifacts.hiddenApiEndpoints && artifacts.hiddenApiEndpoints.length > 0) {
      intConfidence = 'HIGH';
      intEvidences.push(`APIs ocultas extraídas del código JS (LinkFinder): ${artifacts.hiddenApiEndpoints.length} rutas encontradas.`);
    }

    if (intEvidences.length > 0) {
      report.contexts.push({
        name: 'API & Communication Interfaces',
        description: 'Canales de comunicación con el backend e interfaces de servicio.',
        confidence: intConfidence,
        evidences: intEvidences,
        inferredTechnologies: intTech
      });
    }

    // 4. ADMINISTRATION & HIDDEN INTERNALS
    const adminEvidences: string[] = [];
    let adminConfidence: 'HIGH' | 'MEDIUM' | 'LOW' = 'LOW';

    if (artifacts.hiddenRoutes && artifacts.hiddenRoutes.length > 0) {
      adminConfidence = 'HIGH';
      adminEvidences.push(`Rutas ocultas descubiertas en artefactos de build: ${artifacts.hiddenRoutes.join(', ')}`);
    }
    if (business.configFlags && business.configFlags.length > 0) {
      adminConfidence = 'MEDIUM';
      adminEvidences.push(`Feature Flags ocultos detectados: ${business.configFlags.join(', ')}`);
    }
    if (artifacts.exposedSourceMaps && artifacts.exposedSourceMaps.length > 0) {
      adminConfidence = 'HIGH';
      adminEvidences.push(`PELIGRO: Source Maps (.map) expuestos permitiendo extracción del código fuente original.`);
    }

    if (adminEvidences.length > 0) {
      report.contexts.push({
        name: 'Administration & Internals',
        description: 'Secciones no públicas, paneles administrativos y configuraciones experimentales.',
        confidence: adminConfidence,
        evidences: adminEvidences,
        inferredTechnologies: []
      });
    }

    // 4.5 EXPOSED SECRETS & CREDENTIALS (CRITICAL)
    if (artifacts.exposedSecrets && artifacts.exposedSecrets.length > 0) {
      const secretEvidences = artifacts.exposedSecrets.map(s => {
        // Redactamos el secreto para el reporte visual
        const safeValue = s.value.substring(0, 10) + '...';
        return `[${s.type}] detectado en el JS cliente: ${safeValue}`;
      });

      report.contexts.push({
        name: 'Exposed Secrets & API Keys',
        description: 'ALERTA CRÍTICA: Credenciales, tokens o claves privadas embebidas en el código fuente de frontend.',
        confidence: 'HIGH', // Tratamos 'HIGH' como crítico visualmente en la UI
        evidences: secretEvidences,
        inferredTechnologies: ['SecretFinder']
      });
    }

    // 4.6 SERVER ACTIONS (NEXT.JS SPECIFIC CRITICAL VULN VECTOR)
    if (serverActions && serverActions.extractedActionsCount > 0) {
      const actionEvidences = serverActions.actions.slice(0, 10).map(a => 
        `Hash: ${a.id} ${a.context ? `(Contexto: ${a.context.substring(0, 50)}...)` : ''}`
      );
      
      if (serverActions.extractedActionsCount > 10) {
        actionEvidences.push(`... y ${serverActions.extractedActionsCount - 10} acciones más.`);
      }

      report.contexts.push({
        name: 'Next.js Server Actions (BOLA/IDOR Vector)',
        description: 'ALERTA OFENSIVA: Hashes de Server Actions extraídos. Pueden ser invocados directamente vía POST saltando la UI para probar vulnerabilidades de Autorización Rota.',
        confidence: 'HIGH',
        evidences: actionEvidences,
        inferredTechnologies: ['ServerActionsExtrator', 'Next.js App Router']
      });
    }

    // 5. ARTIFICIAL INTELLIGENCE & LLMs
    const aiEvidences: string[] = [];
    const aiTech: string[] = [];
    let aiConfidence: 'HIGH' | 'MEDIUM' | 'LOW' = 'LOW';

    if (ai.detected) {
      aiConfidence = 'HIGH';
      if (ai.providers.length > 0) {
        aiTech.push(...ai.providers);
        aiEvidences.push(`Proveedores de IA detectados en uso: ${ai.providers.join(', ')}`);
      }
      if (ai.frameworks.length > 0) {
        aiTech.push(...ai.frameworks);
        aiEvidences.push(`Frameworks de IA / Agentes detectados: ${ai.frameworks.join(', ')}`);
      }
      if (ai.features.length > 0) {
        aiEvidences.push(`Funcionalidades LLM inferidas: ${ai.features.join(', ')}`);
      }
      
      report.contexts.push({
        name: 'Artificial Intelligence Ecosystem',
        description: 'Integración con Modelos de Lenguaje Grande (LLMs), frameworks de Agentes y bases de datos vectoriales.',
        confidence: aiConfidence,
        evidences: aiEvidences,
        inferredTechnologies: aiTech
      });
    }

    return report;
  }
}
