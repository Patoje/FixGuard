export interface EntityNode {
  name: string;
  type: string; // "Entity" | "Resource" | "Action"
  attributes: string[];
}

export interface EntityRelation {
  source: string;
  target: string;
  relationType: string; // "1:N", "1:1", "N:M", "BelongsTo"
  evidence: string; // e.g. "/api/orgs/1/users"
}

export class EntityRelationshipEngine {
  
  /**
   * Analiza un conjunto de URLs descubiertas y parámetros para reconstruir el modelo
   * de datos y relaciones del objetivo.
   */
  public static analyze(endpoints: string[], parameters: any[] = []): { nodes: EntityNode[], edges: EntityRelation[] } {
    const nodesMap = new Map<string, EntityNode>();
    const edgesMap = new Map<string, EntityRelation>();

    for (const url of endpoints) {
      try {
        const parsedUrl = new URL(url);
        // Filtrar archivos estáticos o no-API
        if (parsedUrl.pathname.match(/\.(js|css|png|jpg|jpeg|gif|woff2?|ttf|svg|ico)$/i)) continue;

        const pathSegments = parsedUrl.pathname.split('/').filter(p => p.length > 0 && p !== 'api' && p !== 'v1' && p !== 'v2');
        
        // Buscamos patrones de Entidad -> ID -> Entidad -> ID
        // ej: /organizations/123/users/456
        let previousEntity: string | null = null;
        
        for (let i = 0; i < pathSegments.length; i++) {
          const segment = pathSegments[i];
          
          // Heurística simple: Si el segmento parece un ID (números, UUIDs, o palabras como 'me')
          const isIdentifier = this.isIdentifier(segment);
          
          if (!isIdentifier) {
            // Es una entidad
            const entityName = this.capitalizeAndSingularize(segment);
            
            if (!nodesMap.has(entityName)) {
              nodesMap.set(entityName, {
                name: entityName,
                type: 'Entity',
                attributes: []
              });
            }

            // Si hay una entidad previa, inferimos relación
            if (previousEntity) {
              const edgeId = `${previousEntity}->${entityName}`;
              if (!edgesMap.has(edgeId)) {
                edgesMap.set(edgeId, {
                  source: previousEntity,
                  target: entityName,
                  relationType: '1:N', // Por defecto asumimos 1 a muchos en REST
                  evidence: parsedUrl.pathname
                });
              }
            }
            
            previousEntity = entityName;
          }
        }
      } catch (e) {
        // Ignorar URLs malformadas
      }
    }

    // Procesar parámetros para inferir atributos de las entidades
    for (const param of parameters) {
      if (param.name && typeof param.name === 'string') {
        const paramLower = param.name.toLowerCase();
        // Ej: organization_id, userId, project_id
        if (paramLower.endsWith('id') || paramLower.endsWith('_id')) {
          const inferredEntity = this.capitalizeAndSingularize(paramLower.replace(/_?id$/, ''));
          if (inferredEntity && nodesMap.has(inferredEntity)) {
            // Relación por parámetro implícito (Foreign Key exposure)
          }
        }
      }
    }

    return {
      nodes: Array.from(nodesMap.values()),
      edges: Array.from(edgesMap.values())
    };
  }

  private static isIdentifier(segment: string): boolean {
    // UUID regex
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(segment)) return true;
    // Numérico
    if (/^\d+$/.test(segment)) return true;
    // Alfanumérico largo sin vocales claras o que parezca un hash (MongoDB ObjectID etc)
    if (segment.length >= 16 && /^[a-f0-9]+$/i.test(segment)) return true;
    // Palabras clave especiales de ID
    if (['me', 'current', 'default'].includes(segment.toLowerCase())) return true;
    
    return false;
  }

  private static capitalizeAndSingularize(word: string): string {
    let clean = word.toLowerCase();
    // Singularize simple (inglés)
    if (clean.endsWith('ies')) {
      clean = clean.substring(0, clean.length - 3) + 'y';
    } else if (clean.endsWith('ses')) {
      clean = clean.substring(0, clean.length - 2);
    } else if (clean.endsWith('s') && !clean.endsWith('ss')) {
      clean = clean.substring(0, clean.length - 1);
    }
    
    if (clean.length === 0) return word;
    return clean.charAt(0).toUpperCase() + clean.slice(1);
  }
}
