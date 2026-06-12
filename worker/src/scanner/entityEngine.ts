export interface EntityNode {
  id: string;
  label: string;
  type: 'model' | 'rest_resource' | 'graphql_type';
}

export interface EntityEdge {
  id: string;
  source: string;
  target: string;
  label: string;
}

export interface EntityGraph {
  nodes: EntityNode[];
  edges: EntityEdge[];
}

export class EntityRelationshipEngine {
  /**
   * Analiza rutas REST, código JS (buscando ORMs como Prisma/Mongoose) y esquemas GraphQL 
   * para construir un árbol genealógico de entidades de base de datos.
   */
  static async analyze(
    endpoints: string[], 
    jsCodes: string[], 
    businessDictionary: { entities: string[] }
  ): Promise<EntityGraph> {
    const nodes = new Map<string, EntityNode>();
    const edges = new Map<string, EntityEdge>();

    const addNode = (label: string, type: EntityNode['type']) => {
      const id = label.toLowerCase();
      if (!nodes.has(id)) {
        // Capitalize for label
        const capLabel = label.charAt(0).toUpperCase() + label.slice(1);
        nodes.set(id, { id, label: capLabel, type });
      }
      return id;
    };

    const addEdge = (sourceId: string, targetId: string, label: string) => {
      const edgeId = `${sourceId}-${targetId}-${label}`;
      if (!edges.has(edgeId) && sourceId !== targetId) {
        edges.set(edgeId, { id: edgeId, source: sourceId, target: targetId, label });
      }
    };

    // 1. INFERENCIA BASADA EN RUTAS RESTful
    // Ej: /api/organizations/{id}/projects/{id} -> Organization -> Project
    for (const ep of endpoints) {
      try {
        const u = new URL(ep.startsWith('http') ? ep : `http://localhost${ep.startsWith('/') ? ep : '/' + ep}`);
        const parts = u.pathname.split('/').filter(p => p.length > 0 && p !== 'api' && p !== 'v1' && p !== 'v2');
        
        let previousEntityId: string | null = null;

        for (let i = 0; i < parts.length; i++) {
          const part = parts[i];
          if (!part) continue;
          // Heurística simple: Si no es un número/UUID y no es una acción verbal, es una entidad.
          if (!part.match(/^[0-9a-fA-F-]+$/) && !['create','update','delete','list','get','search'].includes(part.toLowerCase())) {
            
            // Singularizar (naive)
            let entityName = part.toLowerCase();
            if (entityName.endsWith('ies')) entityName = entityName.slice(0, -3) + 'y';
            else if (entityName.endsWith('s') && entityName.length > 3) entityName = entityName.slice(0, -1);
            
            const entityId = addNode(entityName, 'rest_resource');

            if (previousEntityId) {
              addEdge(previousEntityId, entityId, 'has_child');
            }
            previousEntityId = entityId;
          }
        }
      } catch (e) {}
    }

    // 2. INFERENCIA BASADA EN DICCIONARIO DE NEGOCIO JS
    // Mapeamos los que no salieron en REST
    if (businessDictionary && businessDictionary.entities) {
      businessDictionary.entities.forEach(ent => {
        addNode(ent, 'model');
      });
    }

    // 3. EXTRACCIÓN DE ESQUEMAS ORM (Prisma / Mongoose) DE ARCHIVOS JS
    // Buscamos patrones de código transpilado de ORMs en los chunks de webpack
    for (const code of jsCodes) {
      // Prisma Model Inference (Buscando "model X {" transpilado o arrays de modelos Prisma)
      // En JS compilado, Prisma Client a veces expone los 'dmmf' (Data Model Meta Format)
      const dmmfMatch = code.match(/["']?dmmf["']?\s*:\s*\{.*?models\s*:\s*\[(.*?)\]/);
      if (dmmfMatch && dmmfMatch[1]) {
        try {
           // Intento de extraer nombres de modelos del DMMF (extremadamente crudo pero útil)
           const modelNames = [...dmmfMatch[1].matchAll(/name\s*:\s*["']([^"']+)["']/g)].map(m => m[1]);
           modelNames.forEach(m => {
             if (m) addNode(m, 'model');
           });
        } catch(e) {}
      }

      // Mongoose Schema Inference: "new Schema({ ... })" 
      // Busca definiciones que parecen mongoose
      const mongooseMatches = [...code.matchAll(/model\(["']([^"']+)["'],/g)];
      mongooseMatches.forEach(m => {
         if (m && m[1]) addNode(m[1], 'model');
      });
    }

    return {
      nodes: Array.from(nodes.values()),
      edges: Array.from(edges.values())
    };
  }
}
