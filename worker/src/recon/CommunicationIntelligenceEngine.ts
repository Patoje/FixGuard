import axios from 'axios';

export interface GraphQLIntelligence {
  enabled: boolean;
  endpoint: string;
  queries: string[];
  mutations: string[];
  types: string[];
}

export interface WebSocketIntelligence {
  detected: boolean;
  urls: string[];
  namespaces: string[];
}

export interface CommunicationIntelligence {
  graphql: GraphQLIntelligence;
  websockets: WebSocketIntelligence;
}

const GRAPHQL_PATHS = ['/graphql', '/api/graphql', '/v1/graphql'];
const INTROSPECTION_QUERY = `{"query":"query IntrospectionQuery { __schema { queryType { name fields { name } } mutationType { name fields { name } } types { name kind } } }"}`;

export class CommunicationIntelligenceEngine {
  static async analyze(targetUrl: string, html: string, jsFiles: string[]): Promise<CommunicationIntelligence> {
    const intel: CommunicationIntelligence = {
      graphql: { enabled: false, endpoint: '', queries: [], mutations: [], types: [] },
      websockets: { detected: false, urls: [], namespaces: [] }
    };

    const baseUrl = new URL(targetUrl).origin;

    // --- GRAPHQL RECON ---
    // Buscar si hay pistas de GraphQL en el HTML o JS antes de escanear a ciegas
    const allText = html + ' ' + jsFiles.join(' ');
    
    for (const path of GRAPHQL_PATHS) {
      try {
        const endpoint = `${baseUrl}${path}`;
        const response = await axios.post(endpoint, INTROSPECTION_QUERY, {
          headers: { 'Content-Type': 'application/json' },
          timeout: 4000
        });

        if (response.data?.data?.__schema) {
          const schema = response.data.data.__schema;
          intel.graphql.enabled = true;
          intel.graphql.endpoint = endpoint;

          // Extraer Queries
          if (schema.queryType?.fields) {
            intel.graphql.queries = schema.queryType.fields.map((f: any) => f.name);
          }

          // Extraer Mutations
          if (schema.mutationType?.fields) {
            intel.graphql.mutations = schema.mutationType.fields.map((f: any) => f.name);
          }

          // Extraer Object Types personalizados (Ignorando los de sistema como __Schema)
          if (schema.types) {
            intel.graphql.types = schema.types
              .filter((t: any) => t.kind === 'OBJECT' && !t.name.startsWith('__'))
              .map((t: any) => t.name);
          }
          break; // Si ya encontramos uno que responde a la introspección, terminamos
        }
      } catch (e) {
        // Ignorar
      }
    }

    // --- WEBSOCKET RECON ---
    const wsRegex = /wss?:\/\/[^\s"'`]+/g;
    for (const match of allText.matchAll(wsRegex)) {
      intel.websockets.detected = true;
      if (!intel.websockets.urls.includes(match[0])) {
        intel.websockets.urls.push(match[0]);
      }
    }

    // Si no encontramos URLs completas pero sí referencias a socket.io o pushover
    if (allText.includes('socket.io') || allText.includes('new WebSocket')) {
      intel.websockets.detected = true;
    }

    // Intentar extraer namespaces comunes de socket.io si existen
    const nsRegex = /io\(['"](\/[a-zA-Z0-9_-]+)['"]/g;
    for (const match of allText.matchAll(nsRegex)) {
      if (!intel.websockets.namespaces.includes(match[1])) {
         intel.websockets.namespaces.push(match[1]);
      }
    }

    return intel;
  }
}
