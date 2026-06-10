import axios from 'axios';
import { db } from '../db/db';
import { vulnerabilities } from '../db/schema';

const GRAPHQL_PATHS = [
  '/graphql',
  '/api/graphql',
  '/v1/graphql',
  '/v2/graphql'
];

const INTROSPECTION_QUERY = `{"query":"query IntrospectionQuery { __schema { queryType { name } } }"}`;

export async function runGraphqlScan(scanId: number, targetUrl: string) {
  try {
    const baseUrl = new URL(targetUrl).origin;
    let foundVulnerability = false;

    for (const path of GRAPHQL_PATHS) {
      if (foundVulnerability) break;
      
      const endpoint = `${baseUrl}${path}`;
      try {
        const response = await axios.post(endpoint, INTROSPECTION_QUERY, {
          headers: { 'Content-Type': 'application/json' },
          timeout: 4000,
          validateStatus: () => true
        });

        // Si devuelve el esquema, significa que la introspección está habilitada
        if (response.data && response.data.data && response.data.data.__schema) {
          await db.insert(vulnerabilities).values({
            scanId,
            type: 'GRAPHQL_INTROSPECTION_ENABLED',
            severity: 'HIGH',
            description: `Vulnerabilidad ALTA en GraphQL. El endpoint '${endpoint}' permite consultas de Introspección (Introspection). Esto significa que cualquier persona puede descargar el esquema completo de tu API (todas las consultas, mutaciones y tipos de datos), facilitando enormemente encontrar otras vulnerabilidades.`,
            autoFixCode: null,
          });
          foundVulnerability = true;
          break;
        }
      } catch (e) {
        // Ignorar timeouts
      }
    }
  } catch (error) {
    console.error(`[Scan ${scanId}] GraphQL scan error:`, error);
  }
}
