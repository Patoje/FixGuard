import axios, { type AxiosRequestConfig, type AxiosResponse } from 'axios';
import { SessionManager } from './SessionManager';
import { IssueManager } from './IssueManager';
import { SimilarityUtils } from './logic/SimilarityUtils';

export interface SmartVector {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  endpoint: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  baselinePayload?: Record<string, any> | string;
  attackPayload: Record<string, any> | string;
  attackType: string;
  customHeaders?: Record<string, string>;
  customEvaluate?: (responseHeaders: Record<string, string>, responseData: any) => boolean;
}

export class AttackExecutor {
  /**
   * Ejecuta un vector de ataque y lo compara contra la línea base.
   */
  public static async executeAndCompare(scanId: number, targetUrl: string, vector: SmartVector) {
    try {
      const authHeaders = await SessionManager.getAuthHeaders(targetUrl);
      
      const configBase: AxiosRequestConfig = {
        url: vector.endpoint,
        method: vector.method,
        headers: {
          ...authHeaders,
          'Content-Type': typeof vector.baselinePayload === 'object' ? 'application/json' : 'application/x-www-form-urlencoded',
          ...(vector.customHeaders || {})
        },
        validateStatus: () => true, // Capturar todos los status sin tirar excepción
        timeout: 10000,
      };

      // 1. Ejecutar baseline (si hay)
      let baselineRes: AxiosResponse | null = null;
      if (vector.baselinePayload !== undefined) {
        // Ejecutar con baselinePayload explícito (puede ser null/object para POST/PUT)
        baselineRes = await axios({
          ...configBase,
          data: vector.baselinePayload,
        }).catch(e => e.response);
      } else {
        // Auto-generar baseline request: hacer GET al targetUrl o al endpoint limpio
        // Para BOLA, endpoint ya está mutado, pero targetUrl es la base limpia
        baselineRes = await axios({
          url: vector.endpoint, // Podríamos usar targetUrl, pero para ser precisos usamos el mismo endpoint pero con GET normal si es posible, o lo dejamos fallar amablemente
          method: 'GET',
          headers: authHeaders,
          validateStatus: () => true,
          timeout: 10000,
        }).catch(e => e.response);
      }

      // 2. Ejecutar ataque
      const attackRes = await axios({
        ...configBase,
        data: vector.attackPayload,
      });

      // 3. Evaluar resultados usando lógica heurística
      let findingConfirmed = false;
      
      if (vector.customEvaluate) {
        findingConfirmed = vector.customEvaluate(attackRes.headers as Record<string, string>, attackRes.data);
      } else {
        findingConfirmed = this.evaluateResponse(baselineRes, attackRes, vector);
      }

      if (findingConfirmed) {
        await IssueManager.reportFinding({
          scanId,
          title: `[${vector.attackType}] ${vector.name}`,
          severity: vector.severity,
          endpoint: vector.endpoint,
          method: vector.method,
          requestRaw: `Metodo: ${vector.method}\nHeaders: ${JSON.stringify(configBase.headers)}\nPayload: ${JSON.stringify(vector.attackPayload)}`,
          responseRaw: `Status: ${attackRes.status}\nHeaders: ${JSON.stringify(attackRes.headers)}\nBody: ${JSON.stringify(attackRes.data).substring(0, 1000)}`,
          payloadUsed: typeof vector.attackPayload === 'string' ? vector.attackPayload : JSON.stringify(vector.attackPayload),
          toolSource: 'FixGuard AttackExecutor'
        });
        return true;
      }

      return false;
    } catch (error) {
      console.error(`[AttackExecutor] Falló la ejecución del vector ${vector.name}:`, error);
      return false;
    }
  }

  /**
   * Lógica interna de comparación inteligente
   */
  private static evaluateResponse(baseline: AxiosResponse | null, attack: AxiosResponse, vector: SmartVector): boolean {
    // Escenario 1: Bypass de Autorización (BFLA)
    // Si la línea base (o un request normal) da 403, y el ataque da 200, es bypass exitoso.
    if (baseline && (baseline.status === 403 || baseline.status === 401)) {
      if (attack.status >= 200 && attack.status < 300) {
        return true;
      }
    }

    // Escenario 2: Mass Assignment o BOLA con éxito de mutación
    if (vector.attackType === 'Mass Assignment' || vector.attackType === 'BOLA') {
       const respStr = JSON.stringify(attack.data);
       if (respStr.includes('"isAdmin":true') || respStr.includes('"role":"admin"')) {
         return true; // Pudo elevar privilegios
       }
       
       if (attack.status >= 200 && attack.status < 300) {
         if (baseline && SimilarityUtils.isSimilar(baseline.data, attack.data)) {
           // Es un falso positivo: la página devolvió 200 pero el contenido es igual (el payload fue ignorado)
           return false;
         }
         // Si cambió estructuralmente, o si no hay baseline y la respuesta es exitosa (sospechoso)
         // Para evitar falsos positivos sin baseline, podríamos ser más estrictos, pero con SimilarityUtils
         // ya filtramos la mayoría de los casos de páginas estáticas.
         return baseline ? true : false; // Si no hay baseline para BOLA, asumimos falso para evitar ruido excesivo
       }
    }

    // Fallback conservador: Para MVP, evitamos tirar falsos positivos por 200 OK genéricos
    // a menos que sea un bypass explícito
    if (vector.attackType === 'Workflow Bypass' && attack.status >= 200 && attack.status < 300) {
       // Si nos saltamos pasos y nos da 200, pero la respuesta es igual al baseline (ej. la misma pantalla de login), falló
       if (baseline && SimilarityUtils.isSimilar(baseline.data, attack.data)) return false;
       return true;
    }

    return false;
  }
}
