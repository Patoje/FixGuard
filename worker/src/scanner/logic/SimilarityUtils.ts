export class SimilarityUtils {
  /**
   * Compara dos respuestas HTTP (HTML o JSON) y determina si son "estructuralmente idénticas"
   * ignorando tokens CSRF, timestamps, o diferencias ínfimas.
   */
  public static isSimilar(baselineData: any, attackData: any): boolean {
    if (!baselineData || !attackData) return false;

    const baseStr = typeof baselineData === 'string' ? baselineData : JSON.stringify(baselineData);
    const attackStr = typeof attackData === 'string' ? attackData : JSON.stringify(attackData);

    // Si son exactamente iguales, fácil
    if (baseStr === attackStr) return true;

    // Si ambos son JSON (u objetos)
    if (typeof baselineData === 'object' && typeof attackData === 'object') {
      const baseKeys = Object.keys(baselineData).sort().join(',');
      const attackKeys = Object.keys(attackData).sort().join(',');
      // Si tienen exactamente la misma estructura de llaves, asumimos que no hubo filtración
      // de datos nuevos (ej. no se filtró "admin_password").
      if (baseKeys === attackKeys) {
        // Podríamos revisar valores, pero para BOLA/MassAssignment un cambio en la llave
        // es la señal más fuerte. O un cambio radical en la longitud.
        const lengthDiff = Math.abs(baseStr.length - attackStr.length);
        const percentDiff = lengthDiff / baseStr.length;
        if (percentDiff < 0.05) { // Menos de 5% de diferencia
           return true; 
        }
      }
    }

    // Si son HTML, limpiar ruido dinámico (Tokens, timestamps)
    if (typeof baselineData === 'string' && baselineData.includes('<html')) {
       const cleanBase = this.cleanHtml(baseStr);
       const cleanAttack = this.cleanHtml(attackStr);
       
       const lengthDiff = Math.abs(cleanBase.length - cleanAttack.length);
       // Si la longitud varía menos de un 2%, es la misma página (falso positivo)
       if (cleanBase.length > 0 && (lengthDiff / cleanBase.length) < 0.02) {
         return true;
       }
    }

    // Si la diferencia de tamaño es insignificante (< 50 bytes), son lo mismo
    if (Math.abs(baseStr.length - attackStr.length) < 50) {
      return true;
    }

    return false; // Son significativamente diferentes -> ¡Vulnerabilidad posible!
  }

  private static cleanHtml(html: string): string {
    return html
      .replace(/<input[^>]*type=["']?hidden["']?[^>]*>/gi, '') // Quitar CSRF tokens
      .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '') // Quitar scripts dinámicos
      .replace(/\s+/g, ' ') // Normalizar espacios
      .replace(/[0-9]{10,}/g, ''); // Quitar posibles timestamps epoch
  }
}
