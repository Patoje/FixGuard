import axios from 'axios';

export interface BreachResult {
  email: string;
  type: string;
  breach_count: number;
  has_plaintext: boolean;
  high_risk: boolean;
  breach_names: string[];
}

export class BreachAnalyzer {
  /**
   * Consulta HIBP para los emails recolectados.
   * Utiliza HIBP_API_KEY si está disponible, sino asume uso público (que puede estar bloqueado o requerir rate limit).
   */
  public static async runBreachAnalysis(emails: string[]): Promise<BreachResult[]> {
    const results: BreachResult[] = [];
    const uniqueEmails = [...new Set(emails)];
    const apiKey = process.env.HIBP_API_KEY;

    if (uniqueEmails.length === 0) return results;

    console.log(`[BreachAnalyzer] Analizando ${uniqueEmails.length} emails en HaveIBeenPwned...`);

    const rateLimitDelay = apiKey ? 500 : 1600; // API pública requiere 1500ms entre requests según su documentación antigua (aunque ahora es de pago en su mayoría, la implementamos con delay por seguridad).

    for (const email of uniqueEmails) {
      try {
        const headers: Record<string, string> = {
          'User-Agent': 'FixGuard-Scanner-Bot'
        };
        if (apiKey) {
          headers['hibp-api-key'] = apiKey;
        }

        const url = `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}`;
        const response = await axios.get(url, {
          headers,
          validateStatus: (status) => status === 200 || status === 404
        });

        if (response.status === 200 && Array.isArray(response.data)) {
          const breaches = response.data;
          results.push({
            email,
            type: 'employee_email',
            breach_count: breaches.length,
            has_plaintext: breaches.some((b: any) => b.DataClasses?.includes('Passwords')),
            high_risk: breaches.length >= 3,
            breach_names: breaches.map((b: any) => b.Name)
          });
        } else if (response.status === 404) {
          // Email no vulnerado
          results.push({
            email,
            type: 'employee_email',
            breach_count: 0,
            has_plaintext: false,
            high_risk: false,
            breach_names: []
          });
        }

        // Respetar rate limit
        await new Promise(resolve => setTimeout(resolve, rateLimitDelay));
      } catch (e: any) {
        console.warn(`[BreachAnalyzer] Error consultando email ${email}: ${e.message}`);
        // Add minimal empty result to avoid losing the email entirely
        results.push({
          email,
          type: 'employee_email',
          breach_count: 0,
          has_plaintext: false,
          high_risk: false,
          breach_names: []
        });
      }
    }

    const breachedCount = results.filter(r => r.breach_count > 0).length;
    console.log(`[BreachAnalyzer] Finalizado. Encontrados ${breachedCount} emails comprometidos.`);
    
    return results;
  }
}
