export interface WorkflowStep {
  name: string;
  endpoint: string;
  method: string;
  description: string;
}

export interface WorkflowJourney {
  name: string;
  category: string; // "Auth", "Onboarding", "Billing", "Core"
  steps: WorkflowStep[];
  confidence: number;
}

export class WorkflowReconstructionEngine {
  
  /**
   * Analiza rutas descubiertas para inferir secuencias funcionales de negocio (Workflows).
   */
  public static analyze(endpoints: string[]): WorkflowJourney[] {
    const journeys: WorkflowJourney[] = [];
    
    // Heurísticas de flujos conocidos
    const authFlow = this.extractAuthFlow(endpoints);
    if (authFlow && authFlow.steps.length > 0) {
      journeys.push(authFlow);
    }

    const billingFlow = this.extractBillingFlow(endpoints);
    if (billingFlow && billingFlow.steps.length > 0) {
      journeys.push(billingFlow);
    }
    
    // Inferir flujos de negocio CORE dinámicos agrupando por prefijos base comunes
    const coreFlows = this.extractDynamicCoreFlows(endpoints);
    journeys.push(...coreFlows);

    return journeys;
  }

  private static extractAuthFlow(endpoints: string[]): WorkflowJourney | null {
    const authEndpoints = endpoints.filter(e => {
      const lower = e.toLowerCase();
      return lower.includes('login') || lower.includes('signin') || 
             lower.includes('signup') || lower.includes('register') || 
             lower.includes('auth') || lower.includes('oauth') || lower.includes('mfa');
    });

    if (authEndpoints.length === 0) return null;

    const steps: WorkflowStep[] = [];
    
    // Intentar ordenar lógicamente: Register -> Login -> MFA -> Refresh
    const register = authEndpoints.find(e => e.toLowerCase().includes('register') || e.toLowerCase().includes('signup'));
    if (register) steps.push({ name: 'User Registration', endpoint: register, method: 'POST', description: 'Creación de nueva identidad.' });

    const login = authEndpoints.find(e => e.toLowerCase().includes('login') || e.toLowerCase().includes('signin'));
    if (login) steps.push({ name: 'Authentication', endpoint: login, method: 'POST', description: 'Validación de credenciales.' });

    const mfa = authEndpoints.find(e => e.toLowerCase().includes('mfa') || e.toLowerCase().includes('2fa'));
    if (mfa) steps.push({ name: 'Multi-Factor Auth', endpoint: mfa, method: 'POST', description: 'Segundo factor de autenticación.' });

    // Si no encontramos un orden exacto pero hay endpoints de auth, listarlos como un pool de autenticación
    if (steps.length === 0) {
      authEndpoints.forEach((e, i) => {
        steps.push({ name: `Auth Action ${i+1}`, endpoint: e, method: 'ANY', description: 'Punto de entrada de autenticación.' });
      });
    }

    return {
      name: 'Authentication Journey',
      category: 'Auth',
      steps,
      confidence: 0.85
    };
  }

  private static extractBillingFlow(endpoints: string[]): WorkflowJourney | null {
    const billingEndpoints = endpoints.filter(e => {
      const lower = e.toLowerCase();
      return lower.includes('billing') || lower.includes('checkout') || 
             lower.includes('payment') || lower.includes('stripe') || lower.includes('invoice');
    });

    if (billingEndpoints.length === 0) return null;

    return {
      name: 'Billing & Checkout Flow',
      category: 'Billing',
      steps: billingEndpoints.map((e, i) => ({
        name: `Billing Step ${i+1}`,
        endpoint: e,
        method: 'POST/GET',
        description: 'Procesamiento de pagos y suscripciones.'
      })),
      confidence: 0.8
    };
  }

  private static extractDynamicCoreFlows(endpoints: string[]): WorkflowJourney[] {
    const journeys: WorkflowJourney[] = [];
    // Agrupación heurística de rutas RESTful en "Workflows de CRUD"
    
    // Mapeamos los recursos principales
    const resourceMap = new Map<string, string[]>();
    
    endpoints.forEach(url => {
      try {
        const parsedUrl = new URL(url);
        if (parsedUrl.pathname.match(/\.(js|css|png|jpg|jpeg|gif|woff2?|ttf|svg|ico)$/i)) return;
        const segments = parsedUrl.pathname.split('/').filter(p => p.length > 0 && p !== 'api' && p !== 'v1' && p !== 'v2');
        
        if (segments.length > 0) {
          const rootResource = segments[0].toLowerCase();
          // Ignorar los ya procesados
          if (['auth', 'login', 'billing', 'stripe'].includes(rootResource)) return;
          
          if (!resourceMap.has(rootResource)) {
            resourceMap.set(rootResource, []);
          }
          resourceMap.get(rootResource)!.push(url);
        }
      } catch (e) {
        // ignora
      }
    });

    // Convertir recursos con múltiples endpoints en flujos
    for (const [resource, urls] of resourceMap.entries()) {
      if (urls.length >= 2) {
        journeys.push({
          name: `${resource.charAt(0).toUpperCase() + resource.slice(1)} Management Flow`,
          category: 'Core',
          steps: urls.map(u => ({
            name: `Interact with ${resource}`,
            endpoint: u,
            method: 'ANY',
            description: `Acción sobre el recurso ${resource}`
          })),
          confidence: 0.6
        });
      }
    }

    return journeys;
  }
}
