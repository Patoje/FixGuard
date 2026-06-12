export interface ServerActionsIntelligence {
  extractedActionsCount: number;
  actions: Array<{
    id: string;
    framework: 'Next.js' | 'Remix' | 'SvelteKit' | 'Nuxt' | 'tRPC';
    context?: string;
  }>;
}

export class ServerActionsEngine {
  // Patrones comunes para identificar Server Actions en Next.js App Router compilado
  private static NEXTJS_PATTERNS = [
    /registerServerReference\([^,]+,\s*["']([a-f0-9]{40}|[a-zA-Z0-9_-]{20,})["']/g,
    /(?:\$\$ACTION_[a-zA-Z0-9_]+|actionId|action_id)\s*[:=]\s*["']([a-f0-9]{40}|[a-zA-Z0-9_-]{20,})["']/g,
    /["']Next-Action["']\s*:\s*["']([a-f0-9]{40}|[a-zA-Z0-9_-]{20,})["']/gi
  ];

  // Patrones para otros frameworks
  private static REMIX_PATTERNS = [
    /useActionData\([^)]*\)/g,
    /["']_data["']\s*:\s*["']([^"']+)["']/g // _data query param for Remix actions
  ];

  private static SVELTEKIT_PATTERNS = [
    /formaction=["']\?\/([a-zA-Z0-9_-]+)["']/g,
    /["']\?\/([a-zA-Z0-9_-]+)["']/g
  ];

  private static NUXT_PATTERNS = [
    /useFetch\(['"](\/api\/[a-zA-Z0-9_/-]+)['"]/g,
    /\$fetch\(['"](\/api\/[a-zA-Z0-9_/-]+)['"]/g
  ];

  private static TRPC_PATTERNS = [
    /trpc\.useQuery\(\s*\[['"]([a-zA-Z0-9_.-]+)['"]/g,
    /trpc\.useMutation\(\s*\[['"]([a-zA-Z0-9_.-]+)['"]/g,
    /_trpc\/([a-zA-Z0-9_.-]+)/g
  ];

  static analyze(jsCodes: string[]): ServerActionsIntelligence {
    const intel: ServerActionsIntelligence = {
      extractedActionsCount: 0,
      actions: []
    };

    const foundActions = new Set<string>();

    console.log(`[ServerActionsEngine] Escaneando ${jsCodes.length} chunks de JS buscando Hashes de Server Actions...`);

    const frameworks = [
      { name: 'Next.js' as const, patterns: this.NEXTJS_PATTERNS },
      { name: 'Remix' as const, patterns: this.REMIX_PATTERNS },
      { name: 'SvelteKit' as const, patterns: this.SVELTEKIT_PATTERNS },
      { name: 'Nuxt' as const, patterns: this.NUXT_PATTERNS },
      { name: 'tRPC' as const, patterns: this.TRPC_PATTERNS },
    ];

    for (const code of jsCodes) {
      for (const fw of frameworks) {
        for (const pattern of fw.patterns) {
          let match;
          while ((match = pattern.exec(code)) !== null) {
            // El match[1] es nuestro ID o ruta. Si no hay grupo de captura, usamos el match completo.
            const actionId = match[1] || match[0]; 
            
            // Filtramos falsos positivos muy cortos
            if (actionId && actionId.length > 2 && !foundActions.has(`${fw.name}::${actionId}`)) {
              foundActions.add(`${fw.name}::${actionId}`);
              
              const contextStart = Math.max(0, match.index - 30);
              const contextSnippet = code.substring(contextStart, match.index).replace(/\n/g, ' ').trim();
              
              intel.actions.push({
                id: actionId,
                framework: fw.name,
                context: contextSnippet ? `...${contextSnippet}` : undefined
              });
              console.log(`[ServerActionsEngine] 🎯 Acción remota / Endpoint oculto descubierto en ${fw.name}! ID: ${actionId.substring(0, 30)}...`);
            }
          }
        }
      }
    }

    intel.extractedActionsCount = foundActions.size;
    return intel;
  }
}
