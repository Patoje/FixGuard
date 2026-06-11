export interface ServerActionsIntelligence {
  extractedActionsCount: number;
  actions: Array<{
    id: string;
    context?: string;
  }>;
}

export class ServerActionsEngine {
  // Patrones comunes para identificar Server Actions en Next.js App Router compilado
  // Busca asignaciones del tipo: $$ACTION_0="d7f3...", action_id="...", etc.
  private static ACTION_PATTERNS = [
    // Next.js >= 14 pattern (ej: registerServerReference(..., "d7f3...", ...))
    /registerServerReference\([^,]+,\s*["']([a-f0-9]{40}|[a-zA-Z0-9_-]{20,})["']/g,
    // Variable assignment (ej: const $$ACTION_1 = "d7f3...")
    /(?:\$\$ACTION_[a-zA-Z0-9_]+|actionId|action_id)\s*[:=]\s*["']([a-f0-9]{40}|[a-zA-Z0-9_-]{20,})["']/g,
    // Inline action hash in fetch calls or Next-Action headers
    /["']Next-Action["']\s*:\s*["']([a-f0-9]{40}|[a-zA-Z0-9_-]{20,})["']/gi
  ];

  static analyze(jsCodes: string[]): ServerActionsIntelligence {
    const intel: ServerActionsIntelligence = {
      extractedActionsCount: 0,
      actions: []
    };

    const foundActions = new Set<string>();

    console.log(`[ServerActionsEngine] Escaneando ${jsCodes.length} chunks de JS buscando Hashes de Server Actions...`);

    for (const code of jsCodes) {
      for (const pattern of this.ACTION_PATTERNS) {
        let match;
        while ((match = pattern.exec(code)) !== null) {
          const actionId = match[1];
          if (actionId && !foundActions.has(actionId)) {
            foundActions.add(actionId);
            
            // Intentar extraer algo de contexto cercano (30 caracteres antes)
            const contextStart = Math.max(0, match.index - 30);
            const contextSnippet = code.substring(contextStart, match.index).replace(/\n/g, ' ').trim();
            
            intel.actions.push({
              id: actionId,
              context: contextSnippet ? `...${contextSnippet}` : undefined
            });
            console.log(`[ServerActionsEngine] 🎯 CRÍTICO: Server Action descubierta! ID: ${actionId.substring(0, 8)}...`);
          }
        }
      }
    }

    intel.extractedActionsCount = foundActions.size;
    return intel;
  }
}
