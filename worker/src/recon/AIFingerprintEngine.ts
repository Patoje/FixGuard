export interface AIFingerprint {
  detected: boolean;
  providers: string[];
  frameworks: string[];
  features: string[];
}

export class AIFingerprintEngine {
  static analyze(jsCodes: string[], headers: Record<string, string | string[]>): AIFingerprint {
    const fingerprint: AIFingerprint = {
      detected: false,
      providers: [],
      frameworks: [],
      features: []
    };

    const combinedJs = jsCodes.join('\n').toLowerCase();
    
    // Providers
    if (combinedJs.includes('api.openai.com') || combinedJs.includes('openai')) {
      fingerprint.providers.push('OpenAI');
    }
    if (combinedJs.includes('anthropic') || combinedJs.includes('claude')) {
      fingerprint.providers.push('Anthropic');
    }
    if (combinedJs.includes('gemini') || combinedJs.includes('generativelanguage.googleapis.com')) {
      fingerprint.providers.push('Google Gemini');
    }

    // Frameworks
    if (combinedJs.includes('langchain')) {
      fingerprint.frameworks.push('LangChain');
    }
    if (combinedJs.includes('ai/react') || combinedJs.includes('usechat') || combinedJs.includes('usecompletion')) {
      fingerprint.frameworks.push('Vercel AI SDK');
    }
    if (combinedJs.includes('llamaindex')) {
      fingerprint.frameworks.push('LlamaIndex');
    }

    // Features / Patterns
    if (combinedJs.includes('vectorstore') || combinedJs.includes('pinecone') || combinedJs.includes('weaviate')) {
      fingerprint.features.push('Vector Search / RAG');
    }
    if (combinedJs.includes('embedding')) {
      fingerprint.features.push('Embeddings');
    }
    if (combinedJs.includes('streamingtextresponse')) {
      fingerprint.features.push('LLM Streaming');
    }

    // Header checks (sometimes backend proxies expose AI headers)
    const headerStr = JSON.stringify(headers).toLowerCase();
    if (headerStr.includes('x-openai') || headerStr.includes('openai-')) {
      if (!fingerprint.providers.includes('OpenAI')) fingerprint.providers.push('OpenAI');
    }

    if (fingerprint.providers.length > 0 || fingerprint.frameworks.length > 0 || fingerprint.features.length > 0) {
      fingerprint.detected = true;
    }

    // Deduplicate
    fingerprint.providers = Array.from(new Set(fingerprint.providers));
    fingerprint.frameworks = Array.from(new Set(fingerprint.frameworks));
    fingerprint.features = Array.from(new Set(fingerprint.features));

    return fingerprint;
  }
}
