export interface AuthIntelligence {
  mechanisms: string[];
  sessionStorage: boolean;
  localStorage: boolean;
  cookieNames: string[];
}

export class AuthIntelligenceEngine {
  static analyze(jsCodes: string[], headers: Record<string, string | string[]>): AuthIntelligence {
    const auth: AuthIntelligence = {
      mechanisms: [],
      sessionStorage: false,
      localStorage: false,
      cookieNames: []
    };

    const cookieSet = new Set<string>();

    for (const code of jsCodes) {
      if (code.includes('localStorage.setItem(') && (code.includes('token') || code.includes('auth') || code.includes('jwt'))) {
        auth.localStorage = true;
        if (!auth.mechanisms.includes('Client-side JWT / Token Storage')) {
          auth.mechanisms.push('Client-side JWT / Token Storage');
        }
      }
      
      if (code.includes('sessionStorage.')) {
         auth.sessionStorage = true;
      }
      
      // Intentar encontrar nombres de cookies en el JS
      const cookieMatches = code.matchAll(/(?:getCookie|setCookie)\(['"]([a-zA-Z0-9_\-]+)['"]/g);
      for (const match of cookieMatches) {
        cookieSet.add(match[1]);
      }
    }

    // Analizar cabeceras Set-Cookie si existen en el objetivo (normalmente en passive scan)
    const setCookie = headers['set-cookie'];
    if (setCookie) {
      const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
      cookies.forEach(c => {
        const name = c.split('=')[0];
        if (name && !cookieSet.has(name)) cookieSet.add(name);
        
        if (c.toLowerCase().includes('httponly')) {
          if (!auth.mechanisms.includes('HttpOnly Cookies')) auth.mechanisms.push('HttpOnly Cookies');
        }
        if (name.toLowerCase().includes('session') || name.toLowerCase().includes('token')) {
          if (!auth.mechanisms.includes('Session Cookie')) auth.mechanisms.push('Session Cookie');
        }
      });
    }

    auth.cookieNames = Array.from(cookieSet);

    return auth;
  }
}
