import axios from 'axios';

export class ActiveSecretValidator {
  /**
   * Intenta validar un secreto haciéndole un ping seguro a la API del proveedor.
   * @returns true si el token es VÁLIDO (Crítico).
   *          false si el token está REVOCADO o es inválido.
   *          null si el proveedor no está soportado o hubo un error de red y no se puede confirmar.
   */
  public static async validate(type: string, secret: string): Promise<boolean | null> {
    try {
      if (type.includes('GitHub')) {
        return await this.validateGitHub(secret);
      }
      if (type.includes('Stripe')) {
        return await this.validateStripe(secret);
      }
      if (type.includes('Slack')) {
        return await this.validateSlack(secret);
      }
      if (type.includes('OpenAI')) return await this.validateOpenAI(secret);
      if (type.includes('Anthropic')) return await this.validateAnthropic(secret);
      if (type.includes('Google') || type.includes('Gemini')) return await this.validateGemini(secret);
      if (type.includes('Hugging Face')) return await this.validateHuggingFace(secret);
      if (type.includes('Square')) return await this.validateSquare(secret);
      if (type.includes('Supabase')) return await this.validateSupabase(secret);
      if (type.includes('Discord')) return await this.validateDiscord(secret);
      if (type.includes('WhatsApp') || type.includes('Meta')) return await this.validateWhatsApp(secret);
      if (type.includes('Mapbox')) return await this.validateMapbox(secret);
      if (type.includes('Cloudinary')) return await this.validateCloudinary(secret);
      if (type.includes('Mailgun')) return await this.validateMailgun(secret);

      return null;
    } catch (error) {
      console.warn(`[ActiveSecretValidator] Falló la validación para ${type}:`, error);
      return null;
    }
  }

  private static async validateGitHub(token: string): Promise<boolean | null> {
    try {
      const res = await axios.get('https://api.github.com/user', {
        headers: { Authorization: `Bearer ${token}` },
        validateStatus: () => true,
        timeout: 5000
      });
      // 200 OK -> Válido
      // 403 Forbidden (con mensaje de scope/SSO) -> Válido
      // 401 Unauthorized -> Inválido/Revocado
      if (res.status === 401) return false;
      if (res.status === 200 || res.status === 403) return true;
      return null;
    } catch (e) {
      return null;
    }
  }

  private static async validateStripe(token: string): Promise<boolean | null> {
    try {
      const res = await axios.get('https://api.stripe.com/v1/charges', {
        headers: { Authorization: `Bearer ${token}` },
        validateStatus: () => true,
        timeout: 5000
      });
      if (res.status === 401) return false;
      if (res.status === 200 || res.status === 403) return true;
      return null;
    } catch (e) {
      return null;
    }
  }

  private static async validateSlack(token: string): Promise<boolean | null> {
    try {
      const res = await axios.post('https://slack.com/api/auth.test', {}, {
        headers: { Authorization: `Bearer ${token}` },
        validateStatus: () => true,
        timeout: 5000
      });
      if (res.status === 200 && res.data) {
        if (res.data.ok === true) return true;
        if (res.data.error === 'invalid_auth' || res.data.error === 'account_inactive') return false;
      }
      return null;
    } catch (e) {
      return null;
    }
  }

  // --- Inteligencia Artificial ---
  private static async validateOpenAI(token: string): Promise<boolean | null> {
    try {
      const res = await axios.get('https://api.openai.com/v1/models', {
        headers: { Authorization: `Bearer ${token}` }, validateStatus: () => true, timeout: 5000
      });
      if (res.status === 401) return false;
      if (res.status === 200) return true;
      return null;
    } catch (e) { return null; }
  }

  private static async validateAnthropic(token: string): Promise<boolean | null> {
    try {
      const res = await axios.post('https://api.anthropic.com/v1/messages', {}, {
        headers: { 'x-api-key': token, 'anthropic-version': '2023-06-01' }, validateStatus: () => true, timeout: 5000
      });
      if (res.status === 401) return false;
      if (res.status === 400 || res.status === 200) return true; // 400 is bad request (body missing), meaning auth passed
      return null;
    } catch (e) { return null; }
  }

  private static async validateGemini(token: string): Promise<boolean | null> {
    try {
      const res = await axios.get(`https://generativelanguage.googleapis.com/v1beta/models?key=${token}`, {
        validateStatus: () => true, timeout: 5000
      });
      if (res.status === 400 || res.status === 403) return false; // Usually bad key
      if (res.status === 200) return true;
      return null;
    } catch (e) { return null; }
  }

  private static async validateHuggingFace(token: string): Promise<boolean | null> {
    try {
      const res = await axios.get('https://huggingface.co/api/whoami-v2', {
        headers: { Authorization: `Bearer ${token}` }, validateStatus: () => true, timeout: 5000
      });
      if (res.status === 401) return false;
      if (res.status === 200) return true;
      return null;
    } catch (e) { return null; }
  }

  // --- Pagos ---
  private static async validateSquare(token: string): Promise<boolean | null> {
    try {
      const res = await axios.get('https://connect.squareup.com/v2/locations', {
        headers: { Authorization: `Bearer ${token}` }, validateStatus: () => true, timeout: 5000
      });
      if (res.status === 401) return false;
      if (res.status === 200 || res.status === 403) return true;
      return null;
    } catch (e) { return null; }
  }

  // --- BaaS ---
  private static async validateSupabase(secretStr: string): Promise<boolean | null> {
     // secretStr podría ser la URL. En un escaneo real deberíamos capturar la URL + la Anon Key juntas.
     // Por ahora, como es solo la URL, reportamos nulo (validación pasiva)
     return null;
  }

  // --- Comunicaciones y Media ---
  private static async validateDiscord(token: string): Promise<boolean | null> {
    try {
      const res = await axios.get('https://discord.com/api/v10/users/@me', {
        headers: { Authorization: `Bot ${token}` }, validateStatus: () => true, timeout: 5000
      });
      if (res.status === 401) return false;
      if (res.status === 200) return true;
      return null;
    } catch (e) { return null; }
  }

  private static async validateWhatsApp(token: string): Promise<boolean | null> {
    try {
      const res = await axios.get(`https://graph.facebook.com/v19.0/me?access_token=${token}`, {
        validateStatus: () => true, timeout: 5000
      });
      if (res.data && res.data.error && res.data.error.code === 190) return false; // Invalid token
      if (res.status === 200) return true;
      return null;
    } catch (e) { return null; }
  }

  private static async validateMapbox(token: string): Promise<boolean | null> {
    try {
      const res = await axios.get(`https://api.mapbox.com/tokens/v2?access_token=${token}`, {
        validateStatus: () => true, timeout: 5000
      });
      if (res.status === 401) return false;
      if (res.status === 200) return true;
      return null;
    } catch (e) { return null; }
  }

  private static async validateCloudinary(url: string): Promise<boolean | null> {
    try {
      const res = await axios.get(`https://api.cloudinary.com/v1_1/ping`, {
        // Axios no auto-parsea Cloudinary URL scheme, tendríamos que parsearlo a HTTP Basic Auth.
        // Lo dejamos como estático si es muy complejo
        validateStatus: () => true, timeout: 3000
      });
      return null;
    } catch (e) { return null; }
  }

  private static async validateMailgun(token: string): Promise<boolean | null> {
    try {
      const res = await axios.get('https://api.mailgun.net/v3/domains', {
        auth: { username: 'api', password: token }, validateStatus: () => true, timeout: 5000
      });
      if (res.status === 401) return false;
      if (res.status === 200) return true;
      return null;
    } catch (e) { return null; }
  }
}
