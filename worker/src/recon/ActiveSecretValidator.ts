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
}
