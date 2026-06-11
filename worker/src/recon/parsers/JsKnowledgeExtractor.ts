import axios from 'axios';

export interface BusinessDictionary {
  roles: string[];
  entities: string[];
  permissions: string[];
  configFlags: string[];
}

export class JsKnowledgeExtractor {
  static async extractFromJsFiles(jsUrls: string[]): Promise<BusinessDictionary> {
    const dictionary: BusinessDictionary = {
      roles: [],
      entities: [],
      permissions: [],
      configFlags: []
    };

    // Usaremos Sets para evitar duplicados
    const rolesSet = new Set<string>();
    const entitiesSet = new Set<string>();
    const permsSet = new Set<string>();
    const flagsSet = new Set<string>();

    // Regex estructuradas
    const roleRegex = /is(Admin|Staff|Premium|Owner|Manager|User|Moderator)/gi;
    const entityRegex = /(?:get|set|fetch|update|delete|create)(User|Organization|Project|Payment|Subscription|Invoice|Team|Workspace)s?/gi;
    const permRegex = /can(Read|Write|Delete|Manage|Edit|Update|Create)/gi;
    const flagRegex = /(?:ENABLE_|FEATURE_)([A-Z_]+)/g;

    for (const url of jsUrls) {
      try {
        const { data: jsCode } = await axios.get(url, { timeout: 3000 });
        if (typeof jsCode !== 'string') continue;

        let match;
        
        // Roles
        while ((match = roleRegex.exec(jsCode)) !== null) {
          rolesSet.add(match[1].toLowerCase());
        }

        // Entities
        while ((match = entityRegex.exec(jsCode)) !== null) {
          entitiesSet.add(match[1].toLowerCase());
        }

        // Permissions
        while ((match = permRegex.exec(jsCode)) !== null) {
          permsSet.add(match[1].toLowerCase());
        }

        // Feature Flags
        while ((match = flagRegex.exec(jsCode)) !== null) {
          flagsSet.add(match[1]);
        }

      } catch (e) {
        // Ignorar errores de red en archivos individuales
      }
    }

    dictionary.roles = Array.from(rolesSet);
    dictionary.entities = Array.from(entitiesSet);
    dictionary.permissions = Array.from(permsSet);
    dictionary.configFlags = Array.from(flagsSet);

    return dictionary;
  }
}
