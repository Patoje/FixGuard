import type { CapabilityRequest, ExecutionRequest } from '../core/ExecutionContracts';
import type { ToolAdapter, ValidationResult } from './ToolAdapter';
import * as os from 'os';

export class HttpxAdapter implements ToolAdapter {
  readonly capability = 'http_probe';

  prepare(request: CapabilityRequest): ExecutionRequest {
    const targetUri = request.target.uri;

    // Extend PATH to support Go tools typical in security tooling
    const homedir = os.homedir();
    const extraPaths = [
      `${homedir}/go/bin`,
      `${homedir}/bin`,
      `${homedir}/.local/bin`,
    ];
    const separator = process.platform === 'win32' ? ';' : ':';
    const currentPath = process.env.PATH || '';
    
    const toAdd = extraPaths.filter(p => !currentPath.includes(p));
    const extendedPath = toAdd.length > 0 
      ? `${currentPath}${separator}${toAdd.join(separator)}` 
      : currentPath;

    return {
      binary: 'httpx',
      args: [
        '-u', targetUri,
        '-json',
        '-silent',
        '-status-code',
        '-title',
        '-web-server',
        '-tech-detect',
        '-follow-redirects',
        '-timeout', '10'
      ],
      env: { PATH: extendedPath },
      timeoutMs: 60_000
    };
  }

  validate(config: Record<string, unknown>, targetUri: string): ValidationResult {
    const errors: string[] = [];
    if (!targetUri || targetUri.trim() === '') {
      errors.push('Target URI is required');
      return { isValid: false, errors };
    }

    // Reject shell/control characters, newlines, and whitespace
    if (/[\s\n\r&|;$`><\\]/.test(targetUri)) {
      errors.push('Target URI contains invalid characters');
      return { isValid: false, errors };
    }

    try {
      if (targetUri.startsWith('http://') || targetUri.startsWith('https://')) {
        new URL(targetUri); // Throws if invalid URL
      } else {
        // Validate as basic hostname
        if (!/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(targetUri)) {
          errors.push('Target URI is not a valid hostname or URL');
        }
      }
    } catch (e) {
      errors.push('Target URI is not a valid URL');
    }

    return {
      isValid: errors.length === 0,
      errors
    };
  }
}
