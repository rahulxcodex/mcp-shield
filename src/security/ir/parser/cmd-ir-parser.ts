import { SecurityCommandIR, SecurityActionIR } from '../ir-types';

export class CmdIRParser {
  public static parse(command: string): SecurityCommandIR {
    const actions: SecurityActionIR[] = [];
    const normalized = command.trim();

    // 1. Filesystem: del / erase / rmdir / rd
    if (/\b(?:del|erase|rd|rmdir)\b/i.test(normalized)) {
      const isRecursive = /\/[sS]\b/.test(normalized);
      const targetMatch = normalized.match(/\b(?:del|erase|rd|rmdir)\s+(?:[\/a-zA-Z:]+\s+)*([^\s]+)/i);
      const path = targetMatch ? targetMatch[1] : 'unknown';
      const rootOrSystem = /^[C-Z]:\\?(\*)?$/i.test(path) || path === '\\';

      actions.push({
        type: 'DELETE_FILE',
        path,
        rootOrSystem,
        recursive: isRecursive,
        rawSnippet: normalized
      });
    }

    // 2. Filesystem: type
    const typeMatch = normalized.match(/\btype\s+([^\s|;&]+)/i);
    if (typeMatch) {
      const p = typeMatch[1];
      actions.push({
        type: 'READ_FILE',
        path: p,
        sensitive: p.toLowerCase().includes('secret') || p.toLowerCase().includes('pass'),
        rawSnippet: typeMatch[0]
      });
    }

    // 3. Sensitive Environment Variables
    const envMatch = normalized.match(/%([a-zA-Z0-9_]+)%/);
    if (envMatch) {
      const varName = envMatch[1].toLowerCase();
      const isSecret = varName.includes('key') || varName.includes('secret') || varName.includes('token');
      actions.push({
        type: 'ENV_ACCESS',
        variableName: envMatch[1],
        isSecret,
        rawSnippet: envMatch[0]
      });
    }

    // 4. Volume Shadow Copy tampering
    if (/vssadmin\s+delete\s+shadows/i.test(normalized)) {
      actions.push({
        type: 'DESTRUCTION' as any,
        path: 'VolumeShadowCopies',
        rawSnippet: 'vssadmin delete shadows'
      });
    }

    return {
      interpreter: 'CMD',
      rawCommand: command,
      normalizedCommand: normalized,
      actions
    };
  }
}
