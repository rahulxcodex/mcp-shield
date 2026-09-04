import { SecurityCommandIR, SecurityActionIR } from '../ir-types';

export class BashIRParser {
  public static parse(command: string): SecurityCommandIR {
    const actions: SecurityActionIR[] = [];
    const normalized = command.trim();

    // 1. Filesystem: Destructive rm
    if (/\brm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+([^\s]+)/.test(normalized) || /\brm\s+-[a-zA-Z]*f[a-zA-Z]*r?\s+([^\s]+)/.test(normalized)) {
      const match = normalized.match(/\brm\s+-[a-zA-Z]*\s+([^\s]+)/);
      const targetPath = match ? match[1] : '/';
      const isRoot = targetPath === '/' || targetPath === '/*' || targetPath === '~';
      actions.push({
        type: 'DELETE_FILE',
        path: targetPath,
        rootOrSystem: isRoot,
        recursive: true,
        rawSnippet: match ? match[0] : 'rm -rf'
      });
    }

    // 2. Filesystem: Reads (cat, less, more, head, tail)
    const readMatch = normalized.match(/\b(?:cat|less|more|head|tail|view)\s+([^\s|;&]+)/);
    if (readMatch) {
      const p = readMatch[1];
      const isSensitivePath = /(?:^|[\\/])(?:\.env|passwd|shadow|sudoers|id_rsa|id_ed25519|credentials|secrets?)(?:[\\/.]|$)/i.test(p);
      actions.push({
        type: 'READ_FILE',
        path: p,
        sensitive: isSensitivePath,
        rawSnippet: readMatch[0]
      });
    }

    // 3. Network / Egress: curl, wget, nc, fetch
    const netMatch = normalized.match(/\b(?:curl|wget|nc|netcat)\s+([^\s|;&]+)/);
    if (netMatch) {
      actions.push({
        type: 'NETWORK_REQUEST',
        destination: netMatch[1],
        rawSnippet: netMatch[0]
      });
    }

    // 4. Base64 / Encoding
    if (/\bbase64\s+-d\b/.test(normalized) || /\bopenssl\s+enc\b/.test(normalized)) {
      actions.push({
        type: 'ENCODE_DECODE',
        algorithm: 'BASE64',
        direction: 'DECODE',
        rawSnippet: 'base64 -d'
      });
    }

    // 5. Privilege Escalation (sudo, doas, su)
    if (/\b(?:sudo|doas|su)\b/.test(normalized)) {
      actions.push({
        type: 'PRIVILEGE_ESCALATION',
        method: 'sudo/su privilege escalation',
        rawSnippet: normalized
      });
    }

    return {
      interpreter: 'BASH',
      rawCommand: command,
      normalizedCommand: normalized,
      actions
    };
  }
}
