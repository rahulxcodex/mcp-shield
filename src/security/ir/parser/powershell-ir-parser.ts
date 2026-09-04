import { SecurityCommandIR, SecurityActionIR } from '../ir-types';

export class PowerShellIRParser {
  public static parse(command: string): SecurityCommandIR {
    const actions: SecurityActionIR[] = [];
    const normalized = command.trim();

    // 1. Filesystem: Remove-Item / del / rm / ri / rmdir
    if (/\b(?:Remove-Item|ri|del|erase|rd|rmdir)\b/i.test(normalized)) {
      const isRecursive = /-(?:Recurse|r)\b/i.test(normalized);
      const isForce = /-(?:Force|f)\b/i.test(normalized);
      const tokens = normalized.split(/\s+/).filter(t => !t.startsWith('-') && !/^(?:Remove-Item|ri|del|erase|rd|rmdir)$/i.test(t));
      const targetPath = tokens.length > 0 ? tokens[0] : 'unknown';
      const rootOrSystem = /^[C-Z]:\\?(\*)?$/i.test(targetPath) || targetPath === '\\' || targetPath === '/' || targetPath === '/*';

      actions.push({
        type: 'DELETE_FILE',
        path: targetPath,
        rootOrSystem,
        recursive: isRecursive,
        rawSnippet: normalized
      });
    }

    // 2. Filesystem: Get-Content / gc / cat / type
    const readMatch = normalized.match(/\b(?:Get-Content|gc|type)\s+(?:-Path\s+)?([^\s|;&]+)/i);
    if (readMatch) {
      const p = readMatch[1];
      const isSensitivePath = /(?:^|[\\/])(?:\.env|password|id_rsa|id_ed25519|credentials|secrets?)(?:[\\/.]|$)/i.test(p);
      actions.push({
        type: 'READ_FILE',
        path: p,
        sensitive: isSensitivePath,
        rawSnippet: readMatch[0]
      });
    }

    // 3. Network: Invoke-WebRequest, Invoke-RestMethod, Net.WebClient
    const netMatch = normalized.match(/\b(?:Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\s+(?:-Uri\s+)?([^\s|;&]+)/i);
    if (netMatch) {
      actions.push({
        type: 'NETWORK_REQUEST',
        destination: netMatch[1],
        rawSnippet: netMatch[0]
      });
    } else if (/DownloadString|DownloadFile/i.test(normalized)) {
      const urlMatch = normalized.match(/['"](https?:\/\/[^'"]+)['"]/i);
      actions.push({
        type: 'NETWORK_REQUEST',
        destination: urlMatch ? urlMatch[1] : 'remote_uri',
        rawSnippet: normalized
      });
    }

    // 4. Base64 / EncodedCommand
    if (/-(?:EncodedCommand|enc|e)\b/i.test(normalized)) {
      const b64Match = normalized.match(/-(?:EncodedCommand|enc|e):?\s*([A-Za-z0-9+/=]+)/i);
      actions.push({
        type: 'ENCODE_DECODE',
        algorithm: 'BASE64',
        direction: 'DECODE',
        payload: b64Match ? b64Match[1] : undefined,
        rawSnippet: b64Match ? b64Match[0] : '-enc'
      });
    }

    // 5. Dynamic Execution: IEX / Invoke-Expression
    if (/\b(?:Invoke-Expression|iex)\b/i.test(normalized)) {
      actions.push({
        type: 'EXECUTE_PROCESS',
        binary: 'powershell_iex',
        arguments: [normalized],
        elevated: true,
        rawSnippet: 'Invoke-Expression'
      });
    }

    return {
      interpreter: 'POWERSHELL',
      rawCommand: command,
      normalizedCommand: normalized,
      actions
    };
  }
}
