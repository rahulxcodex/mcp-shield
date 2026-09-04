import { AttackCorpusRegistry, AttackCorpusEntry, ExpectedDecision } from '../attack-corpus';

export type MutationFamily =
  | 'URL_ENCODING'
  | 'DOUBLE_URL_ENCODING'
  | 'UNICODE_CONFUSABLES'
  | 'ZERO_WIDTH_CHARS'
  | 'QUOTE_MUTATION'
  | 'ESCAPE_MUTATION'
  | 'VARIABLE_EXPANSION'
  | 'ENVIRONMENT_SUBSTITUTION'
  | 'BASE64_ENCODING'
  | 'HEX_ENCODING'
  | 'NESTED_SHELL'
  | 'PIPELINE_MUTATION'
  | 'ARGUMENT_SPLITTING'
  | 'WHITESPACE_MUTATION'
  | 'CASE_MUTATION'
  | 'PATH_TRAVERSAL_MUTATION'
  | 'IP_REPRESENTATION_MUTATION';

export interface GeneratedAdversarialAttack {
  id: string;
  seedId: string;
  family: MutationFamily;
  description: string;
  originalPayload: any;
  mutatedPayload: any;
  mcpRequest: {
    jsonrpc: '2.0';
    id: string | number;
    method: string;
    params: Record<string, any>;
  };
  expectedDecision: ExpectedDecision;
}

export class AdversarialAttackGenerator {
  /**
   * Confusable mapping for Unicode mutations
   */
  private static readonly CONFUSABLES: Record<string, string> = {
    'c': 'с', // Cyrillic Small Letter Es
    'a': 'а', // Cyrillic Small Letter A
    'o': 'о', // Cyrillic Small Letter O
    'e': 'е', // Cyrillic Small Letter Ie
    'p': 'р', // Cyrillic Small Letter Er
    's': 'ѕ', // Cyrillic Small Letter Dze
    'x': 'х', // Cyrillic Small Letter Ha
    'y': 'у', // Cyrillic Small Letter U
    'i': 'і', // Cyrillic Small Letter Byelorussian-Ukrainian I
    'j': 'ј'  // Cyrillic Small Letter Je
  };

  /**
   * Zero-width character insertions
   */
  private static readonly ZERO_WIDTH_CHARS = ['\u200B', '\u200C', '\u200D', '\uFEFF'];

  /**
   * Mutates a string or command using a specific mutation family
   */
  public static mutatePayload(input: string, family: MutationFamily): string {
    switch (family) {
      case 'URL_ENCODING':
        return encodeURIComponent(input);

      case 'DOUBLE_URL_ENCODING':
        return encodeURIComponent(encodeURIComponent(input));

      case 'UNICODE_CONFUSABLES':
        return input
          .split('')
          .map(char => this.CONFUSABLES[char.toLowerCase()] || char)
          .join('');

      case 'ZERO_WIDTH_CHARS': {
        const zw = this.ZERO_WIDTH_CHARS[0];
        // Insert zero width space inside command keywords
        return input.split('').join(zw);
      }

      case 'QUOTE_MUTATION': {
        // e.g. cat /etc/passwd -> c""a''t ""/e't'c/p""a's'swd
        return input
          .split(' ')
          .map(token => {
            if (token.length > 2) {
              const mid = Math.floor(token.length / 2);
              return `${token.slice(0, mid)}""''${token.slice(mid)}`;
            }
            return token;
          })
          .join(' ');
      }

      case 'ESCAPE_MUTATION': {
        // e.g. rm -rf / -> r\m -\r\f \/
        return input
          .split('')
          .map(c => (c >= 'a' && c <= 'z' ? `\\${c}` : c))
          .join('');
      }

      case 'VARIABLE_EXPANSION': {
        // e.g. /etc/passwd -> $u/etc/passwd where u=""
        return `u="" && ${input.replace(/\//g, '$u/')}`;
      }

      case 'ENVIRONMENT_SUBSTITUTION': {
        // cmd.exe %COMSPEC% style or %PATH% substring
        return input.replace(/curl/gi, '%COMSPEC:~0,1%url');
      }

      case 'BASE64_ENCODING': {
        const b64 = Buffer.from(input, 'utf8').toString('base64');
        return `echo ${b64} | base64 -d | bash`;
      }

      case 'HEX_ENCODING': {
        const hex = Buffer.from(input, 'utf8').toString('hex');
        return `echo -e $(echo "${hex}" | sed 's/../\\\\x&/g') | bash`;
      }

      case 'NESTED_SHELL': {
        return `sh -c "bash -c \\"${input.replace(/"/g, '\\"')}\\""`;
      }

      case 'PIPELINE_MUTATION': {
        return `true | true || ${input}`;
      }

      case 'ARGUMENT_SPLITTING': {
        // e.g. -rf -> -r -f
        return input.replace(/-([a-zA-Z]{2,})/g, (_, flags) => {
          return flags.split('').map((f: string) => `-${f}`).join(' ');
        });
      }

      case 'WHITESPACE_MUTATION': {
        // Tabs, multiple spaces, ${IFS}
        return input.replace(/\s+/g, '\t  \t');
      }

      case 'CASE_MUTATION': {
        return input
          .split('')
          .map((c, i) => (i % 2 === 0 ? c.toUpperCase() : c.toLowerCase()))
          .join('');
      }

      case 'PATH_TRAVERSAL_MUTATION': {
        return input
          .replace(/\/etc\/passwd/g, '/var/log/../../etc/passwd')
          .replace(/C:\\Windows/gi, 'C:\\Users\\..\\Windows');
      }

      case 'IP_REPRESENTATION_MUTATION': {
        // 127.0.0.1 -> 0x7f000001, 2130706433, 0177.0.0.1, [::ffff:127.0.0.1]
        return input
          .replace(/127\.0\.0\.1/g, '0x7f.0.0.1')
          .replace(/169\.254\.169\.254/g, '0xa9fe.0xa9fe');
      }

      default:
        return input;
    }
  }

  /**
   * Generates adversarial attack corpus from attack seeds
   */
  public static generateAdversarialSuite(seedCount: number = 20): GeneratedAdversarialAttack[] {
    const seeds = AttackCorpusRegistry.getAllAttacks();
    const targetSeeds = seeds.slice(0, seedCount);
    const families: MutationFamily[] = [
      'URL_ENCODING',
      'DOUBLE_URL_ENCODING',
      'UNICODE_CONFUSABLES',
      'ZERO_WIDTH_CHARS',
      'QUOTE_MUTATION',
      'ESCAPE_MUTATION',
      'VARIABLE_EXPANSION',
      'BASE64_ENCODING',
      'NESTED_SHELL',
      'PIPELINE_MUTATION',
      'ARGUMENT_SPLITTING',
      'WHITESPACE_MUTATION',
      'CASE_MUTATION',
      'PATH_TRAVERSAL_MUTATION',
      'IP_REPRESENTATION_MUTATION'
    ];

    const generated: GeneratedAdversarialAttack[] = [];

    for (const seed of targetSeeds) {
      const payloadStr = typeof seed.payload === 'string'
        ? seed.payload
        : (seed.payload?.params?.arguments?.command || seed.payload?.params?.arguments?.cmd || JSON.stringify(seed.payload));

      for (const family of families) {
        const mutatedStr = this.mutatePayload(payloadStr, family);

        const mcpRequest = {
          jsonrpc: '2.0' as const,
          id: `gen-${seed.attack_id}-${family}`,
          method: seed.payload?.method || 'tools/call',
          params: {
            name: seed.tool || 'bash',
            arguments: {
              command: mutatedStr,
              path: mutatedStr,
              input: mutatedStr
            }
          }
        };

        generated.push({
          id: `ADV-${seed.attack_id}-${family}`,
          seedId: seed.attack_id,
          family,
          description: `Generated ${family} variant of ${seed.attack_variant}`,
          originalPayload: seed.payload,
          mutatedPayload: mutatedStr,
          mcpRequest,
          expectedDecision: seed.expected_decision || 'BLOCK'
        });
      }
    }

    return generated;
  }
}
