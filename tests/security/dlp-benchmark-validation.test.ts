import { Sanitizer } from '../../src/security/sanitizer';

describe('Independent DLP Benchmark & Held-Out Corpus Validation (Roadmap P2.5)', () => {
  let sanitizer: Sanitizer;

  beforeEach(() => {
    sanitizer = new Sanitizer({
      maskStyle: 'token',
      highEntropyCheck: true,
      entropyThreshold: 4.5
    });
  });

  describe('True Positives (Known Secret Test Corpus)', () => {
    const awsKey = ['AK', 'IA', 'IOSFODNN7EXAMPLE'].join('');
    const ghpToken = ['gh', 'p_', '0123456789abcdefghijklmnopqrstuvwxyzAB'].join('');
    const ghuToken = ['gh', 'u_', 'abcdefghijklmnopqrstuvwxyz0123456789ABCD'].join('');
    const ghsToken = ['gh', 's_', '0123456789abcdefghijklmnopqrstuvwxyzAB'].join('');
    const ghrToken = ['gh', 'r_', '0123456789abcdefghijklmnopqrstuvwxyzAB'].join('');
    const xoxbToken = ['xo', 'xb-', '123456789012-1234567890123-4jc9V8g7U9Qz6X5W4Y3Z2A1B'].join('');
    const xoxpToken = ['xo', 'xp-', '123456789012-1234567890123-4jc9V8g7U9Qz6X5W4Y3Z2A1B'].join('');
    const stripeKey = ['sk', '_live_', '51AbcDefGhIjKlMnOpQrStUvWxYz012'].join('');

    const truePositiveCorpus: Array<{ label: string; payload: string; tokenSnippet: string }> = [
      { label: 'AWS Access Key ID', payload: `Configuring AWS: ${awsKey} for account access`, tokenSnippet: awsKey },
      { label: 'GitHub PAT (ghp_)', payload: `git remote set-url origin https://${ghpToken}@github.com/repo`, tokenSnippet: ghpToken },
      { label: 'GitHub User Token (ghu_)', payload: `Session token: ${ghuToken}`, tokenSnippet: ghuToken },
      { label: 'GitHub Server Token (ghs_)', payload: `Webhook bot token: ${ghsToken}`, tokenSnippet: ghsToken },
      { label: 'GitHub Refresh Token (ghr_)', payload: `OAuth refresh: ${ghrToken}`, tokenSnippet: ghrToken },
      { label: 'Slack Bot Token', payload: xoxbToken, tokenSnippet: xoxbToken },
      { label: 'Slack User Token', payload: xoxpToken, tokenSnippet: xoxpToken },
      { label: 'Stripe Secret Key', payload: `Billing config: ${stripeKey}`, tokenSnippet: stripeKey }
    ];

    truePositiveCorpus.forEach(({ label, payload, tokenSnippet }) => {
      it(`redacts ${label} with 100% recall`, () => {
        const res = sanitizer.sanitize(payload);
        expect(res).not.toBe(payload);
        expect(res).toContain('[[SHIELD_SECRET_');
        expect(res).not.toContain(tokenSnippet);
      });
    });
  });

  describe('Structured Data & Embedding Formats', () => {
    const awsKey = ['AK', 'IA', 'IOSFODNN7EXAMPLE'].join('');
    const ghpToken = ['gh', 'p_', '0123456789abcdefghijklmnopqrstuvwxyzAB'].join('');

    it('redacts secrets embedded in JSON documents', () => {
      const jsonPayload = JSON.stringify({
        status: 'success',
        auth: {
          key: awsKey,
          provider: 'aws'
        }
      });
      const res = sanitizer.sanitize(jsonPayload);
      expect(res).toContain('[[SHIELD_SECRET_');
      expect(res).not.toContain(awsKey);
    });

    it('redacts secrets embedded in YAML snippets', () => {
      const yamlPayload = `env:\n  GITHUB_TOKEN: ${ghpToken}\n  PORT: 8080`;
      const res = sanitizer.sanitize(yamlPayload);
      expect(res).toContain('[[SHIELD_SECRET_');
      expect(res).not.toContain(ghpToken);
    });

    it('redacts secrets embedded in URL query parameters', () => {
      const urlPayload = `https://api.example.com/v1/data?api_key=${ghpToken}&format=json`;
      const res = sanitizer.sanitize(urlPayload);
      expect(res).toContain('[[SHIELD_SECRET_');
      expect(res).not.toContain(ghpToken);
    });
  });

  describe('False Positives (Benign Text & Code Snippets)', () => {
    const benignCorpus = [
      'The quick brown fox jumps over the lazy dog.',
      'console.log("Hello from MCP Shield");',
      'const port = process.env.PORT || 3000;',
      'Lorem ipsum dolor sit amet, consectetur adipiscing elit.',
      'SELECT id, name, created_at FROM users WHERE status = "active";'
    ];

    benignCorpus.forEach((text) => {
      it(`preserves benign text without false positive redaction: "${text.slice(0, 30)}..."`, () => {
        const res = sanitizer.sanitize(text);
        expect(res).toBe(text);
        expect(res).not.toContain('[[SHIELD_SECRET_');
      });
    });
  });
});
