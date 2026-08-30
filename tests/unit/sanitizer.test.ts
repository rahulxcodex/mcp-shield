import { SecretSanitizer } from '../../src/security/sanitizer';

describe('SecretSanitizer', () => {
  let sanitizer: SecretSanitizer;

  beforeEach(() => {
    sanitizer = new SecretSanitizer();
  });

  it('should sanitize AWS access keys', () => {
    const payload = 'Here is my key AKIAIOSFODNN7EXAMPLE and more text';
    const sanitized = sanitizer.sanitize(payload);
    expect(sanitized).toMatch(/\[\[SHIELD_SECRET_[0-9a-fA-F-]{36}\]\]/);
    expect(sanitized).not.toContain('AKIAIOSFODNN7EXAMPLE');
  });

  it('should sanitize GitHub PATs', () => {
    const payload = 'Token: ghp_111122223333444455556666777788889999';
    const sanitized = sanitizer.sanitize(payload);
    expect(sanitized).toMatch(/\[\[SHIELD_SECRET_[0-9a-fA-F-]{36}\]\]/);
    expect(sanitized).not.toContain('ghp_111122223333444455556666777788889999');
  });

  it('should sanitize OpenAI keys', () => {
    const payload = 'sk-proj-123456789012345678901234567890';
    const sanitized = sanitizer.sanitize(payload);
    expect(sanitized).toMatch(/\[\[SHIELD_SECRET_[0-9a-fA-F-]{36}\]\]/);
    expect(sanitized).not.toContain('sk-proj-123456789012345678901234567890');
  });
  
  it('should sanitize SSH private keys', () => {
    const payload = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----';
    const sanitized = sanitizer.sanitize(payload);
    expect(sanitized).toMatch(/\[\[SHIELD_SECRET_[0-9a-fA-F-]{36}\]\]/);
    expect(sanitized).not.toContain('MIIEowIBAAKCAQEA');
  });

  it('should replace identical secrets with the same token (bijective replacement)', () => {
    const payload = 'Key1: ghp_111122223333444455556666777788889999, Key2: ghp_111122223333444455556666777788889999';
    const sanitized = sanitizer.sanitize(payload);
    
    // Extract tokens
    const matches = sanitized.match(/\[\[SHIELD_SECRET_[0-9a-fA-F-]{36}\]\]/g);
    expect(matches?.length).toBe(2);
    expect(matches![0]).toBe(matches![1]); // Identical tokens
  });

  it('should replace different secrets with different tokens', () => {
    const payload = 'Key1: ghp_111122223333444455556666777788889999, AWS: AKIAIOSFODNN7EXAMPLE';
    const sanitized = sanitizer.sanitize(payload);
    
    const matches = sanitized.match(/\[\[SHIELD_SECRET_[0-9a-fA-F-]{36}\]\]/g);
    expect(matches?.length).toBe(2);
    expect(matches![0]).not.toBe(matches![1]); // Different tokens
  });

  it('should restore a tokenized payload back to original', () => {
    const payload = 'Key1: ghp_111122223333444455556666777788889999';
    const sanitized = sanitizer.sanitize(payload);
    const restored = sanitizer.restore(sanitized);
    expect(restored).toBe(payload);
  });

  it('should not alter tokens that are not recognized', () => {
    const payload = 'Fake token [[SHIELD_SECRET_b30cfb04-a21f-4b0d-b2a8-0814ab5c3efc]]';
    const restored = sanitizer.restore(payload);
    expect(restored).toBe(payload);
  });
  
  it('should sanitize Anthropic keys and prioritize over OpenAI', () => {
    const anthropicKey = 'sk-ant-api03-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678';
    const payload = `Anthropic: ${anthropicKey}`;
    const sanitized = sanitizer.sanitize(payload);
    expect(sanitized).toMatch(/\[\[SHIELD_SECRET_[0-9a-fA-F-]{36}\]\]/);
    expect(sanitized).not.toContain(anthropicKey);
    const restored = sanitizer.restore(sanitized);
    expect(restored).toBe(payload);
  });

  it('should sanitize high entropy strings with base64url dashes and underscores', () => {
    // Generate a long random looking base64url string with - and _
    const payload = 'Here is a JWT secret: xY398f12Jkd94hfA-0q124Nvk9Lp04xMbc7VzQwE_1234567890';
    const sanitized = sanitizer.sanitize(payload);
    expect(sanitized).toMatch(/\[\[SHIELD_SECRET_[0-9a-fA-F-]{36}\]\]/);
  });
});
