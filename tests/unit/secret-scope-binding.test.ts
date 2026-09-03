import { SecretVault } from '../../src/security/vault';
import { SecretSanitizer } from '../../src/security/sanitizer';

describe('SecretVault Memory Bounds & Scoped Token Binding', () => {
  it('VAULT-01: Exposes ephemeral property and enforces hard byte limit eviction', () => {
    // 500 bytes maximum buffer memory limit
    const vault = new SecretVault(60000, 500);
    expect(vault.isEphemeral).toBe(true);

    const tokens: string[] = [];
    // Insert 15 secrets of 50 chars each (~80 bytes per encrypted entry)
    for (let i = 0; i < 15; i++) {
      const token = vault.store(`secret-value-${i}-${'X'.repeat(30)}`);
      tokens.push(token);
    }

    // Current byte size must not exceed the configured 500 byte limit
    expect(vault.getCurrentByteSize()).toBeLessThanOrEqual(500);

    // Oldest entries must have been evicted by LRU byte limit
    expect(vault.retrieve(tokens[0])).toBeNull();

    // Newest entry must still be retrievable
    expect(vault.retrieve(tokens[tokens.length - 1])).not.toBeNull();
  });

  it('VAULT-02: Scoped deduplication prevents cross-tool token linkage', () => {
    const vault = new SecretVault();
    const commonSecret = 'ghp_A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8';

    // Same secret used across two distinct tools / scopes
    const tokenToolA = vault.store(commonSecret, 60000, {
      serverIdentity: 'srv-1',
      toolName: 'git_sync',
      scope: 'srv-1:git_sync'
    });

    const tokenToolB = vault.store(commonSecret, 60000, {
      serverIdentity: 'srv-2',
      toolName: 'http_fetch',
      scope: 'srv-2:http_fetch'
    });

    // SECURITY INVARIANT: Tokens MUST differ across distinct scopes to prevent cross-tool correlation attacks!
    expect(tokenToolA).not.toBe(tokenToolB);

    // Retrieval strictly enforces matching caller scope
    const retrievedA = vault.retrieve(tokenToolA, { scope: 'srv-1:git_sync' });
    expect(retrievedA).toBe(commonSecret);

    // Mismatched scope retrieval must be rejected
    const stolenAttempt = vault.retrieve(tokenToolA, { scope: 'srv-2:http_fetch' });
    expect(stolenAttempt).toBeNull();
  });

  it('VAULT-03: Sanitizer respects SecretContext during restoration', () => {
    const sanitizer = new SecretSanitizer();
    const rawSecret = 'sk-ant-api03-abcdef1234567890abcdef1234567890';

    const token = sanitizer.registerSecret(rawSecret, {
      serverIdentity: 'trusted-server',
      sessionId: 'sess-100',
      scope: 'trusted-server:ai_query'
    });

    const payload = `Bearer ${token}`;

    // Restoration with matching context succeeds
    const restoredValid = sanitizer.restore(payload, {
      serverIdentity: 'trusted-server',
      sessionId: 'sess-100',
      scope: 'trusted-server:ai_query'
    });
    expect(restoredValid).toContain(rawSecret);

    // Restoration with mismatched session or identity fails
    const restoredInvalid = sanitizer.restore(payload, {
      serverIdentity: 'attacker-server',
      sessionId: 'sess-100',
      scope: 'trusted-server:ai_query'
    });
    expect(restoredInvalid).toBe(payload); // Remains masked!
  });
});
