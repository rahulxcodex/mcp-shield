import { canonicalizeJson, hashCanonicalJson } from '../../src/security/canonical-json';

describe('Canonical JSON & Stable Digest (Roadmap Section 5)', () => {
  it('produces identical string serialization regardless of key ordering', () => {
    const objA = { z: 1, a: 2, m: { y: 'hello', x: 'world' } };
    const objB = { a: 2, m: { x: 'world', y: 'hello' }, z: 1 };

    const strA = canonicalizeJson(objA);
    const strB = canonicalizeJson(objB);

    expect(strA).toBe(strB);
    expect(strA).toBe('{"a":2,"m":{"x":"world","y":"hello"},"z":1}');
 });

 it('produces identical cryptographic hashes for permuted objects', () => {
 const schema1 = {
 type: 'object',
 properties: {
 command: { type: 'string' },
 timeout: { type: 'number' }
 },
 required: ['command']
 };

 const schema2 = {
 required: ['command'],
 properties: {
 timeout: { type: 'number' },
 command: { type: 'string' }
 },
 type: 'object'
 };

 const hash1 = hashCanonicalJson(schema1);
 const hash2 = hashCanonicalJson(schema2);

 expect(hash1).toBe(hash2);
 expect(typeof hash1).toBe('string');
 expect(hash1.length).toBe(64);
 });

 it('changes digest when security-relevant properties change', () => {
 const schema1 = { type: 'object', properties: { command: { type: 'string' } } };
 const schema2 = { type: 'object', properties: { command: { type: 'string', secret: true } } };

 expect(hashCanonicalJson(schema1)).not.toBe(hashCanonicalJson(schema2));
 });

 it('correctly handles primitives, nulls, and arrays', () => {
 expect(canonicalizeJson(null)).toBe('null');
 expect(canonicalizeJson(undefined)).toBe('null');
 expect(canonicalizeJson([3, 1, 2])).toBe('[3,1,2]'); // Arrays maintain sequence
 expect(canonicalizeJson(true)).toBe('true');
 expect(canonicalizeJson(123.45)).toBe('123.45');
 });
});
