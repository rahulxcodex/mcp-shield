import * as crypto from 'crypto';

/**
 * Deterministic JSON Canonicalization (Roadmap Section 5 & RFC 8785)
 *
 * Guarantees that semantically identical objects produce byte-identical JSON strings
 * and cryptographic digests regardless of property insertion order or spacing.
 */

export function canonicalizeJson(value: any, seen = new WeakSet()): string {
  if (value === null || value === undefined) {
    return 'null';
  }

  const type = typeof value;

  if (type === 'number') {
    if (!Number.isFinite(value)) {
      return 'null';
    }
    return String(value);
  }

  if (type === 'boolean') {
    return value ? 'true' : 'false';
  }

  if (type === 'string') {
    return JSON.stringify(value);
  }

  if (type === 'bigint') {
    return String(value);
  }

  if (type === 'object') {
    if (seen.has(value)) {
      throw new TypeError('Circular structure detected in canonicalizeJson');
    }
    seen.add(value);

    // Handle toJSON if present (e.g. Date)
    if (typeof value.toJSON === 'function') {
      const jsonVal = value.toJSON();
      seen.delete(value);
      return canonicalizeJson(jsonVal, seen);
    }

    if (Array.isArray(value)) {
      const items = value.map(item => {
        if (item === undefined || typeof item === 'function' || typeof item === 'symbol') {
          return 'null';
        }
        return canonicalizeJson(item, seen);
      });
      seen.delete(value);
      return '[' + items.join(',') + ']';
    }

    const keys = Object.keys(value)
      .filter(k => {
        const v = value[k];
        return v !== undefined && typeof v !== 'function' && typeof v !== 'symbol';
      })
      .sort(); // Lexicographical UTF-16 sort

    const properties = keys.map(key => {
      const serializedKey = JSON.stringify(key);
      const serializedVal = canonicalizeJson(value[key], seen);
      return serializedKey + ':' + serializedVal;
    });

    seen.delete(value);
    return '{' + properties.join(',') + '}';
  }

  return 'null';
}

/**
 * Computes a deterministic SHA-256 (or custom algorithm) digest of any object
 */
export function hashCanonicalJson(value: any, algorithm: string = 'sha256'): string {
  const canonical = canonicalizeJson(value);
  return crypto.createHash(algorithm).update(canonical, 'utf8').digest('hex');
}
