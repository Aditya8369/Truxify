import { describe, it, expect, afterEach } from 'vitest';
import { execFileSync } from 'node:child_process';
import hmacService, {
  isNonceValid,
  isTimestampValid,
  generateSignature,
  verifySignature,
} from '../../src/services/hmacService.js';

const configuredSecret = 'a'.repeat(64);
process.env.HMAC_SECRET = configuredSecret;

afterEach(() => {
  process.env.HMAC_SECRET = configuredSecret;
});

describe('hmacService', () => {
  describe('isNonceValid', () => {
    it('accepts a new unique nonce and rejects replay with the same nonce', () => {
      const nonce = `test-nonce-${Date.now()}-${Math.random()}`;
      expect(isNonceValid(nonce)).toBe(true);
      expect(isNonceValid(nonce)).toBe(false);
    });
  });

  describe('isTimestampValid', () => {
    it('accepts timestamps within the 5-minute tolerance window', () => {
      const now = Date.now();
      expect(isTimestampValid(now)).toBe(true);
      expect(isTimestampValid(now - 2 * 60 * 1000)).toBe(true);
      expect(isTimestampValid(now + 2 * 60 * 1000)).toBe(true);
    });

    it('rejects timestamps older than 5 minutes or too far in the future', () => {
      const now = Date.now();
      expect(isTimestampValid(now - 6 * 60 * 1000)).toBe(false);
      expect(isTimestampValid(now + 6 * 60 * 1000)).toBe(false);
    });

    it('handles numeric string timestamps safely', () => {
      expect(isTimestampValid(String(Date.now()))).toBe(true);
    });
  });

  describe('generateSignature', () => {
    it('generates a 64-character hex sha256 HMAC signature', () => {
      const payload = JSON.stringify({ amount: 500, bookingId: 'bk-123' });
      const timestamp = Date.now();
      const nonce = 'unique-nonce-1';
      const sig = generateSignature(payload, timestamp, nonce);

      expect(typeof sig).toBe('string');
      expect(sig).toHaveLength(64);
      expect(/^[0-9a-f]{64}$/.test(sig)).toBe(true);
    });

    it('produces deterministic signatures for identical inputs', () => {
      const payload = 'order-payload';
      const timestamp = 1700000000000;
      const nonce = 'nonce-abc';
      expect(generateSignature(payload, timestamp, nonce)).toBe(
        generateSignature(payload, timestamp, nonce)
      );
    });
  });

  describe('secret configuration', () => {
    it('rejects a missing secret instead of using a hardcoded fallback', () => {
      delete process.env.HMAC_SECRET;
      expect(() => generateSignature('payload', Date.now(), 'nonce')).toThrow(/HMAC_SECRET is required/);
    });

    it('rejects secrets shorter than the minimum length', () => {
      process.env.HMAC_SECRET = 'too-short';
      expect(() => generateSignature('payload', Date.now(), 'nonce')).toThrow(/at least 32 bytes/);
    });

    it('fails closed during production startup when the secret is missing', () => {
      expect(() => execFileSync(
        process.execPath,
        ['--input-type=module', '-e', "await import('./src/services/hmacService.js')"],
        {
          cwd: process.cwd(),
          env: { ...process.env, NODE_ENV: 'production', HMAC_SECRET: '' },
          stdio: 'pipe',
        }
      )).toThrow();
    });
  });

  describe('verifySignature', () => {
    it('returns true when the signature matches the payload, timestamp, and nonce', () => {
      const payload = 'payment-confirmation';
      const timestamp = Date.now();
      const nonce = 'nonce-xyz';
      const signature = generateSignature(payload, timestamp, nonce);
      expect(verifySignature(signature, payload, timestamp, nonce)).toBe(true);
    });

    it('returns false when the payload is tampered', () => {
      const payload = 'payment-confirmation';
      const timestamp = Date.now();
      const nonce = 'nonce-xyz';
      const signature = generateSignature(payload, timestamp, nonce);
      expect(verifySignature(signature, 'tampered-payload', timestamp, nonce)).toBe(false);
    });

    it('returns false when the timestamp or nonce is altered', () => {
      const payload = 'escrow-lock';
      const timestamp = Date.now();
      const nonce = 'nonce-test';
      const signature = generateSignature(payload, timestamp, nonce);
      expect(verifySignature(signature, payload, timestamp + 100, nonce)).toBe(false);
      expect(verifySignature(signature, payload, timestamp, 'wrong-nonce')).toBe(false);
    });

    it('returns false when signature length or encoding is malformed without crashing', () => {
      const payload = 'data';
      const timestamp = Date.now();
      const nonce = 'nonce-1';
      expect(verifySignature('invalid-sig', payload, timestamp, nonce)).toBe(false);
      expect(verifySignature('', payload, timestamp, nonce)).toBe(false);
      expect(verifySignature('123456', payload, timestamp, nonce)).toBe(false);
    });

    it('exports default service object matching named functions', () => {
      expect(hmacService.isNonceValid).toBe(isNonceValid);
      expect(hmacService.isTimestampValid).toBe(isTimestampValid);
      expect(hmacService.generateSignature).toBe(generateSignature);
      expect(hmacService.verifySignature).toBe(verifySignature);
    });
  });
});
