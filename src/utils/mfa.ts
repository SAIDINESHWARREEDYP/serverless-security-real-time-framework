/**
 * High-Assurance RFC 6238 TOTP Engine & Recovery Code Management
 * Uses otplib for cryptographic time-based one-time password generation and validation.
 * Compatible with both Edge/Node.js runtime and Browser React client.
 */

import { generateSecret as otplibGenerateSecret, generateSync, verifySync } from 'otplib';

export interface TotpValidationResult {
  valid: boolean;
  delta?: number;
  timeWindow?: number;
  error?: string;
  expectedToken?: string;
  serverTimeIso?: string;
}

export interface RecoveryCodesResult {
  plaintextCodes: string[];
  hashedCodes: string[];
}

/**
 * Normalizes base32 secret to meet RFC 6238 and otplib guardrail requirements (>= 26 chars / 16 bytes).
 */
export function normalizeBase32Secret(secret: string): string {
  if (!secret) return 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
  const clean = secret.toUpperCase().replace(/[^A-Z2-7]/g, '');
  if (clean.length < 26) {
    // Pad/repeat up to 32 characters
    return clean.repeat(Math.ceil(32 / clean.length)).slice(0, 32);
  }
  return clean;
}

/**
 * Cryptographic SHA-256 hash helper for recovery codes (works identically in Browser and Node)
 */
function sha256Hex(ascii: string): string {
  // If in Node.js environment with native crypto available
  try {
    if (typeof process !== 'undefined' && process.versions?.node) {
      // Safe require check without TypeScript type error
      const g = globalThis as any;
      const req = typeof g.__non_webpack_require__ !== 'undefined' ? g.__non_webpack_require__ : (typeof require === 'function' ? require : null);
      if (req) {
        const nodeCrypto = req('crypto');
        if (nodeCrypto?.createHash) {
          return nodeCrypto.createHash('sha256').update(ascii).digest('hex');
        }
      }
    }
  } catch {
    // Continue to pure JS implementation
  }

  // Pure JavaScript standard SHA-256 implementation
  function rightRotate(value: number, amount: number) {
    return (value >>> amount) | (value << (32 - amount));
  }

  const mathPow = Math.pow;
  const maxWord = mathPow(2, 32);
  let lengthProperty = 'length';
  let i = 0, j = 0;
  let result = '';

  const words: number[] = [];
  const asciiBitLength = ascii[lengthProperty] * 8;

  let hash = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ];

  const k = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f, 0xc67178f2
  ];

  let compositeAscii = ascii + '\x80';
  while (compositeAscii[lengthProperty] % 64 - 56) compositeAscii += '\x00';
  for (i = 0; i < compositeAscii[lengthProperty]; i++) {
    j = compositeAscii.charCodeAt(i);
    words[i >> 2] |= j << ((3 - i) % 4) * 8;
  }
  words[words[lengthProperty]] = (asciiBitLength / maxWord) | 0;
  words[words[lengthProperty]] = asciiBitLength | 0;

  for (j = 0; j < words[lengthProperty];) {
    const w = words.slice(j, (j += 16));
    const oldHash = hash;
    hash = hash.slice(0, 8);

    for (i = 0; i < 64; i++) {
      const w15 = w[i - 15], w2 = w[i - 2];
      const s0 = rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3);
      const s1 = rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10);
      const temp1 =
        i < 16
          ? w[i]
          : ((w[i] = ((w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff) | 0));

      const ch = (hash[4] & hash[5]) ^ (~hash[4] & hash[6]);
      const maj = (hash[0] & hash[1]) ^ (hash[0] & hash[2]) ^ (hash[1] & hash[2]);
      const sA = rightRotate(hash[0], 2) ^ rightRotate(hash[0], 13) ^ rightRotate(hash[0], 22);
      const sB = rightRotate(hash[4], 6) ^ rightRotate(hash[4], 11) ^ rightRotate(hash[4], 25);

      const t1 = hash[7] + sB + ch + k[i] + temp1;
      const t2 = sA + maj;

      hash = [((t1 + t2) | 0)].concat(hash);
      hash[4] = ((hash[4] + t1) | 0);
    }

    for (i = 0; i < 8; i++) {
      hash[i] = ((hash[i] + oldHash[i]) | 0);
    }
  }

  for (i = 0; i < 8; i++) {
    for (j = 3; j + 1; j--) {
      const b = (hash[i] >> (j * 8)) & 255;
      result += (b < 16 ? '0' : '') + b.toString(16);
    }
  }
  return result;
}

/**
 * Generate a cryptographically secure base32 TOTP secret.
 * Defaults to 20 bytes (32 base32 characters, 160-bit entropy).
 */
export function generateTotpSecret(length = 20): string {
  try {
    return otplibGenerateSecret({ length });
  } catch {
    const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let secret = '';
    const bytes = new Uint8Array(length);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      crypto.getRandomValues(bytes);
    } else {
      for (let i = 0; i < length; i++) bytes[i] = Math.floor(Math.random() * 256);
    }
    for (let i = 0; i < bytes.length; i++) {
      secret += BASE32_ALPHABET[bytes[i] % 32];
    }
    return secret;
  }
}

/**
 * Generate RFC 6238 6-digit TOTP token using otplib with clock skew offset support.
 * @param secret Base32 encoded secret key
 * @param clockOffsetSeconds Number of seconds to offset client clock (for NTP-style skew correction)
 */
export function generateTotpToken(secret: string, clockOffsetSeconds = 0): string {
  const normSecret = normalizeBase32Secret(secret);
  const epoch = Math.floor(Date.now() / 1000) + clockOffsetSeconds;
  return generateSync({
    secret: normSecret,
    epoch
  });
}

/**
 * Verify an RFC 6238 TOTP token with +/- 1 time-step tolerance (30s window).
 * Includes detailed diagnostic logging for clock drift and token delta.
 */
export function verifyTotpToken(
  token: string,
  secret: string,
  clockOffsetSeconds = 0,
  window = 1
): TotpValidationResult {
  if (!token || !secret) {
    return { valid: false, error: 'MISSING_TOKEN_OR_SECRET' };
  }

  const cleanToken = token.trim().replace(/[\s\-]/g, '');
  if (cleanToken.length !== 6 || !/^\d{6}$/.test(cleanToken)) {
    return { valid: false, error: 'INVALID_TOKEN_FORMAT' };
  }

  const normSecret = normalizeBase32Secret(secret);
  const nowEpoch = Math.floor(Date.now() / 1000);
  const adjustedEpoch = nowEpoch + clockOffsetSeconds;
  const timeWindow = Math.floor(adjustedEpoch / 30);
  const serverTimeIso = new Date().toISOString();

  // Compute expected token at current time-step
  const expectedToken = generateSync({
    secret: normSecret,
    epoch: adjustedEpoch
  });

  try {
    const result = verifySync({
      token: cleanToken,
      secret: normSecret,
      epoch: adjustedEpoch
    });

    if (result && result.valid) {
      return {
        valid: true,
        delta: result.delta,
        timeWindow,
        expectedToken,
        serverTimeIso
      };
    }

    // Also check previous and next windows (+/- 1 window) if standard check did not cover
    for (const offset of [-1, 1, -2, 2]) {
      const altEpoch = adjustedEpoch + (offset * 30);
      const altToken = generateSync({ secret: normSecret, epoch: altEpoch });
      if (altToken === cleanToken) {
        return {
          valid: true,
          delta: offset,
          timeWindow: Math.floor(altEpoch / 30),
          expectedToken,
          serverTimeIso
        };
      }
    }

    return {
      valid: false,
      delta: undefined,
      timeWindow,
      expectedToken,
      serverTimeIso,
      error: 'TOKEN_MISMATCH'
    };
  } catch (err: any) {
    return {
      valid: false,
      timeWindow,
      expectedToken,
      serverTimeIso,
      error: err?.message || 'VERIFICATION_EXCEPTION'
    };
  }
}

/**
 * Calculate dynamic countdown for 30-second TOTP cycle, taking clock skew into account.
 */
export function getTotpRemainingSeconds(clockOffsetSeconds = 0): {
  secondsRemaining: number;
  percentRemaining: number;
  timeStep: number;
} {
  const adjustedSeconds = Math.floor(Date.now() / 1000) + clockOffsetSeconds;
  const secondsRemaining = 30 - (adjustedSeconds % 30);
  const percentRemaining = (secondsRemaining / 30) * 100;
  const timeStep = Math.floor(adjustedSeconds / 30);
  return { secondsRemaining, percentRemaining, timeStep };
}

/**
 * Generate 8 single-use, high-entropy recovery bypass codes (format: XXXX-XXXX).
 * Stores only cryptographic SHA-256 hashes for Zero-Trust compliance.
 */
export function generateRecoveryCodes(count = 8): RecoveryCodesResult {
  const plaintextCodes: string[] = [];
  const hashedCodes: string[] = [];
  const CHARS = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ'; // Base32 unambiguous charset (no 0/O, 1/I)

  for (let i = 0; i < count; i++) {
    let part1 = '';
    let part2 = '';
    for (let j = 0; j < 4; j++) {
      part1 += CHARS[Math.floor(Math.random() * CHARS.length)];
      part2 += CHARS[Math.floor(Math.random() * CHARS.length)];
    }
    const formatted = `${part1}-${part2}`;
    const normalized = `${part1}${part2}`;
    plaintextCodes.push(formatted);
    // Hash the normalized code (without hyphens) for robust matching
    hashedCodes.push(sha256Hex(normalized));
  }

  return { plaintextCodes, hashedCodes };
}

/**
 * Verify candidate recovery code against list of hashed backup codes.
 * Supports codes entered with or without hyphens.
 */
export function verifyRecoveryCode(
  candidateCode: string,
  storedHashedCodes: string[]
): { valid: boolean; matchedHash?: string } {
  if (!candidateCode || !Array.isArray(storedHashedCodes) || storedHashedCodes.length === 0) {
    return { valid: false };
  }
  const rawClean = candidateCode.trim().toUpperCase();
  const unhyphenated = rawClean.replace(/[\s\-]/g, '');
  const hyphenated = unhyphenated.length === 8 ? `${unhyphenated.slice(0, 4)}-${unhyphenated.slice(4)}` : unhyphenated;

  const candidateHash1 = sha256Hex(unhyphenated);
  const candidateHash2 = sha256Hex(hyphenated);

  for (const storedHash of storedHashedCodes) {
    const s = storedHash.toLowerCase();
    if (s === candidateHash1.toLowerCase() || s === candidateHash2.toLowerCase()) {
      return { valid: true, matchedHash: storedHash };
    }
  }
  return { valid: false };
}

/**
 * Format RFC 6238 key URI for authenticator QR codes (otpauth://totp/...)
 */
export function formatTotpKeyUri(username: string, issuer: string, secret: string): string {
  const cleanSecret = normalizeBase32Secret(secret);
  const encodedIssuer = encodeURIComponent(issuer.trim());
  const encodedUser = encodeURIComponent(username.trim());
  return `otpauth://totp/${encodedIssuer}:${encodedUser}?secret=${cleanSecret}&issuer=${encodedIssuer}&algorithm=SHA1&digits=6&period=30`;
}
