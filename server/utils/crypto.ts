import crypto from 'crypto';
import { CONFIG } from '../config/env.ts';
import { JwtClaims } from '../types/index.ts';

/**
 * Base64URL Encoding & Decoding helpers (RFC 7515)
 */
export function base64UrlEncode(input: Buffer | string): string {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input, 'utf-8');
  return buf.toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

export function base64UrlDecode(str: string): Buffer {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64');
}

/**
 * Secure PBKDF2 Password Hashing (compatible with modern edge & Node runtime)
 */
export function hashPassword(password: string, providedSalt?: string): { salt: string; hash: string } {
  const salt = providedSalt || crypto.randomBytes(CONFIG.PASSWORD_SALT_BYTES).toString('hex');
  const derivedKey = crypto.pbkdf2Sync(
    password,
    salt,
    CONFIG.PASSWORD_HASH_ITERATIONS,
    CONFIG.PASSWORD_HASH_KEYLEN,
    'sha512'
  );
  return {
    salt,
    hash: derivedKey.toString('hex')
  };
}

export function verifyPassword(password: string, salt: string, expectedHash: string): boolean {
  if (!password || !salt || !expectedHash) return false;
  try {
    const derivedKey = crypto.pbkdf2Sync(
      password,
      salt,
      CONFIG.PASSWORD_HASH_ITERATIONS,
      CONFIG.PASSWORD_HASH_KEYLEN,
      'sha512'
    );
    const expectedBuf = Buffer.from(expectedHash, 'hex');
    if (derivedKey.length !== expectedBuf.length) return false;
    return crypto.timingSafeEqual(derivedKey, expectedBuf);
  } catch {
    return false;
  }
}

/**
 * Cryptographic JWT Generation (HMAC-SHA256 / HS256)
 */
export function signJwt(claims: Omit<JwtClaims, 'iss' | 'aud' | 'iat' | 'nbf' | 'exp'> & { expiresInSeconds?: number }): string {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + (claims.expiresInSeconds || CONFIG.JWT_EXPIRY_SECONDS);

  const fullPayload: JwtClaims = {
    sub: claims.sub,
    username: claims.username,
    role: claims.role,
    jti: claims.jti || `jti_${crypto.randomBytes(12).toString('hex')}`,
    iss: CONFIG.JWT_ISSUER,
    aud: CONFIG.JWT_AUDIENCE,
    iat: now,
    nbf: now,
    exp
  };

  const header = {
    alg: 'HS256',
    typ: 'JWT'
  };

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(fullPayload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const signature = crypto
    .createHmac('sha256', CONFIG.JWT_SECRET)
    .update(signingInput)
    .digest();

  const encodedSignature = base64UrlEncode(signature);
  return `${signingInput}.${encodedSignature}`;
}

/**
 * Cryptographic JWT Verification (Signature, Expiration, Issuer, Audience)
 */
export function verifyJwt(token: string): { valid: boolean; claims?: JwtClaims; error?: string } {
  if (!token || typeof token !== 'string') {
    return { valid: false, error: 'TOKEN_MISSING' };
  }

  const parts = token.trim().split('.');
  if (parts.length !== 3) {
    return { valid: false, error: 'TOKEN_MALFORMED' };
  }

  const [encodedHeader, encodedPayload, encodedSignature] = parts;

  // 1. Validate Header
  let header: { alg?: string; typ?: string };
  try {
    header = JSON.parse(base64UrlDecode(encodedHeader).toString('utf-8'));
    if (header.alg !== 'HS256') {
      return { valid: false, error: 'UNSUPPORTED_ALGORITHM' };
    }
  } catch {
    return { valid: false, error: 'HEADER_DECODE_FAILED' };
  }

  // 2. Cryptographic Signature Verification
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const expectedSignature = crypto
    .createHmac('sha256', CONFIG.JWT_SECRET)
    .update(signingInput)
    .digest();

  const providedSignature = base64UrlDecode(encodedSignature);
  if (
    expectedSignature.length !== providedSignature.length ||
    !crypto.timingSafeEqual(expectedSignature, providedSignature)
  ) {
    return { valid: false, error: 'SIGNATURE_INVALID' };
  }

  // 3. Claims Verification
  let claims: JwtClaims;
  try {
    claims = JSON.parse(base64UrlDecode(encodedPayload).toString('utf-8'));
  } catch {
    return { valid: false, error: 'PAYLOAD_DECODE_FAILED' };
  }

  const now = Math.floor(Date.now() / 1000);

  // Expiration Check
  if (typeof claims.exp !== 'number' || claims.exp <= now) {
    return { valid: false, error: 'TOKEN_EXPIRED' };
  }

  // Not Before Check
  if (typeof claims.nbf === 'number' && claims.nbf > now) {
    return { valid: false, error: 'TOKEN_NOT_YET_VALID' };
  }

  // Issuer Check
  if (claims.iss && claims.iss !== CONFIG.JWT_ISSUER) {
    return { valid: false, error: 'INVALID_ISSUER' };
  }

  // Audience Check
  if (claims.aud && claims.aud !== CONFIG.JWT_AUDIENCE) {
    return { valid: false, error: 'INVALID_AUDIENCE' };
  }

  return { valid: true, claims };
}

/**
 * Standard RFC 6238 TOTP Engine (Time-Based One-Time Password)
 */
const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function generateTotpSecret(byteLength = 20): string {
  const randomBytes = crypto.randomBytes(byteLength);
  let bits = '';
  let secret = '';
  for (let i = 0; i < randomBytes.length; i++) {
    bits += randomBytes[i].toString(2).padStart(8, '0');
  }
  for (let i = 0; i + 5 <= bits.length; i += 5) {
    const chunk = bits.substring(i, i + 5);
    secret += BASE32_CHARS[parseInt(chunk, 2)];
  }
  return secret;
}

function base32ToBuffer(base32: string): Buffer {
  const clean = base32.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = '';
  for (let i = 0; i < clean.length; i++) {
    const val = BASE32_CHARS.indexOf(clean[i]);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.substring(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

export function computeTotp(secretBase32: string, stepOffset = 0): string {
  const key = base32ToBuffer(secretBase32);
  const timeStep = Math.floor(Date.now() / 1000 / CONFIG.MFA_STEP_SECONDS) + stepOffset;

  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigInt64BE(BigInt(timeStep));

  const hmac = crypto.createHmac('sha1', key).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const codeInt =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const otp = (codeInt % 1000000).toString().padStart(6, '0');
  return otp;
}

export function verifyTotp(token: string, secretBase32: string, window = CONFIG.MFA_WINDOW): boolean {
  if (!token || !secretBase32) return false;
  const cleanToken = token.trim().replace(/\s+/g, '');
  if (cleanToken.length !== 6 || !/^\d{6}$/.test(cleanToken)) return false;

  for (let offset = -window; offset <= window; offset++) {
    const expected = computeTotp(secretBase32, offset);
    if (crypto.timingSafeEqual(Buffer.from(cleanToken), Buffer.from(expected))) {
      return true;
    }
  }
  return false;
}

/**
 * Secure Backup Codes Generator
 */
export function generateBackupCodes(count = 8): string[] {
  const codes: string[] = [];
  for (let i = 0; i < count; i++) {
    const raw = crypto.randomBytes(4).toString('hex').toUpperCase();
    codes.push(`${raw.slice(0, 4)}-${raw.slice(4)}`);
  }
  return codes;
}

/**
 * Masking utilities for PII
 */
export function maskPhone(phone?: string): string {
  if (!phone) return '+1 (•••) •••-4829';
  const clean = phone.replace(/[^\d+]/g, '');
  if (clean.length >= 4) {
    const last4 = clean.slice(-4);
    return `+1 (•••) •••-${last4}`;
  }
  return '+1 (•••) •••-4829';
}

export function maskEmail(email?: string): string {
  if (!email || !email.includes('@')) return 'u••••@corp.internal';
  const [local, domain] = email.split('@');
  const visible = local.length > 2 ? local.slice(0, 2) + '••••' : local + '••••';
  return `${visible}@${domain}`;
}
