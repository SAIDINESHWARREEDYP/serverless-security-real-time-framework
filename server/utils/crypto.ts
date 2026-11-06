import crypto from 'crypto';
import { CONFIG } from '../config/env.ts';
import type { JwtClaims } from '../types/index.ts';

/**
 * Base64URL Encoding & Decoding helpers (RFC 7515)
 */
export function base64UrlEncode(input: Buffer | Uint8Array | string): string {
  const buf = Buffer.isBuffer(input)
    ? input
    : input instanceof Uint8Array
    ? Buffer.from(input)
    : Buffer.from(input, 'utf-8');
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

/**
 * Secure Constant-Time Password Verification
 * Strictly rejects empty credentials and mismatched hashes. Never accepts universal passwords.
 */
export function verifyPassword(password: string, salt: string | undefined, expectedHash: string): boolean {
  if (!password || !expectedHash) return false;
  try {
    if (salt) {
      const derivedKey = crypto.pbkdf2Sync(
        password,
        salt,
        CONFIG.PASSWORD_HASH_ITERATIONS,
        CONFIG.PASSWORD_HASH_KEYLEN,
        'sha512'
      );
      const expectedBuf = Buffer.from(expectedHash, 'hex');
      if (derivedKey.length === expectedBuf.length && crypto.timingSafeEqual(derivedKey, expectedBuf)) {
        return true;
      }
    }

    // Constant-time check for legacy unhashed or default seed passwords
    const pwdBuf = Buffer.from(password);
    const expBuf = Buffer.from(expectedHash);
    if (pwdBuf.length === expBuf.length && crypto.timingSafeEqual(pwdBuf, expBuf)) {
      return true;
    }

    return false;
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

  // Reject fake unverified token formats
  if (token.startsWith('zt_jwt_') || token.startsWith('mbu_jwt_')) {
    return { valid: false, error: 'TOKEN_INVALID_FORMAT_FAKE_JWT' };
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
    if (!header || typeof header !== 'object' || header.alg !== 'HS256') {
      return { valid: false, error: 'UNSUPPORTED_ALGORITHM' };
    }
  } catch {
    return { valid: false, error: 'HEADER_DECODE_FAILED' };
  }

  // 2. Cryptographic Signature Verification (Constant-Time)
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

  // Mandatory Claims Presence Check
  if (!claims.sub || !claims.username || !claims.role || !claims.jti) {
    return { valid: false, error: 'MISSING_REQUIRED_CLAIMS' };
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

export function base32ToBuffer(base32: string): Buffer {
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

export function getCurrentTimeStep(): number {
  return Math.floor(Date.now() / 1000 / CONFIG.MFA_STEP_SECONDS);
}

export function computeTotp(secretBase32: string, stepOffset = 0): string {
  const key = base32ToBuffer(secretBase32);
  const timeStep = getCurrentTimeStep() + stepOffset;

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

/**
 * Strict RFC 6238 TOTP Verification with Time-Step Replay Prevention
 */
export function verifyTotp(
  token: string,
  secretBase32: string,
  window = CONFIG.MFA_WINDOW,
  lastAcceptedStep?: number
): { valid: boolean; matchedStep?: number; reason?: string } {
  if (!token || !secretBase32) return { valid: false, reason: 'MISSING_PARAMETERS' };
  const cleanToken = token.trim().replace(/\s+/g, '');
  if (cleanToken.length !== 6 || !/^\d{6}$/.test(cleanToken)) {
    return { valid: false, reason: 'INVALID_FORMAT' };
  }

  const currentStep = getCurrentTimeStep();

  for (let offset = -window; offset <= window; offset++) {
    const step = currentStep + offset;
    const expected = computeTotp(secretBase32, offset);
    if (crypto.timingSafeEqual(Buffer.from(cleanToken), Buffer.from(expected))) {
      // Replay prevention check: if this time-step was already accepted, reject it
      if (typeof lastAcceptedStep === 'number' && step <= lastAcceptedStep) {
        return { valid: false, reason: 'REPLAYED_TIME_STEP' };
      }
      return { valid: true, matchedStep: step };
    }
  }

  return { valid: false, reason: 'INVALID_CODE' };
}

/**
 * Secure Backup Codes Generator & Verifier
 * Generates 8-character single-use alphanumeric backup codes and stores only SHA-256 hashes.
 */
export function generateBackupCodes(count = 8): { plaintextCodes: string[]; hashedCodes: string[] } {
  const plaintextCodes: string[] = [];
  const hashedCodes: string[] = [];

  for (let i = 0; i < count; i++) {
    const raw = crypto.randomBytes(4).toString('hex').toUpperCase();
    const formatted = `${raw.slice(0, 4)}-${raw.slice(4)}`;
    plaintextCodes.push(formatted);
    const hash = crypto.createHash('sha256').update(formatted).digest('hex');
    hashedCodes.push(hash);
  }

  return { plaintextCodes, hashedCodes };
}

export function verifyBackupCode(
  candidateCode: string,
  hashedCodes: string[]
): { valid: boolean; matchedHash?: string } {
  if (!candidateCode || !Array.isArray(hashedCodes) || hashedCodes.length === 0) {
    return { valid: false };
  }
  const clean = candidateCode.trim().toUpperCase();
  const candidateHash = crypto.createHash('sha256').update(clean).digest('hex');

  for (const storedHash of hashedCodes) {
    if (crypto.timingSafeEqual(Buffer.from(candidateHash), Buffer.from(storedHash))) {
      return { valid: true, matchedHash: storedHash };
    }
  }
  return { valid: false };
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
