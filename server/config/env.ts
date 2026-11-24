/**
 * Global Configuration for Serverless Security Verification Framework
 * Enforces Zero-Trust Security, Strict Secret Validation, and Environment Hygiene.
 */

import crypto from 'crypto';

const isProd = process.env.NODE_ENV === 'production';

// Cryptographic Secret Resolution:
// Uses process.env.JWT_SECRET if provided. If under 32 chars, derives a high-entropy 256-bit key.
// Falls back gracefully to standard dev verification key if unconfigured to prevent container crashes.
let resolvedJwtSecret: string;
const rawSecret = process.env.JWT_SECRET?.trim();

if (rawSecret && rawSecret.length >= 32) {
  resolvedJwtSecret = rawSecret;
} else if (rawSecret && rawSecret.length > 0) {
  console.warn('[SECURITY_NOTICE] JWT_SECRET is shorter than 32 characters. Deriving 256-bit cryptographic key via SHA-256.');
  resolvedJwtSecret = crypto.createHash('sha256').update(rawSecret).digest('hex');
} else {
  if (isProd) {
    throw new Error('[FATAL_SECURITY_ERROR] JWT_SECRET must be configured with at least 32 characters in production.');
  }
  // Ephemeral high-entropy development/testing secret generated via CSPRNG per process startup
  resolvedJwtSecret = crypto.randomBytes(32).toString('hex');
}

// Explicit Trusted Origins for CORS Defense
function parseSafeOrigin(val?: string): string[] {
  if (!val) return [];
  const trimmed = val.trim();
  if (!trimmed) return [];
  try {
    const origin = new URL(trimmed).origin;
    return [origin];
  } catch {
    if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
      return [trimmed.replace(/\/+$/, '')];
    }
    return [`https://${trimmed.replace(/\/+$/, '')}`, `http://${trimmed.replace(/\/+$/, '')}`];
  }
}

const rawAppUrlOrigins = parseSafeOrigin(process.env.APP_URL);
const rawZeroTrustOrigins = parseSafeOrigin(process.env.ZERO_TRUST_ORIGIN);

export function deriveAnchorHmacKey(rawSecret: string): string {
  return crypto
    .createHmac('sha256', rawSecret)
    .update('serverless-security:audit-chain-anchor:v1')
    .digest('hex');
}

export function computeAnchorKeyFingerprint(derivedKey: string): string {
  return crypto.createHash('sha256').update(derivedKey).digest('hex').slice(0, 16);
}

export function parseAnchorKeyRing(rawPreviousKeys?: string): Record<string, string> {
  const ring: Record<string, string> = {};
  if (!rawPreviousKeys || !rawPreviousKeys.trim()) return ring;
  const trimmed = rawPreviousKeys.trim();

  if (trimmed.startsWith('{')) {
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed && typeof parsed === 'object') {
        for (const [keyId, secret] of Object.entries(parsed)) {
          if (typeof secret === 'string' && secret.trim()) {
            ring[keyId.trim()] = deriveAnchorHmacKey(secret.trim());
          }
        }
        return ring;
      }
    } catch {
      // fall through to delimited parser
    }
  }

  for (const entry of trimmed.split(',')) {
    const clean = entry.trim();
    if (!clean) continue;
    const sepIdx = clean.indexOf(':');
    if (sepIdx <= 0) continue;
    const keyId = clean.slice(0, sepIdx).trim();
    const secret = clean.slice(sepIdx + 1).trim();
    if (keyId && secret) {
      ring[keyId] = deriveAnchorHmacKey(secret);
    }
  }
  return ring;
}

const rawAnchorSecret = process.env.AUDIT_ANCHOR_KEY?.trim() || resolvedJwtSecret;
const resolvedAnchorKey = deriveAnchorHmacKey(rawAnchorSecret);
const resolvedAnchorKeyId = process.env.AUDIT_ANCHOR_KEY_ID?.trim() || 'anchor-v1';
const resolvedAnchorPreviousKeys = parseAnchorKeyRing(process.env.AUDIT_ANCHOR_PREVIOUS_KEYS);
const resolvedAnchorKeyFingerprint = computeAnchorKeyFingerprint(resolvedAnchorKey);

export const CONFIG = {
  NODE_ENV: process.env.NODE_ENV || 'development',
  IS_PROD: isProd,
  PORT: process.env.NODE_ENV === 'production' && process.env.PORT ? parseInt(process.env.PORT, 10) : 3000,

  // Explicit Trusted Origins for CORS Defense (Never reflect arbitrary untrusted origins)
  TRUSTED_ORIGINS: [
    'https://serverless-securityverification.ai.studio',
    'https://ais-pre-2gbvx5rv6rvvsia4jitmad-712384669760.asia-east1.run.app',
    'https://ais-dev-2gbvx5rv6rvvsia4jitmad-712384669760.asia-east1.run.app',
    ...rawAppUrlOrigins,
    ...rawZeroTrustOrigins,
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    'http://localhost:5173'
  ],

  // Cryptographic Key Material (Zero-Trust Standard)
  JWT_SECRET: resolvedJwtSecret,
  JWT_ISSUER: 'https://auth.serverless-security.local',
  JWT_AUDIENCE: 'serverless-security-framework',
  JWT_EXPIRY_SECONDS: 3600, // 1 hour token lifespan

  // Server-Side Audit Chain Anchor HMAC Key Ring (Never exposed to clients)
  AUDIT_ANCHOR_KEY: resolvedAnchorKey,
  AUDIT_ANCHOR_KEY_ID: resolvedAnchorKeyId,
  AUDIT_ANCHOR_KEY_SOURCE: process.env.AUDIT_ANCHOR_KEY?.trim() ? 'AUDIT_ANCHOR_KEY_ENV' : 'JWT_SECRET_DOMAIN_DERIVED',
  AUDIT_ANCHOR_KEY_FINGERPRINT: resolvedAnchorKeyFingerprint,
  AUDIT_ANCHOR_PREVIOUS_KEYS: resolvedAnchorPreviousKeys,

  // Password Hashing (PBKDF2 SHA-512)
  PASSWORD_SALT_BYTES: 16,
  PASSWORD_HASH_ITERATIONS: 100000,
  PASSWORD_HASH_KEYLEN: 64,

  // MFA & TOTP Settings
  MFA_STEP_SECONDS: 30,
  MFA_WINDOW: 1, // Strict +/- 1 step (30s clock skew)
  MFA_CHALLENGE_TTL_MS: 5 * 60 * 1000, // 5 minutes
  MFA_MAX_ATTEMPTS: 5,

  // Rate Limiting & Brute-Force Safeguards
  LOGIN_RATE_LIMIT_WINDOW_MS: 60 * 1000, // 1 minute
  MAX_FAILED_LOGIN_ATTEMPTS: 5,
  ACCOUNT_LOCKOUT_MS: 5 * 60 * 1000, // 5 minutes lockout

  // Invocation Rate Limiting
  BURST_RATE_LIMIT_PER_MINUTE: 120,

  // Payload Constraints
  MAX_PAYLOAD_BYTES: 512 * 1024 // 512 KB
};

