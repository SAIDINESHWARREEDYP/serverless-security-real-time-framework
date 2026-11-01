/**
 * Global Configuration for Serverless Security Verification Framework
 */

export const CONFIG = {
  NODE_ENV: process.env.NODE_ENV || 'development',
  PORT: parseInt(process.env.PORT || '3000', 10),

  // Cryptographic Key Material (Zero-Trust Standard)
  JWT_SECRET: process.env.JWT_SECRET || 'zt_secops_cloud_verification_secret_key_2026_x89q!#kL99',
  JWT_ISSUER: 'https://auth.serverless-security.local',
  JWT_AUDIENCE: 'serverless-security-framework',
  JWT_EXPIRY_SECONDS: 3600, // 1 hour token lifespan

  // Password Hashing (PBKDF2 SHA-512)
  PASSWORD_SALT_BYTES: 16,
  PASSWORD_HASH_ITERATIONS: 100000,
  PASSWORD_HASH_KEYLEN: 64,

  // MFA & TOTP Settings
  MFA_STEP_SECONDS: 30,
  MFA_WINDOW: 1, // Allow +/- 1 step (30s clock skew)
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
