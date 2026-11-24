import crypto from 'crypto';
import { userRepository } from '../repositories/user.repository.ts';
import { sessionRepository } from '../repositories/session.repository.ts';
import { auditRepository } from '../repositories/audit.repository.ts';
import { policyRepository } from '../repositories/policy.repository.ts';
import {
  verifyPassword,
  hashPassword,
  signJwt,
  computeTotp,
  verifyTotp,
  generateTotpSecret,
  generateBackupCodes,
  verifyBackupCode,
  maskPhone,
  maskEmail
} from '../utils/crypto.ts';
import {
  verifyTotpToken,
  generateTotpToken,
  normalizeBase32Secret,
  verifyRecoveryCode,
  generateRecoveryCodes
} from '../../src/utils/mfa.ts';
import { rateLimiter } from '../middleware/rateLimiter.ts';
import type { MfaChallengeSession, UserRecord, SanitizedUser } from '../types/index.ts';
import { CONFIG } from '../config/env.ts';
import { db } from '../db.ts';
import { logger } from '../utils/logger.ts';

class AuthService {
  private pendingEnrollmentCache = new Map<
    string,
    {
      userId: string;
      expiresAtMs: number;
      result: {
        success: true;
        mode: 'recovery_codes' | 'authenticator';
        username: string;
        secret?: string;
        provisioningUri?: string;
        backupCodes: string[];
        issuer: string;
      };
    }
  >();

  private clearEnrollmentCacheForUser(userId: string) {
    for (const [k, v] of this.pendingEnrollmentCache.entries()) {
      if (v.userId === userId || v.expiresAtMs <= Date.now()) {
        this.pendingEnrollmentCache.delete(k);
      }
    }
  }

  public async login(params: {
    username: string;
    password: string;
    ipAddress?: string;
    userAgent?: string;
  }): Promise<{
    status: 'AUTHENTICATED' | 'MFA_REQUIRED' | 'PENDING_APPROVAL' | 'REJECTED' | 'SUSPENDED';
    token?: string;
    user?: SanitizedUser;
    mfaChallengeId?: string;
    enrollmentRequired?: boolean;
    phoneMasked?: string;
    emailMasked?: string;
    methods?: string[];
    preferredMethod?: 'authenticator' | 'backup_code';
    recoveryCodesRemaining?: number;
    attemptsLeft?: number;
    error?: string;
    remainingAttempts?: number;
  }> {
    const { username, password, ipAddress = '127.0.0.1' } = params;
    const identifier = `${ipAddress}:${username.trim().toLowerCase()}`;

    // 1. Check rate limit & brute force protection
    const rateCheck = rateLimiter.checkLoginAllowed(identifier);
    if (!rateCheck.allowed) {
      return {
        status: 'SUSPENDED',
        error: `Account temporarily locked out due to repeated login failures. Try again in ${rateCheck.remainingLockoutSeconds} seconds.`
      };
    }

    // 2. Lookup user in database (no dynamic user creation during login)
    const user = userRepository.findByUsername(username);
    if (!user) {
      const fail = rateLimiter.recordLoginFailure(identifier);
      auditRepository.record({
        username,
        requested_function: '/api/v1/auth/login',
        calculated_risk: 80,
        status: 'BLOCKED',
        reason: 'Failed login attempt: User not found.',
        verification_latency_ms: 1.2,
        event_type: 'LOGIN_FAILURE'
      });
      return {
        status: 'REJECTED',
        error: 'Invalid credentials or unapproved account.',
        remainingAttempts: fail.remainingAttempts
      };
    }

    // 3. Cryptographic Password Verification (Strict Constant-Time PBKDF2)
    const isPasswordValid = verifyPassword(password, user.password_salt, user.password_hash);

    if (!isPasswordValid) {
      const fail = rateLimiter.recordLoginFailure(identifier);
      auditRepository.record({
        username: user.username,
        requested_function: '/api/v1/auth/login',
        calculated_risk: Math.min(100, user.base_risk_score + 30),
        status: 'BLOCKED',
        reason: 'Failed login attempt: Cryptographic password verification failed.',
        verification_latency_ms: 1.5,
        event_type: 'INVALID_CREDENTIALS'
      });
      return {
        status: 'REJECTED',
        error: 'Authentication failed: Incorrect password for this identity.',
        remainingAttempts: fail.remainingAttempts
      };
    }

    // Password passed: reset failed attempts counter
    rateLimiter.recordLoginSuccess(identifier);

    // 4. Zero-Trust Approval Status Verification
    if (user.status === 'PENDING_APPROVAL') {
      return {
        status: 'PENDING_APPROVAL',
        user: userRepository.sanitize(user),
        error: 'Zero-Trust Gate: Account pending Administrator verification and clearance.'
      };
    }

    if (user.status === 'REJECTED') {
      return {
        status: 'REJECTED',
        error: 'Access Denied: Account clearance was rejected by SecOps Administration.'
      };
    }

    if (user.status === 'SUSPENDED') {
      return {
        status: 'SUSPENDED',
        error: 'Access Denied: Account is suspended due to elevated security threat profile.'
      };
    }

    // 5. Multi-Factor Authentication Check (Persistent mfa_challenges Registry)
    if (user.mfa_enabled) {
      const challengeId = `mfa_${crypto.randomBytes(16).toString('hex')}`;
      const challengeToken = `tok_${crypto.randomBytes(20).toString('hex')}`;
      let secretToUse = user.mfa_secret;
      if (!secretToUse || secretToUse.trim().length < 16) {
        secretToUse = generateTotpSecret(20);
        userRepository.update(user.id, { mfa_secret: secretToUse });
      } else if (secretToUse.length < 26) {
        secretToUse = normalizeBase32Secret(secretToUse);
        userRepository.update(user.id, { mfa_secret: secretToUse });
      }

      const nowIso = new Date().toISOString();
      const expiresAtIso = new Date(Date.now() + CONFIG.MFA_CHALLENGE_TTL_MS).toISOString();

      db.prepare(
        `INSERT INTO mfa_challenges (
          id, user_id, challenge_token, expires_at, attempts, max_attempts, consumed, created_at
        ) VALUES (?, ?, ?, ?, 0, ?, 0, ?)`
      ).bind(challengeId, user.id, challengeToken, expiresAtIso, CONFIG.MFA_MAX_ATTEMPTS, nowIso).run();

      auditRepository.record({
        username: user.username,
        requested_function: '/api/v1/auth/login',
        calculated_risk: user.base_risk_score,
        status: 'ALLOWED',
        reason: `[MFA CHALLENGE] Password verified for ${user.username}. Recovery-code or RFC 6238 TOTP verification required.`,
        verification_latency_ms: 1.1,
        event_type: 'MFA_CHALLENGE_ISSUED'
      });

      const hasTotpEnrolled = typeof user.last_totp_step === 'number' && user.last_totp_step > 0;
      const enrollmentRequired = !user.mfa_enrolled && !hasTotpEnrolled;
      const preferredMethod: 'authenticator' | 'backup_code' =
        enrollmentRequired || !hasTotpEnrolled ? 'backup_code' : 'authenticator';
      const recoveryCodesRemaining = Array.isArray(user.mfa_backup_codes) ? user.mfa_backup_codes.length : 0;

      return {
        status: 'MFA_REQUIRED',
        mfaChallengeId: challengeId,
        enrollmentRequired,
        phoneMasked: maskPhone(user.phone),
        emailMasked: maskEmail(user.email),
        methods: ['backup_code', 'authenticator'],
        preferredMethod,
        recoveryCodesRemaining,
        attemptsLeft: CONFIG.MFA_MAX_ATTEMPTS,
        user: userRepository.sanitize(user)
      };
    }

    // 6. Issue Cryptographically Signed JWT & Persistent Session in D1
    return this.completeLoginSession(user, params.ipAddress, params.userAgent);
  }

  public async verifyMfa(params: {
    mfaChallengeId: string;
    code: string;
    method?: string;
    username?: string;
    ipAddress?: string;
    userAgent?: string;
  }): Promise<{
    success: boolean;
    token?: string;
    user?: SanitizedUser;
    mfaMethod?: 'authenticator' | 'backup_code';
    recoveryCodesRemaining?: number;
    error?: string;
    attemptsLeft?: number;
  }> {
    const { mfaChallengeId, code, method, ipAddress, userAgent, username } = params;
    if (!mfaChallengeId || !mfaChallengeId.trim()) {
      return {
        success: false,
        error: 'MFA challenge identifier is required.'
      };
    }

    const challengeKey = mfaChallengeId.trim();
    const cleanCode = (code || '').trim().replace(/[\s\-]/g, '');

    let auditEventToRecord: {
      username: string;
      requested_function: string;
      calculated_risk: number;
      status: 'ALLOWED' | 'BLOCKED';
      reason: string;
      verification_latency_ms: number;
      event_type: string;
    }[] = [];

    let txOutcome:
      | { ok: true; user: UserRecord; mfaMethod: 'authenticator' | 'backup_code'; recoveryCodesRemaining: number }
      | { ok: false; error: string; attemptsLeft?: number } = {
      ok: false,
      error: 'MFA verification failed.'
    };

    db.exec('BEGIN IMMEDIATE;');
    try {
      const challengeRow = db.prepare(
        'SELECT * FROM mfa_challenges WHERE id = ? OR challenge_token = ? LIMIT 1'
      ).bind(challengeKey, challengeKey).first<any>();

      if (!challengeRow) {
        txOutcome = {
          ok: false,
          error: 'MFA challenge not found or expired. Please re-authenticate.'
        };
      } else if (challengeRow.consumed) {
        txOutcome = {
          ok: false,
          error: 'MFA challenge has already been consumed. Please re-authenticate.'
        };
      } else if (new Date(challengeRow.expires_at).getTime() <= Date.now()) {
        db.prepare('UPDATE mfa_challenges SET consumed = 1 WHERE id = ?').bind(challengeRow.id).run();
        txOutcome = {
          ok: false,
          error: 'MFA challenge timed out (5-minute security limit exceeded). Please re-enter credentials.'
        };
      } else {
        const currentAttempts = Number(challengeRow.attempts || 0);
        const maxAttempts = Number(challengeRow.max_attempts || CONFIG.MFA_MAX_ATTEMPTS);

        if (currentAttempts >= maxAttempts) {
          db.prepare('UPDATE mfa_challenges SET consumed = 1 WHERE id = ?').bind(challengeRow.id).run();
          txOutcome = {
            ok: false,
            error: 'MFA verification locked out. Maximum attempts exceeded. Please re-authenticate.',
            attemptsLeft: 0
          };
        } else {
          const user = userRepository.findById(challengeRow.user_id);
          if (!user) {
            db.prepare('UPDATE mfa_challenges SET consumed = 1 WHERE id = ?').bind(challengeRow.id).run();
            txOutcome = {
              ok: false,
              error: 'User record for MFA challenge not found. Please re-authenticate.'
            };
          } else if (username && username.trim().toLowerCase() !== user.username.toLowerCase()) {
            txOutcome = {
              ok: false,
              error: 'MFA challenge binding mismatch for specified principal.'
            };
          } else if (!user.mfa_secret || !user.mfa_secret.trim()) {
            txOutcome = {
              ok: false,
              error: 'MFA is not configured for this principal.'
            };
          } else {
            const storedBase32Secret = normalizeBase32Secret(user.mfa_secret);
            const backupHashes = Array.isArray(user.mfa_backup_codes) ? user.mfa_backup_codes : [];

            let isCodeValid = false;
            let verifiedStep: number | undefined;
            let consumedRecoveryCode = false;
            let remainingHashedCodes = backupHashes;
            let replayBlocked = false;
            let exhaustedRecoveryCodes = false;

            // 1. RFC 6238 TOTP check when code is 6 digits and caller did not force backup_code
            if (method !== 'backup_code' && /^\d{6}$/.test(cleanCode)) {
              const totpResult = verifyTotpToken(cleanCode, storedBase32Secret, 0, 1);
              if (totpResult.valid) {
                if (
                  typeof user.last_totp_step === 'number' &&
                  totpResult.timeWindow &&
                  totpResult.timeWindow <= user.last_totp_step
                ) {
                  replayBlocked = true;
                  logger.warn('MFA_REPLAY_BLOCKED', 'MFA TOTP replay attempt blocked', {
                    userId: user.id,
                    metadata: { username: user.username, timeStep: totpResult.timeWindow }
                  });
                } else {
                  isCodeValid = true;
                  verifiedStep = totpResult.timeWindow;
                }
              }
            }

            // 2. Single-Use SHA-256 Recovery Code verification & atomic consumption
            if (!isCodeValid && !replayBlocked && (method === 'backup_code' || cleanCode.length >= 8)) {
              if (backupHashes.length === 0) {
                exhaustedRecoveryCodes = true;
              } else {
                const backupResult = verifyRecoveryCode(cleanCode, backupHashes);
                if (backupResult.valid && backupResult.matchedHash) {
                  isCodeValid = true;
                  consumedRecoveryCode = true;
                  remainingHashedCodes = backupHashes.filter((h) => h !== backupResult.matchedHash);
                }
              }
            }

            if (replayBlocked) {
              auditEventToRecord.push({
                username: user.username,
                requested_function: '/api/v1/auth/mfa/verify',
                calculated_risk: Math.min(100, user.base_risk_score + 30),
                status: 'BLOCKED',
                reason: `[MFA REPLAY BLOCKED] TOTP time-step replay rejected for ${user.username}.`,
                verification_latency_ms: 1.1,
                event_type: 'MFA_REPLAY_BLOCKED'
              });
              txOutcome = {
                ok: false,
                error: 'Replay Attack Prevention: This TOTP time-step was already consumed. Please wait for the next 30-second token.',
                attemptsLeft: Math.max(0, maxAttempts - currentAttempts)
              };
            } else if (!isCodeValid) {
              const nextAttempts = currentAttempts + 1;
              const attemptsLeft = Math.max(0, maxAttempts - nextAttempts);
              const shouldConsume = nextAttempts >= maxAttempts ? 1 : 0;

              db.prepare('UPDATE mfa_challenges SET attempts = ?, consumed = ? WHERE id = ?')
                .bind(nextAttempts, shouldConsume, challengeRow.id)
                .run();

              auditEventToRecord.push({
                username: user.username,
                requested_function: '/api/v1/auth/mfa/verify',
                calculated_risk: Math.min(100, user.base_risk_score + 25),
                status: 'BLOCKED',
                reason: exhaustedRecoveryCodes
                  ? `[RECOVERY CODES EXHAUSTED] ${user.username} attempted recovery-code verification with 0 valid codes remaining (${attemptsLeft} attempts left).`
                  : `[MFA REJECTED] Invalid ${method === 'backup_code' ? 'recovery code' : 'verification code'} submitted (${attemptsLeft} attempts remaining).`,
                verification_latency_ms: 1.4,
                event_type: attemptsLeft <= 0 ? 'MFA_LOCKOUT' : 'MFA_VERIFICATION_FAILURE'
              });

              txOutcome =
                attemptsLeft <= 0
                  ? {
                      ok: false,
                      error: 'MFA verification locked out. Maximum attempts exceeded. Please re-authenticate.',
                      attemptsLeft: 0
                    }
                  : exhaustedRecoveryCodes
                  ? {
                      ok: false,
                      error: `No valid recovery codes remain for this account (0 remaining). Contact an Administrator to reset MFA or regenerate recovery codes. ${attemptsLeft} attempts remaining.`,
                      attemptsLeft
                    }
                  : {
                      ok: false,
                      error: `Invalid verification code. ${attemptsLeft} attempts remaining.`,
                      attemptsLeft
                    };
            } else {
              // Consume challenge strictly once inside BEGIN IMMEDIATE lock
              const consumeRes = db.prepare(
                'UPDATE mfa_challenges SET consumed = 1 WHERE id = ? AND consumed = 0'
              ).bind(challengeRow.id).run();

              if ((consumeRes.changes || 0) === 0) {
                txOutcome = {
                  ok: false,
                  error: 'MFA challenge already consumed. Please re-authenticate.'
                };
              } else {
                const wasFirstEnrollment = !user.mfa_enrolled;

                if (consumedRecoveryCode) {
                  db.prepare(
                    'UPDATE users SET mfa_backup_codes = ?, mfa_enrolled = 1 WHERE id = ?'
                  ).bind(JSON.stringify(remainingHashedCodes), user.id).run();

                  auditEventToRecord.push({
                    username: user.username,
                    requested_function: '/api/v1/auth/mfa/verify',
                    calculated_risk: 15,
                    status: 'ALLOWED',
                    reason: `[RECOVERY CODE CONSUMED] Single-use recovery code verified & permanently invalidated for ${user.username} (${remainingHashedCodes.length} remaining).`,
                    verification_latency_ms: 1.2,
                    event_type: 'BACKUP_CODE_CONSUMED'
                  });

                  if (wasFirstEnrollment) {
                    auditEventToRecord.push({
                      username: user.username,
                      requested_function: '/api/v1/auth/mfa/verify',
                      calculated_risk: user.base_risk_score,
                      status: 'ALLOWED',
                      reason: `[RECOVERY ENROLLMENT COMPLETED] Laptop-only recovery-code MFA activated for ${user.username} (${remainingHashedCodes.length} backup codes remaining).`,
                      verification_latency_ms: 1.0,
                      event_type: 'RECOVERY_CODE_ENROLLMENT_COMPLETED'
                    });
                  }
                } else if (typeof verifiedStep === 'number') {
                  db.prepare(
                    'UPDATE users SET last_totp_step = ?, mfa_enrolled = 1 WHERE id = ?'
                  ).bind(verifiedStep, user.id).run();
                }

                auditEventToRecord.push({
                  username: user.username,
                  requested_function: '/api/v1/auth/mfa/verify',
                  calculated_risk: user.base_risk_score,
                  status: 'ALLOWED',
                  reason: consumedRecoveryCode
                    ? `[MFA AUTHORIZED] Multi-factor authentication confirmed via single-use recovery code (${remainingHashedCodes.length} remaining). Cryptographic JWT session established.`
                    : `[MFA AUTHORIZED] Multi-factor authentication successfully confirmed via RFC 6238 TOTP. Cryptographic JWT session established.`,
                  verification_latency_ms: 1.2,
                  event_type: 'MFA_SUCCESS'
                });

                const updatedUser = userRepository.findById(user.id) || user;
                txOutcome = {
                  ok: true,
                  user: updatedUser,
                  mfaMethod: consumedRecoveryCode ? 'backup_code' : 'authenticator',
                  recoveryCodesRemaining: remainingHashedCodes.length
                };
              }
            }
          }
        }
      }

      db.exec('COMMIT;');
    } catch (err) {
      try {
        db.exec('ROLLBACK;');
      } catch {
        // ignore rollback error
      }
      throw err;
    }

    for (const ev of auditEventToRecord) {
      auditRepository.record(ev);
    }

    if (!txOutcome.ok) {
      const failedOutcome = txOutcome as { ok: false; error: string; attemptsLeft?: number };
      return {
        success: false,
        error: failedOutcome.error,
        attemptsLeft: failedOutcome.attemptsLeft
      };
    }

    const okOutcome = txOutcome as {
      ok: true;
      user: UserRecord;
      mfaMethod: 'authenticator' | 'backup_code';
      recoveryCodesRemaining: number;
    };
    this.clearEnrollmentCacheForUser(okOutcome.user.id);
    const sessionRes = this.completeLoginSession(okOutcome.user, ipAddress, userAgent);
    return {
      success: true,
      token: sessionRes.token,
      user: sessionRes.user,
      mfaMethod: okOutcome.mfaMethod,
      recoveryCodesRemaining: okOutcome.recoveryCodesRemaining
    };
  }

  public completeLoginSession(user: UserRecord, ipAddress?: string, userAgent?: string) {
    userRepository.update(user.id, { last_login_at: new Date().toISOString() });

    // Issue genuine RFC 7519 HMAC-SHA256 Signed JWT
    const token = signJwt({
      sub: user.id,
      username: user.username,
      role: user.role,
      jti: `jti_${crypto.randomBytes(12).toString('hex')}`,
      expiresInSeconds: CONFIG.JWT_EXPIRY_SECONDS
    });

    // Write persistent session record into D1 SQLite
    sessionRepository.createSession({
      userId: user.id,
      username: user.username,
      role: user.role,
      token,
      expiresInSeconds: CONFIG.JWT_EXPIRY_SECONDS,
      ipAddress,
      userAgent
    });

    return {
      status: 'AUTHENTICATED' as const,
      token,
      user: userRepository.sanitize(user)
    };
  }

  public setupMfa(userId: string): { secret: string; uri: string; backupCodes: string[] } {
    const user = userRepository.findById(userId);
    if (!user) throw new Error('User not found');

    const secret = generateTotpSecret();
    const { plaintextCodes, hashedCodes } = generateBackupCodes(8);

    userRepository.update(user.id, {
      mfa_secret: secret,
      mfa_backup_codes: hashedCodes,
      mfa_enabled: true,
      mfa_enrolled: true
    });

    const uri = `otpauth://totp/ServerlessSecOps:${encodeURIComponent(user.username)}?secret=${secret}&issuer=ServerlessSecOps&algorithm=SHA1&digits=6&period=30`;

    auditRepository.record({
      username: user.username,
      requested_function: '/api/v1/auth/mfa/setup',
      calculated_risk: 0,
      status: 'ALLOWED',
      reason: `MFA enrollment completed for user ${user.username}. 8 single-use recovery codes generated.`,
      verification_latency_ms: 0.8,
      event_type: 'MFA_ENROLLED'
    });

    return { secret, uri, backupCodes: plaintextCodes };
  }

  /**
   * Provides one-time MFA enrollment material for an active Factor-1 MFA challenge
   * ONLY if the identity has not yet completed MFA enrollment (mfa_enrolled = false and last_totp_step = 0).
   * Supports laptop-only 'recovery_codes' mode (no authenticator app required) or 'authenticator' TOTP QR mode.
   */
  public getChallengeEnrollment(
    mfaChallengeId: string,
    mode?: 'recovery_codes' | 'authenticator',
    forceRefresh = false
  ): {
    success: boolean;
    status?: number;
    error?: string;
    mode?: 'recovery_codes' | 'authenticator';
    username?: string;
    secret?: string;
    provisioningUri?: string;
    backupCodes?: string[];
    issuer?: string;
  } {
    const cid = (mfaChallengeId || '').trim();
    if (!cid) {
      return { success: false, status: 400, error: 'MFA challenge identifier is required.' };
    }

    const effectiveMode: 'recovery_codes' | 'authenticator' =
      mode === 'recovery_codes' ? 'recovery_codes' : 'authenticator';

    db.exec('BEGIN IMMEDIATE;');
    try {
      const challengeRow = db.prepare(
        'SELECT * FROM mfa_challenges WHERE id = ? OR challenge_token = ? LIMIT 1'
      ).bind(cid, cid).first<any>();

      if (!challengeRow || challengeRow.consumed) {
        db.exec('COMMIT;');
        return { success: false, status: 401, error: 'MFA challenge not found or already consumed. Please sign in again.' };
      }
      if (new Date(challengeRow.expires_at).getTime() <= Date.now()) {
        db.exec('COMMIT;');
        return { success: false, status: 401, error: 'MFA challenge expired. Please sign in again.' };
      }
      if (Number(challengeRow.attempts || 0) >= Number(challengeRow.max_attempts || CONFIG.MFA_MAX_ATTEMPTS)) {
        db.exec('COMMIT;');
        return { success: false, status: 429, error: 'MFA challenge locked due to failed attempts. Please sign in again.' };
      }

      const user = userRepository.findById(challengeRow.user_id);
      if (!user) {
        db.exec('COMMIT;');
        return { success: false, status: 404, error: 'User identity not found.' };
      }

      if (user.mfa_enrolled || (typeof user.last_totp_step === 'number' && user.last_totp_step > 0)) {
        this.clearEnrollmentCacheForUser(user.id);
        db.exec('COMMIT;');
        return {
          success: false,
          status: 403,
          error: 'MFA is already enrolled for this identity. Enter a recovery code, your 6-digit TOTP code, or contact an Administrator to reset MFA.'
        };
      }

      const cacheKey = `${challengeRow.id}:${effectiveMode}`;
      if (!forceRefresh) {
        const cached = this.pendingEnrollmentCache.get(cacheKey);
        if (cached && cached.expiresAtMs > Date.now()) {
          db.exec('COMMIT;');
          return cached.result;
        }
      }

      // Invalidate any prior mode cache for this challenge before generating a new set
      for (const k of Array.from(this.pendingEnrollmentCache.keys())) {
        if (k.startsWith(`${challengeRow.id}:`)) {
          this.pendingEnrollmentCache.delete(k);
        }
      }

      const { plaintextCodes, hashedCodes } = generateRecoveryCodes(8);
      const expiresAtMs = Math.min(new Date(challengeRow.expires_at).getTime(), Date.now() + 5 * 60 * 1000);

      if (effectiveMode === 'recovery_codes') {
        const upd = db.prepare(
          'UPDATE users SET mfa_backup_codes = ?, mfa_enabled = 1 WHERE id = ? AND COALESCE(mfa_enrolled, 0) = 0 AND COALESCE(last_totp_step, 0) = 0'
        ).bind(JSON.stringify(hashedCodes), user.id).run();
        if (!upd.changes) {
          db.exec('COMMIT;');
          return {
            success: false,
            status: 403,
            error: 'MFA is already enrolled for this identity. Enter a recovery code, your 6-digit TOTP code, or contact an Administrator to reset MFA.'
          };
        }

        const result = {
          success: true as const,
          mode: 'recovery_codes' as const,
          username: user.username,
          backupCodes: plaintextCodes,
          issuer: 'ServerlessSecOps'
        };
        this.pendingEnrollmentCache.set(cacheKey, { userId: user.id, expiresAtMs, result });
        db.exec('COMMIT;');

        auditRepository.record({
          username: user.username,
          requested_function: '/api/auth/mfa/enroll-challenge',
          calculated_risk: user.base_risk_score,
          status: 'ALLOWED',
          reason: `[RECOVERY ENROLLMENT ISSUED] Issued 8 single-use hashed recovery codes for laptop-only MFA setup (${user.username}). Pending confirmation.`,
          verification_latency_ms: 0.9,
          event_type: 'RECOVERY_CODE_ENROLLMENT_STARTED'
        });

        return result;
      }

      const secret = user.mfa_secret && user.mfa_secret.trim().length >= 16
        ? normalizeBase32Secret(user.mfa_secret)
        : generateTotpSecret(20);

      const updAuth = db.prepare(
        'UPDATE users SET mfa_secret = ?, mfa_backup_codes = ?, mfa_enabled = 1 WHERE id = ? AND COALESCE(mfa_enrolled, 0) = 0 AND COALESCE(last_totp_step, 0) = 0'
      ).bind(secret, JSON.stringify(hashedCodes), user.id).run();
      if (!updAuth.changes) {
        db.exec('COMMIT;');
        return {
          success: false,
          status: 403,
          error: 'MFA is already enrolled for this identity. Enter a recovery code, your 6-digit TOTP code, or contact an Administrator to reset MFA.'
        };
      }

      const provisioningUri = `otpauth://totp/ServerlessSecOps:${encodeURIComponent(user.username)}?secret=${secret}&issuer=ServerlessSecOps&algorithm=SHA1&digits=6&period=30`;
      const result = {
        success: true as const,
        mode: 'authenticator' as const,
        username: user.username,
        secret,
        provisioningUri,
        backupCodes: plaintextCodes,
        issuer: 'ServerlessSecOps'
      };
      this.pendingEnrollmentCache.set(cacheKey, { userId: user.id, expiresAtMs, result });
      db.exec('COMMIT;');

      auditRepository.record({
        username: user.username,
        requested_function: '/api/auth/mfa/enroll-challenge',
        calculated_risk: user.base_risk_score,
        status: 'ALLOWED',
        reason: `[FIRST-TIME MFA PAIRING] Issued one-time Authenticator QR & recovery codes for unenrolled identity ${user.username}.`,
        verification_latency_ms: 0.9,
        event_type: 'MFA_PAIRING_ISSUED'
      });

      return result;
    } catch (err) {
      try {
        db.exec('ROLLBACK;');
      } catch {
        // ignore rollback error
      }
      throw err;
    }
  }

  public resetMfaEnrollment(targetUsernameOrId: string, adminUsername: string) {
    const user = userRepository.findByUsername(targetUsernameOrId) || userRepository.findById(targetUsernameOrId);
    if (!user) return null;
    const newSecret = generateTotpSecret(20);
    const { hashedCodes } = generateRecoveryCodes(8);

    // Revoke all existing sessions and consume pending MFA challenges on reset
    sessionRepository.revoke({
      username: user.username,
      revokedBy: adminUsername,
      reason: 'MFA enrollment reset by Administrator'
    });
    db.prepare('UPDATE mfa_challenges SET consumed = 1 WHERE user_id = ? AND consumed = 0')
      .bind(user.id)
      .run();

    const updated = userRepository.update(user.id, {
      mfa_secret: newSecret,
      mfa_backup_codes: hashedCodes,
      mfa_enabled: true,
      mfa_enrolled: false,
      last_totp_step: 0
    });

    auditRepository.record({
      username: adminUsername,
      requested_function: `/api/system/users/${user.username}/mfa-reset`,
      calculated_risk: 15,
      status: 'ALLOWED',
      reason: `[ADMIN MFA RESET] MFA enrollment & recovery codes reset for ${user.username} by ${adminUsername} at ${new Date().toISOString()}; existing sessions revoked. Outcome: RESET_COMPLETED.`,
      verification_latency_ms: 1.0,
      event_type: 'MFA_ENROLLMENT_RESET'
    });

    return updated;
  }

  public logout(token: string, username: string) {
    sessionRepository.revoke({
      token,
      username,
      revokedBy: username,
      reason: 'User voluntary session termination'
    });
  }

  public revokeUserSession(targetUsername: string, revokedBy: string, reason?: string) {
    return sessionRepository.revoke({
      username: targetUsername,
      revokedBy,
      reason: reason || 'Terminated by Administrator via SecOps Console'
    });
  }

  public changePassword(userId: string, oldPlaintext: string, newPlaintext: string): boolean {
    const user = userRepository.findById(userId);
    if (!user) return false;
    if (!verifyPassword(oldPlaintext, user.password_salt, user.password_hash)) {
      return false;
    }

    userRepository.updatePassword(userId, newPlaintext);

    // Invalidate existing sessions on password change
    sessionRepository.revoke({
      username: user.username,
      revokedBy: user.username,
      reason: 'Password change invalidation'
    });

    auditRepository.record({
      username: user.username,
      requested_function: '/api/v1/auth/change-password',
      calculated_risk: 10,
      status: 'ALLOWED',
      reason: `Password updated successfully for ${user.username}. Existing sessions revoked in D1.`,
      verification_latency_ms: 1.5,
      event_type: 'PASSWORD_CHANGED'
    });

    return true;
  }
}

export const authService = new AuthService();
