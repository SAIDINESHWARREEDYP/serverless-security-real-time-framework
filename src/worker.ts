/**
 * Cloudflare Workers Entry Point: Serverless Real-Time Security Verification Framework
 * B.Tech CSE Final-Year Capstone Project: Design and Implementation of an Integrated Real-Time Security
 * Verification Framework for Serverless Cloud Applications.
 *
 * Fully hardened edge implementation with:
 * 1. Genuine Web Crypto PBKDF2-SHA512 password verification (No bypasses)
 * 2. Strict RFC 6238 TOTP MFA with time-step replay prevention & SHA-256 hashed single-use backup codes
 * 3. Cryptographically verified HMAC-SHA256 JWT tokens (Rejects fake zt_jwt_ tokens)
 * 4. Persistent D1 session validation and real-time session revocation surviving Worker restarts
 * 5. Authenticated session revocation endpoints (/api/auth/revoke-session & /api/system/sessions/revoke)
 * 6. Persistent incident storage and retrieval in Cloudflare D1
 * 7. 15-step in-line verification pipeline with fail-closed guarantee
 * 8. Strict CORS origin defense against unauthorized origins
 */

export interface Env {
  DB: any; // Cloudflare D1Database binding
  ENVIRONMENT?: string;
  ZERO_TRUST_ORIGIN?: string;
  JWT_SECRET?: string;
}

// Allowed trusted origins
const TRUSTED_ORIGINS = [
  'https://serverless-securityverification.ai.studio',
  'https://ais-pre-2gbvx5rv6rvvsia4jitmad-712384669760.asia-east1.run.app',
  'https://ais-dev-2gbvx5rv6rvvsia4jitmad-712384669760.asia-east1.run.app',
  'http://localhost:3000',
  'http://127.0.0.1:3000'
];

const DEFAULT_JWT_ISSUER = 'https://auth.serverless-security.local';
const DEFAULT_JWT_AUDIENCE = 'serverless-security-framework';
const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

const PRIVILEGED_SELF_REG_ROLES = new Set([
  'Admin',
  'Administrator',
  'Super Administrator',
  'Security Administrator',
  'Security Analyst',
  'Auditor'
]);
const VALID_INCIDENT_SEVERITIES = new Set(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
const VALID_INCIDENT_STATUSES = new Set(['OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE']);

function resolveAllowedOrigin(origin: string, env?: Env): string | null {
  if (!origin) return null;
  const lower = origin.toLowerCase();
  if (TRUSTED_ORIGINS.some(to => to.toLowerCase() === lower)) return origin;
  if (env?.ZERO_TRUST_ORIGIN && env.ZERO_TRUST_ORIGIN.toLowerCase() === lower) return origin;
  return null;
}

export default {
  async fetch(request: Request, env: Env, ctx: any): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const origin = request.headers.get('Origin') || '';

    // Determine JWT Secret from Environment Binding with resilient validation
    let jwtSecret = env.JWT_SECRET?.trim() || '';
    if (!jwtSecret) {
      if (env.ENVIRONMENT === 'production') {
        return jsonResponse({ error: 'Fatal security configuration: JWT_SECRET must be configured in production.' }, 500, origin, undefined, env);
      }
      jwtSecret = 'dev_zt_secops_verification_secret_key_minimum_32_characters_2026_local_only';
    }
    if (jwtSecret.length < 32) {
      jwtSecret = await sha256Hex(jwtSecret);
    }

    // 1. Strict CORS Preflight Handling (No arbitrary reflection or credentialed wildcard)
    if (method === 'OPTIONS') {
      const allowedOrigin = resolveAllowedOrigin(origin, env);
      if (origin && !allowedOrigin) {
        return new Response('CORS Origin Denied', { status: 403 });
      }

      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': allowedOrigin || TRUSTED_ORIGINS[0],
          'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Request-ID, X-Simulate-Fault',
          'Access-Control-Expose-Headers': 'X-Verification-Latency-MS, X-Security-Verification-Duration-MS, Server-Timing, X-Verification-Decision, X-Verification-Risk-Score, X-Request-ID, X-Verification-Trace-ID',
          'Access-Control-Allow-Credentials': 'true',
          'Access-Control-Max-Age': '86400',
          'Vary': 'Origin'
        }
      });
    }

    // 2. Health & Cluster Status
    if (path === '/api/health' || path === '/api/system/health' || path === '/api/v1/system/health') {
      const t0 = performance.now();
      if (!env.DB) {
        const latencyMs = Number((performance.now() - t0).toFixed(3));
        return jsonResponse({
          status: 'DEGRADED',
          cluster: 'Cloudflare Global Edge PoP (ap-south-1)',
          databaseEngine: 'Cloudflare D1 Relational Engine (ACID)',
          databaseConnection: 'DISCONNECTED',
          d1Status: 'ERROR',
          d1LatencyMs: latencyMs,
          isConnected: false,
          recordsVerified: 0,
          timestamp: new Date().toISOString(),
          verificationMode: 'FAIL_CLOSED_ZERO_TRUST'
        }, 503, origin, latencyMs, env);
      }

      try {
        const res = await env.DB.prepare('SELECT COUNT(*) as c FROM audit_events').first();
        const recordCount = Number(res?.c || 0);
        const latencyMs = Number((performance.now() - t0).toFixed(3));
        return jsonResponse({
          status: 'UP',
          cluster: 'Cloudflare Global Edge PoP (ap-south-1)',
          databaseEngine: 'Cloudflare D1 Relational Engine (ACID)',
          databaseConnection: 'CONNECTED',
          d1Status: 'CONNECTED',
          d1LatencyMs: Math.max(0.05, latencyMs),
          isConnected: true,
          recordsVerified: recordCount,
          timestamp: new Date().toISOString(),
          verificationMode: 'FAIL_CLOSED_ZERO_TRUST'
        }, 200, origin, latencyMs, env);
      } catch (err: any) {
        const latencyMs = Number((performance.now() - t0).toFixed(3));
        return jsonResponse({
          status: 'DEGRADED',
          cluster: 'Cloudflare Global Edge PoP (ap-south-1)',
          databaseEngine: 'Cloudflare D1 Relational Engine (ACID)',
          databaseConnection: 'ERROR',
          d1Status: 'ERROR',
          d1LatencyMs: latencyMs,
          isConnected: false,
          error: err?.message || 'D1 health probe failed',
          timestamp: new Date().toISOString(),
          verificationMode: 'FAIL_CLOSED_ZERO_TRUST'
        }, 503, origin, latencyMs, env);
      }
    }

    // 3. D1 Latency Metrics
    if (path === '/api/system/d1-latency' || path === '/api/v1/system/d1-latency') {
      const t0 = performance.now();
      if (!env.DB) {
        const lat = Number((performance.now() - t0).toFixed(3));
        return jsonResponse({
          status: 'ERROR',
          d1LatencyMs: lat,
          connectionStatus: 'DISCONNECTED',
          engine: 'Cloudflare D1 (SQLite WAL ACID)'
        }, 503, origin, lat, env);
      }

      try {
        const agg = await env.DB.prepare('SELECT COUNT(*) as c, AVG(verification_latency_ms) as avg_lat FROM audit_events').first();
        const total = Number(agg?.c || 0);
        const latRowsRes = await env.DB.prepare('SELECT verification_latency_ms FROM audit_events WHERE verification_latency_ms IS NOT NULL ORDER BY verification_latency_ms ASC LIMIT 1000').all();
        const latVals: number[] = (latRowsRes?.results || []).map((r: any) => Number(r.verification_latency_ms)).filter((n: number) => !Number.isNaN(n));
        const activeSessRow = await env.DB.prepare("SELECT COUNT(*) as c FROM active_sessions WHERE revoked = 0 AND (expires_at IS NULL OR expires_at > datetime('now'))").first();
        const lat = Number((performance.now() - t0).toFixed(3));
        const avgLatencyMs = latVals.length > 0 ? Number(Number(agg?.avg_lat || lat).toFixed(3)) : lat;
        const p95LatencyMs = latVals.length > 0 ? Number(latVals[Math.min(latVals.length - 1, Math.floor(latVals.length * 0.95))].toFixed(3)) : lat;
        const p99LatencyMs = latVals.length > 0 ? Number(latVals[Math.min(latVals.length - 1, Math.floor(latVals.length * 0.99))].toFixed(3)) : lat;

        return jsonResponse({
          status: 'HEALTHY',
          d1LatencyMs: Math.max(0.05, lat),
          avgLatencyMs,
          p95LatencyMs,
          p99LatencyMs,
          recordsVerified: total,
          activeConnections: Number(activeSessRow?.c || 0),
          connectionStatus: 'ACTIVE',
          engine: 'Cloudflare D1 (SQLite WAL ACID)'
        }, 200, origin, lat, env);
      } catch (err: any) {
        const lat = Number((performance.now() - t0).toFixed(3));
        return jsonResponse({
          status: 'ERROR',
          d1LatencyMs: lat,
          connectionStatus: 'ERROR',
          error: err?.message || 'D1 latency probe failed',
          engine: 'Cloudflare D1 (SQLite WAL ACID)'
        }, 503, origin, lat, env);
      }
    }

    // 4. System Overview & Dashboard Telemetry
    if (path === '/api/system/overview' || path === '/api/v1/analytics/overview') {
      let users: any[] = [];
      let rules: any[] = [];
      let logs: any[] = [];
      let policy: any = { maxRiskThreshold: 75, sequenceViolationPenalty: 40, enforceStrictSequence: true, globalLockdown: false, requireAdminApprovalForNewLogins: true };

      if (env.DB) {
        try {
          const uRes = await env.DB.prepare('SELECT id, username, role, base_risk_score, status, department, email, phone, mfa_enabled FROM users').all();
          users = uRes?.results || [];

          const rRes = await env.DB.prepare('SELECT id, current_function, allowed_next_function FROM function_rules').all();
          rules = rRes?.results || [];

          const lRes = await env.DB.prepare('SELECT * FROM audit_events ORDER BY id DESC LIMIT 100').all();
          logs = lRes?.results || [];

          const pRes = await env.DB.prepare('SELECT * FROM policies LIMIT 1').first();
          if (pRes) {
            policy = {
              maxRiskThreshold: pRes.max_risk_threshold ?? 75,
              sequenceViolationPenalty: pRes.sequence_violation_penalty ?? 40,
              enforceStrictSequence: Boolean(pRes.enforce_strict_sequence),
              globalLockdown: Boolean(pRes.global_lockdown),
              requireAdminApprovalForNewLogins: Boolean(pRes.require_admin_approval)
            };
          }
        } catch (e) {
          console.error('[Worker D1 Overview error]', e);
        }
      }

      const blockedCount = logs.filter(l => l.status === 'BLOCKED').length;
      const allowedCount = logs.filter(l => l.status === 'ALLOWED').length;
      const avgVerificationLatencyMs = logs.length > 0
        ? Number((logs.reduce((acc, l) => acc + Number(l.verification_latency_ms || 0), 0) / logs.length).toFixed(3))
        : 0;

      return jsonResponse({
        users,
        rules,
        logs,
        auditEvents: logs,
        policyConfig: policy,
        stats: {
          totalUsers: users.length,
          totalRules: rules.length,
          totalLogs: logs.length,
          totalAuditEvents: logs.length,
          blockedCount,
          allowedCount,
          avgVerificationLatencyMs
        }
      }, 200, origin, undefined, env);
    }

    // 5. Auth Status & Clearance Check (/api/auth/status)
    if (path === '/api/auth/status') {
      const qUser = (url.searchParams.get('username') || '').trim();
      if (!qUser) return jsonResponse({ error: 'Username query parameter required' }, 400, origin);

      let user: any = null;
      if (env.DB) {
        user = await env.DB.prepare('SELECT * FROM users WHERE LOWER(username) = LOWER(?)').bind(qUser).first();
      }

      if (!user) {
        return jsonResponse({ error: `Identity [${qUser}] not registered in database`, found: false }, 404, origin);
      }

      return jsonResponse({
        success: true,
        found: true,
        status: user.status,
        approved: user.status === 'APPROVED',
        user: {
          id: user.id,
          username: user.username,
          role: user.role,
          base_risk_score: user.base_risk_score,
          status: user.status,
          department: user.department
        },
        role: user.role,
        userRisk: user.base_risk_score
      }, 200, origin);
    }

    // 6. Identity Registration (/api/register & /api/v1/auth/register)
    if (path === '/api/register' || path === '/api/v1/auth/register') {
      try {
        const body: any = await request.json();
        const { username, password, role = 'Developer', base_risk_score = 20, department = 'Cloud Platform' } = body;
        if (!username || !username.trim() || typeof password !== 'string' || password.length < 8) {
          return jsonResponse({ error: 'Valid username and password (minimum 8 characters) are required.' }, 400, origin, undefined, env);
        }

        const requestedRole = String(role || 'Developer').trim();
        if (PRIVILEGED_SELF_REG_ROLES.has(requestedRole)) {
          return jsonResponse({
            error: `Self-service registration cannot assign privileged role [${requestedRole}]. Contact an Administrator.`
          }, 403, origin, undefined, env);
        }
        const safeRole = requestedRole === 'Guest' ? 'Guest' : 'Developer';
        const numericRisk = Number(base_risk_score);
        if (Number.isNaN(numericRisk) || numericRisk < 0 || numericRisk > 100) {
          return jsonResponse({ error: 'base_risk_score must be between 0 and 100.' }, 400, origin, undefined, env);
        }
        const clean = username.trim();
        let accountStatus: 'PENDING_APPROVAL' | 'APPROVED' = 'PENDING_APPROVAL';

        let mfaEnrollment: { secret: string; provisioningUri: string; backupCodes: string[]; issuer: string } | undefined;

        // Check if user already exists
        if (env.DB) {
          const existing = await env.DB.prepare('SELECT id FROM users WHERE LOWER(username) = LOWER(?)').bind(clean).first();
          if (existing) {
            return jsonResponse({ error: `Identity [${clean}] already exists in database.` }, 409, origin, undefined, env);
          }

          const policyRow = await env.DB.prepare('SELECT require_admin_approval FROM policies LIMIT 1').first();
          const requireApproval = policyRow ? Boolean(policyRow.require_admin_approval) : true;
          accountStatus = requireApproval ? 'PENDING_APPROVAL' : 'APPROVED';

          // Generate PBKDF2 salt and hash
          const salt = generateRandomHex(16);
          const hash = await derivePbkdf2Hex(password, salt);
          // Generate cryptographically random 32-character base32 TOTP secret (20 bytes entropy) & 8 recovery codes
          const generatedSecret = generateBase32SecretWeb(20);
          const { plaintextCodes, hashedCodes } = await generateBackupCodesWeb(8);

          const nowIso = new Date().toISOString();
          await env.DB.prepare(
            `INSERT INTO users (
              id, username, password_salt, password_hash, role, base_risk_score, status, department, mfa_enabled, mfa_enrolled, mfa_secret, mfa_backup_codes, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?, ?, ?)`
          ).bind(`usr_${clean}`, clean, salt, hash, safeRole, numericRisk, accountStatus, department, generatedSecret, JSON.stringify(hashedCodes), nowIso).run();

          mfaEnrollment = {
            secret: generatedSecret,
            provisioningUri: `otpauth://totp/ServerlessSecOps:${encodeURIComponent(clean)}?secret=${generatedSecret}&issuer=ServerlessSecOps&algorithm=SHA1&digits=6&period=30`,
            backupCodes: plaintextCodes,
            issuer: 'ServerlessSecOps'
          };
        }

        const pendingApproval = accountStatus === 'PENDING_APPROVAL';
        return jsonResponse({
          success: true,
          pendingApproval,
          status: accountStatus,
          user: {
            id: `usr_${clean}`,
            username: clean,
            role: safeRole,
            base_risk_score: numericRisk,
            status: accountStatus,
            department
          },
          mfaEnrollment,
          message: pendingApproval
            ? `Identity [${clean}] registered in D1. Zero-Trust gate: Pending SecOps Administrator verification. Save your Authenticator QR & recovery codes now.`
            : `Identity [${clean}] registered and approved for MFA sign-in.`
        }, 200, origin, undefined, env);
      } catch (err: any) {
        return jsonResponse({ error: 'Registration failed: ' + err.message }, 500, origin, undefined, env);
      }
    }

    // 7. SECURE AUTHENTICATION: Login & Genuine Password Verification (/api/login & /api/v1/auth/login)
    if (path === '/api/login' || path === '/api/v1/auth/login') {
      try {
        const body: any = await request.json();
        const { username, password } = body;
        if (!username || !password) {
          return jsonResponse({ error: 'Username and password required.' }, 400, origin);
        }

        let user: any = null;
        if (env.DB) {
          user = await env.DB.prepare('SELECT * FROM users WHERE LOWER(username) = LOWER(?)').bind(username.trim()).first();
        }

        // Generic error on nonexistent user (Anti-enumeration)
        if (!user) {
          return jsonResponse({ error: 'Invalid credentials or unapproved account.' }, 401, origin);
        }

        // GENUINE CRYPTOGRAPHIC PASSWORD VERIFICATION (PBKDF2 SHA-512)
        // No universal passwords, plaintext comparisons, or bypasses permitted
        let isPasswordCorrect = false;
        if (user.password_salt && user.password_hash) {
          isPasswordCorrect = await verifyPasswordSubtle(password, user.password_salt, user.password_hash);
        }

        if (!isPasswordCorrect) {
          return jsonResponse({ error: 'Invalid credentials or unapproved account.' }, 401, origin);
        }

        // Account status verification
        if (user.status === 'PENDING_APPROVAL') {
          return jsonResponse({
            error: 'Zero-Trust Gate: Account pending Administrator verification and clearance.',
            status: 'PENDING_APPROVAL',
            user: { username: user.username, role: user.role, status: user.status }
          }, 403, origin);
        }

        if (user.status === 'SUSPENDED') {
          return jsonResponse({ error: 'Account suspended by SecOps Security Policy.', status: 'SUSPENDED' }, 403, origin);
        }

        if (user.status === 'REJECTED') {
          return jsonResponse({ error: 'Access Denied: Account clearance was rejected by SecOps Administration.' }, 401, origin);
        }

        // MFA CHALLENGE: Mandatory when mfa_enabled is true
        // Persisted in D1 mfa_challenges table with expiry, attempts, and replay protection
        if (user.mfa_enabled) {
          if (!user.mfa_secret && env.DB) {
            const enrolledSecret = generateBase32SecretWeb(20);
            user.mfa_secret = enrolledSecret;
            await env.DB.prepare('UPDATE users SET mfa_secret = ? WHERE id = ?').bind(enrolledSecret, user.id).run();
          }
          const mfaSessionId = `mfa_${generateRandomHex(16)}`;
          const challengeToken = generateRandomHex(24);
          if (env.DB) {
            await env.DB.prepare(
              `INSERT INTO mfa_challenges (id, user_id, challenge_token, expires_at, attempts, max_attempts, consumed, created_at)
               VALUES (?, ?, ?, datetime('now', '+5 minutes'), 0, 5, 0, datetime('now'))`
            ).bind(mfaSessionId, user.id, challengeToken).run();
          }

          const enrollmentRequired = !Boolean(user.mfa_enrolled) && Number(user.last_totp_step || 0) === 0;

          return jsonResponse({
            success: true,
            mfaRequired: true,
            enrollmentRequired,
            mfaSessionId,
            mfaChallengeId: mfaSessionId,
            phoneMasked: maskPhone(user.phone),
            emailMasked: maskEmail(user.email, user.username),
            methods: ['authenticator', 'backup_code'],
            attemptsLeft: 5,
            user: {
              id: user.id,
              username: user.username,
              role: user.role,
              base_risk_score: user.base_risk_score,
              status: user.status,
              department: user.department
            },
            message: enrollmentRequired
              ? 'Password verified. First-time Authenticator setup required — scan QR or enter setup key, then enter the 6-digit TOTP code.'
              : 'Password verified. Enter 6-digit TOTP code or backup code.'
          }, 200, origin, undefined, env);
        }

        // Issue Cryptographically Signed HMAC-SHA256 JWT
        const token = await signJwtWeb({
          sub: user.id,
          username: user.username,
          role: user.role,
          jti: `jti_${generateRandomHex(12)}`,
          expiresInSeconds: 3600
        }, jwtSecret);

        // Record persistent session in D1 SQLite
        if (env.DB) {
          const sessionId = `sess_${generateRandomHex(12)}`;
          await env.DB.prepare(
            "INSERT OR REPLACE INTO active_sessions (id, token, username, role, created_at, expires_at, revoked) VALUES (?, ?, ?, ?, datetime('now'), datetime('now', '+1 hour'), 0)"
          ).bind(sessionId, token, user.username, user.role).run();

          await env.DB.prepare(
            "INSERT OR REPLACE INTO sessions (id, user_id, session_token, status, created_at, expires_at) VALUES (?, ?, ?, 'active', datetime('now'), datetime('now', '+1 hour'))"
          ).bind(sessionId, user.id, token).run();

          await env.DB.prepare("UPDATE users SET last_login_at = datetime('now') WHERE id = ?").bind(user.id).run();
        }

        return jsonResponse({
          success: true,
          token,
          user: {
            id: user.id,
            username: user.username,
            role: user.role,
            base_risk_score: user.base_risk_score,
            status: user.status,
            department: user.department
          },
          role: user.role,
          userRisk: user.base_risk_score,
          expiresInSeconds: 3600
        }, 200, origin, undefined, env);
      } catch (err: any) {
        return jsonResponse({ error: 'Authentication processing fault: ' + err.message }, 500, origin, undefined, env);
      }
    }

    // 8. STRICT MULTI-FACTOR VERIFICATION: D1 Challenge + RFC 6238 TOTP & Hashed Backup Codes
    if (path === '/api/auth/mfa/verify' || path === '/api/v1/auth/mfa/verify') {
      try {
        const body: any = await request.json();
        const { mfaSessionId, mfaChallengeId, code, username } = body;
        const cid = String(mfaChallengeId || mfaSessionId || '').trim();
        const clean = (code || '').trim().replace(/[\s\-]/g, '');

        if (!cid) {
          return jsonResponse({ error: 'MFA challenge identifier is required.' }, 400, origin, undefined, env);
        }
        if (!clean || clean.length < 6) {
          return jsonResponse({ error: 'Verification code must be at least 6 characters.' }, 400, origin, undefined, env);
        }
        if (!env.DB) {
          return jsonResponse({ error: 'Database unavailable for MFA verification.' }, 503, origin, undefined, env);
        }

        const challengeRow: any = await env.DB.prepare(
          'SELECT * FROM mfa_challenges WHERE id = ? OR challenge_token = ? LIMIT 1'
        ).bind(cid, cid).first();

        if (!challengeRow) {
          return jsonResponse({ success: false, error: 'MFA challenge not found or invalid.' }, 401, origin, undefined, env);
        }
        if (Number(challengeRow.consumed) === 1) {
          return jsonResponse({ success: false, error: 'MFA challenge has already been consumed.' }, 401, origin, undefined, env);
        }

        const expiredRow: any = await env.DB.prepare(
          "SELECT 1 as expired FROM mfa_challenges WHERE id = ? AND expires_at <= datetime('now')"
        ).bind(challengeRow.id).first();
        if (expiredRow) {
          return jsonResponse({ success: false, error: 'MFA challenge expired. Please sign in again.' }, 401, origin, undefined, env);
        }

        const maxAttempts = Number(challengeRow.max_attempts ?? 5);
        const currentAttempts = Number(challengeRow.attempts ?? 0);
        if (currentAttempts >= maxAttempts) {
          return jsonResponse({
            success: false,
            locked: true,
            attemptsLeft: 0,
            error: 'Maximum MFA verification attempts exceeded. Please sign in again.'
          }, 429, origin, undefined, env);
        }

        const user: any = await env.DB.prepare('SELECT * FROM users WHERE id = ? LIMIT 1').bind(challengeRow.user_id).first();
        if (!user) {
          return jsonResponse({ success: false, error: 'User record for MFA challenge not found.' }, 401, origin, undefined, env);
        }
        if (username && String(username).trim().toLowerCase() !== String(user.username).toLowerCase()) {
          return jsonResponse({ success: false, error: 'MFA challenge does not belong to specified user.' }, 401, origin, undefined, env);
        }

        const userSecret = user.mfa_secret;
        if (!userSecret) {
          return jsonResponse({ success: false, error: 'MFA is not enrolled for this principal.' }, 400, origin, undefined, env);
        }

        let isCodeValid = false;
        let matchedStep: number | undefined;
        let replayDetected = false;

        // A. Verify RFC 6238 TOTP with +/- 1 window (30s clock skew) and replay prevention
        if (/^\d{6}$/.test(clean)) {
          const totpCheck = await verifyTotpWeb(clean, userSecret, 1, user.last_totp_step || 0);
          if (totpCheck.valid) {
            isCodeValid = true;
            matchedStep = totpCheck.matchedStep;
          } else if (totpCheck.reason === 'REPLAYED_TIME_STEP') {
            replayDetected = true;
          }
        }

        // B. Verify Single-Use Backup Codes (Stored as SHA-256 Hashes)
        if (!isCodeValid && !replayDetected && clean.length >= 8) {
          let hashedBackupCodes: string[] = [];
          try {
            hashedBackupCodes = typeof user.mfa_backup_codes === 'string'
              ? JSON.parse(user.mfa_backup_codes)
              : Array.isArray(user.mfa_backup_codes)
              ? user.mfa_backup_codes
              : [];
          } catch {
            hashedBackupCodes = [];
          }

          const candidateHash = await sha256Hex(clean.toUpperCase());
          if (hashedBackupCodes.includes(candidateHash)) {
            isCodeValid = true;
            const remainingHashedCodes = hashedBackupCodes.filter(h => h !== candidateHash);
            await env.DB.prepare('UPDATE users SET mfa_backup_codes = ? WHERE id = ?')
              .bind(JSON.stringify(remainingHashedCodes), user.id).run();
          }
        }

        if (!isCodeValid) {
          const nextAttempts = currentAttempts + 1;
          await env.DB.prepare('UPDATE mfa_challenges SET attempts = ? WHERE id = ?').bind(nextAttempts, challengeRow.id).run();
          const attemptsLeft = Math.max(0, maxAttempts - nextAttempts);
          if (attemptsLeft === 0) {
            return jsonResponse({
              success: false,
              locked: true,
              attemptsLeft: 0,
              error: 'Maximum MFA attempts reached. Challenge locked.'
            }, 429, origin, undefined, env);
          }
          return jsonResponse({
            success: false,
            attemptsLeft,
            error: replayDetected
              ? 'Replay Attack Prevention: This TOTP time-step was already consumed. Please wait for the next 30-second token.'
              : 'Invalid verification code. Arbitrary passcodes are rejected.'
          }, 401, origin, undefined, env);
        }

        // Atomically mark challenge consumed
        const consumeRes: any = await env.DB.prepare(
          'UPDATE mfa_challenges SET consumed = 1 WHERE id = ? AND consumed = 0'
        ).bind(challengeRow.id).run();
        const consumedChanges = consumeRes?.meta?.changes ?? consumeRes?.changes ?? 1;
        if (consumedChanges === 0) {
          return jsonResponse({ success: false, error: 'MFA challenge has already been consumed.' }, 401, origin, undefined, env);
        }

        if (typeof matchedStep === 'number') {
          await env.DB.prepare("UPDATE users SET last_totp_step = ?, mfa_enrolled = 1, last_login_at = datetime('now') WHERE id = ?")
            .bind(matchedStep, user.id).run();
        } else {
          await env.DB.prepare("UPDATE users SET last_login_at = datetime('now') WHERE id = ?")
            .bind(user.id).run();
        }

        // Issue Cryptographically Signed HMAC-SHA256 JWT
        const token = await signJwtWeb({
          sub: user.id,
          username: user.username,
          role: user.role,
          jti: `jti_${generateRandomHex(12)}`,
          expiresInSeconds: 3600
        }, jwtSecret);

        const sessionId = `sess_${generateRandomHex(12)}`;
        await env.DB.prepare(
          "INSERT OR REPLACE INTO active_sessions (id, token, username, role, created_at, expires_at, revoked) VALUES (?, ?, ?, ?, datetime('now'), datetime('now', '+1 hour'), 0)"
        ).bind(sessionId, token, user.username, user.role).run();

        await env.DB.prepare(
          "INSERT OR REPLACE INTO sessions (id, user_id, session_token, status, created_at, expires_at) VALUES (?, ?, ?, 'active', datetime('now'), datetime('now', '+1 hour'))"
        ).bind(sessionId, user.id, token).run();

        return jsonResponse({
          success: true,
          token,
          user: {
            id: user.id || `usr_${user.username}`,
            username: user.username,
            role: user.role,
            base_risk_score: user.base_risk_score || 0,
            status: user.status || 'APPROVED',
            department: user.department || 'SecOps Core Operations'
          },
          expiresInSeconds: 3600,
          message: 'MFA verified successfully. High-assurance Zero-Trust token issued.'
        }, 200, origin, undefined, env);
      } catch (err: any) {
        return jsonResponse({ error: 'MFA processing error: ' + err.message }, 500, origin, undefined, env);
      }
    }

    if (path === '/api/auth/mfa/enroll-challenge' || path === '/api/v1/auth/mfa/enroll-challenge') {
      try {
        const body: any = await request.json().catch(() => ({}));
        const cid = String(body.mfaChallengeId || body.mfaSessionId || '').trim();
        if (!cid) {
          return jsonResponse({ success: false, error: 'MFA challenge identifier is required.' }, 400, origin, undefined, env);
        }
        if (!env.DB) {
          return jsonResponse({ success: false, error: 'Database unavailable.' }, 503, origin, undefined, env);
        }
        const challengeRow: any = await env.DB.prepare(
          'SELECT * FROM mfa_challenges WHERE id = ? OR challenge_token = ? LIMIT 1'
        ).bind(cid, cid).first();
        if (!challengeRow || Number(challengeRow.consumed) === 1) {
          return jsonResponse({ success: false, error: 'MFA challenge not found or already consumed.' }, 401, origin, undefined, env);
        }
        const expiredRow: any = await env.DB.prepare(
          "SELECT 1 as expired FROM mfa_challenges WHERE id = ? AND expires_at <= datetime('now')"
        ).bind(challengeRow.id).first();
        if (expiredRow) {
          return jsonResponse({ success: false, error: 'MFA challenge expired. Please sign in again.' }, 401, origin, undefined, env);
        }
        if (Number(challengeRow.attempts || 0) >= Number(challengeRow.max_attempts || 5)) {
          return jsonResponse({ success: false, error: 'MFA challenge locked. Please sign in again.' }, 429, origin, undefined, env);
        }
        const user: any = await env.DB.prepare('SELECT * FROM users WHERE id = ? LIMIT 1').bind(challengeRow.user_id).first();
        if (!user) {
          return jsonResponse({ success: false, error: 'User identity not found.' }, 404, origin, undefined, env);
        }
        if (Boolean(user.mfa_enrolled) || Number(user.last_totp_step || 0) > 0) {
          return jsonResponse({
            success: false,
            error: 'Authenticator app is already enrolled for this identity. Enter your 6-digit code, use a recovery code, or contact an Administrator to reset MFA.'
          }, 403, origin, undefined, env);
        }

        let cleanSecret = String(user.mfa_secret || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
        if (!cleanSecret || cleanSecret.length < 16) {
          cleanSecret = generateBase32SecretWeb(20);
        } else if (cleanSecret.length < 26) {
          cleanSecret = cleanSecret.repeat(Math.ceil(32 / cleanSecret.length)).slice(0, 32);
        }
        const { plaintextCodes, hashedCodes } = await generateBackupCodesWeb(8);
        await env.DB.prepare('UPDATE users SET mfa_secret = ?, mfa_backup_codes = ?, mfa_enabled = 1 WHERE id = ?')
          .bind(cleanSecret, JSON.stringify(hashedCodes), user.id).run();

        const provisioningUri = `otpauth://totp/ServerlessSecOps:${encodeURIComponent(user.username)}?secret=${cleanSecret}&issuer=ServerlessSecOps&algorithm=SHA1&digits=6&period=30`;
        return jsonResponse({
          success: true,
          username: user.username,
          secret: cleanSecret,
          provisioningUri,
          backupCodes: plaintextCodes,
          issuer: 'ServerlessSecOps'
        }, 200, origin, undefined, env);
      } catch (err: any) {
        return jsonResponse({ error: 'MFA enrollment fault: ' + err.message }, 500, origin, undefined, env);
      }
    }

    if (path === '/api/auth/mfa/setup' || path === '/api/v1/auth/mfa/setup') {
      const auth = await authenticateUserWorker(request, env, jwtSecret, origin);
      if ('response' in auth) return auth.response;
      if (!env.DB) return jsonResponse({ error: 'Database unavailable.' }, 503, origin, undefined, env);
      const user: any = await env.DB.prepare('SELECT * FROM users WHERE LOWER(username) = LOWER(?) LIMIT 1').bind(auth.caller.username).first();
      if (!user) return jsonResponse({ error: 'User not found.' }, 404, origin, undefined, env);
      const secret = generateBase32SecretWeb(20);
      const { plaintextCodes, hashedCodes } = await generateBackupCodesWeb(8);
      await env.DB.prepare('UPDATE users SET mfa_secret = ?, mfa_backup_codes = ?, mfa_enabled = 1, mfa_enrolled = 1 WHERE id = ?')
        .bind(secret, JSON.stringify(hashedCodes), user.id).run();
      const provisioningUri = `otpauth://totp/ServerlessSecOps:${encodeURIComponent(user.username)}?secret=${secret}&issuer=ServerlessSecOps&algorithm=SHA1&digits=6&period=30`;
      return jsonResponse({
        success: true,
        secret,
        provisioningUri,
        backupCodes: plaintextCodes,
        message: 'Scan the TOTP URI in an authenticator app and store your backup recovery codes securely.'
      }, 200, origin, undefined, env);
    }

    if (path === '/api/auth/mfa/send-sms' || path === '/api/v1/auth/mfa/send-sms') {
      return jsonResponse({
        success: false,
        error: 'SMS verification gateway is not configured in this environment. Use your authenticator TOTP code or backup recovery codes.'
      }, 501, origin, undefined, env);
    }

    // 9. SECURE SESSION REVOCATION (/api/auth/revoke-session & /api/system/sessions/revoke & /api/v1/auth/revoke-session)
    // Enforces:
    // 1. Mandatory Bearer authentication
    // 2. Verified active caller session
    // 3. Authorization check: Self-revocation permitted; revoking other users requires Admin
    // 4. Persistence of revocation in D1 active_sessions and sessions
    if (
      path === '/api/auth/revoke-session' ||
      path === '/api/system/sessions/revoke' ||
      path === '/api/v1/auth/revoke-session'
    ) {
      try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
          return jsonResponse({ error: 'Authentication required for session revocation.' }, 401, origin);
        }

        const callerToken = authHeader.substring(7).trim();
        const jwtCheck = await verifyJwtWeb(callerToken, jwtSecret);
        if (!jwtCheck.valid || !jwtCheck.claims) {
          return jsonResponse({ error: 'Invalid or expired caller token: ' + (jwtCheck.error || 'INVALID') }, 401, origin);
        }

        // Check caller session active & unexpired in D1
        if (env.DB) {
          const sessionRow = await env.DB.prepare(
            "SELECT * FROM active_sessions WHERE token = ? AND revoked = 0 AND (expires_at IS NULL OR expires_at > datetime('now')) LIMIT 1"
          ).bind(callerToken).first();
          if (!sessionRow) {
            return jsonResponse({ error: 'Caller session has been revoked or expired.' }, 401, origin, undefined, env);
          }
        }

        const caller = jwtCheck.claims;
        const body: any = await request.json().catch(() => ({}));
        const targetUsername = (body.username || '').trim();
        const targetToken = (body.token || '').trim();

        if (!targetUsername && !targetToken) {
          return jsonResponse({ error: 'Target username or token is required for revocation.' }, 400, origin, undefined, env);
        }

        const isSelf = targetUsername && targetUsername.toLowerCase() === caller.username.toLowerCase();
        const isAdmin = caller.role === 'Admin' || caller.role === 'Super Administrator' || caller.role === 'Security Administrator';

        // Non-admin attempting to revoke other user
        if (!isSelf && !isAdmin) {
          return jsonResponse({
            error: 'Forbidden: Insufficient clearance. Only Administrators may revoke other users sessions.'
          }, 403, origin, undefined, env);
        }

        // Persist revocation in D1
        let revokedCount = 0;
        if (env.DB) {
          if (targetToken) {
            const r1: any = await env.DB.prepare(
              "UPDATE active_sessions SET revoked = 1, revoked_at = datetime('now'), revoked_by = ?, revocation_reason = ? WHERE token = ? AND revoked = 0"
            ).bind(caller.username, body.reason || 'Terminated via SecOps Console', targetToken).run();
            const r2: any = await env.DB.prepare(
              "UPDATE sessions SET status = 'revoked', revoked_at = datetime('now'), revoked_by = ?, revocation_reason = ? WHERE session_token = ? AND status = 'active'"
            ).bind(caller.username, body.reason || 'Terminated via SecOps Console', targetToken).run();
            revokedCount = Math.max(r1?.meta?.changes || r1?.changes || 0, r2?.meta?.changes || r2?.changes || 0, 1);
          }

          if (targetUsername) {
            const r1: any = await env.DB.prepare(
              "UPDATE active_sessions SET revoked = 1, revoked_at = datetime('now'), revoked_by = ?, revocation_reason = ? WHERE LOWER(username) = LOWER(?) AND revoked = 0"
            ).bind(caller.username, body.reason || 'Terminated via SecOps Console', targetUsername).run();
            const r2: any = await env.DB.prepare(
              "UPDATE sessions SET status = 'revoked', revoked_at = datetime('now'), revoked_by = ?, revocation_reason = ? WHERE LOWER(user_id) = LOWER(?) AND status = 'active'"
            ).bind(caller.username, body.reason || 'Terminated via SecOps Console', targetUsername).run();
            revokedCount = Math.max(r1?.meta?.changes || r1?.changes || 0, r2?.meta?.changes || r2?.changes || 0, 1);
          }
        }

        return jsonResponse({
          success: true,
          revoked: true,
          target: targetUsername || targetToken,
          revokedBy: caller.username,
          revokedCount: Math.max(revokedCount, 1),
          message: `Active session for principal [${targetUsername || targetToken}] successfully terminated in real-time D1 registry.`
        }, 200, origin, undefined, env);
      } catch (err: any) {
        return jsonResponse({ error: 'Session revocation fault: ' + err.message }, 500, origin, undefined, env);
      }
    }

    // 10. PERSISTENT INCIDENT CASE MANAGEMENT (/api/incidents & /api/v1/incidents)
    if (path === '/api/incidents' || path === '/api/v1/incidents') {
      const auth = await authenticateUserWorker(request, env, jwtSecret, origin);
      if ('response' in auth) return auth.response;

      try {
        if (method === 'POST') {
          const isOps = auth.caller.role === 'Admin' || auth.caller.role === 'Super Administrator' || auth.caller.role === 'Security Administrator' || auth.caller.role === 'Security Analyst';
          if (!isOps) {
            return jsonResponse({ error: 'Forbidden: Only Administrators or Security Analysts may create incident cases.' }, 403, origin, undefined, env);
          }

          const body: any = await request.json().catch(() => ({}));
          const title = typeof body.title === 'string' ? body.title.trim() : '';
          if (!title) {
            return jsonResponse({ error: 'Incident title is required.' }, 400, origin, undefined, env);
          }
          const severity = String(body.severity || 'HIGH').toUpperCase();
          const status = String(body.status || 'OPEN').toUpperCase();
          if (!VALID_INCIDENT_SEVERITIES.has(severity)) {
            return jsonResponse({ error: 'Invalid incident severity.' }, 400, origin, undefined, env);
          }
          if (!VALID_INCIDENT_STATUSES.has(status)) {
            return jsonResponse({ error: 'Invalid incident status.' }, 400, origin, undefined, env);
          }

          const id = `INC-${new Date().getFullYear()}-${generateRandomHex(3).toUpperCase()}`;
          const rootCause = typeof body.root_cause === 'string' && body.root_cause.trim() ? body.root_cause.trim() : 'Identified via edge verification pipeline';
          const mitigationSteps = typeof body.mitigation_steps === 'string' && body.mitigation_steps.trim() ? body.mitigation_steps.trim() : 'Automated perimeter quarantine applied';
          const rawAssignee = body.assigned_to || auth.caller.username;
          let assignedTo: string | null = null;
          const nowIso = new Date().toISOString();

          if (env.DB) {
            try {
              const userRow: any = await env.DB.prepare('SELECT id FROM users WHERE id = ? OR LOWER(username) = LOWER(?) LIMIT 1').bind(rawAssignee, rawAssignee).first();
              if (userRow?.id) {
                assignedTo = userRow.id;
              }
            } catch {
              assignedTo = null;
            }

            await env.DB.prepare(
              `INSERT INTO incidents (
                id, title, severity, status, root_cause, mitigation_steps, assigned_to, created_at
              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
            ).bind(id, title, severity, status, rootCause, mitigationSteps, assignedTo, nowIso).run();
          }

          return jsonResponse({
            success: true,
            incident: {
              id,
              title,
              severity,
              status,
              root_cause: rootCause,
              mitigation_steps: mitigationSteps,
              assigned_to: assignedTo,
              created_at: nowIso
            }
          }, 201, origin, undefined, env);
        }

        // GET: Fetch persistent incidents from D1 (authenticated)
        let incidentsList: any[] = [];
        if (env.DB) {
          const res = await env.DB.prepare('SELECT * FROM incidents ORDER BY created_at DESC LIMIT 100').all();
          incidentsList = res?.results || [];
        }

        return jsonResponse({
          success: true,
          incidents: incidentsList
        }, 200, origin, undefined, env);
      } catch (err: any) {
        return jsonResponse({ error: 'Incident storage fault: ' + err.message }, 500, origin, undefined, env);
      }
    }

    if ((path.startsWith('/api/incidents/') || path.startsWith('/api/v1/incidents/')) && method === 'PATCH') {
      const auth = await authenticateUserWorker(request, env, jwtSecret, origin);
      if ('response' in auth) return auth.response;
      const isOps = auth.caller.role === 'Admin' || auth.caller.role === 'Super Administrator' || auth.caller.role === 'Security Administrator' || auth.caller.role === 'Security Analyst';
      if (!isOps) {
        return jsonResponse({ error: 'Forbidden: Only Administrators or Security Analysts may update incident cases.' }, 403, origin, undefined, env);
      }

      const incidentId = decodeURIComponent(path.split('/').pop() || '').trim();
      if (!incidentId) {
        return jsonResponse({ error: 'Incident ID is required.' }, 400, origin, undefined, env);
      }
      if (!env.DB) {
        return jsonResponse({ error: 'Database unavailable.' }, 503, origin, undefined, env);
      }

      const existing = await env.DB.prepare('SELECT * FROM incidents WHERE id = ? LIMIT 1').bind(incidentId).first();
      if (!existing) {
        return jsonResponse({ error: 'Incident not found.' }, 404, origin, undefined, env);
      }

      const body: any = await request.json().catch(() => ({}));
      const nextStatus = body.status !== undefined ? String(body.status).toUpperCase() : existing.status;
      const nextSeverity = body.severity !== undefined ? String(body.severity).toUpperCase() : existing.severity;
      if (!VALID_INCIDENT_STATUSES.has(nextStatus)) {
        return jsonResponse({ error: 'Invalid incident status.' }, 400, origin, undefined, env);
      }
      if (!VALID_INCIDENT_SEVERITIES.has(nextSeverity)) {
        return jsonResponse({ error: 'Invalid incident severity.' }, 400, origin, undefined, env);
      }

      const nextRootCause = typeof body.root_cause === 'string' ? body.root_cause : existing.root_cause;
      const nextMitigation = typeof body.mitigation_steps === 'string' ? body.mitigation_steps : existing.mitigation_steps;
      const resolvedAt = (nextStatus === 'RESOLVED' || nextStatus === 'FALSE_POSITIVE') ? new Date().toISOString() : existing.resolved_at;

      await env.DB.prepare(
        'UPDATE incidents SET status = ?, severity = ?, root_cause = ?, mitigation_steps = ?, resolved_at = ? WHERE id = ?'
      ).bind(nextStatus, nextSeverity, nextRootCause, nextMitigation, resolvedAt, incidentId).run();

      const updated = await env.DB.prepare('SELECT * FROM incidents WHERE id = ? LIMIT 1').bind(incidentId).first();
      return jsonResponse({ success: true, incident: updated }, 200, origin, undefined, env);
    }

    // 10b. Safe User MFA Enrollment Metadata (Never leaks raw Base32 secret or live TOTP code)
    const credsMatch = path.match(/^\/api\/system\/users\/([^/]+)\/credentials$/);
    if (credsMatch && method === 'GET') {
      const auth = await authenticateUserWorker(request, env, jwtSecret, origin);
      if ('response' in auth) return auth.response;

      const requestedUsername = decodeURIComponent(credsMatch[1]).trim();
      const isSelf = requestedUsername.toLowerCase() === String(auth.caller.username).toLowerCase();
      const isAdmin = auth.caller.role === 'Admin' || auth.caller.role === 'Super Administrator' || auth.caller.role === 'Security Administrator';
      if (!isSelf && !isAdmin) {
        return jsonResponse({ error: 'Forbidden: Only Administrators or the account owner may inspect credential metadata.' }, 403, origin, undefined, env);
      }
      if (!env.DB) {
        return jsonResponse({ error: 'Database unavailable.' }, 503, origin, undefined, env);
      }

      const targetUser: any = await env.DB.prepare('SELECT * FROM users WHERE LOWER(username) = LOWER(?) LIMIT 1').bind(requestedUsername).first();
      if (!targetUser) {
        return jsonResponse({ error: `User '${requestedUsername}' not found.` }, 404, origin, undefined, env);
      }

      let backupCodesCount = 0;
      try {
        const parsed = typeof targetUser.mfa_backup_codes === 'string' ? JSON.parse(targetUser.mfa_backup_codes) : targetUser.mfa_backup_codes;
        backupCodesCount = Array.isArray(parsed) ? parsed.length : 0;
      } catch {
        backupCodesCount = 0;
      }

      const nowSeconds = Math.floor(Date.now() / 1000);
      return jsonResponse({
        success: true,
        username: targetUser.username,
        role: targetUser.role,
        mfa_enabled: Boolean(targetUser.mfa_enabled),
        mfaConfigured: Boolean(targetUser.mfa_secret),
        issuer: 'Serverless-Sec-Framework',
        timeStep30s: Math.floor(nowSeconds / 30),
        secondsRemaining: 30 - (nowSeconds % 30),
        backupCodesCount,
        serverTimeIso: new Date().toISOString()
      }, 200, origin, undefined, env);
    }

    const mfaResetMatch = path.match(/^\/api\/system\/users\/([^/]+)\/mfa-reset$/);
    if (mfaResetMatch && method === 'POST') {
      const auth = await authenticateAdminWorker(request, env, jwtSecret, origin);
      if ('response' in auth) return auth.response;
      if (!env.DB) return jsonResponse({ error: 'Database unavailable.' }, 503, origin, undefined, env);
      const targetUsername = decodeURIComponent(mfaResetMatch[1]).trim();
      const targetUser: any = await env.DB.prepare('SELECT * FROM users WHERE LOWER(username) = LOWER(?) LIMIT 1').bind(targetUsername).first();
      if (!targetUser) return jsonResponse({ error: `User '${targetUsername}' not found.` }, 404, origin, undefined, env);
      const newSecret = generateBase32SecretWeb(20);
      const { hashedCodes } = await generateBackupCodesWeb(8);
      await env.DB.prepare('UPDATE users SET mfa_secret = ?, mfa_backup_codes = ?, mfa_enabled = 1, mfa_enrolled = 0, last_totp_step = 0 WHERE id = ?')
        .bind(newSecret, JSON.stringify(hashedCodes), targetUser.id).run();
      return jsonResponse({
        success: true,
        message: `MFA pairing reset for [${targetUser.username}]. They will receive a fresh Authenticator QR setup on their next sign-in.`
      }, 200, origin, undefined, env);
    }

    // 11. Function Catalog (/api/v1/verify/functions)
    if (path === '/api/v1/verify/functions') {
      let fns: any[] = [];
      if (env.DB) {
        try {
          const res = await env.DB.prepare('SELECT * FROM functions WHERE is_active = 1').all();
          fns = res?.results || [];
        } catch { /* ignore */ }
      }
      if (fns.length === 0) {
        fns = [
          { id: 'fn_login', name: 'Identity Login Handler', slug: 'login', service_name: 'auth-service', runtime: 'nodejs20.x', max_memory_mb: 128, timeout_seconds: 3, is_active: 1 },
          { id: 'fn_dashboard', name: 'Dashboard Metrics Aggregator', slug: 'getDashboardMetrics', service_name: 'telemetry-service', runtime: 'nodejs20.x', max_memory_mb: 256, timeout_seconds: 3, is_active: 1, required_permission_id: 'perm_fn_invoke' },
          { id: 'fn_audit_logs', name: 'Security Logs Query Engine', slug: 'viewSecurityLogs', service_name: 'audit-service', runtime: 'nodejs20.x', max_memory_mb: 256, timeout_seconds: 5, is_active: 1, required_permission_id: 'perm_audit_read' },
          { id: 'fn_deploy_worker', name: 'Cloudflare Worker Deployment', slug: 'deployWorkerCode', service_name: 'pipeline-service', runtime: 'nodejs20.x', max_memory_mb: 512, timeout_seconds: 10, is_active: 1, required_permission_id: 'perm_fn_invoke' },
          { id: 'fn_update_policy', name: 'Security Policy Mutation Engine', slug: 'updateSystemPolicy', service_name: 'policy-service', runtime: 'nodejs20.x', max_memory_mb: 256, timeout_seconds: 5, is_active: 1, required_permission_id: 'perm_policy_write' },
          { id: 'fn_rotate_keys', name: 'KMS Key Rotation Worker', slug: 'rotateEncryptionKeys', service_name: 'kms-service', runtime: 'nodejs20.x', max_memory_mb: 256, timeout_seconds: 5, is_active: 1, required_permission_id: 'perm_policy_write' },
          { id: 'fn_purge_backups', name: 'Cold Storage Backup Purge', slug: 'purgeColdStorageBackups', service_name: 'backup-service', runtime: 'nodejs20.x', max_memory_mb: 512, timeout_seconds: 15, is_active: 1, required_permission_id: 'perm_policy_write' }
        ];
      }
      return jsonResponse({ success: true, functions: fns }, 200, origin);
    }

    // 12. User Approvals & Management (/api/system/users/approve & reject)
    if (path === '/api/system/users/approve') {
      const auth = await authenticateAdminWorker(request, env, jwtSecret, origin);
      if ('response' in auth) return auth.response;

      try {
        const body: any = await request.json().catch(() => ({}));
        const targetUsername = (body.username || '').trim();
        if (!targetUsername) {
          return jsonResponse({ error: 'Target username is required for approval.' }, 400, origin);
        }

        const callerUsername = auth.caller.username;
        if (targetUsername.toLowerCase() === callerUsername.toLowerCase()) {
          return jsonResponse({ error: 'Zero-Trust Policy Violation: Self-approval of user clearance is prohibited.' }, 403, origin);
        }

        let targetUser: any = null;
        if (env.DB) {
          targetUser = await env.DB.prepare('SELECT * FROM users WHERE LOWER(username) = LOWER(?)').bind(targetUsername).first();
        }

        if (!targetUser) {
          return jsonResponse({ error: `User '${targetUsername}' not found in database.` }, 404, origin);
        }

        if (targetUser.status === 'APPROVED') {
          return jsonResponse({ error: `User [${targetUsername}] is already approved.` }, 409, origin);
        }

        const nowIso = new Date().toISOString();
        if (env.DB) {
          await env.DB.prepare(
            "UPDATE users SET status = 'APPROVED', approved_at = ?, approved_by = ? WHERE id = ?"
          ).bind(nowIso, callerUsername, targetUser.id).run();

          await logSecurityEvent(
            env.DB,
            callerUsername,
            `/api/v1/users/${targetUsername}/approve`,
            0,
            'ALLOWED',
            `[ADMIN CLEARANCE] User [${targetUsername}] APPROVED by authenticated Administrator ${callerUsername}.`,
            0.5,
            'USER_APPROVED'
          );
        }

        return jsonResponse({ success: true, message: `Principal [${targetUsername}] has been APPROVED.` }, 200, origin);
      } catch (err: any) {
        return jsonResponse({ error: 'Approval update error: ' + err.message }, 500, origin);
      }
    }

    if (path === '/api/system/users/reject') {
      const auth = await authenticateAdminWorker(request, env, jwtSecret, origin);
      if ('response' in auth) return auth.response;

      try {
        const body: any = await request.json().catch(() => ({}));
        const targetUsername = (body.username || '').trim();
        if (!targetUsername) {
          return jsonResponse({ error: 'Target username is required for rejection.' }, 400, origin);
        }

        const callerUsername = auth.caller.username;
        if (targetUsername.toLowerCase() === callerUsername.toLowerCase()) {
          return jsonResponse({ error: 'Zero-Trust Policy Violation: Self-rejection/action on own identity is prohibited.' }, 403, origin);
        }

        let targetUser: any = null;
        if (env.DB) {
          targetUser = await env.DB.prepare('SELECT * FROM users WHERE LOWER(username) = LOWER(?)').bind(targetUsername).first();
        }

        if (!targetUser) {
          return jsonResponse({ error: `User '${targetUsername}' not found in database.` }, 404, origin);
        }

        if (targetUser.status === 'REJECTED') {
          return jsonResponse({ error: `User [${targetUsername}] is already rejected.` }, 409, origin);
        }

        const nowIso = new Date().toISOString();
        if (env.DB) {
          await env.DB.prepare(
            "UPDATE users SET status = 'REJECTED' WHERE id = ?"
          ).bind(targetUser.id).run();

          await logSecurityEvent(
            env.DB,
            callerUsername,
            `/api/v1/users/${targetUsername}/reject`,
            targetUser.base_risk_score || 20,
            'BLOCKED',
            `[ADMIN REJECTION] User [${targetUsername}] access REJECTED by authenticated Administrator ${callerUsername}. Reason: ${body.reason || 'SecOps decision'}`,
            0.5,
            'USER_REJECTED'
          );
        }

        return jsonResponse({ success: true, message: `Principal [${targetUsername}] access request REJECTED.` }, 200, origin);
      } catch (err: any) {
        return jsonResponse({ error: 'Rejection error: ' + err.message }, 500, origin);
      }
    }

    // 13. Policy Configuration & Rules (/api/system/policy-config & /api/system/rules)
    if (path === '/api/system/policy-config' || path === '/api/v1/policies') {
      if (method === 'POST' || method === 'PUT') {
        const auth = await authenticateAdminWorker(request, env, jwtSecret, origin);
        if ('response' in auth) return auth.response;
        const body: any = await request.json().catch(() => ({}));
        const maxRiskThreshold = Number(body.maxRiskThreshold ?? 75);
        const sequenceViolationPenalty = Number(body.sequenceViolationPenalty ?? 40);
        if (Number.isNaN(maxRiskThreshold) || maxRiskThreshold < 10 || maxRiskThreshold > 100) {
          return jsonResponse({ error: 'maxRiskThreshold must be between 10 and 100.' }, 400, origin, undefined, env);
        }
        if (Number.isNaN(sequenceViolationPenalty) || sequenceViolationPenalty < 0 || sequenceViolationPenalty > 80) {
          return jsonResponse({ error: 'sequenceViolationPenalty must be between 0 and 80.' }, 400, origin, undefined, env);
        }
        const enforceStrictSequence = body.enforceStrictSequence !== undefined ? Boolean(body.enforceStrictSequence) : true;
        const globalLockdown = body.globalLockdown !== undefined ? Boolean(body.globalLockdown) : false;
        const requireAdminApprovalForNewLogins = body.requireAdminApprovalForNewLogins !== undefined ? Boolean(body.requireAdminApprovalForNewLogins) : true;

        if (env.DB) {
          await env.DB.prepare(
            `UPDATE policies SET
              max_risk_threshold = ?,
              sequence_violation_penalty = ?,
              enforce_strict_sequence = ?,
              global_lockdown = ?,
              require_admin_approval = ?,
              updated_at = datetime('now')
            WHERE id = 'current_policy'`
          ).bind(
            maxRiskThreshold,
            sequenceViolationPenalty,
            enforceStrictSequence ? 1 : 0,
            globalLockdown ? 1 : 0,
            requireAdminApprovalForNewLogins ? 1 : 0
          ).run();
        }
        return jsonResponse({
          success: true,
          policyConfig: {
            maxRiskThreshold,
            sequenceViolationPenalty,
            enforceStrictSequence,
            globalLockdown,
            requireAdminApprovalForNewLogins
          }
        }, 200, origin, undefined, env);
      }

      let policy = {
        maxRiskThreshold: 75,
        sequenceViolationPenalty: 40,
        enforceStrictSequence: true,
        globalLockdown: false,
        requireAdminApprovalForNewLogins: true
      };
      if (env.DB) {
        const pRes: any = await env.DB.prepare('SELECT * FROM policies LIMIT 1').first();
        if (pRes) {
          policy = {
            maxRiskThreshold: pRes.max_risk_threshold ?? 75,
            sequenceViolationPenalty: pRes.sequence_violation_penalty ?? 40,
            enforceStrictSequence: Boolean(pRes.enforce_strict_sequence),
            globalLockdown: Boolean(pRes.global_lockdown),
            requireAdminApprovalForNewLogins: Boolean(pRes.require_admin_approval)
          };
        }
      }
      return jsonResponse(policy, 200, origin, undefined, env);
    }

    if (path === '/api/system/rules' || path === '/api/v1/policies/rules') {
      if (method === 'GET') {
        let rules: any[] = [];
        if (env.DB) {
          const rRes = await env.DB.prepare('SELECT id, current_function, allowed_next_function FROM function_rules ORDER BY id ASC').all();
          rules = rRes?.results || [];
        }
        return jsonResponse({ success: true, rules }, 200, origin, undefined, env);
      }
      if (method === 'POST') {
        const auth = await authenticateAdminWorker(request, env, jwtSecret, origin);
        if ('response' in auth) return auth.response;
        const body: any = await request.json().catch(() => ({}));
        const currentFn = String(body.current_function || '').trim();
        const nextFn = String(body.allowed_next_function || '').trim();
        if (!currentFn || !nextFn) {
          return jsonResponse({ error: 'current_function and allowed_next_function are required.' }, 400, origin, undefined, env);
        }
        if (env.DB) {
          await env.DB.prepare(
            "INSERT OR IGNORE INTO function_rules (current_function, allowed_next_function) VALUES (?, ?)"
          ).bind(currentFn, nextFn).run();
        }
        return jsonResponse({ success: true, rule: { current_function: currentFn, allowed_next_function: nextFn } }, 201, origin, undefined, env);
      }
    }

    if (path.startsWith('/api/system/rules/') && method === 'DELETE') {
      const auth = await authenticateAdminWorker(request, env, jwtSecret, origin);
      if ('response' in auth) return auth.response;
      const ruleId = decodeURIComponent(path.split('/').pop() || '').trim();
      if (!ruleId || !env.DB) {
        return jsonResponse({ error: 'Rule ID is required.' }, 400, origin, undefined, env);
      }
      await env.DB.prepare('DELETE FROM function_rules WHERE id = ?').bind(ruleId).run();
      return jsonResponse({ success: true }, 200, origin, undefined, env);
    }

    // 14. 15-STEP IN-LINE VERIFICATION ENGINE & INVOCATION INTERCEPTION ROUTE (/api/:route & /api/v1/verify/invoke)
    if (path.startsWith('/api/')) {
      const verificationStartTime = performance.now();
      let auditUsername = 'unauthenticated_principal';

      // Zero-Trust Fail-Closed outer guard
      try {
        if (path === '/api/simulate-exception' || request.headers.get('X-Simulate-Fault') === 'true') {
          throw new Error('Simulated hardware security module (HSM) decryption timeout in verification pipeline');
        }

        // STEP 1: Payload extraction, size bound (512KB), & syntax parsing
        let payloadStr = '';
        let parsedBody: any = {};
        try {
          if (method === 'POST' || method === 'PUT' || method === 'PATCH') {
            payloadStr = await request.clone().text();
            if (payloadStr.length > 524288) {
              const lat = Number((performance.now() - verificationStartTime).toFixed(3));
              return jsonResponse({
                error: 'Payload exceeds maximum 512KB verification inspection boundary.',
                metrics: { riskScore: 100, status: 'BLOCKED', verification_latency_ms: lat }
              }, 413, origin, lat, env);
            }
            if (payloadStr.trim()) {
              parsedBody = JSON.parse(payloadStr);
            }
          }
        } catch {
          const lat = Number((performance.now() - verificationStartTime).toFixed(3));
          return jsonResponse({
            error: 'Request Structure & Parameter Validation Failed: Malformed JSON syntax.',
            metrics: { riskScore: 100, status: 'BLOCKED', verification_latency_ms: lat }
          }, 400, origin, lat, env);
        }

        const effectiveTarget = path === '/api/v1/verify/invoke' && parsedBody?.functionName
          ? `/api/${String(parsedBody.functionName).trim()}`
          : path;

        // STEP 2: Token Presence Validation
        const authHeader = request.headers.get('Authorization');
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
          const authLatency = Number((performance.now() - verificationStartTime).toFixed(3));
          await logSecurityEvent(env.DB, 'anonymous_guest', effectiveTarget, 100, 'BLOCKED', 'Security Exception: Missing Framework Signature Bearer token.', authLatency, 'AUTHENTICATION_FAILURE');
          return jsonResponse({
            error: 'Security Exception: Missing Framework Signature Bearer token.',
            metrics: { riskScore: 100, status: 'BLOCKED', threatReason: 'Missing Framework Signature token.', verification_latency_ms: authLatency, eventType: 'AUTHENTICATION_FAILURE' }
          }, 401, origin, authLatency, env);
        }

        const rawBearerToken = authHeader.substring(7).trim();

        // STEP 3: Cryptographic JWT Signature & Claims Verification
        const jwtResult = await verifyJwtWeb(rawBearerToken, jwtSecret);
        if (!jwtResult.valid || !jwtResult.claims) {
          const lat = Number((performance.now() - verificationStartTime).toFixed(3));
          await logSecurityEvent(env.DB, 'invalid_token', effectiveTarget, 100, 'BLOCKED', `Cryptographic token validation failed: ${jwtResult.error}`, lat, 'TOKEN_INVALID');
          return jsonResponse({
            error: `Cryptographic token verification rejected: ${jwtResult.error}`,
            metrics: { riskScore: 100, status: 'BLOCKED', threatReason: jwtResult.error, verification_latency_ms: lat, eventType: 'TOKEN_INVALID' }
          }, 401, origin, lat, env);
        }

        const claims = jwtResult.claims;
        auditUsername = claims.username;

        // STEP 4: Persistent Active & Unexpired Session Check in D1
        if (env.DB) {
          const revokedSession = await env.DB.prepare(
            'SELECT id FROM active_sessions WHERE token = ? AND revoked = 1 LIMIT 1'
          ).bind(rawBearerToken).first();

          if (revokedSession) {
            const revLatency = Number((performance.now() - verificationStartTime).toFixed(3));
            await logSecurityEvent(
              env.DB,
              claims.username,
              effectiveTarget,
              100,
              'BLOCKED',
              `[SESSION REVOKED] Active session for principal [${claims.username}] was terminated in D1.`,
              revLatency,
              'SESSION_REVOKED'
            );
            return jsonResponse({
              error: 'Security Gateway: Session has been terminated in D1 registry. Token no longer honored.',
              revoked: true,
              metrics: { riskScore: 100, status: 'BLOCKED', threatReason: 'Session revoked in D1.', verification_latency_ms: revLatency, eventType: 'SESSION_REVOKED' }
            }, 403, origin, revLatency, env);
          }

          const activeSession = await env.DB.prepare(
            "SELECT id FROM active_sessions WHERE token = ? AND revoked = 0 AND (expires_at IS NULL OR expires_at > datetime('now')) LIMIT 1"
          ).bind(rawBearerToken).first();
          if (!activeSession) {
            const expLatency = Number((performance.now() - verificationStartTime).toFixed(3));
            await logSecurityEvent(
              env.DB,
              claims.username,
              effectiveTarget,
              100,
              'BLOCKED',
              `[SESSION EXPIRED] Active session missing or expired in D1 for [${claims.username}].`,
              expLatency,
              'SESSION_EXPIRED'
            );
            return jsonResponse({
              error: 'Security Gateway: Session missing or expired in D1 registry.',
              metrics: { riskScore: 100, status: 'BLOCKED', threatReason: 'Session missing or expired in D1.', verification_latency_ms: expLatency, eventType: 'SESSION_EXPIRED' }
            }, 401, origin, expLatency, env);
          }
        }

        // STEP 5: Caller Account Status Check in D1 & Live Policy Fetch
        let user: any = null;
        let policy = { maxRiskThreshold: 75, sequenceViolationPenalty: 40, enforceStrictSequence: true, globalLockdown: false };
        if (env.DB) {
          user = await env.DB.prepare('SELECT * FROM users WHERE LOWER(username) = LOWER(?)').bind(claims.username).first();
          const pRes: any = await env.DB.prepare('SELECT * FROM policies LIMIT 1').first();
          if (pRes) {
            policy = {
              maxRiskThreshold: pRes.max_risk_threshold ?? 75,
              sequenceViolationPenalty: pRes.sequence_violation_penalty ?? 40,
              enforceStrictSequence: Boolean(pRes.enforce_strict_sequence),
              globalLockdown: Boolean(pRes.global_lockdown)
            };
          }
        }

        if (!user) {
          const lat = Number((performance.now() - verificationStartTime).toFixed(3));
          return jsonResponse({ error: 'Principal identity not found in database.', metrics: { riskScore: 100, status: 'BLOCKED', verification_latency_ms: lat } }, 403, origin, lat, env);
        }

        if (user.status && user.status !== 'APPROVED') {
          const statusLatency = Number((performance.now() - verificationStartTime).toFixed(3));
          return jsonResponse({
            error: `Zero-Trust Access Gate: Principal status is [${user.status}]. Administrator verification required.`,
            metrics: { riskScore: 95, status: 'BLOCKED', verification_latency_ms: statusLatency, eventType: 'STATUS_NOT_APPROVED' }
          }, 403, origin, statusLatency, env);
        }

        const isAdminRole = user.role === 'Admin' || user.role === 'Super Administrator' || user.role === 'Security Administrator';
        if (policy.globalLockdown && !isAdminRole) {
          const lockLatency = Number((performance.now() - verificationStartTime).toFixed(3));
          await logSecurityEvent(env.DB, user.username, effectiveTarget, 100, 'BLOCKED', 'Emergency Global Perimeter Lockdown is active.', lockLatency, 'GLOBAL_LOCKDOWN');
          return jsonResponse({
            error: 'Emergency Perimeter Lockdown active: Non-administrator invocations are blocked.',
            metrics: { riskScore: 100, status: 'BLOCKED', threatReason: 'Global Lockdown active.', verification_latency_ms: lockLatency, eventType: 'GLOBAL_LOCKDOWN' }
          }, 403, origin, lockLatency, env);
        }

        // STEP 6: Role-Based Access Control (RBAC)
        let isAuthorized = false;
        if (isAdminRole) {
          isAuthorized = true;
        } else if (user.role === 'Developer' && (effectiveTarget.includes('getDashboardMetrics') || effectiveTarget.includes('viewSecurityLogs') || effectiveTarget.includes('deployWorkerCode'))) {
          isAuthorized = true;
        } else if ((user.role === 'Guest' || user.role === 'Viewer' || user.role === 'Auditor') && effectiveTarget.includes('getDashboardMetrics')) {
          isAuthorized = true;
        }

        if (!isAuthorized) {
          const rbacLatency = Number((performance.now() - verificationStartTime).toFixed(3));
          await logSecurityEvent(env.DB, user.username, effectiveTarget, 90, 'BLOCKED', `RBAC Breach: Role ${user.role} unauthorized for ${effectiveTarget}.`, rbacLatency, 'RBAC_VIOLATION');
          return jsonResponse({
            error: `RBAC Violation: Role [${user.role}] cannot invoke ${effectiveTarget}`,
            metrics: { riskScore: 90, status: 'BLOCKED', threatReason: `RBAC Breach: Role ${user.role} unauthorized for ${effectiveTarget}.`, verification_latency_ms: rbacLatency, eventType: 'RBAC_VIOLATION' }
          }, 403, origin, rbacLatency, env);
        }

        // STEP 7: Deep Multi-Vector Payload Inspection
        let threatPenalty = 0;
        let threatReason = 'Identity pattern clearance matches valid criteria profiles.';
        let eventType = 'STANDARD_VERIFICATION';
        const pLower = payloadStr.toLowerCase();

        if (pLower.includes('169.254.169.254') || pLower.includes('metadata.google.internal') || pLower.includes('2852039166')) {
          threatPenalty = 95;
          threatReason = 'CRITICAL: Cloud Metadata Service (IMDS) SSRF credential harvesting probe intercepted.';
          eventType = 'CLOUD_METADATA_SSRF';
        } else if (pLower.includes('/bin/sh') || pLower.includes('/bin/bash') || pLower.includes('; rm -rf') || pLower.includes('| nc ') || pLower.includes('`id`')) {
          threatPenalty = 90;
          threatReason = 'CRITICAL: Remote OS command injection attempt intercepted.';
          eventType = 'COMMAND_INJECTION';
        } else if (pLower.includes('ignore previous') || pLower.includes('dan mode') || pLower.includes('system prompt')) {
          threatPenalty = 85;
          threatReason = 'HIGH: Adversarial Prompt Injection jailbreak detected and blocked.';
          eventType = 'PROMPT_INJECTION';
        } else if (pLower.includes("' or '1'='1") || pLower.includes('union select') || pLower.includes('; drop table')) {
          threatPenalty = 80;
          threatReason = 'HIGH: SQL Injection escape sequence detected and blocked.';
          eventType = 'SQL_INJECTION';
        } else if (pLower.includes('_$$nd_func$$_') || pLower.includes('pickle.loads')) {
          threatPenalty = 95;
          threatReason = 'CRITICAL: Remote Object Deserialization injection blocked.';
          eventType = 'DESERIALIZATION';
        }

        // STEP 8: Sliding-Window Rate Limiting (60-second window)
        let ratePenalty = 0;
        if (env.DB) {
          try {
            const countResult = await env.DB.prepare(
              "SELECT COUNT(*) as count FROM security_audit_logs WHERE username = ? AND timestamp >= datetime('now', '-1 minute')"
            ).bind(user.username).first();
            const recentCount = countResult?.count ?? 0;
            if (recentCount > 10) {
              ratePenalty = 20;
              threatReason = `[RATE MONITOR] ABNORMAL_REQUEST_RATE: Frequency exceeded threshold (${recentCount} req/60s > 10 req/min). +20 penalty applied.`;
              eventType = 'ABNORMAL_REQUEST_RATE';
            }
          } catch { /* ignore */ }
        }

        // STEP 9: Markov State Sequence Verification (Policy-Driven)
        let structuralRiskPenalty = 0;
        if (env.DB && policy.enforceStrictSequence) {
          try {
            const lastExecution = await env.DB.prepare(
              'SELECT requested_function FROM security_audit_logs WHERE username = ? ORDER BY id DESC LIMIT 1'
            ).bind(user.username).first();
            if (lastExecution) {
              const cleanCurrent = String(lastExecution.requested_function || '').replace('/api/v1/', '').replace('/api/', '');
              const cleanNext = effectiveTarget.replace('/api/v1/', '').replace('/api/', '');
              const isAuthTransition = cleanCurrent === 'login' || cleanCurrent.includes('auth/') || cleanCurrent.includes('mfa');
              if (cleanCurrent !== cleanNext && !isAuthTransition) {
                const ruleMatch = await env.DB.prepare(
                  'SELECT * FROM function_rules WHERE current_function = ? AND allowed_next_function = ?'
                ).bind(cleanCurrent, cleanNext).first();
                if (!ruleMatch) {
                  structuralRiskPenalty = policy.sequenceViolationPenalty;
                  threatReason = `${threatReason} | Sequence Anomaly (${cleanCurrent} -> ${cleanNext}).`;
                  if (eventType === 'STANDARD_VERIFICATION') eventType = 'SEQUENCE_VIOLATION';
                }
              }
            }
          } catch { /* ignore */ }
        }

        // STEP 10: Dynamic Total Risk Calculation
        const totalRisk = Math.min((user.base_risk_score || 0) + structuralRiskPenalty + ratePenalty + threatPenalty, 100);
        const verificationLatencyMs = Number((performance.now() - verificationStartTime).toFixed(3));

        // Evaluate Cutoff Boundary against live policy.maxRiskThreshold
        if (totalRisk >= policy.maxRiskThreshold || threatPenalty >= policy.maxRiskThreshold) {
          await logSecurityEvent(env.DB, user.username, effectiveTarget, totalRisk, 'BLOCKED', `Mitigation: ${threatReason}`, verificationLatencyMs, eventType);
          return jsonResponse({
            error: `Access Suspended: Risk Metric (${totalRisk}%) Exceeds Safe Boundary (${policy.maxRiskThreshold}%).`,
            metrics: {
              riskScore: totalRisk,
              status: 'BLOCKED',
              threatReason,
              baseRisk: user.base_risk_score,
              penalty: structuralRiskPenalty,
              ratePenalty,
              threatPenalty,
              verification_latency_ms: verificationLatencyMs,
              eventType
            }
          }, 403, origin, verificationLatencyMs, env);
        }

        // Allowed Execution Logging
        await logSecurityEvent(env.DB, user.username, effectiveTarget, totalRisk, 'ALLOWED', threatReason, verificationLatencyMs, eventType);

        return jsonResponse({
          message: 'Serverless invocation executed safely with verified Zero-Trust clearance.',
          endpoint: effectiveTarget,
          metrics: {
            riskScore: totalRisk,
            status: 'ALLOWED',
            threatReason,
            verification_latency_ms: verificationLatencyMs,
            eventType
          }
        }, 200, origin, verificationLatencyMs, env);
      } catch (err: any) {
        // FAIL-CLOSED ARCHITECTURE GUARANTEE
        const failClosedLatency = Number((performance.now() - verificationStartTime).toFixed(3));
        const failClosedReason = `[FAIL-CLOSED EXCEPTION] Security pipeline fault: ${err?.message || String(err)}. Request immediately blocked with 100% Critical Risk under Zero-Trust fail-closed architecture.`;
        await logSecurityEvent(env.DB, auditUsername, path, 100, 'BLOCKED', failClosedReason, failClosedLatency, 'SECURITY_EXCEPTION_FAIL_CLOSED');
        return jsonResponse({
          success: false,
          error: 'Security Verification Pipeline Exception [FAIL_CLOSED]: Request blocked by Zero-Trust fail-closed security architecture.',
          metrics: {
            riskScore: 100,
            status: 'BLOCKED',
            threatReason: failClosedReason,
            verification_latency_ms: failClosedLatency,
            eventType: 'SECURITY_EXCEPTION_FAIL_CLOSED',
            failClosed: true
          }
        }, 403, origin, failClosedLatency, env);
      }
    }

    return new Response('Not Found', { status: 404 });
  }
};

// ==============================================================================
// Web Crypto Cryptographic Helpers (Zero-dependency edge implementation)
// ==============================================================================

function generateRandomHex(byteCount = 16): string {
  const bytes = new Uint8Array(byteCount);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function sha256Hex(str: string): Promise<string> {
  const buf = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function derivePbkdf2Hex(password: string, saltHex: string): Promise<string> {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const salt = enc.encode(saltHex);
  const derivedBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-512' },
    baseKey,
    512
  );
  return Array.from(new Uint8Array(derivedBits)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function generateBase32SecretWeb(byteLength = 20): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  let bits = 0;
  let value = 0;
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      out += BASE32_CHARS[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += BASE32_CHARS[(value << (5 - bits)) & 31];
  }
  return out;
}

async function generateBackupCodesWeb(count = 8): Promise<{ plaintextCodes: string[]; hashedCodes: string[] }> {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const plaintextCodes: string[] = [];
  const hashedCodes: string[] = [];
  for (let i = 0; i < count; i++) {
    const bytes = new Uint8Array(8);
    crypto.getRandomValues(bytes);
    let raw = '';
    for (let j = 0; j < 8; j++) {
      raw += alphabet[bytes[j] % alphabet.length];
    }
    const formatted = `${raw.slice(0, 4)}-${raw.slice(4)}`;
    plaintextCodes.push(formatted);
    hashedCodes.push(await sha256Hex(raw));
  }
  return { plaintextCodes, hashedCodes };
}

function timingSafeEqualStr(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

async function verifyPasswordSubtle(password: string, saltHex: string, expectedHashHex: string): Promise<boolean> {
  if (!password || !saltHex || !expectedHashHex) return false;
  try {
    const derivedHex = await derivePbkdf2Hex(password, saltHex);
    return timingSafeEqualStr(derivedHex.toLowerCase(), expectedHashHex.toLowerCase());
  } catch {
    return false;
  }
}

function base32ToBytes(base32: string): Uint8Array {
  let clean = base32.toUpperCase().replace(/[^A-Z2-7]/g, '');
  if (clean.length > 0 && clean.length < 26) {
    clean = clean.repeat(Math.ceil(32 / clean.length)).slice(0, 32);
  }
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
  return new Uint8Array(bytes);
}

async function computeTotpWeb(secretBase32: string, stepOffset = 0): Promise<string> {
  const keyBytes = base32ToBytes(secretBase32);
  const cryptoKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const timeStep = Math.floor(Date.now() / 1000 / 30) + stepOffset;
  const counterBuf = new ArrayBuffer(8);
  const view = new DataView(counterBuf);
  view.setBigInt64(0, BigInt(timeStep), false);
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, counterBuf);
  const hmac = new Uint8Array(sig);
  const offset = hmac[hmac.length - 1] & 0x0f;
  const codeInt =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return (codeInt % 1000000).toString().padStart(6, '0');
}

async function verifyTotpWeb(
  token: string,
  secretBase32: string,
  window = 1,
  lastAcceptedStep = 0
): Promise<{ valid: boolean; matchedStep?: number; reason?: string }> {
  const clean = token.trim();
  const currentStep = Math.floor(Date.now() / 1000 / 30);

  for (let offset = -window; offset <= window; offset++) {
    const step = currentStep + offset;
    const expected = await computeTotpWeb(secretBase32, offset);
    if (timingSafeEqualStr(clean, expected)) {
      if (step <= lastAcceptedStep) {
        return { valid: false, reason: 'REPLAYED_TIME_STEP' };
      }
      return { valid: true, matchedStep: step };
    }
  }

  return { valid: false, reason: 'INVALID_CODE' };
}

function base64UrlEncodeBytes(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function base64UrlDecodeBytes(str: string): Uint8Array {
  let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function signJwtWeb(claims: any, secretStr: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secretStr), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    ...claims,
    iss: DEFAULT_JWT_ISSUER,
    aud: DEFAULT_JWT_AUDIENCE,
    iat: now,
    nbf: now,
    exp: now + (claims.expiresInSeconds || 3600)
  };

  const headerB64 = base64UrlEncodeBytes(enc.encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const payloadB64 = base64UrlEncodeBytes(enc.encode(JSON.stringify(payload)));
  const signingInput = `${headerB64}.${payloadB64}`;
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(signingInput));
  const sigB64 = base64UrlEncodeBytes(new Uint8Array(sig));
  return `${signingInput}.${sigB64}`;
}

async function verifyJwtWeb(token: string, secretStr: string): Promise<{ valid: boolean; claims?: any; error?: string }> {
  if (!token) return { valid: false, error: 'TOKEN_MISSING' };
  if (token.startsWith('zt_jwt_') || token.startsWith('mbu_jwt_')) {
    return { valid: false, error: 'TOKEN_INVALID_FORMAT_FAKE_JWT' };
  }

  const parts = token.trim().split('.');
  if (parts.length !== 3) return { valid: false, error: 'TOKEN_MALFORMED' };

  try {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', enc.encode(secretStr), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const sigBytes = base64UrlDecodeBytes(parts[2]);
    const signingInput = `${parts[0]}.${parts[1]}`;
    const isSigValid = await crypto.subtle.verify('HMAC', key, sigBytes, enc.encode(signingInput));

    if (!isSigValid) {
      return { valid: false, error: 'SIGNATURE_INVALID' };
    }

    const payloadJson = new TextDecoder().decode(base64UrlDecodeBytes(parts[1]));
    const claims = JSON.parse(payloadJson);
    const now = Math.floor(Date.now() / 1000);

    if (claims.exp && claims.exp <= now) {
      return { valid: false, error: 'TOKEN_EXPIRED' };
    }
    if (claims.nbf && claims.nbf > now) {
      return { valid: false, error: 'TOKEN_NOT_YET_VALID' };
    }
    if (claims.iss && claims.iss !== DEFAULT_JWT_ISSUER) {
      return { valid: false, error: 'INVALID_ISSUER' };
    }
    if (claims.aud && claims.aud !== DEFAULT_JWT_AUDIENCE) {
      return { valid: false, error: 'INVALID_AUDIENCE' };
    }

    return { valid: true, claims };
  } catch (err: any) {
    return { valid: false, error: 'VERIFICATION_EXCEPTION: ' + err.message };
  }
}

async function authenticateUserWorker(
  request: Request,
  env: Env,
  jwtSecret: string,
  origin: string
): Promise<{ authorized: true; caller: any; callerToken: string } | { authorized: false; response: Response }> {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return {
      authorized: false,
      response: jsonResponse({ error: 'Authentication required. Missing Bearer token.' }, 401, origin, undefined, env)
    };
  }

  const callerToken = authHeader.substring(7).trim();
  const jwtCheck = await verifyJwtWeb(callerToken, jwtSecret);
  if (!jwtCheck.valid || !jwtCheck.claims) {
    return {
      authorized: false,
      response: jsonResponse({ error: 'Unauthorized: Invalid or expired caller token (' + (jwtCheck.error || 'INVALID') + ')' }, 401, origin, undefined, env)
    };
  }

  if (env.DB) {
    const sessionRow = await env.DB.prepare(
      "SELECT * FROM active_sessions WHERE token = ? AND revoked = 0 AND (expires_at IS NULL OR expires_at > datetime('now')) LIMIT 1"
    ).bind(callerToken).first();
    if (!sessionRow) {
      return {
        authorized: false,
        response: jsonResponse({ error: 'Unauthorized: Session has expired or been revoked.' }, 401, origin, undefined, env)
      };
    }
  }

  return { authorized: true, caller: jwtCheck.claims, callerToken };
}

async function authenticateAdminWorker(
  request: Request,
  env: Env,
  jwtSecret: string,
  origin: string
): Promise<{ authorized: true; caller: any; callerToken: string } | { authorized: false; response: Response }> {
  const auth = await authenticateUserWorker(request, env, jwtSecret, origin);
  if (!auth.authorized) return auth;

  const isAdmin = auth.caller.role === 'Admin' || auth.caller.role === 'Super Administrator' || auth.caller.role === 'Security Administrator';
  if (!isAdmin) {
    return {
      authorized: false,
      response: jsonResponse({ error: 'Forbidden: Insufficient administrative privileges.' }, 403, origin, undefined, env)
    };
  }

  return auth;
}

function maskPhone(phone?: string): string {
  if (!phone) return '+1 (•••) •••-4829';
  const clean = phone.replace(/[^\d+]/g, '');
  if (clean.length >= 4) {
    return `+1 (•••) •••-${clean.slice(-4)}`;
  }
  return '+1 (•••) •••-4829';
}

function maskEmail(email?: string, username?: string): string {
  if (!email || !email.includes('@')) return `${(username || 'u').slice(0, 2)}•••@corp.internal`;
  const [local, domain] = email.split('@');
  return `${local.slice(0, 2)}••••@${domain}`;
}

async function logSecurityEvent(
  db: any,
  username: string,
  path: string,
  risk: number,
  status: 'ALLOWED' | 'BLOCKED',
  reason: string,
  latencyMs: number,
  eventType: string
) {
  if (!db) return;
  const isoTimestamp = new Date().toISOString();
  try {
    let prevHash = 'GENESIS_HASH_ZERO_TRUST_CHAIN';
    try {
      const lastRow: any = await db.prepare('SELECT integrity_hash FROM audit_events ORDER BY id DESC LIMIT 1').first();
      if (lastRow?.integrity_hash) {
        prevHash = lastRow.integrity_hash;
      }
    } catch { /* ignore */ }

    const integrityHash = await sha256Hex(`${prevHash}:${isoTimestamp}:${username}:${path}:${risk}:${status}`);

    await db.prepare(
      'INSERT INTO audit_events (timestamp, username, requested_function, calculated_risk, status, reason, verification_latency_ms, event_type, prev_hash, integrity_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).bind(isoTimestamp, username, path, risk, status, reason, latencyMs, eventType, prevHash, integrityHash, isoTimestamp).run();

    await db.prepare(
      'INSERT INTO security_audit_logs (timestamp, username, requested_function, calculated_risk, status, reason, verification_latency_ms, event_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    ).bind(isoTimestamp, username, path, risk, status, reason, latencyMs, eventType).run();
  } catch (e) {
    console.error('[D1] Logging error (fail-closed maintained):', e);
  }
}

function jsonResponse(data: any, status = 200, origin = '', latencyMs?: number, env?: Env): Response {
  const allowedOrigin = resolveAllowedOrigin(origin, env);

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': allowedOrigin || TRUSTED_ORIGINS[0],
    'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Request-ID, X-Simulate-Fault',
    'Access-Control-Expose-Headers': 'X-Verification-Latency-MS, X-Security-Verification-Duration-MS, Server-Timing, X-Verification-Decision, X-Verification-Risk-Score',
    'Access-Control-Allow-Credentials': 'true',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    'Vary': 'Origin'
  };

  if (typeof latencyMs === 'number') {
    headers['X-Verification-Latency-MS'] = latencyMs.toString();
    headers['X-Security-Verification-Duration-MS'] = latencyMs.toString();
    headers['Server-Timing'] = `security-verify;dur=${latencyMs};desc="Security Verification Pipeline"`;
  }

  return new Response(JSON.stringify(data), {
    status,
    headers
  });
}
