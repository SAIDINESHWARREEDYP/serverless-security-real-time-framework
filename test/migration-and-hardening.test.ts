/**
 * Automated Migration Integrity, Laptop-Only Recovery Code MFA, Strict JWT & Worker Hardening Suite
 * Tests isolated SQLite databases (/tmp & :memory:) and cleans up any ephemeral test records from production SQLite.
 */

import assert from 'node:assert';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { PersistentSecurityDatabase, splitSqlStatements, db as prodDb } from '../server/db.ts';
import { authService } from '../server/services/auth.service.ts';
import { userRepository } from '../server/repositories/user.repository.ts';
import { sessionRepository } from '../server/repositories/session.repository.ts';
import { generateTotpToken } from '../src/utils/mfa.ts';
import { base64UrlEncode, hashPassword, verifyJwt } from '../server/utils/crypto.ts';
import { CONFIG } from '../server/config/env.ts';
import worker from '../src/worker.ts';

function signCustomHmacJwt(header: Record<string, any>, payload: Record<string, any>, secret: string): string {
  const h = base64UrlEncode(JSON.stringify(header));
  const p = base64UrlEncode(JSON.stringify(payload));
  const signingInput = `${h}.${p}`;
  const sig = base64UrlEncode(crypto.createHmac('sha256', secret).update(signingInput).digest());
  return `${signingInput}.${sig}`;
}

function createAsyncD1Adapter(sqliteDb: PersistentSecurityDatabase) {
  return {
    prepare(sql: string) {
      let params: any[] = [];
      const boundStmt = {
        bind(...args: any[]) {
          params = args;
          return boundStmt;
        },
        async first<T = any>(colName?: string): Promise<T | null> {
          return sqliteDb.prepare(sql).bind(...params).first<T>(colName);
        },
        async all<T = any>(): Promise<{ results: T[]; success: boolean }> {
          return sqliteDb.prepare(sql).bind(...params).all<T>();
        },
        async run(): Promise<{ success: boolean; meta: { changes: number; last_row_id: number | bigint }; changes: number }> {
          const res = sqliteDb.prepare(sql).bind(...params).run();
          return {
            success: res.success,
            changes: res.changes,
            meta: { changes: res.changes, last_row_id: res.lastRowId }
          };
        }
      };
      return boundStmt;
    }
  };
}

function getTablesAndIndexes(sqlitePath: string) {
  const raw = new DatabaseSync(sqlitePath);
  try {
    const tables = (raw.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as { name: string }[]).map((r) => r.name);
    const indexes = (raw.prepare("SELECT name FROM sqlite_master WHERE type = 'index'").all() as { name: string }[]).map((r) => r.name);
    const migrations = (raw.prepare('SELECT version FROM schema_migrations ORDER BY version ASC').all() as { version: string }[]).map((r) => r.version);
    return { raw, tables: new Set(tables), indexes: new Set(indexes), migrations };
  } catch (err) {
    raw.close();
    throw err;
  }
}

async function runTests() {
  console.log('\n=== RUNNING MIGRATION, RECOVERY-CODE MFA, STRICT JWT & WORKER HARDENING TESTS ===\n');

  const tmpCleanPath = `/tmp/test_migration_clean_${Date.now()}.sqlite`;
  const tmpLegacyPath = `/tmp/test_migration_legacy_${Date.now()}.sqlite`;
  const cleanupUserIds: string[] = [];
  const cleanupUsernames: string[] = [];
  const tempChallengeIds: string[] = [];

  try {
    // 1. Comment-aware SQL statement parser preserves statements following -- and /* */ comments
    const commentedSql = `
      -- Leading comment
      /* Multi-line block
         comment before DDL */
      CREATE TABLE IF NOT EXISTS sample_tbl (
        id TEXT PRIMARY KEY, -- inline comment
        note TEXT DEFAULT '-- not a comment; semicolon inside string'
      );
      -- Trailing comment only
    `;
    const parsedStmts = splitSqlStatements(commentedSql);
    assert.strictEqual(parsedStmts.length, 1, 'splitSqlStatements should emit exactly 1 executable statement');
    assert.ok(parsedStmts[0].startsWith('CREATE TABLE IF NOT EXISTS sample_tbl'), 'Statement must survive leading comments');
    assert.ok(parsedStmts[0].includes("'-- not a comment; semicolon inside string'"), 'String literal semicolons must not split statements');
    console.log('✔ PASS 1: Comment- and string-aware SQL splitter preserves multiline DDL & literals');

    // 2. Clean database initialization (0001 -> 0004) + no hardcoded weak defaults
    const cleanDb = new PersistentSecurityDatabase(tmpCleanPath);
    const cleanInspect = getTablesAndIndexes(tmpCleanPath);
    try {
      const requiredTables = [
        'schema_migrations',
        'users',
        'user_roles',
        'policies',
        'function_rules',
        'active_sessions',
        'sessions',
        'audit_events',
        'security_events',
        'security_audit_logs',
        'incidents',
        'security_alerts',
        'invocation_history',
        'verification_results',
        'administrative_approval_records',
        'password_change_requests',
        'username_change_requests',
        'mfa_challenges'
      ];
      for (const tbl of requiredTables) {
        assert.ok(cleanInspect.tables.has(tbl), `Missing required table in clean DB: ${tbl}`);
      }
      assert.ok(cleanInspect.indexes.has('idx_mfa_challenges_token'), 'Missing idx_mfa_challenges_token');
      assert.ok(cleanInspect.indexes.has('idx_mfa_challenges_user'), 'Missing idx_mfa_challenges_user');
      assert.strictEqual(cleanInspect.migrations.length, 4, 'Expected 4 applied migrations in clean DB');
      assert.ok(cleanInspect.migrations.includes('0004_mfa_enrollment_status.sql'), 'Expected 0004_mfa_enrollment_status.sql');
      const userCols = (cleanInspect.raw.prepare('PRAGMA table_info(users)').all() as { name: string }[]).map((c) => c.name);
      assert.ok(userCols.includes('mfa_enrolled'), 'users table must include mfa_enrolled column');

      const seededAdmin = cleanDb.getUser('secops_admin');
      assert.ok(seededAdmin, 'Seeded secops_admin record should exist');
      assert.ok(seededAdmin!.password_salt.length >= 32 && !seededAdmin!.password_hash.startsWith('!'), 'Seeded admin must use CSPRNG PBKDF2 hash');
      assert.ok(seededAdmin!.mfa_secret && seededAdmin!.mfa_secret !== 'JBSWY3DPEHPK3PXP' && seededAdmin!.mfa_secret.length >= 20, 'Seeded admin must use unique >=20-char Base32 MFA secret');
    } finally {
      cleanInspect.raw.close();
    }
    console.log('✔ PASS 2: Clean SQLite DB applies 0001-0004 with mfa_challenges, mfa_enrolled, and CSPRNG credentials');

    // 3. Upgrade pre-0003 DB preserving existing custom users and audit records + idempotent re-init
    const legacySqlite = new DatabaseSync(tmpLegacyPath);
    legacySqlite.exec('PRAGMA foreign_keys = ON;');
    legacySqlite.exec('CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL);');
    for (const migFile of ['0001_initial_schema.sql', '0002_normalized_d1_schema.sql']) {
      const sql = fs.readFileSync(path.resolve(process.cwd(), 'migrations', migFile), 'utf-8');
      for (const stmt of splitSqlStatements(sql)) {
        if (!/^PRAGMA\s+foreign_keys\s*=/i.test(stmt)) {
          legacySqlite.exec(stmt);
        }
      }
      legacySqlite.prepare('INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)').run(migFile, new Date().toISOString());
    }
    legacySqlite
      .prepare(
        `INSERT INTO users (id, username, password_hash, role, base_risk_score, status, department, mfa_enabled)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run('usr_legacy_custom', 'legacy_custom_user', 'custom_legacy_hash_keep_me', 'Developer', 15, 'APPROVED', 'Research', 1);
    legacySqlite
      .prepare(
        `INSERT INTO audit_events (timestamp, username, requested_function, calculated_risk, status, reason, verification_latency_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .run(new Date().toISOString(), 'legacy_custom_user', '/api/legacy', 10, 'ALLOWED', 'Pre-migration preserved event', 1.25);
    legacySqlite.close();

    new PersistentSecurityDatabase(tmpLegacyPath);
    new PersistentSecurityDatabase(tmpLegacyPath);

    const upgradedInspect = getTablesAndIndexes(tmpLegacyPath);
    try {
      assert.ok(upgradedInspect.tables.has('mfa_challenges'), 'Upgraded DB must contain mfa_challenges');
      assert.ok(upgradedInspect.indexes.has('idx_mfa_challenges_token'), 'Upgraded DB must contain idx_mfa_challenges_token');
      assert.strictEqual(upgradedInspect.migrations.length, 4, 'Repeated initialization must keep exactly 4 migration entries');
      const preservedUser = upgradedInspect.raw.prepare('SELECT password_hash, status, mfa_enrolled FROM users WHERE id = ?').get('usr_legacy_custom') as any;
      assert.strictEqual(preservedUser?.password_hash, 'custom_legacy_hash_keep_me', 'Existing custom user hash must not be overwritten');
      assert.strictEqual(Number(preservedUser?.mfa_enrolled), 0, 'Unverified legacy user must default to mfa_enrolled = 0');
      const preservedAudit = upgradedInspect.raw.prepare("SELECT COUNT(*) as c FROM audit_events WHERE username = 'legacy_custom_user'").get() as any;
      assert.strictEqual(Number(preservedAudit?.c), 1, 'Existing audit_events record must be preserved');
    } finally {
      upgradedInspect.raw.close();
    }
    console.log('✔ PASS 3: Pre-0003 DB upgrades through 0004 without data loss and repeated init is idempotent');

    // 4. Express Strict JWT Verification Checks
    const validClaimsBase = {
      sub: 'usr_jwt_test',
      username: 'jwt_tester',
      role: 'Developer',
      jti: 'jti_strict_1',
      iss: CONFIG.JWT_ISSUER,
      aud: CONFIG.JWT_AUDIENCE,
      iat: Math.floor(Date.now() / 1000),
      nbf: Math.floor(Date.now() / 1000) - 5,
      exp: Math.floor(Date.now() / 1000) + 3600
    };
    const algNoneToken = `${base64UrlEncode(JSON.stringify({ alg: 'none', typ: 'JWT' }))}.${base64UrlEncode(JSON.stringify(validClaimsBase))}.`;
    assert.strictEqual(verifyJwt(algNoneToken).valid, false, 'alg:none JWT must be rejected');

    const { iss: _omitIss, ...noIssClaims } = validClaimsBase;
    assert.strictEqual(verifyJwt(signCustomHmacJwt({ alg: 'HS256', typ: 'JWT' }, noIssClaims, CONFIG.JWT_SECRET)).valid, false, 'JWT without iss must be rejected');

    const { aud: _omitAud, ...noAudClaims } = validClaimsBase;
    assert.strictEqual(verifyJwt(signCustomHmacJwt({ alg: 'HS256', typ: 'JWT' }, noAudClaims, CONFIG.JWT_SECRET)).valid, false, 'JWT without aud must be rejected');

    const { nbf: _omitNbf, ...noNbfClaims } = validClaimsBase;
    assert.strictEqual(verifyJwt(signCustomHmacJwt({ alg: 'HS256', typ: 'JWT' }, noNbfClaims, CONFIG.JWT_SECRET)).valid, false, 'JWT without nbf must be rejected');

    const { iat: _omitIat, ...noIatClaims } = validClaimsBase;
    assert.strictEqual(verifyJwt(signCustomHmacJwt({ alg: 'HS256', typ: 'JWT' }, noIatClaims, CONFIG.JWT_SECRET)).valid, false, 'JWT without iat must be rejected');

    const futureIatClaims = { ...validClaimsBase, iat: Math.floor(Date.now() / 1000) + 600 };
    assert.strictEqual(verifyJwt(signCustomHmacJwt({ alg: 'HS256', typ: 'JWT' }, futureIatClaims, CONFIG.JWT_SECRET)).valid, false, 'JWT with future iat > now+60 must be rejected');

    console.log('✔ PASS 4: Express verifyJwt strictly rejects alg:none, missing iss/aud/iat/nbf, and future iat');

    // 5. Express AuthService Laptop-Only Recovery Code Enrollment, Verification, Replay, Expiry, Lockout, Concurrency & Exhaustion/Reset (Tests RC-1..RC-10)
    const testUname = `mfa_recovery_test_${Date.now()}`;
    const testPwd = `StrongPassword_${Date.now()}!`;
    cleanupUsernames.push(testUname);

    const createdUser = userRepository.create({
      username: testUname,
      password: testPwd,
      role: 'Developer',
      base_risk_score: 10,
      status: 'APPROVED',
      department: 'Security QA',
      mfa_enabled: true
    });
    cleanupUserIds.push(createdUser.id);
    assert.ok(createdUser.mfa_secret && createdUser.mfa_secret !== 'JBSWY3DPEHPK3PXP' && createdUser.mfa_secret.length >= 20, 'New user must receive >=20-char random secret');

    // Test RC-8: First-time recovery-code enrollment without phone issues 8 codes (no TOTP secret/URI) and confirming 1 activates enrollment
    const enrollLogin = await authService.login({ username: testUname, password: testPwd, ipAddress: '127.0.0.10' });
    assert.strictEqual(enrollLogin.status, 'MFA_REQUIRED');
    assert.strictEqual(enrollLogin.enrollmentRequired, true);
    assert.strictEqual(enrollLogin.preferredMethod, 'backup_code', 'First-time login must default to laptop recovery code mode');
    tempChallengeIds.push(enrollLogin.mfaChallengeId!);

    const recoveryEnrollOut = authService.getChallengeEnrollment(enrollLogin.mfaChallengeId!, 'recovery_codes');
    assert.strictEqual(recoveryEnrollOut.success, true);
    assert.strictEqual(recoveryEnrollOut.mode, 'recovery_codes');
    assert.strictEqual(recoveryEnrollOut.secret, undefined, 'recovery_codes enrollment must not expose TOTP secret');
    assert.strictEqual(recoveryEnrollOut.provisioningUri, undefined, 'recovery_codes enrollment must not expose provisioningUri');
    assert.ok(Array.isArray(recoveryEnrollOut.backupCodes) && recoveryEnrollOut.backupCodes.length === 8, 'Must issue 8 recovery codes');

    // Confirm first code activates enrollment and consumes code #0 -> leaves 7 remaining
    const confirmCode0 = recoveryEnrollOut.backupCodes![0];
    const enrollVerify = await authService.verifyMfa({
      mfaChallengeId: enrollLogin.mfaChallengeId!,
      code: confirmCode0,
      method: 'backup_code'
    });
    assert.strictEqual(enrollVerify.success, true, 'Test RC-8: Confirming 1 recovery code activates laptop-only MFA');
    assert.strictEqual(enrollVerify.mfaMethod, 'backup_code');
    assert.strictEqual(enrollVerify.recoveryCodesRemaining, 7);
    assert.ok(enrollVerify.token && verifyJwt(enrollVerify.token).valid, 'Must issue valid JWT');
    assert.strictEqual(userRepository.findById(createdUser.id)?.mfa_enrolled, true, 'User must be marked mfa_enrolled = true after recovery code confirmation');

    // Test RC-3 & RC-4: Replay of same consumed challenge OR previously consumed recovery code fails
    const replayChallengeRes = await authService.verifyMfa({
      mfaChallengeId: enrollLogin.mfaChallengeId!,
      code: recoveryEnrollOut.backupCodes![1],
      method: 'backup_code'
    });
    assert.strictEqual(replayChallengeRes.success, false, 'Test RC-4: Replaying consumed mfaChallengeId must fail');

    // Test RC-9 & RC-3 & RC-2: Subsequent login succeeds without authenticator, blocks enroll-challenge (403), rejects invalid & previously consumed code
    const loginNext = await authService.login({ username: testUname, password: testPwd, ipAddress: '127.0.0.11' });
    assert.strictEqual(loginNext.status, 'MFA_REQUIRED');
    assert.strictEqual(loginNext.enrollmentRequired, false, 'Test RC-9: Enrolled laptop-only user must NOT prompt enrollment again');
    assert.strictEqual(loginNext.recoveryCodesRemaining, 7);
    tempChallengeIds.push(loginNext.mfaChallengeId!);

    const blockedEnroll = authService.getChallengeEnrollment(loginNext.mfaChallengeId!, 'recovery_codes');
    assert.strictEqual(blockedEnroll.success, false);
    assert.strictEqual(blockedEnroll.status, 403, 'Already-enrolled user must be blocked from re-fetching enrollment codes');

    const invalidAttempt = await authService.verifyMfa({
      mfaChallengeId: loginNext.mfaChallengeId!,
      code: 'ZZZZ-9999',
      method: 'backup_code'
    });
    assert.strictEqual(invalidAttempt.success, false, 'Test RC-2: Invalid recovery code rejected');
    assert.strictEqual(invalidAttempt.attemptsLeft, 4, 'Test RC-2: Invalid recovery code decrements attemptsLeft');

    const reuseOldCodeAttempt = await authService.verifyMfa({
      mfaChallengeId: loginNext.mfaChallengeId!,
      code: confirmCode0,
      method: 'backup_code'
    });
    assert.strictEqual(reuseOldCodeAttempt.success, false, 'Test RC-3: Previously consumed recovery code rejected');
    assert.strictEqual(reuseOldCodeAttempt.attemptsLeft, 3);

    // Valid code #1 succeeds -> leaves 6 remaining
    const confirmCode1 = recoveryEnrollOut.backupCodes![1];
    const loginNextOk = await authService.verifyMfa({
      mfaChallengeId: loginNext.mfaChallengeId!,
      code: confirmCode1,
      method: 'backup_code'
    });
    assert.strictEqual(loginNextOk.success, true, 'Test RC-1 & RC-9: Valid recovery code succeeds without authenticator');
    assert.strictEqual(loginNextOk.recoveryCodesRemaining, 6);

    // Test RC-6: Max-attempts lockout on repeated invalid recovery codes
    const lockLogin = await authService.login({ username: testUname, password: testPwd, ipAddress: '127.0.0.12' });
    tempChallengeIds.push(lockLogin.mfaChallengeId!);
    for (let i = 1; i <= 5; i++) {
      const bad = await authService.verifyMfa({
        mfaChallengeId: lockLogin.mfaChallengeId!,
        code: 'AAAA-BBBB',
        method: 'backup_code'
      });
      assert.strictEqual(bad.success, false);
      assert.strictEqual(bad.attemptsLeft, Math.max(0, 5 - i));
    }
    const lockRow = prodDb.prepare('SELECT consumed, attempts FROM mfa_challenges WHERE id = ?').bind(lockLogin.mfaChallengeId).first<any>();
    assert.strictEqual(Number(lockRow.consumed), 1, 'Test RC-6: Exhausted recovery attempts lock out challenge');
    assert.strictEqual(Number(lockRow.attempts), 5);

    // Test RC-5: Expired mfaChallengeId rejected
    const expLogin = await authService.login({ username: testUname, password: testPwd, ipAddress: '127.0.0.13' });
    tempChallengeIds.push(expLogin.mfaChallengeId!);
    prodDb.prepare('UPDATE mfa_challenges SET expires_at = ? WHERE id = ?').bind(new Date(Date.now() - 60_000).toISOString(), expLogin.mfaChallengeId).run();
    const expiredRes = await authService.verifyMfa({
      mfaChallengeId: expLogin.mfaChallengeId!,
      code: recoveryEnrollOut.backupCodes![2],
      method: 'backup_code'
    });
    assert.strictEqual(expiredRes.success, false, 'Test RC-5: Expired mfaChallengeId must be rejected');
    assert.ok(expiredRes.error?.toLowerCase().includes('timed out') || expiredRes.error?.toLowerCase().includes('expired'));

    // Test RC-7: Concurrent submission with the SAME recovery code (Promise.all) -> strictly 1 succeeds, 1 fails
    const concLoginA = await authService.login({ username: testUname, password: testPwd, ipAddress: '127.0.0.14' });
    const concLoginB = await authService.login({ username: testUname, password: testPwd, ipAddress: '127.0.0.15' });
    tempChallengeIds.push(concLoginA.mfaChallengeId!, concLoginB.mfaChallengeId!);
    const raceCode = recoveryEnrollOut.backupCodes![2];
    const [raceResA, raceResB] = await Promise.all([
      authService.verifyMfa({ mfaChallengeId: concLoginA.mfaChallengeId!, code: raceCode, method: 'backup_code' }),
      authService.verifyMfa({ mfaChallengeId: concLoginB.mfaChallengeId!, code: raceCode, method: 'backup_code' })
    ]);
    const raceSuccesses = [raceResA, raceResB].filter((r) => r.success).length;
    assert.strictEqual(raceSuccesses, 1, 'Test RC-7 (Express): Exactly 1 concurrent submission of same recovery code may succeed');
    assert.strictEqual(userRepository.findById(createdUser.id)?.mfa_backup_codes?.length, 5, '5 backup codes should remain after 1 wins race');

    // Test RC-10: Exhaust all remaining recovery codes -> clear exhaustion error -> Admin MFA reset revokes prior session & restores enrollment
    const priorToken = enrollVerify.token!;
    for (let idx = 3; idx < 8; idx++) {
      const l = await authService.login({ username: testUname, password: testPwd, ipAddress: '127.0.0.16' });
      tempChallengeIds.push(l.mfaChallengeId!);
      const v = await authService.verifyMfa({
        mfaChallengeId: l.mfaChallengeId!,
        code: recoveryEnrollOut.backupCodes![idx],
        method: 'backup_code'
      });
      assert.strictEqual(v.success, true, `Consuming recovery code #${idx} must succeed`);
    }
    const zeroLogin = await authService.login({ username: testUname, password: testPwd, ipAddress: '127.0.0.17' });
    tempChallengeIds.push(zeroLogin.mfaChallengeId!);
    assert.strictEqual(zeroLogin.recoveryCodesRemaining, 0, 'Test RC-10: 0 recovery codes remain');
    const exhaustedAttempt = await authService.verifyMfa({
      mfaChallengeId: zeroLogin.mfaChallengeId!,
      code: recoveryEnrollOut.backupCodes![7],
      method: 'backup_code'
    });
    assert.strictEqual(exhaustedAttempt.success, false);
    assert.ok(exhaustedAttempt.error?.includes('0 remaining') || exhaustedAttempt.error?.toLowerCase().includes('no valid recovery codes'), 'Test RC-10: Clear exhaustion message required');

    const resetUser = authService.resetMfaEnrollment(testUname, 'secops_admin');
    assert.ok(resetUser, 'Test RC-10: Admin MFA reset succeeds');
    assert.strictEqual(resetUser?.mfa_enrolled, false);
    const revokedPriorSession = sessionRepository.findByToken(priorToken);
    assert.strictEqual(revokedPriorSession?.status, 'revoked', 'Test RC-10: Admin MFA reset must revoke active sessions');
    const resetAuditLogged = prodDb
      .prepare("SELECT * FROM audit_events WHERE username = ? AND event_type = 'MFA_ENROLLMENT_RESET' AND requested_function LIKE ? ORDER BY id DESC LIMIT 1")
      .bind('secops_admin', `%${testUname}%`)
      .first<any>();
    assert.ok(resetAuditLogged && resetAuditLogged.reason.includes('secops_admin'), 'Test RC-10: MFA reset must log actor & event');

    // Optional TOTP flow still works smoothly after MFA reset
    const loginAfterReset = await authService.login({ username: testUname, password: testPwd, ipAddress: '127.0.0.18' });
    assert.strictEqual(loginAfterReset.enrollmentRequired, true);
    tempChallengeIds.push(loginAfterReset.mfaChallengeId!);
    const qrEnroll = authService.getChallengeEnrollment(loginAfterReset.mfaChallengeId!, 'authenticator');
    assert.strictEqual(qrEnroll.success, true);
    assert.ok(qrEnroll.provisioningUri?.startsWith('otpauth://totp/'));
    const validTotp = generateTotpToken(userRepository.findById(createdUser.id)!.mfa_secret!);
    const totpVerify = await authService.verifyMfa({ mfaChallengeId: loginAfterReset.mfaChallengeId!, code: validTotp, method: 'authenticator' });
    assert.strictEqual(totpVerify.success, true, 'Optional RFC 6238 TOTP enrollment verification succeeds');
    assert.strictEqual(totpVerify.mfaMethod, 'authenticator');
    console.log('✔ PASS 5: Express laptop-only recovery-code enrollment, replay, expiry, lockout, concurrency, exhaustion & Admin reset verified (Tests RC-1..RC-10)');

    // 6. Cloudflare Worker end-to-end tests against isolated in-memory SQLite D1 adapter
    const workerMemDb = new PersistentSecurityDatabase(':memory:');
    // Set an isolated test password on in-memory worker admin ONLY (never hardcoded default)
    const workerAdminPwd = `WorkerAdmin_Test_${Date.now()}!`;
    const { salt: wSalt, hash: wHash } = hashPassword(workerAdminPwd);
    workerMemDb.prepare('UPDATE users SET password_salt = ?, password_hash = ? WHERE username = ?').bind(wSalt, wHash, 'secops_admin').run();

    const workerEnv = {
      DB: createAsyncD1Adapter(workerMemDb),
      ENVIRONMENT: 'development',
      ZERO_TRUST_ORIGIN: 'https://serverless-securityverification.ai.studio',
      JWT_SECRET: 'worker_test_jwt_secret_minimum_32_characters_2026'
    };
    const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };

    // 6a. Worker fail-closed 503 across all DB-dependent endpoints when env.DB is missing
    const noDbEnv = { ...workerEnv, DB: undefined } as any;
    const validWorkerJwt = signCustomHmacJwt({ alg: 'HS256', typ: 'JWT' }, validClaimsBase, workerEnv.JWT_SECRET);
    const failClosedChecks = [
      worker.fetch(new Request('http://localhost:3000/api/health'), noDbEnv, ctx),
      worker.fetch(new Request('http://localhost:3000/api/system/overview'), noDbEnv, ctx),
      worker.fetch(new Request('http://localhost:3000/api/auth/status?username=secops_admin'), noDbEnv, ctx),
      worker.fetch(new Request('http://localhost:3000/api/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'x', password: 'StrongPassword_123!' }) }), noDbEnv, ctx),
      worker.fetch(new Request('http://localhost:3000/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'secops_admin', password: workerAdminPwd }) }), noDbEnv, ctx),
      worker.fetch(new Request('http://localhost:3000/api/incidents', { headers: { Authorization: `Bearer ${validWorkerJwt}` } }), noDbEnv, ctx),
      worker.fetch(new Request('http://localhost:3000/api/v1/verify/invoke', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${validWorkerJwt}` }, body: JSON.stringify({ functionName: 'getDashboardMetrics' }) }), noDbEnv, ctx),
      worker.fetch(new Request('http://localhost:3000/api/system/policy-config'), noDbEnv, ctx),
      worker.fetch(new Request('http://localhost:3000/api/system/rules'), noDbEnv, ctx)
    ];
    const failClosedResponses = await Promise.all(failClosedChecks);
    for (const r of failClosedResponses) {
      assert.strictEqual(r.status, 503, `Expected 503 when DB missing on ${r.url}`);
    }
    const unauthIncNoDb = await worker.fetch(new Request('http://localhost:3000/api/incidents'), noDbEnv, ctx);
    assert.strictEqual(unauthIncNoDb.status, 401);

    // Health healthy check
    const healthOk = await worker.fetch(new Request('http://localhost:3000/api/health'), workerEnv, ctx);
    assert.strictEqual(healthOk.status, 200);

    // 6b. Strict JWT checks in Worker (reject alg:none & missing iss/aud/nbf even when signed with worker secret)
    const workerAlgNone = `${base64UrlEncode(JSON.stringify({ alg: 'none', typ: 'JWT' }))}.${base64UrlEncode(JSON.stringify({
      sub: 'usr_secops_admin',
      username: 'secops_admin',
      role: 'Super Administrator',
      jti: 'jti_fake',
      iss: 'https://auth.serverless-security.local',
      aud: 'serverless-security-framework',
      iat: Math.floor(Date.now() / 1000),
      nbf: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600
    }))}.`;
    const workerRejectNone = await worker.fetch(
      new Request('http://localhost:3000/api/incidents', { headers: { Authorization: `Bearer ${workerAlgNone}` } }),
      workerEnv,
      ctx
    );
    assert.strictEqual(workerRejectNone.status, 401, 'Worker must reject alg:none JWT');

    const workerMissingClaimsJwt = signCustomHmacJwt(
      { alg: 'HS256', typ: 'JWT' },
      { sub: 'usr_secops_admin', username: 'secops_admin', role: 'Super Administrator', jti: 'jti_m', exp: Math.floor(Date.now() / 1000) + 3600 },
      workerEnv.JWT_SECRET
    );
    const workerRejectMissingClaims = await worker.fetch(
      new Request('http://localhost:3000/api/incidents', { headers: { Authorization: `Bearer ${workerMissingClaimsJwt}` } }),
      workerEnv,
      ctx
    );
    assert.strictEqual(workerRejectMissingClaims.status, 401, 'Worker must reject JWT missing iss/aud/iat/nbf');

    // 6c. /api/register rejects self-assigned Admin role (403) and accepts Developer (PENDING_APPROVAL)
    const regAdminRes = await worker.fetch(
      new Request('http://localhost:3000/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'priv_esc_user', password: 'StrongPassword_123!', role: 'Admin' })
      }),
      workerEnv,
      ctx
    );
    assert.strictEqual(regAdminRes.status, 403);

    const regDevRes = await worker.fetch(
      new Request('http://localhost:3000/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'worker_dev_1', password: 'StrongPassword_123!', role: 'Developer' })
      }),
      workerEnv,
      ctx
    );
    assert.strictEqual(regDevRes.status, 200);
    const regDevJson: any = await regDevRes.json();
    assert.strictEqual(regDevJson.status, 'PENDING_APPROVAL');
    assert.strictEqual(regDevJson.pendingApproval, true);
    assert.ok(Array.isArray(regDevJson.mfaEnrollment?.backupCodes) && regDevJson.mfaEnrollment.backupCodes.length === 8);

    // 6d. /api/auth/mfa/send-sms returns 501
    const smsRes = await worker.fetch(new Request('http://localhost:3000/api/auth/mfa/send-sms', { method: 'POST' }), workerEnv, ctx);
    assert.strictEqual(smsRes.status, 501);

    // 6e. Worker laptop-only Recovery-Code Enrollment -> Verify -> Concurrent Race CAS -> Reset
    const workerLogin = await worker.fetch(
      new Request('http://localhost:3000/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'secops_admin', password: workerAdminPwd })
      }),
      workerEnv,
      ctx
    );
    assert.strictEqual(workerLogin.status, 200);
    const workerLoginJson: any = await workerLogin.json();
    assert.strictEqual(workerLoginJson.mfaRequired, true);
    assert.strictEqual(workerLoginJson.enrollmentRequired, true);
    assert.strictEqual(workerLoginJson.preferredMethod, 'backup_code');
    assert.strictEqual('totpSecret' in workerLoginJson, false);

    // Enroll with mode: 'recovery_codes'
    const workerEnrollRec = await worker.fetch(
      new Request('http://localhost:3000/api/auth/mfa/enroll-challenge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mfaChallengeId: workerLoginJson.mfaChallengeId, mode: 'recovery_codes' })
      }),
      workerEnv,
      ctx
    );
    assert.strictEqual(workerEnrollRec.status, 200);
    const workerEnrollRecJson: any = await workerEnrollRec.json();
    assert.strictEqual(workerEnrollRecJson.mode, 'recovery_codes');
    assert.strictEqual(workerEnrollRecJson.secret, undefined);
    assert.ok(Array.isArray(workerEnrollRecJson.backupCodes) && workerEnrollRecJson.backupCodes.length === 8);

    // Confirm recovery code #0 activates enrollment in Worker
    const workerVerifyRec = await worker.fetch(
      new Request('http://localhost:3000/api/auth/mfa/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mfaChallengeId: workerLoginJson.mfaChallengeId,
          code: workerEnrollRecJson.backupCodes[0],
          method: 'backup_code'
        })
      }),
      workerEnv,
      ctx
    );
    assert.strictEqual(workerVerifyRec.status, 200);
    const workerVerifyRecJson: any = await workerVerifyRec.json();
    assert.strictEqual(workerVerifyRecJson.mfaMethod, 'backup_code');
    assert.strictEqual(workerVerifyRecJson.recoveryCodesRemaining, 7);
    const adminJwt = workerVerifyRecJson.token as string;
    assert.ok(adminJwt && adminJwt.split('.').length === 3);

    // Worker concurrent Promise.all race with same recovery code #1 across two active challenges -> strictly 1 succeeds
    const wLoginRace1: any = await (await worker.fetch(
      new Request('http://localhost:3000/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'secops_admin', password: workerAdminPwd })
      }),
      workerEnv,
      ctx
    )).json();
    const wLoginRace2: any = await (await worker.fetch(
      new Request('http://localhost:3000/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'secops_admin', password: workerAdminPwd })
      }),
      workerEnv,
      ctx
    )).json();
    const wRaceCode = workerEnrollRecJson.backupCodes[1];
    const [wRaceA, wRaceB] = await Promise.all([
      worker.fetch(
        new Request('http://localhost:3000/api/auth/mfa/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ mfaChallengeId: wLoginRace1.mfaChallengeId, code: wRaceCode, method: 'backup_code' })
        }),
        workerEnv,
        ctx
      ),
      worker.fetch(
        new Request('http://localhost:3000/api/auth/mfa/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ mfaChallengeId: wLoginRace2.mfaChallengeId, code: wRaceCode, method: 'backup_code' })
        }),
        workerEnv,
        ctx
      )
    ]);
    const workerRaceSuccessCount = [wRaceA, wRaceB].filter((r) => r.status === 200).length;
    assert.strictEqual(workerRaceSuccessCount, 1, 'Test RC-7 (Worker CAS): Exactly 1 concurrent submission of same recovery code may succeed');

    // Lockout test (429 on 5th bad attempt)
    const wLockLogin: any = await (await worker.fetch(
      new Request('http://localhost:3000/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'secops_admin', password: workerAdminPwd })
      }),
      workerEnv,
      ctx
    )).json();
    for (let i = 1; i <= 4; i++) {
      const failRes = await worker.fetch(
        new Request('http://localhost:3000/api/auth/mfa/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ mfaChallengeId: wLockLogin.mfaChallengeId, code: 'BAD1-BAD2', method: 'backup_code' })
        }),
        workerEnv,
        ctx
      );
      assert.strictEqual(failRes.status, 401);
    }
    const lockRes = await worker.fetch(
      new Request('http://localhost:3000/api/auth/mfa/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mfaChallengeId: wLockLogin.mfaChallengeId, code: 'BAD1-BAD2', method: 'backup_code' })
      }),
      workerEnv,
      ctx
    );
    assert.strictEqual(lockRes.status, 429);

    // Worker regenerate recovery codes + mfa-reset
    const wRegenRes = await worker.fetch(
      new Request('http://localhost:3000/api/system/users/secops_admin/recovery-codes', {
        method: 'POST',
        headers: { Authorization: `Bearer ${adminJwt}` }
      }),
      workerEnv,
      ctx
    );
    assert.strictEqual(wRegenRes.status, 200);
    const wRegenJson: any = await wRegenRes.json();
    assert.ok(Array.isArray(wRegenJson.plaintextCodes) && wRegenJson.plaintextCodes.length === 8);

    const wResetRes = await worker.fetch(
      new Request('http://localhost:3000/api/system/users/secops_admin/mfa-reset', {
        method: 'POST',
        headers: { Authorization: `Bearer ${adminJwt}` }
      }),
      workerEnv,
      ctx
    );
    assert.strictEqual(wResetRes.status, 200);

    // Confirm prior JWT revoked after mfa-reset on authenticated route
    const afterResetIncidents = await worker.fetch(
      new Request('http://localhost:3000/api/incidents', {
        headers: { Authorization: `Bearer ${adminJwt}` }
      }),
      workerEnv,
      ctx
    );
    assert.strictEqual(afterResetIncidents.status, 401, 'Session must be revoked after Admin MFA reset in Worker');

    // Fresh login & optional TOTP verify to re-obtain Admin JWT for remaining Worker assertions
    const wFreshLogin: any = await (await worker.fetch(
      new Request('http://localhost:3000/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'secops_admin', password: workerAdminPwd })
      }),
      workerEnv,
      ctx
    )).json();
    assert.strictEqual(wFreshLogin.enrollmentRequired, true);
    const wEnrollQr: any = await (await worker.fetch(
      new Request('http://localhost:3000/api/auth/mfa/enroll-challenge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mfaChallengeId: wFreshLogin.mfaChallengeId, mode: 'authenticator' })
      }),
      workerEnv,
      ctx
    )).json();
    assert.ok(wEnrollQr.secret && wEnrollQr.provisioningUri?.startsWith('otpauth://totp/'));
    const freshTotp = generateTotpToken(wEnrollQr.secret);
    const wFreshVerify: any = await (await worker.fetch(
      new Request('http://localhost:3000/api/auth/mfa/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mfaChallengeId: wFreshLogin.mfaChallengeId, code: freshTotp, method: 'authenticator' })
      }),
      workerEnv,
      ctx
    )).json();
    assert.strictEqual(wFreshVerify.success, true);
    const adminJwt2 = wFreshVerify.token as string;

    // 6f. /api/system/overview strips raw email/phone
    const overviewRes = await worker.fetch(
      new Request('http://localhost:3000/api/system/overview', {
        headers: { Authorization: `Bearer ${adminJwt2}` }
      }),
      workerEnv,
      ctx
    );
    assert.strictEqual(overviewRes.status, 200);
    const overviewJson: any = await overviewRes.json();
    for (const u of overviewJson.users || []) {
      assert.strictEqual('email' in u, false, '/api/system/overview must not expose raw email');
      assert.strictEqual('phone' in u, false, '/api/system/overview must not expose raw phone');
    }

    // 6g. /api/incidents & /api/v1/verify/invoke
    const incCreate = await worker.fetch(
      new Request('http://localhost:3000/api/incidents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminJwt2}` },
        body: JSON.stringify({ title: 'Worker D1 Incident Verification', severity: 'HIGH', status: 'OPEN' })
      }),
      workerEnv,
      ctx
    );
    assert.strictEqual(incCreate.status, 201);
    const incCreateJson: any = await incCreate.json();

    const incPatch = await worker.fetch(
      new Request(`http://localhost:3000/api/incidents/${incCreateJson.incident.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminJwt2}` },
        body: JSON.stringify({ status: 'CONTAINED', mitigation_steps: 'Edge block enforced' })
      }),
      workerEnv,
      ctx
    );
    assert.strictEqual(incPatch.status, 200);

    const allowRes = await worker.fetch(
      new Request('http://localhost:3000/api/v1/verify/invoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminJwt2}` },
        body: JSON.stringify({ functionName: 'getDashboardMetrics', payload: { region: 'ap-south-1' } })
      }),
      workerEnv,
      ctx
    );
    assert.strictEqual(allowRes.status, 200);

    const denyRes = await worker.fetch(
      new Request('http://localhost:3000/api/v1/verify/invoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminJwt2}` },
        body: JSON.stringify({ functionName: 'getDashboardMetrics', payload: { target: 'http://169.254.169.254/latest/meta-data/' } })
      }),
      workerEnv,
      ctx
    );
    assert.strictEqual(denyRes.status, 403);

    const auditRows = workerMemDb.getAllLogs();
    const chainedEvents = auditRows.filter((r) => typeof r.integrity_hash === 'string' && r.integrity_hash.length === 64);
    assert.ok(chainedEvents.length >= 2, 'Worker verification events must be SHA-256 hash-chained in D1 audit_events');
    console.log('✔ PASS 6: Cloudflare Worker fail-closed 503s, strict JWT, recovery-code CAS concurrency, MFA reset, PII stripping & 15-step verification passed');

    console.log('\nALL MIGRATION, RECOVERY-CODE MFA, STRICT JWT & WORKER HARDENING TESTS PASSED (6/6)\n');
  } finally {
    for (const cid of tempChallengeIds) {
      try {
        prodDb.prepare('DELETE FROM mfa_challenges WHERE id = ?').bind(cid).run();
      } catch { /* ignore */ }
    }
    for (const uname of cleanupUsernames) {
      try {
        prodDb.prepare('DELETE FROM active_sessions WHERE username = ?').bind(uname).run();
        prodDb.prepare('DELETE FROM audit_events WHERE username = ? OR requested_function LIKE ?').bind(uname, `%${uname}%`).run();
      } catch { /* ignore */ }
    }
    for (const uid of cleanupUserIds) {
      try {
        prodDb.prepare('DELETE FROM sessions WHERE user_id = ?').bind(uid).run();
        prodDb.prepare('DELETE FROM users WHERE id = ?').bind(uid).run();
      } catch { /* ignore */ }
    }
    for (const f of [tmpCleanPath, tmpLegacyPath]) {
      try {
        if (fs.existsSync(f)) fs.unlinkSync(f);
      } catch { /* ignore */ }
    }
  }
}

runTests().catch((err) => {
  console.error('❌ Migration/Hardening Test Failed:', err);
  process.exit(1);
});
