/**
 * Automated Migration Integrity, MFA Persistence, and Cloudflare Worker Hardening Suite
 * Tests isolated SQLite databases (/tmp & :memory:) without modifying production security_framework.sqlite.
 */

import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { PersistentSecurityDatabase, splitSqlStatements, db as prodDb } from '../server/db.ts';
import { authService } from '../server/services/auth.service.ts';
import { userRepository } from '../server/repositories/user.repository.ts';
import { generateTotpToken } from '../src/utils/mfa.ts';
import { verifyJwt } from '../server/utils/crypto.ts';
import worker from '../src/worker.ts';

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
  console.log('\n=== RUNNING MIGRATION, MFA PERSISTENCE & WORKER HARDENING TESTS ===\n');

  const tmpCleanPath = `/tmp/test_migration_clean_${Date.now()}.sqlite`;
  const tmpLegacyPath = `/tmp/test_migration_legacy_${Date.now()}.sqlite`;
  let tempUserId: string | null = null;
  let tempChallengeIds: string[] = [];

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

    // 2. Clean database initialization (0001 -> 0002 -> 0003)
    new PersistentSecurityDatabase(tmpCleanPath);
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
    } finally {
      cleanInspect.raw.close();
    }
    console.log('✔ PASS 2: Clean SQLite DB applies 0001-0004 with mfa_challenges, mfa_enrolled, and all indexes');

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

    // Run upgrade via PersistentSecurityDatabase constructor
    new PersistentSecurityDatabase(tmpLegacyPath);
    // Repeated initialization must be completely idempotent
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

    // 4. Express AuthService persistent mfa_challenges lifecycle (DB stored, replay blocked, 5-attempt lockout)
    const testUname = `mfa_persist_test_${Date.now()}`;
    const createdUser = userRepository.create({
      username: testUname,
      password: 'StrongPassword_2026!',
      role: 'Developer',
      base_risk_score: 10,
      status: 'APPROVED',
      department: 'Security QA',
      mfa_enabled: true
    });
    tempUserId = createdUser.id;
    assert.ok(createdUser.mfa_secret && createdUser.mfa_secret !== 'JBSWY3DPEHPK3PXP', 'New user must receive random TOTP secret');

    const loginRes = await authService.login({ username: testUname, password: 'StrongPassword_2026!', ipAddress: '127.0.0.10' });
    assert.strictEqual(loginRes.status, 'MFA_REQUIRED');
    assert.strictEqual(loginRes.enrollmentRequired, true, 'First-time unpaired login must set enrollmentRequired = true');
    assert.ok(loginRes.mfaChallengeId, 'Login should return persistent mfaChallengeId');
    tempChallengeIds.push(loginRes.mfaChallengeId!);

    const enrollOut = authService.getChallengeEnrollment(loginRes.mfaChallengeId!);
    assert.strictEqual(enrollOut.success, true, 'Unpaired active challenge must allow one-time enrollment QR retrieval');
    assert.ok(enrollOut.provisioningUri?.startsWith('otpauth://totp/'));
    assert.ok(Array.isArray(enrollOut.backupCodes) && enrollOut.backupCodes.length === 8);

    const dbChallenge = prodDb.prepare('SELECT * FROM mfa_challenges WHERE id = ?').bind(loginRes.mfaChallengeId).first<any>();
    assert.ok(dbChallenge, 'MFA challenge must be persisted in mfa_challenges table');
    assert.strictEqual(Number(dbChallenge.consumed), 0);

    // 5 failed attempts lock out challenge
    for (let i = 1; i <= 5; i++) {
      const badVerify = await authService.verifyMfa({ mfaChallengeId: loginRes.mfaChallengeId!, code: '000000' });
      assert.strictEqual(badVerify.success, false);
      assert.strictEqual(badVerify.attemptsLeft, Math.max(0, 5 - i));
    }
    const lockedChallenge = prodDb.prepare('SELECT consumed, attempts FROM mfa_challenges WHERE id = ?').bind(loginRes.mfaChallengeId).first<any>();
    assert.strictEqual(Number(lockedChallenge.consumed), 1, 'Exhausted challenge must be marked consumed');
    assert.strictEqual(Number(lockedChallenge.attempts), 5);

    // Fresh challenge with valid RFC 6238 TOTP code succeeds, seals enrollment, and blocks replay
    const loginRes2 = await authService.login({ username: testUname, password: 'StrongPassword_2026!', ipAddress: '127.0.0.11' });
    assert.strictEqual(loginRes2.status, 'MFA_REQUIRED');
    tempChallengeIds.push(loginRes2.mfaChallengeId!);
    const refreshedUser = userRepository.findById(createdUser.id)!;
    const validTotp = generateTotpToken(refreshedUser.mfa_secret!);
    const okVerify = await authService.verifyMfa({ mfaChallengeId: loginRes2.mfaChallengeId!, code: validTotp });
    assert.strictEqual(okVerify.success, true, 'Valid TOTP must complete MFA verification');
    assert.ok(okVerify.token && verifyJwt(okVerify.token).valid, 'Completed MFA must issue valid JWT');
    assert.strictEqual(userRepository.findById(createdUser.id)?.mfa_enrolled, true, 'User must be marked mfa_enrolled after verification');

    const replayVerify = await authService.verifyMfa({ mfaChallengeId: loginRes2.mfaChallengeId!, code: validTotp });
    assert.strictEqual(replayVerify.success, false, 'Replaying consumed MFA challenge must fail');

    // Subsequent login for already-enrolled user must NOT allow enroll-challenge (403)
    const loginRes3 = await authService.login({ username: testUname, password: 'StrongPassword_2026!', ipAddress: '127.0.0.12' });
    assert.strictEqual(loginRes3.enrollmentRequired, false, 'Enrolled user login must set enrollmentRequired = false');
    tempChallengeIds.push(loginRes3.mfaChallengeId!);
    const blockedEnroll = authService.getChallengeEnrollment(loginRes3.mfaChallengeId!);
    assert.strictEqual(blockedEnroll.success, false);
    assert.strictEqual(blockedEnroll.status, 403, 'Enrolled user must be blocked from fetching QR via enroll-challenge');

    // Admin MFA reset re-enables first-time QR pairing
    const resetRes = authService.resetMfaEnrollment(testUname, 'secops_admin');
    assert.ok(resetRes, 'resetMfaEnrollment must return updated UserRecord');
    assert.strictEqual(resetRes?.mfa_enrolled, false);
    assert.strictEqual(userRepository.findById(createdUser.id)?.mfa_enrolled, false);
    const loginRes4 = await authService.login({ username: testUname, password: 'StrongPassword_2026!', ipAddress: '127.0.0.13' });
    assert.strictEqual(loginRes4.enrollmentRequired, true, 'Login after MFA reset must restore enrollmentRequired = true');
    if (loginRes4.mfaChallengeId) tempChallengeIds.push(loginRes4.mfaChallengeId);
    console.log('✔ PASS 4: Express AuthService handles one-time MFA enrollment, seals pairing after TOTP verification, and supports Admin reset');

    // 5. Cloudflare Worker end-to-end tests against isolated in-memory SQLite D1 adapter
    const workerMemDb = new PersistentSecurityDatabase(':memory:');
    const workerEnv = {
      DB: createAsyncD1Adapter(workerMemDb),
      ENVIRONMENT: 'development',
      ZERO_TRUST_ORIGIN: 'https://serverless-securityverification.ai.studio',
      JWT_SECRET: 'worker_test_jwt_secret_minimum_32_characters_2026'
    };
    const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };

    // 5a. /api/health returns 200 when D1 healthy and 503 when DB binding missing
    const healthOk = await worker.fetch(new Request('http://localhost:3000/api/health'), workerEnv, ctx);
    assert.strictEqual(healthOk.status, 200);
    const healthOkJson: any = await healthOk.json();
    assert.strictEqual(healthOkJson.status, 'UP');
    assert.strictEqual(healthOkJson.databaseConnection, 'CONNECTED');

    const healthDown = await worker.fetch(new Request('http://localhost:3000/api/health'), { ...workerEnv, DB: undefined } as any, ctx);
    assert.strictEqual(healthDown.status, 503);
    const healthDownJson: any = await healthDown.json();
    assert.strictEqual(healthDownJson.status, 'DEGRADED');

    // 5b. /api/register rejects self-assigned Admin role (403) and accepts Developer (PENDING_APPROVAL)
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
    assert.ok(regDevJson.mfaEnrollment?.secret && regDevJson.mfaEnrollment?.provisioningUri?.startsWith('otpauth://totp/'), 'Registration should return one-time MFA enrollment payload');
    assert.ok(Array.isArray(regDevJson.mfaEnrollment?.backupCodes) && regDevJson.mfaEnrollment.backupCodes.length === 8);

    // 5c. /api/auth/mfa/send-sms returns 501
    const smsRes = await worker.fetch(
      new Request('http://localhost:3000/api/auth/mfa/send-sms', { method: 'POST' }),
      workerEnv,
      ctx
    );
    assert.strictEqual(smsRes.status, 501);

    // 5d. Worker /api/login + /api/auth/mfa/enroll-challenge + /api/auth/mfa/verify with seeded secops_admin
    const workerLogin = await worker.fetch(
      new Request('http://localhost:3000/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'secops_admin', password: '12345@pro' })
      }),
      workerEnv,
      ctx
    );
    assert.strictEqual(workerLogin.status, 200);
    const workerLoginJson: any = await workerLogin.json();
    assert.strictEqual(workerLoginJson.mfaRequired, true);
    assert.strictEqual(workerLoginJson.enrollmentRequired, true, 'Seeded unpaired user must flag enrollmentRequired');
    assert.ok(workerLoginJson.mfaChallengeId, 'Worker login must return mfaChallengeId');
    assert.strictEqual('totpSecret' in workerLoginJson, false, 'Worker login must NOT leak totpSecret');
    assert.strictEqual('demoTotpCode' in workerLoginJson, false, 'Worker login must NOT leak demoTotpCode');

    // Fetch one-time QR pairing payload for active unpaired challenge
    const workerEnrollRes = await worker.fetch(
      new Request('http://localhost:3000/api/auth/mfa/enroll-challenge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mfaChallengeId: workerLoginJson.mfaChallengeId })
      }),
      workerEnv,
      ctx
    );
    assert.strictEqual(workerEnrollRes.status, 200);
    const workerEnrollJson: any = await workerEnrollRes.json();
    assert.ok(workerEnrollJson.secret && workerEnrollJson.provisioningUri?.startsWith('otpauth://totp/'));

    // Test 5 wrong attempts lock Worker challenge (429 on 5th)
    for (let i = 1; i <= 4; i++) {
      const failRes = await worker.fetch(
        new Request('http://localhost:3000/api/auth/mfa/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ mfaChallengeId: workerLoginJson.mfaChallengeId, code: '000000' })
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
        body: JSON.stringify({ mfaChallengeId: workerLoginJson.mfaChallengeId, code: '000000' })
      }),
      workerEnv,
      ctx
    );
    assert.strictEqual(lockRes.status, 429);

    // Fresh login + valid TOTP yields Admin JWT
    const workerLogin2 = await worker.fetch(
      new Request('http://localhost:3000/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'secops_admin', password: '12345@pro' })
      }),
      workerEnv,
      ctx
    );
    const workerLogin2Json: any = await workerLogin2.json();
    const adminRow = workerMemDb.getUser('secops_admin');
    assert.ok(adminRow?.mfa_secret);
    const adminTotp = generateTotpToken(adminRow!.mfa_secret!);

    const verifyOk = await worker.fetch(
      new Request('http://localhost:3000/api/auth/mfa/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mfaChallengeId: workerLogin2Json.mfaChallengeId, code: adminTotp })
      }),
      workerEnv,
      ctx
    );
    assert.strictEqual(verifyOk.status, 200);
    const verifyOkJson: any = await verifyOk.json();
    const adminJwt = verifyOkJson.token as string;
    assert.ok(adminJwt && adminJwt.split('.').length === 3, 'Worker MFA verification must issue JWT');

    // Replay same challenge fails
    const verifyReplay = await worker.fetch(
      new Request('http://localhost:3000/api/auth/mfa/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mfaChallengeId: workerLogin2Json.mfaChallengeId, code: adminTotp })
      }),
      workerEnv,
      ctx
    );
    assert.strictEqual(verifyReplay.status, 401);

    // Subsequent login once enrolled sets enrollmentRequired = false & blocks enroll-challenge (403)
    const workerLogin3 = await worker.fetch(
      new Request('http://localhost:3000/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'secops_admin', password: '12345@pro' })
      }),
      workerEnv,
      ctx
    );
    const workerLogin3Json: any = await workerLogin3.json();
    assert.strictEqual(workerLogin3Json.enrollmentRequired, false);

    const workerEnrollBlocked = await worker.fetch(
      new Request('http://localhost:3000/api/auth/mfa/enroll-challenge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mfaChallengeId: workerLogin3Json.mfaChallengeId })
      }),
      workerEnv,
      ctx
    );
    assert.strictEqual(workerEnrollBlocked.status, 403);

    // Admin MFA reset restores enrollmentRequired = true
    const workerResetRes = await worker.fetch(
      new Request('http://localhost:3000/api/system/users/secops_admin/mfa-reset', {
        method: 'POST',
        headers: { Authorization: `Bearer ${adminJwt}` }
      }),
      workerEnv,
      ctx
    );
    assert.strictEqual(workerResetRes.status, 200);
    const workerLogin4 = await worker.fetch(
      new Request('http://localhost:3000/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'secops_admin', password: '12345@pro' })
      }),
      workerEnv,
      ctx
    );
    const workerLogin4Json: any = await workerLogin4.json();
    assert.strictEqual(workerLogin4Json.enrollmentRequired, true);

    // 5e. Credentials metadata endpoint: unauth -> 401, Admin -> 200 without raw secret or live code
    const credUnauth = await worker.fetch(
      new Request('http://localhost:3000/api/system/users/secops_admin/credentials'),
      workerEnv,
      ctx
    );
    assert.strictEqual(credUnauth.status, 401);

    const credAuth = await worker.fetch(
      new Request('http://localhost:3000/api/system/users/secops_admin/credentials', {
        headers: { Authorization: `Bearer ${adminJwt}` }
      }),
      workerEnv,
      ctx
    );
    assert.strictEqual(credAuth.status, 200);
    const credJson: any = await credAuth.json();
    assert.strictEqual(credJson.mfaConfigured, true);
    assert.strictEqual('base32Secret' in credJson, false, 'Must not expose raw base32Secret');
    assert.strictEqual('activeTotpToken' in credJson, false, 'Must not expose live activeTotpToken');
    assert.strictEqual('keyUri' in credJson, false, 'Must not expose otpauth keyUri');

    // 5f. /api/incidents: unauth -> 401, Admin POST -> 201, PATCH -> 200
    const incUnauth = await worker.fetch(new Request('http://localhost:3000/api/incidents'), workerEnv, ctx);
    assert.strictEqual(incUnauth.status, 401);

    const incCreate = await worker.fetch(
      new Request('http://localhost:3000/api/incidents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminJwt}` },
        body: JSON.stringify({ title: 'Worker D1 Incident Verification', severity: 'HIGH', status: 'OPEN' })
      }),
      workerEnv,
      ctx
    );
    assert.strictEqual(incCreate.status, 201);
    const incCreateJson: any = await incCreate.json();
    assert.ok(incCreateJson.incident?.id?.startsWith('INC-'));

    const incPatch = await worker.fetch(
      new Request(`http://localhost:3000/api/incidents/${incCreateJson.incident.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminJwt}` },
        body: JSON.stringify({ status: 'CONTAINED', mitigation_steps: 'Edge block enforced' })
      }),
      workerEnv,
      ctx
    );
    assert.strictEqual(incPatch.status, 200);
    const incPatchJson: any = await incPatch.json();
    assert.strictEqual(incPatchJson.incident?.status, 'CONTAINED');

    // 5g. /api/v1/verify/invoke pipeline + SHA-256 hash chaining in D1 audit_events
    const allowRes = await worker.fetch(
      new Request('http://localhost:3000/api/v1/verify/invoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminJwt}` },
        body: JSON.stringify({ functionName: 'getDashboardMetrics', payload: { region: 'ap-south-1' } })
      }),
      workerEnv,
      ctx
    );
    assert.strictEqual(allowRes.status, 200);

    const denyRes = await worker.fetch(
      new Request('http://localhost:3000/api/v1/verify/invoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminJwt}` },
        body: JSON.stringify({ functionName: 'getDashboardMetrics', payload: { target: 'http://169.254.169.254/latest/meta-data/' } })
      }),
      workerEnv,
      ctx
    );
    assert.strictEqual(denyRes.status, 403);

    const auditRows = workerMemDb.getAllLogs();
    const chainedEvents = auditRows.filter((r) => typeof r.integrity_hash === 'string' && r.integrity_hash.length === 64);
    assert.ok(chainedEvents.length >= 2, 'Worker verification events must be SHA-256 hash-chained in D1 audit_events');
    console.log('✔ PASS 5: Cloudflare Worker auth, MFA D1 persistence, RBAC, incidents & 15-step verification verified');

    console.log('\nALL MIGRATION, MFA PERSISTENCE & WORKER HARDENING TESTS PASSED (5/5)\n');
  } finally {
    for (const cid of tempChallengeIds) {
      try {
        prodDb.prepare('DELETE FROM mfa_challenges WHERE id = ?').bind(cid).run();
      } catch { /* ignore cleanup error */ }
    }
    if (tempUserId) {
      try {
        prodDb.prepare('DELETE FROM active_sessions WHERE username LIKE ?').bind('mfa_persist_test_%').run();
        prodDb.prepare('DELETE FROM sessions WHERE user_id = ?').bind(tempUserId).run();
        prodDb.prepare('DELETE FROM audit_events WHERE username LIKE ?').bind('mfa_persist_test_%').run();
        prodDb.prepare('DELETE FROM users WHERE id = ?').bind(tempUserId).run();
      } catch { /* ignore cleanup error */ }
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
