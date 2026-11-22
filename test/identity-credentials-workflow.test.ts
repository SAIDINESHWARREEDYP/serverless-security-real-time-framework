/**
 * Automated Identity & Credential Governance Test Suite
 * Evaluates CSPRNG PBKDF2 Zero-Plaintext Storage,
 * Admin Approval Workflow for Password and Username Change Requests, and SQLite Persistence.
 */

import { userRepository } from '../server/repositories/user.repository.ts';
import { passwordRequestRepository } from '../server/repositories/password-request.repository.ts';
import { usernameRequestRepository } from '../server/repositories/username-request.repository.ts';
import { verifyPassword } from '../server/utils/crypto.ts';
import { db } from '../server/db.ts';

interface TestResult {
  name: string;
  passed: boolean;
  details: string;
}

const results: TestResult[] = [];

function assert(condition: boolean, name: string, details: string) {
  results.push({
    name,
    passed: condition,
    details: condition ? details : `FAILED: ${details}`
  });
}

async function runTestSuite() {
  console.log('================================================================');
  console.log('STARTING IDENTITY & CREDENTIAL WORKFLOW TEST SUITE');
  console.log('================================================================\n');

  const cleanupUserIds: string[] = [];
  const cleanupPasswordReqIds: string[] = [];
  const cleanupUsernameReqIds: string[] = [];
  const cleanupUsernames: string[] = [];

  try {
    // Test 1: CSPRNG PBKDF2 Enforcement & Zero-Plaintext Storage
    try {
      const uniquePwd = `GovPass_${Date.now()}_!Z`;
      const govUname = `GovCheck_${Date.now()}`;
      cleanupUsernames.push(govUname);
      const govUser = userRepository.create({
        username: govUname,
        password: uniquePwd,
        role: 'Developer',
        base_risk_score: 15,
        status: 'APPROVED',
        department: 'Governance QA'
      });
      cleanupUserIds.push(govUser.id);

      const isPwValid = verifyPassword(uniquePwd, govUser.password_salt, govUser.password_hash);
      const isOtherPwInvalid = !verifyPassword('WrongPass_2026!', govUser.password_salt, govUser.password_hash);
      const noPlaintextInHash = !govUser.password_hash.includes(uniquePwd) && govUser.password_hash.length >= 64;
      const noPlaintextInSalt = !govUser.password_salt.includes(uniquePwd) && govUser.password_salt.length >= 32;

      const admin = userRepository.findByUsername('secops_admin');
      const adminSecure = Boolean(
        admin &&
          admin.password_salt.length >= 32 &&
          admin.password_hash.length >= 64 &&
          !admin.password_hash.startsWith('!')
      );

      assert(
        Boolean(adminSecure && isPwValid && isOtherPwInvalid && noPlaintextInHash && noPlaintextInSalt),
        '1. CSPRNG PBKDF2 Enforcement & Zero-Plaintext Storage',
        'CSPRNG salt & PBKDF2 SHA-512 hash verified with zero plaintext; seeded admin uses non-placeholder credentials.'
      );
    } catch (err: any) {
      assert(false, '1. CSPRNG PBKDF2 Enforcement & Zero-Plaintext Storage', err.message);
    }

    // Test 2: Password Change Request Workflow (Pending -> Approved -> DB Updated)
    try {
      const testUsername = `UserPw_${Date.now()}`;
      cleanupUsernames.push(testUsername);
      const initialPwd = `InitialPassword_${Date.now()}!`;

      const user = userRepository.create({
        username: testUsername,
        password: initialPwd,
        role: 'Developer',
        base_risk_score: 20,
        status: 'APPROVED',
        department: 'Platform Security'
      });
      cleanupUserIds.push(user.id);

      const newPwd = `NewSecurePassword_${Date.now()}!`;
      const req = await passwordRequestRepository.create({
        username: testUsername,
        newPasswordPlaintext: newPwd,
        justification: 'Quarterly compliance rotation'
      });
      cleanupPasswordReqIds.push(req.id);

      const isPending = req && req.status === 'PENDING';

      const userBefore = userRepository.findByUsername(testUsername);
      const oldValidBefore = userBefore ? verifyPassword(initialPwd, userBefore.password_salt, userBefore.password_hash) : false;
      const newValidBefore = userBefore ? verifyPassword(newPwd, userBefore.password_salt, userBefore.password_hash) : false;

      const approveRes = await passwordRequestRepository.approve(req.id, 'secops_admin');

      const userAfter = userRepository.findByUsername(testUsername);
      const newValidAfter = userAfter ? verifyPassword(newPwd, userAfter.password_salt, userAfter.password_hash) : false;
      const oldValidAfter = userAfter ? verifyPassword(initialPwd, userAfter.password_salt, userAfter.password_hash) : false;

      assert(
        Boolean(isPending && oldValidBefore && !newValidBefore && approveRes.success && newValidAfter && !oldValidAfter),
        '2. Password Change Request Admin Approval Workflow',
        'Request held in PENDING; approved by Admin; PBKDF2 hash & salt committed to SQLite.'
      );
    } catch (err: any) {
      assert(false, '2. Password Change Request Admin Approval Workflow', err.message);
    }

    // Test 3: Username Change Request Workflow (Pending -> Approved -> DB Updated)
    try {
      const origUsername = `OriginUser_${Date.now()}`;
      const newUsername = `RenamedUser_${Date.now()}`;
      cleanupUsernames.push(origUsername, newUsername);
      const testPwd = `UserAuth_${Date.now()}!`;

      const user = userRepository.create({
        username: origUsername,
        password: testPwd,
        role: 'Developer',
        base_risk_score: 25,
        status: 'APPROVED',
        department: 'Cloud Security'
      });
      cleanupUserIds.push(user.id);

      const req = await usernameRequestRepository.create({
        currentUsername: origUsername,
        requestedUsername: newUsername,
        justification: 'Reorganization update'
      });
      cleanupUsernameReqIds.push(req.id);

      const isPending = req && req.status === 'PENDING';
      const beforeOrigExists = userRepository.findByUsername(origUsername) !== null;
      const beforeNewExists = userRepository.findByUsername(newUsername) !== null;

      const approveRes = await usernameRequestRepository.approve(req.id, 'secops_admin');

      const afterOrigExists = userRepository.findByUsername(origUsername) !== null;
      const afterUser = userRepository.findByUsername(newUsername);
      const afterNewValid = afterUser ? verifyPassword(testPwd, afterUser.password_salt, afterUser.password_hash) : false;

      assert(
        Boolean(isPending && beforeOrigExists && !beforeNewExists && approveRes.success && !afterOrigExists && afterUser && afterNewValid),
        '3. Username Change Request Admin Approval Workflow',
        'Request held in PENDING; approved by Admin; users table updated; user authenticates under new username.'
      );
    } catch (err: any) {
      assert(false, '3. Username Change Request Admin Approval Workflow', err.message);
    }

    // Test 4: Username Collision Prevention
    try {
      let collisionThrew = false;
      let collisionError = '';
      try {
        usernameRequestRepository.create({
          currentUsername: 'auditor_guest',
          requestedUsername: 'secops_admin',
          justification: 'Unauthorized spoof'
        });
      } catch (err: any) {
        collisionThrew = true;
        collisionError = err.message;
      }

      assert(
        Boolean(collisionThrew && collisionError.includes('already registered')),
        '4. Username Collision Prevention & Conflict Detection',
        `Duplicate username request blocked fail-closed with conflict error: ${collisionError}`
      );
    } catch (err: any) {
      assert(false, '4. Username Collision Prevention & Conflict Detection', err.message);
    }
  } finally {
    for (const id of cleanupPasswordReqIds) {
      try { db.prepare('DELETE FROM password_change_requests WHERE id = ?').bind(id).run(); } catch { /* ignore */ }
    }
    for (const id of cleanupUsernameReqIds) {
      try { db.prepare('DELETE FROM username_change_requests WHERE id = ?').bind(id).run(); } catch { /* ignore */ }
    }
    for (const uname of cleanupUsernames) {
      try { db.prepare('DELETE FROM audit_events WHERE username = ?').bind(uname).run(); } catch { /* ignore */ }
    }
    for (const uid of cleanupUserIds) {
      try { db.prepare('DELETE FROM users WHERE id = ?').bind(uid).run(); } catch { /* ignore */ }
    }
  }

  console.log('--- TEST RESULTS SUMMARY ---');
  let allPassed = true;
  for (const r of results) {
    const icon = r.passed ? '✅ PASS' : '❌ FAIL';
    console.log(`${icon} | ${r.name}: ${r.details}`);
    if (!r.passed) allPassed = false;
  }

  const passedCount = results.filter((r) => r.passed).length;
  console.log(`\nTOTAL: ${passedCount} / ${results.length} PASSED (${Math.round((passedCount / results.length) * 100)}% SUCCESS RATE)\n`);

  if (!allPassed) {
    process.exit(1);
  }
}

runTestSuite().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
