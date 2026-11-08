/**
 * Automated Identity & Credential Governance Test Suite
 * Evaluates Admin Password Enforcement (12345@pro), Zero-Plaintext Masking,
 * Admin Approval Workflow for Password and Username Change Requests, and Cloudflare D1/SQLite Persistence.
 */

import { userRepository } from '../server/repositories/user.repository.ts';
import { passwordRequestRepository } from '../server/repositories/password-request.repository.ts';
import { usernameRequestRepository } from '../server/repositories/username-request.repository.ts';
import { verifyPassword } from '../server/utils/crypto.ts';

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
  console.log('STARTING ADMIN CREDENTIALS & IDENTITY WORKFLOW TEST SUITE');
  console.log('================================================================\n');

  // Test 1: Admin Password is 12345@pro and Plaintext is Never Stored
  try {
    const admin = userRepository.findByUsername('secops_admin');
    const isPwValid = admin ? verifyPassword('12345@pro', admin.password_salt, admin.password_hash) : false;
    const isOtherPwInvalid = admin ? !verifyPassword('ZeroTrust_2026', admin.password_salt, admin.password_hash) : false;
    const noPlaintextInHash = admin ? !admin.password_hash.includes('12345@pro') : false;
    const noPlaintextInSalt = admin ? !admin.password_salt.includes('12345@pro') : false;

    assert(
      Boolean(admin && isPwValid && isOtherPwInvalid && noPlaintextInHash && noPlaintextInSalt),
      '1. Admin Password Enforcement & Zero-Plaintext Storage',
      'secops_admin password verified with 12345@pro; PBKDF2 hash & salt contain zero plaintext.'
    );
  } catch (err: any) {
    assert(false, '1. Admin Password Enforcement & Zero-Plaintext Storage', err.message);
  }

  // Test 2: Password Change Request Workflow (Pending -> Approved -> DB Updated)
  try {
    const testUsername = `UserPw_${Date.now()}`;
    const initialPwd = 'InitialPassword_2026!';

    const user = userRepository.create({
      username: testUsername,
      password: initialPwd,
      role: 'Developer',
      base_risk_score: 20,
      status: 'APPROVED',
      department: 'Platform Security'
    });

    const newPwd = 'NewSecurePassword_999!';
    const req = await passwordRequestRepository.create({
      username: testUsername,
      newPasswordPlaintext: newPwd,
      justification: 'Quarterly compliance rotation'
    });

    const isPending = req && req.status === 'PENDING';

    // Verify before approval: old password still valid, new password invalid
    const userBefore = userRepository.findByUsername(testUsername);
    const oldValidBefore = userBefore ? verifyPassword(initialPwd, userBefore.password_salt, userBefore.password_hash) : false;
    const newValidBefore = userBefore ? verifyPassword(newPwd, userBefore.password_salt, userBefore.password_hash) : false;

    // Approve
    const approveRes = await passwordRequestRepository.approve(req.id, 'secops_admin');

    // Verify after approval: new password valid, old password invalid
    const userAfter = userRepository.findByUsername(testUsername);
    const newValidAfter = userAfter ? verifyPassword(newPwd, userAfter.password_salt, userAfter.password_hash) : false;
    const oldValidAfter = userAfter ? verifyPassword(initialPwd, userAfter.password_salt, userAfter.password_hash) : false;

    assert(
      Boolean(isPending && oldValidBefore && !newValidBefore && approveRes.success && newValidAfter && !oldValidAfter),
      '2. Password Change Request Admin Approval Workflow',
      'Request held in PENDING; approved by Admin; PBKDF2 hash & salt committed to D1/SQLite.'
    );
  } catch (err: any) {
    assert(false, '2. Password Change Request Admin Approval Workflow', err.message);
  }

  // Test 3: Username Change Request Workflow (Pending -> Approved -> DB Updated)
  try {
    const origUsername = `OriginUser_${Date.now()}`;
    const newUsername = `RenamedUser_${Date.now()}`;
    const testPwd = 'UserAuth_2026!';

    const user = userRepository.create({
      username: origUsername,
      password: testPwd,
      role: 'Developer',
      base_risk_score: 25,
      status: 'APPROVED',
      department: 'Cloud Security'
    });

    // Submit username change request
    const req = await usernameRequestRepository.create({
      currentUsername: origUsername,
      requestedUsername: newUsername,
      justification: 'Reorganization update'
    });

    const isPending = req && req.status === 'PENDING';
    const beforeOrigExists = userRepository.findByUsername(origUsername) !== null;
    const beforeNewExists = userRepository.findByUsername(newUsername) !== null;

    // Approve
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
        requestedUsername: 'secops_admin', // duplicate
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
