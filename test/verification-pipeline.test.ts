import assert from 'assert';
import { verificationService } from '../server/services/verification.service.ts';
import { policyRepository } from '../server/repositories/policy.repository.ts';
import { auditRepository } from '../server/repositories/audit.repository.ts';
import { UserRecord } from '../server/types/index.ts';

console.log('=== RUNNING PHASE 6 SERVERLESS INVOCATION VERIFICATION ENGINE TESTS ===\n');

const authorizedAdmin: UserRecord = {
  id: 'usr_secops_admin',
  username: 'secops_admin',
  password_hash: 'hash',
  password_salt: 'salt',
  role: 'Super Administrator',
  base_risk_score: 5,
  status: 'APPROVED',
  mfa_enabled: true,
  created_at: new Date().toISOString()
};

const developerUser: UserRecord = {
  id: 'usr_cloud_dev',
  username: 'cloud_dev',
  password_hash: 'hash',
  password_salt: 'salt',
  role: 'Developer',
  base_risk_score: 15,
  status: 'APPROVED',
  mfa_enabled: true,
  created_at: new Date().toISOString()
};

const suspendedUser: UserRecord = {
  id: 'usr_suspended',
  username: 'suspended_user',
  password_hash: 'hash',
  password_salt: 'salt',
  role: 'Developer',
  base_risk_score: 25,
  status: 'SUSPENDED',
  mfa_enabled: false,
  created_at: new Date().toISOString()
};

// SCENARIO 1: Authorized caller with benign payload
const res1 = verificationService.execute15StepPipeline({
  requestId: 'req_test_01',
  targetFunction: 'getDashboardMetrics',
  payloadStr: JSON.stringify({ range: '1h' }),
  user: authorizedAdmin,
  token: 'jwt_valid',
  timerStart: performance.now()
});
assert.strictEqual(res1.decision, 'ALLOW', 'Scenario 1: Authorized caller must be ALLOWED');
assert.strictEqual(res1.steps.length, 15, 'Scenario 1: Must execute all 15 pipeline steps');
assert(res1.compositeRiskScore < 75, 'Scenario 1: Composite risk score must be within safe boundary');
console.log('✔ PASS Scenario 1: Authorized caller permitted with 15 verified steps');

// SCENARIO 2: Unauthenticated caller
const res2 = verificationService.execute15StepPipeline({
  requestId: 'req_test_02',
  targetFunction: 'getDashboardMetrics',
  payloadStr: JSON.stringify({ range: '1h' }),
  user: null,
  token: undefined,
  timerStart: performance.now()
});
assert.strictEqual(res2.decision, 'DENY', 'Scenario 2: Unauthenticated caller must be DENIED');
assert(res2.denialReasons.some(r => r.includes('Unauthenticated')), 'Scenario 2: Denial must cite unauthenticated caller');
console.log('✔ PASS Scenario 2: Unauthenticated caller denied at Step 2');

// SCENARIO 3: Invalid identity / missing token
const res3 = verificationService.execute15StepPipeline({
  requestId: 'req_test_03',
  targetFunction: 'getDashboardMetrics',
  payloadStr: JSON.stringify({ filter: 'all' }),
  user: developerUser,
  token: undefined, // Missing token
  timerStart: performance.now()
});
assert.strictEqual(res3.decision, 'DENY', 'Scenario 3: Missing token must be DENIED');
assert(res3.denialReasons.some(r => r.includes('Missing authorization token')), 'Scenario 3: Missing token cited');
console.log('✔ PASS Scenario 3: Missing token rejected at Step 3');

// SCENARIO 4: Missing permission (Viewer attempting policy mutation)
const viewerUser: UserRecord = {
  id: 'usr_viewer',
  username: 'viewer_guest',
  password_hash: 'hash',
  password_salt: 'salt',
  role: 'Viewer',
  base_risk_score: 10,
  status: 'APPROVED',
  mfa_enabled: false,
  created_at: new Date().toISOString()
};
const res4 = verificationService.execute15StepPipeline({
  requestId: 'req_test_04',
  targetFunction: 'updateSystemPolicy',
  payloadStr: JSON.stringify({ maxRiskThreshold: 50 }),
  user: viewerUser,
  token: 'jwt_valid',
  timerStart: performance.now()
});
assert.strictEqual(res4.decision, 'DENY', 'Scenario 4: Missing permission must be DENIED');
assert(res4.denialReasons.some(r => r.includes('unauthorized for function')), 'Scenario 4: Unauthorized cited');
console.log('✔ PASS Scenario 4: Missing permission rejected at Step 6');

// SCENARIO 5: Disabled or Non-existent function
const res5 = verificationService.execute15StepPipeline({
  requestId: 'req_test_05',
  targetFunction: 'nonExistentArbitraryEndpoint',
  payloadStr: JSON.stringify({ action: 'run' }),
  user: authorizedAdmin,
  token: 'jwt_valid',
  timerStart: performance.now()
});
assert.strictEqual(res5.decision, 'DENY', 'Scenario 5: Non-existent function must be DENIED');
assert(res5.denialReasons.some(r => r.includes('does not exist in catalog')), 'Scenario 5: Missing catalog entry cited');
console.log('✔ PASS Scenario 5: Non-existent function rejected at Step 5');

// SCENARIO 6: Inactive / Suspended account
const res6 = verificationService.execute15StepPipeline({
  requestId: 'req_test_06',
  targetFunction: 'getDashboardMetrics',
  payloadStr: JSON.stringify({ range: '24h' }),
  user: suspendedUser,
  token: 'jwt_valid',
  timerStart: performance.now()
});
assert.strictEqual(res6.decision, 'DENY', 'Scenario 6: Suspended account must be DENIED');
assert(res6.denialReasons.some(r => r.includes('SUSPENDED')), 'Scenario 6: Suspended status cited');
console.log('✔ PASS Scenario 6: Suspended account blocked at Step 4');

// SCENARIO 7: Malformed request payload
const res7 = verificationService.execute15StepPipeline({
  requestId: 'req_test_07',
  targetFunction: 'getDashboardMetrics',
  payloadStr: '{ "invalidJson": broken',
  user: authorizedAdmin,
  token: 'jwt_valid',
  timerStart: performance.now()
});
assert.strictEqual(res7.decision, 'DENY', 'Scenario 7: Malformed payload must be DENIED');
assert(res7.denialReasons.some(r => r.includes('Malformed payload syntax')), 'Scenario 7: Malformed syntax cited');
console.log('✔ PASS Scenario 7: Malformed payload syntax caught at Step 1');

// SCENARIO 8: Policy violation (Strict sequence drift)
policyRepository.updatePolicy({ enforceStrictSequence: true, sequenceViolationPenalty: 40, maxRiskThreshold: 75 });
// Seed prior function in audit ledger
auditRepository.record({
  username: developerUser.username,
  requested_function: 'deployWorkerCode',
  calculated_risk: 15,
  status: 'ALLOWED',
  reason: 'Initial deploy',
  verification_latency_ms: 0.25,
  event_type: 'STANDARD_VERIFICATION'
});
// Developer attempts invalid sequence: deployWorkerCode -> purgeColdStorageBackups
const res8 = verificationService.execute15StepPipeline({
  requestId: 'req_test_08',
  targetFunction: 'purgeColdStorageBackups',
  payloadStr: JSON.stringify({}),
  user: developerUser,
  token: 'jwt_valid',
  timerStart: performance.now()
});
assert.strictEqual(res8.decision, 'DENY', 'Scenario 8: Sequence drift exceeding cutoff must be DENIED');
assert(res8.penalties.sequence >= 40, 'Scenario 8: Sequence penalty must be applied');
console.log(`✔ PASS Scenario 8: Markov sequence violation triggered +${res8.penalties.sequence}% penalty`);

// SCENARIO 9: Suspicious invocation frequency / rate limit
const burstUser: UserRecord = {
  id: 'usr_burst',
  username: 'burst_tester',
  password_hash: 'hash',
  password_salt: 'salt',
  role: 'Developer',
  base_risk_score: 60,
  status: 'APPROVED',
  mfa_enabled: true,
  created_at: new Date().toISOString()
};
// Seed 12 requests in audit log within 60s
for (let i = 0; i < 12; i++) {
  auditRepository.record({
    username: 'burst_tester',
    requested_function: 'getDashboardMetrics',
    calculated_risk: 25,
    status: 'ALLOWED',
    reason: `Burst seed #${i}`,
    verification_latency_ms: 0.2,
    event_type: 'RATE_PROBE'
  });
}
const res9 = verificationService.execute15StepPipeline({
  requestId: 'req_test_09',
  targetFunction: 'getDashboardMetrics',
  payloadStr: JSON.stringify({}),
  user: burstUser,
  token: 'jwt_valid',
  timerStart: performance.now()
});
assert.strictEqual(res9.decision, 'DENY', 'Scenario 9: Rate-burst combined with elevated risk must be DENIED');
assert(res9.penalties.rate === 20, 'Scenario 9: +20% rate penalty must be applied');
console.log('✔ PASS Scenario 9: High frequency burst detected with rate penalty applied');

// SCENARIO 10: Multi-vector threat probe (IMDS SSRF Link-Local probe)
const res10 = verificationService.execute15StepPipeline({
  requestId: 'req_test_10',
  targetFunction: 'getDashboardMetrics',
  payloadStr: JSON.stringify({ url: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/' }),
  user: authorizedAdmin,
  token: 'jwt_valid',
  timerStart: performance.now()
});
assert.strictEqual(res10.decision, 'DENY', 'Scenario 10: IMDS SSRF probe must be immediately DENIED');
assert.strictEqual(res10.threatVector.threatDetected, true, 'Scenario 10: Threat must be flagged');
assert.strictEqual(res10.threatVector.threatCategory, 'CLOUD_METADATA_SSRF', 'Scenario 10: Correct SSRF categorization');
console.log('✔ PASS Scenario 10: Cloud Metadata IMDS SSRF intercepted with 95% penalty');

console.log('\n=== ALL PHASE 6 INVOCATION VERIFICATION SCENARIOS PASSED (10/10) ===');
