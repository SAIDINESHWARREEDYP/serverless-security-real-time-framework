import assert from 'assert';
import { rbacRepository } from '../server/repositories/rbac.repository.ts';

console.log('=== RUNNING PHASE 5 RBAC SECURITY & AUTHORIZATION TESTS ===\n');

// 1. Verify 6 Canonical Roles Exist
const roles = rbacRepository.getRoles();
assert.strictEqual(roles.length, 6, 'Must define exactly 6 canonical roles');
const roleNames = roles.map(r => r.name);
assert(roleNames.includes('Super Administrator'), 'Super Administrator role required');
assert(roleNames.includes('Security Administrator'), 'Security Administrator role required');
assert(roleNames.includes('Security Analyst'), 'Security Analyst role required');
assert(roleNames.includes('Developer'), 'Developer role required');
assert(roleNames.includes('Auditor'), 'Auditor role required');
assert(roleNames.includes('Viewer'), 'Viewer role required');
console.log('✔ PASS: 6 Canonical Roles successfully loaded');

// 2. Verify 21 Granular Permissions Catalog
const perms = rbacRepository.getPermissions();
assert.strictEqual(perms.length, 21, 'Must define exactly 21 granular permissions');
console.log(`✔ PASS: 21 Granular permissions defined across 5 security categories`);

// 3. Test Super Administrator has full permissions
assert(rbacRepository.hasPermission('Super Administrator', 'users:delete'), 'Super Admin can delete users');
assert(rbacRepository.hasPermission('Super Administrator', 'keys:rotate'), 'Super Admin can rotate KMS keys');
assert(rbacRepository.hasPermission('Super Administrator', 'policies:write'), 'Super Admin can write policies');
console.log('✔ PASS: Super Administrator has comprehensive permissions');

// 4. Test Developer cannot mutate policies or revoke sessions
assert(rbacRepository.hasPermission('Developer', 'functions:invoke'), 'Developer can invoke functions');
assert(!rbacRepository.hasPermission('Developer', 'policies:write'), 'Developer cannot mutate policies');
assert(!rbacRepository.hasPermission('Developer', 'sessions:revoke'), 'Developer cannot revoke sessions');
console.log('✔ PASS: Developer restricted from policy and session modification');

// 5. Test Auditor is read-only
assert(rbacRepository.hasPermission('Auditor', 'audit:read'), 'Auditor can read audit ledger');
assert(rbacRepository.hasPermission('Auditor', 'audit:export'), 'Auditor can export compliance reports');
assert(!rbacRepository.hasPermission('Auditor', 'functions:invoke'), 'Auditor cannot execute functions');
assert(!rbacRepository.hasPermission('Auditor', 'policies:write'), 'Auditor cannot mutate policies');
console.log('✔ PASS: Auditor restricted to read-only compliance operations');

// 6. Test Viewer has minimal read access
assert(rbacRepository.hasPermission('Viewer', 'audit:read'), 'Viewer can read baseline audit log');
assert(!rbacRepository.hasPermission('Viewer', 'users:read'), 'Viewer cannot read full user roster');
assert(!rbacRepository.hasPermission('Viewer', 'functions:invoke'), 'Viewer cannot execute operational endpoints');
console.log('✔ PASS: Viewer restricted to baseline public read');

// 7. Test Self-Privilege Escalation Prevention
const selfEscalationResult = rbacRepository.assignUserRole({
  targetUsername: 'cloud_dev',
  newRole: 'Super Administrator',
  previousRole: 'Developer',
  actorUsername: 'cloud_dev',
  actorRole: 'Developer',
  reason: 'Attempting self-promotion'
});
assert.strictEqual(selfEscalationResult.success, false, 'Self-privilege escalation must fail');
console.log('✔ PASS: Self-privilege escalation blocked by Zero-Trust policy');

// 8. Test Non-Super Admin Promoting to Super Administrator Prevention
const unauthorizedPromotionResult = rbacRepository.assignUserRole({
  targetUsername: 'cloud_dev',
  newRole: 'Super Administrator',
  previousRole: 'Developer',
  actorUsername: 'sec_admin_john',
  actorRole: 'Security Administrator',
  reason: 'Promoting peer'
});
assert.strictEqual(unauthorizedPromotionResult.success, false, 'Security Admin cannot grant Super Admin');
console.log('✔ PASS: Non-Super Administrator cannot grant Super Administrator clearance');

// 9. Test Authorized Role Assignment with Audit Logging
const validAssignmentResult = rbacRepository.assignUserRole({
  targetUsername: 'cloud_dev',
  newRole: 'Security Analyst',
  previousRole: 'Developer',
  actorUsername: 'secops_admin',
  actorRole: 'Super Administrator',
  reason: 'Clearance elevation following certification'
});
assert.strictEqual(validAssignmentResult.success, true, 'Authorized promotion must succeed');
const history = rbacRepository.getPermissionChangeHistory();
assert(history.some(h => h.target_user === 'cloud_dev' && h.new_role === 'Security Analyst'), 'Must record audit log');
console.log('✔ PASS: Authorized role assignment succeeded and recorded in permission change history');

// 10. Verify Access Denied Audit Record Creation
const deniedLogs = rbacRepository.getAccessDeniedHistory();
assert(deniedLogs.length >= 2, 'Denied attempts must be recorded in access-denied history');
console.log(`✔ PASS: Access-denied history actively recorded (${deniedLogs.length} events logged)`);

console.log('\n=== ALL PHASE 5 RBAC SECURITY TESTS PASSED (10/10) ===');
