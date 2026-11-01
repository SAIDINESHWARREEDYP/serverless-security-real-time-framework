# Role-Based Access Control (RBAC) & Identity Governance

## 1. Principles of Access Control
The framework enforces **Principle of Least Privilege (PoLP)** and **Separation of Duties (SoD)** through a centralized, server-side authorization service (`rbacRepository` and `authorizeMiddleware`). Navigational restrictions on the frontend are treated as UX guidance; access control is verified unconditionally on the backend.

---

## 2. Six Canonical Clearance Roles

| Role Name | Clearance Tier | System Role | Operational Domain & Entitlements |
|---|:---:|:---:|---|
| **Super Administrator** | **Tier 6** | `true` | Root authority: Master KMS rotation, architecture mutation, schema definitions, and user deactivation. |
| **Security Administrator** | **Tier 5** | `true` | SecOps operations: Registration approvals, real-time session revocation, risk threshold tuning, emergency lockdown. |
| **Security Analyst** | **Tier 4** | `true` | Threat triage: AI Threat Sentinel analysis, incident containment updates, forensic inspection. |
| **Developer** | **Tier 3** | `true` | Engineering sandbox: Serverless function invocation, worker bundle deployment, debug telemetry. |
| **Auditor** | **Tier 2** | `true` | Regulatory compliance: Read-only access to immutable audit ledger, certified ISO/SOC-2 export generation. |
| **Viewer** | **Tier 1** | `true` | Public observer: Baseline operational metrics and edge cluster health probers. |

---

## 3. Twenty-One Granular Permissions Catalog

| Category | Permission Code | Description |
|---|---|---|
| **IDENTITY** | `users:read` | Inspect user directory and clearance profiles |
| **IDENTITY** | `users:create` | Provision new principals into database |
| **IDENTITY** | `users:update` | Update user departments, email, or metadata |
| **IDENTITY** | `users:delete` | Remove or deactivate identity accounts |
| **IDENTITY** | `users:approve` | Approve or reject zero-trust registrations |
| **IDENTITY** | `roles:read` | Inspect role specifications and clearance tiers |
| **IDENTITY** | `roles:assign` | Assign or promote roles to principals |
| **IDENTITY** | `permissions:read` | Inspect granular permissions matrix |
| **IDENTITY** | `permissions:modify` | Reconfigure role-permission mappings |
| **POLICY** | `policies:read` | View active risk cutoffs and Markov rules |
| **POLICY** | `policies:write` | Mutate risk thresholds, penalties, and lockdown |
| **EXECUTION** | `functions:invoke` | Execute verified serverless operational endpoints |
| **EXECUTION** | `functions:read` | Inspect function catalog and state machines |
| **EXECUTION** | `functions:deploy` | Deploy serverless worker bundles to global edge |
| **SECURITY** | `sessions:read` | Inspect active D1 database sessions and tokens |
| **SECURITY** | `sessions:revoke` | Terminate active JWT sessions in D1 registry |
| **SECURITY** | `threats:scan` | Execute real-time multi-vector threat scans |
| **SECURITY** | `keys:rotate` | Rotate KMS master encryption keys at edge |
| **SECURITY** | `security_matrix:view`| View cloud blueprint and schema matrix |
| **TELEMETRY** | `audit:read` | Query immutable SHA-256 audit ledger events |
| **TELEMETRY** | `audit:export` | Export certified ISO 27001 / SOC 2 reports |

---

## 4. Privilege Escalation Defenses

1. **Anti-Self-Escalation Guard**:  
   In `rbac.repository.ts`, any attempt by an authenticated principal to alter their own role or elevate their own clearance is blocked by an explicit integrity constraint:
   ```typescript
   if (actorUsername.toLowerCase() === targetUsername.toLowerCase()) {
     recordAccessDenied(..., 'SELF_PRIVILEGE_ESCALATION');
     return { success: false, error: 'Self-grant privilege escalation is strictly prohibited by Zero-Trust policy.' };
   }
   ```
2. **Super Admin Tier Barrier**:  
   Only an existing Super Administrator may promote a principal to the Super Administrator tier. Attempts by Security Administrators or below are intercepted and recorded in the access-denied history.
3. **Immutable Permission Change Audit**:  
   Every role mutation records an audit entry in `permission_change_history` containing `target_user`, `previous_role`, `new_role`, `changed_by`, `reason`, `ip_address`, and `timestamp`.
4. **Access-Denied Forensic Ledger**:  
   All blocked authorization probes, missing permission attempts, and unauthorized administrative actions are recorded in `access_denied_history`.
