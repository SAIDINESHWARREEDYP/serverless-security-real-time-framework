/**
 * RBAC Central Authorization Repository
 * Implements 6 Canonical Roles, 21 Granular Permissions, Role-Permission Matrix,
 * User-Role assignment, change history ledger, and access-denied logging.
 */

export interface RoleEntity {
  id: string;
  name: string;
  description: string;
  is_system_role: boolean;
  clearance_tier: number;
  created_at: string;
}

export interface PermissionEntity {
  id: string;
  name: string;
  resource: string;
  action: string;
  description: string;
  category: 'IDENTITY' | 'POLICY' | 'EXECUTION' | 'TELEMETRY' | 'SECURITY';
}

export interface PermissionChangeLog {
  id: string;
  target_user: string;
  previous_role: string;
  new_role: string;
  changed_by: string;
  reason: string;
  timestamp: string;
  ip_address?: string;
}

export interface AccessDeniedLog {
  id: string;
  username: string;
  role: string;
  endpoint: string;
  required_permission: string;
  violation_type: 'MISSING_ROLE' | 'MISSING_PERMISSION' | 'SELF_PRIVILEGE_ESCALATION' | 'UNAUTHORIZED_PROVISIONING';
  ip_address?: string;
  timestamp: string;
}

const CANONICAL_ROLES: RoleEntity[] = [
  {
    id: 'role_super_admin',
    name: 'Super Administrator',
    description: 'Supreme authority: Full access to all security policies, root IAM, KMS master rotation & architecture.',
    is_system_role: true,
    clearance_tier: 6,
    created_at: '2026-09-01T08:00:00.000Z'
  },
  {
    id: 'role_sec_admin',
    name: 'Security Administrator',
    description: 'SecOps Command authority: User approvals, session revocation, policy threshold mutation, and emergency lockdown.',
    is_system_role: true,
    clearance_tier: 5,
    created_at: '2026-09-01T08:00:00.000Z'
  },
  {
    id: 'role_sec_analyst',
    name: 'Security Analyst',
    description: 'Threat detection, AI Sentinel investigation, telemetry analysis, and incident inspection.',
    is_system_role: true,
    clearance_tier: 4,
    created_at: '2026-09-01T08:00:00.000Z'
  },
  {
    id: 'role_developer',
    name: 'Developer',
    description: 'Serverless invocation testbed, worker code deployment, function telemetry, and mesh debugging.',
    is_system_role: true,
    clearance_tier: 3,
    created_at: '2026-09-01T08:00:00.000Z'
  },
  {
    id: 'role_auditor',
    name: 'Auditor',
    description: 'Zero-trust regulatory compliance, immutable audit ledger access, and certified report generation.',
    is_system_role: true,
    clearance_tier: 2,
    created_at: '2026-09-01T08:00:00.000Z'
  },
  {
    id: 'role_viewer',
    name: 'Viewer',
    description: 'Read-only gateway observer with baseline operational visibility into public edge metrics.',
    is_system_role: true,
    clearance_tier: 1,
    created_at: '2026-09-01T08:00:00.000Z'
  }
];

const PERMISSIONS: PermissionEntity[] = [
  // IDENTITY & ACCESS
  { id: 'perm_usr_read', name: 'users:read', resource: 'user', action: 'read', description: 'View user directory and identity profiles', category: 'IDENTITY' },
  { id: 'perm_usr_create', name: 'users:create', resource: 'user', action: 'create', description: 'Register or provision new principals', category: 'IDENTITY' },
  { id: 'perm_usr_update', name: 'users:update', resource: 'user', action: 'update', description: 'Update user profiles and departmental tags', category: 'IDENTITY' },
  { id: 'perm_usr_delete', name: 'users:delete', resource: 'user', action: 'delete', description: 'Delete or deactivate user accounts', category: 'IDENTITY' },
  { id: 'perm_usr_approve', name: 'users:approve', resource: 'user', action: 'approve', description: 'Approve or reject zero-trust identity registrations', category: 'IDENTITY' },

  // ROLES & ACCESS CONTROL
  { id: 'perm_rol_read', name: 'roles:read', resource: 'role', action: 'read', description: 'Inspect role specifications and assigned rights', category: 'IDENTITY' },
  { id: 'perm_rol_assign', name: 'roles:assign', resource: 'role', action: 'assign', description: 'Assign or reassign roles to principals', category: 'IDENTITY' },
  { id: 'perm_prm_read', name: 'permissions:read', resource: 'permission', action: 'read', description: 'View permissions matrix catalog', category: 'IDENTITY' },
  { id: 'perm_prm_modify', name: 'permissions:modify', resource: 'permission', action: 'modify', description: 'Reconfigure role permission mappings', category: 'IDENTITY' },

  // POLICIES & BOUNDARIES
  { id: 'perm_plc_read', name: 'policies:read', resource: 'policy', action: 'read', description: 'View risk thresholds and Markov sequence rules', category: 'POLICY' },
  { id: 'perm_plc_write', name: 'policies:write', resource: 'policy', action: 'write', description: 'Update risk cutoffs, sequence penalties, and lockdown', category: 'POLICY' },

  // FUNCTION EXECUTION & PIPELINE
  { id: 'perm_fnc_invoke', name: 'functions:invoke', resource: 'function', action: 'invoke', description: 'Execute verified serverless operational endpoints', category: 'EXECUTION' },
  { id: 'perm_fnc_read', name: 'functions:read', resource: 'function', action: 'read', description: 'Inspect function catalog and state machines', category: 'EXECUTION' },
  { id: 'perm_fnc_deploy', name: 'functions:deploy', resource: 'function', action: 'deploy', description: 'Deploy serverless worker bundles to global edge', category: 'EXECUTION' },

  // SESSIONS & REVOCATION
  { id: 'perm_ses_read', name: 'sessions:read', resource: 'session', action: 'read', description: 'Inspect active D1 database sessions and tokens', category: 'SECURITY' },
  { id: 'perm_ses_revoke', name: 'sessions:revoke', resource: 'session', action: 'revoke', description: 'Terminate and revoke active JWT sessions in D1', category: 'SECURITY' },

  // AUDIT & COMPLIANCE
  { id: 'perm_adt_read', name: 'audit:read', resource: 'audit', action: 'read', description: 'Query immutable SHA-256 audit ledger events', category: 'TELEMETRY' },
  { id: 'perm_adt_export', name: 'audit:export', resource: 'audit', action: 'export', description: 'Export certified ISO 27001 / SOC 2 compliance reports', category: 'TELEMETRY' },

  // THREATS & SECURITY INTELLIGENCE
  { id: 'perm_trt_scan', name: 'threats:scan', resource: 'threat', action: 'scan', description: 'Run real-time multi-vector AI threat inspection', category: 'SECURITY' },
  { id: 'perm_key_rotate', name: 'keys:rotate', resource: 'kms', action: 'rotate', description: 'Rotate KMS master encryption keys at edge', category: 'SECURITY' },
  { id: 'perm_mtx_view', name: 'security_matrix:view', resource: 'security_matrix', action: 'read', description: 'View cloud blueprint & schema matrix', category: 'SECURITY' }
];

const CANONICAL_ROLE_PERMISSIONS: Record<string, string[]> = {
  'Super Administrator': [
    'users:read', 'users:create', 'users:update', 'users:delete', 'users:approve',
    'roles:read', 'roles:assign', 'permissions:read', 'permissions:modify',
    'policies:read', 'policies:write',
    'functions:invoke', 'functions:read', 'functions:deploy',
    'sessions:read', 'sessions:revoke',
    'audit:read', 'audit:export',
    'threats:scan', 'keys:rotate', 'security_matrix:view'
  ],
  'Security Administrator': [
    'users:read', 'users:create', 'users:update', 'users:approve',
    'roles:read', 'roles:assign', 'permissions:read',
    'policies:read', 'policies:write',
    'functions:invoke', 'functions:read', 'functions:deploy',
    'sessions:read', 'sessions:revoke',
    'audit:read', 'audit:export',
    'threats:scan', 'keys:rotate', 'security_matrix:view'
  ],
  'Security Analyst': [
    'users:read', 'roles:read', 'permissions:read',
    'policies:read', 'functions:read', 'sessions:read',
    'audit:read', 'audit:export',
    'threats:scan', 'security_matrix:view'
  ],
  'Developer': [
    'functions:invoke', 'functions:read', 'functions:deploy',
    'audit:read', 'threats:scan'
  ],
  'Auditor': [
    'users:read', 'roles:read', 'permissions:read',
    'policies:read', 'functions:read', 'sessions:read',
    'audit:read', 'audit:export'
  ],
  'Viewer': [
    'functions:read', 'audit:read'
  ]
};

// Map legacy role aliases
const ROLE_ALIASES: Record<string, string> = {
  'Admin': 'Super Administrator',
  'Administrator': 'Super Administrator',
  'Guest': 'Viewer'
};

class RbacRepository {
  private rolePermissionsMap: Record<string, string[]> = { ...CANONICAL_ROLE_PERMISSIONS };
  private permissionChangeHistory: PermissionChangeLog[] = [
    {
      id: 'pch_seed_001',
      target_user: 'secops_admin',
      previous_role: 'Security Administrator',
      new_role: 'Super Administrator',
      changed_by: 'SYSTEM_BOOTSTRAP',
      reason: 'Root zero-trust authority initialization',
      timestamp: '2026-09-01T08:00:00.000Z'
    }
  ];

  private accessDeniedHistory: AccessDeniedLog[] = [
    {
      id: 'adh_seed_001',
      username: 'guest_user',
      role: 'Viewer',
      endpoint: '/api/v1/policies',
      required_permission: 'policies:write',
      violation_type: 'MISSING_PERMISSION',
      timestamp: new Date(Date.now() - 3600000).toISOString()
    }
  ];

  public getRoles(): RoleEntity[] {
    return [...CANONICAL_ROLES];
  }

  public getPermissions(): PermissionEntity[] {
    return [...PERMISSIONS];
  }

  public resolveCanonicalRole(role: string): string {
    return ROLE_ALIASES[role] || role;
  }

  public getPermissionsForRole(roleName: string): string[] {
    const canonical = this.resolveCanonicalRole(roleName);
    return this.rolePermissionsMap[canonical] || [];
  }

  public getMatrix(): Record<string, string[]> {
    return { ...this.rolePermissionsMap };
  }

  public hasPermission(roleName: string, permissionName: string): boolean {
    const perms = this.getPermissionsForRole(roleName);
    return perms.includes(permissionName) || perms.includes('*');
  }

  public hasAnyPermission(roleName: string, permissionNames: string[]): boolean {
    return permissionNames.some((p) => this.hasPermission(roleName, p));
  }

  public hasAllPermissions(roleName: string, permissionNames: string[]): boolean {
    return permissionNames.every((p) => this.hasPermission(roleName, p));
  }

  /**
   * Safe role assignment preventing:
   * 1. Self-privilege escalation (user changing own role to higher)
   * 2. Non-Super Admin assigning Super Administrator role
   * 3. IDOR escalation
   */
  public assignUserRole(params: {
    targetUsername: string;
    newRole: string;
    previousRole: string;
    actorUsername: string;
    actorRole: string;
    reason?: string;
    ipAddress?: string;
  }): { success: boolean; error?: string } {
    const canonicalNewRole = this.resolveCanonicalRole(params.newRole);
    const canonicalActorRole = this.resolveCanonicalRole(params.actorRole);

    // 1. Self-grant check
    if (params.targetUsername.toLowerCase() === params.actorUsername.toLowerCase()) {
      this.recordAccessDenied({
        username: params.actorUsername,
        role: params.actorRole,
        endpoint: '/api/v1/rbac/assign',
        required_permission: 'roles:assign',
        violation_type: 'SELF_PRIVILEGE_ESCALATION',
        ip_address: params.ipAddress
      });
      return { success: false, error: 'Self-grant privilege escalation is strictly prohibited by Zero-Trust policy.' };
    }

    // 2. Actor authority check
    if (canonicalActorRole !== 'Super Administrator' && canonicalActorRole !== 'Security Administrator') {
      this.recordAccessDenied({
        username: params.actorUsername,
        role: params.actorRole,
        endpoint: '/api/v1/rbac/assign',
        required_permission: 'roles:assign',
        violation_type: 'UNAUTHORIZED_PROVISIONING',
        ip_address: params.ipAddress
      });
      return { success: false, error: 'Unauthorized: Only Super Administrators and Security Administrators may assign roles.' };
    }

    // 3. Elevating to Super Administrator check
    if (canonicalNewRole === 'Super Administrator' && canonicalActorRole !== 'Super Administrator') {
      this.recordAccessDenied({
        username: params.actorUsername,
        role: params.actorRole,
        endpoint: '/api/v1/rbac/assign',
        required_permission: 'roles:assign',
        violation_type: 'SELF_PRIVILEGE_ESCALATION',
        ip_address: params.ipAddress
      });
      return { success: false, error: 'Unauthorized: Only an existing Super Administrator may promote a principal to Super Administrator.' };
    }

    // Record change history
    const changeEntry: PermissionChangeLog = {
      id: `pch_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
      target_user: params.targetUsername,
      previous_role: params.previousRole,
      new_role: canonicalNewRole,
      changed_by: params.actorUsername,
      reason: params.reason || 'Role clearance update via IAM Console',
      timestamp: new Date().toISOString(),
      ip_address: params.ipAddress
    };

    this.permissionChangeHistory.unshift(changeEntry);
    return { success: true };
  }

  public recordAccessDenied(event: Omit<AccessDeniedLog, 'id' | 'timestamp'>): void {
    const entry: AccessDeniedLog = {
      ...event,
      id: `adh_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
      timestamp: new Date().toISOString()
    };
    this.accessDeniedHistory.unshift(entry);
    if (this.accessDeniedHistory.length > 200) {
      this.accessDeniedHistory.pop();
    }
  }

  public getPermissionChangeHistory(): PermissionChangeLog[] {
    return [...this.permissionChangeHistory];
  }

  public getAccessDeniedHistory(): AccessDeniedLog[] {
    return [...this.accessDeniedHistory];
  }
}

export const rbacRepository = new RbacRepository();
