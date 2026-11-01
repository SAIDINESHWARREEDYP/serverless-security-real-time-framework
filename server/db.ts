/**
 * Database Engine mimicking Cloudflare D1 / SQLite for the Serverless Security Framework.
 * Implements the normalized 3NF schema tables: users, roles, permissions, user_roles,
 * role_permissions, functions, invocation_history, verification_results, security_alerts,
 * incidents, audit_events, sessions, and system_configuration.
 * Preserves backwards compatibility for existing controllers and frontends.
 */

export type UserApprovalStatus = 'APPROVED' | 'PENDING_APPROVAL' | 'REJECTED' | 'SUSPENDED';

export interface User {
  id: string;
  username: string;
  password_hash: string;
  role: 'Admin' | 'Developer' | 'Guest';
  base_risk_score: number;
  status: UserApprovalStatus;
  department?: string;
  email?: string;
  phone?: string;
  mfa_enabled?: boolean;
  createdAt?: string;
  approvedAt?: string;
  approvedBy?: string;
  lastLoginAt?: string;
  requestJustification?: string;
}

export interface Role {
  id: string;
  name: string;
  description: string;
  is_system_role: boolean;
  created_at: string;
  updated_at: string;
}

export interface Permission {
  id: string;
  name: string;
  resource: string;
  action: string;
  description: string;
  created_at: string;
}

export interface RolePermission {
  role_id: string;
  permission_id: string;
  assigned_at: string;
  assigned_by: string;
}

export interface UserRole {
  user_id: string;
  role_id: string;
  assigned_at: string;
  assigned_by: string;
}

export interface FunctionEntity {
  id: string;
  name: string;
  slug: string;
  service_name: string;
  runtime: string;
  max_memory_mb: number;
  timeout_seconds: number;
  is_active: boolean;
  required_permission_id?: string;
  created_at: string;
  updated_at: string;
}

export interface InvocationHistoryRecord {
  id: string;
  trace_id: string;
  parent_trace_id?: string;
  user_id?: string;
  function_id: string;
  source_ip: string;
  http_method: string;
  payload_size_bytes: number;
  payload_sha256: string;
  invoked_at: string;
}

export interface VerificationResultRecord {
  id: string;
  invocation_id: string;
  verdict: 'ALLOW' | 'DENY' | 'QUARANTINE';
  risk_score: number;
  verification_latency_ms: number;
  imds_probe_detected: boolean;
  prompt_injection_detected: boolean;
  sequence_deviation_detected: boolean;
  shell_injection_detected: boolean;
  token_signature_valid: boolean;
  session_active: boolean;
  rbac_granted: boolean;
  fail_closed_triggered: boolean;
  decision_reason: string;
  verified_at: string;
}

export interface SecurityAlertRecord {
  id: string;
  invocation_id?: string;
  alert_type: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  threat_vector: string;
  details_json: string;
  ip_address: string;
  user_id?: string;
  acknowledged_at?: string;
  acknowledged_by?: string;
  created_at: string;
}

export interface IncidentRecord {
  id: string;
  title: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  status: 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'FALSE_POSITIVE';
  root_cause?: string;
  mitigation_steps?: string;
  assigned_to?: string;
  created_at: string;
  resolved_at?: string;
  resolved_by?: string;
}

export interface SystemConfigRecord {
  config_key: string;
  config_value: string;
  description: string;
  data_type: 'string' | 'number' | 'boolean' | 'json';
  is_runtime_tunable: boolean;
  updated_at: string;
  updated_by: string;
}

export interface FunctionRule {
  id: number;
  current_function: string;
  allowed_next_function: string;
}

export interface SecurityAuditLog {
  id: number;
  timestamp: string;
  username: string;
  requested_function: string;
  calculated_risk: number;
  status: 'ALLOWED' | 'BLOCKED';
  reason: string;
  verification_latency_ms?: number;
  event_type?: string;
}

export type SecurityEvent = SecurityAuditLog;

export interface ActiveSession {
  id: string;
  token: string;
  username: string;
  role: 'Admin' | 'Developer' | 'Guest';
  createdAt: string;
  expiresAt: string;
  revoked: boolean;
  revokedAt?: string;
  revokedBy?: string;
  revocationReason?: string;
}

const INITIAL_ROLES: Role[] = [
  {
    id: 'role_admin',
    name: 'Administrator',
    description: 'Full system access, policy mutation, user management, and session revocation.',
    is_system_role: true,
    created_at: '2026-09-01T08:00:00.000Z',
    updated_at: '2026-09-01T08:00:00.000Z'
  },
  {
    id: 'role_dev',
    name: 'Developer',
    description: 'Read and execute serverless functions, inspect telemetry and invocation baselines.',
    is_system_role: true,
    created_at: '2026-09-01T08:00:00.000Z',
    updated_at: '2026-09-01T08:00:00.000Z'
  },
  {
    id: 'role_guest',
    name: 'Guest',
    description: 'Restricted evaluation role with read-only access to compliance reports.',
    is_system_role: true,
    created_at: '2026-09-01T08:00:00.000Z',
    updated_at: '2026-09-01T08:00:00.000Z'
  }
];

const INITIAL_PERMISSIONS: Permission[] = [
  { id: 'perm_fn_invoke', name: 'function:invoke', resource: 'function', action: 'invoke', description: 'Execute serverless function through verification gateway', created_at: '2026-09-01T08:00:00.000Z' },
  { id: 'perm_fn_read', name: 'function:read', resource: 'function', action: 'read', description: 'Inspect function configuration and schema specifications', created_at: '2026-09-01T08:00:00.000Z' },
  { id: 'perm_policy_write', name: 'policy:write', resource: 'policy', action: 'write', description: 'Mutate security policies, thresholds, and sequence rules', created_at: '2026-09-01T08:00:00.000Z' },
  { id: 'perm_session_revoke', name: 'session:revoke', resource: 'session', action: 'revoke', description: 'Revoke active user sessions in real-time D1 registry', created_at: '2026-09-01T08:00:00.000Z' },
  { id: 'perm_user_approve', name: 'user:approve', resource: 'user', action: 'approve', description: 'Approve or reject pending registration requests', created_at: '2026-09-01T08:00:00.000Z' },
  { id: 'perm_audit_read', name: 'audit:read', resource: 'audit', action: 'read', description: 'Query and export cryptographic audit log streams', created_at: '2026-09-01T08:00:00.000Z' },
  { id: 'perm_matrix_view', name: 'security_matrix:view', resource: 'security_matrix', action: 'read', description: 'View enterprise cloud blueprint and schema matrix', created_at: '2026-09-01T08:00:00.000Z' }
];

const INITIAL_ROLE_PERMISSIONS: RolePermission[] = [
  { role_id: 'role_admin', permission_id: 'perm_fn_invoke', assigned_at: '2026-09-01T08:00:00.000Z', assigned_by: 'SYSTEM' },
  { role_id: 'role_admin', permission_id: 'perm_fn_read', assigned_at: '2026-09-01T08:00:00.000Z', assigned_by: 'SYSTEM' },
  { role_id: 'role_admin', permission_id: 'perm_policy_write', assigned_at: '2026-09-01T08:00:00.000Z', assigned_by: 'SYSTEM' },
  { role_id: 'role_admin', permission_id: 'perm_session_revoke', assigned_at: '2026-09-01T08:00:00.000Z', assigned_by: 'SYSTEM' },
  { role_id: 'role_admin', permission_id: 'perm_user_approve', assigned_at: '2026-09-01T08:00:00.000Z', assigned_by: 'SYSTEM' },
  { role_id: 'role_admin', permission_id: 'perm_audit_read', assigned_at: '2026-09-01T08:00:00.000Z', assigned_by: 'SYSTEM' },
  { role_id: 'role_admin', permission_id: 'perm_matrix_view', assigned_at: '2026-09-01T08:00:00.000Z', assigned_by: 'SYSTEM' },
  { role_id: 'role_dev', permission_id: 'perm_fn_invoke', assigned_at: '2026-09-01T08:00:00.000Z', assigned_by: 'SYSTEM' },
  { role_id: 'role_dev', permission_id: 'perm_fn_read', assigned_at: '2026-09-01T08:00:00.000Z', assigned_by: 'SYSTEM' },
  { role_id: 'role_dev', permission_id: 'perm_audit_read', assigned_at: '2026-09-01T08:00:00.000Z', assigned_by: 'SYSTEM' },
  { role_id: 'role_guest', permission_id: 'perm_fn_read', assigned_at: '2026-09-01T08:00:00.000Z', assigned_by: 'SYSTEM' },
  { role_id: 'role_guest', permission_id: 'perm_audit_read', assigned_at: '2026-09-01T08:00:00.000Z', assigned_by: 'SYSTEM' }
];

const INITIAL_FUNCTIONS: FunctionEntity[] = [
  { id: 'fn_login', name: 'Identity Login Handler', slug: 'login', service_name: 'auth-service', runtime: 'nodejs20.x', max_memory_mb: 128, timeout_seconds: 3, is_active: true, created_at: '2026-09-01T08:00:00.000Z', updated_at: '2026-09-01T08:00:00.000Z' },
  { id: 'fn_dashboard', name: 'Dashboard Metrics Aggregator', slug: 'getDashboardMetrics', service_name: 'telemetry-service', runtime: 'nodejs20.x', max_memory_mb: 256, timeout_seconds: 3, is_active: true, required_permission_id: 'perm_fn_invoke', created_at: '2026-09-01T08:00:00.000Z', updated_at: '2026-09-01T08:00:00.000Z' },
  { id: 'fn_audit_logs', name: 'Security Logs Query Engine', slug: 'viewSecurityLogs', service_name: 'audit-service', runtime: 'nodejs20.x', max_memory_mb: 256, timeout_seconds: 5, is_active: true, required_permission_id: 'perm_audit_read', created_at: '2026-09-01T08:00:00.000Z', updated_at: '2026-09-01T08:00:00.000Z' },
  { id: 'fn_deploy_worker', name: 'Cloudflare Worker Deployment', slug: 'deployWorkerCode', service_name: 'pipeline-service', runtime: 'nodejs20.x', max_memory_mb: 512, timeout_seconds: 10, is_active: true, required_permission_id: 'perm_fn_invoke', created_at: '2026-09-01T08:00:00.000Z', updated_at: '2026-09-01T08:00:00.000Z' },
  { id: 'fn_update_policy', name: 'Security Policy Mutation Engine', slug: 'updateSystemPolicy', service_name: 'policy-service', runtime: 'nodejs20.x', max_memory_mb: 256, timeout_seconds: 5, is_active: true, required_permission_id: 'perm_policy_write', created_at: '2026-09-01T08:00:00.000Z', updated_at: '2026-09-01T08:00:00.000Z' },
  { id: 'fn_rotate_keys', name: 'KMS Key Rotation Worker', slug: 'rotateEncryptionKeys', service_name: 'kms-service', runtime: 'nodejs20.x', max_memory_mb: 256, timeout_seconds: 5, is_active: true, required_permission_id: 'perm_policy_write', created_at: '2026-09-01T08:00:00.000Z', updated_at: '2026-09-01T08:00:00.000Z' },
  { id: 'fn_purge_backups', name: 'Cold Storage Backup Purge', slug: 'purgeColdStorageBackups', service_name: 'backup-service', runtime: 'nodejs20.x', max_memory_mb: 512, timeout_seconds: 15, is_active: true, required_permission_id: 'perm_policy_write', created_at: '2026-09-01T08:00:00.000Z', updated_at: '2026-09-01T08:00:00.000Z' }
];

const INITIAL_CONFIG: SystemConfigRecord[] = [
  { config_key: 'verification.max_risk_threshold', config_value: '75', description: 'Maximum composite risk score before invocation is blocked', data_type: 'number', is_runtime_tunable: true, updated_at: '2026-09-01T08:00:00.000Z', updated_by: 'SYSTEM' },
  { config_key: 'verification.imds_strict_block', config_value: 'true', description: 'Instantly block cloud metadata IP (169.254.169.254) probes', data_type: 'boolean', is_runtime_tunable: true, updated_at: '2026-09-01T08:00:00.000Z', updated_by: 'SYSTEM' },
  { config_key: 'verification.sequence_penalty', config_value: '40', description: 'Penalty added to risk score on Markov sequence violation', data_type: 'number', is_runtime_tunable: true, updated_at: '2026-09-01T08:00:00.000Z', updated_by: 'SYSTEM' },
  { config_key: 'verification.fail_closed_active', config_value: 'true', description: 'Enforce fail-closed architecture on unhandled exceptions', data_type: 'boolean', is_runtime_tunable: false, updated_at: '2026-09-01T08:00:00.000Z', updated_by: 'SYSTEM' },
  { config_key: 'audit.retention_days', config_value: '90', description: 'Automated data retention period for audit logs', data_type: 'number', is_runtime_tunable: true, updated_at: '2026-09-01T08:00:00.000Z', updated_by: 'SYSTEM' },
  { config_key: 'rate_limit.max_requests_per_minute', config_value: '120', description: 'Per-user request threshold for burst rate limiting', data_type: 'number', is_runtime_tunable: true, updated_at: '2026-09-01T08:00:00.000Z', updated_by: 'SYSTEM' }
];

const INITIAL_USERS: User[] = [
  {
    id: 'usr_secops_admin',
    username: 'secops_admin',
    password_hash: 'ZeroTrust_2026',
    role: 'Admin',
    base_risk_score: 0,
    status: 'APPROVED',
    department: 'SecOps Core Operations',
    email: 'secops_admin@corp.internal',
    phone: '+1 (555) 019-4829',
    mfa_enabled: true,
    createdAt: '2026-09-01T08:00:00.000Z',
    approvedAt: '2026-09-01T08:00:00.000Z',
    approvedBy: 'SYSTEM_ROOT'
  },
  {
    id: 'usr_cloud_dev',
    username: 'cloud_dev',
    password_hash: 'ZeroTrust_2026',
    role: 'Developer',
    base_risk_score: 15,
    status: 'APPROVED',
    department: 'Cloud Platform Engineering',
    email: 'cloud_dev@corp.internal',
    phone: '+1 (555) 019-7261',
    mfa_enabled: true,
    createdAt: '2026-09-02T10:00:00.000Z',
    approvedAt: '2026-09-02T10:15:00.000Z',
    approvedBy: 'secops_admin'
  },
  {
    id: 'usr_auditor_guest',
    username: 'auditor_guest',
    password_hash: 'ZeroTrust_2026',
    role: 'Guest',
    base_risk_score: 30,
    status: 'APPROVED',
    department: 'Third-Party Compliance & SOC-2',
    email: 'auditor_guest@compliance-partner.com',
    phone: '+1 (555) 019-9154',
    mfa_enabled: true,
    createdAt: '2026-09-05T14:30:00.000Z',
    approvedAt: '2026-09-05T14:35:00.000Z',
    approvedBy: 'secops_admin'
  },
  {
    id: 'usr_sarah_infra',
    username: 'sarah_infra',
    password_hash: 'ZeroTrust_2026',
    role: 'Developer',
    base_risk_score: 10,
    status: 'APPROVED',
    department: 'Infrastructure & Edge Reliability',
    email: 'sarah_infra@corp.internal',
    phone: '+1 (555) 019-3820',
    mfa_enabled: true,
    createdAt: '2026-09-08T09:00:00.000Z',
    approvedAt: '2026-09-08T09:20:00.000Z',
    approvedBy: 'secops_admin'
  },
  {
    id: 'usr_alex_contractor',
    username: 'alex_contractor',
    password_hash: 'ZeroTrust_2026',
    role: 'Developer',
    base_risk_score: 25,
    status: 'PENDING_APPROVAL',
    department: 'Edge Pipeline Contractors',
    email: 'alex_contractor@contractor.internal',
    phone: '+1 (555) 019-6183',
    mfa_enabled: true,
    requestJustification: 'Contractor onboarded for Cloudflare Worker serverless microservices deployment and telemetry audit.',
    createdAt: '2026-09-14T20:15:00.000Z'
  },
  {
    id: 'usr_threat_actor',
    username: 'threat_actor',
    password_hash: 'ZeroTrust_2026',
    role: 'Guest',
    base_risk_score: 70,
    status: 'SUSPENDED',
    department: 'Untrusted Public Origin',
    email: 'threat_actor@darknet-proxy.io',
    phone: '+1 (555) 019-0099',
    mfa_enabled: true,
    createdAt: '2026-09-10T22:00:00.000Z'
  }
];

const INITIAL_RULES: Omit<FunctionRule, 'id'>[] = [
  { current_function: 'login', allowed_next_function: 'getDashboardMetrics' },
  { current_function: 'getDashboardMetrics', allowed_next_function: 'viewSecurityLogs' },
  { current_function: 'viewSecurityLogs', allowed_next_function: 'deployWorkerCode' },
  { current_function: 'deployWorkerCode', allowed_next_function: 'updateSystemPolicy' },
  { current_function: 'viewSecurityLogs', allowed_next_function: 'rotateEncryptionKeys' },
  { current_function: 'rotateEncryptionKeys', allowed_next_function: 'purgeColdStorageBackups' }
];

class SecurityDatabase {
  private users: User[] = [];
  private roles: Role[] = [];
  private permissions: Permission[] = [];
  private rolePermissions: RolePermission[] = [];
  private userRoles: UserRole[] = [];
  private functions: FunctionEntity[] = [];
  private invocationHistory: InvocationHistoryRecord[] = [];
  private verificationResults: VerificationResultRecord[] = [];
  private securityAlerts: SecurityAlertRecord[] = [];
  private incidents: IncidentRecord[] = [];
  private systemConfigs: SystemConfigRecord[] = [];

  private rules: FunctionRule[] = [];
  private logs: SecurityAuditLog[] = [];
  private auditEvents: SecurityAuditLog[] = [];
  private sessions: ActiveSession[] = [];
  private revokedTokens: Set<string> = new Set();
  private revokedUsernames: Set<string> = new Set();
  private ruleIdCounter = 1;
  private logIdCounter = 1;
  private userIdCounter = 100;

  constructor() {
    this.reset();
  }

  public reset() {
    this.users = JSON.parse(JSON.stringify(INITIAL_USERS));
    this.roles = JSON.parse(JSON.stringify(INITIAL_ROLES));
    this.permissions = JSON.parse(JSON.stringify(INITIAL_PERMISSIONS));
    this.rolePermissions = JSON.parse(JSON.stringify(INITIAL_ROLE_PERMISSIONS));
    this.functions = JSON.parse(JSON.stringify(INITIAL_FUNCTIONS));
    this.systemConfigs = JSON.parse(JSON.stringify(INITIAL_CONFIG));
    this.userRoles = [
      { user_id: 'usr_secops_admin', role_id: 'role_admin', assigned_at: '2026-09-01T08:00:00.000Z', assigned_by: 'SYSTEM' },
      { user_id: 'usr_cloud_dev', role_id: 'role_dev', assigned_at: '2026-09-02T10:00:00.000Z', assigned_by: 'SYSTEM' },
      { user_id: 'usr_auditor_guest', role_id: 'role_guest', assigned_at: '2026-09-05T14:30:00.000Z', assigned_by: 'SYSTEM' },
      { user_id: 'usr_sarah_infra', role_id: 'role_dev', assigned_at: '2026-09-08T09:00:00.000Z', assigned_by: 'SYSTEM' }
    ];

    this.rules = INITIAL_RULES.map((r, i) => ({ id: i + 1, ...r }));
    this.logs = [];
    this.auditEvents = [];
    this.sessions = [];
    this.invocationHistory = [];
    this.verificationResults = [];
    this.securityAlerts = [];
    this.incidents = [];
    this.revokedTokens.clear();
    this.revokedUsernames.clear();
    this.ruleIdCounter = this.rules.length + 1;
    this.logIdCounter = 1;

    // Seed default baseline active session for secops_admin
    this.createSession({
      token: 'zt_jwt_secops_admin_k7x9',
      username: 'secops_admin',
      role: 'Admin',
      expiresInSeconds: 86400
    });
  }

  public clearLogs() {
    this.logs = [];
    this.auditEvents = [];
    this.invocationHistory = [];
    this.verificationResults = [];
    this.securityAlerts = [];
  }

  public createSession(data: {
    token: string;
    username: string;
    role: 'Admin' | 'Developer' | 'Guest';
    expiresInSeconds?: number;
  }): ActiveSession {
    const cleanUser = data.username.trim().toLowerCase();
    this.revokedUsernames.delete(cleanUser);
    this.revokedTokens.delete(data.token);

    const expiresAt = new Date(Date.now() + (data.expiresInSeconds || 3600) * 1000).toISOString();
    const session: ActiveSession = {
      id: `sess_${Date.now().toString(36)}_${Math.random().toString(36).substring(2, 6)}`,
      token: data.token,
      username: data.username.trim(),
      role: data.role,
      createdAt: new Date().toISOString(),
      expiresAt,
      revoked: false
    };

    this.sessions.push(session);
    return session;
  }

  public revokeSession(target: {
    username?: string;
    token?: string;
    revokedBy?: string;
    reason?: string;
  }): { success: boolean; revokedCount: number; revokedUsers: string[] } {
    const revokedBy = target.revokedBy || 'secops_admin';
    const reason = target.reason || 'Terminated by Administrator via SecOps Console';
    let revokedCount = 0;
    const affectedUsers = new Set<string>();

    if (target.token) {
      this.revokedTokens.add(target.token);
      for (const s of this.sessions) {
        if (s.token === target.token && !s.revoked) {
          s.revoked = true;
          s.revokedAt = new Date().toISOString();
          s.revokedBy = revokedBy;
          s.revocationReason = reason;
          revokedCount++;
          affectedUsers.add(s.username);
        }
      }
    }

    if (target.username) {
      const q = target.username.toLowerCase().trim();
      this.revokedUsernames.add(q);
      for (const s of this.sessions) {
        if (s.username.toLowerCase() === q && !s.revoked) {
          s.revoked = true;
          s.revokedAt = new Date().toISOString();
          s.revokedBy = revokedBy;
          s.revocationReason = reason;
          this.revokedTokens.add(s.token);
          revokedCount++;
          affectedUsers.add(s.username);
        }
      }
      affectedUsers.add(target.username);
    }

    return {
      success: true,
      revokedCount: Math.max(revokedCount, target.username ? 1 : 0),
      revokedUsers: Array.from(affectedUsers)
    };
  }

  public isSessionRevoked(token: string, username?: string): boolean {
    if (this.revokedTokens.has(token)) return true;
    if (username && this.revokedUsernames.has(username.toLowerCase().trim())) return true;
    const s = this.sessions.find(sess => sess.token === token);
    if (s && s.revoked) return true;
    return false;
  }

  public getSessions(): ActiveSession[] {
    return [...this.sessions];
  }

  public getUsers(): User[] {
    return [...this.users];
  }

  public getRoles(): Role[] {
    return [...this.roles];
  }

  public getPermissions(): Permission[] {
    return [...this.permissions];
  }

  public getFunctions(): FunctionEntity[] {
    return [...this.functions];
  }

  public getSecurityAlerts(): SecurityAlertRecord[] {
    return [...this.securityAlerts];
  }

  public getSystemConfigs(): SystemConfigRecord[] {
    return [...this.systemConfigs];
  }

  public getUserPermissions(userIdOrUsername: string): string[] {
    const user = this.getUser(userIdOrUsername);
    if (!user) return [];
    
    // Check direct role string mapping
    const roleMap: Record<string, string> = {
      Admin: 'role_admin',
      Developer: 'role_dev',
      Guest: 'role_guest'
    };
    const roleId = roleMap[user.role] || 'role_guest';

    const permIds = this.rolePermissions
      .filter(rp => rp.role_id === roleId)
      .map(rp => rp.permission_id);

    return this.permissions
      .filter(p => permIds.includes(p.id))
      .map(p => p.name);
  }

  public getUser(usernameOrId: string): User | undefined {
    const q = usernameOrId.toLowerCase().trim();
    return this.users.find(u => u.username.toLowerCase() === q || u.id.toLowerCase() === q);
  }

  public addUser(userData: {
    username: string;
    role?: 'Admin' | 'Developer' | 'Guest';
    password?: string;
    base_risk_score?: number;
    status?: UserApprovalStatus;
    department?: string;
    email?: string;
    phone?: string;
    mfa_enabled?: boolean;
    requestJustification?: string;
    approvedBy?: string;
  }): User {
    const existing = this.users.find(u => u.username.toLowerCase() === userData.username.toLowerCase().trim());
    if (existing) {
      if (userData.role) existing.role = userData.role;
      if (typeof userData.base_risk_score === 'number') existing.base_risk_score = userData.base_risk_score;
      if (userData.status) existing.status = userData.status;
      if (userData.department) existing.department = userData.department;
      if (userData.password) existing.password_hash = userData.password;
      if (userData.phone) existing.phone = userData.phone;
      if (userData.mfa_enabled !== undefined) existing.mfa_enabled = userData.mfa_enabled;
      return existing;
    }

    const newUser: User = {
      id: `usr_${Date.now().toString(36)}_${++this.userIdCounter}`,
      username: userData.username.trim(),
      password_hash: userData.password || 'ZeroTrust_2026',
      role: userData.role || 'Developer',
      base_risk_score: typeof userData.base_risk_score === 'number' ? userData.base_risk_score : 20,
      status: userData.status || 'PENDING_APPROVAL',
      department: userData.department || 'General Engineering',
      email: userData.email || `${userData.username.trim().toLowerCase()}@corp.internal`,
      phone: userData.phone || '+1 (555) 019-8392',
      mfa_enabled: userData.mfa_enabled ?? true,
      createdAt: new Date().toISOString(),
      requestJustification: userData.requestJustification,
      approvedBy: userData.approvedBy,
      approvedAt: userData.status === 'APPROVED' ? new Date().toISOString() : undefined
    };

    this.users.push(newUser);
    return newUser;
  }

  public updateUser(username: string, updates: Partial<User>): User | null {
    const user = this.users.find(u => u.username.toLowerCase() === username.toLowerCase().trim());
    if (!user) return null;

    if (updates.role) user.role = updates.role;
    if (typeof updates.base_risk_score === 'number') {
      user.base_risk_score = Math.max(0, Math.min(100, Math.round(updates.base_risk_score)));
    }
    if (updates.status) user.status = updates.status;
    if (updates.department !== undefined) user.department = updates.department;
    if (updates.email !== undefined) user.email = updates.email;
    if (updates.phone !== undefined) user.phone = updates.phone;
    if (updates.mfa_enabled !== undefined) user.mfa_enabled = updates.mfa_enabled;
    if (updates.password_hash) user.password_hash = updates.password_hash;
    if (updates.approvedBy !== undefined) user.approvedBy = updates.approvedBy;
    if (updates.approvedAt !== undefined) user.approvedAt = updates.approvedAt;
    if (updates.lastLoginAt !== undefined) user.lastLoginAt = updates.lastLoginAt;

    return user;
  }

  public approveUser(username: string, approvedBy: string = 'secops_admin', roleOverride?: 'Admin' | 'Developer' | 'Guest', riskOverride?: number): User | null {
    const user = this.users.find(u => u.username.toLowerCase() === username.toLowerCase().trim());
    if (!user) return null;

    user.status = 'APPROVED';
    user.approvedAt = new Date().toISOString();
    user.approvedBy = approvedBy;
    if (roleOverride) user.role = roleOverride;
    if (typeof riskOverride === 'number') user.base_risk_score = riskOverride;

    return user;
  }

  public rejectUser(username: string, rejectedBy: string = 'secops_admin', reason?: string): User | null {
    const user = this.users.find(u => u.username.toLowerCase() === username.toLowerCase().trim());
    if (!user) return null;

    user.status = 'REJECTED';
    user.requestJustification = reason ? `Rejected by ${rejectedBy}: ${reason}` : `Rejected by ${rejectedBy}`;
    return user;
  }

  public deleteUser(username: string): boolean {
    const idx = this.users.findIndex(u => u.username.toLowerCase() === username.toLowerCase().trim());
    if (idx !== -1) {
      this.users.splice(idx, 1);
      return true;
    }
    return false;
  }

  public seedBatchUsers(): User[] {
    const batchTemplates = [
      { username: 'devops_marcus', role: 'Developer' as const, risk: 15, dept: 'Edge SRE Operations', status: 'APPROVED' as const },
      { username: 'sec_analyst_elena', role: 'Developer' as const, risk: 10, dept: 'Threat Intelligence & Detection', status: 'APPROVED' as const },
      { username: 'qa_lead_david', role: 'Developer' as const, risk: 20, dept: 'Integration Testing & QA', status: 'PENDING_APPROVAL' as const },
      { username: 'auditor_compliance_rachel', role: 'Guest' as const, risk: 25, dept: 'External SOC-2 Audit', status: 'APPROVED' as const },
      { username: 'dev_intern_kevin', role: 'Guest' as const, risk: 35, dept: 'Core Backend Engineering', status: 'PENDING_APPROVAL' as const }
    ];

    const added: User[] = [];
    for (const t of batchTemplates) {
      if (!this.users.some(u => u.username.toLowerCase() === t.username.toLowerCase())) {
        const u = this.addUser({
          username: t.username,
          role: t.role,
          base_risk_score: t.risk,
          department: t.dept,
          status: t.status,
          password: 'ZeroTrust_2026',
          requestJustification: t.status === 'PENDING_APPROVAL' ? 'Requested environment access for verification' : undefined
        });
        added.push(u);
      }
    }
    return added;
  }

  public getRules(): FunctionRule[] {
    return [...this.rules];
  }

  public addRule(current_function: string, allowed_next_function: string): FunctionRule {
    const newRule: FunctionRule = {
      id: this.ruleIdCounter++,
      current_function,
      allowed_next_function
    };
    this.rules.push(newRule);
    return newRule;
  }

  public deleteRule(id: number): boolean {
    const idx = this.rules.findIndex(r => r.id === id);
    if (idx !== -1) {
      this.rules.splice(idx, 1);
      return true;
    }
    return false;
  }

  public getAllLogs(): SecurityAuditLog[] {
    return [...this.logs].sort((a, b) => b.id - a.id);
  }

  public getAuditEvents(): SecurityAuditLog[] {
    return (this.auditEvents.length > 0 ? this.auditEvents : this.logs).slice().sort((a, b) => b.id - a.id);
  }

  public getRecentRequestCount(username: string, windowMs = 60000): number {
    const cutoff = Date.now() - windowMs;
    return this.logs.filter(
      l => l.username.toLowerCase() === username.toLowerCase() && new Date(l.timestamp).getTime() >= cutoff
    ).length;
  }

  /**
   * Compatibility layer providing env.DB.prepare(sql).bind(...).first() / .all() / .run()
   */
  public prepare(sql: string) {
    const self = this;
    let boundParams: any[] = [];

    const stmt = {
      bind(...params: any[]) {
        boundParams = params;
        return stmt;
      },
      async first(): Promise<any> {
        const trimmed = sql.trim();
        if (trimmed.includes('FROM users WHERE username = ?')) {
          const username = boundParams[0];
          return self.users.find(u => u.username.toLowerCase() === (username || '').toLowerCase()) || null;
        }
        if (trimmed.includes('COUNT(*)') && (trimmed.includes('security_audit_logs') || trimmed.includes('security_events') || trimmed.includes('audit_events'))) {
          const username = boundParams[0];
          const count = self.getRecentRequestCount(username, 60000);
          return { count, total: count };
        }
        if (trimmed.includes('FROM audit_events WHERE username = ?')) {
          const username = boundParams[0];
          const source = self.auditEvents.length > 0 ? self.auditEvents : self.logs;
          const userLogs = source.filter(l => l.username.toLowerCase() === (username || '').toLowerCase());
          if (userLogs.length === 0) return null;
          return userLogs[userLogs.length - 1];
        }
        if (trimmed.includes('FROM security_audit_logs WHERE username = ?') || trimmed.includes('FROM security_events WHERE username = ?')) {
          const username = boundParams[0];
          const userLogs = self.logs.filter(l => l.username.toLowerCase() === (username || '').toLowerCase());
          if (userLogs.length === 0) return null;
          return userLogs[userLogs.length - 1];
        }
        if (trimmed.includes('FROM function_rules WHERE current_function = ? AND allowed_next_function = ?')) {
          const [current, next] = boundParams;
          return self.rules.find(r => r.current_function === current && r.allowed_next_function === next) || null;
        }
        if (trimmed.includes('FROM active_sessions WHERE token = ?') || trimmed.includes('FROM sessions WHERE session_token = ?')) {
          const token = boundParams[0];
          return self.sessions.find(s => s.token === token) || null;
        }
        if (trimmed.includes('FROM active_sessions WHERE username = ?') || trimmed.includes('FROM sessions WHERE username = ?')) {
          const username = boundParams[0];
          return self.sessions.find(s => s.username.toLowerCase() === (username || '').toLowerCase() && !s.revoked) || null;
        }
        if (trimmed.includes('FROM functions WHERE slug = ?')) {
          const slug = boundParams[0];
          return self.functions.find(f => f.slug === slug) || null;
        }
        if (trimmed.includes('FROM system_configuration WHERE config_key = ?')) {
          const key = boundParams[0];
          return self.systemConfigs.find(c => c.config_key === key) || null;
        }
        return null;
      },
      async all(): Promise<{ results: any[] }> {
        const trimmed = sql.trim();
        if (trimmed.includes('FROM active_sessions') || trimmed.includes('FROM sessions')) {
          return { results: [...self.sessions] };
        }
        if (trimmed.includes('FROM audit_events')) {
          const limitMatch = trimmed.match(/LIMIT\s+(\d+)/i);
          const limit = limitMatch ? parseInt(limitMatch[1], 10) : 50;
          const source = self.auditEvents.length > 0 ? self.auditEvents : self.logs;
          const sorted = [...source].sort((a, b) => b.id - a.id).slice(0, limit);
          return { results: sorted };
        }
        if (trimmed.includes('FROM security_audit_logs') || trimmed.includes('FROM security_events')) {
          const limitMatch = trimmed.match(/LIMIT\s+(\d+)/i);
          const limit = limitMatch ? parseInt(limitMatch[1], 10) : 50;
          const sorted = [...self.logs].sort((a, b) => b.id - a.id).slice(0, limit);
          return { results: sorted };
        }
        if (trimmed.includes('FROM users')) {
          return { results: [...self.users] };
        }
        if (trimmed.includes('FROM roles')) {
          return { results: [...self.roles] };
        }
        if (trimmed.includes('FROM permissions')) {
          return { results: [...self.permissions] };
        }
        if (trimmed.includes('FROM functions')) {
          return { results: [...self.functions] };
        }
        if (trimmed.includes('FROM security_alerts')) {
          return { results: [...self.securityAlerts] };
        }
        if (trimmed.includes('FROM incidents')) {
          return { results: [...self.incidents] };
        }
        if (trimmed.includes('FROM system_configuration')) {
          return { results: [...self.systemConfigs] };
        }
        if (trimmed.includes('FROM function_rules')) {
          return { results: [...self.rules] };
        }
        return { results: [] };
      },
      async run(): Promise<{ success: boolean; id?: number }> {
        const trimmed = sql.trim();
        if (trimmed.startsWith('INSERT INTO security_audit_logs') || trimmed.startsWith('INSERT INTO security_events') || trimmed.startsWith('INSERT INTO audit_events')) {
          const [username, requested_function, calculated_risk, status, reason, verification_latency_ms, event_type] = boundParams;
          const numericLatency = typeof verification_latency_ms === 'number'
            ? verification_latency_ms
            : (parseFloat(verification_latency_ms) || 0.0);

          const newLog: SecurityAuditLog = {
            id: self.logIdCounter++,
            timestamp: new Date().toISOString(),
            username: username || 'unknown',
            requested_function: requested_function || '/api/unknown',
            calculated_risk: typeof calculated_risk === 'number' ? calculated_risk : 0,
            status: status === 'ALLOWED' ? 'ALLOWED' : 'BLOCKED',
            reason: reason || 'Audit evaluation recorded.',
            verification_latency_ms: numericLatency,
            event_type: event_type || (reason?.includes('ABNORMAL_REQUEST_RATE') ? 'ABNORMAL_REQUEST_RATE' : 'STANDARD_VERIFICATION')
          };

          self.logs.push(newLog);
          self.auditEvents.push(newLog);
          return { success: true, id: newLog.id };
        }
        if (trimmed.startsWith('INSERT INTO active_sessions') || trimmed.startsWith('INSERT INTO sessions')) {
          const [id, token, username, role, expires_at] = boundParams;
          self.createSession({ token, username, role });
          return { success: true };
        }
        if (trimmed.startsWith('UPDATE active_sessions SET revoked = 1') || trimmed.startsWith('UPDATE sessions SET status = \'revoked\'')) {
          const [revokedBy, reason, target] = boundParams;
          self.revokeSession({ username: target, token: target, revokedBy, reason });
          return { success: true };
        }
        if (trimmed.startsWith('INSERT INTO security_alerts')) {
          const [id, invocation_id, alert_type, severity, threat_vector, details_json, ip_address, user_id] = boundParams;
          const newAlert: SecurityAlertRecord = {
            id: id || `alt_${Date.now().toString(36)}`,
            invocation_id,
            alert_type: alert_type || 'SECURITY_THREAT',
            severity: severity || 'MEDIUM',
            threat_vector: threat_vector || 'UNKNOWN',
            details_json: typeof details_json === 'string' ? details_json : JSON.stringify(details_json || {}),
            ip_address: ip_address || '127.0.0.1',
            user_id,
            created_at: new Date().toISOString()
          };
          self.securityAlerts.push(newAlert);
          return { success: true };
        }
        return { success: true };
      }
    };

    return stmt;
  }
}

export const db = new SecurityDatabase();
