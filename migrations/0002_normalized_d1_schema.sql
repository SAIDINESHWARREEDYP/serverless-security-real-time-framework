-- ==============================================================================
-- Cloudflare D1 Database Migration: 0002_normalized_d1_schema.sql
-- Project: Design and Implementation of an Integrated Real-Time Security
--          Verification Framework for Serverless Cloud Applications
-- Capstone: B.Tech CSE Capstone 2026–2027 (IEEE Access / Bλambda Foundation)
-- Description: Third Normal Form (3NF) relational schema for zero-trust identity,
--              fine-grained RBAC, serverless function routing, verification verdicts,
--              security incidents, and tamper-evident audit logging.
-- ==============================================================================

PRAGMA foreign_keys = ON;

-- ------------------------------------------------------------------------------
-- 1. ROLES & PERMISSIONS (Fine-Grained RBAC Foundation)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS roles (
  id TEXT PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  description TEXT,
  is_system_role INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now', 'utc'))
);

CREATE TABLE IF NOT EXISTS permissions (
  id TEXT PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  resource TEXT NOT NULL,
  action TEXT NOT NULL,
  description TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now', 'utc'))
);

CREATE TABLE IF NOT EXISTS role_permissions (
  role_id TEXT NOT NULL,
  permission_id TEXT NOT NULL,
  assigned_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
  assigned_by TEXT NOT NULL DEFAULT 'SYSTEM',
  PRIMARY KEY (role_id, permission_id),
  FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
  FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_role_permissions_role ON role_permissions(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_perm ON role_permissions(permission_id);

-- ------------------------------------------------------------------------------
-- 2. USERS & USER ROLE ASSIGNMENTS
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_roles (
  user_id TEXT NOT NULL,
  role_id TEXT NOT NULL,
  assigned_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
  assigned_by TEXT NOT NULL DEFAULT 'SYSTEM',
  PRIMARY KEY (user_id, role_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role_id);

-- ------------------------------------------------------------------------------
-- 3. POLICIES & POLICY VERSIONS (Immutable Versioning)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS policy_versions (
  id TEXT PRIMARY KEY,
  policy_id TEXT NOT NULL,
  version_number INTEGER NOT NULL,
  rules_definition_json TEXT NOT NULL,
  change_summary TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
  FOREIGN KEY (policy_id) REFERENCES policies(id) ON DELETE CASCADE,
  UNIQUE(policy_id, version_number)
);

CREATE INDEX IF NOT EXISTS idx_policy_versions_policy ON policy_versions(policy_id, version_number DESC);

-- ------------------------------------------------------------------------------
-- 4. SERVERLESS FUNCTIONS REGISTRY & SERVICE INVENTORY
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS functions (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  service_name TEXT NOT NULL,
  runtime TEXT NOT NULL DEFAULT 'nodejs20.x',
  max_memory_mb INTEGER NOT NULL DEFAULT 256,
  timeout_seconds INTEGER NOT NULL DEFAULT 5,
  is_active INTEGER NOT NULL DEFAULT 1,
  required_permission_id TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
  FOREIGN KEY (required_permission_id) REFERENCES permissions(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_functions_slug ON functions(slug);
CREATE INDEX IF NOT EXISTS idx_functions_service ON functions(service_name);
CREATE INDEX IF NOT EXISTS idx_functions_active ON functions(is_active);

-- ------------------------------------------------------------------------------
-- 5. INVOCATION HISTORY & REAL-TIME VERIFICATION RESULTS
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS invocation_history (
  id TEXT PRIMARY KEY,
  trace_id TEXT UNIQUE NOT NULL,
  parent_trace_id TEXT,
  user_id TEXT,
  function_id TEXT NOT NULL,
  source_ip TEXT NOT NULL,
  http_method TEXT NOT NULL DEFAULT 'POST',
  payload_size_bytes INTEGER NOT NULL DEFAULT 0,
  payload_sha256 TEXT NOT NULL,
  invoked_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
  FOREIGN KEY (function_id) REFERENCES functions(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_invocation_trace ON invocation_history(trace_id);
CREATE INDEX IF NOT EXISTS idx_invocation_user ON invocation_history(user_id);
CREATE INDEX IF NOT EXISTS idx_invocation_fn ON invocation_history(function_id);
CREATE INDEX IF NOT EXISTS idx_invocation_time ON invocation_history(invoked_at DESC);

CREATE TABLE IF NOT EXISTS verification_results (
  id TEXT PRIMARY KEY,
  invocation_id TEXT UNIQUE NOT NULL,
  verdict TEXT NOT NULL CHECK(verdict IN ('ALLOW', 'DENY', 'QUARANTINE')),
  risk_score INTEGER NOT NULL CHECK(risk_score BETWEEN 0 AND 100),
  verification_latency_ms REAL NOT NULL,
  imds_probe_detected INTEGER NOT NULL DEFAULT 0,
  prompt_injection_detected INTEGER NOT NULL DEFAULT 0,
  sequence_deviation_detected INTEGER NOT NULL DEFAULT 0,
  shell_injection_detected INTEGER NOT NULL DEFAULT 0,
  token_signature_valid INTEGER NOT NULL DEFAULT 1,
  session_active INTEGER NOT NULL DEFAULT 1,
  rbac_granted INTEGER NOT NULL DEFAULT 1,
  fail_closed_triggered INTEGER NOT NULL DEFAULT 0,
  decision_reason TEXT NOT NULL,
  verified_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
  FOREIGN KEY (invocation_id) REFERENCES invocation_history(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_verif_invocation ON verification_results(invocation_id);
CREATE INDEX IF NOT EXISTS idx_verif_verdict ON verification_results(verdict);
CREATE INDEX IF NOT EXISTS idx_verif_latency ON verification_results(verification_latency_ms);
CREATE INDEX IF NOT EXISTS idx_verif_time ON verification_results(verified_at DESC);

-- ------------------------------------------------------------------------------
-- 6. SECURITY ALERTS & INCIDENT CASE MANAGEMENT
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security_alerts (
  id TEXT PRIMARY KEY,
  invocation_id TEXT,
  alert_type TEXT NOT NULL,
  severity TEXT NOT NULL CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
  threat_vector TEXT NOT NULL,
  details_json TEXT NOT NULL,
  ip_address TEXT NOT NULL,
  user_id TEXT,
  acknowledged_at TEXT,
  acknowledged_by TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
  FOREIGN KEY (invocation_id) REFERENCES invocation_history(id) ON DELETE SET NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_severity ON security_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_type ON security_alerts(alert_type);
CREATE INDEX IF NOT EXISTS idx_alerts_user ON security_alerts(user_id);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON security_alerts(created_at DESC);

CREATE TABLE IF NOT EXISTS incidents (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  severity TEXT NOT NULL CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
  status TEXT NOT NULL DEFAULT 'OPEN' CHECK(status IN ('OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE')),
  root_cause TEXT,
  mitigation_steps TEXT,
  assigned_to TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
  resolved_at TEXT,
  resolved_by TEXT,
  FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);

-- ------------------------------------------------------------------------------
-- 7. SESSIONS (Standardized Stateful Session Registry)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  session_token TEXT UNIQUE NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'revoked', 'expired')),
  ip_address TEXT,
  user_agent TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  revoked_by TEXT,
  revocation_reason TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);

-- ------------------------------------------------------------------------------
-- 8. SYSTEM CONFIGURATION (Dynamic Operational Tuning)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS system_configuration (
  config_key TEXT PRIMARY KEY,
  config_value TEXT NOT NULL,
  description TEXT,
  data_type TEXT NOT NULL DEFAULT 'string' CHECK(data_type IN ('string', 'number', 'boolean', 'json')),
  is_runtime_tunable INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
  updated_by TEXT NOT NULL DEFAULT 'SYSTEM'
);

-- ------------------------------------------------------------------------------
-- SEED DATA: Roles, Permissions, System Config & Function Catalog
-- ------------------------------------------------------------------------------

-- Seed Canonical Roles
INSERT OR IGNORE INTO roles (id, name, description, is_system_role) VALUES
  ('role_admin', 'Administrator', 'Full system access, policy mutation, user management, and session revocation.', 1),
  ('role_dev', 'Developer', 'Read and execute serverless functions, inspect telemetry and invocation baselines.', 1),
  ('role_guest', 'Guest', 'Restricted evaluation role with read-only access to compliance reports.', 1);

-- Seed Granular Permissions
INSERT OR IGNORE INTO permissions (id, name, resource, action, description) VALUES
  ('perm_fn_invoke', 'function:invoke', 'function', 'invoke', 'Execute serverless function through verification gateway'),
  ('perm_fn_read', 'function:read', 'function', 'read', 'Inspect function configuration and schema specifications'),
  ('perm_policy_write', 'policy:write', 'policy', 'write', 'Mutate security policies, thresholds, and sequence rules'),
  ('perm_session_revoke', 'session:revoke', 'session', 'revoke', 'Revoke active user sessions in real-time D1 registry'),
  ('perm_user_approve', 'user:approve', 'user', 'approve', 'Approve or reject pending registration requests'),
  ('perm_audit_read', 'audit:read', 'audit', 'read', 'Query and export cryptographic audit log streams'),
  ('perm_matrix_view', 'security_matrix:view', 'security_matrix', 'read', 'View enterprise cloud blueprint and schema matrix');

-- Seed Role-Permission Associations
INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES
  -- Admin Permissions (All)
  ('role_admin', 'perm_fn_invoke'),
  ('role_admin', 'perm_fn_read'),
  ('role_admin', 'perm_policy_write'),
  ('role_admin', 'perm_session_revoke'),
  ('role_admin', 'perm_user_approve'),
  ('role_admin', 'perm_audit_read'),
  ('role_admin', 'perm_matrix_view'),
  -- Developer Permissions
  ('role_dev', 'perm_fn_invoke'),
  ('role_dev', 'perm_fn_read'),
  ('role_dev', 'perm_audit_read'),
  -- Guest Permissions
  ('role_guest', 'perm_fn_read'),
  ('role_guest', 'perm_audit_read');

-- Associate Initial Users with Normalized Roles
INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES
  ('usr_secops_admin', 'role_admin'),
  ('usr_cloud_dev', 'role_dev'),
  ('usr_auditor_guest', 'role_guest'),
  ('usr_sarah_infra', 'role_dev');

-- Seed Serverless Function Inventory
INSERT OR IGNORE INTO functions (id, name, slug, service_name, runtime, max_memory_mb, timeout_seconds, required_permission_id) VALUES
  ('fn_login', 'Identity Login Handler', 'login', 'auth-service', 'nodejs20.x', 128, 3, NULL),
  ('fn_dashboard', 'Dashboard Metrics Aggregator', 'getDashboardMetrics', 'telemetry-service', 'nodejs20.x', 256, 3, 'perm_fn_invoke'),
  ('fn_audit_logs', 'Security Logs Query Engine', 'viewSecurityLogs', 'audit-service', 'nodejs20.x', 256, 5, 'perm_audit_read'),
  ('fn_deploy_worker', 'Cloudflare Worker Deployment', 'deployWorkerCode', 'pipeline-service', 'nodejs20.x', 512, 10, 'perm_fn_invoke'),
  ('fn_update_policy', 'Security Policy Mutation Engine', 'updateSystemPolicy', 'policy-service', 'nodejs20.x', 256, 5, 'perm_policy_write'),
  ('fn_rotate_keys', 'KMS Key Rotation Worker', 'rotateEncryptionKeys', 'kms-service', 'nodejs20.x', 256, 5, 'perm_policy_write'),
  ('fn_purge_backups', 'Cold Storage Backup Purge', 'purgeColdStorageBackups', 'backup-service', 'nodejs20.x', 512, 15, 'perm_policy_write');

-- Seed System Configuration Baselines
INSERT OR IGNORE INTO system_configuration (config_key, config_value, description, data_type, is_runtime_tunable) VALUES
  ('verification.max_risk_threshold', '75', 'Maximum composite risk score before invocation is blocked', 'number', 1),
  ('verification.imds_strict_block', 'true', 'Instantly block cloud metadata IP (169.254.169.254) probes', 'boolean', 1),
  ('verification.sequence_penalty', '40', 'Penalty added to risk score on Markov sequence violation', 'number', 1),
  ('verification.fail_closed_active', 'true', 'Enforce fail-closed architecture on unhandled exceptions', 'boolean', 0),
  ('audit.retention_days', '90', 'Automated data retention period for audit logs', 'number', 1),
  ('rate_limit.max_requests_per_minute', '120', 'Per-user request threshold for burst rate limiting', 'number', 1);
