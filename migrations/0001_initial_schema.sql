-- Cloudflare D1 Migration: Initial Schema for Serverless Security Verification Framework
-- Capstone Project: Design and Implementation of an Integrated Real-Time Security Verification Framework for Serverless Cloud Applications

-- 1. Users & Identities with Zero-Trust Clearance States
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('Admin', 'Developer', 'Guest')),
  base_risk_score INTEGER NOT NULL DEFAULT 20,
  status TEXT NOT NULL DEFAULT 'APPROVED' CHECK(status IN ('APPROVED', 'PENDING_APPROVAL', 'REJECTED', 'SUSPENDED')),
  department TEXT,
  email TEXT,
  phone TEXT,
  mfa_enabled INTEGER DEFAULT 1,
  password_salt TEXT,
  mfa_secret TEXT,
  mfa_backup_codes TEXT,
  last_totp_step INTEGER DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  approved_at TEXT,
  approved_by TEXT,
  last_login_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);

-- 2. Markov Chain Sequential Transition Verification Rules
CREATE TABLE IF NOT EXISTS function_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  current_function TEXT NOT NULL,
  allowed_next_function TEXT NOT NULL,
  UNIQUE(current_function, allowed_next_function)
);

CREATE INDEX IF NOT EXISTS idx_rules_sequence ON function_rules(current_function, allowed_next_function);

-- 3. High-Assurance Security Audit Logs with Microsecond Latency Metrics
CREATE TABLE IF NOT EXISTS security_audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL DEFAULT (datetime('now')),
  username TEXT NOT NULL,
  requested_function TEXT NOT NULL,
  calculated_risk INTEGER NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('ALLOWED', 'BLOCKED')),
  reason TEXT NOT NULL,
  verification_latency_ms REAL,
  event_type TEXT,
  integrity_hash TEXT,
  prev_hash TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_username ON security_audit_logs(username);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON security_audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_status ON security_audit_logs(status);

-- 4. Dedicated Security Events Table with High-Resolution Verification Latency
CREATE TABLE IF NOT EXISTS security_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL DEFAULT (datetime('now')),
  username TEXT NOT NULL,
  requested_function TEXT NOT NULL,
  calculated_risk INTEGER NOT NULL,
  status TEXT NOT NULL,
  reason TEXT NOT NULL,
  verification_latency_ms REAL,
  event_type TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_events_latency ON security_events(verification_latency_ms);
CREATE INDEX IF NOT EXISTS idx_events_type ON security_events(event_type);

-- 4b. Primary Audit Events Table capturing pipeline verification duration
CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL DEFAULT (datetime('now')),
  username TEXT NOT NULL,
  requested_function TEXT NOT NULL,
  calculated_risk INTEGER NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('ALLOWED', 'BLOCKED')),
  reason TEXT NOT NULL,
  verification_latency_ms REAL NOT NULL,
  event_type TEXT,
  integrity_hash TEXT,
  prev_hash TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_events_latency ON audit_events(verification_latency_ms);
CREATE INDEX IF NOT EXISTS idx_audit_events_user ON audit_events(username);

-- 5. Enterprise Security Policy Configuration
CREATE TABLE IF NOT EXISTS policies (
  id TEXT PRIMARY KEY DEFAULT 'current_policy',
  max_risk_threshold INTEGER NOT NULL DEFAULT 75,
  sequence_violation_penalty INTEGER NOT NULL DEFAULT 40,
  enforce_strict_sequence INTEGER NOT NULL DEFAULT 1,
  global_lockdown INTEGER NOT NULL DEFAULT 0,
  require_admin_approval INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 6. Active Session and Token Revocation Registry (Real-time Session Revocation)
CREATE TABLE IF NOT EXISTS active_sessions (
  id TEXT PRIMARY KEY,
  token TEXT UNIQUE NOT NULL,
  username TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('Admin', 'Developer', 'Guest')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  revoked_at TEXT,
  revoked_by TEXT,
  revocation_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_sessions_token ON active_sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_username ON active_sessions(username);
CREATE INDEX IF NOT EXISTS idx_sessions_revoked ON active_sessions(revoked);

-- Seed Initial Security Principals
INSERT OR IGNORE INTO users (id, username, password_hash, password_salt, role, base_risk_score, status, department, email, mfa_secret, mfa_backup_codes, last_totp_step)
VALUES
  ('usr_secops_admin', 'secops_admin', '6fd9eca72eb6de8a3771a9eb5a932fe27ce2eca34c4542ef889021dbc1c8cef9d53beb2c69abf0eaf6ab8c72b6d73145ecab70bd0b3d6134a7b2343d970c302e', 'a1f8c29e4b6d3a7f80e5c1d2e3f4a5b6', 'Admin', 0, 'APPROVED', 'SecOps Core Operations', 'secops_admin@corp.internal', 'JBSWY3DPEHPK3PXP', '["28a78be9a0696a510de354eb442c1b4199d16b6b344817b3fd4cb9427e78b6af","f067b0c6798d0a64e8b6963c52cbc5d9dc441a497cb2ac1c52ce3a8f8704dd1f"]', 0),
  ('usr_cloud_dev', 'cloud_dev', '6fd9eca72eb6de8a3771a9eb5a932fe27ce2eca34c4542ef889021dbc1c8cef9d53beb2c69abf0eaf6ab8c72b6d73145ecab70bd0b3d6134a7b2343d970c302e', 'a1f8c29e4b6d3a7f80e5c1d2e3f4a5b6', 'Developer', 15, 'APPROVED', 'Cloud Platform Engineering', 'cloud_dev@corp.internal', 'JBSWY3DPEHPK3PXP', '["28a78be9a0696a510de354eb442c1b4199d16b6b344817b3fd4cb9427e78b6af","f067b0c6798d0a64e8b6963c52cbc5d9dc441a497cb2ac1c52ce3a8f8704dd1f"]', 0),
  ('usr_auditor_guest', 'auditor_guest', '6fd9eca72eb6de8a3771a9eb5a932fe27ce2eca34c4542ef889021dbc1c8cef9d53beb2c69abf0eaf6ab8c72b6d73145ecab70bd0b3d6134a7b2343d970c302e', 'a1f8c29e4b6d3a7f80e5c1d2e3f4a5b6', 'Guest', 30, 'APPROVED', 'Third-Party Compliance & SOC-2', 'auditor_guest@compliance-partner.com', 'JBSWY3DPEHPK3PXP', '["28a78be9a0696a510de354eb442c1b4199d16b6b344817b3fd4cb9427e78b6af","f067b0c6798d0a64e8b6963c52cbc5d9dc441a497cb2ac1c52ce3a8f8704dd1f"]', 0),
  ('usr_sarah_infra', 'sarah_infra', '6fd9eca72eb6de8a3771a9eb5a932fe27ce2eca34c4542ef889021dbc1c8cef9d53beb2c69abf0eaf6ab8c72b6d73145ecab70bd0b3d6134a7b2343d970c302e', 'a1f8c29e4b6d3a7f80e5c1d2e3f4a5b6', 'Developer', 10, 'APPROVED', 'Infrastructure & Edge Reliability', 'sarah_infra@corp.internal', 'JBSWY3DPEHPK3PXP', '["28a78be9a0696a510de354eb442c1b4199d16b6b344817b3fd4cb9427e78b6af","f067b0c6798d0a64e8b6963c52cbc5d9dc441a497cb2ac1c52ce3a8f8704dd1f"]', 0),
  ('usr_alex_contractor', 'alex_contractor', '6fd9eca72eb6de8a3771a9eb5a932fe27ce2eca34c4542ef889021dbc1c8cef9d53beb2c69abf0eaf6ab8c72b6d73145ecab70bd0b3d6134a7b2343d970c302e', 'a1f8c29e4b6d3a7f80e5c1d2e3f4a5b6', 'Developer', 25, 'PENDING_APPROVAL', 'Edge Pipeline Contractors', 'alex_contractor@contractor.internal', 'JBSWY3DPEHPK3PXP', '["28a78be9a0696a510de354eb442c1b4199d16b6b344817b3fd4cb9427e78b6af","f067b0c6798d0a64e8b6963c52cbc5d9dc441a497cb2ac1c52ce3a8f8704dd1f"]', 0),
  ('usr_threat_actor', 'threat_actor', '6fd9eca72eb6de8a3771a9eb5a932fe27ce2eca34c4542ef889021dbc1c8cef9d53beb2c69abf0eaf6ab8c72b6d73145ecab70bd0b3d6134a7b2343d970c302e', 'a1f8c29e4b6d3a7f80e5c1d2e3f4a5b6', 'Guest', 70, 'SUSPENDED', 'Untrusted Public Origin', 'threat_actor@darknet-proxy.io', 'JBSWY3DPEHPK3PXP', '["28a78be9a0696a510de354eb442c1b4199d16b6b344817b3fd4cb9427e78b6af","f067b0c6798d0a64e8b6963c52cbc5d9dc441a497cb2ac1c52ce3a8f8704dd1f"]', 0);

-- Seed Initial Markov Chain Sequences
INSERT OR IGNORE INTO function_rules (current_function, allowed_next_function)
VALUES
  ('login', 'getDashboardMetrics'),
  ('getDashboardMetrics', 'viewSecurityLogs'),
  ('viewSecurityLogs', 'deployWorkerCode'),
  ('deployWorkerCode', 'updateSystemPolicy'),
  ('viewSecurityLogs', 'rotateEncryptionKeys'),
  ('rotateEncryptionKeys', 'purgeColdStorageBackups');

-- Seed Default Policy
INSERT OR IGNORE INTO policies (id, max_risk_threshold, sequence_violation_penalty, enforce_strict_sequence, global_lockdown, require_admin_approval)
VALUES ('current_policy', 75, 40, 1, 0, 1);
