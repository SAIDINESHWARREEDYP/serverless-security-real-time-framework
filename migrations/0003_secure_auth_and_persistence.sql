-- ==============================================================================
-- Cloudflare D1 Database Migration: 0003_secure_auth_and_persistence.sql
-- Project: Design and Implementation of an Integrated Real-Time Security
--          Verification Framework for Serverless Cloud Applications
-- Description: Hardens user authentication with PBKDF2 salt, RFC 6238 TOTP secrets,
--              hashed one-time backup codes, TOTP step replay prevention,
--              and establishes persistent indexes for sessions and incidents.
-- ==============================================================================

PRAGMA foreign_keys = ON;

-- 1. Safely add security-critical columns to users table
ALTER TABLE users ADD COLUMN password_salt TEXT;
ALTER TABLE users ADD COLUMN mfa_secret TEXT;
ALTER TABLE users ADD COLUMN mfa_backup_codes TEXT;
ALTER TABLE users ADD COLUMN last_totp_step INTEGER DEFAULT 0;

-- 1b. Add cryptographic hash-chaining columns to audit_events table
ALTER TABLE audit_events ADD COLUMN integrity_hash TEXT;
ALTER TABLE audit_events ADD COLUMN prev_hash TEXT;

-- 2. Credential salts, PBKDF2-SHA512 hashes, unique TOTP secrets, and hashed recovery codes
-- are provisioned per identity via CSPRNG during runtime bootstrap (never statically in SQL).
UPDATE users SET last_totp_step = COALESCE(last_totp_step, 0) WHERE last_totp_step IS NULL;

-- 3. Ensure Incidents Table exists and has required forensic fields
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
CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at DESC);

-- 4. Ensure Sessions Table exists and has active/revoked index
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

-- 5. Persistent MFA Challenges Registry (RFC 6238 TOTP Session Challenges)
CREATE TABLE IF NOT EXISTS mfa_challenges (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  challenge_token TEXT UNIQUE NOT NULL,
  expires_at TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 5,
  consumed INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_mfa_challenges_token ON mfa_challenges(challenge_token);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_user ON mfa_challenges(user_id);

-- 6. Identity & Credential Governance: Password Change Requests
CREATE TABLE IF NOT EXISTS password_change_requests (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  username TEXT NOT NULL,
  new_password_hash TEXT NOT NULL,
  new_password_salt TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'PENDING' CHECK(status IN ('PENDING', 'APPROVED', 'REJECTED')),
  requested_at TEXT NOT NULL,
  reviewed_at TEXT,
  reviewed_by TEXT,
  justification TEXT,
  rejection_reason TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_password_req_status ON password_change_requests(status);
CREATE INDEX IF NOT EXISTS idx_password_req_user ON password_change_requests(user_id);

-- 7. Identity & Credential Governance: Username Change Requests
CREATE TABLE IF NOT EXISTS username_change_requests (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  current_username TEXT NOT NULL,
  requested_username TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'PENDING' CHECK(status IN ('PENDING', 'APPROVED', 'REJECTED')),
  requested_at TEXT NOT NULL,
  reviewed_at TEXT,
  reviewed_by TEXT,
  justification TEXT,
  rejection_reason TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_username_req_status ON username_change_requests(status);
CREATE INDEX IF NOT EXISTS idx_username_req_user ON username_change_requests(user_id);

-- 8. High-Assurance Administrative Decision & Approval Records
CREATE TABLE IF NOT EXISTS administrative_approval_records (
  id TEXT PRIMARY KEY,
  request_type TEXT NOT NULL,
  target_id TEXT NOT NULL,
  target_identifier TEXT NOT NULL,
  action TEXT NOT NULL CHECK(action IN ('APPROVE', 'REJECT')),
  admin_id TEXT NOT NULL,
  admin_username TEXT NOT NULL,
  reason TEXT,
  timestamp TEXT NOT NULL,
  ip_address TEXT
);

CREATE INDEX IF NOT EXISTS idx_admin_approvals_target ON administrative_approval_records(target_id);
CREATE INDEX IF NOT EXISTS idx_admin_approvals_admin ON administrative_approval_records(admin_username);

