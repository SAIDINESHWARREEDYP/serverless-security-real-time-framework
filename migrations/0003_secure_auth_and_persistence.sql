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

-- 2. Upgrade seeded principals to genuine PBKDF2-SHA512 password hashes and secure MFA secrets
-- Password for all default test seeds: 'ZeroTrust_2026'
UPDATE users SET 
  password_salt = 'a1f8c29e4b6d3a7f80e5c1d2e3f4a5b6',
  password_hash = '6fd9eca72eb6de8a3771a9eb5a932fe27ce2eca34c4542ef889021dbc1c8cef9d53beb2c69abf0eaf6ab8c72b6d73145ecab70bd0b3d6134a7b2343d970c302e',
  mfa_secret = 'JBSWY3DPEHPK3PXP',
  mfa_backup_codes = '["28a78be9a0696a510de354eb442c1b4199d16b6b344817b3fd4cb9427e78b6af","f067b0c6798d0a64e8b6963c52cbc5d9dc441a497cb2ac1c52ce3a8f8704dd1f","b2d6d45ffdbd2ec495d69e642343a1b83ec1ed22e58221eae54ac00df1577152","59294c3b8da03511ccba650818e3b885ade07dc3704d4ac3a8dd8a29d0e49124"]',
  last_totp_step = 0
WHERE username IN ('secops_admin', 'cloud_dev', 'auditor_guest', 'sarah_infra', 'alex_contractor', 'threat_actor');

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
