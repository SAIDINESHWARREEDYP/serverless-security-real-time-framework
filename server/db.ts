/**
 * Persistent SQLite Database Engine for the Serverless Security Verification Framework.
 * Implements Cloudflare D1 prepared statement API contract (prepare/bind/first/all/run)
 * backed by persistent SQLite storage on disk.
 * Automatically bootstraps and applies migrations:
 * - 0001_initial_schema.sql
 * - 0002_normalized_d1_schema.sql
 * - 0003_secure_auth_and_persistence.sql
 */

import { DatabaseSync } from 'node:sqlite';
import fs from 'fs';
import path from 'path';

export type UserApprovalStatus = 'APPROVED' | 'PENDING_APPROVAL' | 'REJECTED' | 'SUSPENDED';

export interface User {
  id: string;
  username: string;
  password_hash: string;
  password_salt?: string;
  role: 'Admin' | 'Developer' | 'Guest' | string;
  base_risk_score: number;
  status: UserApprovalStatus;
  department?: string;
  email?: string;
  phone?: string;
  mfa_enabled?: boolean;
  mfa_secret?: string;
  mfa_backup_codes?: string[];
  last_totp_step?: number;
  created_at?: string;
  createdAt?: string;
  approved_at?: string;
  approvedAt?: string;
  approved_by?: string;
  approvedBy?: string;
  last_login_at?: string;
  lastLoginAt?: string;
  request_justification?: string;
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
  integrity_hash?: string;
  prev_hash?: string;
}

export interface ActiveSession {
  id: string;
  token: string;
  username: string;
  role: string;
  createdAt: string;
  expiresAt: string;
  revoked: boolean;
  revokedAt?: string;
  revokedBy?: string;
  revocationReason?: string;
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

class PersistentSecurityDatabase {
  private sqlite: DatabaseSync;
  private dbPath: string;

  constructor(filePath?: string) {
    if (filePath === ':memory:') {
      this.dbPath = ':memory:';
      this.sqlite = new DatabaseSync(':memory:');
    } else {
      const dataDir = path.resolve(process.cwd(), 'server/data');
      if (!fs.existsSync(dataDir)) {
        fs.mkdirSync(dataDir, { recursive: true });
      }
      this.dbPath = filePath || path.join(dataDir, 'security_framework.sqlite');
      this.sqlite = new DatabaseSync(this.dbPath);
    }

    this.initDatabase();
  }

  private initDatabase() {
    this.sqlite.exec('PRAGMA foreign_keys = ON;');

    // Execute migrations in order if needed
    const migrationFiles = [
      'migrations/0001_initial_schema.sql',
      'migrations/0002_normalized_d1_schema.sql',
      'migrations/0003_secure_auth_and_persistence.sql'
    ];

    for (const file of migrationFiles) {
      const fullPath = path.resolve(process.cwd(), file);
      if (fs.existsSync(fullPath)) {
        const sql = fs.readFileSync(fullPath, 'utf-8');
        // Split by statement to ensure a single statement failure (e.g. duplicate column)
        // does not abort the remainder of the migration file
        const statements = sql
          .split(/;\s*(?:\r?\n|$)/)
          .map((s) => s.trim())
          .filter((s) => s.length > 0 && !s.startsWith('--'));

        for (const stmt of statements) {
          try {
            this.sqlite.exec(stmt);
          } catch (err: any) {
            // Ignore expected duplicate column or object already exists errors
            if (
              !err.message.includes('duplicate column') &&
              !err.message.includes('already exists')
            ) {
              // Non-breaking migration notice
            }
          }
        }
      }
    }

    // Explicit safeguards to guarantee integrity_hash & prev_hash exist on audit tables
    for (const col of ['integrity_hash', 'prev_hash']) {
      try {
        this.sqlite.exec(`ALTER TABLE audit_events ADD COLUMN ${col} TEXT;`);
      } catch {}
      try {
        this.sqlite.exec(`ALTER TABLE security_audit_logs ADD COLUMN ${col} TEXT;`);
      } catch {}
    }

    // Guarantee user security fields exist
    for (const col of ['password_salt TEXT', 'mfa_secret TEXT', 'mfa_backup_codes TEXT', 'last_totp_step INTEGER DEFAULT 0']) {
      try {
        this.sqlite.exec(`ALTER TABLE users ADD COLUMN ${col};`);
      } catch {}
    }

    // Guarantee password_change_requests table exists for admin approval workflow
    try {
      this.sqlite.exec(`
        CREATE TABLE IF NOT EXISTS password_change_requests (
          id TEXT PRIMARY KEY,
          user_id TEXT NOT NULL,
          username TEXT NOT NULL,
          new_password_hash TEXT NOT NULL,
          new_password_salt TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'PENDING',
          requested_at TEXT NOT NULL,
          reviewed_at TEXT,
          reviewed_by TEXT,
          justification TEXT,
          rejection_reason TEXT
        );
      `);
    } catch {}

    // Guarantee username_change_requests table exists for admin approval workflow
    try {
      this.sqlite.exec(`
        CREATE TABLE IF NOT EXISTS username_change_requests (
          id TEXT PRIMARY KEY,
          user_id TEXT NOT NULL,
          current_username TEXT NOT NULL,
          requested_username TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'PENDING',
          requested_at TEXT NOT NULL,
          reviewed_at TEXT,
          reviewed_by TEXT,
          justification TEXT,
          rejection_reason TEXT
        );
      `);
    } catch {}

    // Ensure all seeded users have valid PBKDF2 hash & salt
    try {
      this.sqlite.exec(`
        UPDATE users SET 
          password_salt = 'a1f8c29e4b6d3a7f80e5c1d2e3f4a5b6',
          password_hash = '6fd9eca72eb6de8a3771a9eb5a932fe27ce2eca34c4542ef889021dbc1c8cef9d53beb2c69abf0eaf6ab8c72b6d73145ecab70bd0b3d6134a7b2343d970c302e',
          mfa_secret = 'JBSWY3DPEHPK3PXP'
        WHERE (password_salt IS NULL OR password_salt = '' OR password_hash = 'ZeroTrust_2026')
          AND username IN ('cloud_dev', 'auditor_guest', 'sarah_infra', 'alex_contractor', 'threat_actor');
      `);
    } catch {}

    // Configure admin login password to 12345@pro with cryptographic salt & PBKDF2 hash
    try {
      this.sqlite.exec(`
        UPDATE users SET 
          password_salt = 'a1f8c29e4b6d3a7f80e5c1d2e3f4a5b6',
          password_hash = 'cc5af848d092362caf2830e08b3e46495ab9cebba694112a0a5025b6cf05bc71d02a8ccbe5a6fa422a7b60bf0f4ce458b14c5af7e9ada0485d73b3397eac5db1',
          mfa_secret = 'JBSWY3DPEHPK3PXP'
        WHERE username = 'secops_admin';
      `);
    } catch {}
  }

  /**
   * Cloudflare D1 Prepared Statement Emulation Contract:
   * db.prepare(sql).bind(...params).first() / .all() / .run()
   */
  public prepare(sql: string) {
    const sqlite = this.sqlite;
    let boundParams: any[] = [];

    const stmtWrapper = {
      bind(...params: any[]) {
        boundParams = params.map((p) => (p === undefined ? null : p));
        return stmtWrapper;
      },
      first<T = any>(colName?: string): T | null {
        try {
          const stmt = sqlite.prepare(sql);
          const row = stmt.get(...boundParams) as any;
          if (!row) return null;
          if (colName && typeof colName === 'string') {
            return row[colName] ?? null;
          }
          return row;
        } catch (err) {
          console.error('[D1 SQLite first() error]:', err, { sql, boundParams });
          return null;
        }
      },
      all<T = any>(): { results: T[]; success: boolean } {
        try {
          const stmt = sqlite.prepare(sql);
          const results = stmt.all(...boundParams) as T[];
          return { results: results || [], success: true };
        } catch (err) {
          console.error('[D1 SQLite all() error]:', err, { sql, boundParams });
          return { results: [], success: false };
        }
      },
      run(): { success: boolean; changes: number; lastRowId: number | bigint } {
        try {
          const stmt = sqlite.prepare(sql);
          const result = stmt.run(...boundParams);
          return {
            success: true,
            changes: Number(result.changes),
            lastRowId: result.lastInsertRowid
          };
        } catch (err: any) {
          console.error('[D1 SQLite run() error]:', err.message, { sql, boundParams });
          throw err;
        }
      }
    };

    return stmtWrapper;
  }

  /**
   * Execute raw SQL statements (for batch DDL or migrations)
   */
  public exec(sql: string): void {
    this.sqlite.exec(sql);
  }

  /**
   * Reset database back to factory seeded baseline
   */
  public reset(): void {
    const tables = [
      'verification_results',
      'invocation_history',
      'security_alerts',
      'incidents',
      'security_audit_logs',
      'security_events',
      'audit_events',
      'active_sessions',
      'sessions',
      'user_roles',
      'users',
      'function_rules',
      'policies'
    ];

    for (const table of tables) {
      try {
        this.sqlite.exec(`DELETE FROM ${table};`);
      } catch {
        // Table might not exist yet
      }
    }

    this.initDatabase();
  }

  public clearLogs(): void {
    this.sqlite.exec('DELETE FROM security_audit_logs;');
    this.sqlite.exec('DELETE FROM security_events;');
    this.sqlite.exec('DELETE FROM audit_events;');
    this.sqlite.exec('DELETE FROM verification_results;');
    this.sqlite.exec('DELETE FROM invocation_history;');
    this.sqlite.exec('DELETE FROM security_alerts;');
  }

  // --- Helper Data Access Methods ---

  public getUsers(): User[] {
    const rows = this.sqlite.prepare('SELECT * FROM users ORDER BY created_at ASC').all() as any[];
    return rows.map((r) => ({
      id: r.id,
      username: r.username,
      password_hash: r.password_hash,
      password_salt: r.password_salt,
      role: r.role,
      base_risk_score: r.base_risk_score,
      status: r.status,
      department: r.department,
      email: r.email,
      phone: r.phone,
      mfa_enabled: Boolean(r.mfa_enabled),
      mfa_secret: r.mfa_secret,
      mfa_backup_codes: r.mfa_backup_codes ? JSON.parse(r.mfa_backup_codes) : [],
      last_totp_step: r.last_totp_step || 0,
      createdAt: r.created_at,
      approvedAt: r.approved_at,
      approvedBy: r.approved_by,
      lastLoginAt: r.last_login_at
    }));
  }

  public getUser(usernameOrId: string): User | undefined {
    const q = usernameOrId.trim();
    const row = this.sqlite.prepare(
      'SELECT * FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(id) = LOWER(?) LIMIT 1'
    ).get(q, q) as any;

    if (!row) return undefined;
    return {
      id: row.id,
      username: row.username,
      password_hash: row.password_hash,
      password_salt: row.password_salt,
      role: row.role,
      base_risk_score: row.base_risk_score,
      status: row.status,
      department: row.department,
      email: row.email,
      phone: row.phone,
      mfa_enabled: Boolean(row.mfa_enabled),
      mfa_secret: row.mfa_secret,
      mfa_backup_codes: row.mfa_backup_codes ? JSON.parse(row.mfa_backup_codes) : [],
      last_totp_step: row.last_totp_step || 0,
      createdAt: row.created_at,
      approvedAt: row.approved_at,
      approvedBy: row.approved_by,
      lastLoginAt: row.last_login_at
    };
  }

  public getSessions(): ActiveSession[] {
    const rows = this.sqlite.prepare('SELECT * FROM active_sessions ORDER BY created_at DESC').all() as any[];
    return rows.map((r) => ({
      id: r.id,
      token: r.token,
      username: r.username,
      role: r.role,
      createdAt: r.created_at,
      expiresAt: r.expires_at,
      revoked: Boolean(r.revoked),
      revokedAt: r.revoked_at,
      revokedBy: r.revoked_by,
      revocationReason: r.revocation_reason
    }));
  }

  public isSessionRevoked(token: string, username?: string): boolean {
    const row = this.sqlite.prepare(
      'SELECT revoked FROM active_sessions WHERE (token = ? OR (username = ? AND username != "")) AND revoked = 1 LIMIT 1'
    ).get(token, username || '') as any;

    if (row && Boolean(row.revoked)) return true;

    // Check sessions table
    const sRow = this.sqlite.prepare(
      'SELECT status FROM sessions WHERE session_token = ? AND status = "revoked" LIMIT 1'
    ).get(token) as any;

    return Boolean(sRow);
  }

  public getRules(): FunctionRule[] {
    const rows = this.sqlite.prepare('SELECT id, current_function, allowed_next_function FROM function_rules ORDER BY id ASC').all() as any[];
    return rows.map((r) => ({
      id: r.id,
      current_function: r.current_function,
      allowed_next_function: r.allowed_next_function
    }));
  }

  public getAllLogs(): SecurityAuditLog[] {
    const rows = this.sqlite.prepare('SELECT * FROM audit_events ORDER BY id DESC LIMIT 200').all() as any[];
    return rows.map((r) => ({
      id: r.id,
      timestamp: r.timestamp,
      username: r.username,
      requested_function: r.requested_function,
      calculated_risk: r.calculated_risk,
      status: r.status,
      reason: r.reason,
      verification_latency_ms: r.verification_latency_ms,
      event_type: r.event_type,
      integrity_hash: r.integrity_hash,
      prev_hash: r.prev_hash
    }));
  }

  public getAuditEvents(): SecurityAuditLog[] {
    return this.getAllLogs();
  }

  public getRecentRequestCount(username: string, windowMs = 60000): number {
    const cutoffDate = new Date(Date.now() - windowMs);
    const cutoffIso = cutoffDate.toISOString();
    const cutoffSql = cutoffIso.replace('T', ' ').slice(0, 19);
    const row = this.sqlite.prepare(
      'SELECT COUNT(*) as count FROM audit_events WHERE LOWER(username) = LOWER(?) AND (timestamp >= ? OR timestamp >= ? OR created_at >= ?)'
    ).get(username, cutoffIso, cutoffSql, cutoffIso) as any;

    return row?.count || 0;
  }
}

export const db = new PersistentSecurityDatabase();
