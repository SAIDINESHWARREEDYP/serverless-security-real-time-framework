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
  mfa_enrolled?: boolean;
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

/**
 * Comment- and string-aware SQL statement splitter for SQLite migrations.
 * Preserves multiline SQL statements that follow line or block comments
 * and only emits non-empty executable statements.
 */
export function splitSqlStatements(sql: string): string[] {
  const statements: string[] = [];
  let current = '';
  let hasExecutableSql = false;
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let inBacktick = false;
  let inBracketIdent = false;
  let inLineComment = false;
  let inBlockComment = false;

  for (let i = 0; i < sql.length; i++) {
    const ch = sql[i];
    const next = sql[i + 1];

    if (inLineComment) {
      if (ch === '\n') {
        inLineComment = false;
        current += ch;
      }
      continue;
    }

    if (inBlockComment) {
      if (ch === '*' && next === '/') {
        inBlockComment = false;
        i++;
      }
      continue;
    }

    if (inSingleQuote) {
      current += ch;
      if (ch === "'" && next === "'") {
        current += next;
        i++;
      } else if (ch === "'") {
        inSingleQuote = false;
      }
      continue;
    }

    if (inDoubleQuote) {
      current += ch;
      if (ch === '"' && next === '"') {
        current += next;
        i++;
      } else if (ch === '"') {
        inDoubleQuote = false;
      }
      continue;
    }

    if (inBacktick) {
      current += ch;
      if (ch === '`' && next === '`') {
        current += next;
        i++;
      } else if (ch === '`') {
        inBacktick = false;
      }
      continue;
    }

    if (inBracketIdent) {
      current += ch;
      if (ch === ']') {
        inBracketIdent = false;
      }
      continue;
    }

    // Outside quotes/comments
    if (ch === '-' && next === '-') {
      inLineComment = true;
      i++;
      continue;
    }

    if (ch === '/' && next === '*') {
      inBlockComment = true;
      i++;
      continue;
    }

    if (ch === "'") {
      inSingleQuote = true;
      hasExecutableSql = true;
      current += ch;
      continue;
    }

    if (ch === '"') {
      inDoubleQuote = true;
      hasExecutableSql = true;
      current += ch;
      continue;
    }

    if (ch === '`') {
      inBacktick = true;
      hasExecutableSql = true;
      current += ch;
      continue;
    }

    if (ch === '[') {
      inBracketIdent = true;
      hasExecutableSql = true;
      current += ch;
      continue;
    }

    if (ch === ';') {
      const trimmed = current.trim();
      if (trimmed.length > 0 && hasExecutableSql) {
        statements.push(trimmed);
      }
      current = '';
      hasExecutableSql = false;
      continue;
    }

    if (!/\s/.test(ch)) {
      hasExecutableSql = true;
    }
    current += ch;
  }

  const trailing = current.trim();
  if (trailing.length > 0 && hasExecutableSql) {
    statements.push(trailing);
  }

  return statements;
}

export class PersistentSecurityDatabase {
  private sqlite: DatabaseSync;
  private dbPath: string;

  constructor(filePath?: string) {
    if (filePath === ':memory:') {
      this.dbPath = ':memory:';
      this.sqlite = new DatabaseSync(':memory:');
    } else {
      const resolvedPath = filePath || path.join(path.resolve(process.cwd(), 'server/data'), 'security_framework.sqlite');
      const parentDir = path.dirname(resolvedPath);
      if (!fs.existsSync(parentDir)) {
        fs.mkdirSync(parentDir, { recursive: true });
      }
      this.dbPath = resolvedPath;
      this.sqlite = new DatabaseSync(this.dbPath);
    }

    this.initDatabase();
  }

  private getTableColumns(tableName: string): Set<string> {
    const safeName = tableName.replace(/[^a-zA-Z0-9_]/g, '');
    const rows = this.sqlite.prepare(`PRAGMA table_info(${safeName})`).all() as { name: string }[];
    return new Set(rows.map((r) => r.name.toLowerCase()));
  }

  private initDatabase() {
    this.sqlite.exec('PRAGMA foreign_keys = ON;');

    // 1. Establish migration version tracking table
    this.sqlite.exec(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version TEXT PRIMARY KEY,
        applied_at TEXT NOT NULL
      );
    `);

    const appliedVersions = new Set(
      (this.sqlite.prepare('SELECT version FROM schema_migrations').all() as { version: string }[]).map((r) => r.version)
    );

    // 2. Discover migration files deterministically in numeric filename order
    const migrationsDir = path.resolve(process.cwd(), 'migrations');
    const migrationFiles = fs.existsSync(migrationsDir)
      ? fs
          .readdirSync(migrationsDir)
          .filter((f) => /^\d+.*\.sql$/i.test(f))
          .sort((a, b) => a.localeCompare(b))
          .map((f) => path.join(migrationsDir, f))
      : [];

    for (const fullPath of migrationFiles) {
      const versionKey = path.basename(fullPath);
      if (appliedVersions.has(versionKey)) {
        continue;
      }

      const sql = fs.readFileSync(fullPath, 'utf-8');
      const statements = splitSqlStatements(sql);

      this.sqlite.exec('BEGIN IMMEDIATE;');
      try {
        for (let idx = 0; idx < statements.length; idx++) {
          const stmt = statements[idx];

          // PRAGMA foreign_keys cannot be toggled meaningfully inside a transaction; safe to skip if already set
          if (/^PRAGMA\s+foreign_keys\s*=/i.test(stmt)) {
            continue;
          }

          // Explicit schema inspection for ALTER TABLE ... ADD COLUMN ...
          const alterColMatch = stmt.match(
            /^ALTER\s+TABLE\s+["'`\[]?([a-zA-Z0-9_]+)["'`\]]?\s+ADD\s+COLUMN\s+["'`\[]?([a-zA-Z0-9_]+)["'`\]]?/i
          );
          if (alterColMatch) {
            const tableName = alterColMatch[1];
            const colName = alterColMatch[2].toLowerCase();
            const existingCols = this.getTableColumns(tableName);
            if (existingCols.size === 0) {
              throw new Error(
                `Migration failure in [${versionKey}] statement #${idx + 1}: target table [${tableName}] does not exist for "${stmt.slice(0, 120)}"`
              );
            }
            if (existingCols.has(colName)) {
              continue; // Column already exists in schema; safe skip via explicit PRAGMA check
            }
          }

          try {
            this.sqlite.exec(stmt);
          } catch (err: any) {
            throw new Error(
              `Migration failure in [${versionKey}] statement #${idx + 1}: "${stmt.slice(0, 140)}" -> ${err.message}`
            );
          }
        }

        this.sqlite
          .prepare('INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)')
          .run(versionKey, new Date().toISOString());

        this.sqlite.exec('COMMIT;');
      } catch (err) {
        try {
          this.sqlite.exec('ROLLBACK;');
        } catch {
          // ignore rollback error if transaction already aborted
        }
        throw err;
      }
    }

    // 3. Non-destructive upgrade ONLY for unmigrated/legacy seed passwords (never overwrite rotated passwords or secrets)
    const legacySeedHash =
      '6fd9eca72eb6de8a3771a9eb5a932fe27ce2eca34c4542ef889021dbc1c8cef9d53beb2c69abf0eaf6ab8c72b6d73145ecab70bd0b3d6134a7b2343d970c302e';

    this.sqlite.exec(`
      UPDATE users SET
        password_salt = 'a1f8c29e4b6d3a7f80e5c1d2e3f4a5b6',
        password_hash = '${legacySeedHash}',
        mfa_secret = COALESCE(NULLIF(mfa_secret, ''), 'JBSWY3DPEHPK3PXP')
      WHERE (password_salt IS NULL OR password_salt = '' OR password_hash = 'ZeroTrust_2026')
        AND username IN ('cloud_dev', 'auditor_guest', 'sarah_infra', 'alex_contractor', 'threat_actor');
    `);

    this.sqlite.exec(`
      UPDATE users SET
        password_salt = 'a1f8c29e4b6d3a7f80e5c1d2e3f4a5b6',
        password_hash = 'cc5af848d092362caf2830e08b3e46495ab9cebba694112a0a5025b6cf05bc71d02a8ccbe5a6fa422a7b60bf0f4ce458b14c5af7e9ada0485d73b3397eac5db1',
        mfa_secret = COALESCE(NULLIF(mfa_secret, ''), 'JBSWY3DPEHPK3PXP')
      WHERE username = 'secops_admin'
        AND (password_salt IS NULL OR password_salt = '' OR password_hash = 'ZeroTrust_2026' OR password_hash = '${legacySeedHash}');
    `);
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
      'mfa_challenges',
      'password_change_requests',
      'username_change_requests',
      'administrative_approval_records',
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
      'policies',
      'schema_migrations'
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
      mfa_enrolled: Boolean(r.mfa_enrolled),
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
      mfa_enrolled: Boolean(row.mfa_enrolled),
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
