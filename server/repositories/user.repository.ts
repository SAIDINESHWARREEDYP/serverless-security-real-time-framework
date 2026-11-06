import type { UserRecord, SanitizedUser, UserApprovalStatus, UserRoleType } from '../types/index.ts';
import { hashPassword, verifyPassword } from '../utils/crypto.ts';
import { db } from '../db.ts';

class UserRepository {
  public reset() {
    db.reset();
  }

  public findById(id: string): UserRecord | null {
    const user = db.getUser(id);
    if (!user) return null;
    return this.mapToUserRecord(user);
  }

  public findByUsername(username: string): UserRecord | null {
    if (!username) return null;
    const user = db.getUser(username);
    if (!user) return null;
    return this.mapToUserRecord(user);
  }

  public findAll(): UserRecord[] {
    const rawUsers = db.getUsers();
    return rawUsers.map((u) => this.mapToUserRecord(u));
  }

  public findAllSanitized(): SanitizedUser[] {
    const all = this.findAll();
    return all.map((u) => this.sanitize(u));
  }

  public sanitize(u: UserRecord | any): SanitizedUser {
    return {
      id: u.id,
      username: u.username,
      role: u.role,
      base_risk_score: u.base_risk_score,
      status: u.status,
      department: u.department,
      email: u.email,
      phone: u.phone,
      mfa_enabled: Boolean(u.mfa_enabled),
      mfa_secret: u.mfa_secret,
      mfa_backup_codes: Array.isArray(u.mfa_backup_codes)
        ? u.mfa_backup_codes
        : typeof u.mfa_backup_codes === 'string'
        ? JSON.parse(u.mfa_backup_codes)
        : [],
      created_at: u.created_at || u.createdAt,
      approved_at: u.approved_at || u.approvedAt,
      approved_by: u.approved_by || u.approvedBy,
      last_login_at: u.last_login_at || u.lastLoginAt,
      request_justification: u.request_justification || u.requestJustification
    };
  }

  public create(data: {
    username: string;
    password: string;
    role?: UserRoleType;
    base_risk_score?: number;
    status?: UserApprovalStatus;
    department?: string;
    email?: string;
    phone?: string;
    mfa_enabled?: boolean;
    request_justification?: string;
    approved_by?: string;
  }): UserRecord {
    const cleanUsername = data.username.trim();
    const { salt, hash } = hashPassword(data.password);
    const id = `usr_${Date.now().toString(36)}_${Math.random().toString(36).substring(2, 6)}`;
    const nowIso = new Date().toISOString();
    const isApproved = data.status === 'APPROVED';

    // Insert directly into persistent SQLite D1 table
    db.prepare(
      `INSERT INTO users (
        id, username, password_salt, password_hash, role, base_risk_score,
        status, department, email, phone, mfa_enabled, mfa_secret, mfa_backup_codes,
        created_at, approved_at, approved_by, last_totp_step
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      id,
      cleanUsername,
      salt,
      hash,
      data.role || 'Developer',
      typeof data.base_risk_score === 'number' ? data.base_risk_score : 20,
      data.status || 'PENDING_APPROVAL',
      data.department || 'General Engineering',
      data.email || `${cleanUsername.toLowerCase()}@corp.internal`,
      data.phone || '+1 (555) 019-8392',
      data.mfa_enabled ? 1 : 1,
      'JBSWY3DPEHPK3PXP', // Default TOTP enrollment secret
      JSON.stringify([
        '28a78be9a0696a510de354eb442c1b4199d16b6b344817b3fd4cb9427e78b6af',
        'f067b0c6798d0a64e8b6963c52cbc5d9dc441a497cb2ac1c52ce3a8f8704dd1f'
      ]),
      nowIso,
      isApproved ? nowIso : null,
      isApproved ? data.approved_by || 'SYSTEM' : null,
      0
    ).run();

    return this.findById(id)!;
  }

  public updatePassword(userId: string, newPlaintext: string): boolean {
    const user = this.findById(userId);
    if (!user) return false;
    const { salt, hash } = hashPassword(newPlaintext);
    db.prepare('UPDATE users SET password_salt = ?, password_hash = ? WHERE id = ?')
      .bind(salt, hash, user.id)
      .run();
    return true;
  }

  public update(userId: string, updates: Partial<UserRecord>): UserRecord | null {
    const user = this.findById(userId) || this.findByUsername(userId);
    if (!user) return null;

    const fields: string[] = [];
    const values: any[] = [];

    if (updates.role !== undefined) {
      fields.push('role = ?');
      values.push(updates.role);
    }
    if (typeof updates.base_risk_score === 'number') {
      fields.push('base_risk_score = ?');
      values.push(updates.base_risk_score);
    }
    if (updates.status !== undefined) {
      fields.push('status = ?');
      values.push(updates.status);
    }
    if (updates.department !== undefined) {
      fields.push('department = ?');
      values.push(updates.department);
    }
    if (updates.email !== undefined) {
      fields.push('email = ?');
      values.push(updates.email);
    }
    if (updates.phone !== undefined) {
      fields.push('phone = ?');
      values.push(updates.phone);
    }
    if (updates.mfa_enabled !== undefined) {
      fields.push('mfa_enabled = ?');
      values.push(updates.mfa_enabled ? 1 : 0);
    }
    if (updates.mfa_secret !== undefined) {
      fields.push('mfa_secret = ?');
      values.push(updates.mfa_secret);
    }
    if (updates.mfa_backup_codes !== undefined) {
      fields.push('mfa_backup_codes = ?');
      values.push(JSON.stringify(updates.mfa_backup_codes));
    }
    if (updates.last_totp_step !== undefined) {
      fields.push('last_totp_step = ?');
      values.push(updates.last_totp_step);
    }
    if (updates.approved_at !== undefined) {
      fields.push('approved_at = ?');
      values.push(updates.approved_at);
    }
    if (updates.approved_by !== undefined) {
      fields.push('approved_by = ?');
      values.push(updates.approved_by);
    }
    if (updates.last_login_at !== undefined) {
      fields.push('last_login_at = ?');
      values.push(updates.last_login_at);
    }

    if (fields.length > 0) {
      values.push(user.id);
      db.prepare(`UPDATE users SET ${fields.join(', ')} WHERE id = ?`).bind(...values).run();
    }

    return this.findById(user.id);
  }

  public delete(userIdOrUsername: string): boolean {
    const user = this.findById(userIdOrUsername) || this.findByUsername(userIdOrUsername);
    if (!user) return false;
    db.prepare('DELETE FROM users WHERE id = ?').bind(user.id).run();
    return true;
  }

  private mapToUserRecord(row: any): UserRecord {
    return {
      id: row.id,
      username: row.username,
      password_hash: row.password_hash,
      password_salt: row.password_salt || '',
      role: row.role as UserRoleType,
      base_risk_score: row.base_risk_score ?? 20,
      status: (row.status as UserApprovalStatus) || 'APPROVED',
      department: row.department,
      email: row.email,
      phone: row.phone,
      mfa_enabled: Boolean(row.mfa_enabled),
      mfa_secret: row.mfa_secret,
      mfa_backup_codes: Array.isArray(row.mfa_backup_codes)
        ? row.mfa_backup_codes
        : typeof row.mfa_backup_codes === 'string'
        ? JSON.parse(row.mfa_backup_codes)
        : [],
      last_totp_step: row.last_totp_step || 0,
      created_at: row.created_at || row.createdAt || new Date().toISOString(),
      approved_at: row.approved_at || row.approvedAt,
      approved_by: row.approved_by || row.approvedBy,
      last_login_at: row.last_login_at || row.lastLoginAt,
      request_justification: row.request_justification || row.requestJustification
    };
  }
}

export const userRepository = new UserRepository();
