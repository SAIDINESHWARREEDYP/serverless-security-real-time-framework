import { db } from '../db.ts';
import { hashPassword } from '../utils/crypto.ts';
import { userRepository } from './user.repository.ts';
import { sessionRepository } from './session.repository.ts';
import { auditRepository } from './audit.repository.ts';

export interface PasswordChangeRequest {
  id: string;
  user_id: string;
  username: string;
  new_password_hash: string;
  new_password_salt: string;
  status: 'PENDING' | 'APPROVED' | 'REJECTED';
  requested_at: string;
  reviewed_at?: string;
  reviewed_by?: string;
  justification?: string;
  rejection_reason?: string;
}

export interface SanitizedPasswordChangeRequest {
  id: string;
  user_id: string;
  username: string;
  status: 'PENDING' | 'APPROVED' | 'REJECTED';
  requested_at: string;
  reviewed_at?: string;
  reviewed_by?: string;
  justification?: string;
  rejection_reason?: string;
}

export class PasswordRequestRepository {
  /**
   * Submits a new password change request.
   * Hashes the requested new password with PBKDF2 & unique salt immediately,
   * so plaintext password is never stored or revealed.
   */
  public create(params: {
    username: string;
    newPasswordPlaintext: string;
    justification?: string;
  }): SanitizedPasswordChangeRequest {
    const user = userRepository.findByUsername(params.username);
    if (!user) {
      throw new Error(`Identity [${params.username}] not found in database.`);
    }

    const { salt, hash } = hashPassword(params.newPasswordPlaintext);
    const id = `pwd_req_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
    const now = new Date().toISOString();

    db.prepare(`
      INSERT INTO password_change_requests (
        id, user_id, username, new_password_hash, new_password_salt,
        status, requested_at, justification
      ) VALUES (?, ?, ?, ?, ?, 'PENDING', ?, ?)
    `).bind(
      id,
      user.id,
      user.username,
      hash,
      salt,
      now,
      params.justification || 'User requested password change via Zero-Trust portal'
    ).run();

    auditRepository.record({
      username: user.username,
      requested_function: '/api/v1/password-requests/submit',
      calculated_risk: 15,
      status: 'ALLOWED',
      reason: `[PASSWORD CHANGE REQUESTED] Identity [${user.username}] submitted a password update request. Awaiting Admin clearance.`,
      verification_latency_ms: 1.2,
      event_type: 'PASSWORD_CHANGE_REQUESTED'
    });

    return {
      id,
      user_id: user.id,
      username: user.username,
      status: 'PENDING',
      requested_at: now,
      justification: params.justification
    };
  }

  /**
   * List all password change requests with sanitized credentials (never expose hashes).
   */
  public list(statusFilter?: string): SanitizedPasswordChangeRequest[] {
    let sql = 'SELECT id, user_id, username, status, requested_at, reviewed_at, reviewed_by, justification, rejection_reason FROM password_change_requests';
    const params: any[] = [];
    if (statusFilter && statusFilter !== 'ALL') {
      sql += ' WHERE status = ?';
      params.push(statusFilter);
    }
    sql += ' ORDER BY requested_at DESC';

    const res = db.prepare(sql).bind(...params).all<SanitizedPasswordChangeRequest>();
    return res.results || [];
  }

  /**
   * Find raw request including cryptographic hashes (internal only).
   */
  public findRawById(id: string): PasswordChangeRequest | null {
    return db.prepare('SELECT * FROM password_change_requests WHERE id = ?').bind(id).first<PasswordChangeRequest>();
  }

  /**
   * Admin accepts and commits the password change request into the database.
   */
  public approve(id: string, adminUsername: string): { success: boolean; username: string; message: string } {
    const req = this.findRawById(id);
    if (!req) {
      throw new Error(`Password change request [${id}] not found.`);
    }

    if (req.status !== 'PENDING') {
      throw new Error(`Request is already ${req.status}. Cannot re-approve.`);
    }

    const now = new Date().toISOString();

    // 1. Commit new password hash and salt into the users table in database
    db.prepare('UPDATE users SET password_salt = ?, password_hash = ? WHERE id = ?')
      .bind(req.new_password_salt, req.new_password_hash, req.user_id)
      .run();

    // 2. Mark password change request as APPROVED
    db.prepare(`
      UPDATE password_change_requests 
      SET status = 'APPROVED', reviewed_at = ?, reviewed_by = ?
      WHERE id = ?
    `).bind(now, adminUsername, id).run();

    // 3. Invalidate existing sessions for security
    sessionRepository.revoke({
      username: req.username,
      revokedBy: adminUsername,
      reason: 'Password change approved by Administrator'
    });

    // 4. Record tamper-evident audit event
    auditRepository.record({
      username: req.username,
      requested_function: '/api/v1/password-requests/approve',
      calculated_risk: 5,
      status: 'ALLOWED',
      reason: `[PASSWORD CHANGE APPROVED] Administrator [${adminUsername}] approved and committed new password for user [${req.username}] into DB.`,
      verification_latency_ms: 1.4,
      event_type: 'PASSWORD_CHANGE_APPROVED'
    });

    return {
      success: true,
      username: req.username,
      message: `Password change request for [${req.username}] approved and updated in database!`
    };
  }

  /**
   * Admin rejects the password change request.
   */
  public reject(id: string, adminUsername: string, reason?: string): { success: boolean; username: string; message: string } {
    const req = this.findRawById(id);
    if (!req) {
      throw new Error(`Password change request [${id}] not found.`);
    }

    if (req.status !== 'PENDING') {
      throw new Error(`Request is already ${req.status}. Cannot re-reject.`);
    }

    const now = new Date().toISOString();
    const rejectionReason = reason || 'Declined by Administrator per Security Policy';

    db.prepare(`
      UPDATE password_change_requests 
      SET status = 'REJECTED', reviewed_at = ?, reviewed_by = ?, rejection_reason = ?
      WHERE id = ?
    `).bind(now, adminUsername, rejectionReason, id).run();

    auditRepository.record({
      username: req.username,
      requested_function: '/api/v1/password-requests/reject',
      calculated_risk: 30,
      status: 'BLOCKED',
      reason: `[PASSWORD CHANGE REJECTED] Administrator [${adminUsername}] rejected password change request for [${req.username}]: ${rejectionReason}`,
      verification_latency_ms: 1.1,
      event_type: 'PASSWORD_CHANGE_REJECTED'
    });

    return {
      success: true,
      username: req.username,
      message: `Password change request for [${req.username}] rejected.`
    };
  }
}

export const passwordRequestRepository = new PasswordRequestRepository();
