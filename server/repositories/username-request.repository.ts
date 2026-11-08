import { db } from '../db.ts';
import { userRepository } from './user.repository.ts';
import { sessionRepository } from './session.repository.ts';
import { auditRepository } from './audit.repository.ts';
import { validateUsername } from '../validators/auth.validator.ts';

export interface UsernameChangeRequest {
  id: string;
  user_id: string;
  current_username: string;
  requested_username: string;
  status: 'PENDING' | 'APPROVED' | 'REJECTED';
  requested_at: string;
  reviewed_at?: string;
  reviewed_by?: string;
  justification?: string;
  rejection_reason?: string;
}

export class UsernameRequestRepository {
  /**
   * Submits a new username change request for Admin approval.
   */
  public create(params: {
    currentUsername: string;
    requestedUsername: string;
    justification?: string;
  }): UsernameChangeRequest {
    const curClean = params.currentUsername.trim();
    const reqClean = params.requestedUsername.trim();

    if (!curClean) {
      throw new Error('Current username is required.');
    }
    if (!reqClean) {
      throw new Error('Requested new username is required.');
    }
    if (curClean.toLowerCase() === reqClean.toLowerCase()) {
      throw new Error('Requested username must be different from current username.');
    }

    const val = validateUsername(reqClean);
    if (!val.valid) {
      throw new Error(val.error || 'Requested username does not satisfy complexity requirements.');
    }

    const user = userRepository.findByUsername(curClean);
    if (!user) {
      throw new Error(`Current identity [${curClean}] not found in database.`);
    }

    const existingTarget = userRepository.findByUsername(reqClean);
    if (existingTarget) {
      throw new Error(`Username [${reqClean}] is already registered in the system.`);
    }

    // Check if there is already a pending request for this username
    const existingPending = db.prepare(
      "SELECT id FROM username_change_requests WHERE requested_username = ? AND status = 'PENDING'"
    ).bind(reqClean).first();
    if (existingPending) {
      throw new Error(`A pending request for username [${reqClean}] is already awaiting Admin approval.`);
    }

    const id = `usr_req_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
    const now = new Date().toISOString();

    db.prepare(`
      INSERT INTO username_change_requests (
        id, user_id, current_username, requested_username,
        status, requested_at, justification
      ) VALUES (?, ?, ?, ?, 'PENDING', ?, ?)
    `).bind(
      id,
      user.id,
      user.username,
      reqClean,
      now,
      params.justification || 'User requested username change via Zero-Trust portal'
    ).run();

    auditRepository.record({
      username: user.username,
      requested_function: '/api/v1/username-requests/submit',
      calculated_risk: 15,
      status: 'ALLOWED',
      reason: `[USERNAME CHANGE REQUESTED] Principal [${user.username}] requested username change to [${reqClean}]. Awaiting Admin clearance.`,
      verification_latency_ms: 1.1,
      event_type: 'USERNAME_CHANGE_REQUESTED'
    });

    return {
      id,
      user_id: user.id,
      current_username: user.username,
      requested_username: reqClean,
      status: 'PENDING',
      requested_at: now,
      justification: params.justification
    };
  }

  /**
   * List username change requests.
   */
  public list(statusFilter?: string): UsernameChangeRequest[] {
    let sql = 'SELECT * FROM username_change_requests';
    const params: any[] = [];
    if (statusFilter && statusFilter !== 'ALL') {
      sql += ' WHERE status = ?';
      params.push(statusFilter);
    }
    sql += ' ORDER BY requested_at DESC';

    const res = db.prepare(sql).bind(...params).all<UsernameChangeRequest>();
    return res.results || [];
  }

  /**
   * Find request by ID.
   */
  public findById(id: string): UsernameChangeRequest | null {
    return db.prepare('SELECT * FROM username_change_requests WHERE id = ?').bind(id).first<UsernameChangeRequest>();
  }

  /**
   * Admin accepts and commits the username change into the database.
   */
  public approve(id: string, adminUsername: string): { success: boolean; oldUsername: string; newUsername: string; message: string } {
    const req = this.findById(id);
    if (!req) {
      throw new Error(`Username change request [${id}] not found.`);
    }

    if (req.status !== 'PENDING') {
      throw new Error(`Request is already ${req.status}. Cannot re-approve.`);
    }

    const collision = userRepository.findByUsername(req.requested_username);
    if (collision && collision.id !== req.user_id) {
      throw new Error(`Cannot approve: username [${req.requested_username}] was registered by another user in the interim.`);
    }

    const now = new Date().toISOString();

    // 1. Commit new username into the users table
    db.prepare('UPDATE users SET username = ? WHERE id = ?')
      .bind(req.requested_username, req.user_id)
      .run();

    // 2. Mark request as APPROVED
    db.prepare(`
      UPDATE username_change_requests 
      SET status = 'APPROVED', reviewed_at = ?, reviewed_by = ?
      WHERE id = ?
    `).bind(now, adminUsername, id).run();

    // 3. Invalidate previous active sessions so user must re-authenticate with their new identity
    sessionRepository.revoke({
      username: req.current_username,
      revokedBy: adminUsername,
      reason: `Username changed to ${req.requested_username}`
    });

    // 4. Record tamper-evident audit log
    auditRepository.record({
      username: req.requested_username,
      requested_function: '/api/v1/username-requests/approve',
      calculated_risk: 5,
      status: 'ALLOWED',
      reason: `[USERNAME CHANGE APPROVED] Administrator [${adminUsername}] approved username change from [${req.current_username}] to [${req.requested_username}] in D1 database.`,
      verification_latency_ms: 1.3,
      event_type: 'USERNAME_CHANGE_APPROVED'
    });

    return {
      success: true,
      oldUsername: req.current_username,
      newUsername: req.requested_username,
      message: `Username change from [${req.current_username}] to [${req.requested_username}] approved and saved to database!`
    };
  }

  /**
   * Admin rejects the username change request.
   */
  public reject(id: string, adminUsername: string, reason?: string): { success: boolean; username: string; message: string } {
    const req = this.findById(id);
    if (!req) {
      throw new Error(`Username change request [${id}] not found.`);
    }

    if (req.status !== 'PENDING') {
      throw new Error(`Request is already ${req.status}. Cannot re-reject.`);
    }

    const now = new Date().toISOString();
    const rejectionReason = reason || 'Declined by Administrator per Security Policy';

    db.prepare(`
      UPDATE username_change_requests 
      SET status = 'REJECTED', reviewed_at = ?, reviewed_by = ?, rejection_reason = ?
      WHERE id = ?
    `).bind(now, adminUsername, rejectionReason, id).run();

    auditRepository.record({
      username: req.current_username,
      requested_function: '/api/v1/username-requests/reject',
      calculated_risk: 25,
      status: 'BLOCKED',
      reason: `[USERNAME CHANGE REJECTED] Administrator [${adminUsername}] rejected username change to [${req.requested_username}] for [${req.current_username}]: ${rejectionReason}`,
      verification_latency_ms: 1.1,
      event_type: 'USERNAME_CHANGE_REJECTED'
    });

    return {
      success: true,
      username: req.current_username,
      message: `Username change request for [${req.current_username}] rejected.`
    };
  }
}

export const usernameRequestRepository = new UsernameRequestRepository();
