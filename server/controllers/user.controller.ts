import crypto from 'crypto';
import { Request, Response } from 'express';
import { userRepository } from '../repositories/user.repository.ts';
import { auditRepository } from '../repositories/audit.repository.ts';

const ALLOWED_ROLES = new Set([
  'Admin',
  'Administrator',
  'Super Administrator',
  'Security Administrator',
  'Security Analyst',
  'Developer',
  'Auditor',
  'Viewer',
  'Guest'
]);
const ALLOWED_STATUSES = new Set(['APPROVED', 'PENDING_APPROVAL', 'REJECTED', 'SUSPENDED']);

export const userController = {
  getUsers(req: Request, res: Response) {
    const users = userRepository.findAllSanitized();
    return res.json({ success: true, count: users.length, users });
  },

  getUserById(req: Request, res: Response) {
    const { id } = req.params;
    const user = userRepository.findById(id) || userRepository.findByUsername(id);
    if (!user) {
      return res.status(404).json({ error: `User '${id}' not found.` });
    }
    return res.json({ success: true, user: userRepository.sanitize(user) });
  },

  approveUser(req: Request, res: Response) {
    const caller = req.user?.username;
    if (!caller) {
      return res.status(401).json({ error: 'Unauthorized: Valid authenticated administrator session required.' });
    }

    const id = req.params.id || req.body.username || req.body.id;
    if (!id) {
      return res.status(400).json({ error: 'Username or user ID is required for approval.' });
    }
    const user = userRepository.findById(id) || userRepository.findByUsername(id);
    if (!user) {
      return res.status(404).json({ error: `User '${id}' not found.` });
    }

    if (user.username.toLowerCase() === caller.toLowerCase()) {
      return res.status(403).json({ error: 'Zero-Trust Policy Violation: Self-approval of user clearance is prohibited.' });
    }

    if (user.status === 'APPROVED') {
      return res.status(409).json({ error: `User [${user.username}] is already approved.` });
    }

    const { role, base_risk_score } = req.body;
    if (role !== undefined && !ALLOWED_ROLES.has(role)) {
      return res.status(400).json({ error: `Invalid role specified: ${role}` });
    }
    if (base_risk_score !== undefined && (typeof base_risk_score !== 'number' || base_risk_score < 0 || base_risk_score > 100)) {
      return res.status(400).json({ error: 'base_risk_score must be a number between 0 and 100.' });
    }
    const nowIso = new Date().toISOString();

    const updated = userRepository.update(user.id, {
      status: 'APPROVED',
      approved_at: nowIso,
      approved_by: caller,
      ...(role ? { role } : {}),
      ...(typeof base_risk_score === 'number' ? { base_risk_score } : {})
    });

    if (!updated) {
      return res.status(500).json({ error: `Failed to persist approval status for user '${user.username}'.` });
    }

    // Persist administrative decision record
    userRepository.recordAdminApproval({
      id: `appr_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,
      request_type: 'USER_CLEARANCE_APPROVAL',
      target_id: user.id,
      target_identifier: user.username,
      action: 'APPROVE',
      admin_id: req.user?.id || caller,
      admin_username: caller,
      reason: `Role: ${role || user.role}, Risk: ${base_risk_score ?? user.base_risk_score}%`,
      timestamp: nowIso,
      ip_address: req.ip || '127.0.0.1'
    });

    auditRepository.record({
      username: caller,
      requested_function: `/api/v1/users/${user.username}/approve`,
      calculated_risk: 0,
      status: 'ALLOWED',
      reason: `[ADMIN CLEARANCE] User [${user.username}] APPROVED by authenticated Administrator ${caller}. Role: ${role || user.role}, Risk: ${base_risk_score ?? user.base_risk_score}%`,
      verification_latency_ms: 0.8,
      event_type: 'USER_APPROVED'
    });

    return res.json({
      success: true,
      user: userRepository.sanitize(updated),
      message: `User [${user.username}] approved and cleared for login.`
    });
  },

  rejectUser(req: Request, res: Response) {
    const caller = req.user?.username;
    if (!caller) {
      return res.status(401).json({ error: 'Unauthorized: Valid authenticated administrator session required.' });
    }

    const id = req.params.id || req.body.username || req.body.id;
    if (!id) {
      return res.status(400).json({ error: 'Username or user ID is required for rejection.' });
    }
    const { reason } = req.body;
    const user = userRepository.findById(id) || userRepository.findByUsername(id);
    if (!user) {
      return res.status(404).json({ error: `User '${id}' not found.` });
    }

    if (user.username.toLowerCase() === caller.toLowerCase()) {
      return res.status(403).json({ error: 'Zero-Trust Policy Violation: Self-rejection/action on own identity is prohibited.' });
    }

    if (user.status === 'REJECTED') {
      return res.status(409).json({ error: `User [${user.username}] is already rejected.` });
    }

    const nowIso = new Date().toISOString();
    const updated = userRepository.update(user.id, {
      status: 'REJECTED'
    });

    if (!updated) {
      return res.status(500).json({ error: `Failed to persist rejection status for user '${user.username}'.` });
    }

    userRepository.recordAdminApproval({
      id: `appr_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,
      request_type: 'USER_CLEARANCE_REJECTION',
      target_id: user.id,
      target_identifier: user.username,
      action: 'REJECT',
      admin_id: req.user?.id || caller,
      admin_username: caller,
      reason: reason || 'Access denied by SecOps Administrator',
      timestamp: nowIso,
      ip_address: req.ip || '127.0.0.1'
    });

    auditRepository.record({
      username: caller,
      requested_function: `/api/v1/users/${user.username}/reject`,
      calculated_risk: user.base_risk_score,
      status: 'BLOCKED',
      reason: `[ADMIN REJECTION] User [${user.username}] access REJECTED by authenticated Administrator ${caller}. ${reason || ''}`,
      verification_latency_ms: 0.8,
      event_type: 'USER_REJECTED'
    });

    return res.json({
      success: true,
      user: userRepository.sanitize(updated),
      message: `Access request for [${user.username}] rejected.`
    });
  },

  updateStatus(req: Request, res: Response) {
    const { id } = req.params;
    const { status, role, base_risk_score, department } = req.body;
    if (status !== undefined && !ALLOWED_STATUSES.has(status)) {
      return res.status(400).json({ error: `Invalid status specified: ${status}` });
    }
    if (role !== undefined && !ALLOWED_ROLES.has(role)) {
      return res.status(400).json({ error: `Invalid role specified: ${role}` });
    }
    if (base_risk_score !== undefined && (typeof base_risk_score !== 'number' || base_risk_score < 0 || base_risk_score > 100)) {
      return res.status(400).json({ error: 'base_risk_score must be a number between 0 and 100.' });
    }
    const user = userRepository.findById(id) || userRepository.findByUsername(id);
    if (!user) {
      return res.status(404).json({ error: `User '${id}' not found.` });
    }

    const updated = userRepository.update(user.id, {
      status,
      role,
      base_risk_score,
      department
    });

    return res.json({ success: true, user: updated ? userRepository.sanitize(updated) : null });
  },

  deleteUser(req: Request, res: Response) {
    const { id } = req.params;
    if (id.toLowerCase() === 'secops_admin') {
      return res.status(400).json({ error: 'Cannot delete primary root SecOps Administrator.' });
    }

    const ok = userRepository.delete(id);
    if (!ok) {
      return res.status(404).json({ error: `User '${id}' not found.` });
    }

    return res.json({ success: true, message: `User '${id}' removed from database.` });
  }
};
