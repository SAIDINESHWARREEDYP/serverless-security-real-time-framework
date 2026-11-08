import { Request, Response } from 'express';
import { userRepository } from '../repositories/user.repository.ts';
import { auditRepository } from '../repositories/audit.repository.ts';

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
    const id = req.params.id || req.body.username || req.body.id;
    if (!id) {
      return res.status(400).json({ error: 'Username or user ID is required for approval.' });
    }
    const user = userRepository.findById(id) || userRepository.findByUsername(id);
    if (!user) {
      return res.status(404).json({ error: `User '${id}' not found.` });
    }

    const { role, base_risk_score } = req.body;
    const caller = req.user?.username || req.body.approvedBy || 'secops_admin';
    const nowIso = new Date().toISOString();

    const updated = userRepository.update(user.id, {
      status: 'APPROVED',
      approved_at: nowIso,
      approved_by: caller,
      ...(role ? { role } : {}),
      ...(typeof base_risk_score === 'number' ? { base_risk_score } : {})
    });

    auditRepository.record({
      username: caller,
      requested_function: `/api/v1/users/${user.username}/approve`,
      calculated_risk: 0,
      status: 'ALLOWED',
      reason: `[ADMIN CLEARANCE] User [${user.username}] APPROVED by ${caller}. Role: ${role || user.role}, Risk: ${base_risk_score ?? user.base_risk_score}%`,
      verification_latency_ms: 0.8,
      event_type: 'USER_APPROVED'
    });

    return res.json({
      success: true,
      user: userRepository.sanitize(updated || user),
      message: `User [${user.username}] approved and cleared for login.`
    });
  },

  rejectUser(req: Request, res: Response) {
    const id = req.params.id || req.body.username || req.body.id;
    if (!id) {
      return res.status(400).json({ error: 'Username or user ID is required for rejection.' });
    }
    const { reason } = req.body;
    const user = userRepository.findById(id) || userRepository.findByUsername(id);
    if (!user) {
      return res.status(404).json({ error: `User '${id}' not found.` });
    }

    const caller = req.user?.username || req.body.rejectedBy || 'secops_admin';
    const justification = reason ? `Rejected by ${caller}: ${reason}` : `Access rejected by ${caller}`;

    const updated = userRepository.update(user.id, {
      status: 'REJECTED'
    });

    auditRepository.record({
      username: caller,
      requested_function: `/api/v1/users/${user.username}/reject`,
      calculated_risk: user.base_risk_score,
      status: 'BLOCKED',
      reason: `[ADMIN REJECTION] User [${user.username}] access REJECTED by ${caller}. ${reason || ''}`,
      verification_latency_ms: 0.8,
      event_type: 'USER_REJECTED'
    });

    return res.json({
      success: true,
      user: userRepository.sanitize(updated || user),
      message: `Access request for [${user.username}] rejected.`
    });
  },

  updateStatus(req: Request, res: Response) {
    const { id } = req.params;
    const { status, role, base_risk_score, department } = req.body;
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
