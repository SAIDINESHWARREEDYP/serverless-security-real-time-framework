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
    const { id } = req.params;
    const user = userRepository.findById(id) || userRepository.findByUsername(id);
    if (!user) {
      return res.status(404).json({ error: `User '${id}' not found.` });
    }

    const { role, base_risk_score } = req.body;
    const caller = req.user?.username || 'secops_admin';

    user.status = 'APPROVED';
    user.approved_at = new Date().toISOString();
    user.approved_by = caller;
    if (role) user.role = role;
    if (typeof base_risk_score === 'number') user.base_risk_score = base_risk_score;

    auditRepository.record({
      username: caller,
      requested_function: `/api/v1/users/${user.username}/approve`,
      calculated_risk: 0,
      status: 'ALLOWED',
      reason: `[ADMIN CLEARANCE] Approved by ${caller}. Role: ${user.role}, Risk: ${user.base_risk_score}%`,
      verification_latency_ms: 0.8,
      event_type: 'USER_APPROVED'
    });

    return res.json({ success: true, user: userRepository.sanitize(user), message: `User [${user.username}] cleared.` });
  },

  rejectUser(req: Request, res: Response) {
    const { id } = req.params;
    const { reason } = req.body;
    const user = userRepository.findById(id) || userRepository.findByUsername(id);
    if (!user) {
      return res.status(404).json({ error: `User '${id}' not found.` });
    }

    const caller = req.user?.username || 'secops_admin';
    user.status = 'REJECTED';
    user.request_justification = reason ? `Rejected by ${caller}: ${reason}` : `Rejected by ${caller}`;

    auditRepository.record({
      username: caller,
      requested_function: `/api/v1/users/${user.username}/reject`,
      calculated_risk: user.base_risk_score,
      status: 'BLOCKED',
      reason: `[ADMIN REJECTED] Access rejected by ${caller}. ${reason || ''}`,
      verification_latency_ms: 0.8,
      event_type: 'USER_REJECTED'
    });

    return res.json({ success: true, user: userRepository.sanitize(user), message: `Access request for [${user.username}] rejected.` });
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
