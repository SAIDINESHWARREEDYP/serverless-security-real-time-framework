import { Request, Response } from 'express';
import { rbacRepository } from '../repositories/rbac.repository.ts';
import { userRepository } from '../repositories/user.repository.ts';

export const rbacController = {
  getRoles(req: Request, res: Response) {
    return res.json({
      success: true,
      roles: rbacRepository.getRoles(),
      canonicalRolesCount: 6
    });
  },

  getPermissions(req: Request, res: Response) {
    return res.json({
      success: true,
      permissions: rbacRepository.getPermissions(),
      totalPermissions: rbacRepository.getPermissions().length
    });
  },

  getMatrix(req: Request, res: Response) {
    return res.json({
      success: true,
      matrix: rbacRepository.getMatrix(),
      roles: rbacRepository.getRoles(),
      permissions: rbacRepository.getPermissions()
    });
  },

  assignRole(req: Request, res: Response) {
    const actor = req.user;
    if (!actor) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const { targetUsername, newRole, reason } = req.body;
    if (!targetUsername || !newRole) {
      return res.status(400).json({ error: 'targetUsername and newRole are required fields.' });
    }

    const targetUser = userRepository.findByUsername(targetUsername);
    if (!targetUser) {
      return res.status(404).json({ error: `Target principal [${targetUsername}] not found in database.` });
    }

    const result = rbacRepository.assignUserRole({
      targetUsername: targetUser.username,
      newRole,
      previousRole: targetUser.role,
      actorUsername: actor.username,
      actorRole: actor.role,
      reason,
      ipAddress: req.ip || req.socket.remoteAddress
    });

    if (!result.success) {
      return res.status(403).json({
        type: 'https://serverless-securityverification.ai.studio/errors/RBAC_ASSIGNMENT_DENIED',
        title: 'Role Assignment Denied',
        status: 403,
        error: result.error,
        errorCode: 'PRIVILEGE_ESCALATION_BLOCKED'
      });
    }

    // Persist user role in user repository
    const updated = userRepository.update(targetUser.id, { role: newRole as any });

    return res.json({
      success: true,
      message: `Role for principal [${targetUsername}] updated to [${newRole}].`,
      user: updated ? userRepository.sanitize(updated) : null
    });
  },

  getChangeHistory(req: Request, res: Response) {
    return res.json({
      success: true,
      history: rbacRepository.getPermissionChangeHistory()
    });
  },

  getAccessDeniedHistory(req: Request, res: Response) {
    return res.json({
      success: true,
      history: rbacRepository.getAccessDeniedHistory()
    });
  }
};
