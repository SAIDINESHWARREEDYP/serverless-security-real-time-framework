import { Request, Response, NextFunction } from 'express';
import { rbacRepository } from '../repositories/rbac.repository.ts';
import { auditRepository } from '../repositories/audit.repository.ts';
import type { UserRoleType } from '../types/index.ts';

export function requireRole(...allowedRoles: UserRoleType[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = req.user;
    if (!user) {
      return res.status(401).json({
        type: 'https://serverless-securityverification.ai.studio/errors/UNAUTHORIZED',
        title: 'Unauthorized',
        status: 401,
        detail: 'Authentication required prior to authorization.',
        instance: req.originalUrl,
        errorCode: 'UNAUTHORIZED'
      });
    }

    if (!allowedRoles.includes(user.role)) {
      const latencyMs = Number((performance.now() - (req.startTime || performance.now())).toFixed(3));
      res.setHeader('X-Verification-Latency-MS', latencyMs.toString());

      auditRepository.record({
        username: user.username,
        requested_function: req.originalUrl,
        calculated_risk: 90,
        status: 'BLOCKED',
        reason: `RBAC Violation: Role [${user.role}] is not authorized for this resource. Required: ${allowedRoles.join(', ')}`,
        verification_latency_ms: latencyMs,
        event_type: 'RBAC_VIOLATION'
      });

      return res.status(403).json({
        type: 'https://serverless-securityverification.ai.studio/errors/RBAC_ROLE_DENIED',
        title: 'Forbidden',
        status: 403,
        detail: `Access denied. Role [${user.role}] lacks required clearance. Required: ${allowedRoles.join(', ')}`,
        instance: req.originalUrl,
        errorCode: 'RBAC_ROLE_DENIED',
        traceId: req.traceId
      });
    }

    next();
  };
}

export function requirePermission(permissionName: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = req.user;
    if (!user) {
      return res.status(401).json({
        type: 'https://serverless-securityverification.ai.studio/errors/UNAUTHORIZED',
        title: 'Unauthorized',
        status: 401,
        detail: 'Authentication required prior to authorization.',
        instance: req.originalUrl,
        errorCode: 'UNAUTHORIZED'
      });
    }

    const hasPerm = rbacRepository.hasPermission(user.role, permissionName);
    if (!hasPerm) {
      const latencyMs = Number((performance.now() - (req.startTime || performance.now())).toFixed(3));
      res.setHeader('X-Verification-Latency-MS', latencyMs.toString());

      auditRepository.record({
        username: user.username,
        requested_function: req.originalUrl,
        calculated_risk: 90,
        status: 'BLOCKED',
        reason: `RBAC Permission Denied: Role [${user.role}] lacks permission [${permissionName}].`,
        verification_latency_ms: latencyMs,
        event_type: 'RBAC_VIOLATION'
      });

      return res.status(403).json({
        type: 'https://serverless-securityverification.ai.studio/errors/RBAC_PERMISSION_DENIED',
        title: 'Permission Denied',
        status: 403,
        detail: `Access denied. Missing required permission: [${permissionName}].`,
        instance: req.originalUrl,
        errorCode: 'RBAC_PERMISSION_DENIED',
        traceId: req.traceId
      });
    }

    next();
  };
}
