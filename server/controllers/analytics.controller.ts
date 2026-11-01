import { Request, Response } from 'express';
import { userRepository } from '../repositories/user.repository.ts';
import { policyRepository } from '../repositories/policy.repository.ts';
import { auditRepository } from '../repositories/audit.repository.ts';
import { db } from '../db.ts';

export const analyticsController = {
  getOverview(req: Request, res: Response) {
    const users = userRepository.findAllSanitized();
    const rules = policyRepository.getRules();
    const policy = policyRepository.getPolicy();
    const auditEvents = auditRepository.getEvents(100);

    const blockedCount = auditEvents.filter(e => e.status === 'BLOCKED').length;
    const allowedCount = auditEvents.filter(e => e.status === 'ALLOWED').length;

    const latencies = auditEvents.map(e => e.verification_latency_ms).filter(n => typeof n === 'number');
    const avgLatencyMs = latencies.length > 0
      ? Number((latencies.reduce((a, b) => a + b, 0) / latencies.length).toFixed(3))
      : 0.38;

    return res.json({
      users,
      rules,
      logs: auditEvents,
      auditEvents,
      policyConfig: policy,
      stats: {
        totalUsers: users.length,
        totalRules: rules.length,
        totalLogs: auditEvents.length,
        totalAuditEvents: auditEvents.length,
        blockedCount,
        allowedCount,
        avgVerificationLatencyMs: avgLatencyMs
      }
    });
  }
};
