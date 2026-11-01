import { Request, Response } from 'express';
import { policyRepository } from '../repositories/policy.repository.ts';
import { auditRepository } from '../repositories/audit.repository.ts';

export const policyController = {
  getPolicy(req: Request, res: Response) {
    return res.json({ success: true, policy: policyRepository.getPolicy() });
  },

  updatePolicy(req: Request, res: Response) {
    const updates = req.body;
    const updated = policyRepository.updatePolicy(updates);

    const caller = req.user?.username || 'secops_admin';
    auditRepository.record({
      username: caller,
      requested_function: '/api/v1/policies',
      calculated_risk: 0,
      status: 'ALLOWED',
      reason: `[POLICY MUTATION] Security policy updated by ${caller}. Max risk: ${updated.maxRiskThreshold}%, Sequence penalty: ${updated.sequenceViolationPenalty}%`,
      verification_latency_ms: 0.9,
      event_type: 'POLICY_UPDATED'
    });

    return res.json({ success: true, policy: updated });
  },

  getRules(req: Request, res: Response) {
    return res.json({ success: true, rules: policyRepository.getRules() });
  },

  addRule(req: Request, res: Response) {
    const { current_function, allowed_next_function } = req.body;
    if (!current_function || !allowed_next_function) {
      return res.status(400).json({ error: 'current_function and allowed_next_function are required.' });
    }

    const rule = policyRepository.addRule(current_function, allowed_next_function);
    return res.json({ success: true, rule });
  },

  deleteRule(req: Request, res: Response) {
    const id = parseInt(req.params.id, 10);
    const ok = policyRepository.deleteRule(id);
    return res.json({ success: ok });
  }
};
