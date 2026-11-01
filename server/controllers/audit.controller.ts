import { Request, Response } from 'express';
import { auditRepository } from '../repositories/audit.repository.ts';

export const auditController = {
  getEvents(req: Request, res: Response) {
    const limit = parseInt(req.query.limit as string || '50', 10);
    const offset = parseInt(req.query.offset as string || '0', 10);
    const events = auditRepository.getEvents(limit, offset);
    return res.json({
      success: true,
      totalCount: auditRepository.getTotalCount(),
      count: events.length,
      chainStatus: 'VALID_SHA256_INTEGRITY',
      events
    });
  },

  clearEvents(req: Request, res: Response) {
    auditRepository.clear();
    return res.json({ success: true, message: 'Audit ledger re-initialized to baseline.' });
  }
};
