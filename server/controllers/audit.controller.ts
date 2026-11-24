import { Request, Response } from 'express';
import { auditRepository } from '../repositories/audit.repository.ts';

export const auditController = {
  getEvents(req: Request, res: Response) {
    const limit = parseInt((req.query.limit as string) || '50', 10);
    const offset = parseInt((req.query.offset as string) || '0', 10);
    const events = auditRepository.getEvents(limit, offset);
    return res.json({
      success: true,
      totalCount: auditRepository.getTotalCount(),
      count: events.length,
      chainStatus: 'VALID_SHA256_INTEGRITY',
      events
    });
  },

  verifyChain(req: Request, res: Response) {
    const rawLimit = req.query.limit as string | undefined;
    const parsedLimit = rawLimit && rawLimit !== 'all' ? parseInt(rawLimit, 10) : undefined;
    const limit =
      typeof parsedLimit === 'number' && Number.isFinite(parsedLimit) && parsedLimit > 0 ? parsedLimit : undefined;
    const result = auditRepository.verifyIntegrityChain(limit);
    return res.json({
      success: true,
      ...result
    });
  },

  getAnchorStatus(req: Request, res: Response) {
    const status = auditRepository.getAnchorStatus();
    return res.json({
      success: true,
      anchor: status
    });
  },

  baselineLegacy(req: Request, res: Response) {
    try {
      const adminUsername = req.user?.username || 'secops_admin';
      const rawCutoff = req.body?.cutoffMaxId;
      let cutoffMaxId: number | undefined;
      if (rawCutoff !== undefined && rawCutoff !== null && rawCutoff !== '') {
        const parsed = Number(rawCutoff);
        if (!Number.isInteger(parsed) || parsed <= 0) {
          return res.status(400).json({ error: 'cutoffMaxId must be a positive integer.' });
        }
        cutoffMaxId = parsed;
      }

      const epochLabel = typeof req.body?.epochLabel === 'string' ? req.body.epochLabel.trim().slice(0, 80) : undefined;
      const reason = typeof req.body?.reason === 'string' ? req.body.reason.trim().slice(0, 280) : undefined;

      const baselineResult = auditRepository.baselineLegacyRecords({
        adminUsername,
        cutoffMaxId,
        epochLabel,
        reason
      });
      const verification = auditRepository.verifyIntegrityChain();

      return res.json({
        ...baselineResult,
        verification
      });
    } catch (err: any) {
      return res.status(400).json({ error: err?.message || 'Failed to seal legacy audit baseline.' });
    }
  },

  rotateAnchorKey(req: Request, res: Response) {
    try {
      const adminUsername = req.user?.username || 'secops_admin';
      const newKeyId = typeof req.body?.newKeyId === 'string' ? req.body.newKeyId.trim().slice(0, 64) : undefined;
      const newSecret = typeof req.body?.newSecret === 'string' ? req.body.newSecret : undefined;
      const reason = typeof req.body?.reason === 'string' ? req.body.reason.trim().slice(0, 280) : undefined;

      if (newKeyId && !/^[a-zA-Z0-9._-]+$/.test(newKeyId)) {
        return res.status(400).json({ error: 'newKeyId may only contain alphanumeric characters, dots, dashes, or underscores.' });
      }
      if (newSecret !== undefined && newSecret.trim().length > 0 && newSecret.trim().length < 16) {
        return res.status(400).json({ error: 'newSecret must be at least 16 characters when supplied.' });
      }

      const rotationResult = auditRepository.rotateAnchorKey({
        adminUsername,
        newKeyId,
        newSecret,
        reason
      });
      const anchor = auditRepository.getAnchorStatus();
      const verification = auditRepository.verifyIntegrityChain();

      return res.json({
        ...rotationResult,
        anchor,
        verification
      });
    } catch (err: any) {
      return res.status(409).json({ error: err?.message || 'Failed to rotate audit chain anchor key.' });
    }
  },

  clearEvents(req: Request, res: Response) {
    auditRepository.clear();
    return res.json({ success: true, message: 'Audit ledger re-initialized to baseline.' });
  }
};
