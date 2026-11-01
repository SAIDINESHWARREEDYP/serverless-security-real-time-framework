import { Request, Response } from 'express';
import { auditRepository } from '../repositories/audit.repository.ts';
import { verificationService } from '../services/verification.service.ts';

export const threatController = {
  getAlerts(req: Request, res: Response) {
    const alerts = auditRepository.getAlerts();
    return res.json({
      success: true,
      totalCount: alerts.length,
      alerts
    });
  },

  ackAlert(req: Request, res: Response) {
    const { id } = req.params;
    const ok = auditRepository.acknowledgeAlert(id);
    return res.json({ success: ok, alertId: id });
  },

  scanPayload(req: Request, res: Response) {
    const { payload, sourceUser } = req.body;
    if (typeof payload !== 'string') {
      return res.status(400).json({ error: 'Payload must be a string.' });
    }

    const report = verificationService.scanThreatVectors(payload);
    const incidentId = `threat_${Date.now().toString(36)}`;

    if (report.threatDetected) {
      auditRepository.record({
        username: sourceUser || req.user?.username || 'ai_threat_probe',
        requested_function: '/api/v1/security/scan',
        calculated_risk: report.penaltyScore,
        status: 'BLOCKED',
        reason: `[AI THREAT SENTINEL] Detected ${report.threatCategory}: ${report.explanation}`,
        verification_latency_ms: 1.1,
        event_type: report.threatCategory
      });
    }

    return res.json({
      success: true,
      incidentId,
      report
    });
  }
};
