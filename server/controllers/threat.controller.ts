import crypto from 'crypto';
import { Request, Response } from 'express';
import { auditRepository } from '../repositories/audit.repository.ts';
import { verificationService } from '../services/verification.service.ts';

const ADMIN_ROLES = new Set(['Admin', 'Administrator', 'Super Administrator', 'Security Administrator']);

export const threatController = {
  getAlerts(req: Request, res: Response) {
    const alerts = auditRepository.getAlerts();
    const threats = alerts.map((a) => {
      let parsedReason = a.details || '';
      try {
        const parsed = JSON.parse(a.details || '{}');
        parsedReason = parsed.reason || a.details;
      } catch {
        // plain string details
      }
      return {
        id: a.id,
        timestamp: a.timestamp,
        severity: a.severity,
        threatCategory: a.alert_type,
        payloadSnippet: a.threat_vector,
        mitigationAction: parsedReason,
        sourceUser: a.username,
        acknowledged: a.acknowledged
      };
    });

    return res.json({
      success: true,
      totalCount: alerts.length,
      alerts,
      threats
    });
  },

  ackAlert(req: Request, res: Response) {
    const { id } = req.params;
    const acknowledgedBy = req.user?.username || 'secops_admin';
    const ok = auditRepository.acknowledgeAlert(id, acknowledgedBy);
    return res.json({ success: ok, alertId: id, acknowledgedBy });
  },

  scanPayload(req: Request, res: Response) {
    const { payload, sourceUser } = req.body;
    if (typeof payload !== 'string') {
      return res.status(400).json({ error: 'Payload must be a string.' });
    }

    const caller = req.user;
    const isAdmin = caller && ADMIN_ROLES.has(caller.role);
    const effectiveUser = isAdmin && typeof sourceUser === 'string' && sourceUser.trim()
      ? sourceUser.trim()
      : caller?.username || 'ai_threat_probe';

    const report = verificationService.scanThreatVectors(payload);
    const incidentId = `threat_${Date.now().toString(36)}_${crypto.randomBytes(3).toString('hex')}`;

    if (report.threatDetected) {
      auditRepository.record({
        username: effectiveUser,
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
