import { Request, Response, NextFunction } from 'express';
import { auditRepository } from '../repositories/audit.repository.ts';
import { logger } from '../utils/logger.ts';

export function errorHandlerMiddleware(err: any, req: Request, res: Response, next: NextFunction) {
  const latencyMs = Number((performance.now() - (req.startTime || performance.now())).toFixed(3));
  res.setHeader('X-Verification-Latency-MS', latencyMs.toString());
  res.setHeader('Server-Timing', `security;dur=${latencyMs};desc="Fail-Closed Exception Block"`);

  const errMsg = err?.message || String(err) || 'Unexpected system anomaly';
  const username = req.user?.username || 'unauthenticated_principal';

  logger.error('FAIL_CLOSED_EXCEPTION', errMsg, {
    correlationId: req.traceId,
    latencyMs,
    userId: username,
    metadata: { stack: err?.stack }
  });

  // Zero-Trust Fail-Closed Guarantee: All pipeline errors log 100% Critical Risk and return 403 Forbidden
  auditRepository.record({
    username,
    requested_function: req.originalUrl,
    calculated_risk: 100,
    status: 'BLOCKED',
    reason: `[FAIL-CLOSED DEFENSE] Unhandled verification pipeline anomaly: ${errMsg}. Execution halted with 100% risk.`,
    verification_latency_ms: latencyMs,
    event_type: 'SECURITY_EXCEPTION_FAIL_CLOSED'
  });

  return res.status(403).json({
    type: 'https://serverless-securityverification.ai.studio/errors/SECURITY_VERIFICATION_EXCEPTION',
    title: 'Fail-Closed Security Intercept',
    status: 403,
    detail: 'Security verification pipeline exception encountered. Request blocked under Zero-Trust fail-closed architecture.',
    instance: req.originalUrl,
    errorCode: 'SECURITY_VERIFICATION_EXCEPTION',
    traceId: req.traceId,
    metrics: {
      riskScore: 100,
      status: 'BLOCKED',
      failClosed: true,
      verification_latency_ms: latencyMs
    }
  });
}
