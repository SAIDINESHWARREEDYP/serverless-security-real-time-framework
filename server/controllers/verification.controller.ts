import { Request, Response } from 'express';
import { verificationService } from '../services/verification.service.ts';
import { functionRepository } from '../repositories/function.repository.ts';

export const verificationController = {
  async verifyInvoke(req: Request, res: Response) {
    const timerStart = req.startTime || performance.now();
    const user = req.user || null;
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : undefined;

    const { functionName, serviceName, payload = {} } = req.body;
    const target = functionName || req.params.functionName || req.path;
    const payloadStr = typeof payload === 'string' ? payload : JSON.stringify(payload);

    // Execute full 15-step serverless verification pipeline
    const result = verificationService.execute15StepPipeline({
      requestId: req.traceId || `req_${Date.now()}`,
      targetFunction: target,
      payloadStr,
      user,
      token,
      timerStart,
      ipAddress: req.ip || req.socket.remoteAddress
    });

    // Set all 5 security telemetry headers
    Object.entries(result.telemetryHeaders).forEach(([key, val]) => {
      res.setHeader(key, val);
    });

    if (result.decision === 'DENY') {
      return res.status(403).json({
        success: false,
        type: 'https://serverless-securityverification.ai.studio/errors/VERIFICATION_FAILED',
        title: 'Invocation Verification Rejected',
        status: 403,
        decision: result.decision,
        riskScore: result.compositeRiskScore,
        denialReasons: result.denialReasons,
        matchedPolicies: result.matchedPolicies,
        threatVector: result.threatVector,
        steps: result.steps,
        auditRecordId: result.auditRecordId,
        auditHash: result.auditHash,
        verifiedInMs: result.verificationLatencyMs,
        traceId: req.traceId
      });
    }

    return res.json({
      success: true,
      decision: result.decision,
      riskScore: result.compositeRiskScore,
      targetFunction: target,
      functionId: result.functionId,
      callerReference: result.callerReference,
      steps: result.steps,
      auditRecordId: result.auditRecordId,
      auditHash: result.auditHash,
      verifiedInMs: result.verificationLatencyMs,
      traceId: req.traceId,
      output: {
        status: 'EXECUTED_SUCCESSFULLY',
        target,
        executedAt: new Date().toISOString()
      }
    });
  },

  getFunctions(req: Request, res: Response) {
    return res.json({
      success: true,
      functions: functionRepository.findAll()
    });
  }
};
