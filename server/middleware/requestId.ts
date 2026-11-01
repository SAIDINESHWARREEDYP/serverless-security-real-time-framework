import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';

declare global {
  namespace Express {
    interface Request {
      traceId: string;
      startTime: number;
    }
  }
}

export function requestIdMiddleware(req: Request, res: Response, next: NextFunction) {
  const incomingId = req.headers['x-request-id'] as string;
  const traceId = incomingId || `trace_${crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex')}`;
  
  req.traceId = traceId;
  req.startTime = performance.now();

  res.setHeader('X-Request-ID', traceId);
  res.setHeader('X-Verification-Trace-ID', traceId);
  next();
}
