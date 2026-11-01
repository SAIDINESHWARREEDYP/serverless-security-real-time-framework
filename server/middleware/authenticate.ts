import { Request, Response, NextFunction } from 'express';
import { verifyJwt } from '../utils/crypto.ts';
import { userRepository } from '../repositories/user.repository.ts';
import { sessionRepository } from '../repositories/session.repository.ts';
import { policyRepository } from '../repositories/policy.repository.ts';
import { auditRepository } from '../repositories/audit.repository.ts';
import { UserRecord, SessionRecord, JwtClaims } from '../types/index.ts';

declare global {
  namespace Express {
    interface Request {
      user?: UserRecord;
      session?: SessionRecord;
      tokenClaims?: JwtClaims;
    }
  }
}

export async function authenticateMiddleware(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers['authorization'];
  const timerStart = req.startTime || performance.now();

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    const latencyMs = Number((performance.now() - timerStart).toFixed(3));
    res.setHeader('X-Verification-Latency-MS', latencyMs.toString());
    res.setHeader('Server-Timing', `auth;dur=${latencyMs};desc="Missing Token"`);

    auditRepository.record({
      username: 'anonymous',
      requested_function: req.originalUrl,
      calculated_risk: 100,
      status: 'BLOCKED',
      reason: 'Authentication failed: Missing Bearer authorization token header.',
      verification_latency_ms: latencyMs,
      event_type: 'AUTHENTICATION_FAILURE'
    });

    return res.status(401).json({
      type: 'https://serverless-securityverification.ai.studio/errors/AUTH_TOKEN_MISSING',
      title: 'Unauthorized',
      status: 401,
      detail: 'Missing or malformed Authorization header. Expected Bearer token.',
      instance: req.originalUrl,
      errorCode: 'AUTH_TOKEN_MISSING',
      traceId: req.traceId
    });
  }

  const rawToken = authHeader.split(' ')[1].trim();

  // 1. Verify token: check if it's a real signed JWT
  let claims: JwtClaims | undefined;
  let username: string | undefined;

  const jwtResult = verifyJwt(rawToken);
  if (jwtResult.valid && jwtResult.claims) {
    claims = jwtResult.claims;
    username = claims.username;
    req.tokenClaims = claims;
  } else {
    // Check backwards compatibility token (e.g. zt_jwt_<user>_<hash>)
    if (rawToken.startsWith('zt_jwt_') || rawToken.startsWith('mbu_jwt_')) {
      const parts = rawToken.split('_');
      if (parts.length >= 3) {
        username = parts.slice(2, -1).join('_');
      }
    } else {
      // Direct username token for developer testing
      username = rawToken;
    }

    // If it was supposed to be a JWT (contains dots) but failed signature/claims
    if (rawToken.includes('.')) {
      const latencyMs = Number((performance.now() - timerStart).toFixed(3));
      res.setHeader('X-Verification-Latency-MS', latencyMs.toString());

      auditRepository.record({
        username: username || 'unknown',
        requested_function: req.originalUrl,
        calculated_risk: 100,
        status: 'BLOCKED',
        reason: `Cryptographic token validation failed: ${jwtResult.error}`,
        verification_latency_ms: latencyMs,
        event_type: 'TOKEN_INVALID'
      });

      return res.status(401).json({
        type: 'https://serverless-securityverification.ai.studio/errors/AUTH_TOKEN_INVALID',
        title: 'Invalid Token',
        status: 401,
        detail: `Token verification failed: ${jwtResult.error}`,
        instance: req.originalUrl,
        errorCode: `AUTH_${jwtResult.error || 'TOKEN_INVALID'}`,
        traceId: req.traceId
      });
    }
  }

  if (!username) {
    return res.status(401).json({
      type: 'https://serverless-securityverification.ai.studio/errors/AUTH_IDENTITY_INVALID',
      title: 'Invalid Identity',
      status: 401,
      detail: 'Unable to resolve identity from presented token.',
      instance: req.originalUrl,
      errorCode: 'AUTH_IDENTITY_INVALID',
      traceId: req.traceId
    });
  }

  // 2. Check Session Status & Revocation Registry in D1
  const session = sessionRepository.findByToken(rawToken);
  if (session && session.status === 'revoked') {
    const latencyMs = Number((performance.now() - timerStart).toFixed(3));
    res.setHeader('X-Verification-Latency-MS', latencyMs.toString());

    auditRepository.record({
      username,
      requested_function: req.originalUrl,
      calculated_risk: 100,
      status: 'BLOCKED',
      reason: `[SESSION REVOKED] Active session for ${username} was revoked by administrator in real-time.`,
      verification_latency_ms: latencyMs,
      event_type: 'SESSION_REVOKED'
    });

    return res.status(401).json({
      type: 'https://serverless-securityverification.ai.studio/errors/AUTH_TOKEN_REVOKED',
      title: 'Session Revoked',
      status: 401,
      detail: 'The presented token has been revoked by an administrator.',
      instance: req.originalUrl,
      errorCode: 'AUTH_TOKEN_REVOKED',
      traceId: req.traceId
    });
  }

  // 3. User Identity Lookup in Database
  const user = userRepository.findByUsername(username);
  if (!user) {
    const latencyMs = Number((performance.now() - timerStart).toFixed(3));
    res.setHeader('X-Verification-Latency-MS', latencyMs.toString());

    auditRepository.record({
      username,
      requested_function: req.originalUrl,
      calculated_risk: 100,
      status: 'BLOCKED',
      reason: 'Identity Spoofing Detected: Principal not registered in user database.',
      verification_latency_ms: latencyMs,
      event_type: 'IDENTITY_SPOOFING'
    });

    return res.status(403).json({
      type: 'https://serverless-securityverification.ai.studio/errors/IDENTITY_NOT_FOUND',
      title: 'Forbidden',
      status: 403,
      detail: 'Principal identity not registered or cleared.',
      instance: req.originalUrl,
      errorCode: 'IDENTITY_NOT_FOUND',
      traceId: req.traceId
    });
  }

  // 4. Clearance Status Check (Zero-Trust Gate)
  if (user.status !== 'APPROVED') {
    const latencyMs = Number((performance.now() - timerStart).toFixed(3));
    res.setHeader('X-Verification-Latency-MS', latencyMs.toString());

    auditRepository.record({
      username: user.username,
      requested_function: req.originalUrl,
      calculated_risk: 95,
      status: 'BLOCKED',
      reason: `Access blocked: Account status is ${user.status}.`,
      verification_latency_ms: latencyMs,
      event_type: 'STATUS_NOT_APPROVED'
    });

    return res.status(403).json({
      type: 'https://serverless-securityverification.ai.studio/errors/ACCOUNT_NOT_APPROVED',
      title: 'Clearance Required',
      status: 403,
      detail: `Your identity clearance status is [${user.status}]. Administrator approval required.`,
      instance: req.originalUrl,
      errorCode: 'ACCOUNT_NOT_APPROVED',
      statusDetail: user.status,
      traceId: req.traceId
    });
  }

  // 5. Emergency Global Perimeter Lockdown Check
  const policy = policyRepository.getPolicy();
  if (policy.globalLockdown && user.role !== 'Admin') {
    const latencyMs = Number((performance.now() - timerStart).toFixed(3));
    res.setHeader('X-Verification-Latency-MS', latencyMs.toString());

    auditRepository.record({
      username: user.username,
      requested_function: req.originalUrl,
      calculated_risk: 100,
      status: 'BLOCKED',
      reason: '[EMERGENCY LOCKDOWN] Edge perimeter actively rejecting non-administrative invocations.',
      verification_latency_ms: latencyMs,
      event_type: 'PERIMETER_LOCKDOWN'
    });

    return res.status(403).json({
      type: 'https://serverless-securityverification.ai.studio/errors/PERIMETER_LOCKDOWN',
      title: 'Perimeter Lockdown Active',
      status: 403,
      detail: 'All non-administrative serverless execution is suspended by SecOps emergency policy.',
      instance: req.originalUrl,
      errorCode: 'PERIMETER_LOCKDOWN',
      traceId: req.traceId
    });
  }

  req.user = user;
  if (session) req.session = session;
  next();
}
