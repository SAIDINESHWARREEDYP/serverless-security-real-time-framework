import { Request, Response, NextFunction } from 'express';
import { CONFIG } from '../config/env.ts';
import { auditRepository } from '../repositories/audit.repository.ts';

interface AttemptRecord {
  count: number;
  firstAttempt: number;
  lockedUntil?: number;
}

class RateLimiterService {
  private loginAttempts: Map<string, AttemptRecord> = new Map();
  private ipCounters: Map<string, { count: number; windowStart: number }> = new Map();

  public checkLoginAllowed(identifier: string): { allowed: boolean; remainingLockoutSeconds?: number } {
    const key = identifier.toLowerCase().trim();
    const now = Date.now();
    const record = this.loginAttempts.get(key);

    if (!record) return { allowed: true };

    if (record.lockedUntil && record.lockedUntil > now) {
      return {
        allowed: false,
        remainingLockoutSeconds: Math.ceil((record.lockedUntil - now) / 1000)
      };
    }

    // Reset window if older than LOGIN_RATE_LIMIT_WINDOW_MS
    if (now - record.firstAttempt > CONFIG.LOGIN_RATE_LIMIT_WINDOW_MS && (!record.lockedUntil || record.lockedUntil <= now)) {
      this.loginAttempts.delete(key);
      return { allowed: true };
    }

    return { allowed: true };
  }

  public recordLoginFailure(identifier: string): { locked: boolean; remainingAttempts: number; lockoutSeconds?: number } {
    const key = identifier.toLowerCase().trim();
    const now = Date.now();
    let record = this.loginAttempts.get(key);

    if (!record || (now - record.firstAttempt > CONFIG.LOGIN_RATE_LIMIT_WINDOW_MS && (!record.lockedUntil || record.lockedUntil <= now))) {
      record = { count: 1, firstAttempt: now };
    } else {
      record.count += 1;
    }

    if (record.count >= CONFIG.MAX_FAILED_LOGIN_ATTEMPTS) {
      record.lockedUntil = now + CONFIG.ACCOUNT_LOCKOUT_MS;
      this.loginAttempts.set(key, record);
      return {
        locked: true,
        remainingAttempts: 0,
        lockoutSeconds: Math.ceil(CONFIG.ACCOUNT_LOCKOUT_MS / 1000)
      };
    }

    this.loginAttempts.set(key, record);
    return {
      locked: false,
      remainingAttempts: CONFIG.MAX_FAILED_LOGIN_ATTEMPTS - record.count
    };
  }

  public recordLoginSuccess(identifier: string) {
    this.loginAttempts.delete(identifier.toLowerCase().trim());
  }

  public checkApiRateLimit(ip: string): boolean {
    const now = Date.now();
    let entry = this.ipCounters.get(ip);

    if (!entry || now - entry.windowStart > 60000) {
      entry = { count: 1, windowStart: now };
      this.ipCounters.set(ip, entry);
      return true;
    }

    entry.count += 1;
    if (entry.count > CONFIG.BURST_RATE_LIMIT_PER_MINUTE) {
      return false;
    }
    return true;
  }
}

export const rateLimiter = new RateLimiterService();

export function loginRateLimitMiddleware(req: Request, res: Response, next: NextFunction) {
  const ip = req.ip || req.socket.remoteAddress || '127.0.0.1';
  const username = (req.body?.username as string || '').trim();
  const identifier = username ? `${ip}:${username}` : ip;

  const check = rateLimiter.checkLoginAllowed(identifier);
  if (!check.allowed) {
    return res.status(429).json({
      type: 'https://serverless-securityverification.ai.studio/errors/RATE_LIMIT_EXCEEDED',
      title: 'Too Many Requests',
      status: 429,
      detail: `Account/IP temporarily locked out due to repeated login failures. Retry in ${check.remainingLockoutSeconds} seconds.`,
      instance: req.originalUrl,
      errorCode: 'LOGIN_RATE_LIMIT_EXCEEDED',
      retryAfterSeconds: check.remainingLockoutSeconds
    });
  }

  next();
}

export function apiBurstRateLimitMiddleware(req: Request, res: Response, next: NextFunction) {
  const ip = req.ip || req.socket.remoteAddress || '127.0.0.1';
  if (!rateLimiter.checkApiRateLimit(ip)) {
    return res.status(429).json({
      type: 'https://serverless-securityverification.ai.studio/errors/BURST_LIMIT_EXCEEDED',
      title: 'Rate Limit Exceeded',
      status: 429,
      detail: 'Per-minute API request quota exceeded.',
      instance: req.originalUrl,
      errorCode: 'API_BURST_LIMIT_EXCEEDED'
    });
  }
  next();
}
