import { Request, Response } from 'express';
import { authService } from '../services/auth.service.ts';
import { userRepository } from '../repositories/user.repository.ts';
import { validateUsername, validatePassword, validateTotpCode } from '../validators/auth.validator.ts';
import { auditRepository } from '../repositories/audit.repository.ts';

export const authController = {
  async login(req: Request, res: Response) {
    const { username, password } = req.body;

    const usernameCheck = validateUsername(username);
    if (!usernameCheck.valid) {
      return res.status(400).json({
        type: 'https://serverless-securityverification.ai.studio/errors/INVALID_USERNAME',
        title: 'Validation Error',
        status: 400,
        detail: usernameCheck.error,
        instance: req.originalUrl,
        errorCode: 'INVALID_USERNAME'
      });
    }

    const passwordCheck = validatePassword(password);
    if (!passwordCheck.valid) {
      return res.status(400).json({
        type: 'https://serverless-securityverification.ai.studio/errors/INVALID_PASSWORD',
        title: 'Validation Error',
        status: 400,
        detail: passwordCheck.error,
        instance: req.originalUrl,
        errorCode: 'INVALID_PASSWORD'
      });
    }

    const ipAddress = req.ip || req.socket.remoteAddress || '127.0.0.1';
    const userAgent = req.headers['user-agent'] as string;

    const result = await authService.login({
      username,
      password,
      ipAddress,
      userAgent
    });

    if (result.status === 'REJECTED') {
      return res.status(401).json({
        type: 'https://serverless-securityverification.ai.studio/errors/INVALID_CREDENTIALS',
        title: 'Unauthorized',
        status: 401,
        detail: result.error || 'Invalid credentials or unapproved account.',
        instance: req.originalUrl,
        errorCode: 'INVALID_CREDENTIALS',
        remainingAttempts: result.remainingAttempts
      });
    }

    if (result.status === 'PENDING_APPROVAL') {
      return res.status(403).json({
        type: 'https://serverless-securityverification.ai.studio/errors/ACCOUNT_PENDING_APPROVAL',
        title: 'Pending Clearance',
        status: 403,
        detail: result.error,
        instance: req.originalUrl,
        errorCode: 'ACCOUNT_PENDING_APPROVAL',
        user: result.user
      });
    }

    if (result.status === 'SUSPENDED') {
      return res.status(403).json({
        type: 'https://serverless-securityverification.ai.studio/errors/ACCOUNT_SUSPENDED',
        title: 'Account Suspended',
        status: 403,
        detail: result.error,
        instance: req.originalUrl,
        errorCode: 'ACCOUNT_SUSPENDED'
      });
    }

    if (result.status === 'MFA_REQUIRED') {
      return res.json({
        success: true,
        mfaRequired: true,
        mfaSessionId: result.mfaChallengeId,
        mfaChallengeId: result.mfaChallengeId,
        phoneMasked: result.phoneMasked,
        emailMasked: result.emailMasked,
        methods: result.methods,
        demoTotpCode: result.demoTotpCode,
        demoSmsCode: result.demoSmsCode,
        attemptsLeft: result.attemptsLeft,
        user: result.user,
        message: 'Password verified. Enter 6-digit TOTP code.'
      });
    }

    return res.json({
      success: true,
      token: result.token,
      user: result.user,
      expiresInSeconds: 3600
    });
  },

  async verifyMfa(req: Request, res: Response) {
    const { mfaSessionId, mfaChallengeId, code, method } = req.body;
    const challengeId = mfaChallengeId || mfaSessionId;

    if (!challengeId) {
      return res.status(400).json({ error: 'Missing mfaChallengeId.' });
    }

    const codeCheck = validateTotpCode(code);
    if (!codeCheck.valid) {
      return res.status(400).json({ error: codeCheck.error });
    }

    const ipAddress = req.ip || req.socket.remoteAddress || '127.0.0.1';
    const userAgent = req.headers['user-agent'] as string;

    const result = await authService.verifyMfa({
      mfaChallengeId: challengeId,
      code,
      method,
      ipAddress,
      userAgent
    });

    if (!result.success) {
      return res.status(401).json({
        success: false,
        error: result.error,
        attemptsLeft: result.attemptsLeft
      });
    }

    return res.json({
      success: true,
      token: result.token,
      user: result.user,
      message: 'MFA verified successfully. High-assurance Zero-Trust token issued.'
    });
  },

  async setupMfa(req: Request, res: Response) {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    try {
      const mfaData = authService.setupMfa(req.user.id);
      return res.json({
        success: true,
        secret: mfaData.secret,
        provisioningUri: mfaData.uri,
        backupCodes: mfaData.backupCodes,
        message: 'Scan the TOTP URI in an authenticator app and store your backup recovery codes securely.'
      });
    } catch (err: any) {
      return res.status(500).json({ error: err?.message || 'Failed to setup MFA' });
    }
  },

  async register(req: Request, res: Response) {
    const { username, password, role, department, requestJustification } = req.body;

    const userCheck = validateUsername(username);
    if (!userCheck.valid) {
      return res.status(400).json({ error: userCheck.error });
    }

    const passCheck = validatePassword(password);
    if (!passCheck.valid) {
      return res.status(400).json({ error: passCheck.error });
    }

    const existing = userRepository.findByUsername(username);
    if (existing) {
      return res.status(409).json({ error: `Identity [${username}] already exists in database.` });
    }

    const user = userRepository.create({
      username,
      password,
      role: (role === 'Admin' || role === 'Developer' || role === 'Guest') ? role : 'Developer',
      department,
      request_justification: requestJustification
    });

    auditRepository.record({
      username: user.username,
      requested_function: '/api/v1/auth/register',
      calculated_risk: user.base_risk_score,
      status: 'BLOCKED',
      reason: `[REGISTRATION QUEUED] New principal registered. Awaiting SecOps clearance.`,
      verification_latency_ms: 0.9,
      event_type: 'USER_REGISTERED'
    });

    return res.json({
      success: true,
      pendingApproval: true,
      user: userRepository.sanitize(user),
      message: `Account [${user.username}] registered! Zero-Trust Gate: Admin approval required.`
    });
  },

  async logout(req: Request, res: Response) {
    const token = req.headers['authorization']?.split(' ')[1] || '';
    const username = req.user?.username || 'anonymous';
    authService.logout(token, username);
    return res.json({ success: true, message: 'Successfully logged out and session revoked.' });
  },

  async revokeSession(req: Request, res: Response) {
    const { username, reason } = req.body;
    if (!username) {
      return res.status(400).json({ error: 'Target username is required for session revocation.' });
    }

    const caller = req.user?.username || 'secops_admin';
    const result = authService.revokeUserSession(username, caller, reason);

    auditRepository.record({
      username: caller,
      requested_function: '/api/v1/auth/revoke-session',
      calculated_risk: 0,
      status: 'ALLOWED',
      reason: `[SESSION REVOKED] Administrator [${caller}] terminated active session for [${username}].`,
      verification_latency_ms: 1.1,
      event_type: 'SESSION_REVOCATION_EXECUTED'
    });

    return res.json({
      success: true,
      revoked: true,
      target: username,
      revokedBy: caller,
      revokedCount: result.revokedCount,
      message: `Active session for principal [${username}] successfully terminated in real-time D1 registry.`
    });
  },

  async changePassword(req: Request, res: Response) {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    const { oldPassword, newPassword } = req.body;

    const passCheck = validatePassword(newPassword);
    if (!passCheck.valid) {
      return res.status(400).json({ error: passCheck.error });
    }

    const ok = authService.changePassword(req.user.id, oldPassword, newPassword);
    if (!ok) {
      return res.status(400).json({ error: 'Current password is incorrect.' });
    }

    return res.json({
      success: true,
      message: 'Password changed successfully. Existing sessions have been revoked. Please sign in again.'
    });
  },

  async getMe(req: Request, res: Response) {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    return res.json({
      success: true,
      user: userRepository.sanitize(req.user),
      session: req.session ? {
        id: req.session.id,
        created_at: req.session.created_at,
        expires_at: req.session.expires_at,
        status: req.session.status
      } : undefined
    });
  }
};
