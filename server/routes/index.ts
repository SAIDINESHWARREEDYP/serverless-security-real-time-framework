import crypto from 'crypto';
import { Router, Request, Response, NextFunction } from 'express';
import v1Router from './v1/index.ts';
import { authController } from '../controllers/auth.controller.ts';
import { userController } from '../controllers/user.controller.ts';
import { policyController } from '../controllers/policy.controller.ts';
import { auditController } from '../controllers/audit.controller.ts';
import { threatController } from '../controllers/threat.controller.ts';
import { analyticsController } from '../controllers/analytics.controller.ts';
import { healthController } from '../controllers/health.controller.ts';
import { verificationController } from '../controllers/verification.controller.ts';
import { authenticateMiddleware } from '../middleware/authenticate.ts';
import { requireRole } from '../middleware/authorize.ts';
import { loginRateLimitMiddleware } from '../middleware/rateLimiter.ts';
import { userRepository } from '../repositories/user.repository.ts';
import { policyRepository } from '../repositories/policy.repository.ts';
import { auditRepository } from '../repositories/audit.repository.ts';
import { sessionRepository } from '../repositories/session.repository.ts';
import { passwordRequestRepository } from '../repositories/password-request.repository.ts';
import { usernameRequestRepository } from '../repositories/username-request.repository.ts';
import { verificationService } from '../services/verification.service.ts';
import { authService } from '../services/auth.service.ts';
import { db } from '../db.ts';
import {
  generateRecoveryCodes,
  getTotpRemainingSeconds
} from '../../src/utils/mfa.ts';

const VALID_ROLES = new Set([
  'Admin',
  'Developer',
  'Guest',
  'Super Administrator',
  'Security Administrator',
  'Security Analyst',
  'Auditor',
  'Viewer'
]);
const VALID_STATUSES = new Set(['APPROVED', 'PENDING_APPROVAL', 'REJECTED', 'SUSPENDED']);
const VALID_INCIDENT_SEVERITIES = new Set(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
const VALID_INCIDENT_STATUSES = new Set(['OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE']);
const ADMIN_ROLES = new Set(['Admin', 'Super Administrator', 'Security Administrator']);
const OPS_VIEW_ROLES = new Set(['Admin', 'Super Administrator', 'Security Administrator', 'Security Analyst', 'Auditor']);

const rootRouter = Router();

// 1. Mount API Version 1
rootRouter.use('/v1', v1Router);

// 2. Health & Telemetry & NTP Time Synchronization
rootRouter.get('/health', healthController.getHealth);
rootRouter.get('/system/health', healthController.getHealth);
rootRouter.get('/system/d1-latency', healthController.getD1Latency);

// NTP-style real-time time synchronization endpoint for ZeroTrustLoginGateway
rootRouter.get(['/system/time', '/time'], (req: Request, res: Response) => {
  const now = Date.now();
  const serverEpochSeconds = Math.floor(now / 1000);
  const timeStep30s = Math.floor(serverEpochSeconds / 30);
  const secondsRemainingInWindow = 30 - (serverEpochSeconds % 30);

  return res.json({
    success: true,
    serverTimeIso: new Date(now).toISOString(),
    serverEpochMs: now,
    serverEpochSeconds,
    timeStep30s,
    secondsRemainingInWindow,
    stepSeconds: 30
  });
});

// Real-Time SSE Stream & Incident Management (Root Mounts)
rootRouter.get('/realtime/stream', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    'Connection': 'keep-alive'
  });
  res.write(`data: ${JSON.stringify({ type: 'CONNECTED', serverTime: new Date().toISOString() })}\n\n`);
  const unsub = auditRepository.subscribe((ev) => {
    try { res.write(`data: ${JSON.stringify(ev)}\n\n`); } catch { /* ignore */ }
  });
  req.on('close', unsub);
});

rootRouter.get('/incidents', authenticateMiddleware, (req: Request, res: Response) => {
  res.json({ success: true, incidents: auditRepository.getIncidents() });
});

rootRouter.post(
  '/incidents',
  authenticateMiddleware,
  requireRole('Super Administrator', 'Security Administrator', 'Security Analyst', 'Admin'),
  (req: Request, res: Response) => {
    const title = typeof req.body?.title === 'string' ? req.body.title.trim() : '';
    if (!title) {
      return res.status(400).json({ error: 'Incident title is required.' });
    }
    const severity = (req.body?.severity || 'MEDIUM').toString().toUpperCase();
    const status = (req.body?.status || 'OPEN').toString().toUpperCase();
    if (!VALID_INCIDENT_SEVERITIES.has(severity)) {
      return res.status(400).json({ error: `Invalid incident severity '${severity}'.` });
    }
    if (!VALID_INCIDENT_STATUSES.has(status)) {
      return res.status(400).json({ error: `Invalid incident status '${status}'.` });
    }

    const inc = auditRepository.createIncident({
      title,
      severity: severity as any,
      status: status as any,
      root_cause: typeof req.body?.root_cause === 'string' ? req.body.root_cause : undefined,
      mitigation_steps: typeof req.body?.mitigation_steps === 'string' ? req.body.mitigation_steps : undefined,
      assigned_to: typeof req.body?.assigned_to === 'string' && req.body.assigned_to.trim()
        ? req.body.assigned_to.trim()
        : (req.user?.username || 'secops_admin')
    });
    return res.json({ success: true, incident: inc });
  }
);

rootRouter.patch(
  '/incidents/:id',
  authenticateMiddleware,
  requireRole('Super Administrator', 'Security Administrator', 'Security Analyst', 'Admin'),
  (req: Request, res: Response) => {
    const updates: Record<string, any> = {};
    if (typeof req.body?.title === 'string' && req.body.title.trim()) {
      updates.title = req.body.title.trim();
    }
    if (req.body?.severity !== undefined) {
      const severity = String(req.body.severity).toUpperCase();
      if (!VALID_INCIDENT_SEVERITIES.has(severity)) {
        return res.status(400).json({ error: `Invalid incident severity '${severity}'.` });
      }
      updates.severity = severity;
    }
    if (req.body?.status !== undefined) {
      const status = String(req.body.status).toUpperCase();
      if (!VALID_INCIDENT_STATUSES.has(status)) {
        return res.status(400).json({ error: `Invalid incident status '${status}'.` });
      }
      updates.status = status;
    }
    if (typeof req.body?.root_cause === 'string') updates.root_cause = req.body.root_cause;
    if (typeof req.body?.mitigation_steps === 'string') updates.mitigation_steps = req.body.mitigation_steps;
    if (typeof req.body?.assigned_to === 'string') updates.assigned_to = req.body.assigned_to;

    const inc = auditRepository.updateIncident(req.params.id, updates);
    if (!inc) return res.status(404).json({ error: 'Incident not found' });
    return res.json({ success: true, incident: inc });
  }
);

// 3. System Overview & Security Reporting (Backwards Compatibility)
rootRouter.get('/system/overview', analyticsController.getOverview);

rootRouter.get(
  '/system/security-report',
  authenticateMiddleware,
  requireRole('Super Administrator', 'Security Administrator', 'Security Analyst', 'Auditor', 'Admin'),
  (req: Request, res: Response) => {
  try {
    const users = userRepository.findAllSanitized();
    const rules = policyRepository.getRules();
    const policy = policyRepository.getPolicy();
    const logs = auditRepository.getEvents(100);
    const format = (req.query.format as string || '').toLowerCase();
    const download = req.query.download === 'true' || req.query.download === '1' || Boolean(format);

    const totalLogs = logs.length;
    const blockedLogs = logs.filter(l => l.status === 'BLOCKED');
    const allowedLogs = logs.filter(l => l.status === 'ALLOWED');
    const totalBlocked = blockedLogs.length;
    const totalAllowed = allowedLogs.length;
    const blockRate = totalLogs > 0 ? Math.round((totalBlocked / totalLogs) * 100) : 0;
    const meanThreat = totalLogs > 0 ? Math.round(logs.reduce((s, l) => s + l.calculated_risk, 0) / totalLogs) : 15;
    const criticalBlocks = logs.filter(l => l.calculated_risk >= policy.maxRiskThreshold && l.status === 'BLOCKED');

    const defconLevel = policy.globalLockdown ? 1 :
      blockRate > 40 || criticalBlocks.length >= 4 ? 1 :
      blockRate > 20 || criticalBlocks.length >= 2 ? 2 :
      blockRate > 5 || meanThreat > 35 ? 3 :
      criticalBlocks.length > 0 ? 4 : 5;

    const reportId = `SEC-REP-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;

    const reportData = {
      reportMetadata: {
        reportId,
        generatedAt: new Date().toISOString(),
        framework: 'Serverless Security Verification Framework - Zero Trust Enterprise',
        version: 'v2.4.0-Production',
        classification: 'CONFIDENTIAL // COMPLIANCE AUDIT RECORD',
        complianceStandards: ['ISO/IEC 27001:2022', 'SOC 2 Type II', 'NIST SP 800-207 Zero Trust Architecture']
      },
      executiveSummary: {
        overallHealth: defconLevel === 1 ? 'CRITICAL_DEFCON_1' : defconLevel <= 3 ? 'ELEVATED' : 'NOMINAL',
        defconLevel,
        complianceStatus: criticalBlocks.length > 3 ? 'HIGH_RISK_BREACHES_DETECTED' : criticalBlocks.length > 0 ? 'CONDITIONAL_APPROVAL' : 'COMPLIANT_ZERO_TRUST',
        activePolicyCutoff: `${policy.maxRiskThreshold}%`,
        sequencePenalty: `+${policy.sequenceViolationPenalty}%`,
        strictSequenceEnforced: policy.enforceStrictSequence,
        perimeterLockdownActive: policy.globalLockdown
      },
      systemHealthTelemetry: {
        edgeStatus: 'ONLINE_ACTIVE',
        edgeCluster: 'Cloudflare Global Edge PoP (ap-south-1)',
        databaseEngine: 'Cloudflare D1 Relational SQLite (ACID)',
        activeRulesCount: rules.length,
        activePrincipalsCount: users.length,
        policyConfig: policy
      },
      riskMetrics: {
        meanThreatLevel: meanThreat,
        highestObservedRisk: totalLogs > 0 ? Math.max(...logs.map(l => l.calculated_risk)) : 0,
        criticalIncidentsCount: criticalBlocks.length,
        totalRiskEvaluations: totalLogs
      },
      principalsRoster: users.map(u => ({
        username: u.username,
        role: u.role,
        baseRiskScore: u.base_risk_score,
        totalRequests: logs.filter(l => l.username === u.username).length,
        blocked: logs.filter(l => l.username === u.username && l.status === 'BLOCKED').length
      })),
      recentIncidents: logs.slice(0, 15)
    };

    if (format === 'csv') {
      const csvLines = [
        '### ZERO-TRUST COMPLIANCE AUDIT REPORT ###',
        `Report ID,${reportId}`,
        `Generated At,${new Date().toISOString()}`,
        `DEFCON Status,DEFCON ${defconLevel}`,
        `Compliance Verdict,${reportData.executiveSummary.complianceStatus}`,
        `Total Audit Evaluations,${totalLogs}`,
        `Blocked Invocations,${totalBlocked}`,
        `Allowed Invocations,${totalAllowed}`,
        `Block Rate,${blockRate}%`,
        `Mean Threat Level,${meanThreat}%`,
        '',
        '### PRINCIPALS ROSTER ###',
        'Username,Role,Base Risk (%),Total Requests,Blocked Requests'
      ];
      reportData.principalsRoster.forEach(p => {
        const safeUser = String(p.username).replace(/"/g, '""');
        const safeRole = String(p.role).replace(/"/g, '""');
        csvLines.push(`"${safeUser}","${safeRole}",${p.baseRiskScore},${p.totalRequests},${p.blocked}`);
      });

      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      if (download) {
        res.setHeader('Content-Disposition', `attachment; filename="security_compliance_audit_report_${new Date().toISOString().slice(0, 10)}.csv"`);
      }
      return res.send(csvLines.join('\r\n'));
    }

    if (download && format === 'json') {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename="security_compliance_audit_report_${new Date().toISOString().slice(0, 10)}.json"`);
      return res.send(JSON.stringify(reportData, null, 2));
    }

    return res.json({ success: true, report: reportData });
  } catch (err: any) {
    return res.status(500).json({ error: 'Failed to generate security report', trace: err?.message || String(err) });
  }
});

// 4. Policy Configuration Routes
rootRouter.get('/system/policy-config', (req, res) => {
  res.json(policyRepository.getPolicy());
});

rootRouter.post('/system/policy-config', authenticateMiddleware, requireRole('Super Administrator', 'Security Administrator', 'Admin'), (req, res) => {
  const updated = policyRepository.updatePolicy(req.body);
  res.json({ success: true, policyConfig: updated });
});

// 5. Auth Status & Clearance Check
rootRouter.get('/auth/status', (req: Request, res: Response) => {
  const username = (req.query.username as string || '').trim();
  if (!username) {
    return res.status(400).json({ error: 'Username query parameter required' });
  }
  const user = userRepository.findByUsername(username);
  if (!user) {
    return res.status(404).json({ error: `Identity [${username}] not registered in database`, found: false });
  }

  return res.json({
    success: true,
    found: true,
    status: user.status,
    approved: user.status === 'APPROVED',
    user: userRepository.sanitize(user),
    role: user.role,
    userRisk: user.base_risk_score
  });
});

// 6. User Management Routes (Protected: Admin clearance required)
rootRouter.post('/system/users', authenticateMiddleware, requireRole('Super Administrator', 'Security Administrator', 'Admin'), (req, res) => {
  const { username, password, role, base_risk_score, department, status, email, requestJustification } = req.body;
  const cleanUsername = typeof username === 'string' ? username.trim() : '';
  if (!cleanUsername) {
    return res.status(400).json({ error: 'Username is required.' });
  }
  if (!password || typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ error: 'Password is required and must be at least 8 characters long.' });
  }
  if (userRepository.findByUsername(cleanUsername)) {
    return res.status(409).json({ error: `Identity '${cleanUsername}' already exists.` });
  }

  const normalizedRole = role || 'Developer';
  if (!VALID_ROLES.has(normalizedRole)) {
    return res.status(400).json({ error: `Invalid role '${normalizedRole}'.` });
  }
  const normalizedStatus = status || 'APPROVED';
  if (!VALID_STATUSES.has(normalizedStatus)) {
    return res.status(400).json({ error: `Invalid status '${normalizedStatus}'.` });
  }
  let validatedRisk: number | undefined;
  if (base_risk_score !== undefined) {
    const parsedRisk = Number(base_risk_score);
    if (!Number.isFinite(parsedRisk) || parsedRisk < 0 || parsedRisk > 100) {
      return res.status(400).json({ error: 'base_risk_score must be between 0 and 100.' });
    }
    validatedRisk = parsedRisk;
  }

  const user = userRepository.create({
    username: cleanUsername,
    password: password.trim(),
    role: normalizedRole,
    base_risk_score: validatedRisk,
    department,
    status: normalizedStatus,
    email,
    request_justification: requestJustification,
    approved_by: req.user!.username
  });
  return res.json({ success: true, user: userRepository.sanitize(user), message: `Identity [${user.username}] saved into database.` });
});

rootRouter.post('/system/users/batch-seed', authenticateMiddleware, requireRole('Super Administrator', 'Security Administrator', 'Admin'), (req, res) => {
  const enterpriseSamples: Array<{ username: string; role: 'Developer' | 'Guest'; base_risk_score: number; department: string }> = [
    { username: 'elena_secops', role: 'Developer', base_risk_score: 10, department: 'Edge Platform Engineering' },
    { username: 'marcus_sre', role: 'Developer', base_risk_score: 15, department: 'Cloud Reliability SRE' },
    { username: 'priya_audit', role: 'Guest', base_risk_score: 20, department: 'Compliance & Risk' },
    { username: 'raj_clouddev', role: 'Developer', base_risk_score: 25, department: 'Serverless Runtime' }
  ];

  const createdUsers: string[] = [];
  for (const sample of enterpriseSamples) {
    if (!userRepository.findByUsername(sample.username)) {
      const strongGeneratedPassword = crypto.randomBytes(16).toString('hex');
      userRepository.create({
        username: sample.username,
        password: strongGeneratedPassword,
        role: sample.role,
        base_risk_score: sample.base_risk_score,
        department: sample.department,
        status: 'APPROVED',
        approved_by: req.user!.username
      });
      createdUsers.push(sample.username);
    }
  }

  return res.json({
    success: true,
    createdCount: createdUsers.length,
    createdUsers,
    message: createdUsers.length > 0
      ? `Provisioned ${createdUsers.length} enterprise identity profiles with unique cryptographic credentials.`
      : 'All enterprise identity profiles are already present in the database.'
  });
});

rootRouter.post('/system/users/approve', authenticateMiddleware, requireRole('Super Administrator', 'Security Administrator', 'Admin'), userController.approveUser);
rootRouter.post('/system/users/reject', authenticateMiddleware, requireRole('Super Administrator', 'Security Administrator', 'Admin'), userController.rejectUser);

rootRouter.delete('/system/users/:username', authenticateMiddleware, requireRole('Super Administrator', 'Security Administrator', 'Admin'), (req, res) => {
  const { username } = req.params;
  if (username.toLowerCase() === 'secops_admin') {
    return res.status(400).json({ error: 'Cannot delete primary root SecOps admin.' });
  }
  const ok = userRepository.delete(username);
  if (!ok) return res.status(404).json({ error: `User '${username}' not found` });
  return res.json({ success: true, message: `User '${username}' removed from database.` });
});

rootRouter.patch('/system/users/:username', authenticateMiddleware, requireRole('Super Administrator', 'Security Administrator', 'Admin'), (req, res) => {
  const { username } = req.params;
  const user = userRepository.findByUsername(username);
  if (!user) return res.status(404).json({ error: `User '${username}' not found` });

  const allowedUpdates: Record<string, any> = {};
  if (req.body?.role !== undefined) {
    if (!VALID_ROLES.has(req.body.role)) {
      return res.status(400).json({ error: `Invalid role '${req.body.role}'.` });
    }
    allowedUpdates.role = req.body.role;
  }
  if (req.body?.base_risk_score !== undefined) {
    const parsedRisk = Number(req.body.base_risk_score);
    if (!Number.isFinite(parsedRisk) || parsedRisk < 0 || parsedRisk > 100) {
      return res.status(400).json({ error: 'base_risk_score must be between 0 and 100.' });
    }
    allowedUpdates.base_risk_score = parsedRisk;
  }
  if (req.body?.status !== undefined) {
    if (!VALID_STATUSES.has(req.body.status)) {
      return res.status(400).json({ error: `Invalid status '${req.body.status}'.` });
    }
    allowedUpdates.status = req.body.status;
  }
  if (typeof req.body?.department === 'string' && req.body.department.trim()) {
    allowedUpdates.department = req.body.department.trim();
  }

  const updated = userRepository.update(user.id, allowedUpdates);
  return res.json({ success: true, user: updated ? userRepository.sanitize(updated) : null });
});

// Single-use recovery bypass codes generation for user profile (self or Admin only)
rootRouter.post('/system/users/:username/recovery-codes', authenticateMiddleware, (req: Request, res: Response) => {
  const { username } = req.params;
  const user = userRepository.findByUsername(username);
  if (!user) {
    return res.status(404).json({ error: `User '${username}' not found in database.` });
  }

  const caller = req.user!;
  const isSelf = caller.username.toLowerCase() === user.username.toLowerCase();
  if (!isSelf && !ADMIN_ROLES.has(caller.role)) {
    return res.status(403).json({ error: 'Forbidden: Only the principal owner or an Administrator may regenerate recovery codes.' });
  }

  const { plaintextCodes, hashedCodes } = generateRecoveryCodes(8);
  userRepository.update(user.id, {
    mfa_backup_codes: hashedCodes,
    mfa_enabled: true
  });

  auditRepository.record({
    username: caller.username,
    requested_function: `/api/system/users/${user.username}/recovery-codes`,
    calculated_risk: 10,
    status: 'ALLOWED',
    reason: `[RECOVERY CODES GENERATED] Created 8 single-use bypass codes for ${user.username} by ${caller.username}. Hashes stored in D1.`,
    verification_latency_ms: 1.1,
    event_type: 'RECOVERY_CODES_GENERATED'
  });

  return res.json({
    success: true,
    username: user.username,
    plaintextCodes,
    codesCount: plaintextCodes.length,
    message: `Generated ${plaintextCodes.length} single-use bypass recovery codes for ${user.username}.`
  });
});

// Admin-triggered MFA enrollment reset (allows user to re-pair a new Authenticator on next login)
rootRouter.post('/system/users/:username/mfa-reset', authenticateMiddleware, requireRole('Super Administrator', 'Security Administrator', 'Admin'), (req: Request, res: Response) => {
  const updated = authService.resetMfaEnrollment(req.params.username, req.user!.username);
  if (!updated) {
    return res.status(404).json({ error: `User '${req.params.username}' not found in database.` });
  }
  return res.json({
    success: true,
    user: userRepository.sanitize(updated),
    message: `MFA pairing reset for [${updated.username}]. They will receive a fresh Authenticator QR setup on their next sign-in.`
  });
});

// 6.5. Password Change Request Management Routes (Zero-Trust: Admin approval required to commit to DB)
rootRouter.post(['/password-requests/submit', '/auth/password-requests/submit'], (req: Request, res: Response) => {
  const { username, newPassword, justification } = req.body;
  if (!username || !username.trim()) {
    return res.status(400).json({ error: 'Username is required.' });
  }
  if (!newPassword || newPassword.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters long.' });
  }

  try {
    const request = passwordRequestRepository.create({
      username: username.trim(),
      newPasswordPlaintext: newPassword,
      justification
    });

    return res.json({
      success: true,
      request,
      message: `Password change request for [${username.trim()}] submitted successfully. Awaiting SecOps Administrator approval before it is applied to the database.`
    });
  } catch (err: any) {
    return res.status(400).json({ error: err?.message || 'Failed to submit password change request.' });
  }
});

rootRouter.get('/password-requests', authenticateMiddleware, (req: Request, res: Response) => {
  const status = (req.query.status as string) || 'ALL';
  const requests = passwordRequestRepository.list(status);
  const caller = req.user!;
  const scoped = OPS_VIEW_ROLES.has(caller.role)
    ? requests
    : requests.filter((r: any) => String(r.username || '').toLowerCase() === caller.username.toLowerCase());
  return res.json({ success: true, requests: scoped });
});

rootRouter.post('/password-requests/:id/approve', authenticateMiddleware, requireRole('Super Administrator', 'Security Administrator', 'Admin'), (req: Request, res: Response) => {
  const { id } = req.params;
  const adminUsername = req.user!.username;

  try {
    const result = passwordRequestRepository.approve(id, adminUsername);
    return res.json({ success: true, ...result });
  } catch (err: any) {
    return res.status(400).json({ error: err?.message || 'Failed to approve password change request.' });
  }
});

rootRouter.post('/password-requests/:id/reject', authenticateMiddleware, requireRole('Super Administrator', 'Security Administrator', 'Admin'), (req: Request, res: Response) => {
  const { id } = req.params;
  const { reason } = req.body;
  const adminUsername = req.user!.username;

  try {
    const result = passwordRequestRepository.reject(id, adminUsername, reason);
    return res.json({ success: true, ...result });
  } catch (err: any) {
    return res.status(400).json({ error: err?.message || 'Failed to reject password change request.' });
  }
});

// 6.6. Username Change Request Management Routes (Zero-Trust: Admin approval required to commit to DB)
rootRouter.post(['/username-requests/submit', '/auth/username-requests/submit'], (req: Request, res: Response) => {
  const { currentUsername, requestedUsername, justification } = req.body;
  if (!currentUsername || !currentUsername.trim()) {
    return res.status(400).json({ error: 'Current username is required.' });
  }
  if (!requestedUsername || !requestedUsername.trim()) {
    return res.status(400).json({ error: 'Requested new username is required.' });
  }

  try {
    const request = usernameRequestRepository.create({
      currentUsername: currentUsername.trim(),
      requestedUsername: requestedUsername.trim(),
      justification
    });

    return res.json({
      success: true,
      request,
      message: `Username change request for [${currentUsername.trim()}] to [${requestedUsername.trim()}] submitted successfully. Awaiting SecOps Administrator approval before it is applied to the database.`
    });
  } catch (err: any) {
    return res.status(400).json({ error: err?.message || 'Failed to submit username change request.' });
  }
});

rootRouter.get('/username-requests', authenticateMiddleware, (req: Request, res: Response) => {
  const status = (req.query.status as string) || 'ALL';
  const requests = usernameRequestRepository.list(status);
  const caller = req.user!;
  const scoped = OPS_VIEW_ROLES.has(caller.role)
    ? requests
    : requests.filter((r: any) => String(r.current_username || '').toLowerCase() === caller.username.toLowerCase());
  return res.json({ success: true, requests: scoped });
});

rootRouter.post('/username-requests/:id/approve', authenticateMiddleware, requireRole('Super Administrator', 'Security Administrator', 'Admin'), (req: Request, res: Response) => {
  const { id } = req.params;
  const adminUsername = req.user!.username;

  try {
    const result = usernameRequestRepository.approve(id, adminUsername);
    return res.json({ success: true, ...result });
  } catch (err: any) {
    return res.status(400).json({ error: err?.message || 'Failed to approve username change request.' });
  }
});

rootRouter.post('/username-requests/:id/reject', authenticateMiddleware, requireRole('Super Administrator', 'Security Administrator', 'Admin'), (req: Request, res: Response) => {
  const { id } = req.params;
  const { reason } = req.body;
  const adminUsername = req.user!.username;

  try {
    const result = usernameRequestRepository.reject(id, adminUsername, reason);
    return res.json({ success: true, ...result });
  } catch (err: any) {
    return res.status(400).json({ error: err?.message || 'Failed to reject username change request.' });
  }
});

// Safe MFA enrollment & clock-window status (never exposes raw Base32 secret or active TOTP tokens)
rootRouter.get('/system/users/:username/credentials', authenticateMiddleware, (req: Request, res: Response) => {
  const { username } = req.params;
  const user = userRepository.findByUsername(username);
  if (!user) {
    return res.status(404).json({ error: `User '${username}' not found in database.` });
  }

  const caller = req.user!;
  const isSelf = caller.username.toLowerCase() === user.username.toLowerCase();
  if (!isSelf && !ADMIN_ROLES.has(caller.role)) {
    return res.status(403).json({ error: 'Forbidden: Only the principal owner or an Administrator may inspect MFA enrollment status.' });
  }

  const remaining = getTotpRemainingSeconds();

  return res.json({
    success: true,
    username: user.username,
    role: user.role,
    mfa_enabled: Boolean(user.mfa_enabled),
    mfaConfigured: Boolean(user.mfa_secret && user.mfa_secret.trim().length > 0),
    issuer: 'ServerlessSecOps',
    timeStep30s: remaining.timeStep,
    secondsRemaining: remaining.secondsRemaining,
    backupCodesCount: Array.isArray(user.mfa_backup_codes) ? user.mfa_backup_codes.length : 0,
    serverTimeIso: new Date().toISOString()
  });
});

// 7. Session Revocation Routes
rootRouter.post(['/auth/revoke-session', '/system/sessions/revoke'], authenticateMiddleware, authController.revokeSession);

// 8. System Reset & Clear
rootRouter.post('/system/reset', authenticateMiddleware, requireRole('Super Administrator', 'Security Administrator', 'Admin'), (req, res) => {
  userRepository.reset();
  policyRepository.reset();
  auditRepository.clear();
  sessionRepository.reset();
  db.reset();
  res.json({ success: true, message: 'Database reset to factory test seed baseline.', policyConfig: policyRepository.getPolicy() });
});

rootRouter.post('/system/clearLogs', authenticateMiddleware, requireRole('Super Administrator', 'Security Administrator', 'Admin'), (req, res) => {
  auditRepository.clear();
  db.clearLogs();
  res.json({ success: true, message: 'Security audit logs cleared.' });
});

// 9. Rule Management
rootRouter.post('/system/rules', authenticateMiddleware, requireRole('Super Administrator', 'Security Administrator', 'Admin'), (req, res) => {
  const { current_function, allowed_next_function } = req.body;
  if (!current_function || !allowed_next_function) {
    return res.status(400).json({ error: 'Missing current_function or allowed_next_function' });
  }
  const rule = policyRepository.addRule(current_function, allowed_next_function);
  res.json({ success: true, rule });
});

rootRouter.delete('/system/rules/:id', authenticateMiddleware, requireRole('Super Administrator', 'Security Administrator', 'Admin'), (req, res) => {
  const id = parseInt(req.params.id, 10);
  const ok = policyRepository.deleteRule(id);
  res.json({ success: ok });
});

// 10. AI Threat Sentinel Routes
rootRouter.post('/security/ai-threat-scan', authenticateMiddleware, threatController.scanPayload);
rootRouter.get('/security/ai-threats', authenticateMiddleware, threatController.getAlerts);

// 11. Security Viva Drills (Authenticated)
rootRouter.post('/security/fail-closed-drill', authenticateMiddleware, async (req: Request, res: Response) => {
  const timerStart = performance.now();
  const caller = req.user!;
  const canSpecifyOther = ADMIN_ROLES.has(caller.role) || caller.role === 'Security Analyst';
  const targetUser = (canSpecifyOther && typeof req.body?.username === 'string' && req.body.username.trim())
    ? req.body.username.trim()
    : caller.username;
  const simulatedErrorType = req.body.errorType || 'KMS_SECRET_DECRYPTION_TIMEOUT';
  const latencyMs = Number((performance.now() - timerStart).toFixed(3));

  res.setHeader('X-Verification-Latency-MS', latencyMs.toString());
  res.setHeader('Server-Timing', `security-verify;dur=${latencyMs};desc="Fail-Closed Exception Drill"`);

  const failClosedReason = `[FAIL-CLOSED EXCEPTION] Simulated critical security pipeline failure: ${simulatedErrorType}. Handled with fail-closed guarantee: assigned 100% CRITICAL risk score and returned 403 Forbidden.`;
  auditRepository.record({
    username: targetUser,
    requested_function: '/api/test/fail-closed-drill',
    calculated_risk: 100,
    status: 'BLOCKED',
    reason: failClosedReason,
    verification_latency_ms: latencyMs,
    event_type: 'SECURITY_EXCEPTION_FAIL_CLOSED'
  });

  return res.status(403).json({
    success: false,
    drill: 'FAIL_CLOSED_EXCEPTION_HANDLING',
    error: 'Security Verification Pipeline Exception [FAIL_CLOSED]: Request blocked by Zero-Trust fail-closed security architecture.',
    metrics: {
      riskScore: 100,
      status: 'BLOCKED',
      threatReason: failClosedReason,
      verification_latency_ms: latencyMs,
      eventType: 'SECURITY_EXCEPTION_FAIL_CLOSED',
      failClosed: true
    }
  });
});

rootRouter.post('/security/rate-limit-drill', authenticateMiddleware, async (req: Request, res: Response) => {
  const timerStart = performance.now();
  const caller = req.user!;
  const canSpecifyOther = ADMIN_ROLES.has(caller.role) || caller.role === 'Security Analyst';
  const targetUser = (canSpecifyOther && typeof req.body?.username === 'string' && req.body.username.trim())
    ? req.body.username.trim()
    : caller.username;

  // Seed 11 rapid requests in audit ledger
  for (let i = 0; i < 11; i++) {
    auditRepository.record({
      username: targetUser,
      requested_function: '/api/getDashboardMetrics',
      calculated_risk: 25,
      status: 'ALLOWED',
      reason: `Burst test packet #${i + 1}`,
      verification_latency_ms: 0.35,
      event_type: i >= 10 ? 'ABNORMAL_REQUEST_RATE' : 'STANDARD_VERIFICATION'
    });
  }

  const recentCount = auditRepository.getRecentUserRequestCount(targetUser, 60000);
  const latencyMs = Number((performance.now() - timerStart).toFixed(3));
  res.setHeader('X-Verification-Latency-MS', latencyMs.toString());

  const ratePenalty = recentCount > 10 ? 20 : 0;
  const user = userRepository.findByUsername(targetUser) || { base_risk_score: 20 };
  const calculatedRisk = Math.min(user.base_risk_score + ratePenalty, 100);

  const rateReason = `[RATE MONITOR] ABNORMAL_REQUEST_RATE: Frequency exceeded threshold (${recentCount} req/60s > 10 req/min). Applied +20 risk penalty.`;
  auditRepository.record({
    username: targetUser,
    requested_function: '/api/getDashboardMetrics',
    calculated_risk: calculatedRisk,
    status: calculatedRisk >= policyRepository.getPolicy().maxRiskThreshold ? 'BLOCKED' : 'ALLOWED',
    reason: rateReason,
    verification_latency_ms: latencyMs,
    event_type: 'ABNORMAL_REQUEST_RATE'
  });

  return res.json({
    success: true,
    drill: 'DYNAMIC_RATE_LIMITING_CHECK',
    user: targetUser,
    recentRequestsCount: recentCount,
    threshold: 10,
    rateLimitExceeded: true,
    ratePenaltyAdded: 20,
    baseRisk: user.base_risk_score,
    totalCalculatedRisk: calculatedRisk,
    eventType: 'ABNORMAL_REQUEST_RATE',
    verification_latency_ms: latencyMs,
    message: `Dynamic rate limit triggered: ${recentCount} requests detected within 60s window. +20 risk score applied.`
  });
});

// 12. Registration & Authentication Routes
rootRouter.post('/register', authController.register);
rootRouter.post('/login', loginRateLimitMiddleware, authController.login);
rootRouter.post('/auth/mfa/verify', authController.verifyMfa);
rootRouter.post('/auth/mfa/enroll-challenge', authController.enrollChallenge);
rootRouter.post('/auth/mfa/setup', authenticateMiddleware, authController.setupMfa);

rootRouter.post('/auth/mfa/send-sms', (req: Request, res: Response) => {
  return res.status(501).json({
    success: false,
    error: 'SMS carrier gateway is not configured in this deployment. Please use RFC 6238 Authenticator TOTP or single-use recovery codes.'
  });
});

// 13. Operational Serverless Function Endpoints Intercepted by Verification Pipeline
rootRouter.all('/:route', authenticateMiddleware, async (req: Request, res: Response) => {
  const timerStart = req.startTime || performance.now();
  const route = req.params.route;
  const path = `/api/${route}`;
  const user = req.user!;

  // Fail-closed drill check
  if (route === 'simulate-exception' || req.headers['x-simulate-fault'] === 'true') {
    throw new Error('Simulated hardware security module (HSM) decryption timeout in verification pipeline');
  }

  // Evaluate invocation through verification service (audit recorded inside Step 14 of pipeline)
  const rawToken = req.headers.authorization?.startsWith('Bearer ')
    ? req.headers.authorization.slice(7).trim()
    : undefined;
  const verdict = verificationService.evaluateInvocation({
    user,
    targetFunction: path,
    payloadStr: JSON.stringify(req.body || {}),
    token: rawToken,
    requestId: (req as any).requestId || (req.headers['x-request-id'] as string | undefined),
    ipAddress: req.ip,
    timerStart
  });

  const latencyMs = verdict.verificationLatencyMs;
  res.setHeader('X-Verification-Latency-MS', latencyMs.toString());
  res.setHeader('X-Verification-Decision', verdict.decision);
  res.setHeader('Server-Timing', `verify;dur=${latencyMs};desc="Security Verification Pipeline"`);

  if (verdict.decision !== 'ALLOW') {
    return res.status(403).json({
      error: `Access Suspended: Risk Metric (${verdict.compositeRisk}%) Exceeds Safe Boundary.`,
      metrics: {
        riskScore: verdict.compositeRisk,
        status: 'BLOCKED',
        threatReason: verdict.reason,
        baseRisk: verdict.baseRisk,
        penalty: verdict.sequencePenalty,
        ratePenalty: verdict.ratePenalty,
        verification_latency_ms: latencyMs,
        eventType: verdict.eventType
      }
    });
  }

  // Dispatch specific functional responses
  if (path === '/api/getDashboardMetrics') {
    return res.json({
      message: 'Metrics loaded successfully from edge cluster.',
      data: {
        status: 'Active Secure',
        integrity: '100%',
        serverTime: new Date().toISOString(),
        activeNodes: 4,
        protectionLevel: 'High Grade Interceptor',
        verificationLatencyMs: latencyMs
      },
      metrics: {
        riskScore: verdict.compositeRisk,
        status: 'ALLOWED',
        threatReason: verdict.reason,
        verification_latency_ms: latencyMs,
        eventType: verdict.eventType
      }
    });
  }

  if (path === '/api/viewAuditEvents') {
    const events = auditRepository.getEvents(50);
    return res.json({
      message: 'High-assurance audit_events entries retrieved with high-resolution latency verification metrics.',
      auditEvents: events,
      systemLogs: events,
      metrics: {
        riskScore: verdict.compositeRisk,
        status: 'ALLOWED',
        threatReason: verdict.reason,
        verification_latency_ms: latencyMs,
        eventType: verdict.eventType
      }
    });
  }

  if (path === '/api/viewSecurityLogs') {
    const events = auditRepository.getEvents(50);
    return res.json({
      message: 'Cryptographic ledger entries retrieved.',
      systemLogs: events,
      auditEvents: events,
      metrics: {
        riskScore: verdict.compositeRisk,
        status: 'ALLOWED',
        threatReason: verdict.reason,
        verification_latency_ms: latencyMs,
        eventType: verdict.eventType
      }
    });
  }

  if (path === '/api/deployWorkerCode') {
    return res.json({
      message: 'Serverless Worker Bundle deployed successfully to Global Edge.',
      data: {
        bundleId: `wrangler_build_${Date.now().toString(36)}`,
        targetZone: 'ap-south-1 (Cloudflare Global Edge Cluster)',
        coldStartMs: 3.8,
        activeReplicas: 16,
        status: 'DEPLOYED_STABLE',
        verificationLatencyMs: latencyMs
      },
      metrics: {
        riskScore: verdict.compositeRisk,
        status: 'ALLOWED',
        threatReason: verdict.reason,
        verification_latency_ms: latencyMs,
        eventType: verdict.eventType
      }
    });
  }

  if (path === '/api/rotateEncryptionKeys') {
    return res.json({
      message: 'Edge KMS Master Encryption Keys rotated successfully.',
      data: {
        previousKeyId: 'kms-edge-2024-v1',
        newKeyId: `kms-edge-2026-v2-${Date.now().toString(36)}`,
        algorithm: 'AES-256-GCM / HMAC-SHA256',
        status: 'ROTATED',
        verificationLatencyMs: latencyMs
      },
      metrics: {
        riskScore: verdict.compositeRisk,
        status: 'ALLOWED',
        threatReason: verdict.reason,
        verification_latency_ms: latencyMs,
        eventType: verdict.eventType
      }
    });
  }

  if (path === '/api/updateSystemPolicy') {
    return res.json({
      message: 'Enterprise Zero-Trust Policy rules updated and propagated.',
      data: {
        policyVersion: 'v2.4.0-STABLE',
        enforcementMode: 'ACTIVE_BLOCKING',
        verificationLatencyMs: latencyMs
      },
      metrics: {
        riskScore: verdict.compositeRisk,
        status: 'ALLOWED',
        threatReason: verdict.reason,
        verification_latency_ms: latencyMs,
        eventType: verdict.eventType
      }
    });
  }

  if (path === '/api/purgeColdStorageBackups') {
    return res.json({
      message: 'Stale cold storage backups purged.',
      data: {
        purgedSnapshotId: 'snap-archive-9912',
        reclaimedBytes: '4.8 GB',
        verificationLatencyMs: latencyMs
      },
      metrics: {
        riskScore: verdict.compositeRisk,
        status: 'ALLOWED',
        threatReason: verdict.reason,
        verification_latency_ms: latencyMs,
        eventType: verdict.eventType
      }
    });
  }

  return res.json({
    message: 'Requested operational function executed safely without errors.',
    executedPath: path,
    metrics: {
      riskScore: verdict.compositeRisk,
      status: 'ALLOWED',
      threatReason: verdict.reason,
      verification_latency_ms: latencyMs,
      eventType: verdict.eventType
    }
  });
});

export default rootRouter;
