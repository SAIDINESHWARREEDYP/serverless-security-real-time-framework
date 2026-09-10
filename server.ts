import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { db } from './server/db.ts';

const app = express();
const PORT = 3000;

app.use(express.json());

// Enable CORS for testing or cross-origin tooling
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, DELETE');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }
  next();
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// Policy configuration state
let policyConfig = {
  maxRiskThreshold: 75,
  sequenceViolationPenalty: 40,
  enforceStrictSequence: true
};

// System administrative & inspection endpoints for the console
app.get('/api/system/overview', (req, res) => {
  try {
    const users = db.getUsers() || [];
    const rules = db.getRules() || [];
    const logs = db.getAllLogs() || [];
    res.json({
      users,
      rules,
      logs,
      policyConfig,
      stats: {
        totalUsers: users.length,
        totalRules: rules.length,
        totalLogs: logs.length,
        blockedCount: logs.filter(l => l.status === 'BLOCKED').length,
        allowedCount: logs.filter(l => l.status === 'ALLOWED').length,
      }
    });
  } catch (err: any) {
    res.status(500).json({
      error: 'Failed to retrieve overview',
      trace: err?.message || String(err),
      users: [],
      rules: [],
      logs: [],
      policyConfig
    });
  }
});

app.get('/api/system/policy-config', (req, res) => {
  res.json(policyConfig);
});

app.post('/api/system/policy-config', (req, res) => {
  const { maxRiskThreshold, sequenceViolationPenalty, enforceStrictSequence } = req.body;
  if (typeof maxRiskThreshold === 'number') policyConfig.maxRiskThreshold = Math.max(10, Math.min(100, maxRiskThreshold));
  if (typeof sequenceViolationPenalty === 'number') policyConfig.sequenceViolationPenalty = Math.max(0, Math.min(80, sequenceViolationPenalty));
  if (typeof enforceStrictSequence === 'boolean') policyConfig.enforceStrictSequence = enforceStrictSequence;
  res.json({ success: true, policyConfig });
});

app.post('/api/system/reset', (req, res) => {
  db.reset();
  policyConfig = {
    maxRiskThreshold: 75,
    sequenceViolationPenalty: 40,
    enforceStrictSequence: true
  };
  res.json({ success: true, message: 'Database reset to factory test seed baseline.', policyConfig });
});

app.post('/api/system/clearLogs', (req, res) => {
  db.clearLogs();
  res.json({ success: true, message: 'Security audit logs cleared.' });
});

app.post('/api/system/rules', (req, res) => {
  const { current_function, allowed_next_function } = req.body;
  if (!current_function || !allowed_next_function) {
    return res.status(400).json({ error: 'Missing current_function or allowed_next_function' });
  }
  const rule = db.addRule(current_function, allowed_next_function);
  res.json({ success: true, rule });
});

app.delete('/api/system/rules/:id', (req, res) => {
  const id = parseInt(req.params.id, 10);
  const ok = db.deleteRule(id);
  res.json({ success: ok });
});

// --- ROUTE: User Registration Interface (/api/register) ---
app.post('/api/register', async (req: Request, res: Response) => {
  try {
    const { username, password, role, base_risk_score } = req.body;
    if (!username || !username.trim()) {
      return res.status(400).json({ error: 'Username is required.' });
    }
    const cleanUsername = username.trim();
    const newUser = db.addUser({
      username: cleanUsername,
      password: password || 'ZeroTrust_2026',
      role: (role === 'Admin' || role === 'Developer' || role === 'Guest') ? role : 'Developer',
      base_risk_score: typeof base_risk_score === 'number' ? Math.max(0, Math.min(100, base_risk_score)) : 15
    });

    const token = `zt_jwt_${newUser.username}_${Date.now().toString(36)}`;
    return res.json({
      success: true,
      message: `User principal [${newUser.username}] registered successfully.`,
      user: {
        id: newUser.id,
        username: newUser.username,
        role: newUser.role,
        base_risk_score: newUser.base_risk_score
      },
      token,
      rawToken: newUser.username,
      role: newUser.role,
      userRisk: newUser.base_risk_score,
      expiresInSeconds: 3600
    });
  } catch (err: any) {
    return res.status(500).json({ error: 'Registration failed: ' + (err?.message || String(err)) });
  }
});

// --- ROUTE: Authentication Interface (/api/login) ---
app.post('/api/login', async (req: Request, res: Response) => {
  try {
    const { username, password, role, base_risk_score } = req.body;
    if (!username) {
      return res.status(400).json({ error: 'Username is required.' });
    }
    const cleanUsername = username.trim();
    let user = await db.prepare('SELECT * FROM users WHERE username = ?').bind(cleanUsername).first();

    // If user does not exist yet, dynamically provision in real-time
    if (!user) {
      const assignedRole = role || (cleanUsername.toLowerCase().includes('admin') ? 'Admin' : cleanUsername.toLowerCase().includes('guest') ? 'Guest' : 'Developer');
      const assignedRisk = typeof base_risk_score === 'number' ? base_risk_score : (assignedRole === 'Admin' ? 0 : assignedRole === 'Developer' ? 15 : 30);
      user = db.addUser({
        username: cleanUsername,
        password: password || 'ZeroTrust_2026',
        role: assignedRole,
        base_risk_score: assignedRisk
      });
    }

    // Verify password if set or accept standard password
    const isPasswordValid = !user.password_hash ||
      password === user.password_hash ||
      password === 'ZeroTrust_2026' ||
      password === 'MBU_Project_2027' ||
      user.password_hash === 'ZeroTrust_2026';

    if (isPasswordValid) {
      const token = `zt_jwt_${user.username}_${Date.now().toString(36)}`;
      return res.json({
        success: true,
        user: {
          id: user.id,
          username: user.username,
          role: user.role,
          base_risk_score: user.base_risk_score
        },
        token,
        rawToken: user.username,
        role: user.role,
        userRisk: user.base_risk_score,
        expiresInSeconds: 3600
      });
    }

    return res.status(401).json({
      success: false,
      error: 'Access Denied: Invalid Credentials. Use password ZeroTrust_2026.'
    });
  } catch (err: any) {
    return res.status(400).json({ error: 'Malformed payload submission.' });
  }
});

// --- REAL-TIME FRAMEWORK VERIFICATION STREAM & PIPELINE INTERCEPTOR ---
// Applied to all operational API paths: /api/getDashboardMetrics, /api/viewSecurityLogs, /api/deployWorkerCode, etc.
app.all('/api/:route', async (req: Request, res: Response) => {
  const route = req.params.route;
  const path = `/api/${route}`;

  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'Security Exception: Missing Framework Signature token.'
    });
  }

  let username = authHeader.split(' ')[1];
  // Support both raw username tokens and formatted zt_jwt_ / mbu_jwt_ tokens
  if (username.startsWith('zt_jwt_') || username.startsWith('mbu_jwt_')) {
    const parts = username.split('_');
    if (parts.length >= 3) {
      // e.g. zt_jwt_secops_admin_k7x9 -> secops_admin
      username = parts.slice(2, -1).join('_');
    }
  }

  try {
    // 1. Identity Context Lookup
    const user = await db.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
    if (!user) {
      return res.status(403).json({
        error: 'Security Framework Alert: Identity Spoofing Detected.'
      });
    }

    // 2. Role-Based Access Control Evaluation (RBAC)
    let isAuthorized = false;
    if (user.role === 'Admin') {
      isAuthorized = true;
    } else if (user.role === 'Developer' && (
      path === '/api/getDashboardMetrics' ||
      path === '/api/viewSecurityLogs' ||
      path === '/api/deployWorkerCode'
    )) {
      isAuthorized = true;
    } else if (user.role === 'Guest' && path === '/api/getDashboardMetrics') {
      isAuthorized = true;
    }

    if (!isAuthorized) {
      await db.prepare('INSERT INTO security_audit_logs (username, requested_function, calculated_risk, status, reason) VALUES (?, ?, ?, ?, ?)')
        .bind(user.username, path, 90, 'BLOCKED', `RBAC Breach: Unauthorized role validation failure for ${user.role}.`).run();
      return res.status(403).json({
        error: `RBAC Violation: Role [${user.role}] cannot invoke ${path}`,
        metrics: {
          riskScore: 90,
          status: 'BLOCKED',
          threatReason: `RBAC Breach: Unauthorized role validation failure for ${user.role}.`
        }
      });
    }

    // 3. Sequential Function Call Flow Verification
    const lastExecution = await db.prepare('SELECT requested_function FROM security_audit_logs WHERE username = ? ORDER BY id DESC LIMIT 1')
      .bind(username).first();
    let structuralRiskPenalty = 0;
    let systemReasoning = 'Identity pattern clearance matches valid criteria profiles.';

    if (lastExecution && policyConfig.enforceStrictSequence) {
      const cleanCurrent = lastExecution.requested_function.replace('/api/', '');
      const cleanNext = path.replace('/api/', '');
      const ruleMatch = await db.prepare('SELECT * FROM function_rules WHERE current_function = ? AND allowed_next_function = ?')
        .bind(cleanCurrent, cleanNext).first();

      if (!ruleMatch && cleanCurrent !== cleanNext) {
        structuralRiskPenalty = policyConfig.sequenceViolationPenalty;
        systemReasoning = `Abnormal invocation order sequence footprint discovered (${cleanCurrent} -> ${cleanNext}).`;
      }
    }

    // 4. Dynamic Total Risk Calculations
    const definitiveRiskValue = Math.min(user.base_risk_score + structuralRiskPenalty, 100);

    // 5. Automated Firewall Interception Check (Evaluated against policy threshold)
    if (definitiveRiskValue >= policyConfig.maxRiskThreshold) {
      await db.prepare('INSERT INTO security_audit_logs (username, requested_function, calculated_risk, status, reason) VALUES (?, ?, ?, ?, ?)')
        .bind(user.username, path, definitiveRiskValue, 'BLOCKED', `Mitigation Triggered: ${systemReasoning}`).run();
      return res.status(403).json({
        error: `Access Suspended: Risk Metric (${definitiveRiskValue}%) Exceeds Safe Boundary (${policyConfig.maxRiskThreshold}%).`,
        metrics: {
          riskScore: definitiveRiskValue,
          status: 'BLOCKED',
          threatReason: systemReasoning,
          baseRisk: user.base_risk_score,
          penalty: structuralRiskPenalty
        }
      });
    }

    // 6. Execution Allowed & Tracked
    await db.prepare('INSERT INTO security_audit_logs (username, requested_function, calculated_risk, status, reason) VALUES (?, ?, ?, ?, ?)')
      .bind(user.username, path, definitiveRiskValue, 'ALLOWED', systemReasoning).run();

    // Mock output dispatch logic based on the requested endpoint
    if (path === '/api/getDashboardMetrics') {
      return res.json({
        message: 'Metrics loaded successfully from edge cluster.',
        data: {
          status: 'Active Secure',
          integrity: '100%',
          serverTime: new Date().toISOString(),
          activeNodes: 4,
          protectionLevel: 'High Grade Interceptor',
          activeThreshold: `${policyConfig.maxRiskThreshold}%`
        },
        metrics: {
          riskScore: definitiveRiskValue,
          status: 'ALLOWED',
          threatReason: systemReasoning
        }
      });
    }

    if (path === '/api/viewSecurityLogs') {
      const logs = await db.prepare('SELECT * FROM security_audit_logs ORDER BY id DESC LIMIT 50').all();
      return res.json({
        message: 'Cryptographic ledger entries retrieved.',
        systemLogs: logs.results,
        metrics: {
          riskScore: definitiveRiskValue,
          status: 'ALLOWED',
          threatReason: systemReasoning
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
          status: 'DEPLOYED_STABLE'
        },
        metrics: {
          riskScore: definitiveRiskValue,
          status: 'ALLOWED',
          threatReason: systemReasoning
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
          reEncryptedRecords: 4,
          status: 'ROTATED'
        },
        metrics: {
          riskScore: definitiveRiskValue,
          status: 'ALLOWED',
          threatReason: systemReasoning
        }
      });
    }

    if (path === '/api/updateSystemPolicy') {
      return res.json({
        message: 'Enterprise Zero-Trust Policy rules updated and propagated.',
        data: {
          policyVersion: 'v2.4.0-STABLE',
          enforcementMode: 'ACTIVE_BLOCKING',
          propagationLatencyMs: 14.2
        },
        metrics: {
          riskScore: definitiveRiskValue,
          status: 'ALLOWED',
          threatReason: systemReasoning
        }
      });
    }

    if (path === '/api/purgeColdStorageBackups') {
      return res.json({
        message: 'Stale cold storage backups purged.',
        data: {
          purgedSnapshotId: 'snap-archive-9912',
          reclaimedBytes: '4.8 GB',
          complianceVerification: 'ISO-27001 Passed'
        },
        metrics: {
          riskScore: definitiveRiskValue,
          status: 'ALLOWED',
          threatReason: systemReasoning
        }
      });
    }

    return res.json({
      message: 'Requested operational function executed safely without errors.',
      executedPath: path,
      metrics: {
        riskScore: definitiveRiskValue,
        status: 'ALLOWED',
        threatReason: systemReasoning
      }
    });

  } catch (err: any) {
    return res.status(500).json({ error: 'Framework Pipeline Fault', trace: err?.message || String(err) });
  }
});

// Vite middleware & Static Serving
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Serverless Security Verification Framework running on port ${PORT}`);
  });
}

startServer();
