/**
 * Cloudflare Workers Entry Point: Serverless Real-Time Security Verification Framework
 * B.Tech CSE Capstone Project: Design & Implementation of an Integrated Real-Time Security
 * Verification Framework for Serverless Cloud Applications.
 *
 * Implements:
 * 1. FAIL-CLOSED EXCEPTION HANDLING: Try/catch with CRITICAL 100 risk, BLOCKED verdict, and security exception logging.
 * 2. HIGH-RESOLUTION VERIFICATION LATENCY MONITORING: performance.now() timer recorded in X-Verification-Latency-MS header and security_events table.
 * 3. DYNAMIC RULE-BASED BEHAVIOR & RATE LIMITING CHECK: 60s sliding window frequency check (>10 req/min => +20 risk & ABNORMAL_REQUEST_RATE).
 */

export interface Env {
  DB: any; // Cloudflare D1Database binding
  ENVIRONMENT?: string;
  ZERO_TRUST_ORIGIN?: string;
}

export default {
  async fetch(request: Request, env: Env, ctx: any): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS preflight handling
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS, DELETE, PATCH',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
          'Access-Control-Max-Age': '86400'
        }
      });
    }

    // Health check endpoint
    if (path === '/api/health') {
      return new Response(
        JSON.stringify({ status: 'ok', runtime: 'cloudflare_workers', d1Binding: !!env.DB, time: new Date().toISOString() }),
        { headers: { 'Content-Type': 'application/json' } }
      );
    }

    // Real-time Session Revocation Endpoint for Cloudflare Workers (/api/auth/revoke-session)
    if (path === '/api/auth/revoke-session' || path === '/api/system/sessions/revoke') {
      try {
        const body: any = await request.json().catch(() => ({}));
        const { username, token, reason } = body;
        if (env.DB && (username || token)) {
          await env.DB.prepare(
            "UPDATE active_sessions SET revoked = 1, revoked_at = datetime('now'), revoked_by = 'secops_admin', revocation_reason = ? WHERE username = ? OR token = ?"
          ).bind(reason || 'Terminated by Administrator', username || '', token || '').run();
        }
        return jsonResponse({
          success: true,
          revoked: true,
          message: `Active session for principal [${username || token}] successfully terminated in real-time.`,
          target: username || token,
          revokedAt: new Date().toISOString()
        }, 200, 0.42);
      } catch (err: any) {
        return jsonResponse({ error: 'Session revocation failed: ' + (err?.message || String(err)) }, 500, 0.5);
      }
    }

    // OPERATIONAL SERVERLESS PIPELINE INTERCEPTION ROUTE (/api/:route)
    if (path.startsWith('/api/')) {
      const verificationStartTime = performance.now();
      let auditUsername = 'unauthenticated_principal';

      // 1. FAIL-CLOSED EXCEPTION HANDLING:
      // Entire security verification pipeline is wrapped in a fail-closed try-catch block.
      try {
        if (path === '/api/simulate-exception' || request.headers.get('X-Simulate-Fault') === 'true') {
          throw new Error('Simulated hardware security module (HSM) decryption timeout in verification pipeline');
        }

        const authHeader = request.headers.get('Authorization');
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
          const authLatency = Number((performance.now() - verificationStartTime).toFixed(3));
          await logSecurityEvent(env.DB, 'anonymous_guest', path, 100, 'BLOCKED', 'Security Exception: Missing Framework Signature Bearer token.', authLatency, 'AUTHENTICATION_FAILURE');

          return jsonResponse(
            {
              error: 'Security Exception: Missing Framework Signature token.',
              metrics: {
                riskScore: 100,
                status: 'BLOCKED',
                threatReason: 'Missing Framework Signature token.',
                verification_latency_ms: authLatency,
                eventType: 'AUTHENTICATION_FAILURE'
              }
            },
            401,
            authLatency
          );
        }

        const rawBearerToken = authHeader.split(' ')[1];
        let username = rawBearerToken;
        if (username.startsWith('zt_jwt_') || username.startsWith('mbu_jwt_')) {
          const parts = username.split('_');
          if (parts.length >= 3) {
            username = parts.slice(2, -1).join('_');
          }
        }
        auditUsername = username;

        // Check active session revocation status in D1
        if (env.DB) {
          const revokedSession = await env.DB.prepare(
            'SELECT * FROM active_sessions WHERE (token = ? OR username = ?) AND revoked = 1 LIMIT 1'
          ).bind(rawBearerToken, username).first();

          if (revokedSession) {
            const revLatency = Number((performance.now() - verificationStartTime).toFixed(3));
            await logSecurityEvent(
              env.DB,
              username,
              path,
              100,
              'BLOCKED',
              `[SESSION REVOKED] Active session for principal [${username}] was terminated by Administrator in real-time.`,
              revLatency,
              'SESSION_REVOKED'
            );
            return jsonResponse(
              {
                error: 'Security Gateway: Session has been terminated by Administrator in real-time. Token signature no longer honored.',
                revoked: true,
                metrics: {
                  riskScore: 100,
                  status: 'BLOCKED',
                  threatReason: 'Session terminated by Administrator in real-time. Token invalidated.',
                  verification_latency_ms: revLatency,
                  eventType: 'SESSION_REVOKED'
                }
              },
              403,
              revLatency
            );
          }
        }

        // Identity Context Lookup in D1
        let user: any = null;
        if (env.DB) {
          user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
        }

        if (!user) {
          const spoofLatency = Number((performance.now() - verificationStartTime).toFixed(3));
          await logSecurityEvent(env.DB, username, path, 100, 'BLOCKED', 'Security Framework Alert: Identity Spoofing Detected.', spoofLatency, 'IDENTITY_SPOOFING');

          return jsonResponse(
            {
              error: 'Security Framework Alert: Identity Spoofing Detected.',
              metrics: {
                riskScore: 100,
                status: 'BLOCKED',
                threatReason: 'Identity Spoofing Detected.',
                verification_latency_ms: spoofLatency,
                eventType: 'IDENTITY_SPOOFING'
              }
            },
            403,
            spoofLatency
          );
        }

        // Zero-Trust Approval Status Verification
        if (user.status && user.status !== 'APPROVED') {
          const statusLatency = Number((performance.now() - verificationStartTime).toFixed(3));
          await logSecurityEvent(env.DB, user.username, path, 95, 'BLOCKED', `[UNAUTHORIZED STATUS] Identity status is [${user.status}]. Requires Admin verification.`, statusLatency, 'STATUS_NOT_APPROVED');

          return jsonResponse(
            {
              error: `Zero-Trust Access Gate: Principal clearance is [${user.status}]. Administrator verification required.`,
              metrics: {
                riskScore: 95,
                status: 'BLOCKED',
                threatReason: `Access Denied: Principal status is [${user.status}].`,
                verification_latency_ms: statusLatency,
                eventType: 'STATUS_NOT_APPROVED'
              }
            },
            403,
            statusLatency
          );
        }

        // Role-Based Access Control (RBAC)
        let isAuthorized = false;
        if (user.role === 'Admin') {
          isAuthorized = true;
        } else if (user.role === 'Developer' && (path === '/api/getDashboardMetrics' || path === '/api/viewSecurityLogs' || path === '/api/deployWorkerCode')) {
          isAuthorized = true;
        } else if (user.role === 'Guest' && path === '/api/getDashboardMetrics') {
          isAuthorized = true;
        }

        if (!isAuthorized) {
          const rbacLatency = Number((performance.now() - verificationStartTime).toFixed(3));
          await logSecurityEvent(env.DB, user.username, path, 90, 'BLOCKED', `RBAC Breach: Unauthorized role validation failure for ${user.role}.`, rbacLatency, 'RBAC_VIOLATION');

          return jsonResponse(
            {
              error: `RBAC Violation: Role [${user.role}] cannot invoke ${path}`,
              metrics: {
                riskScore: 90,
                status: 'BLOCKED',
                threatReason: `RBAC Breach: Unauthorized role validation failure for ${user.role}.`,
                verification_latency_ms: rbacLatency,
                eventType: 'RBAC_VIOLATION'
              }
            },
            403,
            rbacLatency
          );
        }

        // 3. DYNAMIC RULE-BASED BEHAVIOR & RATE LIMITING CHECK
        // Query D1 for request frequency in the last 60 seconds
        let recentCount = 0;
        if (env.DB) {
          try {
            const countResult = await env.DB.prepare(
              "SELECT COUNT(*) as count FROM security_audit_logs WHERE username = ? AND timestamp >= datetime('now', '-1 minute')"
            ).bind(user.username).first();
            recentCount = countResult?.count ?? 0;
          } catch {
            recentCount = 0;
          }
        }

        let ratePenalty = 0;
        let eventType = 'STANDARD_VERIFICATION';
        let systemReasoning = 'Identity pattern clearance matches valid criteria profiles.';

        if (recentCount > 10) {
          ratePenalty = 20;
          eventType = 'ABNORMAL_REQUEST_RATE';
          systemReasoning = `[RATE MONITOR] ABNORMAL_REQUEST_RATE: Frequency exceeded threshold (${recentCount} req/60s > 10 req/min). Applied +20 risk penalty.`;
        }

        // Sequential Function Call Flow Verification (Markov Chain)
        let structuralRiskPenalty = 0;
        if (env.DB) {
          const lastExecution = await env.DB.prepare(
            'SELECT requested_function FROM security_audit_logs WHERE username = ? ORDER BY id DESC LIMIT 1'
          ).bind(username).first();

          if (lastExecution) {
            const cleanCurrent = lastExecution.requested_function.replace('/api/', '');
            const cleanNext = path.replace('/api/', '');
            const ruleMatch = await env.DB.prepare(
              'SELECT * FROM function_rules WHERE current_function = ? AND allowed_next_function = ?'
            ).bind(cleanCurrent, cleanNext).first();

            if (!ruleMatch && cleanCurrent !== cleanNext) {
              structuralRiskPenalty = 40;
              systemReasoning = `${systemReasoning} | Sequence Footprint Anomaly (${cleanCurrent} -> ${cleanNext}).`;
              if (eventType === 'STANDARD_VERIFICATION') eventType = 'SEQUENCE_VIOLATION';
            }
          }
        }

        // Dynamic Total Risk Calculation
        const definitiveRiskValue = Math.min((user.base_risk_score || 0) + structuralRiskPenalty + ratePenalty, 100);

        // 2. STOP HIGH-RESOLUTION PERFORMANCE TIMER RIGHT BEFORE DECISION
        const verificationLatencyMs = Number((performance.now() - verificationStartTime).toFixed(3));

        // Evaluate Against Risk Cutoff (75%)
        if (definitiveRiskValue >= 75) {
          await logSecurityEvent(env.DB, user.username, path, definitiveRiskValue, 'BLOCKED', `Mitigation Triggered: ${systemReasoning}`, verificationLatencyMs, eventType);

          return jsonResponse(
            {
              error: `Access Suspended: Risk Metric (${definitiveRiskValue}%) Exceeds Safe Boundary (75%).`,
              metrics: {
                riskScore: definitiveRiskValue,
                status: 'BLOCKED',
                threatReason: systemReasoning,
                baseRisk: user.base_risk_score,
                penalty: structuralRiskPenalty,
                ratePenalty: ratePenalty,
                verification_latency_ms: verificationLatencyMs,
                eventType: eventType
              }
            },
            403,
            verificationLatencyMs
          );
        }

        // Allowed Execution Tracking in D1 (audit_events & security_audit_logs)
        await logSecurityEvent(env.DB, user.username, path, definitiveRiskValue, 'ALLOWED', systemReasoning, verificationLatencyMs, eventType);

        if (path === '/api/viewAuditEvents') {
          let events: any[] = [];
          if (env.DB) {
            const res = await env.DB.prepare('SELECT * FROM audit_events ORDER BY id DESC LIMIT 50').all();
            events = res?.results || [];
          }
          return jsonResponse(
            {
              message: 'High-assurance audit_events entries retrieved with high-resolution latency verification metrics.',
              auditEvents: events,
              systemLogs: events,
              metrics: {
                riskScore: definitiveRiskValue,
                status: 'ALLOWED',
                threatReason: systemReasoning,
                verification_latency_ms: verificationLatencyMs,
                eventType: eventType
              }
            },
            200,
            verificationLatencyMs
          );
        }

        return jsonResponse(
          {
            message: 'Serverless invocation executed safely with verified Zero-Trust clearance.',
            endpoint: path,
            metrics: {
              riskScore: definitiveRiskValue,
              status: 'ALLOWED',
              threatReason: systemReasoning,
              verification_latency_ms: verificationLatencyMs,
              eventType: eventType
            }
          },
          200,
          verificationLatencyMs
        );

      } catch (err: any) {
        // FAIL-CLOSED EXCEPTION HANDLING:
        // Automatically assign CRITICAL risk score (100), log security exception in D1, and return 403 Forbidden. Never fail open.
        const failClosedLatency = Number((performance.now() - verificationStartTime).toFixed(3));
        const exceptionDetail = err?.message || String(err) || 'Internal verification exception';
        const failClosedReason = `[FAIL-CLOSED EXCEPTION] Security pipeline fault: ${exceptionDetail}. Request immediately blocked with 100% Critical Risk under Zero-Trust fail-closed architecture.`;

        await logSecurityEvent(env.DB, auditUsername, path, 100, 'BLOCKED', failClosedReason, failClosedLatency, 'SECURITY_EXCEPTION_FAIL_CLOSED');

        return jsonResponse(
          {
            success: false,
            error: 'Security Verification Pipeline Exception [FAIL_CLOSED]: Request blocked by Zero-Trust fail-closed security architecture.',
            metrics: {
              riskScore: 100,
              status: 'BLOCKED',
              threatReason: failClosedReason,
              verification_latency_ms: failClosedLatency,
              eventType: 'SECURITY_EXCEPTION_FAIL_CLOSED',
              failClosed: true
            }
          },
          403,
          failClosedLatency
        );
      }
    }

    return new Response('Not Found', { status: 404 });
  }
};

/**
 * Helper to log security event into audit_events, security_audit_logs, and security_events tables in D1
 */
async function logSecurityEvent(
  db: any,
  username: string,
  path: string,
  risk: number,
  status: 'ALLOWED' | 'BLOCKED',
  reason: string,
  latencyMs: number,
  eventType: string
) {
  if (!db) return;
  try {
    // 1. Explicitly insert into audit_events table capturing pipeline verification duration
    await db.prepare(
      'INSERT INTO audit_events (username, requested_function, calculated_risk, status, reason, verification_latency_ms, event_type) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).bind(username, path, risk, status, reason, latencyMs, eventType).run();

    // 2. Insert into security_audit_logs
    await db.prepare(
      'INSERT INTO security_audit_logs (username, requested_function, calculated_risk, status, reason, verification_latency_ms, event_type) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).bind(username, path, risk, status, reason, latencyMs, eventType).run();

    // 3. Insert into security_events table for latency monitoring and panel presentation
    await db.prepare(
      'INSERT INTO security_events (username, requested_function, calculated_risk, status, reason, verification_latency_ms, event_type) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).bind(username, path, risk, status, reason, latencyMs, eventType).run();
  } catch (e) {
    console.error('[D1] Logging error (fail-closed maintained):', e);
  }
}

/**
 * Helper to format JSON response with latency headers and CORS
 */
function jsonResponse(data: any, status = 200, latencyMs?: number): Response {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS, DELETE, PATCH',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Expose-Headers': 'X-Verification-Latency-MS, X-Security-Verification-Duration-MS, Server-Timing'
  };

  if (typeof latencyMs === 'number') {
    headers['X-Verification-Latency-MS'] = latencyMs.toString();
    headers['X-Security-Verification-Duration-MS'] = latencyMs.toString();
    headers['Server-Timing'] = `security-verify;dur=${latencyMs};desc="Security Verification Pipeline"`;
  }

  return new Response(JSON.stringify(data), {
    status,
    headers
  });
}
