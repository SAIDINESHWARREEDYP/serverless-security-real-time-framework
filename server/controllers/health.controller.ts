import { Request, Response } from 'express';
import { db } from '../db.ts';

export const healthController = {
  getHealth(req: Request, res: Response) {
    const t0 = performance.now();
    try {
      const row = db.prepare('SELECT COUNT(*) as c FROM audit_events').first<{ c: number }>();
      const queryDuration = Number((performance.now() - t0).toFixed(3));
      const totalEvents = Number(row?.c ?? 0);

      return res.json({
        status: 'UP',
        cluster: 'Local Node.js Express Runtime',
        databaseEngine: 'Node.js SQLite (WAL ACID)',
        databaseConnection: 'ACTIVE',
        d1Status: 'CONNECTED',
        d1LatencyMs: queryDuration,
        isConnected: true,
        recordsVerified: totalEvents,
        timestamp: new Date().toISOString(),
        uptimeSeconds: Math.floor(process.uptime()),
        verificationMode: 'FAIL_CLOSED_ZERO_TRUST'
      });
    } catch (err: any) {
      const queryDuration = Number((performance.now() - t0).toFixed(3));
      return res.status(503).json({
        status: 'DOWN',
        cluster: 'Local Node.js Express Runtime',
        databaseEngine: 'Node.js SQLite (WAL ACID)',
        databaseConnection: 'DISCONNECTED',
        d1Status: 'ERROR',
        d1LatencyMs: queryDuration,
        isConnected: false,
        recordsVerified: 0,
        error: err?.message || 'Database health check failed',
        timestamp: new Date().toISOString(),
        uptimeSeconds: Math.floor(process.uptime()),
        verificationMode: 'FAIL_CLOSED_ZERO_TRUST'
      });
    }
  },

  getD1Latency(req: Request, res: Response) {
    const t0 = performance.now();
    try {
      const countRow = db.prepare('SELECT COUNT(*) as c FROM audit_events').first<{ c: number }>();
      const activeRow = db.prepare(
        "SELECT COUNT(*) as c FROM active_sessions WHERE revoked = 0 AND expires_at > datetime('now')"
      ).first<{ c: number }>();
      const latRows = db.prepare(
        'SELECT verification_latency_ms FROM audit_events WHERE verification_latency_ms IS NOT NULL ORDER BY id DESC LIMIT 200'
      ).all<{ verification_latency_ms: number }>();
      const queryDuration = Number((performance.now() - t0).toFixed(3));

      const values = (latRows.results || [])
        .map((r) => Number(r.verification_latency_ms))
        .filter((n) => Number.isFinite(n) && n >= 0)
        .sort((a, b) => a - b);

      const avgLatencyMs = values.length > 0
        ? Number((values.reduce((sum, v) => sum + v, 0) / values.length).toFixed(3))
        : queryDuration;
      const p95LatencyMs = values.length > 0
        ? Number(values[Math.min(values.length - 1, Math.floor(values.length * 0.95))].toFixed(3))
        : queryDuration;
      const p99LatencyMs = values.length > 0
        ? Number(values[Math.min(values.length - 1, Math.floor(values.length * 0.99))].toFixed(3))
        : queryDuration;

      return res.json({
        status: 'HEALTHY',
        d1LatencyMs: queryDuration,
        avgLatencyMs,
        p95LatencyMs,
        p99LatencyMs,
        recordsVerified: Number(countRow?.c ?? 0),
        activeConnections: Number(activeRow?.c ?? 0),
        connectionStatus: 'ACTIVE',
        engine: 'Node.js SQLite (WAL ACID)'
      });
    } catch (err: any) {
      const queryDuration = Number((performance.now() - t0).toFixed(3));
      return res.status(503).json({
        status: 'UNHEALTHY',
        d1LatencyMs: queryDuration,
        connectionStatus: 'DISCONNECTED',
        error: err?.message || 'Latency telemetry query failed',
        engine: 'Node.js SQLite (WAL ACID)'
      });
    }
  }
};
