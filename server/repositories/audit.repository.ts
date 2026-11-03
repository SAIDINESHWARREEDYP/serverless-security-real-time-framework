import crypto from 'crypto';
import { db } from '../db.ts';

export interface AuditRecord {
  id: number;
  timestamp: string;
  username: string;
  requested_function: string;
  calculated_risk: number;
  status: 'ALLOWED' | 'BLOCKED';
  reason: string;
  verification_latency_ms: number;
  event_type: string;
  integrity_hash: string;
  prev_hash: string;
}

export interface SecurityAlert {
  id: string;
  timestamp: string;
  alert_type: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  threat_vector: string;
  details: string;
  ip_address: string;
  username: string;
  acknowledged: boolean;
}

export interface IncidentCase {
  id: string;
  title: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  status: 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'FALSE_POSITIVE';
  created_at: string;
  root_cause?: string;
  mitigation_steps?: string;
  assigned_to?: string;
  resolved_at?: string;
  resolved_by?: string;
}

class AuditRepository {
  private lastHash = '0000000000000000000000000000000000000000000000000000000000000000';
  private subscribers: Set<(event: { type: string; data: any; timestamp: string }) => void> = new Set();

  constructor() {
    this.seedBaseline();
  }

  private seedBaseline() {
    // Check if initial baseline incident exists in D1
    try {
      const existing = db.prepare('SELECT COUNT(*) as count FROM incidents').first();
      if (!existing || existing.count === 0) {
        this.createIncident({
          title: 'Cloud Metadata IMDS SSRF Probe Intercepted',
          severity: 'CRITICAL',
          status: 'CONTAINED',
          root_cause: 'Malicious probe targeting 169.254.169.254 AWS/GCP metadata service credentials.',
          mitigation_steps: 'Link-local IP egress filtered at edge. Token quarantined.',
          assigned_to: 'secops_admin'
        });
        this.createIncident({
          title: 'Markov State Transition Drift Detected',
          severity: 'HIGH',
          status: 'INVESTIGATING',
          root_cause: 'Lateral out-of-order jump: deployWorkerCode attempted before required telemetry inspection.',
          mitigation_steps: 'Assigned +40% sequence violation penalty. Investigating caller credentials.',
          assigned_to: 'secops_admin'
        });
        this.createIncident({
          title: 'Abnormal Request Rate Burst Exceeded Safe Boundary',
          severity: 'MEDIUM',
          status: 'RESOLVED',
          root_cause: 'Scripted burst invocation exceeding 10 req/60s rate limit window.',
          mitigation_steps: 'Applied dynamic +20% threat penalty. Caller rate normalized.',
          assigned_to: 'secops_admin'
        });
      }
    } catch {
      // ignore
    }
  }

  public record(data: {
    username: string;
    requested_function: string;
    calculated_risk: number;
    status: 'ALLOWED' | 'BLOCKED';
    reason: string;
    verification_latency_ms: number;
    event_type?: string;
  }): AuditRecord {
    const timestamp = new Date().toISOString();
    const eventType = data.event_type || 'STANDARD_VERIFICATION';

    // Retrieve previous hash from last recorded audit event if available
    try {
      const lastRow = db.prepare('SELECT integrity_hash FROM audit_events ORDER BY id DESC LIMIT 1').first();
      if (lastRow && lastRow.integrity_hash) {
        this.lastHash = lastRow.integrity_hash;
      }
    } catch {
      // fallback to current in-memory lastHash
    }

    // Insert into persistent D1 SQLite audit_events
    const runResult = db.prepare(
      `INSERT INTO audit_events (
        username, requested_function, calculated_risk, status, reason, verification_latency_ms, event_type, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      data.username,
      data.requested_function,
      data.calculated_risk,
      data.status,
      data.reason,
      data.verification_latency_ms,
      eventType,
      timestamp
    ).run();

    const id = Number(runResult.lastRowId || Date.now());

    // Cryptographic SHA-256 Hash Chaining
    const payloadToHash = `${id}|${timestamp}|${data.username}|${data.requested_function}|${data.calculated_risk}|${data.status}|${data.reason}|${this.lastHash}`;
    const hash = crypto.createHash('sha256').update(payloadToHash).digest('hex');
    this.lastHash = hash;

    // Insert into security_audit_logs for audit compatibility
    try {
      db.prepare(
        `INSERT INTO security_audit_logs (
          id, timestamp, username, requested_function, calculated_risk, status, reason, verification_latency_ms, event_type
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        id,
        timestamp,
        data.username,
        data.requested_function,
        data.calculated_risk,
        data.status,
        data.reason,
        data.verification_latency_ms,
        eventType
      ).run();
    } catch {
      // ignore duplicate id on compatibility table
    }

    const record: AuditRecord = {
      id,
      timestamp,
      username: data.username,
      requested_function: data.requested_function,
      calculated_risk: data.calculated_risk,
      status: data.status,
      reason: data.reason,
      verification_latency_ms: data.verification_latency_ms,
      event_type: eventType,
      integrity_hash: hash,
      prev_hash: this.lastHash
    };

    // Real-time broadcast for SSE subscribers
    this.broadcast({ type: 'NEW_INVOCATION', data: record, timestamp });

    // Auto-create security alert if critical risk or blocked threat
    if (data.status === 'BLOCKED' || data.calculated_risk >= 75) {
      const severity = data.calculated_risk >= 90 ? 'CRITICAL' : data.calculated_risk >= 75 ? 'HIGH' : 'MEDIUM';
      const alertId = `alt_${id}_${Date.now().toString(36)}`;
      const alert: SecurityAlert = {
        id: alertId,
        timestamp,
        alert_type: eventType,
        severity,
        threat_vector: data.requested_function,
        details: data.reason,
        ip_address: '127.0.0.1',
        username: data.username,
        acknowledged: false
      };

      // Safely resolve user_id foreign key from users table (must reference users(id) or NULL)
      let alertUserId: string | null = null;
      if (data.username) {
        try {
          const u = db.getUser(data.username);
          if (u?.id) {
            alertUserId = u.id;
          }
        } catch {
          // ignore
        }
      }

      // Check if invocation_id exists in invocation_history (must reference invocation_history(id) or NULL)
      let alertInvocationId: string | null = null;
      try {
        const invRow = db.prepare('SELECT id FROM invocation_history WHERE id = ? LIMIT 1').bind(String(id)).first<any>();
        if (invRow?.id) {
          alertInvocationId = invRow.id;
        }
      } catch {
        // ignore
      }

      try {
        db.prepare(
          `INSERT INTO security_alerts (
            id, invocation_id, alert_type, severity, threat_vector, details_json, ip_address, user_id, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(
          alertId,
          alertInvocationId,
          eventType,
          severity,
          data.requested_function,
          JSON.stringify({ username: data.username, reason: data.reason, risk: data.calculated_risk }),
          '127.0.0.1',
          alertUserId,
          timestamp
        ).run();
      } catch (err: any) {
        console.warn('[D1 security_alerts insert note]', err?.message);
      }

      this.broadcast({ type: 'THREAT_ALERT', data: alert, timestamp });
    }

    return record;
  }

  public getEvents(limit = 50, offset = 0): AuditRecord[] {
    const rows = db.prepare(
      'SELECT * FROM audit_events ORDER BY id DESC LIMIT ? OFFSET ?'
    ).bind(limit, offset).all<any>();

    return (rows.results || []).map((r) => ({
      id: r.id,
      timestamp: r.timestamp || r.created_at,
      username: r.username,
      requested_function: r.requested_function,
      calculated_risk: r.calculated_risk,
      status: r.status as 'ALLOWED' | 'BLOCKED',
      reason: r.reason,
      verification_latency_ms: r.verification_latency_ms || 0.28,
      event_type: r.event_type || 'STANDARD_VERIFICATION',
      integrity_hash: r.integrity_hash || this.lastHash,
      prev_hash: r.prev_hash || '0000000000000000000000000000000000000000000000000000000000000000'
    }));
  }

  public getTotalCount(): number {
    const row = db.prepare('SELECT COUNT(*) as count FROM audit_events').first<any>();
    return row?.count || 0;
  }

  public getRecentUserRequestCount(username: string, windowMs = 60000): number {
    return db.getRecentRequestCount(username, windowMs);
  }

  public getAlerts(): SecurityAlert[] {
    const rows = db.prepare('SELECT * FROM security_alerts ORDER BY created_at DESC LIMIT 100').all<any>();
    return (rows.results || []).map((r) => {
      let username = 'anonymous';
      if (r.details_json) {
        try {
          const parsed = JSON.parse(r.details_json);
          if (parsed.username) username = parsed.username;
        } catch {
          // ignore
        }
      }
      if (username === 'anonymous' && r.user_id) {
        const u = db.getUser(r.user_id);
        username = u?.username || r.user_id;
      }
      return {
        id: r.id,
        timestamp: r.created_at,
        alert_type: r.alert_type,
        severity: r.severity as any,
        threat_vector: r.threat_vector,
        details: r.details_json,
        ip_address: r.ip_address,
        username,
        acknowledged: Boolean(r.acknowledged_at)
      };
    });
  }

  public acknowledgeAlert(id: string): boolean {
    const res = db.prepare(
      "UPDATE security_alerts SET acknowledged_at = datetime('now', 'utc'), acknowledged_by = 'secops_admin' WHERE id = ?"
    ).bind(id).run();
    return (res.changes || 0) > 0;
  }

  public getIncidents(): IncidentCase[] {
    const rows = db.prepare('SELECT * FROM incidents ORDER BY created_at DESC').all<any>();
    return (rows.results || []).map((r) => {
      let assignee = r.assigned_to;
      if (assignee) {
        const u = db.getUser(assignee);
        if (u) assignee = u.username;
      }
      return {
        id: r.id,
        title: r.title,
        severity: r.severity as any,
        status: r.status as any,
        created_at: r.created_at,
        root_cause: r.root_cause,
        mitigation_steps: r.mitigation_steps,
        assigned_to: assignee || 'secops_admin',
        resolved_at: r.resolved_at,
        resolved_by: r.resolved_by
      };
    });
  }

  public getIncidentById(id: string): IncidentCase | null {
    const r = db.prepare('SELECT * FROM incidents WHERE id = ? LIMIT 1').bind(id).first<any>();
    if (!r) return null;
    let assignee = r.assigned_to;
    if (assignee) {
      const u = db.getUser(assignee);
      if (u) assignee = u.username;
    }
    return {
      id: r.id,
      title: r.title,
      severity: r.severity as any,
      status: r.status as any,
      created_at: r.created_at,
      root_cause: r.root_cause,
      mitigation_steps: r.mitigation_steps,
      assigned_to: assignee || 'secops_admin',
      resolved_at: r.resolved_at,
      resolved_by: r.resolved_by
    };
  }

  public createIncident(data: {
    title: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    status?: 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'FALSE_POSITIVE';
    root_cause?: string;
    mitigation_steps?: string;
    assigned_to?: string;
  }): IncidentCase {
    const id = `INC-${new Date().getFullYear()}-${Math.floor(100 + Math.random() * 900)}`;
    const nowIso = new Date().toISOString();
    const status = data.status || 'OPEN';

    // Resolve assigned_to foreign key: must match users(id) or be NULL
    let resolvedAssigneeId: string | null = null;
    const assigneeInput = data.assigned_to || 'secops_admin';
    try {
      const u = db.getUser(assigneeInput);
      if (u?.id) {
        resolvedAssigneeId = u.id;
      }
    } catch {
      // ignore
    }

    // Persist to D1 SQLite incidents table
    db.prepare(
      `INSERT INTO incidents (
        id, title, severity, status, root_cause, mitigation_steps, assigned_to, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      id,
      data.title,
      data.severity,
      status,
      data.root_cause || 'Under investigation by SecOps team',
      data.mitigation_steps || 'Automated perimeter quarantine applied',
      resolvedAssigneeId,
      nowIso
    ).run();

    const incident: IncidentCase = {
      id,
      title: data.title,
      severity: data.severity,
      status,
      created_at: nowIso,
      root_cause: data.root_cause || 'Under investigation by SecOps team',
      mitigation_steps: data.mitigation_steps || 'Automated perimeter quarantine applied',
      assigned_to: data.assigned_to || 'secops_admin'
    };

    this.broadcast({ type: 'INCIDENT_CREATED', data: incident, timestamp: nowIso });
    return incident;
  }

  public updateIncident(id: string, updates: Partial<IncidentCase>): IncidentCase | null {
    const inc = this.getIncidentById(id);
    if (!inc) return null;

    const fields: string[] = [];
    const values: any[] = [];

    if (updates.status) {
      fields.push('status = ?');
      values.push(updates.status);
      if (updates.status === 'RESOLVED') {
        fields.push("resolved_at = datetime('now', 'utc')");
      }
    }
    if (updates.mitigation_steps) {
      fields.push('mitigation_steps = ?');
      values.push(updates.mitigation_steps);
    }
    if (updates.root_cause) {
      fields.push('root_cause = ?');
      values.push(updates.root_cause);
    }
    if (updates.assigned_to !== undefined) {
      let resolvedAssigneeId: string | null = null;
      if (updates.assigned_to) {
        try {
          const u = db.getUser(updates.assigned_to);
          if (u?.id) {
            resolvedAssigneeId = u.id;
          }
        } catch {
          // ignore
        }
      }
      fields.push('assigned_to = ?');
      values.push(resolvedAssigneeId);
    }

    if (fields.length > 0) {
      values.push(id);
      db.prepare(`UPDATE incidents SET ${fields.join(', ')} WHERE id = ?`).bind(...values).run();
    }

    const updated = this.getIncidentById(id);
    this.broadcast({ type: 'INCIDENT_UPDATED', data: updated, timestamp: new Date().toISOString() });
    return updated;
  }

  // Real-time Event Bus for SSE & WebSockets
  public subscribe(listener: (event: { type: string; data: any; timestamp: string }) => void): () => void {
    this.subscribers.add(listener);
    return () => {
      this.subscribers.delete(listener);
    };
  }

  public broadcast(event: { type: string; data: any; timestamp: string }) {
    for (const listener of this.subscribers) {
      try {
        listener(event);
      } catch {
        // ignore subscriber delivery error
      }
    }
  }

  public clear() {
    db.clearLogs();
    this.lastHash = '0000000000000000000000000000000000000000000000000000000000000000';
    this.seedBaseline();
  }
}

export const auditRepository = new AuditRepository();
