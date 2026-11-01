import crypto from 'crypto';

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
}

class AuditRepository {
  private events: AuditRecord[] = [];
  private alerts: SecurityAlert[] = [];
  private incidents: IncidentCase[] = [];
  private idCounter = 1;
  private lastHash = '0000000000000000000000000000000000000000000000000000000000000000';

  constructor() {
    this.seedBaseline();
  }

  private seedBaseline() {
    this.record({
      username: 'SYSTEM_BOOT',
      requested_function: '/api/v1/system/init',
      calculated_risk: 0,
      status: 'ALLOWED',
      reason: 'Serverless Security Verification Framework initialized with Zero-Trust baseline.',
      verification_latency_ms: 0.12,
      event_type: 'SYSTEM_INIT'
    });

    // Seed baseline operational incidents
    this.incidents = [
      {
        id: 'INC-2026-101',
        title: 'Cloud Metadata IMDS SSRF Probe Intercepted',
        severity: 'CRITICAL',
        status: 'CONTAINED',
        created_at: new Date(Date.now() - 7200000).toISOString(),
        root_cause: 'Malicious probe targeting 169.254.169.254 AWS/GCP metadata service credentials.',
        mitigation_steps: 'Link-local IP egress filtered at edge. Token quarantined.',
        assigned_to: 'secops_admin'
      },
      {
        id: 'INC-2026-094',
        title: 'Markov State Transition Drift Detected',
        severity: 'HIGH',
        status: 'INVESTIGATING',
        created_at: new Date(Date.now() - 14400000).toISOString(),
        root_cause: 'Lateral out-of-order jump: deployWorkerCode attempted before required telemetry inspection.',
        mitigation_steps: 'Assigned +40% sequence violation penalty. Investigating caller credentials.',
        assigned_to: 'secops_admin'
      },
      {
        id: 'INC-2026-088',
        title: 'Abnormal Request Rate Burst Exceeded Safe Boundary',
        severity: 'MEDIUM',
        status: 'RESOLVED',
        created_at: new Date(Date.now() - 28800000).toISOString(),
        root_cause: 'Scripted burst invocation exceeding 10 req/60s rate limit window.',
        mitigation_steps: 'Applied dynamic +20% threat penalty. Caller rate normalized.',
        assigned_to: 'secops_admin'
      }
    ];
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
    const id = this.idCounter++;
    const timestamp = new Date().toISOString();
    const eventType = data.event_type || 'STANDARD_VERIFICATION';

    // Cryptographic SHA-256 Hash Chaining
    const payloadToHash = `${id}|${timestamp}|${data.username}|${data.requested_function}|${data.calculated_risk}|${data.status}|${data.reason}|${this.lastHash}`;
    const hash = crypto.createHash('sha256').update(payloadToHash).digest('hex');

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

    this.lastHash = hash;
    this.events.unshift(record); // newest first

    // Real-time broadcast for SSE subscribers
    this.broadcast({ type: 'NEW_INVOCATION', data: record, timestamp });

    // Auto-create security alert if critical risk or blocked threat
    if (data.status === 'BLOCKED' || data.calculated_risk >= 75) {
      const severity = data.calculated_risk >= 90 ? 'CRITICAL' : data.calculated_risk >= 75 ? 'HIGH' : 'MEDIUM';
      const alert: SecurityAlert = {
        id: `alt_${id}_${Date.now().toString(36)}`,
        timestamp,
        alert_type: eventType,
        severity,
        threat_vector: data.requested_function,
        details: data.reason,
        ip_address: '127.0.0.1',
        username: data.username,
        acknowledged: false
      };
      this.alerts.unshift(alert);
      this.broadcast({ type: 'THREAT_ALERT', data: alert, timestamp });
    }

    return record;
  }

  public getEvents(limit = 50, offset = 0): AuditRecord[] {
    return this.events.slice(offset, offset + limit);
  }

  public getTotalCount(): number {
    return this.events.length;
  }

  public getRecentUserRequestCount(username: string, windowMs = 60000): number {
    const cutoff = Date.now() - windowMs;
    return this.events.filter(
      e => e.username.toLowerCase() === username.toLowerCase() && new Date(e.timestamp).getTime() >= cutoff
    ).length;
  }

  public getAlerts(): SecurityAlert[] {
    return [...this.alerts];
  }

  public acknowledgeAlert(id: string): boolean {
    const a = this.alerts.find(al => al.id === id);
    if (a) {
      a.acknowledged = true;
      return true;
    }
    return false;
  }

  public getIncidents(): IncidentCase[] {
    return [...this.incidents];
  }

  public getIncidentById(id: string): IncidentCase | null {
    return this.incidents.find(i => i.id === id) || null;
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
    const incident: IncidentCase = {
      id,
      title: data.title,
      severity: data.severity,
      status: data.status || 'OPEN',
      created_at: new Date().toISOString(),
      root_cause: data.root_cause || 'Under investigation by SecOps team',
      mitigation_steps: data.mitigation_steps || 'Automated perimeter quarantine applied',
      assigned_to: data.assigned_to || 'secops_admin'
    };
    this.incidents.unshift(incident);
    this.broadcast({ type: 'INCIDENT_CREATED', data: incident, timestamp: new Date().toISOString() });
    return incident;
  }

  public updateIncident(id: string, updates: Partial<IncidentCase>): IncidentCase | null {
    const inc = this.incidents.find(i => i.id === id);
    if (!inc) return null;
    Object.assign(inc, updates);
    this.broadcast({ type: 'INCIDENT_UPDATED', data: inc, timestamp: new Date().toISOString() });
    return inc;
  }

  // Real-time Event Bus for SSE & WebSockets
  private subscribers: Set<(event: { type: string; data: any; timestamp: string }) => void> = new Set();

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
    this.events = [];
    this.alerts = [];
    this.incidents = [];
    this.idCounter = 1;
    this.lastHash = '0000000000000000000000000000000000000000000000000000000000000000';
    this.seedBaseline();
  }
}

export const auditRepository = new AuditRepository();
