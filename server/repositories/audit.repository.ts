import crypto from 'crypto';
import { db } from '../db.ts';
import {
  CONFIG,
  computeAnchorKeyFingerprint,
  deriveAnchorHmacKey,
  parseAnchorKeyRing
} from '../config/env.ts';

export const TRUSTED_AUDIT_GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

export type AuditBrokenLinkReason =
  | 'HASH_MISMATCH'
  | 'CHAIN_LINK_BREAK'
  | 'INVALID_FORMAT'
  | 'GENESIS_MISMATCH'
  | 'TAIL_TRUNCATION'
  | 'UNTRACKED_INSERTION'
  | 'HEAD_HASH_MISMATCH'
  | 'ANCHOR_HMAC_MISMATCH'
  | 'ORDER_ANOMALY'
  | 'LEGACY_SNAPSHOT_TAMPERED'
  | 'EPOCH_HMAC_MISMATCH'
  | 'EPOCH_BOUNDARY_MISMATCH';

export type AuditVerificationStatus =
  | 'FULL_LEDGER_VERIFIED'
  | 'VERIFIED_EPOCH_WITH_ARCHIVED_LEGACY'
  | 'LEGACY_SNAPSHOT_TAMPERED'
  | 'INTEGRITY_DISCREPANCY'
  | 'EMPTY_LEDGER';

export interface AuditBrokenLink {
  id: number;
  reason: AuditBrokenLinkReason;
  detail?: string;
}

export interface AuditEpochInfo {
  id: number;
  epochLabel: string;
  legacyCutoffMaxId: number;
  legacyRecordCount: number;
  legacySnapshotSha256: string;
  epochStartId: number;
  epochGenesisHash: string;
  reason: string | null;
  createdBy: string;
  createdAt: string;
  keyId: string;
  snapshotVerified: boolean;
  epochHmacVerified: boolean;
}

export interface AuditChainAnchorStatus {
  present: boolean;
  verified: boolean;
  keyId: string | null;
  previousKeyId: string | null;
  rotatedAt: string | null;
  activeKeyId: string;
  keySource: string;
  keyFingerprint: string;
  activeEpoch: AuditEpochInfo | null;
  genesisHash: string;
  headId: number;
  headHash: string | null;
  recordCount: number;
  updatedAt: string | null;
}

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

export interface VerifyIntegrityChainResult {
  chainIntact: boolean;
  fullLedgerVerified: boolean;
  verifiedEpochIntact: boolean;
  verificationStatus: AuditVerificationStatus;
  genesisVerified: boolean;
  trustedGenesisHash: string;
  anchorPresent: boolean;
  anchorVerified: boolean;
  anchorKeyId: string | null;
  anchorPreviousKeyId: string | null;
  anchorRotatedAt: string | null;
  keySource: string;
  keyFingerprint: string;
  legacyRecordsCount: number;
  legacyCutoffMaxId: number;
  legacySnapshotVerified: boolean | null;
  verifiedEpochCount: number;
  suggestedLegacyCutoffMaxId: number | null;
  epochLabel: string | null;
  activeEpoch: AuditEpochInfo | null;
  totalInLedger: number;
  totalChecked: number;
  verifiedCount: number;
  brokenLinks: AuditBrokenLink[];
  headHash: string | null;
  verifiedAt: string;
}

function safeHexEqual(a: string | null | undefined, b: string | null | undefined): boolean {
  if (!a || !b) return false;
  if (!/^[0-9a-f]+$/i.test(a) || !/^[0-9a-f]+$/i.test(b) || a.length !== b.length) {
    return false;
  }
  const bufA = Buffer.from(a.toLowerCase(), 'hex');
  const bufB = Buffer.from(b.toLowerCase(), 'hex');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function computeRowIntegrityHash(r: {
  timestamp?: string | null;
  created_at?: string | null;
  username: string;
  requested_function: string;
  calculated_risk: number;
  status: string;
  reason: string;
  prev_hash?: string | null;
}): string {
  const ts = r.timestamp || r.created_at || '';
  const payload = `${ts}|${r.username}|${r.requested_function}|${r.calculated_risk}|${r.status}|${r.reason}|${r.prev_hash || ''}`;
  return crypto.createHash('sha256').update(payload).digest('hex');
}

function isRowStructurallyValidAndHashed(r: any): boolean {
  if (
    !r?.integrity_hash ||
    !/^[0-9a-f]{64}$/i.test(String(r.integrity_hash)) ||
    !r?.prev_hash ||
    !/^[0-9a-f]{64}$/i.test(String(r.prev_hash))
  ) {
    return false;
  }
  const expected = computeRowIntegrityHash(r);
  return safeHexEqual(String(r.integrity_hash), expected);
}

class AuditRepository {
  private lastHash = TRUSTED_AUDIT_GENESIS_HASH;
  private subscribers: Set<(event: { type: string; data: any; timestamp: string }) => void> = new Set();

  private activeKeyId: string = CONFIG.AUDIT_ANCHOR_KEY_ID;
  private activeKey: string = CONFIG.AUDIT_ANCHOR_KEY;
  private activeKeySource: string = CONFIG.AUDIT_ANCHOR_KEY_SOURCE;
  private activeKeyFingerprint: string = CONFIG.AUDIT_ANCHOR_KEY_FINGERPRINT;
  private previousKeys: Map<string, string> = new Map(Object.entries(CONFIG.AUDIT_ANCHOR_PREVIOUS_KEYS || {}));
  private rotatedKeysThisProcess: Map<string, string> = new Map();

  constructor() {
    this.ensureAnchorTable();
    this.seedBaseline();
  }

  public reloadAnchorKeysFromConfig() {
    const rawAnchorSecret = process.env.AUDIT_ANCHOR_KEY?.trim() || CONFIG.JWT_SECRET;
    this.activeKeyId = process.env.AUDIT_ANCHOR_KEY_ID?.trim() || CONFIG.AUDIT_ANCHOR_KEY_ID || 'anchor-v1';
    this.activeKey = deriveAnchorHmacKey(rawAnchorSecret);
    this.activeKeySource = process.env.AUDIT_ANCHOR_KEY?.trim()
      ? 'AUDIT_ANCHOR_KEY_ENV'
      : CONFIG.AUDIT_ANCHOR_KEY_SOURCE;
    this.activeKeyFingerprint = computeAnchorKeyFingerprint(this.activeKey);
    this.previousKeys = new Map(Object.entries(parseAnchorKeyRing(process.env.AUDIT_ANCHOR_PREVIOUS_KEYS)));
  }

  private getTableColumns(tableName: string): Set<string> {
    try {
      const safeName = tableName.replace(/[^a-zA-Z0-9_]/g, '');
      const res = db.prepare(`PRAGMA table_info(${safeName})`).all<{ name: string }>();
      return new Set((res.results || []).map((c) => c.name.toLowerCase()));
    } catch {
      return new Set();
    }
  }

  private ensureAnchorTable() {
    try {
      db.exec(`
        CREATE TABLE IF NOT EXISTS audit_chain_anchor (
          id INTEGER PRIMARY KEY CHECK (id = 1),
          genesis_hash TEXT NOT NULL,
          head_id INTEGER NOT NULL,
          head_hash TEXT NOT NULL,
          record_count INTEGER NOT NULL,
          anchor_hmac TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          key_id TEXT NOT NULL DEFAULT 'anchor-v1',
          previous_key_id TEXT,
          rotated_at TEXT
        );
      `);

      const anchorCols = this.getTableColumns('audit_chain_anchor');
      if (anchorCols.size > 0) {
        if (!anchorCols.has('key_id')) {
          db.exec(`ALTER TABLE audit_chain_anchor ADD COLUMN key_id TEXT NOT NULL DEFAULT 'anchor-v1';`);
        }
        if (!anchorCols.has('previous_key_id')) {
          db.exec(`ALTER TABLE audit_chain_anchor ADD COLUMN previous_key_id TEXT;`);
        }
        if (!anchorCols.has('rotated_at')) {
          db.exec(`ALTER TABLE audit_chain_anchor ADD COLUMN rotated_at TEXT;`);
        }
      }

      db.exec(`
        CREATE TABLE IF NOT EXISTS audit_ledger_epochs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          epoch_label TEXT NOT NULL,
          legacy_cutoff_max_id INTEGER NOT NULL,
          legacy_record_count INTEGER NOT NULL,
          legacy_snapshot_sha256 TEXT NOT NULL,
          epoch_start_id INTEGER NOT NULL,
          epoch_genesis_hash TEXT NOT NULL,
          reason TEXT,
          created_by TEXT NOT NULL,
          created_at TEXT NOT NULL,
          key_id TEXT NOT NULL DEFAULT 'anchor-v1',
          epoch_hmac TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_audit_ledger_epochs_cutoff ON audit_ledger_epochs(legacy_cutoff_max_id);
      `);
    } catch {
      // ignore if read-only
    }
  }

  private deriveVersionedKey(keyId: string): string {
    const masterSecret = process.env.AUDIT_ANCHOR_KEY?.trim() || CONFIG.JWT_SECRET;
    if (keyId === 'anchor-v1') {
      return deriveAnchorHmacKey(masterSecret);
    }
    return crypto
      .createHmac('sha256', masterSecret)
      .update(`serverless-security:audit-chain-anchor:${keyId}`)
      .digest('hex');
  }

  private resolveKeyForId(keyId?: string | null): string | null {
    const targetId = (keyId || 'anchor-v1').trim();
    if (targetId === this.activeKeyId) {
      return this.activeKey;
    }
    if (this.rotatedKeysThisProcess.has(targetId)) {
      return this.rotatedKeysThisProcess.get(targetId)!;
    }
    if (this.previousKeys.has(targetId)) {
      return this.previousKeys.get(targetId)!;
    }
    // Support deterministic rotation version IDs generated via rotateAnchorKey without explicit custom secret
    if (/^anchor-v\d+(?:[-_][a-z0-9]+)*$/i.test(targetId) && this.activeKeySource !== 'CUSTOM_ROTATED_KEY') {
      return this.deriveVersionedKey(targetId);
    }
    return null;
  }

  private computeAnchorHmac(
    genesisHash: string,
    headId: number,
    headHash: string,
    recordCount: number,
    keyId: string,
    hmacKey: string
  ): string {
    return crypto
      .createHmac('sha256', hmacKey)
      .update(`${genesisHash}|${headId}|${headHash}|${recordCount}|${keyId}`)
      .digest('hex');
  }

  private computeEpochHmac(
    epoch: {
      epochLabel: string;
      legacyCutoffMaxId: number;
      legacyRecordCount: number;
      legacySnapshotSha256: string;
      epochStartId: number;
      epochGenesisHash: string;
      createdBy: string;
      createdAt: string;
      keyId: string;
    },
    hmacKey: string
  ): string {
    const payload = [
      epoch.epochLabel,
      epoch.legacyCutoffMaxId,
      epoch.legacyRecordCount,
      epoch.legacySnapshotSha256,
      epoch.epochStartId,
      epoch.epochGenesisHash,
      epoch.createdBy,
      epoch.createdAt,
      epoch.keyId
    ].join('|');
    return crypto.createHmac('sha256', hmacKey).update(payload).digest('hex');
  }

  private computeLegacySnapshotSha256(rows: any[]): string {
    const canonical = rows
      .map((r) => {
        const ts = r.timestamp || r.created_at || '';
        return `${r.id}|${ts}|${r.username}|${r.requested_function}|${r.calculated_risk}|${r.status}|${r.reason}|${r.integrity_hash || ''}|${r.prev_hash || ''}`;
      })
      .join('\n');
    return crypto.createHash('sha256').update(canonical).digest('hex');
  }

  private verifyAnchorRow(anchor: any, keyOverride?: string): { verified: boolean; usedKeyId: string | null } {
    if (!anchor) return { verified: false, usedKeyId: null };
    const anchorKeyId = (anchor.key_id || 'anchor-v1').trim();
    const resolvedKey = keyOverride || this.resolveKeyForId(anchorKeyId);
    if (!resolvedKey) {
      return { verified: false, usedKeyId: anchorKeyId };
    }
    const expectedHmac = this.computeAnchorHmac(
      String(anchor.genesis_hash),
      Number(anchor.head_id),
      String(anchor.head_hash),
      Number(anchor.record_count),
      anchorKeyId,
      resolvedKey
    );
    if (safeHexEqual(String(anchor.anchor_hmac), expectedHmac)) {
      return { verified: true, usedKeyId: anchorKeyId };
    }
    // Check unversioned legacy 4-part HMAC only if anchor was never rotated (previous_key_id is null)
    if (anchorKeyId === 'anchor-v1' && !anchor.previous_key_id && !anchor.rotated_at) {
      const legacy4PartDomain = crypto
        .createHmac('sha256', resolvedKey)
        .update(`${anchor.genesis_hash}|${anchor.head_id}|${anchor.head_hash}|${anchor.record_count}`)
        .digest('hex');
      if (safeHexEqual(String(anchor.anchor_hmac), legacy4PartDomain)) {
        return { verified: true, usedKeyId: anchorKeyId };
      }
      const legacy4PartJwt = crypto
        .createHmac('sha256', CONFIG.JWT_SECRET)
        .update(`${anchor.genesis_hash}|${anchor.head_id}|${anchor.head_hash}|${anchor.record_count}`)
        .digest('hex');
      if (safeHexEqual(String(anchor.anchor_hmac), legacy4PartJwt)) {
        return { verified: true, usedKeyId: anchorKeyId };
      }
    }
    return { verified: false, usedKeyId: anchorKeyId };
  }

  private findSuggestedLegacyCutoff(chronological: any[]): {
    suggestedCutoffMaxId: number | null;
    modernStartIndex: number;
  } {
    if (chronological.length === 0) {
      return { suggestedCutoffMaxId: null, modernStartIndex: 0 };
    }

    // Walk backwards from tail to find the earliest index of the unbroken valid suffix
    let startIdx = chronological.length;
    for (let i = chronological.length - 1; i >= 0; i--) {
      const cur = chronological[i];
      if (!isRowStructurallyValidAndHashed(cur)) {
        break;
      }
      startIdx = i;
      if (i > 0) {
        const prev = chronological[i - 1];
        if (!isRowStructurallyValidAndHashed(prev)) {
          break;
        }
        if (String(cur.prev_hash) !== String(prev.integrity_hash)) {
          break;
        }
        const prevTsMs = Date.parse(prev.timestamp || prev.created_at);
        const curTsMs = Date.parse(cur.timestamp || cur.created_at);
        if (Number.isFinite(prevTsMs) && Number.isFinite(curTsMs) && curTsMs + 1000 < prevTsMs) {
          break;
        }
      }
    }

    if (startIdx === 0) {
      if (chronological[0].prev_hash === TRUSTED_AUDIT_GENESIS_HASH) {
        return { suggestedCutoffMaxId: null, modernStartIndex: 0 };
      }
      // Entire ledger starts from a non-trusted genesis
      return {
        suggestedCutoffMaxId: Number(chronological[chronological.length - 1].id),
        modernStartIndex: chronological.length
      };
    }

    if (startIdx >= chronological.length) {
      return {
        suggestedCutoffMaxId: Number(chronological[chronological.length - 1].id),
        modernStartIndex: chronological.length
      };
    }

    return {
      suggestedCutoffMaxId: Number(chronological[startIdx - 1].id),
      modernStartIndex: startIdx
    };
  }

  private seedBaseline() {
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
    this.ensureAnchorTable();

    let postCommitRecord!: AuditRecord;
    let postCommitAlert: SecurityAlert | null = null;
    const timestamp = new Date().toISOString();
    const eventType = data.event_type || 'STANDARD_VERIFICATION';

    db.transaction(() => {
      // Retrieve previous hash atomically inside BEGIN IMMEDIATE lock
      const lastRow = db.prepare('SELECT id, integrity_hash FROM audit_events ORDER BY id DESC LIMIT 1').first<any>();
      const prevHash = lastRow && lastRow.integrity_hash ? String(lastRow.integrity_hash) : TRUSTED_AUDIT_GENESIS_HASH;

      const payloadToHash = `${timestamp}|${data.username}|${data.requested_function}|${data.calculated_risk}|${data.status}|${data.reason}|${prevHash}`;
      const hash = crypto.createHash('sha256').update(payloadToHash).digest('hex');

      const runResult = db.prepare(
        `INSERT INTO audit_events (
          timestamp, username, requested_function, calculated_risk, status, reason, verification_latency_ms, event_type, integrity_hash, prev_hash, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        timestamp,
        data.username,
        data.requested_function,
        data.calculated_risk,
        data.status,
        data.reason,
        data.verification_latency_ms,
        eventType,
        hash,
        prevHash,
        timestamp
      ).run();

      const id = Number(runResult.lastRowId || Date.now());
      this.lastHash = hash;

      // Atomically update HMAC checkpoint anchor in the same transaction
      const countRow = db.prepare('SELECT COUNT(*) as c FROM audit_events').first<any>();
      const totalCount = Number(countRow?.c || 0);
      const existingAnchor = db.prepare('SELECT key_id, previous_key_id, rotated_at FROM audit_chain_anchor WHERE id = 1').first<any>();

      const previousKeyId =
        existingAnchor && existingAnchor.key_id && existingAnchor.key_id !== this.activeKeyId
          ? String(existingAnchor.key_id)
          : (existingAnchor?.previous_key_id ?? null);
      const rotatedAt =
        existingAnchor && existingAnchor.key_id && existingAnchor.key_id !== this.activeKeyId
          ? timestamp
          : (existingAnchor?.rotated_at ?? null);

      const anchorHmac = this.computeAnchorHmac(
        TRUSTED_AUDIT_GENESIS_HASH,
        id,
        hash,
        totalCount,
        this.activeKeyId,
        this.activeKey
      );

      db.prepare(
        `INSERT INTO audit_chain_anchor (id, genesis_hash, head_id, head_hash, record_count, anchor_hmac, updated_at, key_id, previous_key_id, rotated_at)
         VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
           genesis_hash = excluded.genesis_hash,
           head_id = excluded.head_id,
           head_hash = excluded.head_hash,
           record_count = excluded.record_count,
           anchor_hmac = excluded.anchor_hmac,
           updated_at = excluded.updated_at,
           key_id = excluded.key_id,
           previous_key_id = excluded.previous_key_id,
           rotated_at = excluded.rotated_at`
      ).bind(
        TRUSTED_AUDIT_GENESIS_HASH,
        id,
        hash,
        totalCount,
        anchorHmac,
        timestamp,
        this.activeKeyId,
        previousKeyId,
        rotatedAt
      ).run();

      // Mirror into legacy security_audit_logs compatibility table inside transaction
      try {
        db.prepare(
          `INSERT INTO security_audit_logs (
            id, timestamp, username, requested_function, calculated_risk, status, reason, verification_latency_ms, event_type, integrity_hash, prev_hash
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(
          id,
          timestamp,
          data.username,
          data.requested_function,
          data.calculated_risk,
          data.status,
          data.reason,
          data.verification_latency_ms,
          eventType,
          hash,
          prevHash
        ).run();
      } catch {
        // ignore duplicate id on compatibility table
      }

      postCommitRecord = {
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
        prev_hash: prevHash
      };

      if (data.status === 'BLOCKED' || data.calculated_risk >= 75) {
        const severity = data.calculated_risk >= 90 ? 'CRITICAL' : data.calculated_risk >= 75 ? 'HIGH' : 'MEDIUM';
        const alertId = `alt_${id}_${Date.now().toString(36)}`;
        postCommitAlert = {
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

        try {
          let validUserId: string | null = null;
          if (data.username) {
            const userRow = db
              .prepare('SELECT id FROM users WHERE id = ? OR LOWER(username) = LOWER(?) LIMIT 1')
              .bind(data.username, data.username)
              .first<any>();
            if (userRow?.id) {
              validUserId = userRow.id;
            }
          }

          db.prepare(
            `INSERT INTO security_alerts (
              id, invocation_id, alert_type, severity, threat_vector, details_json, ip_address, user_id, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
          ).bind(
            alertId,
            null,
            eventType,
            severity,
            data.requested_function,
            JSON.stringify({ reason: data.reason, risk: data.calculated_risk }),
            '127.0.0.1',
            validUserId,
            timestamp
          ).run();
        } catch (alertErr: any) {
          console.warn('[AuditRepository Alert Warning]:', alertErr?.message);
        }
      }
    });

    // Broadcast strictly after SQLite transaction commits
    this.broadcast({ type: 'NEW_INVOCATION', data: postCommitRecord, timestamp });
    if (postCommitAlert) {
      this.broadcast({ type: 'THREAT_ALERT', data: postCommitAlert, timestamp });
    }

    return postCommitRecord;
  }

  public getAnchorStatus(): AuditChainAnchorStatus {
    this.ensureAnchorTable();
    const anchor = db.prepare('SELECT * FROM audit_chain_anchor WHERE id = 1').first<any>();
    const latestEpochRow = db.prepare('SELECT * FROM audit_ledger_epochs ORDER BY id DESC LIMIT 1').first<any>();

    let anchorVerified = false;
    if (anchor) {
      anchorVerified = this.verifyAnchorRow(anchor).verified;
    }

    let activeEpoch: AuditEpochInfo | null = null;
    if (latestEpochRow) {
      const legacyRows =
        db
          .prepare(
            `SELECT id, timestamp, created_at, username, requested_function, calculated_risk, status, reason, integrity_hash, prev_hash
             FROM audit_events WHERE id <= ? ORDER BY id ASC`
          )
          .bind(Number(latestEpochRow.legacy_cutoff_max_id))
          .all<any>().results || [];
      const recomputedSnapshot = this.computeLegacySnapshotSha256(legacyRows);
      const snapshotVerified =
        legacyRows.length === Number(latestEpochRow.legacy_record_count) &&
        safeHexEqual(recomputedSnapshot, String(latestEpochRow.legacy_snapshot_sha256));

      const epochKey = this.resolveKeyForId(latestEpochRow.key_id);
      const epochHmacVerified = Boolean(
        epochKey &&
          safeHexEqual(
            String(latestEpochRow.epoch_hmac),
            this.computeEpochHmac(
              {
                epochLabel: String(latestEpochRow.epoch_label),
                legacyCutoffMaxId: Number(latestEpochRow.legacy_cutoff_max_id),
                legacyRecordCount: Number(latestEpochRow.legacy_record_count),
                legacySnapshotSha256: String(latestEpochRow.legacy_snapshot_sha256),
                epochStartId: Number(latestEpochRow.epoch_start_id),
                epochGenesisHash: String(latestEpochRow.epoch_genesis_hash),
                createdBy: String(latestEpochRow.created_by),
                createdAt: String(latestEpochRow.created_at),
                keyId: String(latestEpochRow.key_id)
              },
              epochKey
            )
          )
      );

      activeEpoch = {
        id: Number(latestEpochRow.id),
        epochLabel: String(latestEpochRow.epoch_label),
        legacyCutoffMaxId: Number(latestEpochRow.legacy_cutoff_max_id),
        legacyRecordCount: Number(latestEpochRow.legacy_record_count),
        legacySnapshotSha256: String(latestEpochRow.legacy_snapshot_sha256),
        epochStartId: Number(latestEpochRow.epoch_start_id),
        epochGenesisHash: String(latestEpochRow.epoch_genesis_hash),
        reason: latestEpochRow.reason || null,
        createdBy: String(latestEpochRow.created_by),
        createdAt: String(latestEpochRow.created_at),
        keyId: String(latestEpochRow.key_id),
        snapshotVerified,
        epochHmacVerified
      };
    }

    return {
      present: Boolean(anchor),
      verified: Boolean(anchor && anchorVerified),
      keyId: anchor?.key_id || null,
      previousKeyId: anchor?.previous_key_id || null,
      rotatedAt: anchor?.rotated_at || null,
      activeKeyId: this.activeKeyId,
      keySource: this.activeKeySource,
      keyFingerprint: this.activeKeyFingerprint,
      activeEpoch,
      genesisHash: anchor?.genesis_hash || TRUSTED_AUDIT_GENESIS_HASH,
      headId: Number(anchor?.head_id || 0),
      headHash: anchor?.head_hash || null,
      recordCount: Number(anchor?.record_count || 0),
      updatedAt: anchor?.updated_at || null
    };
  }

  public rotateAnchorKey(params: {
    adminUsername: string;
    newKeyId?: string;
    newSecret?: string;
    reason?: string;
  }): {
    success: boolean;
    keyId: string;
    previousKeyId: string | null;
    rotatedAt: string;
    keyFingerprint: string;
    keySource: string;
    auditEventId: number;
  } {
    this.ensureAnchorTable();
    const admin = params.adminUsername?.trim();
    if (!admin) {
      throw new Error('Administrator identity is required to rotate the audit chain anchor key.');
    }

    if (params.newSecret !== undefined && params.newSecret.trim().length > 0 && params.newSecret.trim().length < 16) {
      throw new Error('Custom anchor rotation secret must be at least 16 characters long.');
    }

    const rotatedAt = new Date().toISOString();
    const sanitizedNewKeyId =
      params.newKeyId?.trim() ||
      `anchor-v${Date.now().toString(36)}`;

    if (sanitizedNewKeyId === this.activeKeyId) {
      throw new Error(`Anchor key ID '${sanitizedNewKeyId}' is already the active signing key.`);
    }

    const oldKeyId = this.activeKeyId;
    const oldKey = this.activeKey;

    const newDerivedKey =
      params.newSecret && params.newSecret.trim().length >= 16
        ? deriveAnchorHmacKey(params.newSecret.trim())
        : this.deriveVersionedKey(sanitizedNewKeyId);
    const newKeySource =
      params.newSecret && params.newSecret.trim().length >= 16
        ? 'CUSTOM_ROTATED_KEY'
        : this.activeKeySource;

    db.transaction(() => {
      const anchor = db.prepare('SELECT * FROM audit_chain_anchor WHERE id = 1').first<any>();
      if (anchor) {
        const verification = this.verifyAnchorRow(anchor);
        if (!verification.verified) {
          throw new Error(
            'Refusing anchor key rotation: existing audit_chain_anchor HMAC verification failed. Resolve tampering first.'
          );
        }
      }

      // Preserve prior key material in in-memory verification key ring for historical epochs
      this.rotatedKeysThisProcess.set(oldKeyId, oldKey);
      this.previousKeys.set(oldKeyId, oldKey);

      this.activeKeyId = sanitizedNewKeyId;
      this.activeKey = newDerivedKey;
      this.activeKeySource = newKeySource;
      this.activeKeyFingerprint = computeAnchorKeyFingerprint(newDerivedKey);

      if (anchor) {
        const updatedHmac = this.computeAnchorHmac(
          String(anchor.genesis_hash),
          Number(anchor.head_id),
          String(anchor.head_hash),
          Number(anchor.record_count),
          this.activeKeyId,
          this.activeKey
        );
        db.prepare(
          `UPDATE audit_chain_anchor
           SET anchor_hmac = ?, key_id = ?, previous_key_id = ?, rotated_at = ?, updated_at = ?
           WHERE id = 1`
        ).bind(updatedHmac, this.activeKeyId, oldKeyId, rotatedAt, rotatedAt).run();
      }
    });

    const reasonText =
      params.reason?.trim() ||
      `Rotated audit_chain_anchor HMAC signing key from [${oldKeyId}] to [${this.activeKeyId}] (fp:${this.activeKeyFingerprint})`;

    const auditRec = this.record({
      username: admin,
      requested_function: '/api/v1/audit/rotate-anchor-key',
      calculated_risk: 10,
      status: 'ALLOWED',
      reason: `[ANCHOR KEY ROTATED] ${reasonText}`,
      verification_latency_ms: 0.9,
      event_type: 'AUDIT_ANCHOR_KEY_ROTATED'
    });

    // Guarantee previous_key_id & rotated_at reflect this rotation cleanly
    try {
      db.prepare(
        `UPDATE audit_chain_anchor SET previous_key_id = ?, rotated_at = ? WHERE id = 1`
      ).bind(oldKeyId, rotatedAt).run();
    } catch {
      // ignore
    }

    return {
      success: true,
      keyId: this.activeKeyId,
      previousKeyId: oldKeyId,
      rotatedAt,
      keyFingerprint: this.activeKeyFingerprint,
      keySource: this.activeKeySource,
      auditEventId: auditRec.id
    };
  }

  public baselineLegacyRecords(params: {
    adminUsername: string;
    cutoffMaxId?: number;
    epochLabel?: string;
    reason?: string;
  }): {
    success: boolean;
    epoch: AuditEpochInfo;
    auditEventId: number;
  } {
    this.ensureAnchorTable();
    const admin = params.adminUsername?.trim();
    if (!admin) {
      throw new Error('Administrator identity is required to seal a legacy audit baseline.');
    }

    const allRows =
      db
        .prepare(
          `SELECT id, timestamp, created_at, username, requested_function, calculated_risk, status, reason, integrity_hash, prev_hash
           FROM audit_events ORDER BY id ASC`
        )
        .all<any>().results || [];

    if (allRows.length === 0) {
      throw new Error('Audit ledger is empty; no historical rows exist to baseline.');
    }

    let cutoffMaxId: number;
    let epochStartId = 0;
    let epochGenesisHash = TRUSTED_AUDIT_GENESIS_HASH;

    if (params.cutoffMaxId !== undefined && Number.isFinite(params.cutoffMaxId)) {
      cutoffMaxId = Math.floor(params.cutoffMaxId);
      if (cutoffMaxId <= 0) {
        throw new Error('cutoffMaxId must be a positive integer.');
      }
      const nextModern = allRows.find((r) => Number(r.id) > cutoffMaxId);
      if (nextModern) {
        epochStartId = Number(nextModern.id);
        epochGenesisHash = String(nextModern.prev_hash || '');
      }
    } else {
      const detected = this.findSuggestedLegacyCutoff(allRows);
      if (detected.suggestedCutoffMaxId === null) {
        throw new Error('Full ledger is already cleanly verified from trusted genesis; no legacy baseline needed.');
      }
      cutoffMaxId = detected.suggestedCutoffMaxId;
      if (detected.modernStartIndex < allRows.length) {
        epochStartId = Number(allRows[detected.modernStartIndex].id);
        epochGenesisHash = String(allRows[detected.modernStartIndex].prev_hash || '');
      }
    }

    const legacyRows = allRows.filter((r) => Number(r.id) <= cutoffMaxId);
    if (legacyRows.length === 0) {
      throw new Error(`No audit_events rows found with id <= ${cutoffMaxId}.`);
    }

    // If modern rows exist after cutoffMaxId, verify they actually form an unbroken hash chain before sealing!
    const modernRows = allRows.filter((r) => Number(r.id) > cutoffMaxId);
    for (let i = 0; i < modernRows.length; i++) {
      const r = modernRows[i];
      if (!isRowStructurallyValidAndHashed(r)) {
        throw new Error(
          `Modern epoch row #${r.id} after cutoff (${cutoffMaxId}) fails SHA-256 verification. Choose a higher cutoffMaxId or resolve tampering.`
        );
      }
      if (i > 0 && String(r.prev_hash) !== String(modernRows[i - 1].integrity_hash)) {
        throw new Error(
          `Modern epoch chain break at row #${r.id} after cutoff (${cutoffMaxId}). Choose cutoffMaxId >= ${modernRows[i - 1].id}.`
        );
      }
    }

    const legacySnapshotSha256 = this.computeLegacySnapshotSha256(legacyRows);
    const createdAt = new Date().toISOString();
    const epochLabel =
      params.epochLabel?.trim() ||
      `epoch-${new Date().toISOString().slice(0, 10)}-cutoff-${cutoffMaxId}`;
    const reasonText =
      params.reason?.trim() ||
      `Sealed ${legacyRows.length} archived legacy rows (id <= ${cutoffMaxId}) without modifying historical records.`;

    // Pre-calculate what the appended baseline audit row will look like when modernRows is empty
    const latestOverallRow = allRows[allRows.length - 1];
    const predictedNextPrevHash = String(latestOverallRow?.integrity_hash || TRUSTED_AUDIT_GENESIS_HASH);
    const willAppendNewEpochStart = modernRows.length === 0;
    const effectiveEpochGenesisHash = willAppendNewEpochStart ? predictedNextPrevHash : epochGenesisHash;

    let insertedEpochId = 0;
    db.transaction(() => {
      // Placeholder epoch_start_id updated immediately if we append the first modern epoch event right after
      const epochHmac = this.computeEpochHmac(
        {
          epochLabel,
          legacyCutoffMaxId: cutoffMaxId,
          legacyRecordCount: legacyRows.length,
          legacySnapshotSha256,
          epochStartId: willAppendNewEpochStart ? Number(latestOverallRow.id) + 1 : epochStartId,
          epochGenesisHash: effectiveEpochGenesisHash,
          createdBy: admin,
          createdAt,
          keyId: this.activeKeyId
        },
        this.activeKey
      );

      const res = db
        .prepare(
          `INSERT INTO audit_ledger_epochs (
            epoch_label, legacy_cutoff_max_id, legacy_record_count, legacy_snapshot_sha256,
            epoch_start_id, epoch_genesis_hash, reason, created_by, created_at, key_id, epoch_hmac
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .bind(
          epochLabel,
          cutoffMaxId,
          legacyRows.length,
          legacySnapshotSha256,
          willAppendNewEpochStart ? Number(latestOverallRow.id) + 1 : epochStartId,
          effectiveEpochGenesisHash,
          reasonText,
          admin,
          createdAt,
          this.activeKeyId,
          epochHmac
        )
        .run();
      insertedEpochId = Number(res.lastRowId || 0);
    });

    const auditRec = this.record({
      username: admin,
      requested_function: '/api/v1/audit/baseline-legacy',
      calculated_risk: 10,
      status: 'ALLOWED',
      reason: `[LEGACY BASELINE SEALED] ${reasonText} (snapshot:${legacySnapshotSha256.slice(0, 16)})`,
      verification_latency_ms: 1.2,
      event_type: 'AUDIT_LEGACY_BASELINE_SEALED'
    });

    // If epoch started cleanly at this newly appended record, lock exact autoincrement ID + re-sign epoch_hmac
    let finalEpochStartId = epochStartId;
    let finalEpochGenesisHash = epochGenesisHash;
    if (willAppendNewEpochStart) {
      finalEpochStartId = auditRec.id;
      finalEpochGenesisHash = auditRec.prev_hash;
      const updatedEpochHmac = this.computeEpochHmac(
        {
          epochLabel,
          legacyCutoffMaxId: cutoffMaxId,
          legacyRecordCount: legacyRows.length,
          legacySnapshotSha256,
          epochStartId: finalEpochStartId,
          epochGenesisHash: finalEpochGenesisHash,
          createdBy: admin,
          createdAt,
          keyId: this.activeKeyId
        },
        this.activeKey
      );
      db.prepare(
        `UPDATE audit_ledger_epochs SET epoch_start_id = ?, epoch_genesis_hash = ?, epoch_hmac = ? WHERE id = ?`
      )
        .bind(finalEpochStartId, finalEpochGenesisHash, updatedEpochHmac, insertedEpochId)
        .run();
    }

    return {
      success: true,
      epoch: {
        id: insertedEpochId,
        epochLabel,
        legacyCutoffMaxId: cutoffMaxId,
        legacyRecordCount: legacyRows.length,
        legacySnapshotSha256,
        epochStartId: finalEpochStartId,
        epochGenesisHash: finalEpochGenesisHash,
        reason: reasonText,
        createdBy: admin,
        createdAt,
        keyId: this.activeKeyId,
        snapshotVerified: true,
        epochHmacVerified: true
      },
      auditEventId: auditRec.id
    };
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
      verification_latency_ms: typeof r.verification_latency_ms === 'number' ? r.verification_latency_ms : 0,
      event_type: r.event_type || 'STANDARD_VERIFICATION',
      integrity_hash: r.integrity_hash || '',
      prev_hash: r.prev_hash || ''
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
    const rows = db.prepare(`
      SELECT a.*, u.username AS resolved_username
      FROM security_alerts a
      LEFT JOIN users u ON a.user_id = u.id
      ORDER BY a.created_at DESC
      LIMIT 100
    `).all<any>();
    return (rows.results || []).map((r) => ({
      id: r.id,
      timestamp: r.created_at,
      alert_type: r.alert_type,
      severity: r.severity as any,
      threat_vector: r.threat_vector,
      details: r.details_json,
      ip_address: r.ip_address,
      username: r.resolved_username || r.user_id || 'anonymous',
      acknowledged: Boolean(r.acknowledged_at)
    }));
  }

  public acknowledgeAlert(id: string, acknowledgedBy = 'secops_admin'): boolean {
    const res = db.prepare(
      "UPDATE security_alerts SET acknowledged_at = datetime('now', 'utc'), acknowledged_by = ? WHERE id = ?"
    ).bind(acknowledgedBy, id).run();
    return (res.changes || 0) > 0;
  }

  public getIncidents(): IncidentCase[] {
    const rows = db.prepare('SELECT * FROM incidents ORDER BY created_at DESC').all<any>();
    return (rows.results || []).map((r) => ({
      id: r.id,
      title: r.title,
      severity: r.severity as any,
      status: r.status as any,
      created_at: r.created_at,
      root_cause: r.root_cause,
      mitigation_steps: r.mitigation_steps,
      assigned_to: r.assigned_to,
      resolved_at: r.resolved_at,
      resolved_by: r.resolved_by
    }));
  }

  public getIncidentById(id: string): IncidentCase | null {
    const r = db.prepare('SELECT * FROM incidents WHERE id = ? LIMIT 1').bind(id).first<any>();
    if (!r) return null;
    return {
      id: r.id,
      title: r.title,
      severity: r.severity as any,
      status: r.status as any,
      created_at: r.created_at,
      root_cause: r.root_cause,
      mitigation_steps: r.mitigation_steps,
      assigned_to: r.assigned_to,
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
    const id = `INC-${new Date().getFullYear()}-${crypto.randomInt(100, 1000)}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
    const nowIso = new Date().toISOString();
    const status = data.status || 'OPEN';

    let assignedUserId: string | null = null;
    const assigned = data.assigned_to || 'secops_admin';
    try {
      const userRow = db.prepare('SELECT id FROM users WHERE id = ? OR LOWER(username) = LOWER(?) LIMIT 1').bind(assigned, assigned).first<any>();
      if (userRow?.id) {
        assignedUserId = userRow.id;
      } else if (assigned === 'secops_admin') {
        assignedUserId = 'usr_secops_admin';
      }
    } catch {
      // ignore
    }

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
      assignedUserId,
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
      let resolvedAssignedId: string | null = null;
      if (updates.assigned_to) {
        try {
          const uRow = db.prepare('SELECT id FROM users WHERE id = ? OR LOWER(username) = LOWER(?) LIMIT 1').bind(updates.assigned_to, updates.assigned_to).first<any>();
          resolvedAssignedId = uRow?.id || (updates.assigned_to === 'secops_admin' ? 'usr_secops_admin' : null);
        } catch {
          // ignore
        }
      }
      fields.push('assigned_to = ?');
      values.push(resolvedAssignedId);
    }

    if (fields.length > 0) {
      values.push(id);
      db.prepare(`UPDATE incidents SET ${fields.join(', ')} WHERE id = ?`).bind(...values).run();
    }

    const updated = this.getIncidentById(id);
    this.broadcast({ type: 'INCIDENT_UPDATED', data: updated, timestamp: new Date().toISOString() });
    return updated;
  }

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

  public verifyIntegrityChain(limit?: number): VerifyIntegrityChainResult {
    this.ensureAnchorTable();
    const totalInLedger = this.getTotalCount();
    const hasExplicitLimit = typeof limit === 'number' && Number.isFinite(limit) && limit > 0;
    const latestEpochRow = db.prepare('SELECT * FROM audit_ledger_epochs ORDER BY id DESC LIMIT 1').first<any>();

    const brokenLinks: AuditBrokenLink[] = [];
    const failedRowIds = new Set<number>();

    let anchorPresent = false;
    let anchorVerified = true;
    let anchorKeyId: string | null = null;
    let anchorPreviousKeyId: string | null = null;
    let anchorRotatedAt: string | null = null;
    let headRow: any = null;

    if (latestEpochRow) {
      // Epoch-based verification: strictly preserve & distinguish archived legacy history vs modern verified chain
      const cutoffMaxId = Number(latestEpochRow.legacy_cutoff_max_id);
      const legacyRows =
        db
          .prepare(
            `SELECT id, timestamp, created_at, username, requested_function, calculated_risk, status, reason, integrity_hash, prev_hash
             FROM audit_events WHERE id <= ? ORDER BY id ASC`
          )
          .bind(cutoffMaxId)
          .all<any>().results || [];

      const recomputedSnapshot = this.computeLegacySnapshotSha256(legacyRows);
      const legacySnapshotVerified =
        legacyRows.length === Number(latestEpochRow.legacy_record_count) &&
        safeHexEqual(recomputedSnapshot, String(latestEpochRow.legacy_snapshot_sha256));

      if (!legacySnapshotVerified) {
        brokenLinks.push({
          id: cutoffMaxId,
          reason: 'LEGACY_SNAPSHOT_TAMPERED',
          detail: `Archived legacy slice (id <= ${cutoffMaxId}, found ${legacyRows.length} vs ${latestEpochRow.legacy_record_count}) failed SHA-256 snapshot verification`
        });
      }

      const epochKey = this.resolveKeyForId(latestEpochRow.key_id);
      const epochHmacVerified = Boolean(
        epochKey &&
          safeHexEqual(
            String(latestEpochRow.epoch_hmac),
            this.computeEpochHmac(
              {
                epochLabel: String(latestEpochRow.epoch_label),
                legacyCutoffMaxId: cutoffMaxId,
                legacyRecordCount: Number(latestEpochRow.legacy_record_count),
                legacySnapshotSha256: String(latestEpochRow.legacy_snapshot_sha256),
                epochStartId: Number(latestEpochRow.epoch_start_id),
                epochGenesisHash: String(latestEpochRow.epoch_genesis_hash),
                createdBy: String(latestEpochRow.created_by),
                createdAt: String(latestEpochRow.created_at),
                keyId: String(latestEpochRow.key_id)
              },
              epochKey
            )
          )
      );

      if (!epochHmacVerified) {
        brokenLinks.push({
          id: Number(latestEpochRow.epoch_start_id || cutoffMaxId),
          reason: 'EPOCH_HMAC_MISMATCH',
          detail: `Epoch baseline record [${latestEpochRow.epoch_label}] HMAC verification failed`
        });
      }

      const totalModernRow = db
        .prepare('SELECT COUNT(*) as count FROM audit_events WHERE id > ?')
        .bind(cutoffMaxId)
        .first<any>();
      const totalModern = Number(totalModernRow?.count || 0);

      const modernRowsDesc = hasExplicitLimit
        ? db
            .prepare(
              `SELECT id, timestamp, created_at, username, requested_function, calculated_risk, status, reason, integrity_hash, prev_hash
               FROM audit_events WHERE id > ? ORDER BY id DESC LIMIT ?`
            )
            .bind(cutoffMaxId, Math.floor(limit!))
            .all<any>().results || []
        : [];
      const modernChrono = hasExplicitLimit
        ? [...modernRowsDesc].reverse()
        : db
            .prepare(
              `SELECT id, timestamp, created_at, username, requested_function, calculated_risk, status, reason, integrity_hash, prev_hash
               FROM audit_events WHERE id > ? ORDER BY id ASC`
            )
            .bind(cutoffMaxId)
            .all<any>().results || [];

      const coversFullModernEpoch = !hasExplicitLimit || modernChrono.length >= totalModern;
      let epochBoundaryVerified = modernChrono.length > 0;
      if (modernChrono.length > 0 && coversFullModernEpoch) {
        const firstModern = modernChrono[0];
        if (
          Number(firstModern.id) !== Number(latestEpochRow.epoch_start_id) ||
          !safeHexEqual(String(firstModern.prev_hash), String(latestEpochRow.epoch_genesis_hash))
        ) {
          epochBoundaryVerified = false;
          brokenLinks.push({
            id: Number(firstModern.id),
            reason: 'EPOCH_BOUNDARY_MISMATCH',
            detail: `Modern epoch start row (${firstModern.id}) failed boundary continuity with baseline [${latestEpochRow.epoch_label}]`
          });
          failedRowIds.add(Number(firstModern.id));
        }
      }

      for (let i = 0; i < modernChrono.length; i++) {
        const r = modernChrono[i];
        const rowId = Number(r.id);

        if (
          !r.integrity_hash ||
          !/^[0-9a-f]{64}$/i.test(String(r.integrity_hash)) ||
          !r.prev_hash ||
          !/^[0-9a-f]{64}$/i.test(String(r.prev_hash))
        ) {
          brokenLinks.push({ id: rowId, reason: 'INVALID_FORMAT', detail: 'Missing or non-64-hex SHA-256 digest' });
          failedRowIds.add(rowId);
          continue;
        }

        const expectedHash = computeRowIntegrityHash(r);
        if (!safeHexEqual(String(r.integrity_hash), expectedHash)) {
          brokenLinks.push({ id: rowId, reason: 'HASH_MISMATCH', detail: 'Stored SHA-256 digest does not match row contents' });
          failedRowIds.add(rowId);
          continue;
        }

        if (i > 0) {
          const prevRow = modernChrono[i - 1];
          if (!safeHexEqual(String(r.prev_hash), String(prevRow.integrity_hash))) {
            brokenLinks.push({
              id: rowId,
              reason: 'CHAIN_LINK_BREAK',
              detail: `prev_hash mismatch after id ${prevRow.id} (deletion, insertion, or reordering detected)`
            });
            failedRowIds.add(rowId);
            continue;
          }

          const prevTsMs = Date.parse(prevRow.timestamp || prevRow.created_at);
          const curTsMs = Date.parse(r.timestamp || r.created_at);
          if (Number.isFinite(prevTsMs) && Number.isFinite(curTsMs) && curTsMs + 1000 < prevTsMs) {
            brokenLinks.push({
              id: rowId,
              reason: 'ORDER_ANOMALY',
              detail: `Chronological timestamp regression relative to preceding id ${prevRow.id}`
            });
            failedRowIds.add(rowId);
          }
        }
      }

      headRow = modernChrono[modernChrono.length - 1] || legacyRows[legacyRows.length - 1] || null;
      const anchor = db.prepare('SELECT * FROM audit_chain_anchor WHERE id = 1').first<any>();
      if (anchor) {
        anchorPresent = true;
        anchorKeyId = anchor.key_id || 'anchor-v1';
        anchorPreviousKeyId = anchor.previous_key_id || null;
        anchorRotatedAt = anchor.rotated_at || null;
        const anchorCheck = this.verifyAnchorRow(anchor);
        if (!anchorCheck.verified) {
          anchorVerified = false;
          brokenLinks.push({
            id: Number(anchor.head_id || 0),
            reason: 'ANCHOR_HMAC_MISMATCH',
            detail: `Audit chain anchor HMAC signature verification failed (key_id=${anchorKeyId})`
          });
        } else if (anchor.genesis_hash !== TRUSTED_AUDIT_GENESIS_HASH) {
          anchorVerified = false;
          brokenLinks.push({
            id: Number(anchor.head_id || 0),
            reason: 'GENESIS_MISMATCH',
            detail: 'Anchor genesis hash mismatch'
          });
        } else if (totalInLedger < Number(anchor.record_count)) {
          anchorVerified = false;
          brokenLinks.push({
            id: Number(headRow?.id || anchor.head_id || 0),
            reason: 'TAIL_TRUNCATION',
            detail: `Ledger count (${totalInLedger}) is lower than sealed anchor count (${anchor.record_count})`
          });
        } else if (totalInLedger > Number(anchor.record_count)) {
          anchorVerified = false;
          brokenLinks.push({
            id: Number(headRow?.id || 0),
            reason: 'UNTRACKED_INSERTION',
            detail: `Ledger count (${totalInLedger}) exceeds sealed anchor count (${anchor.record_count})`
          });
        } else if (
          headRow &&
          (Number(headRow.id) !== Number(anchor.head_id) || headRow.integrity_hash !== anchor.head_hash)
        ) {
          anchorVerified = false;
          brokenLinks.push({
            id: Number(headRow.id),
            reason: 'HEAD_HASH_MISMATCH',
            detail: `Current head (${headRow.id}) differs from sealed anchor head (${anchor.head_id})`
          });
        }
      }

      const verifiedEpochCount = Math.max(0, modernChrono.length - failedRowIds.size);
      const verifiedEpochIntact =
        brokenLinks.length === 0 &&
        legacySnapshotVerified &&
        epochHmacVerified &&
        epochBoundaryVerified &&
        anchorVerified &&
        modernChrono.length > 0;

      const activeEpochInfo: AuditEpochInfo = {
        id: Number(latestEpochRow.id),
        epochLabel: String(latestEpochRow.epoch_label),
        legacyCutoffMaxId: cutoffMaxId,
        legacyRecordCount: Number(latestEpochRow.legacy_record_count),
        legacySnapshotSha256: String(latestEpochRow.legacy_snapshot_sha256),
        epochStartId: Number(latestEpochRow.epoch_start_id),
        epochGenesisHash: String(latestEpochRow.epoch_genesis_hash),
        reason: latestEpochRow.reason || null,
        createdBy: String(latestEpochRow.created_by),
        createdAt: String(latestEpochRow.created_at),
        keyId: String(latestEpochRow.key_id),
        snapshotVerified: legacySnapshotVerified,
        epochHmacVerified
      };

      const verificationStatus: AuditVerificationStatus = !legacySnapshotVerified
        ? 'LEGACY_SNAPSHOT_TAMPERED'
        : verifiedEpochIntact
          ? 'VERIFIED_EPOCH_WITH_ARCHIVED_LEGACY'
          : 'INTEGRITY_DISCREPANCY';

      return {
        chainIntact: false, // Never silently label unchained legacy records as full-ledger valid
        fullLedgerVerified: false,
        verifiedEpochIntact,
        verificationStatus,
        genesisVerified: false,
        trustedGenesisHash: TRUSTED_AUDIT_GENESIS_HASH,
        anchorPresent,
        anchorVerified,
        anchorKeyId,
        anchorPreviousKeyId,
        anchorRotatedAt,
        keySource: this.activeKeySource,
        keyFingerprint: this.activeKeyFingerprint,
        legacyRecordsCount: Number(latestEpochRow.legacy_record_count),
        legacyCutoffMaxId: cutoffMaxId,
        legacySnapshotVerified,
        verifiedEpochCount,
        suggestedLegacyCutoffMaxId: null,
        epochLabel: String(latestEpochRow.epoch_label),
        activeEpoch: activeEpochInfo,
        totalInLedger,
        totalChecked: modernChrono.length,
        verifiedCount: verifiedEpochCount,
        brokenLinks: brokenLinks.slice(0, 50),
        headHash: headRow?.integrity_hash || null,
        verifiedAt: new Date().toISOString()
      };
    }

    // Standard full-ledger verification (no legacy baseline epoch)
    const rows = hasExplicitLimit
      ? db
          .prepare(
            `SELECT id, timestamp, created_at, username, requested_function, calculated_risk, status, reason, integrity_hash, prev_hash
             FROM audit_events
             ORDER BY id DESC
             LIMIT ?`
          )
          .bind(Math.floor(limit!))
          .all<any>().results || []
      : db
          .prepare(
            `SELECT id, timestamp, created_at, username, requested_function, calculated_risk, status, reason, integrity_hash, prev_hash
             FROM audit_events
             ORDER BY id ASC`
          )
          .all<any>().results || [];

    const chronological = hasExplicitLimit ? [...rows].reverse() : rows;
    const fullLedgerVerified = !hasExplicitLimit || chronological.length >= totalInLedger;

    let genesisVerified = false;
    if (chronological.length === 0) {
      genesisVerified = true;
    } else {
      const firstRow = chronological[0];
      if (fullLedgerVerified) {
        genesisVerified = firstRow.prev_hash === TRUSTED_AUDIT_GENESIS_HASH;
        if (!genesisVerified) {
          brokenLinks.push({
            id: Number(firstRow.id),
            reason: 'GENESIS_MISMATCH',
            detail: `First record prev_hash (${String(firstRow.prev_hash || 'NULL').slice(0, 16)}) does not match trusted genesis anchor`
          });
          failedRowIds.add(Number(firstRow.id));
        }
      } else {
        genesisVerified = firstRow.prev_hash === TRUSTED_AUDIT_GENESIS_HASH;
      }
    }

    for (let i = 0; i < chronological.length; i++) {
      const r = chronological[i];
      const rowId = Number(r.id);

      if (
        !r.integrity_hash ||
        !/^[0-9a-f]{64}$/i.test(String(r.integrity_hash)) ||
        !r.prev_hash ||
        !/^[0-9a-f]{64}$/i.test(String(r.prev_hash))
      ) {
        brokenLinks.push({ id: rowId, reason: 'INVALID_FORMAT', detail: 'Missing or non-64-hex SHA-256 digest' });
        failedRowIds.add(rowId);
        continue;
      }

      const expectedHash = computeRowIntegrityHash(r);
      if (!safeHexEqual(String(r.integrity_hash), expectedHash)) {
        brokenLinks.push({ id: rowId, reason: 'HASH_MISMATCH', detail: 'Stored SHA-256 digest does not match row contents' });
        failedRowIds.add(rowId);
        continue;
      }

      if (i > 0) {
        const prevRow = chronological[i - 1];
        if (!safeHexEqual(String(r.prev_hash), String(prevRow.integrity_hash))) {
          brokenLinks.push({
            id: rowId,
            reason: 'CHAIN_LINK_BREAK',
            detail: `prev_hash mismatch after id ${prevRow.id} (deletion, insertion, or reordering detected)`
          });
          failedRowIds.add(rowId);
          continue;
        }

        const prevTsMs = Date.parse(prevRow.timestamp || prevRow.created_at);
        const curTsMs = Date.parse(r.timestamp || r.created_at);
        if (Number.isFinite(prevTsMs) && Number.isFinite(curTsMs) && curTsMs + 1000 < prevTsMs) {
          brokenLinks.push({
            id: rowId,
            reason: 'ORDER_ANOMALY',
            detail: `Chronological timestamp regression relative to preceding id ${prevRow.id}`
          });
          failedRowIds.add(rowId);
        }
      }
    }

    headRow = chronological[chronological.length - 1];

    try {
      const anchor = db.prepare('SELECT * FROM audit_chain_anchor WHERE id = 1').first<any>();
      if (anchor) {
        anchorPresent = true;
        anchorKeyId = anchor.key_id || 'anchor-v1';
        anchorPreviousKeyId = anchor.previous_key_id || null;
        anchorRotatedAt = anchor.rotated_at || null;
        const anchorCheck = this.verifyAnchorRow(anchor);
        if (!anchorCheck.verified) {
          anchorVerified = false;
          brokenLinks.push({
            id: Number(anchor.head_id || 0),
            reason: 'ANCHOR_HMAC_MISMATCH',
            detail: `Audit chain anchor HMAC signature verification failed (key_id=${anchorKeyId})`
          });
        } else if (anchor.genesis_hash !== TRUSTED_AUDIT_GENESIS_HASH) {
          anchorVerified = false;
          brokenLinks.push({
            id: Number(anchor.head_id || 0),
            reason: 'GENESIS_MISMATCH',
            detail: 'Anchor genesis hash mismatch'
          });
        } else {
          if (totalInLedger < Number(anchor.record_count)) {
            anchorVerified = false;
            brokenLinks.push({
              id: Number(headRow?.id || anchor.head_id || 0),
              reason: 'TAIL_TRUNCATION',
              detail: `Ledger count (${totalInLedger}) is lower than sealed anchor count (${anchor.record_count})`
            });
          } else if (totalInLedger > Number(anchor.record_count)) {
            anchorVerified = false;
            brokenLinks.push({
              id: Number(headRow?.id || 0),
              reason: 'UNTRACKED_INSERTION',
              detail: `Ledger count (${totalInLedger}) exceeds sealed anchor count (${anchor.record_count})`
            });
          } else if (
            headRow &&
            (Number(headRow.id) !== Number(anchor.head_id) || headRow.integrity_hash !== anchor.head_hash)
          ) {
            anchorVerified = false;
            brokenLinks.push({
              id: Number(headRow.id),
              reason: 'HEAD_HASH_MISMATCH',
              detail: `Current head (${headRow.id}) differs from sealed anchor head (${anchor.head_id})`
            });
          }
        }
      }
    } catch {
      // ignore if anchor table inaccessible
    }

    const verifiedCount = Math.max(0, chronological.length - failedRowIds.size);
    const chainIntact =
      brokenLinks.length === 0 &&
      chronological.length > 0 &&
      (!fullLedgerVerified || genesisVerified) &&
      anchorVerified;

    let suggestedLegacyCutoffMaxId: number | null = null;
    if (!chainIntact && chronological.length > 0 && fullLedgerVerified) {
      suggestedLegacyCutoffMaxId = this.findSuggestedLegacyCutoff(chronological).suggestedCutoffMaxId;
    }

    const verificationStatus: AuditVerificationStatus =
      totalInLedger === 0
        ? 'EMPTY_LEDGER'
        : chainIntact
          ? 'FULL_LEDGER_VERIFIED'
          : 'INTEGRITY_DISCREPANCY';

    return {
      chainIntact,
      fullLedgerVerified,
      verifiedEpochIntact: chainIntact,
      verificationStatus,
      genesisVerified,
      trustedGenesisHash: TRUSTED_AUDIT_GENESIS_HASH,
      anchorPresent,
      anchorVerified,
      anchorKeyId,
      anchorPreviousKeyId,
      anchorRotatedAt,
      keySource: this.activeKeySource,
      keyFingerprint: this.activeKeyFingerprint,
      legacyRecordsCount: 0,
      legacyCutoffMaxId: 0,
      legacySnapshotVerified: null,
      verifiedEpochCount: verifiedCount,
      suggestedLegacyCutoffMaxId,
      epochLabel: null,
      activeEpoch: null,
      totalInLedger,
      totalChecked: chronological.length,
      verifiedCount,
      brokenLinks: brokenLinks.slice(0, 50),
      headHash: headRow?.integrity_hash || null,
      verifiedAt: new Date().toISOString()
    };
  }

  public clear() {
    this.ensureAnchorTable();
    db.transaction(() => {
      db.clearLogs();
      try {
        db.exec('DELETE FROM audit_chain_anchor;');
        db.exec('DELETE FROM audit_ledger_epochs;');
      } catch {
        // ignore
      }
      this.lastHash = TRUSTED_AUDIT_GENESIS_HASH;
    });
    this.seedBaseline();
  }
}

export const auditRepository = new AuditRepository();
