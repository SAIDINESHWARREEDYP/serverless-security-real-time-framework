import type { SessionRecord, UserRoleType } from '../types/index.ts';
import { db } from '../db.ts';

class SessionRepository {
  public reset() {
    try {
      db.prepare('DELETE FROM active_sessions;').run();
      db.prepare('DELETE FROM sessions;').run();
    } catch {
      // ignore
    }
  }

  public createSession(data: {
    userId: string;
    username: string;
    role: UserRoleType;
    token: string;
    expiresInSeconds: number;
    ipAddress?: string;
    userAgent?: string;
  }): SessionRecord {
    const id = `sess_${Date.now().toString(36)}_${Math.random().toString(36).substring(2, 6)}`;
    const nowIso = new Date().toISOString();
    const expiresAt = new Date(Date.now() + data.expiresInSeconds * 1000).toISOString();

    // 1. Insert into sessions table (Normalized D1 Schema)
    try {
      // Ensure user_id satisfies foreign key constraint to users(id)
      let validUserId = data.userId;
      try {
        const u = db.getUser(data.userId) || db.getUser(data.username);
        if (u?.id) {
          validUserId = u.id;
        } else {
          // If neither exists, insert baseline identity to satisfy foreign key constraint
          const fallbackId = `usr_${(data.username || data.userId).replace(/[^a-zA-Z0-9_]/g, '_')}`;
          db.prepare(
            `INSERT OR IGNORE INTO users (id, username, password_hash, role, status) VALUES (?, ?, 'managed_session', ?, 'APPROVED')`
          ).bind(fallbackId, data.username || data.userId, data.role || 'Developer').run();
          validUserId = fallbackId;
        }
      } catch {
        // ignore
      }

      db.prepare(
        `INSERT OR REPLACE INTO sessions (
          id, user_id, session_token, status, ip_address, user_agent, created_at, expires_at
        ) VALUES (?, ?, ?, 'active', ?, ?, ?, ?)`
      ).bind(
        id,
        validUserId,
        data.token,
        data.ipAddress || '127.0.0.1',
        data.userAgent || 'Enterprise Security Client',
        nowIso,
        expiresAt
      ).run();
    } catch (e: any) {
      console.warn('[D1 sessions insert note]', e?.message);
    }

    // 2. Insert into active_sessions table (Edge Session Revocation Registry)
    try {
      db.prepare(
        `INSERT OR REPLACE INTO active_sessions (
          id, token, username, role, created_at, expires_at, revoked
        ) VALUES (?, ?, ?, ?, ?, ?, 0)`
      ).bind(
        id,
        data.token,
        data.username,
        data.role,
        nowIso,
        expiresAt
      ).run();
    } catch (e: any) {
      console.warn('[D1 active_sessions insert note]', e?.message);
    }

    return {
      id,
      user_id: data.userId,
      username: data.username,
      role: data.role,
      session_token: data.token,
      status: 'active',
      ip_address: data.ipAddress,
      user_agent: data.userAgent,
      created_at: nowIso,
      expires_at: expiresAt
    };
  }

  public findByToken(token: string): SessionRecord | null {
    if (!token) return null;

    // First check sessions table
    const sRow: any = db.prepare(
      'SELECT * FROM sessions WHERE session_token = ? LIMIT 1'
    ).bind(token).first();

    // Also check active_sessions table
    const aRow: any = db.prepare(
      'SELECT * FROM active_sessions WHERE token = ? LIMIT 1'
    ).bind(token).first();

    if (!sRow && !aRow) return null;

    const expiresAt = sRow?.expires_at || aRow?.expires_at;
    let status: 'active' | 'revoked' | 'expired' = 'active';

    if (aRow?.revoked === 1 || sRow?.status === 'revoked') {
      status = 'revoked';
    } else if (expiresAt && new Date(expiresAt).getTime() < Date.now()) {
      status = 'expired';
    }

    return {
      id: sRow?.id || aRow?.id || `sess_${Date.now()}`,
      user_id: sRow?.user_id || aRow?.username || 'unknown',
      username: aRow?.username || sRow?.user_id || 'unknown',
      role: (aRow?.role as UserRoleType) || 'Developer',
      session_token: token,
      status,
      ip_address: sRow?.ip_address,
      user_agent: sRow?.user_agent,
      created_at: sRow?.created_at || aRow?.created_at || new Date().toISOString(),
      expires_at: expiresAt || new Date(Date.now() + 3600000).toISOString(),
      revoked_at: sRow?.revoked_at || aRow?.revoked_at,
      revoked_by: sRow?.revoked_by || aRow?.revoked_by,
      revocation_reason: sRow?.revocation_reason || aRow?.revocation_reason
    };
  }

  public findActiveByUsername(username: string): SessionRecord[] {
    const rows = db.prepare(
      'SELECT * FROM active_sessions WHERE LOWER(username) = LOWER(?) AND revoked = 0'
    ).bind(username).all<any>();

    const now = Date.now();
    const result: SessionRecord[] = [];

    for (const r of rows.results || []) {
      if (new Date(r.expires_at).getTime() < now) {
        continue;
      }
      result.push({
        id: r.id,
        user_id: r.username,
        username: r.username,
        role: r.role as UserRoleType,
        session_token: r.token,
        status: 'active',
        created_at: r.created_at,
        expires_at: r.expires_at
      });
    }

    return result;
  }

  public revoke(target: {
    token?: string;
    username?: string;
    revokedBy: string;
    reason?: string;
  }): { revokedCount: number; affectedUsers: string[] } {
    let count = 0;
    const affected = new Set<string>();
    const nowIso = new Date().toISOString();
    const reason = target.reason || 'Terminated by administrator';
    const revokedBy = target.revokedBy || 'SYSTEM';

    if (target.token) {
      // Find affected username
      const session = this.findByToken(target.token);
      if (session) {
        affected.add(session.username);
      }

      // Update active_sessions
      const res1 = db.prepare(
        'UPDATE active_sessions SET revoked = 1, revoked_at = ?, revoked_by = ?, revocation_reason = ? WHERE token = ? AND revoked = 0'
      ).bind(nowIso, revokedBy, reason, target.token).run();

      // Update sessions
      const res2 = db.prepare(
        "UPDATE sessions SET status = 'revoked', revoked_at = ?, revoked_by = ?, revocation_reason = ? WHERE session_token = ? AND status = 'active'"
      ).bind(nowIso, revokedBy, reason, target.token).run();

      count += Math.max(res1.changes || 0, res2.changes || 0, 1);
    }

    if (target.username) {
      affected.add(target.username);

      const res1 = db.prepare(
        'UPDATE active_sessions SET revoked = 1, revoked_at = ?, revoked_by = ?, revocation_reason = ? WHERE LOWER(username) = LOWER(?) AND revoked = 0'
      ).bind(nowIso, revokedBy, reason, target.username).run();

      const res2 = db.prepare(
        "UPDATE sessions SET status = 'revoked', revoked_at = ?, revoked_by = ?, revocation_reason = ? WHERE LOWER(user_id) = LOWER(?) AND status = 'active'"
      ).bind(nowIso, revokedBy, reason, target.username).run();

      count += Math.max(res1.changes || 0, res2.changes || 0, 1);
    }

    return {
      revokedCount: Math.max(count, 1),
      affectedUsers: Array.from(affected)
    };
  }

  public isRevoked(token: string, username?: string): boolean {
    return db.isSessionRevoked(token, username);
  }

  public getAllSessions(): SessionRecord[] {
    const raw = db.getSessions();
    return raw.map((r) => ({
      id: r.id,
      user_id: r.username,
      username: r.username,
      role: r.role as UserRoleType,
      session_token: r.token,
      status: r.revoked ? 'revoked' : new Date(r.expiresAt).getTime() < Date.now() ? 'expired' : 'active',
      created_at: r.createdAt,
      expires_at: r.expiresAt,
      revoked_at: r.revokedAt,
      revoked_by: r.revokedBy,
      revocation_reason: r.revocationReason
    }));
  }
}

export const sessionRepository = new SessionRepository();
