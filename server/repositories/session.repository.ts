import { SessionRecord, UserRoleType } from '../types/index.ts';

class SessionRepository {
  private sessions: Map<string, SessionRecord> = new Map();
  private tokenIndex: Map<string, string> = new Map();
  private userSessionsIndex: Map<string, Set<string>> = new Map();

  constructor() {
    this.reset();
  }

  public reset() {
    this.sessions.clear();
    this.tokenIndex.clear();
    this.userSessionsIndex.clear();
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
    const expiresAt = new Date(Date.now() + data.expiresInSeconds * 1000).toISOString();

    const record: SessionRecord = {
      id,
      user_id: data.userId,
      username: data.username,
      role: data.role,
      session_token: data.token,
      status: 'active',
      ip_address: data.ipAddress,
      user_agent: data.userAgent,
      created_at: new Date().toISOString(),
      expires_at: expiresAt
    };

    this.sessions.set(id, record);
    this.tokenIndex.set(data.token, id);

    const userSet = this.userSessionsIndex.get(data.username.toLowerCase()) || new Set();
    userSet.add(id);
    this.userSessionsIndex.set(data.username.toLowerCase(), userSet);

    return record;
  }

  public findByToken(token: string): SessionRecord | null {
    const id = this.tokenIndex.get(token);
    if (!id) return null;
    const session = this.sessions.get(id);
    if (!session) return null;

    // Check if expired
    if (new Date(session.expires_at).getTime() < Date.now() && session.status === 'active') {
      session.status = 'expired';
    }

    return session;
  }

  public findActiveByUsername(username: string): SessionRecord[] {
    const ids = this.userSessionsIndex.get(username.toLowerCase()) || new Set();
    const result: SessionRecord[] = [];
    const now = Date.now();

    for (const id of ids) {
      const s = this.sessions.get(id);
      if (s) {
        if (new Date(s.expires_at).getTime() < now && s.status === 'active') {
          s.status = 'expired';
        }
        if (s.status === 'active') {
          result.push(s);
        }
      }
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

    if (target.token) {
      const id = this.tokenIndex.get(target.token);
      if (id) {
        const s = this.sessions.get(id);
        if (s && s.status === 'active') {
          s.status = 'revoked';
          s.revoked_at = nowIso;
          s.revoked_by = target.revokedBy;
          s.revocation_reason = target.reason || 'Revoked by administrator';
          count++;
          affected.add(s.username);
        }
      }
    }

    if (target.username) {
      const ids = this.userSessionsIndex.get(target.username.toLowerCase()) || new Set();
      for (const id of ids) {
        const s = this.sessions.get(id);
        if (s && s.status === 'active') {
          s.status = 'revoked';
          s.revoked_at = nowIso;
          s.revoked_by = target.revokedBy;
          s.revocation_reason = target.reason || 'Revoked by administrator';
          count++;
          affected.add(s.username);
        }
      }
      affected.add(target.username);
    }

    return { revokedCount: count, affectedUsers: Array.from(affected) };
  }

  public getAllSessions(): SessionRecord[] {
    return Array.from(this.sessions.values());
  }
}

export const sessionRepository = new SessionRepository();
