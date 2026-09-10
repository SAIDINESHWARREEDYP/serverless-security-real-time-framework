/**
 * Database Engine mimicking Cloudflare D1 / SQLite for the Serverless Security Framework.
 * Implements the users, function_rules, and security_audit_logs tables and seed data.
 */

export interface User {
  id: string;
  username: string;
  password_hash: string;
  role: 'Admin' | 'Developer' | 'Guest';
  base_risk_score: number;
}

export interface FunctionRule {
  id: number;
  current_function: string;
  allowed_next_function: string;
}

export interface SecurityAuditLog {
  id: number;
  timestamp: string;
  username: string;
  requested_function: string;
  calculated_risk: number;
  status: 'ALLOWED' | 'BLOCKED';
  reason: string;
}

const INITIAL_USERS: User[] = [
  { id: 'usr_secops_admin', username: 'secops_admin', password_hash: 'ZeroTrust_2026', role: 'Admin', base_risk_score: 0 },
  { id: 'usr_cloud_dev', username: 'cloud_dev', password_hash: 'ZeroTrust_2026', role: 'Developer', base_risk_score: 15 },
  { id: 'usr_auditor_guest', username: 'auditor_guest', password_hash: 'ZeroTrust_2026', role: 'Guest', base_risk_score: 30 },
  { id: 'usr_threat_actor', username: 'threat_actor', password_hash: 'ZeroTrust_2026', role: 'Guest', base_risk_score: 70 }
];

const INITIAL_RULES: Omit<FunctionRule, 'id'>[] = [
  { current_function: 'login', allowed_next_function: 'getDashboardMetrics' },
  { current_function: 'getDashboardMetrics', allowed_next_function: 'viewSecurityLogs' },
  { current_function: 'viewSecurityLogs', allowed_next_function: 'deployWorkerCode' },
  { current_function: 'deployWorkerCode', allowed_next_function: 'updateSystemPolicy' },
  { current_function: 'viewSecurityLogs', allowed_next_function: 'rotateEncryptionKeys' },
  { current_function: 'rotateEncryptionKeys', allowed_next_function: 'purgeColdStorageBackups' }
];

class SecurityDatabase {
  private users: User[] = [];
  private rules: FunctionRule[] = [];
  private logs: SecurityAuditLog[] = [];
  private ruleIdCounter = 1;
  private logIdCounter = 1;
  private userIdCounter = 100;

  constructor() {
    this.reset();
  }

  public reset() {
    this.users = JSON.parse(JSON.stringify(INITIAL_USERS));
    this.rules = INITIAL_RULES.map((r, i) => ({ id: i + 1, ...r }));
    this.logs = [];
    this.ruleIdCounter = this.rules.length + 1;
    this.logIdCounter = 1;
  }

  public clearLogs() {
    this.logs = [];
  }

  public getUsers(): User[] {
    return [...this.users];
  }

  public addUser(userData: { username: string; role?: 'Admin' | 'Developer' | 'Guest'; password?: string; base_risk_score?: number }): User {
    const existing = this.users.find(u => u.username.toLowerCase() === userData.username.toLowerCase());
    if (existing) {
      if (userData.role) existing.role = userData.role;
      if (typeof userData.base_risk_score === 'number') existing.base_risk_score = userData.base_risk_score;
      return existing;
    }
    const newUser: User = {
      id: `usr_${Date.now().toString(36)}_${++this.userIdCounter}`,
      username: userData.username.trim(),
      password_hash: userData.password || 'ZeroTrust_2026',
      role: userData.role || 'Developer',
      base_risk_score: typeof userData.base_risk_score === 'number' ? userData.base_risk_score : 20
    };
    this.users.push(newUser);
    return newUser;
  }

  public getRules(): FunctionRule[] {
    return [...this.rules];
  }

  public addRule(current_function: string, allowed_next_function: string): FunctionRule {
    const newRule: FunctionRule = {
      id: this.ruleIdCounter++,
      current_function,
      allowed_next_function
    };
    this.rules.push(newRule);
    return newRule;
  }

  public deleteRule(id: number): boolean {
    const idx = this.rules.findIndex(r => r.id === id);
    if (idx !== -1) {
      this.rules.splice(idx, 1);
      return true;
    }
    return false;
  }

  public getAllLogs(): SecurityAuditLog[] {
    return [...this.logs].sort((a, b) => b.id - a.id);
  }

  /**
   * Compatibility layer providing env.DB.prepare(sql).bind(...).first() / .all() / .run()
   */
  public prepare(sql: string) {
    const self = this;
    let boundParams: any[] = [];

    const stmt = {
      bind(...params: any[]) {
        boundParams = params;
        return stmt;
      },
      async first(): Promise<any> {
        const trimmed = sql.trim();
        if (trimmed.includes('FROM users WHERE username = ?')) {
          const username = boundParams[0];
          return self.users.find(u => u.username === username) || null;
        }
        if (trimmed.includes('FROM security_audit_logs WHERE username = ?')) {
          const username = boundParams[0];
          const userLogs = self.logs.filter(l => l.username === username);
          if (userLogs.length === 0) return null;
          return userLogs[userLogs.length - 1]; // last log
        }
        if (trimmed.includes('FROM function_rules WHERE current_function = ? AND allowed_next_function = ?')) {
          const [current, next] = boundParams;
          return self.rules.find(r => r.current_function === current && r.allowed_next_function === next) || null;
        }
        return null;
      },
      async all(): Promise<{ results: any[] }> {
        const trimmed = sql.trim();
        if (trimmed.includes('FROM security_audit_logs')) {
          const limitMatch = trimmed.match(/LIMIT\s+(\d+)/i);
          const limit = limitMatch ? parseInt(limitMatch[1], 10) : 50;
          const sorted = [...self.logs].sort((a, b) => b.id - a.id).slice(0, limit);
          return { results: sorted };
        }
        if (trimmed.includes('FROM users')) {
          return { results: [...self.users] };
        }
        if (trimmed.includes('FROM function_rules')) {
          return { results: [...self.rules] };
        }
        return { results: [] };
      },
      async run(): Promise<{ success: boolean; id?: number }> {
        const trimmed = sql.trim();
        if (trimmed.startsWith('INSERT INTO security_audit_logs')) {
          const [username, requested_function, calculated_risk, status, reason] = boundParams;
          const newLog: SecurityAuditLog = {
            id: self.logIdCounter++,
            timestamp: new Date().toISOString(),
            username,
            requested_function,
            calculated_risk,
            status,
            reason
          };
          self.logs.push(newLog);
          return { success: true, id: newLog.id };
        }
        return { success: true };
      }
    };

    return stmt;
  }
}

export const db = new SecurityDatabase();
