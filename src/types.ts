export interface User {
  id: string;
  username: string;
  password_hash: string;
  role: 'Admin' | 'Developer' | 'Guest';
  base_risk_score: number;
}

export interface AuthSession {
  user: User;
  token: string;
  loginTime: string;
  expiresInSeconds: number;
}

export interface SecurityPolicyConfig {
  maxRiskThreshold: number; // default 75
  sequenceViolationPenalty: number; // default 40
  enforceStrictSequence: boolean; // default true
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

export interface SystemOverview {
  users: User[];
  rules: FunctionRule[];
  logs: SecurityAuditLog[];
  stats: {
    totalUsers: number;
    totalRules: number;
    totalLogs: number;
    blockedCount: number;
    allowedCount: number;
  };
  policyConfig?: SecurityPolicyConfig;
}

export interface TerminalLogEntry {
  id: string;
  timestamp: string;
  type: 'info' | 'post' | 'get' | 'success' | 'alert' | 'error' | 'metric';
  text: string;
}

