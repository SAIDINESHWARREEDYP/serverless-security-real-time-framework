/**
 * Centralized Backend Types & Domain Models
 */

export type CanonicalUserRole =
  | 'Super Administrator'
  | 'Security Administrator'
  | 'Security Analyst'
  | 'Developer'
  | 'Auditor'
  | 'Viewer';

export type UserRoleType = CanonicalUserRole | 'Admin' | 'Developer' | 'Guest' | 'Administrator';
export type UserApprovalStatus = 'APPROVED' | 'PENDING_APPROVAL' | 'REJECTED' | 'SUSPENDED';

export interface UserRecord {
  id: string;
  username: string;
  password_hash: string;
  password_salt: string;
  role: UserRoleType;
  base_risk_score: number;
  status: UserApprovalStatus;
  department?: string;
  email?: string;
  phone?: string;
  mfa_enabled: boolean;
  mfa_secret?: string; // Stored securely, never returned in API responses
  mfa_backup_codes?: string[]; // Hashed or securely kept
  created_at: string;
  approved_at?: string;
  approved_by?: string;
  last_login_at?: string;
  request_justification?: string;
}

export interface SanitizedUser {
  id: string;
  username: string;
  role: UserRoleType;
  base_risk_score: number;
  status: UserApprovalStatus;
  department?: string;
  email?: string;
  phone?: string;
  mfa_enabled: boolean;
  created_at: string;
  approved_at?: string;
  approved_by?: string;
  last_login_at?: string;
  request_justification?: string;
}

export interface SessionRecord {
  id: string;
  user_id: string;
  username: string;
  role: UserRoleType;
  session_token: string;
  status: 'active' | 'revoked' | 'expired';
  ip_address?: string;
  user_agent?: string;
  created_at: string;
  expires_at: string;
  revoked_at?: string;
  revoked_by?: string;
  revocation_reason?: string;
}

export interface JwtClaims {
  sub: string; // user id
  username: string;
  role: UserRoleType;
  jti: string; // unique session/token id
  iss: string;
  aud: string;
  iat: number;
  nbf: number;
  exp: number;
}

export interface MfaChallengeSession {
  id: string;
  userId: string;
  username: string;
  role: UserRoleType;
  attemptsLeft: number;
  expiresAt: number;
  phoneMasked: string;
  emailMasked: string;
  totpSecret: string;
}

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  message?: string;
  meta?: {
    traceId?: string;
    latencyMs?: number;
    timestamp?: string;
  };
}

export interface ProblemDetails {
  type: string;
  title: string;
  status: number;
  detail: string;
  instance: string;
  errorCode: string;
  traceId?: string;
}
