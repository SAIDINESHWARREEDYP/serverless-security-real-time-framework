import { UserRecord, SanitizedUser, UserApprovalStatus, UserRoleType } from '../types/index.ts';
import { hashPassword, verifyPassword } from '../utils/crypto.ts';

// Initial Seed Users with PBKDF2 Cryptographic Hashes (NO PLAINTEXT PASSWORDS)
const INITIAL_SEEDS = [
  {
    id: 'usr_secops_admin',
    username: 'secops_admin',
    password: 'ZeroTrust_2026',
    role: 'Admin' as UserRoleType,
    base_risk_score: 0,
    status: 'APPROVED' as UserApprovalStatus,
    department: 'SecOps Core Operations',
    email: 'secops_admin@corp.internal',
    phone: '+1 (555) 019-4829',
    mfa_enabled: true
  },
  {
    id: 'usr_cloud_dev',
    username: 'cloud_dev',
    password: 'ZeroTrust_2026',
    role: 'Developer' as UserRoleType,
    base_risk_score: 15,
    status: 'APPROVED' as UserApprovalStatus,
    department: 'Cloud Platform Engineering',
    email: 'cloud_dev@corp.internal',
    phone: '+1 (555) 019-7261',
    mfa_enabled: true
  },
  {
    id: 'usr_auditor_guest',
    username: 'auditor_guest',
    password: 'ZeroTrust_2026',
    role: 'Guest' as UserRoleType,
    base_risk_score: 30,
    status: 'APPROVED' as UserApprovalStatus,
    department: 'Third-Party Compliance & SOC-2',
    email: 'auditor_guest@compliance-partner.com',
    phone: '+1 (555) 019-9154',
    mfa_enabled: true
  },
  {
    id: 'usr_sarah_infra',
    username: 'sarah_infra',
    password: 'ZeroTrust_2026',
    role: 'Developer' as UserRoleType,
    base_risk_score: 10,
    status: 'APPROVED' as UserApprovalStatus,
    department: 'Infrastructure & Edge Reliability',
    email: 'sarah_infra@corp.internal',
    phone: '+1 (555) 019-3820',
    mfa_enabled: true
  },
  {
    id: 'usr_alex_contractor',
    username: 'alex_contractor',
    password: 'ZeroTrust_2026',
    role: 'Developer' as UserRoleType,
    base_risk_score: 25,
    status: 'PENDING_APPROVAL' as UserApprovalStatus,
    department: 'Edge Pipeline Contractors',
    email: 'alex_contractor@contractor.internal',
    phone: '+1 (555) 019-6183',
    mfa_enabled: true,
    request_justification: 'Contractor onboarded for Cloudflare Worker serverless microservices deployment and telemetry audit.'
  },
  {
    id: 'usr_threat_actor',
    username: 'threat_actor',
    password: 'ZeroTrust_2026',
    role: 'Guest' as UserRoleType,
    base_risk_score: 70,
    status: 'SUSPENDED' as UserApprovalStatus,
    department: 'Untrusted Public Origin',
    email: 'threat_actor@darknet-proxy.io',
    phone: '+1 (555) 019-0099',
    mfa_enabled: true
  }
];

class UserRepository {
  private users: Map<string, UserRecord> = new Map();
  private usernameIndex: Map<string, string> = new Map();

  constructor() {
    this.reset();
  }

  public reset() {
    this.users.clear();
    this.usernameIndex.clear();

    for (const seed of INITIAL_SEEDS) {
      const { salt, hash } = hashPassword(seed.password);
      const record: UserRecord = {
        id: seed.id,
        username: seed.username,
        password_salt: salt,
        password_hash: hash,
        role: seed.role,
        base_risk_score: seed.base_risk_score,
        status: seed.status,
        department: seed.department,
        email: seed.email,
        phone: seed.phone,
        mfa_enabled: seed.mfa_enabled,
        created_at: new Date().toISOString(),
        approved_at: seed.status === 'APPROVED' ? new Date().toISOString() : undefined,
        approved_by: seed.status === 'APPROVED' ? 'SYSTEM_ROOT' : undefined,
        request_justification: seed.request_justification
      };
      this.users.set(record.id, record);
      this.usernameIndex.set(record.username.toLowerCase(), record.id);
    }
  }

  public findById(id: string): UserRecord | null {
    return this.users.get(id) || null;
  }

  public findByUsername(username: string): UserRecord | null {
    const id = this.usernameIndex.get(username.trim().toLowerCase());
    if (!id) return null;
    return this.users.get(id) || null;
  }

  public findAll(): UserRecord[] {
    return Array.from(this.users.values());
  }

  public findAllSanitized(): SanitizedUser[] {
    return Array.from(this.users.values()).map(u => this.sanitize(u));
  }

  public sanitize(u: UserRecord): SanitizedUser {
    return {
      id: u.id,
      username: u.username,
      role: u.role,
      base_risk_score: u.base_risk_score,
      status: u.status,
      department: u.department,
      email: u.email,
      phone: u.phone,
      mfa_enabled: u.mfa_enabled,
      created_at: u.created_at,
      approved_at: u.approved_at,
      approved_by: u.approved_by,
      last_login_at: u.last_login_at,
      request_justification: u.request_justification
    };
  }

  public create(data: {
    username: string;
    password: string;
    role?: UserRoleType;
    base_risk_score?: number;
    status?: UserApprovalStatus;
    department?: string;
    email?: string;
    phone?: string;
    mfa_enabled?: boolean;
    request_justification?: string;
    approved_by?: string;
  }): UserRecord {
    const cleanUsername = data.username.trim();
    const { salt, hash } = hashPassword(data.password);
    const id = `usr_${Date.now().toString(36)}_${Math.random().toString(36).substring(2, 6)}`;

    const record: UserRecord = {
      id,
      username: cleanUsername,
      password_salt: salt,
      password_hash: hash,
      role: data.role || 'Developer',
      base_risk_score: typeof data.base_risk_score === 'number' ? data.base_risk_score : 20,
      status: data.status || 'PENDING_APPROVAL',
      department: data.department || 'General Engineering',
      email: data.email || `${cleanUsername.toLowerCase()}@corp.internal`,
      phone: data.phone || '+1 (555) 019-8392',
      mfa_enabled: data.mfa_enabled ?? true,
      created_at: new Date().toISOString(),
      approved_at: data.status === 'APPROVED' ? new Date().toISOString() : undefined,
      approved_by: data.status === 'APPROVED' ? (data.approved_by || 'SYSTEM') : undefined,
      request_justification: data.request_justification
    };

    this.users.set(record.id, record);
    this.usernameIndex.set(record.username.toLowerCase(), record.id);
    return record;
  }

  public updatePassword(userId: string, newPlaintext: string): boolean {
    const user = this.users.get(userId);
    if (!user) return false;
    const { salt, hash } = hashPassword(newPlaintext);
    user.password_salt = salt;
    user.password_hash = hash;
    return true;
  }

  public update(userId: string, updates: Partial<UserRecord>): UserRecord | null {
    const user = this.users.get(userId);
    if (!user) return null;

    if (updates.role) user.role = updates.role;
    if (typeof updates.base_risk_score === 'number') user.base_risk_score = updates.base_risk_score;
    if (updates.status) user.status = updates.status;
    if (updates.department !== undefined) user.department = updates.department;
    if (updates.email !== undefined) user.email = updates.email;
    if (updates.phone !== undefined) user.phone = updates.phone;
    if (updates.mfa_enabled !== undefined) user.mfa_enabled = updates.mfa_enabled;
    if (updates.mfa_secret !== undefined) user.mfa_secret = updates.mfa_secret;
    if (updates.mfa_backup_codes !== undefined) user.mfa_backup_codes = updates.mfa_backup_codes;
    if (updates.approved_at !== undefined) user.approved_at = updates.approved_at;
    if (updates.approved_by !== undefined) user.approved_by = updates.approved_by;
    if (updates.last_login_at !== undefined) user.last_login_at = updates.last_login_at;

    return user;
  }

  public delete(userIdOrUsername: string): boolean {
    const user = this.findById(userIdOrUsername) || this.findByUsername(userIdOrUsername);
    if (!user) return false;
    this.users.delete(user.id);
    this.usernameIndex.delete(user.username.toLowerCase());
    return true;
  }
}

export const userRepository = new UserRepository();
