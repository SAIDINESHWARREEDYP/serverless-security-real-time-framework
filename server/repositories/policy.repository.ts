export interface PolicyConfig {
  maxRiskThreshold: number;
  sequenceViolationPenalty: number;
  enforceStrictSequence: boolean;
  globalLockdown: boolean;
  requireAdminApprovalForNewLogins: boolean;
}

export interface MarkovRule {
  id: number;
  current_function: string;
  allowed_next_function: string;
}

const DEFAULT_POLICY: PolicyConfig = {
  maxRiskThreshold: 75,
  sequenceViolationPenalty: 40,
  enforceStrictSequence: true,
  globalLockdown: false,
  requireAdminApprovalForNewLogins: true
};

const INITIAL_RULES: MarkovRule[] = [
  { id: 1, current_function: 'login', allowed_next_function: 'getDashboardMetrics' },
  { id: 2, current_function: 'getDashboardMetrics', allowed_next_function: 'viewSecurityLogs' },
  { id: 3, current_function: 'viewSecurityLogs', allowed_next_function: 'deployWorkerCode' },
  { id: 4, current_function: 'deployWorkerCode', allowed_next_function: 'updateSystemPolicy' },
  { id: 5, current_function: 'viewSecurityLogs', allowed_next_function: 'rotateEncryptionKeys' },
  { id: 6, current_function: 'rotateEncryptionKeys', allowed_next_function: 'purgeColdStorageBackups' },
  { id: 7, current_function: 'auth/mfa/verify', allowed_next_function: 'getDashboardMetrics' },
  { id: 8, current_function: 'v1/auth/mfa/verify', allowed_next_function: 'getDashboardMetrics' }
];

class PolicyRepository {
  private policy: PolicyConfig = { ...DEFAULT_POLICY };
  private rules: MarkovRule[] = [...INITIAL_RULES];
  private ruleCounter = 9;

  public getPolicy(): PolicyConfig {
    return { ...this.policy };
  }

  public updatePolicy(updates: Partial<PolicyConfig>): PolicyConfig {
    if (typeof updates.maxRiskThreshold === 'number') {
      this.policy.maxRiskThreshold = Math.max(10, Math.min(100, updates.maxRiskThreshold));
    }
    if (typeof updates.sequenceViolationPenalty === 'number') {
      this.policy.sequenceViolationPenalty = Math.max(0, Math.min(80, updates.sequenceViolationPenalty));
    }
    if (typeof updates.enforceStrictSequence === 'boolean') {
      this.policy.enforceStrictSequence = updates.enforceStrictSequence;
    }
    if (typeof updates.globalLockdown === 'boolean') {
      this.policy.globalLockdown = updates.globalLockdown;
    }
    if (typeof updates.requireAdminApprovalForNewLogins === 'boolean') {
      this.policy.requireAdminApprovalForNewLogins = updates.requireAdminApprovalForNewLogins;
    }
    return { ...this.policy };
  }

  public getRules(): MarkovRule[] {
    return [...this.rules];
  }

  public addRule(currentFunction: string, allowedNextFunction: string): MarkovRule {
    const existing = this.rules.find(
      r => r.current_function === currentFunction && r.allowed_next_function === allowedNextFunction
    );
    if (existing) return existing;

    const newRule: MarkovRule = {
      id: this.ruleCounter++,
      current_function: currentFunction,
      allowed_next_function: allowedNextFunction
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

  public isTransitionAllowed(currentFunction: string, nextFunction: string): boolean {
    return this.rules.some(
      r => r.current_function === currentFunction && r.allowed_next_function === nextFunction
    );
  }

  public reset() {
    this.policy = { ...DEFAULT_POLICY };
    this.rules = [...INITIAL_RULES];
  }
}

export const policyRepository = new PolicyRepository();
