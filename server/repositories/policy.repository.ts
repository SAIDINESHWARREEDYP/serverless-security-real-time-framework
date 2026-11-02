import { db } from '../db.ts';

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

class PolicyRepository {
  public getPolicy(): PolicyConfig {
    const row = db.prepare('SELECT * FROM policies WHERE id = ? LIMIT 1').bind('current_policy').first<any>();
    if (!row) return { ...DEFAULT_POLICY };
    return {
      maxRiskThreshold: row.max_risk_threshold ?? DEFAULT_POLICY.maxRiskThreshold,
      sequenceViolationPenalty: row.sequence_violation_penalty ?? DEFAULT_POLICY.sequenceViolationPenalty,
      enforceStrictSequence: Boolean(row.enforce_strict_sequence),
      globalLockdown: Boolean(row.global_lockdown),
      requireAdminApprovalForNewLogins: Boolean(row.require_admin_approval)
    };
  }

  public updatePolicy(updates: Partial<PolicyConfig>): PolicyConfig {
    const current = this.getPolicy();
    const next: PolicyConfig = {
      maxRiskThreshold: typeof updates.maxRiskThreshold === 'number'
        ? Math.max(10, Math.min(100, updates.maxRiskThreshold))
        : current.maxRiskThreshold,
      sequenceViolationPenalty: typeof updates.sequenceViolationPenalty === 'number'
        ? Math.max(0, Math.min(80, updates.sequenceViolationPenalty))
        : current.sequenceViolationPenalty,
      enforceStrictSequence: typeof updates.enforceStrictSequence === 'boolean'
        ? updates.enforceStrictSequence
        : current.enforceStrictSequence,
      globalLockdown: typeof updates.globalLockdown === 'boolean'
        ? updates.globalLockdown
        : current.globalLockdown,
      requireAdminApprovalForNewLogins: typeof updates.requireAdminApprovalForNewLogins === 'boolean'
        ? updates.requireAdminApprovalForNewLogins
        : current.requireAdminApprovalForNewLogins
    };

    db.prepare(
      `UPDATE policies SET
        max_risk_threshold = ?,
        sequence_violation_penalty = ?,
        enforce_strict_sequence = ?,
        global_lockdown = ?,
        require_admin_approval = ?,
        updated_at = datetime('now')
      WHERE id = 'current_policy'`
    ).bind(
      next.maxRiskThreshold,
      next.sequenceViolationPenalty,
      next.enforceStrictSequence ? 1 : 0,
      next.globalLockdown ? 1 : 0,
      next.requireAdminApprovalForNewLogins ? 1 : 0
    ).run();

    return next;
  }

  public getRules(): MarkovRule[] {
    const rows = db.prepare('SELECT id, current_function, allowed_next_function FROM function_rules ORDER BY id ASC').all<any>();
    return (rows.results || []).map((r) => ({
      id: r.id,
      current_function: r.current_function,
      allowed_next_function: r.allowed_next_function
    }));
  }

  public addRule(currentFunction: string, allowedNextFunction: string): MarkovRule {
    const existing = db.prepare(
      'SELECT id, current_function, allowed_next_function FROM function_rules WHERE current_function = ? AND allowed_next_function = ? LIMIT 1'
    ).bind(currentFunction, allowedNextFunction).first<any>();

    if (existing) {
      return {
        id: existing.id,
        current_function: existing.current_function,
        allowed_next_function: existing.allowed_next_function
      };
    }

    const runRes = db.prepare(
      'INSERT INTO function_rules (current_function, allowed_next_function) VALUES (?, ?)'
    ).bind(currentFunction, allowedNextFunction).run();

    return {
      id: Number(runRes.lastRowId || 999),
      current_function: currentFunction,
      allowed_next_function: allowedNextFunction
    };
  }

  public deleteRule(id: number): boolean {
    const res = db.prepare('DELETE FROM function_rules WHERE id = ?').bind(id).run();
    return (res.changes || 0) > 0;
  }

  public isTransitionAllowed(currentFunction: string, nextFunction: string): boolean {
    const match = db.prepare(
      'SELECT id FROM function_rules WHERE current_function = ? AND allowed_next_function = ? LIMIT 1'
    ).bind(currentFunction, nextFunction).first<any>();

    return Boolean(match);
  }

  public reset() {
    this.updatePolicy(DEFAULT_POLICY);
  }
}

export const policyRepository = new PolicyRepository();
