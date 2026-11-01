export interface FunctionEntity {
  id: string;
  name: string;
  slug: string;
  service_name: string;
  runtime: string;
  max_memory_mb: number;
  timeout_seconds: number;
  is_active: boolean;
  required_permission?: string;
  created_at: string;
  updated_at: string;
}

const INITIAL_FUNCTIONS: FunctionEntity[] = [
  { id: 'fn_login', name: 'Identity Login Handler', slug: 'login', service_name: 'auth-service', runtime: 'nodejs20.x', max_memory_mb: 128, timeout_seconds: 3, is_active: true, created_at: '2026-09-01T08:00:00.000Z', updated_at: '2026-09-01T08:00:00.000Z' },
  { id: 'fn_dashboard', name: 'Dashboard Metrics Aggregator', slug: 'getDashboardMetrics', service_name: 'telemetry-service', runtime: 'nodejs20.x', max_memory_mb: 256, timeout_seconds: 3, is_active: true, required_permission: 'function:invoke', created_at: '2026-09-01T08:00:00.000Z', updated_at: '2026-09-01T08:00:00.000Z' },
  { id: 'fn_audit_logs', name: 'Security Logs Query Engine', slug: 'viewSecurityLogs', service_name: 'audit-service', runtime: 'nodejs20.x', max_memory_mb: 256, timeout_seconds: 5, is_active: true, required_permission: 'audit:read', created_at: '2026-09-01T08:00:00.000Z', updated_at: '2026-09-01T08:00:00.000Z' },
  { id: 'fn_audit_events', name: 'Audit Events Stream', slug: 'viewAuditEvents', service_name: 'audit-service', runtime: 'nodejs20.x', max_memory_mb: 256, timeout_seconds: 5, is_active: true, required_permission: 'audit:read', created_at: '2026-09-01T08:00:00.000Z', updated_at: '2026-09-01T08:00:00.000Z' },
  { id: 'fn_deploy_worker', name: 'Cloudflare Worker Deployment', slug: 'deployWorkerCode', service_name: 'pipeline-service', runtime: 'nodejs20.x', max_memory_mb: 512, timeout_seconds: 10, is_active: true, required_permission: 'function:invoke', created_at: '2026-09-01T08:00:00.000Z', updated_at: '2026-09-01T08:00:00.000Z' },
  { id: 'fn_update_policy', name: 'Security Policy Mutation Engine', slug: 'updateSystemPolicy', service_name: 'policy-service', runtime: 'nodejs20.x', max_memory_mb: 256, timeout_seconds: 5, is_active: true, required_permission: 'policy:write', created_at: '2026-09-01T08:00:00.000Z', updated_at: '2026-09-01T08:00:00.000Z' },
  { id: 'fn_rotate_keys', name: 'KMS Key Rotation Worker', slug: 'rotateEncryptionKeys', service_name: 'kms-service', runtime: 'nodejs20.x', max_memory_mb: 256, timeout_seconds: 5, is_active: true, required_permission: 'policy:write', created_at: '2026-09-01T08:00:00.000Z', updated_at: '2026-09-01T08:00:00.000Z' },
  { id: 'fn_purge_backups', name: 'Cold Storage Backup Purge', slug: 'purgeColdStorageBackups', service_name: 'backup-service', runtime: 'nodejs20.x', max_memory_mb: 512, timeout_seconds: 15, is_active: true, required_permission: 'policy:write', created_at: '2026-09-01T08:00:00.000Z', updated_at: '2026-09-01T08:00:00.000Z' }
];

class FunctionRepository {
  private functions: Map<string, FunctionEntity> = new Map();

  constructor() {
    this.reset();
  }

  public reset() {
    this.functions.clear();
    for (const fn of INITIAL_FUNCTIONS) {
      this.functions.set(fn.slug, fn);
    }
  }

  public findAll(): FunctionEntity[] {
    return Array.from(this.functions.values());
  }

  public findBySlug(slug: string): FunctionEntity | null {
    const clean = slug.replace(/^\/api\//, '').replace(/^\/api\/v1\//, '');
    return this.functions.get(clean) || null;
  }

  public create(fn: Omit<FunctionEntity, 'id' | 'created_at' | 'updated_at'>): FunctionEntity {
    const record: FunctionEntity = {
      ...fn,
      id: `fn_${Date.now().toString(36)}_${Math.random().toString(36).substring(2, 6)}`,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
    this.functions.set(record.slug, record);
    return record;
  }
}

export const functionRepository = new FunctionRepository();
