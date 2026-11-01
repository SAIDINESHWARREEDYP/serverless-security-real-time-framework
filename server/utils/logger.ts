export interface StructuredLog {
  timestamp: string;
  level: 'info' | 'warn' | 'error' | 'security';
  correlationId?: string;
  action: string;
  userId?: string;
  ip?: string;
  latencyMs?: number;
  message: string;
  metadata?: Record<string, any>;
}

export const logger = {
  info(action: string, message: string, meta?: Partial<StructuredLog>) {
    const entry: StructuredLog = {
      timestamp: new Date().toISOString(),
      level: 'info',
      action,
      message,
      ...meta
    };
    console.log(`[INFO] [${entry.action}] ${entry.message}`, meta?.metadata ? JSON.stringify(meta.metadata) : '');
  },

  warn(action: string, message: string, meta?: Partial<StructuredLog>) {
    const entry: StructuredLog = {
      timestamp: new Date().toISOString(),
      level: 'warn',
      action,
      message,
      ...meta
    };
    console.warn(`[WARN] [${entry.action}] ${entry.message}`, meta?.metadata ? JSON.stringify(meta.metadata) : '');
  },

  error(action: string, message: string, meta?: Partial<StructuredLog>) {
    const entry: StructuredLog = {
      timestamp: new Date().toISOString(),
      level: 'error',
      action,
      message,
      ...meta
    };
    console.error(`[ERROR] [${entry.action}] ${entry.message}`, meta?.metadata ? JSON.stringify(meta.metadata) : '');
  },

  security(action: string, message: string, meta?: Partial<StructuredLog>) {
    const entry: StructuredLog = {
      timestamp: new Date().toISOString(),
      level: 'security',
      action,
      message,
      ...meta
    };
    console.warn(`[SECURITY_ALERT] [${entry.action}] ${entry.message}`, meta?.metadata ? JSON.stringify(meta.metadata) : '');
  }
};
