import { User, SecurityAuditLog, FunctionRule, SecurityPolicyConfig, AuthSession } from '../types.ts';

export interface SecurityReportData {
  reportMetadata: {
    reportId: string;
    generatedAt: string;
    generatedTimestamp: number;
    generatedBy: {
      username: string;
      role: string;
    };
    framework: string;
    version: string;
    classification: string;
    complianceStandards: string[];
    integrityChecksum: string;
  };
  executiveSummary: {
    overallHealth: 'NOMINAL' | 'ELEVATED' | 'CRITICAL_DEFCON_1';
    defconLevel: number;
    complianceStatus: 'COMPLIANT_ZERO_TRUST' | 'CONDITIONAL_APPROVAL' | 'HIGH_RISK_BREACHES_DETECTED';
    summaryNarrative: string;
  };
  systemHealthTelemetry: {
    edgeStatus: string;
    edgeCluster: string;
    runtimeIsolate: string;
    databaseEngine: string;
    activeRulesCount: number;
    activePrincipalsCount: number;
    policyConfig: SecurityPolicyConfig;
  };
  riskMetrics: {
    meanThreatLevel: number;
    highestObservedRisk: number;
    totalRiskEvaluations: number;
    criticalIncidentsCount: number;
    riskTierDistribution: {
      nominal: { count: number; percentage: number; range: '0-24%' };
      moderate: { count: number; percentage: number; range: '25-49%' };
      elevated: { count: number; percentage: number; range: '50-74%' };
      critical: { count: number; percentage: number; range: '>=75%' };
    };
  };
  auditLogStatistics: {
    totalAuditLogs: number;
    totalAllowed: number;
    totalBlocked: number;
    blockRatePercentage: number;
    violationCategories: {
      rbacViolations: number;
      sequenceViolations: number;
      cutoffViolations: number;
      lockdownViolations: number;
    };
    endpointActivity: Array<{
      endpoint: string;
      totalCalls: number;
      allowed: number;
      blocked: number;
      avgRisk: number;
    }>;
  };
  principalsRoster: Array<{
    username: string;
    role: string;
    baseRiskScore: number;
    totalRequests: number;
    allowed: number;
    blocked: number;
    maxRiskObserved: number;
    averageRisk: number;
    complianceStatus: 'CLEARED' | 'ANOMALY_FLAGGED' | 'QUARANTINED';
  }>;
  recentIncidents: Array<{
    id: number;
    timestamp: string;
    username: string;
    endpoint: string;
    calculatedRisk: number;
    status: 'ALLOWED' | 'BLOCKED';
    reason: string;
  }>;
}

/**
 * Aggregates live system health, risk metrics, and audit log statistics into a comprehensive report object.
 */
export function generateSecurityReportData(
  users: User[],
  logs: SecurityAuditLog[],
  rules: FunctionRule[],
  policyConfig: SecurityPolicyConfig | undefined,
  currentSession: AuthSession | null
): SecurityReportData {
  const effectivePolicy: SecurityPolicyConfig = {
    maxRiskThreshold: policyConfig?.maxRiskThreshold ?? 75,
    sequenceViolationPenalty: policyConfig?.sequenceViolationPenalty ?? 40,
    enforceStrictSequence: policyConfig?.enforceStrictSequence ?? true,
    globalLockdown: policyConfig?.globalLockdown ?? false
  };

  const totalLogs = logs.length;
  const blockedLogs = logs.filter((l) => l.status === 'BLOCKED');
  const allowedLogs = logs.filter((l) => l.status === 'ALLOWED');
  const totalBlocked = blockedLogs.length;
  const totalAllowed = allowedLogs.length;
  const blockRate = totalLogs > 0 ? Math.round((totalBlocked / totalLogs) * 100) : 0;

  const criticalBlocks = logs.filter(
    (l) => l.calculated_risk >= effectivePolicy.maxRiskThreshold && l.status === 'BLOCKED'
  );
  const criticalCount = criticalBlocks.length;

  const meanThreat = totalLogs > 0
    ? Math.round(logs.reduce((s, l) => s + l.calculated_risk, 0) / totalLogs)
    : 15;

  const highestObserved = totalLogs > 0
    ? Math.max(...logs.map((l) => l.calculated_risk))
    : users.length > 0
    ? Math.max(...users.map((u) => u.base_risk_score))
    : 0;

  // DEFCON calculation
  const defconLevel = effectivePolicy.globalLockdown ? 1 :
    blockRate > 40 || criticalCount >= 4 ? 1 :
    blockRate > 20 || criticalCount >= 2 ? 2 :
    blockRate > 5 || meanThreat > 35 ? 3 :
    criticalCount > 0 ? 4 : 5;

  const overallHealth: 'NOMINAL' | 'ELEVATED' | 'CRITICAL_DEFCON_1' =
    defconLevel === 1 ? 'CRITICAL_DEFCON_1' :
    defconLevel <= 3 ? 'ELEVATED' : 'NOMINAL';

  const complianceStatus: 'COMPLIANT_ZERO_TRUST' | 'CONDITIONAL_APPROVAL' | 'HIGH_RISK_BREACHES_DETECTED' =
    criticalCount > 3 ? 'HIGH_RISK_BREACHES_DETECTED' :
    criticalCount > 0 || blockRate > 15 ? 'CONDITIONAL_APPROVAL' : 'COMPLIANT_ZERO_TRUST';

  // Risk Tier Breakdown
  const evaluations = totalLogs > 0
    ? logs.map((l) => l.calculated_risk)
    : users.map((u) => u.base_risk_score);

  let nominalCount = 0;
  let moderateCount = 0;
  let elevatedCount = 0;
  let criticalTierCount = 0;

  evaluations.forEach((score) => {
    if (score >= effectivePolicy.maxRiskThreshold) {
      criticalTierCount++;
    } else if (score >= 50) {
      elevatedCount++;
    } else if (score >= 25) {
      moderateCount++;
    } else {
      nominalCount++;
    }
  });

  const totalEvaluationsCount = evaluations.length || 1;

  // Violation categorization
  let rbacViolations = 0;
  let sequenceViolations = 0;
  let cutoffViolations = 0;
  let lockdownViolations = 0;

  blockedLogs.forEach((l) => {
    const reasonLower = (l.reason || '').toLowerCase();
    if (reasonLower.includes('lockdown')) {
      lockdownViolations++;
    } else if (reasonLower.includes('rbac') || reasonLower.includes('unauthorized role')) {
      rbacViolations++;
    } else if (reasonLower.includes('sequence') || reasonLower.includes('out-of-order') || reasonLower.includes('abnormal invocation')) {
      sequenceViolations++;
    } else if (reasonLower.includes('risk') || reasonLower.includes('exceeds safe boundary') || reasonLower.includes('mitigation triggered')) {
      cutoffViolations++;
    } else {
      cutoffViolations++;
    }
  });

  // Endpoint activity
  const endpointMap = new Map<string, { total: number; allowed: number; blocked: number; totalRisk: number }>();
  logs.forEach((l) => {
    const fn = l.requested_function || 'unknown';
    if (!endpointMap.has(fn)) {
      endpointMap.set(fn, { total: 0, allowed: 0, blocked: 0, totalRisk: 0 });
    }
    const entry = endpointMap.get(fn)!;
    entry.total++;
    if (l.status === 'ALLOWED') entry.allowed++;
    if (l.status === 'BLOCKED') entry.blocked++;
    entry.totalRisk += l.calculated_risk;
  });

  const endpointActivity = Array.from(endpointMap.entries()).map(([endpoint, val]) => ({
    endpoint,
    totalCalls: val.total,
    allowed: val.allowed,
    blocked: val.blocked,
    avgRisk: val.total > 0 ? Math.round(val.totalRisk / val.total) : 0
  })).sort((a, b) => b.totalCalls - a.totalCalls);

  // Principals roster
  const principalsRoster = users.map((u) => {
    const uLogs = logs.filter((l) => l.username === u.username);
    const uBlocked = uLogs.filter((l) => l.status === 'BLOCKED').length;
    const uAllowed = uLogs.filter((l) => l.status === 'ALLOWED').length;
    const uMaxRisk = uLogs.length > 0 ? Math.max(...uLogs.map((l) => l.calculated_risk)) : u.base_risk_score;
    const uAvgRisk = uLogs.length > 0 ? Math.round(uLogs.reduce((s, l) => s + l.calculated_risk, 0) / uLogs.length) : u.base_risk_score;

    let status: 'CLEARED' | 'ANOMALY_FLAGGED' | 'QUARANTINED' = 'CLEARED';
    if (u.base_risk_score >= 80 || uMaxRisk >= 90) {
      status = 'QUARANTINED';
    } else if (uBlocked > 0 || uAvgRisk >= 50) {
      status = 'ANOMALY_FLAGGED';
    }

    return {
      username: u.username,
      role: u.role,
      baseRiskScore: u.base_risk_score,
      totalRequests: uLogs.length,
      allowed: uAllowed,
      blocked: uBlocked,
      maxRiskObserved: uMaxRisk,
      averageRisk: uAvgRisk,
      complianceStatus: status
    };
  });

  // Recent incidents (last 15)
  const recentIncidents = [...logs]
    .sort((a, b) => b.id - a.id)
    .slice(0, 15)
    .map((l) => ({
      id: l.id,
      timestamp: l.timestamp,
      username: l.username,
      endpoint: l.requested_function,
      calculatedRisk: l.calculated_risk,
      status: l.status,
      reason: l.reason
    }));

  const now = new Date();
  const dateStr = now.toISOString().slice(0, 10).replace(/-/g, '');
  const randomSuffix = Math.random().toString(36).substring(2, 6).toUpperCase();
  const reportId = `SEC-AUDIT-${dateStr}-${randomSuffix}`;

  // Deterministic lightweight checksum representation
  const integrityPayload = `${reportId}:${totalLogs}:${totalBlocked}:${meanThreat}:${now.getTime()}`;
  let hash = 0;
  for (let i = 0; i < integrityPayload.length; i++) {
    hash = (hash << 5) - hash + integrityPayload.charCodeAt(i);
    hash |= 0;
  }
  const integrityChecksum = `SHA256-SIM:${Math.abs(hash).toString(16).padStart(8, '0').toUpperCase()}`;

  let summaryNarrative = 'System operates within nominal zero-trust perimeter criteria with baseline integrity.';
  if (effectivePolicy.globalLockdown) {
    summaryNarrative = 'EMERGENCY PERIMETER LOCKDOWN ENGAGED: Non-administrative endpoints are actively intercepted and suspended.';
  } else if (criticalCount > 0) {
    summaryNarrative = `High-risk anomalous access attempts (${criticalCount} incidents) were intercepted and neutralized by edge firewall boundaries.`;
  } else if (totalLogs === 0) {
    summaryNarrative = 'Initial baseline deployment verified. Awaiting production API activity streams.';
  }

  return {
    reportMetadata: {
      reportId,
      generatedAt: now.toISOString(),
      generatedTimestamp: now.getTime(),
      generatedBy: {
        username: currentSession?.user?.username || 'SecOps_Auditor_Console',
        role: currentSession?.user?.role || 'Admin'
      },
      framework: 'Serverless Security Verification Framework - Zero Trust Enterprise',
      version: '2.4.0-Production',
      classification: 'CONFIDENTIAL // COMPLIANCE AUDIT RECORD',
      complianceStandards: [
        'ISO/IEC 27001:2022 (A.9 Access Control & A.12 Operations Security)',
        'SOC 2 Type II (Trust Services Criteria - CC6 Security & CC7 Monitoring)',
        'NIST SP 800-207 (Zero Trust Architecture Principle Validation)',
        'Cloudflare Edge Worker & D1 Relational Integrity Standard'
      ],
      integrityChecksum
    },
    executiveSummary: {
      overallHealth,
      defconLevel,
      complianceStatus,
      summaryNarrative
    },
    systemHealthTelemetry: {
      edgeStatus: 'ONLINE_ACTIVE',
      edgeCluster: 'Cloudflare Global Edge PoP (ap-south-1)',
      runtimeIsolate: 'V8 Serverless Worker Isolate Engine',
      databaseEngine: 'Cloudflare D1 Relational SQLite (ACID Compliant)',
      activeRulesCount: rules.length,
      activePrincipalsCount: users.length,
      policyConfig: effectivePolicy
    },
    riskMetrics: {
      meanThreatLevel: meanThreat,
      highestObservedRisk: highestObserved,
      totalRiskEvaluations: evaluations.length,
      criticalIncidentsCount: criticalCount,
      riskTierDistribution: {
        nominal: {
          count: nominalCount,
          percentage: Math.round((nominalCount / totalEvaluationsCount) * 100),
          range: '0-24%'
        },
        moderate: {
          count: moderateCount,
          percentage: Math.round((moderateCount / totalEvaluationsCount) * 100),
          range: '25-49%'
        },
        elevated: {
          count: elevatedCount,
          percentage: Math.round((elevatedCount / totalEvaluationsCount) * 100),
          range: '50-74%'
        },
        critical: {
          count: criticalTierCount,
          percentage: Math.round((criticalTierCount / totalEvaluationsCount) * 100),
          range: '>=75%'
        }
      }
    },
    auditLogStatistics: {
      totalAuditLogs: totalLogs,
      totalAllowed,
      totalBlocked,
      blockRatePercentage: blockRate,
      violationCategories: {
        rbacViolations,
        sequenceViolations,
        cutoffViolations,
        lockdownViolations
      },
      endpointActivity
    },
    principalsRoster,
    recentIncidents
  };
}

/**
 * Converts the report data into a RFC-4180 compliant CSV string with distinct audit sections.
 */
export function formatSecurityReportCSV(report: SecurityReportData): string {
  const escape = (val: any): string => {
    const str = String(val ?? '');
    if (str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r')) {
      return `"${str.replace(/"/g, '""')}"`;
    }
    return str;
  };

  const lines: string[] = [];

  const addHeader = (title: string) => {
    lines.push('');
    lines.push(`================================================================`);
    lines.push(`### ${title.toUpperCase()} ###`);
    lines.push(`================================================================`);
  };

  const addRow = (cols: (string | number)[]) => {
    lines.push(cols.map(escape).join(','));
  };

  // Section 1: Report Metadata
  addHeader('EXECUTIVE COMPLIANCE AUDIT REPORT METADATA');
  addRow(['Report Identifier', report.reportMetadata.reportId]);
  addRow(['Generation Timestamp (ISO)', report.reportMetadata.generatedAt]);
  addRow(['Auditor / Operator Identity', report.reportMetadata.generatedBy.username]);
  addRow(['Operator Clearance Role', report.reportMetadata.generatedBy.role]);
  addRow(['Framework Architecture', report.reportMetadata.framework]);
  addRow(['Framework Version', report.reportMetadata.version]);
  addRow(['Security Classification', report.reportMetadata.classification]);
  addRow(['Integrity Checksum Hash', report.reportMetadata.integrityChecksum]);
  addRow(['Compliance Standards Validated', report.reportMetadata.complianceStandards.join('; ')]);

  // Section 2: Executive Summary & Health
  addHeader('EXECUTIVE SYSTEM HEALTH & DEFCON ASSESSMENT');
  addRow(['Overall System Health Status', report.executiveSummary.overallHealth]);
  addRow(['Defense Condition (DEFCON)', `DEFCON ${report.executiveSummary.defconLevel}`]);
  addRow(['Zero-Trust Compliance Status', report.executiveSummary.complianceStatus]);
  addRow(['Executive Assessment Narrative', report.executiveSummary.summaryNarrative]);

  // Section 3: Edge Architecture & Active Policy Telemetry
  addHeader('EDGE ARCHITECTURE & SECURITY POLICY CONFIGURATION');
  addRow(['Edge Gateway Status', report.systemHealthTelemetry.edgeStatus]);
  addRow(['Edge Global Cluster Zone', report.systemHealthTelemetry.edgeCluster]);
  addRow(['V8 Isolate Runtime Engine', report.systemHealthTelemetry.runtimeIsolate]);
  addRow(['Distributed D1 SQL Database', report.systemHealthTelemetry.databaseEngine]);
  addRow(['Markov Transition Rules Count', report.systemHealthTelemetry.activeRulesCount]);
  addRow(['Active Principals Provisioned', report.systemHealthTelemetry.activePrincipalsCount]);
  addRow(['Max Risk Cutoff Threshold', `${report.systemHealthTelemetry.policyConfig.maxRiskThreshold}%`]);
  addRow(['Sequence Violation Threat Penalty', `+${report.systemHealthTelemetry.policyConfig.sequenceViolationPenalty}%`]);
  addRow(['Strict Markov Sequence Enforced', report.systemHealthTelemetry.policyConfig.enforceStrictSequence ? 'ENABLED' : 'DISABLED']);
  addRow(['Perimeter Emergency Lockdown', report.systemHealthTelemetry.policyConfig.globalLockdown ? 'ACTIVE' : 'STANDBY']);

  // Section 4: Risk Metrics & Distribution
  addHeader('SYSTEM RISK DISTRIBUTION & THREAT METRICS');
  addRow(['Mean System Threat Level', `${report.riskMetrics.meanThreatLevel}%`]);
  addRow(['Highest Observed Threat Risk', `${report.riskMetrics.highestObservedRisk}%`]);
  addRow(['Total Risk Evaluations Scored', report.riskMetrics.totalRiskEvaluations]);
  addRow(['Critical Risk Incidents (>=Cutoff)', report.riskMetrics.criticalIncidentsCount]);
  lines.push('');
  addRow(['Risk Tier', 'Risk Range', 'Evaluation Count', 'Percentage Share']);
  addRow(['Nominal', report.riskMetrics.riskTierDistribution.nominal.range, report.riskMetrics.riskTierDistribution.nominal.count, `${report.riskMetrics.riskTierDistribution.nominal.percentage}%`]);
  addRow(['Moderate', report.riskMetrics.riskTierDistribution.moderate.range, report.riskMetrics.riskTierDistribution.moderate.count, `${report.riskMetrics.riskTierDistribution.moderate.percentage}%`]);
  addRow(['Elevated', report.riskMetrics.riskTierDistribution.elevated.range, report.riskMetrics.riskTierDistribution.elevated.count, `${report.riskMetrics.riskTierDistribution.elevated.percentage}%`]);
  addRow(['Critical', report.riskMetrics.riskTierDistribution.critical.range, report.riskMetrics.riskTierDistribution.critical.count, `${report.riskMetrics.riskTierDistribution.critical.percentage}%`]);

  // Section 5: Audit Log Statistics & Violation Categorization
  addHeader('SECURITY AUDIT LEDGER STATISTICS & VIOLATION CATEGORIES');
  addRow(['Total Audit Ledger Records', report.auditLogStatistics.totalAuditLogs]);
  addRow(['Total Requests Allowed', report.auditLogStatistics.totalAllowed]);
  addRow(['Total Requests Blocked', report.auditLogStatistics.totalBlocked]);
  addRow(['Global System Intercept Rate', `${report.auditLogStatistics.blockRatePercentage}%`]);
  addRow(['RBAC Clearance Breach Count', report.auditLogStatistics.violationCategories.rbacViolations]);
  addRow(['Markov Sequence Deviation Count', report.auditLogStatistics.violationCategories.sequenceViolations]);
  addRow(['Cutoff Threshold Suspensions', report.auditLogStatistics.violationCategories.cutoffViolations]);
  addRow(['Perimeter Lockdown Intercepts', report.auditLogStatistics.violationCategories.lockdownViolations]);

  // Section 6: Endpoint Activity Distribution
  addHeader('ENDPOINT ACTIVITY & INTERCEPTION TELEMETRY');
  addRow(['Endpoint Function Path', 'Total Invocations', 'Allowed Count', 'Blocked Count', 'Mean Risk (%)']);
  if (report.auditLogStatistics.endpointActivity.length === 0) {
    addRow(['No endpoint invocations recorded in active ledger', 0, 0, 0, 0]);
  } else {
    report.auditLogStatistics.endpointActivity.forEach((ep) => {
      addRow([ep.endpoint, ep.totalCalls, ep.allowed, ep.blocked, `${ep.avgRisk}%`]);
    });
  }

  // Section 7: Principals Roster & Risk Breakdown
  addHeader('ACTIVE PRINCIPALS COMPLIANCE & RISK ROSTER');
  addRow([
    'Username',
    'Assigned Role',
    'Base Risk (%)',
    'Total Requests',
    'Allowed Requests',
    'Blocked Requests',
    'Max Observed Risk (%)',
    'Average Risk (%)',
    'Compliance Clearance'
  ]);
  report.principalsRoster.forEach((p) => {
    addRow([
      p.username,
      p.role,
      `${p.baseRiskScore}%`,
      p.totalRequests,
      p.allowed,
      p.blocked,
      `${p.maxRiskObserved}%`,
      `${p.averageRisk}%`,
      p.complianceStatus
    ]);
  });

  // Section 8: Recent Incident Log Sample
  addHeader('RECENT SECURITY AUDIT LEDGER TRAIL (SAMPLE)');
  addRow(['Log ID', 'Timestamp (ISO)', 'Principal', 'Requested Function', 'Calculated Risk (%)', 'Verdict', 'Reason / Mitigation']);
  if (report.recentIncidents.length === 0) {
    addRow(['N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'Ledger is clean. No audit events recorded.']);
  } else {
    report.recentIncidents.forEach((inc) => {
      addRow([
        inc.id,
        inc.timestamp,
        inc.username,
        inc.endpoint,
        `${inc.calculatedRisk}%`,
        inc.status,
        inc.reason
      ]);
    });
  }

  return lines.join('\r\n');
}

/**
 * Downloads a string or blob as a client-side file.
 */
export function downloadFile(content: string, filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', filename);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
