import React, { useState, useMemo } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  FileText,
  FileSpreadsheet,
  Download,
  Printer,
  Copy,
  Check,
  X,
  Activity,
  AlertTriangle,
  Server,
  Database,
  Lock,
  Users,
  Terminal,
  ExternalLink,
  ChevronRight
} from 'lucide-react';
import { User, SecurityAuditLog, FunctionRule, SecurityPolicyConfig, AuthSession } from '../types.ts';
import { generateSecurityReportData, formatSecurityReportCSV, downloadFile, SecurityReportData } from '../utils/securityReport.ts';

interface SecurityReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  users: User[];
  logs: SecurityAuditLog[];
  rules: FunctionRule[];
  policyConfig?: SecurityPolicyConfig;
  currentSession: AuthSession | null;
}

export const SecurityReportModal: React.FC<SecurityReportModalProps> = ({
  isOpen,
  onClose,
  users,
  logs,
  rules,
  policyConfig,
  currentSession
}) => {
  const [activeTab, setActiveTab] = useState<'executive' | 'printable' | 'json' | 'csv'>('executive');
  const [copiedFormat, setCopiedFormat] = useState<string | null>(null);
  const [isDownloading, setIsDownloading] = useState<string | null>(null);

  // Generate complete aggregated security report
  const reportData = useMemo(() => {
    return generateSecurityReportData(users, logs, rules, policyConfig, currentSession);
  }, [users, logs, rules, policyConfig, currentSession]);

  const csvString = useMemo(() => {
    return formatSecurityReportCSV(reportData);
  }, [reportData]);

  const jsonString = useMemo(() => {
    return JSON.stringify(reportData, null, 2);
  }, [reportData]);

  if (!isOpen) return null;

  const handleDownloadJSON = () => {
    setIsDownloading('json');
    const dateStr = new Date().toISOString().slice(0, 10);
    downloadFile(
      jsonString,
      `security_compliance_report_${reportData.reportMetadata.reportId.toLowerCase()}_${dateStr}.json`,
      'application/json'
    );
    setTimeout(() => setIsDownloading(null), 1200);
  };

  const handleDownloadCSV = () => {
    setIsDownloading('csv');
    const dateStr = new Date().toISOString().slice(0, 10);
    downloadFile(
      csvString,
      `security_compliance_report_${reportData.reportMetadata.reportId.toLowerCase()}_${dateStr}.csv`,
      'text/csv;charset=utf-8;'
    );
    setTimeout(() => setIsDownloading(null), 1200);
  };

  const handleCopy = (format: 'json' | 'csv') => {
    const text = format === 'json' ? jsonString : csvString;
    navigator.clipboard.writeText(text);
    setCopiedFormat(format);
    setTimeout(() => setCopiedFormat(null), 2000);
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div
      id="security-report-modal"
      role="dialog"
      aria-modal="true"
      aria-labelledby="security-report-title"
      className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-black/80 backdrop-blur-sm overflow-y-auto"
    >
      <div className="bg-[#0b1220] border border-[#223d66] rounded-xl w-full max-w-5xl max-h-[92vh] flex flex-col shadow-2xl overflow-hidden font-mono text-slate-200">
        {/* Modal Header */}
        <div className="p-4 sm:p-5 border-b border-[#1e2e4a] bg-[#0d1627] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
              <FileSpreadsheet className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h2 id="security-report-title" className="text-base sm:text-lg font-bold text-white tracking-wide">
                  Compliance Security Audit Report
                </h2>
                <span className="text-[10px] px-2 py-0.5 rounded bg-blue-500/20 text-blue-400 border border-blue-500/30">
                  {reportData.reportMetadata.reportId}
                </span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                  {reportData.executiveSummary.complianceStatus}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Aggregated system health telemetry, risk metrics, and audit log statistics for compliance auditing.
              </p>
            </div>
          </div>

          {/* Quick Action Buttons */}
          <div className="flex items-center gap-2 flex-wrap self-start sm:self-auto">
            <button
              id="btn-download-report-json"
              onClick={handleDownloadJSON}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold bg-blue-600 hover:bg-blue-500 text-white transition-all shadow-md"
              title="Download full audit report as JSON file"
            >
              {isDownloading === 'json' ? (
                <>
                  <Check className="w-3.5 h-3.5" />
                  <span>Downloaded!</span>
                </>
              ) : (
                <>
                  <Download className="w-3.5 h-3.5" />
                  <span>Download JSON</span>
                </>
              )}
            </button>

            <button
              id="btn-download-report-csv"
              onClick={handleDownloadCSV}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold bg-emerald-600 hover:bg-emerald-500 text-white transition-all shadow-md"
              title="Download full audit report as CSV spreadsheet"
            >
              {isDownloading === 'csv' ? (
                <>
                  <Check className="w-3.5 h-3.5" />
                  <span>Downloaded!</span>
                </>
              ) : (
                <>
                  <FileSpreadsheet className="w-3.5 h-3.5" />
                  <span>Download CSV</span>
                </>
              )}
            </button>

            <button
              id="btn-print-report"
              onClick={handlePrint}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
              title="Print document or Save to PDF"
            >
              <Printer className="w-3.5 h-3.5 text-slate-300" />
              <span>Print / PDF</span>
            </button>

            <button
              id="btn-close-report-modal"
              onClick={onClose}
              className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-white border border-slate-800 transition-colors ml-1"
              aria-label="Close Security Report modal"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Tab Navigation & Metadata Bar */}
        <div className="px-4 py-2 bg-[#090f1a] border-b border-[#1e2e4a] flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
          <div className="flex items-center gap-1">
            <button
              id="tab-report-executive"
              onClick={() => setActiveTab('executive')}
              className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-colors ${
                activeTab === 'executive'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
              }`}
            >
              Executive Summary
            </button>
            <button
              id="tab-report-printable"
              onClick={() => setActiveTab('printable')}
              className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-colors ${
                activeTab === 'printable'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
              }`}
            >
              Formal Audit Document
            </button>
            <button
              id="tab-report-json"
              onClick={() => setActiveTab('json')}
              className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-colors ${
                activeTab === 'json'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
              }`}
            >
              JSON View
            </button>
            <button
              id="tab-report-csv"
              onClick={() => setActiveTab('csv')}
              className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-colors ${
                activeTab === 'csv'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
              }`}
            >
              CSV Ledger
            </button>
          </div>

          <div className="flex items-center gap-2 text-[11px] text-slate-400">
            <span>Operator: <strong className="text-white">{reportData.reportMetadata.generatedBy.username}</strong></span>
            <span>•</span>
            <span>Generated: <strong className="text-white">{new Date(reportData.reportMetadata.generatedAt).toLocaleTimeString()}</strong></span>
          </div>
        </div>

        {/* Modal Scrollable Body */}
        <div className="p-5 overflow-y-auto flex-1 space-y-6">
          {/* TAB 1: EXECUTIVE SUMMARY */}
          {activeTab === 'executive' && (
            <div className="space-y-6">
              {/* Executive Assessment Header Banner */}
              <div className="bg-[#0e172a] border border-[#223d66] p-4 rounded-xl relative overflow-hidden">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                  <div className="space-y-1">
                    <span className="text-[10px] uppercase font-bold text-blue-400 tracking-wider">
                      Zero-Trust Compliance Assessment
                    </span>
                    <h3 className="text-lg font-bold text-white flex items-center gap-2">
                      <span>Defense Condition:</span>
                      <span className={`px-2 py-0.5 rounded text-sm ${
                        reportData.executiveSummary.defconLevel === 1 ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' :
                        reportData.executiveSummary.defconLevel <= 3 ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' :
                        'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                      }`}>
                        DEFCON {reportData.executiveSummary.defconLevel} ({reportData.executiveSummary.overallHealth})
                      </span>
                    </h3>
                    <p className="text-xs text-slate-300 max-w-2xl font-sans mt-1">
                      {reportData.executiveSummary.summaryNarrative}
                    </p>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <div className="bg-[#090d16] border border-[#1e2e4a] p-3 rounded-lg text-center min-w-[100px]">
                      <div className="text-[10px] text-slate-400 uppercase">Mean Threat</div>
                      <div className="text-xl font-bold text-white mt-0.5">{reportData.riskMetrics.meanThreatLevel}%</div>
                    </div>
                    <div className="bg-[#090d16] border border-[#1e2e4a] p-3 rounded-lg text-center min-w-[100px]">
                      <div className="text-[10px] text-slate-400 uppercase">Block Rate</div>
                      <div className="text-xl font-bold text-rose-400 mt-0.5">{reportData.auditLogStatistics.blockRatePercentage}%</div>
                    </div>
                    <div className="bg-[#090d16] border border-[#1e2e4a] p-3 rounded-lg text-center min-w-[100px]">
                      <div className="text-[10px] text-slate-400 uppercase">Critical Stops</div>
                      <div className="text-xl font-bold text-amber-400 mt-0.5">{reportData.riskMetrics.criticalIncidentsCount}</div>
                    </div>
                  </div>
                </div>
              </div>

              {/* 3 Pillars Summary Grid */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {/* 1. System Health Data */}
                <div className="bg-[#0e172a] border border-[#1e2e4a] p-4 rounded-xl space-y-3">
                  <div className="flex items-center justify-between border-b border-[#1e2e4a] pb-2">
                    <div className="flex items-center gap-2 font-bold text-white text-xs uppercase">
                      <Server className="w-4 h-4 text-blue-400" />
                      System Health
                    </div>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300">
                      Active V8
                    </span>
                  </div>
                  <ul className="space-y-2 text-xs">
                    <li className="flex justify-between">
                      <span className="text-slate-400">Edge Gateway:</span>
                      <span className="text-emerald-400 font-bold">{reportData.systemHealthTelemetry.edgeStatus}</span>
                    </li>
                    <li className="flex justify-between">
                      <span className="text-slate-400">Database Engine:</span>
                      <span className="text-white">Cloudflare D1 (ACID)</span>
                    </li>
                    <li className="flex justify-between">
                      <span className="text-slate-400">Active Rules in D1:</span>
                      <span className="text-white">{reportData.systemHealthTelemetry.activeRulesCount}</span>
                    </li>
                    <li className="flex justify-between">
                      <span className="text-slate-400">Cutoff Boundary:</span>
                      <span className="text-blue-400 font-bold">{reportData.systemHealthTelemetry.policyConfig.maxRiskThreshold}%</span>
                    </li>
                    <li className="flex justify-between">
                      <span className="text-slate-400">Sequence Threat Penalty:</span>
                      <span className="text-amber-400 font-bold">+{reportData.systemHealthTelemetry.policyConfig.sequenceViolationPenalty}%</span>
                    </li>
                    <li className="flex justify-between">
                      <span className="text-slate-400">Emergency Perimeter:</span>
                      <span className={reportData.systemHealthTelemetry.policyConfig.globalLockdown ? 'text-rose-400 font-bold' : 'text-slate-300'}>
                        {reportData.systemHealthTelemetry.policyConfig.globalLockdown ? 'ENGAGED' : 'STANDBY'}
                      </span>
                    </li>
                  </ul>
                </div>

                {/* 2. Risk Metrics */}
                <div className="bg-[#0e172a] border border-[#1e2e4a] p-4 rounded-xl space-y-3">
                  <div className="flex items-center justify-between border-b border-[#1e2e4a] pb-2">
                    <div className="flex items-center gap-2 font-bold text-white text-xs uppercase">
                      <Activity className="w-4 h-4 text-emerald-400" />
                      Risk Telemetry
                    </div>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-300">
                      Heuristic Matrix
                    </span>
                  </div>
                  <div className="space-y-2 text-xs">
                    <div>
                      <div className="flex justify-between text-[11px] mb-1">
                        <span className="text-slate-400">Nominal (0-24%):</span>
                        <span className="text-emerald-400 font-bold">
                          {reportData.riskMetrics.riskTierDistribution.nominal.count} ({reportData.riskMetrics.riskTierDistribution.nominal.percentage}%)
                        </span>
                      </div>
                      <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                        <div className="bg-emerald-400 h-full" style={{ width: `${reportData.riskMetrics.riskTierDistribution.nominal.percentage}%` }} />
                      </div>
                    </div>
                    <div>
                      <div className="flex justify-between text-[11px] mb-1">
                        <span className="text-slate-400">Moderate (25-49%):</span>
                        <span className="text-blue-400 font-bold">
                          {reportData.riskMetrics.riskTierDistribution.moderate.count} ({reportData.riskMetrics.riskTierDistribution.moderate.percentage}%)
                        </span>
                      </div>
                      <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                        <div className="bg-blue-400 h-full" style={{ width: `${reportData.riskMetrics.riskTierDistribution.moderate.percentage}%` }} />
                      </div>
                    </div>
                    <div>
                      <div className="flex justify-between text-[11px] mb-1">
                        <span className="text-slate-400">Elevated (50-74%):</span>
                        <span className="text-amber-400 font-bold">
                          {reportData.riskMetrics.riskTierDistribution.elevated.count} ({reportData.riskMetrics.riskTierDistribution.elevated.percentage}%)
                        </span>
                      </div>
                      <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                        <div className="bg-amber-400 h-full" style={{ width: `${reportData.riskMetrics.riskTierDistribution.elevated.percentage}%` }} />
                      </div>
                    </div>
                    <div>
                      <div className="flex justify-between text-[11px] mb-1">
                        <span className="text-slate-400">Critical (≥75%):</span>
                        <span className="text-rose-400 font-bold">
                          {reportData.riskMetrics.riskTierDistribution.critical.count} ({reportData.riskMetrics.riskTierDistribution.critical.percentage}%)
                        </span>
                      </div>
                      <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                        <div className="bg-rose-400 h-full" style={{ width: `${reportData.riskMetrics.riskTierDistribution.critical.percentage}%` }} />
                      </div>
                    </div>
                  </div>
                </div>

                {/* 3. Audit Log Statistics */}
                <div className="bg-[#0e172a] border border-[#1e2e4a] p-4 rounded-xl space-y-3">
                  <div className="flex items-center justify-between border-b border-[#1e2e4a] pb-2">
                    <div className="flex items-center gap-2 font-bold text-white text-xs uppercase">
                      <FileText className="w-4 h-4 text-purple-400" />
                      Audit Log Stats
                    </div>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-300">
                      {reportData.auditLogStatistics.totalAuditLogs} Records
                    </span>
                  </div>
                  <ul className="space-y-2 text-xs">
                    <li className="flex justify-between">
                      <span className="text-slate-400">Total Evaluations:</span>
                      <span className="text-white font-bold">{reportData.auditLogStatistics.totalAuditLogs}</span>
                    </li>
                    <li className="flex justify-between">
                      <span className="text-slate-400">Allowed Invocations:</span>
                      <span className="text-emerald-400 font-bold">{reportData.auditLogStatistics.totalAllowed}</span>
                    </li>
                    <li className="flex justify-between">
                      <span className="text-slate-400">Blocked Breaches:</span>
                      <span className="text-rose-400 font-bold">{reportData.auditLogStatistics.totalBlocked}</span>
                    </li>
                    <li className="flex justify-between">
                      <span className="text-slate-400">RBAC Clearance Breaches:</span>
                      <span className="text-amber-400 font-bold">{reportData.auditLogStatistics.violationCategories.rbacViolations}</span>
                    </li>
                    <li className="flex justify-between">
                      <span className="text-slate-400">Markov Sequence Deviations:</span>
                      <span className="text-amber-400 font-bold">{reportData.auditLogStatistics.violationCategories.sequenceViolations}</span>
                    </li>
                    <li className="flex justify-between">
                      <span className="text-slate-400">Threshold Suspensions:</span>
                      <span className="text-rose-400 font-bold">{reportData.auditLogStatistics.violationCategories.cutoffViolations}</span>
                    </li>
                  </ul>
                </div>
              </div>

              {/* Principals Roster Summary Table */}
              <div className="bg-[#0e172a] border border-[#1e2e4a] p-4 rounded-xl">
                <div className="flex items-center justify-between border-b border-[#1e2e4a] pb-3 mb-3">
                  <div className="flex items-center gap-2">
                    <Users className="w-4 h-4 text-blue-400" />
                    <h4 className="font-bold text-white text-xs uppercase tracking-wider">
                      Principal Identity &amp; Compliance Clearance Roster
                    </h4>
                  </div>
                  <span className="text-[11px] text-slate-400">
                    {reportData.principalsRoster.length} Provisioned Identities
                  </span>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="border-b border-[#1e2e4a] text-slate-400 uppercase text-[10px]">
                        <th className="pb-2">Principal</th>
                        <th className="pb-2">Role</th>
                        <th className="pb-2">Base Risk</th>
                        <th className="pb-2">Invocations</th>
                        <th className="pb-2">Allowed / Blocked</th>
                        <th className="pb-2">Max Risk</th>
                        <th className="pb-2 text-right">Clearance</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1e2e4a]/60">
                      {reportData.principalsRoster.map((p) => (
                        <tr key={p.username} className="hover:bg-slate-800/30">
                          <td className="py-2.5 font-bold text-white">{p.username}</td>
                          <td className="py-2.5">
                            <span className={`px-1.5 py-0.5 rounded text-[10px] ${
                              p.role === 'Admin' ? 'bg-purple-900/60 text-purple-300' :
                              p.role === 'Developer' ? 'bg-blue-900/60 text-blue-300' : 'bg-emerald-900/60 text-emerald-300'
                            }`}>
                              {p.role}
                            </span>
                          </td>
                          <td className="py-2.5 text-slate-300">{p.baseRiskScore}%</td>
                          <td className="py-2.5 text-slate-300">{p.totalRequests}</td>
                          <td className="py-2.5">
                            <span className="text-emerald-400">{p.allowed}</span>
                            <span className="text-slate-500"> / </span>
                            <span className={p.blocked > 0 ? 'text-rose-400 font-bold' : 'text-slate-400'}>{p.blocked}</span>
                          </td>
                          <td className="py-2.5 text-slate-300">{p.maxRiskObserved}%</td>
                          <td className="py-2.5 text-right">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              p.complianceStatus === 'QUARANTINED' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' :
                              p.complianceStatus === 'ANOMALY_FLAGGED' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' :
                              'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                            }`}>
                              {p.complianceStatus}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: PRINTABLE COMPLIANCE AUDIT DOCUMENT */}
          {activeTab === 'printable' && (
            <div id="printable-compliance-document" className="bg-white text-slate-900 p-6 sm:p-8 rounded-xl shadow-lg font-sans">
              {/* Document Header */}
              <div className="border-b-2 border-slate-900 pb-4 mb-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                  <div className="text-xs uppercase tracking-widest text-slate-500 font-bold">
                    Official Compliance Audit Record
                  </div>
                  <h1 className="text-xl sm:text-2xl font-extrabold text-slate-900">
                    Zero-Trust Security Verification Report
                  </h1>
                  <p className="text-xs text-slate-600 mt-0.5 font-mono">
                    Framework: {reportData.reportMetadata.framework} v{reportData.reportMetadata.version}
                  </p>
                </div>
                <div className="text-right font-mono text-xs text-slate-600">
                  <div><strong>Report ID:</strong> {reportData.reportMetadata.reportId}</div>
                  <div><strong>Date:</strong> {new Date(reportData.reportMetadata.generatedAt).toLocaleDateString()}</div>
                  <div><strong>Time:</strong> {new Date(reportData.reportMetadata.generatedAt).toLocaleTimeString()}</div>
                  <div className="text-[11px] text-slate-500"><strong>Checksum:</strong> {reportData.reportMetadata.integrityChecksum}</div>
                </div>
              </div>

              {/* Executive Verdict Callout */}
              <div className={`p-4 rounded-lg border mb-6 ${
                reportData.executiveSummary.defconLevel === 1 ? 'bg-rose-50 border-rose-300 text-rose-900' :
                reportData.executiveSummary.defconLevel <= 3 ? 'bg-amber-50 border-amber-300 text-amber-900' :
                'bg-emerald-50 border-emerald-300 text-emerald-900'
              }`}>
                <div className="font-bold text-sm uppercase flex items-center justify-between">
                  <span>Compliance Verdict: {reportData.executiveSummary.complianceStatus}</span>
                  <span className="font-mono text-xs">DEFCON {reportData.executiveSummary.defconLevel}</span>
                </div>
                <p className="text-xs mt-1 leading-relaxed">
                  {reportData.executiveSummary.summaryNarrative}
                </p>
              </div>

              {/* Printable Metric Summary */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 p-4 bg-slate-50 rounded-lg border border-slate-200 mb-6 font-mono text-xs">
                <div>
                  <div className="text-slate-500 uppercase text-[10px]">Total Evaluations</div>
                  <div className="text-lg font-bold text-slate-900">{reportData.auditLogStatistics.totalAuditLogs}</div>
                </div>
                <div>
                  <div className="text-slate-500 uppercase text-[10px]">Mean System Threat</div>
                  <div className="text-lg font-bold text-slate-900">{reportData.riskMetrics.meanThreatLevel}%</div>
                </div>
                <div>
                  <div className="text-slate-500 uppercase text-[10px]">Intercept Block Rate</div>
                  <div className="text-lg font-bold text-rose-600">{reportData.auditLogStatistics.blockRatePercentage}%</div>
                </div>
                <div>
                  <div className="text-slate-500 uppercase text-[10px]">Cutoff Threshold</div>
                  <div className="text-lg font-bold text-blue-600">{reportData.systemHealthTelemetry.policyConfig.maxRiskThreshold}%</div>
                </div>
              </div>

              {/* Compliance Standards Checklist */}
              <div className="mb-6">
                <h3 className="text-xs uppercase font-bold tracking-wider text-slate-700 border-b border-slate-200 pb-1 mb-2">
                  Compliance Framework Attestations
                </h3>
                <ul className="text-xs space-y-1.5 text-slate-700">
                  {reportData.reportMetadata.complianceStandards.map((std, idx) => (
                    <li key={idx} className="flex items-start gap-2">
                      <span className="text-emerald-600 font-bold">✔</span>
                      <span>{std}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Principals Table */}
              <div className="mb-6">
                <h3 className="text-xs uppercase font-bold tracking-wider text-slate-700 border-b border-slate-200 pb-1 mb-2">
                  Identity Clearance Ledger
                </h3>
                <table className="w-full text-left text-xs font-mono">
                  <thead>
                    <tr className="border-b border-slate-300 text-slate-600 text-[10px] uppercase">
                      <th className="py-1">Principal</th>
                      <th className="py-1">Role</th>
                      <th className="py-1">Base Risk</th>
                      <th className="py-1">Evaluations</th>
                      <th className="py-1">Blocked</th>
                      <th className="py-1 text-right">Clearance</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200">
                    {reportData.principalsRoster.map((p) => (
                      <tr key={p.username}>
                        <td className="py-1.5 font-bold">{p.username}</td>
                        <td className="py-1.5">{p.role}</td>
                        <td className="py-1.5">{p.baseRiskScore}%</td>
                        <td className="py-1.5">{p.totalRequests}</td>
                        <td className="py-1.5 text-rose-600 font-bold">{p.blocked}</td>
                        <td className="py-1.5 text-right font-bold text-slate-700">{p.complianceStatus}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Signatures & Auditor Sign-off Block */}
              <div className="border-t-2 border-slate-900 pt-4 mt-8 grid grid-cols-2 gap-6 text-xs font-mono">
                <div>
                  <div className="text-slate-500 uppercase text-[10px]">Auditing Official:</div>
                  <div className="font-bold text-slate-900 mt-1">{reportData.reportMetadata.generatedBy.username} ({reportData.reportMetadata.generatedBy.role})</div>
                  <div className="text-slate-400 text-[10px] mt-4 border-b border-slate-300 pb-1">Authorized Compliance Signature</div>
                </div>
                <div className="text-right">
                  <div className="text-slate-500 uppercase text-[10px]">Verification Seal:</div>
                  <div className="text-slate-900 font-bold mt-1">NIST SP 800-207 CERTIFIED</div>
                  <div className="text-slate-400 text-[10px] mt-4 border-b border-slate-300 pb-1">{reportData.reportMetadata.integrityChecksum}</div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: JSON PREVIEW & EXPORT */}
          {activeTab === 'json' && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs text-slate-400">
                  Complete hierarchical security report JSON payload with all metrics &amp; logs.
                </span>
                <button
                  type="button"
                  onClick={() => handleCopy('json')}
                  className="flex items-center gap-1.5 px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 border border-slate-700 transition-colors"
                >
                  {copiedFormat === 'json' ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      <span>Copied JSON!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Copy JSON Payload</span>
                    </>
                  )}
                </button>
              </div>
              <pre className="bg-[#070c14] border border-[#1e2e4a] p-4 rounded-xl text-xs text-emerald-300 overflow-x-auto max-h-[60vh] font-mono leading-relaxed">
                {jsonString}
              </pre>
            </div>
          )}

          {/* TAB 4: CSV PREVIEW & EXPORT */}
          {activeTab === 'csv' && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs text-slate-400">
                  Tabular RFC-4180 audit spreadsheet ready for compliance import into Excel, Google Sheets, or SIEM.
                </span>
                <button
                  type="button"
                  onClick={() => handleCopy('csv')}
                  className="flex items-center gap-1.5 px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 border border-slate-700 transition-colors"
                >
                  {copiedFormat === 'csv' ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      <span>Copied CSV!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Copy CSV Content</span>
                    </>
                  )}
                </button>
              </div>
              <pre className="bg-[#070c14] border border-[#1e2e4a] p-4 rounded-xl text-xs text-blue-300 overflow-x-auto max-h-[60vh] font-mono whitespace-pre-wrap leading-relaxed">
                {csvString}
              </pre>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-3 sm:p-4 border-t border-[#1e2e4a] bg-[#0d1627] flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
          <div className="text-slate-400 flex items-center gap-2 text-[11px]">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span>RFC-7519 &amp; ISO/IEC 27001 Cryptographic Ledger Verified</span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleDownloadJSON}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold bg-blue-600 hover:bg-blue-500 text-white transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Save JSON</span>
            </button>
            <button
              onClick={handleDownloadCSV}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold bg-emerald-600 hover:bg-emerald-500 text-white transition-colors"
            >
              <FileSpreadsheet className="w-3.5 h-3.5" />
              <span>Save CSV</span>
            </button>
            <button
              onClick={onClose}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
