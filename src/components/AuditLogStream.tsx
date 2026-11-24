import React, { useState, useMemo } from 'react';
import {
  Shield,
  Search,
  Filter,
  RefreshCw,
  AlertOctagon,
  CheckCircle,
  Flame,
  Activity,
  Download,
  FileJson,
  Check,
  X,
  SlidersHorizontal,
  ChevronDown,
  AlertTriangle,
  Layers,
  UserCheck,
  Clock,
  Eye
} from 'lucide-react';
import { SecurityAuditLog } from '../types.ts';
import { useTheme } from '../context/ThemeContext.tsx';
import { InteractiveSecurityTimeline } from './InteractiveSecurityTimeline.tsx';

interface AuditLogStreamProps {
  logs: SecurityAuditLog[];
  onRefresh: () => void;
  isRefreshing: boolean;
}

export type RiskSeverityFilter = 'ALL' | 'CRITICAL' | 'ELEVATED' | 'MODERATE' | 'LOW';

export const AuditLogStream: React.FC<AuditLogStreamProps> = ({
  logs,
  onRefresh,
  isRefreshing
}) => {
  const { isLight } = useTheme();
  const [streamViewMode, setStreamViewMode] = useState<'split' | 'timeline' | 'table'>('split');
  const [selectedTimelineLogId, setSelectedTimelineLogId] = useState<number | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterVerdict, setFilterVerdict] = useState<'ALL' | 'ALLOWED' | 'BLOCKED'>('ALL');
  const [filterSeverity, setFilterSeverity] = useState<RiskSeverityFilter>('ALL');
  const [filterFunction, setFilterFunction] = useState<string>('ALL');
  const [filterPrincipal, setFilterPrincipal] = useState<string>('ALL');
  const [minRiskThreshold, setMinRiskThreshold] = useState<number>(0);
  const [downloadSuccess, setDownloadSuccess] = useState(false);
  const [downloadJsonSuccess, setDownloadJsonSuccess] = useState(false);
  const [showAdvancedFilters, setShowAdvancedFilters] = useState(false);

  // Extract unique function paths and principals for dynamic dropdowns
  const uniqueFunctions = useMemo(() => {
    const set = new Set<string>();
    logs.forEach((l) => set.add(l.requested_function));
    return Array.from(set).sort();
  }, [logs]);

  const uniquePrincipals = useMemo(() => {
    const set = new Set<string>();
    logs.forEach((l) => set.add(l.username));
    return Array.from(set).sort();
  }, [logs]);

  // Visual Risk Breakdown calculations
  const riskSpectrum = useMemo(() => {
    let low = 0; // < 25
    let moderate = 0; // 25-49
    let elevated = 0; // 50-74
    let critical = 0; // >= 75

    logs.forEach((l) => {
      if (l.calculated_risk >= 75) critical++;
      else if (l.calculated_risk >= 50) elevated++;
      else if (l.calculated_risk >= 25) moderate++;
      else low++;
    });

    const total = logs.length || 1;
    return {
      low: { count: low, pct: Math.round((low / total) * 100) },
      moderate: { count: moderate, pct: Math.round((moderate / total) * 100) },
      elevated: { count: elevated, pct: Math.round((elevated / total) * 100) },
      critical: { count: critical, pct: Math.round((critical / total) * 100) }
    };
  }, [logs]);

  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      // 1. Verdict filter
      if (filterVerdict !== 'ALL' && log.status !== filterVerdict) return false;

      // 2. Risk Severity tier filter
      if (filterSeverity === 'CRITICAL' && log.calculated_risk < 75) return false;
      if (filterSeverity === 'ELEVATED' && (log.calculated_risk < 50 || log.calculated_risk >= 75)) return false;
      if (filterSeverity === 'MODERATE' && (log.calculated_risk < 25 || log.calculated_risk >= 50)) return false;
      if (filterSeverity === 'LOW' && log.calculated_risk >= 25) return false;

      // 3. Minimum Risk Slider
      if (minRiskThreshold > 0 && log.calculated_risk < minRiskThreshold) return false;

      // 4. Function Path filter
      if (filterFunction !== 'ALL' && log.requested_function !== filterFunction) return false;

      // 5. Principal filter
      if (filterPrincipal !== 'ALL' && log.username !== filterPrincipal) return false;

      // 6. Text search query
      const q = searchQuery.toLowerCase().trim();
      if (q) {
        const matchesUsername = log.username.toLowerCase().includes(q);
        const matchesFunction = log.requested_function.toLowerCase().includes(q);
        const matchesReason = log.reason.toLowerCase().includes(q);
        const matchesStatus = log.status.toLowerCase().includes(q);
        const matchesRisk = log.calculated_risk.toString().includes(q);
        if (!matchesUsername && !matchesFunction && !matchesReason && !matchesStatus && !matchesRisk) {
          return false;
        }
      }

      return true;
    });
  }, [logs, filterVerdict, filterSeverity, minRiskThreshold, filterFunction, filterPrincipal, searchQuery]);

  const stats = useMemo(() => {
    const total = logs.length;
    const blocked = logs.filter((l) => l.status === 'BLOCKED').length;
    const allowed = logs.filter((l) => l.status === 'ALLOWED').length;
    const avgRisk = total > 0 ? Math.round(logs.reduce((acc, curr) => acc + curr.calculated_risk, 0) / total) : 0;
    const criticalCount = logs.filter((l) => l.calculated_risk >= 75).length;
    return { total, blocked, allowed, avgRisk, criticalCount };
  }, [logs]);

  const hasActiveFilters =
    searchQuery.trim() !== '' ||
    filterVerdict !== 'ALL' ||
    filterSeverity !== 'ALL' ||
    filterFunction !== 'ALL' ||
    filterPrincipal !== 'ALL' ||
    minRiskThreshold > 0;

  const handleResetFilters = () => {
    setSearchQuery('');
    setFilterVerdict('ALL');
    setFilterSeverity('ALL');
    setFilterFunction('ALL');
    setFilterPrincipal('ALL');
    setMinRiskThreshold(0);
  };

  const handleDownloadCSV = () => {
    if (filteredLogs.length === 0) return;

    const escapeCsv = (val: string | number | undefined | null) => {
      const str = String(val ?? '');
      if (str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r')) {
        return `"${str.replace(/"/g, '""')}"`;
      }
      return str;
    };

    const headers = [
      'Log ID',
      'Timestamp (ISO)',
      'Local Time',
      'Principal (Username)',
      'Requested Function Path',
      'Calculated Risk (%)',
      'Verdict',
      'Mitigation Heuristics / Reason'
    ];

    const rows = filteredLogs.map((log) => [
      escapeCsv(log.id),
      escapeCsv(log.timestamp),
      escapeCsv(new Date(log.timestamp).toLocaleString()),
      escapeCsv(log.username),
      escapeCsv(log.requested_function),
      escapeCsv(log.calculated_risk),
      escapeCsv(log.status),
      escapeCsv(log.reason)
    ]);

    const csvContent = [headers.join(','), ...rows.map((row) => row.join(','))].join('\r\n');

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;

    const dateStr = new Date().toISOString().slice(0, 10);
    const filterTag = filterVerdict !== 'ALL' ? `_${filterVerdict.toLowerCase()}` : '';
    link.setAttribute('download', `security_audit_logs${filterTag}_${dateStr}.csv`);

    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    setDownloadSuccess(true);
    setTimeout(() => setDownloadSuccess(false), 2200);
  };

  const handleDownloadJSON = () => {
    if (filteredLogs.length === 0) return;

    const payload = {
      exportMetadata: {
        title: 'Serverless Security Verification Framework - Cryptographic Audit Ledger Export',
        exportedAt: new Date().toISOString(),
        totalLogsInDataset: logs.length,
        filteredLogsCount: filteredLogs.length,
        activeFilters: {
          verdict: filterVerdict,
          severity: filterSeverity,
          functionPath: filterFunction,
          principal: filterPrincipal,
          minRiskThreshold,
          searchQuery: searchQuery.trim() || null
        },
        statistics: {
          allowed: filteredLogs.filter((l) => l.status === 'ALLOWED').length,
          blocked: filteredLogs.filter((l) => l.status === 'BLOCKED').length,
          averageRiskScore: filteredLogs.length > 0
            ? Math.round(filteredLogs.reduce((acc, curr) => acc + curr.calculated_risk, 0) / filteredLogs.length)
            : 0,
          criticalCount: filteredLogs.filter((l) => l.calculated_risk >= 75).length
        }
      },
      auditLogs: filteredLogs.map((log) => ({
        id: log.id,
        timestamp: log.timestamp,
        localTime: new Date(log.timestamp).toLocaleString(),
        principal: log.username,
        requestedFunction: log.requested_function,
        calculatedRisk: log.calculated_risk,
        status: log.status,
        verdict: log.status,
        reason: log.reason,
        verificationLatencyMs: log.verification_latency_ms ?? 0.28,
        eventType: log.event_type || 'STANDARD_VERIFICATION'
      }))
    };

    const jsonString = JSON.stringify(payload, null, 2);
    const blob = new Blob([jsonString], { type: 'application/json;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;

    const dateStr = new Date().toISOString().slice(0, 10);
    const filterTag = filterVerdict !== 'ALL' ? `_${filterVerdict.toLowerCase()}` : '';
    link.setAttribute('download', `security_audit_logs${filterTag}_${dateStr}.json`);

    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    setDownloadJsonSuccess(true);
    setTimeout(() => setDownloadJsonSuccess(false), 2200);
  };

  return (
    <div className={`border p-4 sm:p-5 rounded-2xl flex flex-col h-full font-mono shadow-sm ${
      isLight ? 'bg-white border-slate-200 text-slate-900' : 'bg-[#0f172a] border-slate-800 text-slate-100'
    }`}>
      {/* 1. Header and Primary Actions */}
      <div className={`border-b pb-3 mb-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
        isLight ? 'border-slate-200' : 'border-slate-800'
      }`}>
        <div>
          <h3 className={`text-sm font-bold uppercase tracking-wider flex items-center gap-2 ${
            isLight ? 'text-slate-900' : 'text-white'
          }`}>
            <Shield className={`w-4 h-4 ${isLight ? 'text-emerald-600' : 'text-[#00ff87]'}`} />
            Real-Time Framework Audit Streams &amp; Risk Visualizer
          </h3>
          <p className={`text-[11px] mt-0.5 ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
            Cryptographic ledger tracking identity tokens, Markov sequences &amp; dynamic risk scoring
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {/* Timeline / Ledger Mode Toggle */}
          <div className={`flex items-center rounded-lg p-0.5 border text-xs ${
            isLight ? 'border-slate-200 bg-slate-100' : 'border-slate-800 bg-[#090d16]'
          }`}>
            <button
              type="button"
              onClick={() => setStreamViewMode('split')}
              className={`px-2.5 py-1 rounded transition-colors flex items-center gap-1.5 ${
                streamViewMode === 'split'
                  ? (isLight ? 'bg-sky-600 text-white font-bold shadow-xs' : 'bg-[#00d2ff] text-black font-bold shadow-xs')
                  : (isLight ? 'text-slate-600 hover:text-slate-900' : 'text-slate-400 hover:text-white')
              }`}
              title="Show both interactive timeline and detailed forensic ledger"
            >
              <Layers className="w-3.5 h-3.5" />
              <span>Split View</span>
            </button>
            <button
              type="button"
              onClick={() => setStreamViewMode('timeline')}
              className={`px-2.5 py-1 rounded transition-colors flex items-center gap-1.5 ${
                streamViewMode === 'timeline'
                  ? (isLight ? 'bg-sky-600 text-white font-bold shadow-xs' : 'bg-[#00d2ff] text-black font-bold shadow-xs')
                  : (isLight ? 'text-slate-600 hover:text-slate-900' : 'text-slate-400 hover:text-white')
              }`}
              title="Interactive Timeline focused view for attack pattern visualization"
            >
              <Clock className="w-3.5 h-3.5" />
              <span>Attack Timeline</span>
            </button>
            <button
              type="button"
              onClick={() => setStreamViewMode('table')}
              className={`px-2.5 py-1 rounded transition-colors flex items-center gap-1.5 ${
                streamViewMode === 'table'
                  ? (isLight ? 'bg-sky-600 text-white font-bold shadow-xs' : 'bg-[#00d2ff] text-black font-bold shadow-xs')
                  : (isLight ? 'text-slate-600 hover:text-slate-900' : 'text-slate-400 hover:text-white')
              }`}
              title="Detailed cryptographic forensic ledger table view"
            >
              <Shield className="w-3.5 h-3.5" />
              <span>Forensic Ledger</span>
            </button>
          </div>

          <button
            id="btn-download-csv"
            onClick={handleDownloadCSV}
            disabled={filteredLogs.length === 0}
            className={`px-2.5 py-1.5 rounded-lg border text-xs flex items-center gap-1.5 transition-colors disabled:opacity-40 disabled:cursor-not-allowed tabular-nums ${
              downloadSuccess
                ? (isLight ? 'bg-emerald-50 text-emerald-700 border-emerald-300' : 'bg-[#090d16] text-[#00ff87] border-[#00ff87]/50')
                : (isLight ? 'bg-slate-50 hover:bg-slate-100 border-slate-200 text-slate-700 hover:text-emerald-700' : 'bg-[#090d16] hover:bg-slate-800 border-slate-800 text-slate-300 hover:text-[#00ff87]')
            }`}
            title={
              filteredLogs.length > 0
                ? `Export ${filteredLogs.length} currently filtered logs to CSV`
                : 'No logs currently match filters to download'
            }
          >
            {downloadSuccess ? (
              <>
                <Check className={`w-3.5 h-3.5 ${isLight ? 'text-emerald-600' : 'text-[#00ff87]'}`} />
                <span className={isLight ? 'text-emerald-700' : 'text-[#00ff87]'}>Downloaded!</span>
              </>
            ) : (
              <>
                <Download className={`w-3.5 h-3.5 ${isLight ? 'text-emerald-600' : 'text-[#00ff87]'}`} />
                <span>Export CSV ({filteredLogs.length})</span>
              </>
            )}
          </button>

          <button
            id="btn-download-json"
            onClick={handleDownloadJSON}
            disabled={filteredLogs.length === 0}
            className={`px-2.5 py-1.5 rounded-lg border text-xs flex items-center gap-1.5 transition-colors disabled:opacity-40 disabled:cursor-not-allowed tabular-nums ${
              downloadJsonSuccess
                ? (isLight ? 'bg-emerald-50 text-emerald-700 border-emerald-300' : 'bg-[#090d16] text-[#00ff87] border-[#00ff87]/50')
                : (isLight ? 'bg-slate-50 hover:bg-slate-100 border-slate-200 text-slate-700 hover:text-sky-700' : 'bg-[#090d16] hover:bg-slate-800 border-slate-800 text-slate-300 hover:text-[#00d2ff]')
            }`}
            title={
              filteredLogs.length > 0
                ? `Export ${filteredLogs.length} currently filtered logs as a structured JSON file`
                : 'No logs currently match filters to download'
            }
          >
            {downloadJsonSuccess ? (
              <>
                <Check className={`w-3.5 h-3.5 ${isLight ? 'text-emerald-600' : 'text-[#00ff87]'}`} />
                <span className={isLight ? 'text-emerald-700' : 'text-[#00ff87]'}>JSON Downloaded!</span>
              </>
            ) : (
              <>
                <FileJson className={`w-3.5 h-3.5 ${isLight ? 'text-sky-600' : 'text-[#00d2ff]'}`} />
                <span>Export JSON ({filteredLogs.length})</span>
              </>
            )}
          </button>

          <button
            id="btn-refresh-logs"
            onClick={onRefresh}
            disabled={isRefreshing}
            className={`px-2.5 py-1.5 rounded-lg border text-xs flex items-center gap-1 transition-colors disabled:opacity-50 ${
              isLight
                ? 'bg-slate-50 hover:bg-slate-100 text-slate-700 border-slate-200'
                : 'bg-[#090d16] hover:bg-slate-800 text-slate-300 hover:text-white border-slate-800'
            }`}
            title="Refresh logs from database"
          >
            <RefreshCw className={`w-3 h-3 ${isLight ? 'text-sky-600' : 'text-[#00d2ff]'} ${isRefreshing ? 'animate-spin' : ''}`} />
            <span>Sync</span>
          </button>
        </div>
      </div>

      {/* Interactive Timeline Component for Attack Pattern Detection */}
      {(streamViewMode === 'split' || streamViewMode === 'timeline') && (
        <div className="mb-4">
          <InteractiveSecurityTimeline
            logs={logs}
            selectedLogId={selectedTimelineLogId}
            onSelectLog={(selectedLog) => {
              setSelectedTimelineLogId(selectedLog.id);
            }}
          />
        </div>
      )}

      {/* 2. Forensic Ledger Table & Metrics (Rendered in Split & Table Modes) */}
      {(streamViewMode === 'split' || streamViewMode === 'table') && (
        <>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 mb-4 tabular-nums">
        <div className={`border p-2.5 rounded-xl ${isLight ? 'bg-slate-50 border-slate-200' : 'bg-[#090d16] border-slate-800'}`}>
          <div className={`text-[10px] uppercase flex items-center justify-between ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
            <span>Total Streams</span>
            <Activity className={`w-3 h-3 ${isLight ? 'text-sky-600' : 'text-[#00d2ff]'}`} />
          </div>
          <div className={`text-lg font-bold mt-1 ${isLight ? 'text-slate-900' : 'text-white'}`}>{stats.total}</div>
          <div className="text-[10px] text-slate-500 mt-0.5">
            {filteredLogs.length} in current view
          </div>
        </div>

        <div className={`border p-2.5 rounded-xl ${isLight ? 'bg-slate-50 border-slate-200' : 'bg-[#090d16] border-slate-800'}`}>
          <div className={`text-[10px] uppercase flex items-center justify-between ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
            <span>Allowed</span>
            <CheckCircle className={`w-3 h-3 ${isLight ? 'text-emerald-600' : 'text-[#00ff87]'}`} />
          </div>
          <div className={`text-lg font-bold mt-1 ${isLight ? 'text-emerald-700' : 'text-[#00ff87]'}`}>{stats.allowed}</div>
          <div className={`text-[10px] mt-0.5 ${isLight ? 'text-emerald-700' : 'text-emerald-400/80'}`}>
            {stats.total > 0 ? Math.round((stats.allowed / stats.total) * 100) : 100}% Pass Rate
          </div>
        </div>

        <div className={`border p-2.5 rounded-xl ${isLight ? 'bg-slate-50 border-slate-200' : 'bg-[#090d16] border-slate-800'}`}>
          <div className={`text-[10px] uppercase flex items-center justify-between ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
            <span>Intercepted</span>
            <AlertOctagon className={`w-3 h-3 ${isLight ? 'text-rose-600' : 'text-[#ff4a6b]'}`} />
          </div>
          <div className={`text-lg font-bold mt-1 ${isLight ? 'text-rose-700' : 'text-[#ff4a6b]'}`}>{stats.blocked}</div>
          <div className={`text-[10px] mt-0.5 ${isLight ? 'text-rose-700' : 'text-rose-400/80'}`}>
            {stats.criticalCount} Critical (≥75%)
          </div>
        </div>

        <div className={`border p-2.5 rounded-xl ${isLight ? 'bg-slate-50 border-slate-200' : 'bg-[#090d16] border-slate-800'}`}>
          <div className={`text-[10px] uppercase flex items-center justify-between ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
            <span>Avg Risk Score</span>
            <Flame className={`w-3 h-3 ${isLight ? 'text-amber-600' : 'text-amber-400'}`} />
          </div>
          <div className={`text-lg font-bold mt-1 ${isLight ? 'text-amber-700' : 'text-amber-400'}`}>{stats.avgRisk}%</div>
          {/* Mini Gradient Progress Bar */}
          <div className={`w-full h-1.5 rounded-full overflow-hidden mt-1.5 border ${isLight ? 'bg-slate-200 border-slate-300' : 'bg-slate-900 border-slate-800'}`}>
            <div
              className={`h-full transition-all duration-300 ${
                stats.avgRisk >= 75 ? 'bg-rose-500' : stats.avgRisk >= 50 ? 'bg-amber-400' : stats.avgRisk >= 25 ? 'bg-sky-500' : 'bg-emerald-500'
              }`}
              style={{ width: `${Math.min(stats.avgRisk, 100)}%` }}
            />
          </div>
        </div>
      </div>

      {/* 3. INTERACTIVE RISK SPECTRUM VISUALIZER (CLICK TO FILTER) */}
      <div className={`border rounded-xl p-3 mb-3 ${isLight ? 'bg-slate-50 border-slate-200' : 'bg-[#090d16] border-slate-800'}`}>
        <div className="flex items-center justify-between text-[11px] mb-2">
          <span className={`font-semibold flex items-center gap-1.5 ${isLight ? 'text-slate-700' : 'text-slate-400'}`}>
            <SlidersHorizontal className={`w-3 h-3 ${isLight ? 'text-sky-600' : 'text-[#00d2ff]'}`} />
            Risk Spectrum Distribution (Click Tier to Filter)
          </span>
          <span className="text-[10px] text-slate-500 tabular-nums">
            {logs.length} Total Events Evaluated
          </span>
        </div>

        {/* Segmented Gradient Distribution Bar */}
        <div className={`h-3 w-full rounded-md overflow-hidden flex border cursor-pointer ${isLight ? 'bg-slate-200 border-slate-300' : 'bg-slate-900 border-slate-800'}`}>
          {riskSpectrum.low.count > 0 && (
            <div
              onClick={() => setFilterSeverity(filterSeverity === 'LOW' ? 'ALL' : 'LOW')}
              style={{ width: `${riskSpectrum.low.pct}%` }}
              className={`h-full bg-emerald-500 hover:brightness-110 transition-all ${
                filterSeverity === 'LOW' ? 'ring-2 ring-white ring-inset' : ''
              }`}
              title={`Nominal Low Risk (<25%): ${riskSpectrum.low.count} events (${riskSpectrum.low.pct}%)`}
            />
          )}
          {riskSpectrum.moderate.count > 0 && (
            <div
              onClick={() => setFilterSeverity(filterSeverity === 'MODERATE' ? 'ALL' : 'MODERATE')}
              style={{ width: `${riskSpectrum.moderate.pct}%` }}
              className={`h-full bg-sky-500 hover:brightness-110 transition-all ${
                filterSeverity === 'MODERATE' ? 'ring-2 ring-white ring-inset' : ''
              }`}
              title={`Moderate Risk (25-49%): ${riskSpectrum.moderate.count} events (${riskSpectrum.moderate.pct}%)`}
            />
          )}
          {riskSpectrum.elevated.count > 0 && (
            <div
              onClick={() => setFilterSeverity(filterSeverity === 'ELEVATED' ? 'ALL' : 'ELEVATED')}
              style={{ width: `${riskSpectrum.elevated.pct}%` }}
              className={`h-full bg-amber-400 hover:brightness-110 transition-all ${
                filterSeverity === 'ELEVATED' ? 'ring-2 ring-white ring-inset' : ''
              }`}
              title={`Elevated Risk (50-74%): ${riskSpectrum.elevated.count} events (${riskSpectrum.elevated.pct}%)`}
            />
          )}
          {riskSpectrum.critical.count > 0 && (
            <div
              onClick={() => setFilterSeverity(filterSeverity === 'CRITICAL' ? 'ALL' : 'CRITICAL')}
              style={{ width: `${riskSpectrum.critical.pct}%` }}
              className={`h-full bg-rose-500 hover:brightness-110 transition-all ${
                filterSeverity === 'CRITICAL' ? 'ring-2 ring-white ring-inset' : ''
              }`}
              title={`Critical Risk (≥75%): ${riskSpectrum.critical.count} events (${riskSpectrum.critical.pct}%)`}
            />
          )}
        </div>

        {/* Legend / Interactive Chips */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mt-2.5 text-[10px] tabular-nums">
          <button
            onClick={() => setFilterSeverity(filterSeverity === 'LOW' ? 'ALL' : 'LOW')}
            className={`p-1.5 rounded border flex items-center justify-between transition-all ${
              filterSeverity === 'LOW'
                ? (isLight ? 'bg-emerald-100 border-emerald-500 text-emerald-900 ring-1 ring-emerald-500' : 'bg-emerald-500/20 border-emerald-400 text-emerald-300 ring-1 ring-emerald-400')
                : (isLight ? 'bg-white border-slate-200 text-slate-700 hover:border-emerald-400' : 'bg-slate-900 border-slate-800 text-slate-400 hover:border-emerald-500/40')
            }`}
          >
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-500" />
              Low (&lt;25%)
            </span>
            <span className={`font-bold ${isLight ? 'text-slate-900' : 'text-white'}`}>{riskSpectrum.low.count}</span>
          </button>

          <button
            onClick={() => setFilterSeverity(filterSeverity === 'MODERATE' ? 'ALL' : 'MODERATE')}
            className={`p-1.5 rounded border flex items-center justify-between transition-all ${
              filterSeverity === 'MODERATE'
                ? (isLight ? 'bg-sky-100 border-sky-500 text-sky-900 ring-1 ring-sky-500' : 'bg-cyan-500/20 border-cyan-400 text-cyan-300 ring-1 ring-cyan-400')
                : (isLight ? 'bg-white border-slate-200 text-slate-700 hover:border-sky-400' : 'bg-slate-900 border-slate-800 text-slate-400 hover:border-cyan-500/40')
            }`}
          >
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-sky-500" />
              Moderate (25-49%)
            </span>
            <span className={`font-bold ${isLight ? 'text-slate-900' : 'text-white'}`}>{riskSpectrum.moderate.count}</span>
          </button>

          <button
            onClick={() => setFilterSeverity(filterSeverity === 'ELEVATED' ? 'ALL' : 'ELEVATED')}
            className={`p-1.5 rounded border flex items-center justify-between transition-all ${
              filterSeverity === 'ELEVATED'
                ? (isLight ? 'bg-amber-100 border-amber-500 text-amber-900 ring-1 ring-amber-500' : 'bg-amber-500/20 border-amber-400 text-amber-300 ring-1 ring-amber-400')
                : (isLight ? 'bg-white border-slate-200 text-slate-700 hover:border-amber-400' : 'bg-slate-900 border-slate-800 text-slate-400 hover:border-amber-500/40')
            }`}
          >
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-amber-400" />
              Elevated (50-74%)
            </span>
            <span className={`font-bold ${isLight ? 'text-slate-900' : 'text-white'}`}>{riskSpectrum.elevated.count}</span>
          </button>

          <button
            onClick={() => setFilterSeverity(filterSeverity === 'CRITICAL' ? 'ALL' : 'CRITICAL')}
            className={`p-1.5 rounded border flex items-center justify-between transition-all ${
              filterSeverity === 'CRITICAL'
                ? (isLight ? 'bg-rose-100 border-rose-500 text-rose-900 ring-1 ring-rose-500' : 'bg-rose-500/20 border-rose-400 text-rose-300 ring-1 ring-rose-400')
                : (isLight ? 'bg-white border-slate-200 text-slate-700 hover:border-rose-400' : 'bg-slate-900 border-slate-800 text-slate-400 hover:border-rose-500/40')
            }`}
          >
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-rose-500" />
              Critical (≥75%)
            </span>
            <span className={`font-bold ${isLight ? 'text-slate-900' : 'text-white'}`}>{riskSpectrum.critical.count}</span>
          </button>
        </div>
      </div>

      {/* 4. Filter & Search Controls Bar */}
      <div className="space-y-2 mb-3">
        <div className="flex flex-col sm:flex-row gap-2">
          {/* Text Search Field */}
          <div className="relative flex-1">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search principal, function route, risk score or heuristic reason..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className={`w-full pl-8 pr-8 py-1.5 border text-xs rounded-lg focus:outline-none ${
                isLight
                  ? 'bg-white border-slate-300 text-slate-900 focus:border-sky-600'
                  : 'bg-[#090d16] border-slate-800 text-white focus:border-[#00d2ff]'
              }`}
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className={`absolute right-2.5 top-2.5 ${isLight ? 'text-slate-400 hover:text-slate-800' : 'text-slate-500 hover:text-white'}`}
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          {/* Verdict Filter Buttons */}
          <div className="flex items-center gap-1 text-xs">
            <span className="text-[10px] text-slate-500 uppercase mr-1 hidden md:inline">Verdict:</span>
            {(['ALL', 'ALLOWED', 'BLOCKED'] as const).map((v) => (
              <button
                key={v}
                onClick={() => setFilterVerdict(v)}
                className={`px-2.5 py-1 rounded-lg text-[11px] font-bold border transition-colors ${
                  filterVerdict === v
                    ? v === 'ALLOWED'
                      ? (isLight ? 'bg-emerald-100 border-emerald-500 text-emerald-800' : 'bg-[#00ff87]/20 border-[#00ff87] text-[#00ff87]')
                      : v === 'BLOCKED'
                      ? (isLight ? 'bg-rose-100 border-rose-500 text-rose-800' : 'bg-[#ff4a6b]/20 border-[#ff4a6b] text-[#ff4a6b]')
                      : (isLight ? 'bg-sky-100 border-sky-500 text-sky-800' : 'bg-[#00d2ff]/20 border-[#00d2ff] text-[#00d2ff]')
                    : (isLight ? 'bg-white border-slate-200 text-slate-700 hover:border-slate-300' : 'bg-[#090d16] border-slate-800 text-slate-400 hover:border-slate-600')
                }`}
              >
                {v}
              </button>
            ))}

            {/* Toggle Advanced Filters */}
            <button
              onClick={() => setShowAdvancedFilters(!showAdvancedFilters)}
              className={`px-2.5 py-1 rounded-lg border text-[11px] flex items-center gap-1 transition-colors ${
                showAdvancedFilters || hasActiveFilters
                  ? (isLight ? 'bg-blue-100 border-blue-400 text-blue-800' : 'bg-blue-500/20 border-blue-500 text-blue-300')
                  : (isLight ? 'bg-white border-slate-200 text-slate-600 hover:text-slate-900' : 'bg-[#090d16] border-slate-800 text-slate-400 hover:text-white')
              }`}
              title="Toggle additional filter dimensions"
            >
              <Filter className="w-3 h-3" />
              <span>Filters</span>
              {hasActiveFilters && (
                <span className="w-1.5 h-1.5 rounded-full bg-blue-500 ml-0.5" />
              )}
            </button>
          </div>
        </div>

        {/* Collapsible Advanced Filtering Row */}
        {showAdvancedFilters && (
          <div className={`p-3 border rounded-xl grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs animate-in fade-in duration-150 ${
            isLight ? 'bg-slate-50 border-slate-200' : 'bg-[#090d16] border-slate-800'
          }`}>
            {/* Function Filter Dropdown */}
            <div>
              <label className="block text-[10px] uppercase text-slate-500 font-semibold mb-1">
                Function Path:
              </label>
              <select
                value={filterFunction}
                onChange={(e) => setFilterFunction(e.target.value)}
                className={`w-full px-2 py-1 border text-xs rounded focus:outline-none ${
                  isLight ? 'bg-white border-slate-300 text-slate-900 focus:border-sky-600' : 'bg-slate-900 border-slate-700 text-white focus:border-[#00d2ff]'
                }`}
              >
                <option value="ALL">All Serverless Endpoints</option>
                {uniqueFunctions.map((fn) => (
                  <option key={fn} value={fn}>
                    {fn}
                  </option>
                ))}
              </select>
            </div>

            {/* Principal Filter Dropdown */}
            <div>
              <label className="block text-[10px] uppercase text-slate-500 font-semibold mb-1">
                Principal Identity:
              </label>
              <select
                value={filterPrincipal}
                onChange={(e) => setFilterPrincipal(e.target.value)}
                className={`w-full px-2 py-1 border text-xs rounded focus:outline-none ${
                  isLight ? 'bg-white border-slate-300 text-slate-900 focus:border-sky-600' : 'bg-slate-900 border-slate-700 text-white focus:border-[#00d2ff]'
                }`}
              >
                <option value="ALL">All Identities</option>
                {uniquePrincipals.map((pr) => (
                  <option key={pr} value={pr}>
                    {pr}
                  </option>
                ))}
              </select>
            </div>

            {/* Min Risk Slider */}
            <div>
              <div className="flex items-center justify-between text-[10px] uppercase text-slate-500 font-semibold mb-1">
                <span>Minimum Risk Filter:</span>
                <span className={`font-bold tabular-nums ${isLight ? 'text-amber-700' : 'text-amber-400'}`}>{minRiskThreshold}%</span>
              </div>
              <input
                type="range"
                min={0}
                max={100}
                step={5}
                value={minRiskThreshold}
                onChange={(e) => setMinRiskThreshold(Number(e.target.value))}
                className={`w-full h-1.5 rounded-lg cursor-pointer ${isLight ? 'accent-sky-600 bg-slate-200' : 'accent-[#00d2ff] bg-slate-800'}`}
              />
            </div>
          </div>
        )}

        {/* Active Filter Indicator Tag Bar */}
        {hasActiveFilters && (
          <div className={`flex items-center justify-between px-3 py-1.5 rounded-lg border text-xs ${
            isLight ? 'bg-slate-50 border-slate-200' : 'bg-[#090d16] border-slate-800'
          }`}>
            <div className="flex items-center gap-1.5 flex-wrap text-[11px]">
              <span className="text-slate-500">Active Filters:</span>
              {searchQuery && (
                <span className={`px-1.5 py-0.5 rounded border ${isLight ? 'bg-blue-50 text-blue-700 border-blue-200' : 'bg-blue-500/15 text-blue-300 border-blue-500/30'}`}>
                  Search: "{searchQuery}"
                </span>
              )}
              {filterVerdict !== 'ALL' && (
                <span className={`px-1.5 py-0.5 rounded border ${isLight ? 'bg-slate-100 text-slate-700 border-slate-300' : 'bg-slate-800 text-slate-300 border-slate-700'}`}>
                  Verdict: {filterVerdict}
                </span>
              )}
              {filterSeverity !== 'ALL' && (
                <span className={`px-1.5 py-0.5 rounded border ${isLight ? 'bg-amber-50 text-amber-800 border-amber-200' : 'bg-amber-500/15 text-amber-300 border-amber-500/30'}`}>
                  Tier: {filterSeverity}
                </span>
              )}
              {filterFunction !== 'ALL' && (
                <span className={`px-1.5 py-0.5 rounded border ${isLight ? 'bg-purple-50 text-purple-800 border-purple-200' : 'bg-purple-500/15 text-purple-300 border-purple-500/30'}`}>
                  Route: {filterFunction}
                </span>
              )}
              {filterPrincipal !== 'ALL' && (
                <span className={`px-1.5 py-0.5 rounded border ${isLight ? 'bg-emerald-50 text-emerald-800 border-emerald-200' : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'}`}>
                  User: {filterPrincipal}
                </span>
              )}
              {minRiskThreshold > 0 && (
                <span className={`px-1.5 py-0.5 rounded border ${isLight ? 'bg-rose-50 text-rose-800 border-rose-200' : 'bg-rose-500/15 text-rose-300 border-rose-500/30'}`}>
                  Risk &ge; {minRiskThreshold}%
                </span>
              )}
            </div>

            <button
              onClick={handleResetFilters}
              className={`text-[11px] hover:underline flex items-center gap-1 shrink-0 ml-2 ${isLight ? 'text-sky-700' : 'text-[#00d2ff]'}`}
            >
              <X className="w-3 h-3" />
              Reset All
            </button>
          </div>
        )}
      </div>

      {/* 5. Enhanced Table Container with Visual Risk Meters */}
      <div className={`overflow-x-auto flex-1 max-h-[540px] rounded-xl border ${isLight ? 'border-slate-200' : 'border-slate-800'}`}>
        <table className="w-full border-collapse text-left text-xs">
          <thead className={`sticky top-0 z-10 ${isLight ? 'bg-slate-50' : 'bg-[#090d16]'}`}>
            <tr className={`border-b uppercase text-[10px] tracking-wider ${
              isLight ? 'border-slate-200 text-slate-600' : 'border-slate-800 text-slate-400'
            }`}>
              <th className="p-3">Time</th>
              <th className="p-3">Principal</th>
              <th className="p-3">Function Path</th>
              <th className="p-3">Risk Visual Score</th>
              <th className="p-3">Latency Overhead</th>
              <th className="p-3">Verdict</th>
              <th className="p-3">Engine Mitigation Heuristics &amp; Behavioral Events</th>
            </tr>
          </thead>
          <tbody id="logs" className={`divide-y ${isLight ? 'divide-slate-200' : 'divide-slate-800'}`}>
            {filteredLogs.length === 0 ? (
              <tr>
                <td colSpan={7} className="text-center text-slate-500 py-12">
                  {logs.length === 0 ? (
                    'No operational triggers executed yet. Fire the pipeline.'
                  ) : (
                    <div className="space-y-1">
                      <p>No audit records match the selected filter criteria.</p>
                      <button
                        onClick={handleResetFilters}
                        className={`text-xs hover:underline ${isLight ? 'text-sky-700' : 'text-[#00d2ff]'}`}
                      >
                        Clear all search filters
                      </button>
                    </div>
                  )}
                </td>
              </tr>
            ) : (
              filteredLogs.map((item) => {
                const isBlocked = item.status === 'BLOCKED';
                const parsedDate = new Date(item.timestamp);
                const isoTimestamp = !isNaN(parsedDate.getTime()) ? parsedDate.toISOString() : (item.timestamp || 'N/A');
                const localFormattedTime = !isNaN(parsedDate.getTime()) ? parsedDate.toLocaleTimeString() : (item.timestamp || 'N/A');
                const risk = item.calculated_risk;

                // Color tier definitions
                const isCritical = risk >= 75;
                const isElevated = risk >= 50 && risk < 75;
                const isModerate = risk >= 25 && risk < 50;

                const riskColor = isCritical
                  ? (isLight ? 'text-rose-700' : 'text-[#ff4a6b]')
                  : isElevated
                  ? (isLight ? 'text-amber-800' : 'text-amber-400')
                  : isModerate
                  ? (isLight ? 'text-sky-700' : 'text-[#00d2ff]')
                  : (isLight ? 'text-emerald-700' : 'text-[#00ff87]');

                const riskBgColor = isCritical
                  ? 'bg-rose-500'
                  : isElevated
                  ? 'bg-amber-400'
                  : isModerate
                  ? 'bg-sky-500'
                  : 'bg-emerald-500';

                const riskTierLabel = isCritical
                  ? 'CRITICAL'
                  : isElevated
                  ? 'ELEVATED'
                  : isModerate
                  ? 'MODERATE'
                  : 'NOMINAL';

                const isSelectedInTimeline = selectedTimelineLogId === item.id;

                return (
                  <tr
                    key={item.id}
                    id={`log-row-${item.id}`}
                    onClick={() => setSelectedTimelineLogId(item.id)}
                    className={`transition-colors cursor-pointer group ${
                      isSelectedInTimeline
                        ? (isLight ? 'bg-sky-50 ring-1 ring-sky-500' : 'bg-cyan-500/20 ring-1 ring-cyan-400')
                        : (isLight ? 'hover:bg-slate-50' : 'hover:bg-slate-800/40')
                    }`}
                  >
                    <td className="p-3 whitespace-nowrap">
                      <div className="flex flex-col gap-0.5 tabular-nums">
                        <div
                          className={`font-mono text-xs flex items-center gap-1.5 ${isLight ? 'text-sky-800' : 'text-cyan-200'}`}
                          title={`High-Precision ISO 8601 (UTC): ${isoTimestamp}`}
                        >
                          <Clock className={`w-3 h-3 shrink-0 ${isLight ? 'text-sky-600' : 'text-cyan-400'}`} />
                          <span>{isoTimestamp}</span>
                        </div>
                        <span className="text-[10px] text-slate-500 pl-4.5">
                          Local: {localFormattedTime}
                        </span>
                      </div>
                    </td>
                    <td className={`p-3 font-semibold whitespace-nowrap ${isLight ? 'text-slate-900' : 'text-white'}`}>
                      <button
                        onClick={() => setFilterPrincipal(item.username)}
                        className={`transition-colors ${isLight ? 'hover:text-sky-700' : 'hover:text-[#00d2ff]'}`}
                        title={`Filter by principal: ${item.username}`}
                      >
                        {item.username}
                      </button>
                    </td>
                    <td className="p-3 whitespace-nowrap">
                      <button
                        onClick={() => setFilterFunction(item.requested_function)}
                        className="text-left"
                        title={`Filter by route: ${item.requested_function}`}
                      >
                        <code className={`px-1.5 py-0.5 rounded border transition-colors ${
                          isLight
                            ? 'text-sky-800 bg-sky-50 border-sky-200 hover:border-sky-400'
                            : 'text-[#00d2ff] bg-[#00d2ff]/10 border-[#00d2ff]/20 hover:border-[#00d2ff]/50'
                        }`}>
                          {item.requested_function}
                        </code>
                      </button>
                    </td>
                    <td className="p-3 whitespace-nowrap tabular-nums">
                      {/* Visual Risk Gauge & Tier Indicator */}
                      <div className="flex flex-col gap-1 min-w-[120px]">
                        <div className="flex items-center justify-between gap-2">
                          <span className={`font-bold ${riskColor}`}>
                            {risk}%
                          </span>
                          <span
                            className={`text-[9px] px-1.5 py-0.2 rounded font-bold uppercase tracking-wider border ${
                              isCritical
                                ? (isLight ? 'bg-rose-100 text-rose-800 border-rose-300' : 'bg-rose-500/20 text-rose-300 border-rose-500/30')
                                : isElevated
                                ? (isLight ? 'bg-amber-100 text-amber-800 border-amber-300' : 'bg-amber-500/20 text-amber-300 border-amber-500/30')
                                : isModerate
                                ? (isLight ? 'bg-sky-100 text-sky-800 border-sky-300' : 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30')
                                : (isLight ? 'bg-emerald-100 text-emerald-800 border-emerald-300' : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30')
                            }`}
                          >
                            {riskTierLabel}
                          </span>
                        </div>

                        {/* Visual 5-segment meter */}
                        <div className="flex items-center gap-1 w-full">
                          {[20, 40, 60, 80, 100].map((step, idx) => {
                            const isFilled = risk >= step - 10;
                            return (
                              <div
                                key={idx}
                                className={`h-1.5 flex-1 rounded-sm transition-all ${
                                  isFilled ? riskBgColor : (isLight ? 'bg-slate-200' : 'bg-slate-800')
                                }`}
                              />
                            );
                          })}
                        </div>
                      </div>
                    </td>
                    <td className="p-3 whitespace-nowrap tabular-nums">
                      {item.verification_latency_ms !== undefined ? (
                        <div className={`inline-flex items-center gap-1.5 px-2 py-1 rounded-md font-mono text-xs font-semibold border ${
                          isLight
                            ? 'bg-sky-50 text-sky-800 border-sky-200'
                            : 'bg-cyan-950/40 text-cyan-300 border-cyan-800/50'
                        }`}>
                          <Activity className={`w-3 h-3 ${isLight ? 'text-sky-600' : 'text-cyan-400'}`} />
                          <span>{item.verification_latency_ms} ms</span>
                        </div>
                      ) : (
                        <span className="text-slate-500 font-mono text-[11px]">&lt; 1.0 ms</span>
                      )}
                    </td>
                    <td className="p-3 whitespace-nowrap">
                      <div className="flex flex-col gap-1 items-start">
                        <span
                          className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${
                            isBlocked
                              ? (isLight ? 'bg-rose-100 text-rose-800 border-rose-300' : 'bg-[#ff4a6b]/15 text-[#ff4a6b] border-[#ff4a6b]/30')
                              : (isLight ? 'bg-emerald-100 text-emerald-800 border-emerald-300' : 'bg-[#00ff87]/15 text-[#00ff87] border-[#00ff87]/30')
                          }`}
                        >
                          {isBlocked ? (
                            <AlertOctagon className="w-2.5 h-2.5" />
                          ) : (
                            <CheckCircle className="w-2.5 h-2.5" />
                          )}
                          {item.status}
                        </span>
                        <span
                          className={`font-mono text-[10px] px-1.5 py-0.5 rounded border flex items-center gap-1 tabular-nums ${
                            isLight
                              ? 'text-slate-700 bg-slate-100 border-slate-200'
                              : 'text-slate-300 bg-slate-900/90 border-slate-800'
                          }`}
                          title={`High-Precision ISO 8601 Timestamp (UTC): ${isoTimestamp}`}
                        >
                          <Clock className={`w-2.5 h-2.5 shrink-0 ${isLight ? 'text-sky-600' : 'text-cyan-400'}`} />
                          <span className="truncate max-w-[145px]">{isoTimestamp}</span>
                        </span>
                      </div>
                    </td>
                    <td className={`p-3 leading-relaxed max-w-xs sm:max-w-md ${isLight ? 'text-slate-700' : 'text-slate-300'}`}>
                      <div className="space-y-1">
                        <div>{item.reason}</div>
                        {/* Behavioral Badges for Review Panel */}
                        <div className="flex items-center gap-1.5 flex-wrap pt-0.5">
                          {item.event_type === 'ABNORMAL_REQUEST_RATE' && (
                            <span className={`text-[9px] font-mono px-1.5 py-0.2 rounded border font-bold uppercase tracking-wider ${
                              isLight ? 'bg-amber-100 text-amber-800 border-amber-300' : 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                            }`}>
                              ABNORMAL_REQUEST_RATE (+20 RISK)
                            </span>
                          )}
                          {(item.event_type === 'SECURITY_EXCEPTION_FAIL_CLOSED' || item.reason?.includes('FAIL-CLOSED')) && (
                            <span className={`text-[9px] font-mono px-1.5 py-0.2 rounded border font-bold uppercase tracking-wider ${
                              isLight ? 'bg-rose-100 text-rose-800 border-rose-300' : 'bg-rose-500/25 text-rose-300 border-rose-500/50'
                            }`}>
                              FAIL-CLOSED GUARANTEE (CRITICAL 100)
                            </span>
                          )}
                          {item.event_type === 'SEQUENCE_VIOLATION' && (
                            <span className={`text-[9px] font-mono px-1.5 py-0.2 rounded border font-bold uppercase tracking-wider ${
                              isLight ? 'bg-purple-100 text-purple-800 border-purple-300' : 'bg-purple-500/20 text-purple-300 border-purple-500/40'
                            }`}>
                              MARKOV SEQUENCE VIOLATION
                            </span>
                          )}
                        </div>
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
        </>
      )}
    </div>
  );
};
