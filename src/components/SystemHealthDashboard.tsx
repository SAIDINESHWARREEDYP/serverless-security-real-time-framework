import React, { useMemo, useState } from 'react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  ReferenceLine,
  Cell,
  PieChart,
  Pie
} from 'recharts';
import {
  Activity,
  ShieldCheck,
  ShieldAlert,
  BarChart3,
  TrendingUp,
  Clock,
  Users,
  Layers,
  Zap,
  Filter,
  Download,
  Check,
  FileSpreadsheet,
  Search,
  X
} from 'lucide-react';
import { User, SecurityAuditLog, SecurityPolicyConfig } from '../types.ts';
import { useTheme } from '../context/ThemeContext.tsx';

interface SystemHealthDashboardProps {
  users: User[];
  logs: SecurityAuditLog[];
  policyConfig?: SecurityPolicyConfig;
  onOpenSecurityReport?: () => void;
}

// Custom responsive styled Tooltip for Recharts
const CustomChartTooltip = ({ active, payload, label, isLight }: any) => {
  if (active && payload && payload.length) {
    return (
      <div className={`p-3 rounded-xl shadow-xl text-xs font-mono border ${
        isLight ? 'bg-white border-slate-300 text-slate-900' : 'bg-slate-900 border-slate-700 text-slate-100'
      }`}>
        <div className={`font-bold mb-1.5 border-b pb-1 ${
          isLight ? 'border-slate-200 text-slate-900' : 'border-slate-800 text-slate-100'
        }`}>
          {label}
        </div>
        <div className="space-y-1">
          {payload.map((entry: any, index: number) => (
            <div key={`item-${index}`} className="flex items-center justify-between gap-4">
              <span className={`flex items-center gap-1.5 ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
                <span
                  className="w-2 h-2 rounded-full inline-block"
                  style={{ backgroundColor: entry.color || entry.fill }}
                />
                {entry.name}:
              </span>
              <span className={`font-bold ${isLight ? 'text-slate-900' : 'text-slate-200'}`}>
                {entry.value}
                {entry.unit || ''}
              </span>
            </div>
          ))}
        </div>
      </div>
    );
  }
  return null;
};

export const SystemHealthDashboard: React.FC<SystemHealthDashboardProps> = ({
  users,
  logs,
  policyConfig,
  onOpenSecurityReport
}) => {
  const { theme } = useTheme();
  const isLight = theme === 'light';
  const chartGridStroke = isLight ? '#e2e8f0' : '#1e2e4a';
  const chartAxisStroke = isLight ? '#cbd5e1' : '#223452';
  const chartTextFill = isLight ? '#475569' : '#64748b';

  const [activeView, setActiveView] = useState<'both' | 'frequency' | 'risk'>('both');
  const [timeResolution, setTimeResolution] = useState<'chronological' | 'hourly'>('chronological');
  const [userSearchQuery, setUserSearchQuery] = useState('');
  const [userRoleFilter, setUserRoleFilter] = useState<'ALL' | 'Admin' | 'Developer' | 'Guest'>('ALL');
  const [userRiskFilter, setUserRiskFilter] = useState<'ALL' | 'CRITICAL' | 'ELEVATED' | 'NOMINAL'>('ALL');

  const maxThreshold = policyConfig?.maxRiskThreshold ?? 75;

  // 1. Process User Risk Distribution Data
  const userRiskData = useMemo(() => {
    return users.map((user) => {
      const userLogs = logs.filter((l) => l.username === user.username);
      const totalUserRequests = userLogs.length;
      const blockedCount = userLogs.filter((l) => l.status === 'BLOCKED').length;
      const allowedCount = userLogs.filter((l) => l.status === 'ALLOWED').length;
      const maxObservedRisk = userLogs.length > 0
        ? Math.max(...userLogs.map((l) => l.calculated_risk))
        : user.base_risk_score;
      const avgObservedRisk = userLogs.length > 0
        ? Math.round(userLogs.reduce((sum, l) => sum + l.calculated_risk, 0) / userLogs.length)
        : user.base_risk_score;

      // Clean display name
      const shortName = user.username.replace(/^(admin_|dev_|guest_|malicious_)/, '');

      return {
        username: user.username,
        shortName,
        role: user.role,
        baseRisk: user.base_risk_score,
        observedMaxRisk: maxObservedRisk,
        avgRisk: avgObservedRisk,
        totalRequests: totalUserRequests,
        blocked: blockedCount,
        allowed: allowedCount,
        threatIndex: Math.max(user.base_risk_score, avgObservedRisk)
      };
    });
  }, [users, logs]);

  // Filtered users according to search and filters
  const displayedUserRiskData = useMemo(() => {
    return userRiskData.filter((u) => {
      if (userRoleFilter !== 'ALL' && u.role !== userRoleFilter) return false;
      if (userRiskFilter === 'CRITICAL' && u.threatIndex < maxThreshold) return false;
      if (userRiskFilter === 'ELEVATED' && (u.threatIndex < 35 || u.threatIndex >= maxThreshold)) return false;
      if (userRiskFilter === 'NOMINAL' && u.threatIndex >= 35) return false;

      if (userSearchQuery.trim()) {
        const q = userSearchQuery.toLowerCase();
        if (!u.username.toLowerCase().includes(q) && !u.shortName.toLowerCase().includes(q) && !u.role.toLowerCase().includes(q)) {
          return false;
        }
      }
      return true;
    });
  }, [userRiskData, userRoleFilter, userRiskFilter, userSearchQuery, maxThreshold]);

  // 2. Risk Tier Breakdown Data (Pie / Donut chart)
  const riskTierData = useMemo(() => {
    // If logs exist, categorize based on observed calculated risks in logs;
    // additionally factor in users' baseline risk.
    const evaluations = logs.length > 0
      ? logs.map((l) => l.calculated_risk)
      : users.map((u) => u.base_risk_score);

    let low = 0;       // 0 - 25%
    let moderate = 0;  // 26 - 50%
    let elevated = 0;  // 51 - 74%
    let critical = 0;  // >= 75%

    evaluations.forEach((score) => {
      if (score >= maxThreshold) {
        critical++;
      } else if (score >= 50) {
        elevated++;
      } else if (score >= 25) {
        moderate++;
      } else {
        low++;
      }
    });

    const total = evaluations.length || 1;

    return [
      { name: 'Nominal (0-24%)', value: low, color: '#00ff87', pct: Math.round((low / total) * 100) },
      { name: 'Moderate (25-49%)', value: moderate, color: '#00d2ff', pct: Math.round((moderate / total) * 100) },
      { name: 'Elevated (50-74%)', value: elevated, color: '#f59e0b', pct: Math.round((elevated / total) * 100) },
      { name: `Critical (≥${maxThreshold}%)`, value: critical, color: '#ff4a6b', pct: Math.round((critical / total) * 100) }
    ].filter((tier) => tier.value > 0 || logs.length === 0);
  }, [logs, users, maxThreshold]);

  // 3. Process Audit Log Frequency Over Time
  const frequencyTimelineData = useMemo(() => {
    if (logs.length === 0) {
      // Return a clean idle baseline timeline with past 5 intervals
      const now = Date.now();
      return Array.from({ length: 5 }).map((_, i) => {
        const timeLabel = new Date(now - (4 - i) * 60000).toLocaleTimeString([], {
          hour: '2-digit',
          minute: '2-digit'
        });
        return {
          time: timeLabel,
          allowed: 0,
          blocked: 0,
          total: 0,
          avgRisk: 0
        };
      });
    }

    // Chronological order (oldest to newest)
    const sortedLogs = [...logs].sort((a, b) => a.id - b.id);

    if (timeResolution === 'chronological') {
      // Group by sliding sequence batches or 10-log intervals to maintain crisp resolution
      // If <= 15 logs, each log is its own temporal point
      if (sortedLogs.length <= 15) {
        return sortedLogs.map((log) => {
          const date = new Date(log.timestamp);
          const timeStr = isNaN(date.getTime())
            ? `Req #${log.id}`
            : date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
          return {
            time: timeStr,
            allowed: log.status === 'ALLOWED' ? 1 : 0,
            blocked: log.status === 'BLOCKED' ? 1 : 0,
            total: 1,
            avgRisk: log.calculated_risk,
            username: log.username,
            fn: log.requested_function.replace('/api/', '')
          };
        });
      }

      // Group into ~10-12 buckets
      const bucketCount = 10;
      const bucketSize = Math.ceil(sortedLogs.length / bucketCount);
      const buckets = [];

      for (let i = 0; i < sortedLogs.length; i += bucketSize) {
        const chunk = sortedLogs.slice(i, i + bucketSize);
        const first = chunk[0];
        const last = chunk[chunk.length - 1];
        const date = new Date(last.timestamp);
        const timeStr = isNaN(date.getTime())
          ? `#${first.id}-${last.id}`
          : date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

        const allowed = chunk.filter((l) => l.status === 'ALLOWED').length;
        const blocked = chunk.filter((l) => l.status === 'BLOCKED').length;
        const avgRisk = Math.round(chunk.reduce((sum, l) => sum + l.calculated_risk, 0) / chunk.length);

        buckets.push({
          time: timeStr,
          allowed,
          blocked,
          total: chunk.length,
          avgRisk
        });
      }
      return buckets;
    } else {
      // Group by minute buckets
      const minuteMap = new Map<string, { allowed: number; blocked: number; totalRisk: number; count: number }>();

      sortedLogs.forEach((log) => {
        const date = new Date(log.timestamp);
        const key = isNaN(date.getTime())
          ? 'Current'
          : date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

        if (!minuteMap.has(key)) {
          minuteMap.set(key, { allowed: 0, blocked: 0, totalRisk: 0, count: 0 });
        }
        const entry = minuteMap.get(key)!;
        if (log.status === 'ALLOWED') entry.allowed++;
        if (log.status === 'BLOCKED') entry.blocked++;
        entry.totalRisk += log.calculated_risk;
        entry.count++;
      });

      return Array.from(minuteMap.entries()).map(([time, val]) => ({
        time,
        allowed: val.allowed,
        blocked: val.blocked,
        total: val.count,
        avgRisk: Math.round(val.totalRisk / val.count)
      }));
    }
  }, [logs, timeResolution]);

  // Overall metrics summary
  const totalAuditCount = logs.length;
  const totalBlocked = logs.filter((l) => l.status === 'BLOCKED').length;
  const totalAllowed = logs.filter((l) => l.status === 'ALLOWED').length;
  const overallAvgRisk = totalAuditCount > 0
    ? Math.round(logs.reduce((s, l) => s + l.calculated_risk, 0) / totalAuditCount)
    : 15;
  const blockRate = totalAuditCount > 0 ? Math.round((totalBlocked / totalAuditCount) * 100) : 0;
  const [downloadSuccess, setDownloadSuccess] = useState(false);

  const handleExportRiskCSV = () => {
    if (userRiskData.length === 0) return;

    const escapeCsv = (val: string | number | undefined | null) => {
      const str = String(val ?? '');
      if (str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r')) {
        return `"${str.replace(/"/g, '""')}"`;
      }
      return str;
    };

    const headers = [
      'Principal Username',
      'Assigned Role',
      'Base Risk (%)',
      'Total Invocations',
      'Allowed Requests',
      'Blocked Requests',
      'Max Observed Risk (%)',
      'Average Risk (%)',
      'Threat Classification',
      'Policy Cutoff Threshold (%)',
      'Compliance Clearance'
    ];

    const rows = userRiskData.map((u) => {
      const threatClass =
        u.threatIndex >= maxThreshold ? 'CRITICAL_BREACH' :
        u.threatIndex >= 50 ? 'ELEVATED_RISK' :
        u.threatIndex >= 25 ? 'MODERATE_RISK' : 'NOMINAL';
      const compliance = u.blocked > 0 ? 'ANOMALY_INTERCEPTED' : 'CLEARED_NOMINAL';

      return [
        escapeCsv(u.username),
        escapeCsv(u.role),
        escapeCsv(u.baseRisk),
        escapeCsv(u.totalRequests),
        escapeCsv(u.allowed),
        escapeCsv(u.blocked),
        escapeCsv(u.observedMaxRisk),
        escapeCsv(u.avgRisk),
        escapeCsv(threatClass),
        escapeCsv(maxThreshold),
        escapeCsv(compliance)
      ];
    });

    const summaryRows = [
      [],
      ['--- AUDIT SUMMARY & POLICIES ---'],
      ['Total Active Principals Evaluated', userRiskData.length],
      ['Total Requests Intercepted in Ledger', logs.length],
      ['Total Blocked Requests', totalBlocked],
      ['Total Allowed Requests', totalAllowed],
      ['Overall Average System Risk', `${overallAvgRisk}%`],
      ['System Max Risk Cutoff Threshold', `${maxThreshold}%`],
      ['Sequence Violation Threat Penalty', `+${policyConfig?.sequenceViolationPenalty ?? 40}%`],
      ['Audit Report Generation ISO Time', new Date().toISOString()]
    ];

    const csvContent = [
      headers.join(','),
      ...rows.map((r) => r.join(',')),
      ...summaryRows.map((r) => r.map((c) => escapeCsv(c)).join(','))
    ].join('\r\n');

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    const dateStr = new Date().toISOString().slice(0, 10);
    link.setAttribute('download', `system_risk_distribution_audit_report_${dateStr}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    setDownloadSuccess(true);
    setTimeout(() => setDownloadSuccess(false), 2500);
  };

  return (
    <div className="glossy-panel rounded-2xl p-5 sm:p-6 relative overflow-hidden font-mono transition-colors duration-200">
      {/* Background Accent Gradient */}
      <div className="absolute top-0 right-0 w-96 h-40 bg-gradient-to-bl from-blue-500/10 via-transparent to-transparent pointer-events-none" />

      {/* Top Header & Interactive View Controls */}
      <div className={`flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b pb-4 mb-5 ${
        isLight ? 'border-slate-200' : 'border-[#1e2e4a]'
      }`}>
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-2xl bg-blue-500/10 border border-blue-500/30 flex items-center justify-center text-blue-500 shadow-sm">
            <Activity className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className={`text-base font-bold uppercase tracking-wider ${isLight ? 'text-slate-900' : 'text-white'}`}>
                System Health &amp; Threat Telemetry
              </h2>
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-600 dark:text-[#00ff87] border border-emerald-500/30 font-semibold shadow-xs">
                Live Recharts Engine
              </span>
            </div>
            <p className={`text-xs mt-0.5 ${isLight ? 'text-slate-500' : 'text-[#94a3b8]'}`}>
              Continuous visualization of principal risk profiles, audit request velocity, and threat mitigation boundaries
            </p>
          </div>
        </div>

        {/* View Switchers & CSV Export Button */}
        <div className="flex items-center gap-2 flex-wrap self-start md:self-auto">
          <button
            id="btn-export-risk-distribution-csv"
            onClick={handleExportRiskCSV}
            className={`glossy-btn flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold transition-all border shadow-xs ${
              downloadSuccess
                ? 'bg-emerald-600 text-white border-emerald-500'
                : isLight
                ? 'bg-blue-50 hover:bg-blue-100 text-blue-700 border-blue-200'
                : 'bg-[#12233f] hover:bg-[#1a3159] text-blue-400 hover:text-white border-blue-500/40'
            }`}
            title="Download full Risk Distribution and Audit Matrix as CSV"
          >
            {downloadSuccess ? (
              <>
                <Check className="w-3.5 h-3.5 text-white" />
                <span>CSV Exported!</span>
              </>
            ) : (
              <>
                <Download className="w-3.5 h-3.5" />
                <span>Export Risk CSV</span>
              </>
            )}
          </button>

          {onOpenSecurityReport && (
            <button
              id="btn-dashboard-security-report"
              onClick={onOpenSecurityReport}
              className={`glossy-btn flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold transition-all shadow-xs border ${
                isLight
                  ? 'bg-emerald-50 hover:bg-emerald-100 text-emerald-700 border-emerald-200'
                  : 'bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border-emerald-500/40'
              }`}
              title="Download full Security Report for compliance auditing (JSON/CSV/Print)"
            >
              <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-500" />
              <span>Security Report</span>
            </button>
          )}

          <div className={`flex border rounded-xl p-1 text-xs ${
            isLight ? 'bg-slate-100 border-slate-200' : 'bg-[#090d16] border-[#223452]'
          }`}>
            <button
              onClick={() => setActiveView('both')}
              className={`px-3 py-1 rounded-lg transition-all ${
                activeView === 'both'
                  ? isLight
                    ? 'bg-white text-blue-700 font-bold shadow-xs'
                    : 'bg-[#00d2ff] text-black font-bold'
                  : isLight
                  ? 'text-slate-600 hover:text-slate-900'
                  : 'text-[#94a3b8] hover:text-white'
              }`}
            >
              Unified Dashboard
            </button>
            <button
              onClick={() => setActiveView('frequency')}
              className={`px-3 py-1 rounded-lg transition-all ${
                activeView === 'frequency'
                  ? isLight
                    ? 'bg-white text-blue-700 font-bold shadow-xs'
                    : 'bg-[#00d2ff] text-black font-bold'
                  : isLight
                  ? 'text-slate-600 hover:text-slate-900'
                  : 'text-[#94a3b8] hover:text-white'
              }`}
            >
              Audit Velocity
            </button>
            <button
              onClick={() => setActiveView('risk')}
              className={`px-3 py-1 rounded-lg transition-all ${
                activeView === 'risk'
                  ? isLight
                    ? 'bg-white text-blue-700 font-bold shadow-xs'
                    : 'bg-[#00d2ff] text-black font-bold'
                  : isLight
                  ? 'text-slate-600 hover:text-slate-900'
                  : 'text-[#94a3b8] hover:text-white'
              }`}
            >
              Risk Distribution
            </button>
          </div>
        </div>
      </div>

      {/* KPI Metrics Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3.5 mb-6">
        <div className="glossy-panel glossy-card-hover p-4 rounded-2xl shadow-xs transition-all">
          <div className="text-[10px] uppercase font-bold text-slate-400 flex items-center justify-between">
            <span>Total Invocations</span>
            <Layers className="w-3.5 h-3.5 text-blue-500" />
          </div>
          <div className={`text-xl font-bold mt-1 ${isLight ? 'text-slate-900' : 'text-white'}`}>
            {totalAuditCount}
          </div>
          <div className="text-[10px] text-slate-400 mt-0.5 flex items-center gap-1.5">
            <span className="text-emerald-500 font-semibold">{totalAllowed} Allowed</span>
            <span>•</span>
            <span className="text-rose-500 font-semibold">{totalBlocked} Blocked</span>
          </div>
        </div>

        <div className="glossy-panel glossy-card-hover p-4 rounded-2xl shadow-xs transition-all">
          <div className="text-[10px] uppercase font-bold text-slate-400 flex items-center justify-between">
            <span>Interception Rate</span>
            <ShieldAlert className="w-3.5 h-3.5 text-rose-500" />
          </div>
          <div className="text-xl font-bold mt-1 flex items-baseline gap-1.5">
            <span className={blockRate > 40 ? 'text-rose-500' : blockRate > 10 ? 'text-amber-500' : 'text-emerald-500'}>
              {blockRate}%
            </span>
            <span className="text-[10px] text-slate-400 font-normal">mitigated</span>
          </div>
          <div className="text-[10px] text-slate-400 mt-0.5">
            Cutoff Boundary: <strong className={isLight ? 'text-slate-900' : 'text-white'}>{maxThreshold}%</strong>
          </div>
        </div>

        <div className="glossy-panel glossy-card-hover p-4 rounded-2xl shadow-xs transition-all">
          <div className="text-[10px] uppercase font-bold text-slate-400 flex items-center justify-between">
            <span>Median Threat Index</span>
            <TrendingUp className="w-3.5 h-3.5 text-amber-500" />
          </div>
          <div className="text-xl font-bold mt-1">
            <span className={overallAvgRisk >= 60 ? 'text-rose-500' : overallAvgRisk >= 30 ? 'text-amber-500' : 'text-emerald-500'}>
              {overallAvgRisk}%
            </span>
          </div>
          <div className="text-[10px] text-slate-400 mt-0.5">
            Evaluated Markov drift
          </div>
        </div>

        <div className="glossy-panel glossy-card-hover p-4 rounded-2xl shadow-xs transition-all">
          <div className="text-[10px] uppercase font-bold text-slate-400 flex items-center justify-between">
            <span>Edge Interceptor SLA</span>
            <Zap className="w-3.5 h-3.5 text-emerald-500" />
          </div>
          <div className="text-xl font-bold text-emerald-500 mt-1">
            99.98%
          </div>
          <div className="text-[10px] text-slate-400 mt-0.5">
            Latency &lt; 4.2ms avg
          </div>
        </div>
      </div>

      {/* Main Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* CHART 1: AUDIT LOG FREQUENCY OVER TIME */}
        {(activeView === 'both' || activeView === 'frequency') && (
          <div className={`${activeView === 'both' ? 'lg:col-span-7' : 'lg:col-span-12'} glossy-panel rounded-2xl p-4 sm:p-5 flex flex-col shadow-xs transition-colors`}>
            <div className={`flex items-center justify-between mb-3 border-b pb-2 ${
              isLight ? 'border-slate-200' : 'border-[#1c2b42]'
            }`}>
              <div className="flex items-center gap-2">
                <Clock className="w-4 h-4 text-blue-500" />
                <h3 className={`text-xs font-bold uppercase tracking-wider ${isLight ? 'text-slate-900' : 'text-white'}`}>
                  Audit Log Frequency &amp; Threat Velocity Over Time
                </h3>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] text-slate-400 hidden sm:inline">Grouping:</span>
                <button
                  onClick={() => setTimeResolution(timeResolution === 'chronological' ? 'hourly' : 'chronological')}
                  className={`px-2.5 py-1 text-[10px] rounded-lg border flex items-center gap-1 transition-all ${
                    isLight
                      ? 'bg-white hover:bg-slate-100 text-blue-600 border-slate-300 shadow-xs'
                      : 'bg-[#131d33] hover:bg-[#1a273f] text-[#00d2ff] border-[#223452]'
                  }`}
                >
                  <Filter className="w-2.5 h-2.5" />
                  {timeResolution === 'chronological' ? 'Chronological Points' : 'Minute Buckets'}
                </button>
              </div>
            </div>

            <div className={`flex items-center justify-between text-[11px] mb-2 px-1 ${
              isLight ? 'text-slate-600' : 'text-[#94a3b8]'
            }`}>
              <div className="flex items-center gap-4">
                <span className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-sm bg-emerald-500 inline-block" />
                  Allowed Invocations
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-sm bg-rose-500 inline-block" />
                  Blocked Invocations
                </span>
              </div>
              <span className="text-[10px] text-slate-400">
                {logs.length} logged events
              </span>
            </div>

            {/* Recharts Area / Composed Chart */}
            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart
                  data={frequencyTimelineData}
                  margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
                >
                  <defs>
                    <linearGradient id="colorAllowed" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#10b981" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#10b981" stopOpacity={0.0} />
                    </linearGradient>
                    <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.5} />
                      <stop offset="95%" stopColor="#f43f5e" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke={chartGridStroke} strokeDasharray="3 3" vertical={false} />
                  <XAxis
                    dataKey="time"
                    stroke={chartTextFill}
                    fontSize={10}
                    tickLine={false}
                    axisLine={{ stroke: chartAxisStroke }}
                  />
                  <YAxis
                    stroke={chartTextFill}
                    fontSize={10}
                    tickLine={false}
                    axisLine={{ stroke: chartAxisStroke }}
                    allowDecimals={false}
                  />
                  <Tooltip content={<CustomChartTooltip isLight={isLight} />} />
                  <Area
                    type="monotone"
                    dataKey="allowed"
                    name="Allowed Requests"
                    stroke="#10b981"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#colorAllowed)"
                  />
                  <Area
                    type="monotone"
                    dataKey="blocked"
                    name="Blocked Requests"
                    stroke="#f43f5e"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#colorBlocked)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>

            <div className={`mt-2 text-[10px] flex items-center justify-between border-t pt-2 ${
              isLight ? 'border-slate-200 text-slate-500' : 'border-[#162236] text-[#64748b]'
            }`}>
              <span>Dynamic area footprint tracks request throughput</span>
              <span className="text-blue-500 font-semibold">
                Zero-Trust Firewall Interception Active
              </span>
            </div>
          </div>
        )}

        {/* CHART 2: USER RISK SCORES DISTRIBUTION */}
        {(activeView === 'both' || activeView === 'risk') && (
          <div className={`${activeView === 'both' ? 'lg:col-span-5' : 'lg:col-span-12'} glossy-panel rounded-2xl p-4 sm:p-5 flex flex-col shadow-xs transition-colors`}>
            <div className={`flex items-center justify-between mb-2 border-b pb-2 ${
              isLight ? 'border-slate-200' : 'border-[#1c2b42]'
            }`}>
              <div className="flex items-center gap-2">
                <BarChart3 className="w-4 h-4 text-blue-500" />
                <h3 className={`text-xs font-bold uppercase tracking-wider ${isLight ? 'text-slate-900' : 'text-white'}`}>
                  User Risk Score Distribution
                </h3>
              </div>
              <span className={`text-[10px] px-2 py-0.5 rounded-full border font-semibold ${
                isLight ? 'bg-purple-100 text-purple-700 border-purple-200' : 'bg-purple-950/80 text-purple-300 border-purple-800'
              }`}>
                {displayedUserRiskData.length} of {users.length} Shown
              </span>
            </div>

            {/* User Search & Filter Toolbar */}
            <div className="flex items-center gap-1.5 mb-2.5 flex-wrap">
              <div className="relative flex-1 min-w-[120px]">
                <Search className="w-3 h-3 text-slate-400 absolute left-2.5 top-2.5" />
                <input
                  type="text"
                  placeholder="Filter principal..."
                  value={userSearchQuery}
                  onChange={(e) => setUserSearchQuery(e.target.value)}
                  className={`w-full pl-7 pr-5 py-1 text-[11px] rounded-lg border focus:outline-none focus:border-blue-500 shadow-xs ${
                    isLight ? 'bg-white border-slate-300 text-slate-900' : 'bg-[#131d33] border-[#223452] text-white'
                  }`}
                />
                {userSearchQuery && (
                  <button
                    onClick={() => setUserSearchQuery('')}
                    className="absolute right-1.5 top-1.5 text-slate-400 hover:text-slate-700 dark:hover:text-white"
                  >
                    <X className="w-3 h-3" />
                  </button>
                )}
              </div>

              {/* Role Filter */}
              <select
                value={userRoleFilter}
                onChange={(e) => setUserRoleFilter(e.target.value as any)}
                className={`px-2 py-1 text-[10px] rounded-lg border focus:outline-none focus:border-blue-500 shadow-xs ${
                  isLight ? 'bg-white border-slate-300 text-slate-700' : 'bg-[#131d33] border-[#223452] text-slate-300'
                }`}
              >
                <option value="ALL">All Roles</option>
                <option value="Admin">Admin</option>
                <option value="Developer">Developer</option>
                <option value="Guest">Guest</option>
              </select>

              {/* Risk Filter */}
              <select
                value={userRiskFilter}
                onChange={(e) => setUserRiskFilter(e.target.value as any)}
                className={`px-2 py-1 text-[10px] rounded-lg border focus:outline-none focus:border-blue-500 shadow-xs ${
                  isLight ? 'bg-white border-slate-300 text-slate-700' : 'bg-[#131d33] border-[#223452] text-slate-300'
                }`}
              >
                <option value="ALL">All Threat Tiers</option>
                <option value="CRITICAL">Critical (≥{maxThreshold}%)</option>
                <option value="ELEVATED">Elevated (35-{maxThreshold}%)</option>
                <option value="NOMINAL">Nominal (&lt;35%)</option>
              </select>

              {(userSearchQuery || userRoleFilter !== 'ALL' || userRiskFilter !== 'ALL') && (
                <button
                  onClick={() => {
                    setUserSearchQuery('');
                    setUserRoleFilter('ALL');
                    setUserRiskFilter('ALL');
                  }}
                  className={`p-1 rounded-lg border transition-colors ${
                    isLight
                      ? 'bg-white text-slate-600 hover:text-slate-900 border-slate-300'
                      : 'bg-[#1a273f] text-slate-400 hover:text-white border-[#223452]'
                  }`}
                  title="Reset filters"
                >
                  <X className="w-3 h-3" />
                </button>
              )}
            </div>

            <div className={`flex items-center justify-between text-[11px] mb-2 px-1 ${
              isLight ? 'text-slate-600' : 'text-[#94a3b8]'
            }`}>
              <div className="flex items-center gap-3">
                <span className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-sm bg-blue-500 inline-block" />
                  Base Risk
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-sm bg-rose-500 inline-block" />
                  Max Observed
                </span>
              </div>
              <span className="text-[10px] text-amber-500 font-semibold">
                Threshold: {maxThreshold}%
              </span>
            </div>

            {/* Recharts BarChart comparing Base Risk and Max Observed Risk per user */}
            <div className="h-64 w-full">
              {displayedUserRiskData.length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center text-xs text-slate-400">
                  <p>No principals match the active filter criteria.</p>
                  <button
                    onClick={() => {
                      setUserSearchQuery('');
                      setUserRoleFilter('ALL');
                      setUserRiskFilter('ALL');
                    }}
                    className="mt-1 text-blue-500 hover:underline"
                  >
                    Reset filters
                  </button>
                </div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={displayedUserRiskData}
                    margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
                    barGap={3}
                  >
                    <CartesianGrid stroke={chartGridStroke} strokeDasharray="3 3" vertical={false} />
                    <XAxis
                      dataKey="shortName"
                      stroke={chartTextFill}
                      fontSize={10}
                      tickLine={false}
                      axisLine={{ stroke: chartAxisStroke }}
                    />
                    <YAxis
                      domain={[0, 100]}
                      stroke={chartTextFill}
                      fontSize={10}
                      tickLine={false}
                      axisLine={{ stroke: chartAxisStroke }}
                      unit="%"
                    />
                    <Tooltip content={<CustomChartTooltip isLight={isLight} />} />
                    <ReferenceLine
                      y={maxThreshold}
                      stroke="#f43f5e"
                      strokeDasharray="4 4"
                      label={{
                        value: `CUTOFF (${maxThreshold}%)`,
                        fill: '#f43f5e',
                        fontSize: 9,
                        position: 'top'
                      }}
                    />
                    <Bar
                      dataKey="baseRisk"
                      name="Base Risk Score"
                      fill="#3b82f6"
                      radius={[3, 3, 0, 0]}
                      unit="%"
                    >
                      {displayedUserRiskData.map((entry, index) => (
                        <Cell
                          key={`cell-base-${index}`}
                          fill={entry.baseRisk >= maxThreshold ? '#f43f5e' : entry.baseRisk > 20 ? '#3b82f6' : '#10b981'}
                        />
                      ))}
                    </Bar>
                    <Bar
                      dataKey="observedMaxRisk"
                      name="Max Evaluated Risk"
                      fill="#f43f5e"
                      radius={[3, 3, 0, 0]}
                      unit="%"
                    />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>

            <div className={`mt-2 text-[10px] flex items-center justify-between border-t pt-2 ${
              isLight ? 'border-slate-200 text-slate-500' : 'border-[#162236] text-[#64748b]'
            }`}>
              <span>Bars above cutoff trigger automated mitigation</span>
              <span className="text-emerald-500 font-semibold">Evaluated Per Invocation</span>
            </div>
          </div>
        )}
      </div>

      {/* Secondary Distribution Row: Threat Tier Composition & Principal Roster */}
      <div className={`mt-5 pt-4 border-t grid grid-cols-1 md:grid-cols-12 gap-4 items-center ${
        isLight ? 'border-slate-200' : 'border-[#1e2e4a]'
      }`}>
        {/* Risk Tier Donut Chart */}
        <div className="md:col-span-5 flex items-center gap-4 glossy-panel p-4 rounded-2xl shadow-xs">
          <div className="w-24 h-24 shrink-0 relative">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={riskTierData}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  innerRadius={28}
                  outerRadius={42}
                  paddingAngle={3}
                >
                  {riskTierData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip content={<CustomChartTooltip isLight={isLight} />} />
              </PieChart>
            </ResponsiveContainer>
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <span className={`text-[11px] font-bold ${isLight ? 'text-slate-900' : 'text-white'}`}>{logs.length}</span>
              <span className="text-[8px] text-slate-400 uppercase">Events</span>
            </div>
          </div>

          <div className="flex-1 space-y-1">
            <div className="text-[10px] uppercase font-bold text-slate-400 mb-1">
              Threat Tier Distribution
            </div>
            {riskTierData.map((tier) => (
              <div key={tier.name} className="flex items-center justify-between text-xs">
                <span className={`flex items-center gap-1.5 ${isLight ? 'text-slate-600' : 'text-[#94a3b8]'}`}>
                  <span className="w-2 h-2 rounded-full" style={{ backgroundColor: tier.color }} />
                  {tier.name}:
                </span>
                <span className={`font-bold ${isLight ? 'text-slate-900' : 'text-white'}`}>
                  {tier.value} <span className="text-[10px] text-slate-400">({tier.pct}%)</span>
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* User Risk Profile Status Cards with Visual Risk Meters */}
        <div className="md:col-span-7 grid grid-cols-2 sm:grid-cols-4 gap-2.5">
          {displayedUserRiskData.slice(0, 8).map((u) => {
            const isCritical = u.threatIndex >= maxThreshold;
            const isElevated = u.threatIndex >= 35 && u.threatIndex < maxThreshold;
            return (
              <div
                key={u.username}
                className={`p-3 rounded-2xl border text-xs flex flex-col justify-between shadow-xs transition-all glossy-card-hover ${
                  isCritical
                    ? isLight
                      ? 'bg-rose-50 border-rose-200'
                      : 'bg-red-950/30 border-red-800/60'
                    : isLight
                    ? 'bg-slate-50 border-slate-200'
                    : 'bg-[#090d16] border-[#223452]'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between">
                    <span className={`font-bold truncate ${isLight ? 'text-slate-900' : 'text-white'}`} title={u.username}>
                      {u.shortName}
                    </span>
                    <span className={`text-[9px] px-1.5 py-0.5 rounded-full font-medium ${
                      u.role === 'Admin' ? 'bg-purple-100 dark:bg-purple-900/60 text-purple-700 dark:text-purple-200' :
                      u.role === 'Developer' ? 'bg-blue-100 dark:bg-cyan-900/60 text-blue-700 dark:text-cyan-200' :
                      'bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300'
                    }`}>
                      {u.role}
                    </span>
                  </div>
                  <div className="mt-1.5 flex items-baseline justify-between">
                    <span className="text-[10px] text-slate-400">Threat:</span>
                    <span className={`font-bold ${isCritical ? 'text-rose-500' : isElevated ? 'text-amber-500' : 'text-emerald-500'}`}>
                      {u.threatIndex}%
                    </span>
                  </div>
                  {/* Visual progress bar */}
                  <div className="w-full bg-slate-200 dark:bg-[#131d33] h-1.5 rounded-full overflow-hidden mt-1 border border-slate-300 dark:border-[#223452]">
                    <div
                      className={`h-full transition-all ${
                        isCritical ? 'bg-rose-500' : isElevated ? 'bg-amber-400' : 'bg-emerald-500'
                      }`}
                      style={{ width: `${Math.min(u.threatIndex, 100)}%` }}
                    />
                  </div>
                </div>
                <div className={`text-[9px] text-slate-400 mt-2 flex justify-between pt-1 border-t ${
                  isLight ? 'border-slate-200' : 'border-[#1a273f]'
                }`}>
                  <span>Reqs: {u.totalRequests}</span>
                  {u.blocked > 0 && <span className="text-rose-500 font-semibold">{u.blocked} Blk</span>}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
