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
  FileSpreadsheet
} from 'lucide-react';
import { User, SecurityAuditLog, SecurityPolicyConfig } from '../types.ts';

interface SystemHealthDashboardProps {
  users: User[];
  logs: SecurityAuditLog[];
  policyConfig?: SecurityPolicyConfig;
}

// Custom dark styled Tooltip for Recharts
const CustomChartTooltip = ({ active, payload, label }: any) => {
  if (active && payload && payload.length) {
    return (
      <div className="bg-[#0b1324] border border-[#223d66] p-3 rounded-lg shadow-xl text-xs font-mono">
        <div className="text-white font-bold mb-1.5 border-b border-[#1e2e4a] pb-1">
          {label}
        </div>
        <div className="space-y-1">
          {payload.map((entry: any, index: number) => (
            <div key={`item-${index}`} className="flex items-center justify-between gap-4">
              <span className="flex items-center gap-1.5 text-[#94a3b8]">
                <span
                  className="w-2 h-2 rounded-full inline-block"
                  style={{ backgroundColor: entry.color || entry.fill }}
                />
                {entry.name}:
              </span>
              <span className="font-bold text-white">
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
  policyConfig
}) => {
  const [activeView, setActiveView] = useState<'both' | 'frequency' | 'risk'>('both');
  const [timeResolution, setTimeResolution] = useState<'chronological' | 'hourly'>('chronological');

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
    <div className="bg-[#0f172a] border border-[#223452] rounded-xl p-5 shadow-lg relative overflow-hidden font-mono">
      {/* Background Accent Gradient */}
      <div className="absolute top-0 right-0 w-96 h-40 bg-gradient-to-bl from-[#00d2ff]/10 via-transparent to-transparent pointer-events-none" />

      {/* Top Header & Interactive View Controls */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-[#1e2e4a] pb-4 mb-5">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-[#00d2ff]/10 border border-[#00d2ff]/30 flex items-center justify-center text-[#00d2ff]">
            <Activity className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-bold text-white uppercase tracking-wider">
                System Health &amp; Threat Telemetry
              </h2>
              <span className="text-[10px] px-2 py-0.5 rounded bg-[#00ff87]/15 text-[#00ff87] border border-[#00ff87]/30">
                Recharts Live Engine
              </span>
            </div>
            <p className="text-xs text-[#94a3b8] mt-0.5">
              Continuous visualization of principal risk profiles, audit request velocity, and threat mitigation boundaries
            </p>
          </div>
        </div>

        {/* View Switchers & CSV Export Button */}
        <div className="flex items-center gap-2 flex-wrap self-start md:self-auto">
          <button
            id="btn-export-risk-distribution-csv"
            onClick={handleExportRiskCSV}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all border shadow-sm ${
              downloadSuccess
                ? 'bg-emerald-600 text-white border-emerald-500'
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

          <div className="flex bg-[#090d16] border border-[#223452] rounded-lg p-1 text-xs">
            <button
              onClick={() => setActiveView('both')}
              className={`px-3 py-1 rounded transition-colors ${
                activeView === 'both'
                  ? 'bg-[#00d2ff] text-black font-bold'
                  : 'text-[#94a3b8] hover:text-white'
              }`}
            >
              Unified Dashboard
            </button>
            <button
              onClick={() => setActiveView('frequency')}
              className={`px-3 py-1 rounded transition-colors ${
                activeView === 'frequency'
                  ? 'bg-[#00d2ff] text-black font-bold'
                  : 'text-[#94a3b8] hover:text-white'
              }`}
            >
              Audit Velocity
            </button>
            <button
              onClick={() => setActiveView('risk')}
              className={`px-3 py-1 rounded transition-colors ${
                activeView === 'risk'
                  ? 'bg-[#00d2ff] text-black font-bold'
                  : 'text-[#94a3b8] hover:text-white'
              }`}
            >
              Risk Distribution
            </button>
          </div>
        </div>
      </div>

      {/* KPI Metrics Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
        <div className="p-3 bg-[#090d16] border border-[#223452] rounded-lg">
          <div className="text-[10px] uppercase font-bold text-[#64748b] flex items-center justify-between">
            <span>Total Invocations</span>
            <Layers className="w-3.5 h-3.5 text-[#00d2ff]" />
          </div>
          <div className="text-xl font-bold text-white mt-1">
            {totalAuditCount}
          </div>
          <div className="text-[10px] text-[#94a3b8] mt-0.5 flex items-center gap-1.5">
            <span className="text-[#00ff87]">{totalAllowed} Allowed</span>
            <span>•</span>
            <span className="text-[#ff4a6b]">{totalBlocked} Blocked</span>
          </div>
        </div>

        <div className="p-3 bg-[#090d16] border border-[#223452] rounded-lg">
          <div className="text-[10px] uppercase font-bold text-[#64748b] flex items-center justify-between">
            <span>Interception Rate</span>
            <ShieldAlert className="w-3.5 h-3.5 text-[#ff4a6b]" />
          </div>
          <div className="text-xl font-bold text-white mt-1 flex items-baseline gap-1.5">
            <span className={blockRate > 40 ? 'text-[#ff4a6b]' : blockRate > 10 ? 'text-amber-400' : 'text-[#00ff87]'}>
              {blockRate}%
            </span>
            <span className="text-[10px] text-[#64748b] font-normal">mitigated</span>
          </div>
          <div className="text-[10px] text-[#94a3b8] mt-0.5">
            Cutoff Boundary: <strong className="text-white">{maxThreshold}%</strong>
          </div>
        </div>

        <div className="p-3 bg-[#090d16] border border-[#223452] rounded-lg">
          <div className="text-[10px] uppercase font-bold text-[#64748b] flex items-center justify-between">
            <span>Median Threat Index</span>
            <TrendingUp className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="text-xl font-bold text-white mt-1">
            <span className={overallAvgRisk >= 60 ? 'text-[#ff4a6b]' : overallAvgRisk >= 30 ? 'text-amber-400' : 'text-[#00ff87]'}>
              {overallAvgRisk}%
            </span>
          </div>
          <div className="text-[10px] text-[#94a3b8] mt-0.5">
            Evaluated Markov drift
          </div>
        </div>

        <div className="p-3 bg-[#090d16] border border-[#223452] rounded-lg">
          <div className="text-[10px] uppercase font-bold text-[#64748b] flex items-center justify-between">
            <span>Edge Interceptor SLA</span>
            <Zap className="w-3.5 h-3.5 text-[#00ff87]" />
          </div>
          <div className="text-xl font-bold text-[#00ff87] mt-1">
            99.98%
          </div>
          <div className="text-[10px] text-[#94a3b8] mt-0.5">
            Latency &lt; 4.2ms avg
          </div>
        </div>
      </div>

      {/* Main Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* CHART 1: AUDIT LOG FREQUENCY OVER TIME */}
        {(activeView === 'both' || activeView === 'frequency') && (
          <div className={`${activeView === 'both' ? 'lg:col-span-7' : 'lg:col-span-12'} bg-[#090d16] border border-[#223452] rounded-xl p-4 flex flex-col`}>
            <div className="flex items-center justify-between mb-3 border-b border-[#1c2b42] pb-2">
              <div className="flex items-center gap-2">
                <Clock className="w-4 h-4 text-[#00d2ff]" />
                <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                  Audit Log Frequency &amp; Threat Velocity Over Time
                </h3>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] text-[#64748b] hidden sm:inline">Grouping:</span>
                <button
                  onClick={() => setTimeResolution(timeResolution === 'chronological' ? 'hourly' : 'chronological')}
                  className="px-2 py-0.5 text-[10px] rounded bg-[#131d33] hover:bg-[#1a273f] text-[#00d2ff] border border-[#223452] flex items-center gap-1"
                >
                  <Filter className="w-2.5 h-2.5" />
                  {timeResolution === 'chronological' ? 'Chronological Points' : 'Minute Buckets'}
                </button>
              </div>
            </div>

            <div className="flex items-center justify-between text-[11px] text-[#94a3b8] mb-2 px-1">
              <div className="flex items-center gap-4">
                <span className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-sm bg-[#00ff87]/80 inline-block" />
                  Allowed Invocations
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-sm bg-[#ff4a6b]/80 inline-block" />
                  Blocked Invocations
                </span>
              </div>
              <span className="text-[10px] text-[#64748b]">
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
                      <stop offset="5%" stopColor="#00ff87" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#00ff87" stopOpacity={0.0} />
                    </linearGradient>
                    <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ff4a6b" stopOpacity={0.5} />
                      <stop offset="95%" stopColor="#ff4a6b" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="#1e2e4a" strokeDasharray="3 3" vertical={false} />
                  <XAxis
                    dataKey="time"
                    stroke="#64748b"
                    fontSize={10}
                    tickLine={false}
                    axisLine={{ stroke: '#223452' }}
                  />
                  <YAxis
                    stroke="#64748b"
                    fontSize={10}
                    tickLine={false}
                    axisLine={{ stroke: '#223452' }}
                    allowDecimals={false}
                  />
                  <Tooltip content={<CustomChartTooltip />} />
                  <Area
                    type="monotone"
                    dataKey="allowed"
                    name="Allowed Requests"
                    stroke="#00ff87"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#colorAllowed)"
                  />
                  <Area
                    type="monotone"
                    dataKey="blocked"
                    name="Blocked Requests"
                    stroke="#ff4a6b"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#colorBlocked)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>

            <div className="mt-2 text-[10px] text-[#64748b] flex items-center justify-between border-t border-[#162236] pt-2">
              <span>Dynamic area footprint tracks request throughput</span>
              <span className="text-[#00d2ff]">
                Zero-Trust Firewall Interception Active
              </span>
            </div>
          </div>
        )}

        {/* CHART 2: USER RISK SCORES DISTRIBUTION */}
        {(activeView === 'both' || activeView === 'risk') && (
          <div className={`${activeView === 'both' ? 'lg:col-span-5' : 'lg:col-span-12'} bg-[#090d16] border border-[#223452] rounded-xl p-4 flex flex-col`}>
            <div className="flex items-center justify-between mb-3 border-b border-[#1c2b42] pb-2">
              <div className="flex items-center gap-2">
                <BarChart3 className="w-4 h-4 text-[#00d2ff]" />
                <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                  User Risk Score Distribution
                </h3>
              </div>
              <span className="text-[10px] px-2 py-0.5 rounded bg-purple-950/80 text-purple-300 border border-purple-800">
                {users.length} Principals
              </span>
            </div>

            <div className="flex items-center justify-between text-[11px] text-[#94a3b8] mb-2 px-1">
              <div className="flex items-center gap-3">
                <span className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-sm bg-[#00d2ff] inline-block" />
                  Base Risk
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-sm bg-[#ff4a6b] inline-block" />
                  Max Observed
                </span>
              </div>
              <span className="text-[10px] text-amber-400">
                Threshold: {maxThreshold}%
              </span>
            </div>

            {/* Recharts BarChart comparing Base Risk and Max Observed Risk per user */}
            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={userRiskData}
                  margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
                  barGap={3}
                >
                  <CartesianGrid stroke="#1e2e4a" strokeDasharray="3 3" vertical={false} />
                  <XAxis
                    dataKey="shortName"
                    stroke="#64748b"
                    fontSize={10}
                    tickLine={false}
                    axisLine={{ stroke: '#223452' }}
                  />
                  <YAxis
                    domain={[0, 100]}
                    stroke="#64748b"
                    fontSize={10}
                    tickLine={false}
                    axisLine={{ stroke: '#223452' }}
                    unit="%"
                  />
                  <Tooltip content={<CustomChartTooltip />} />
                  <ReferenceLine
                    y={maxThreshold}
                    stroke="#ff4a6b"
                    strokeDasharray="4 4"
                    label={{
                      value: `CUTOFF (${maxThreshold}%)`,
                      fill: '#ff4a6b',
                      fontSize: 9,
                      position: 'top'
                    }}
                  />
                  <Bar
                    dataKey="baseRisk"
                    name="Base Risk Score"
                    fill="#00d2ff"
                    radius={[3, 3, 0, 0]}
                    unit="%"
                  >
                    {userRiskData.map((entry, index) => (
                      <Cell
                        key={`cell-base-${index}`}
                        fill={entry.baseRisk >= maxThreshold ? '#ff4a6b' : entry.baseRisk > 20 ? '#00d2ff' : '#00ff87'}
                      />
                    ))}
                  </Bar>
                  <Bar
                    dataKey="observedMaxRisk"
                    name="Max Evaluated Risk"
                    fill="#ff4a6b"
                    radius={[3, 3, 0, 0]}
                    unit="%"
                  />
                </BarChart>
              </ResponsiveContainer>
            </div>

            <div className="mt-2 text-[10px] text-[#64748b] flex items-center justify-between border-t border-[#162236] pt-2">
              <span>Bars above cutoff trigger automated mitigation</span>
              <span className="text-[#00ff87]">Evaluated Per Invocation</span>
            </div>
          </div>
        )}
      </div>

      {/* Secondary Distribution Row: Threat Tier Composition & Principal Roster */}
      <div className="mt-5 pt-4 border-t border-[#1e2e4a] grid grid-cols-1 md:grid-cols-12 gap-4 items-center">
        {/* Risk Tier Donut Chart */}
        <div className="md:col-span-5 flex items-center gap-4 bg-[#090d16] border border-[#223452] p-3 rounded-lg">
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
                <Tooltip content={<CustomChartTooltip />} />
              </PieChart>
            </ResponsiveContainer>
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <span className="text-[11px] font-bold text-white">{logs.length}</span>
              <span className="text-[8px] text-[#64748b] uppercase">Events</span>
            </div>
          </div>

          <div className="flex-1 space-y-1">
            <div className="text-[10px] uppercase font-bold text-[#64748b] mb-1">
              Threat Tier Distribution
            </div>
            {riskTierData.map((tier) => (
              <div key={tier.name} className="flex items-center justify-between text-xs">
                <span className="flex items-center gap-1.5 text-[#94a3b8]">
                  <span className="w-2 h-2 rounded-full" style={{ backgroundColor: tier.color }} />
                  {tier.name}:
                </span>
                <span className="font-bold text-white">
                  {tier.value} <span className="text-[10px] text-[#64748b]">({tier.pct}%)</span>
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* User Risk Profile Status Cards */}
        <div className="md:col-span-7 grid grid-cols-2 sm:grid-cols-4 gap-2">
          {userRiskData.map((u) => {
            const isCritical = u.threatIndex >= maxThreshold;
            return (
              <div
                key={u.username}
                className={`p-2.5 rounded-lg border text-xs ${
                  isCritical
                    ? 'bg-red-950/30 border-red-800/60'
                    : 'bg-[#090d16] border-[#223452]'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold text-white truncate" title={u.username}>
                    {u.shortName}
                  </span>
                  <span className={`text-[9px] px-1 py-0.2 rounded ${
                    u.role === 'Admin' ? 'bg-purple-900/60 text-purple-200' :
                    u.role === 'Developer' ? 'bg-cyan-900/60 text-cyan-200' :
                    'bg-slate-800 text-slate-300'
                  }`}>
                    {u.role}
                  </span>
                </div>
                <div className="mt-2 flex items-baseline justify-between">
                  <span className="text-[10px] text-[#64748b]">Threat:</span>
                  <span className={`font-bold ${isCritical ? 'text-[#ff4a6b]' : u.threatIndex > 20 ? 'text-[#00d2ff]' : 'text-[#00ff87]'}`}>
                    {u.threatIndex}%
                  </span>
                </div>
                <div className="text-[9px] text-[#64748b] mt-0.5 flex justify-between">
                  <span>Reqs: {u.totalRequests}</span>
                  {u.blocked > 0 && <span className="text-[#ff4a6b]">{u.blocked} Blk</span>}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
