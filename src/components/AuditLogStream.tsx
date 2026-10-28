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
  Check,
  X,
  SlidersHorizontal,
  ChevronDown,
  AlertTriangle,
  Layers,
  UserCheck
} from 'lucide-react';
import { SecurityAuditLog } from '../types.ts';
import { useTheme } from '../context/ThemeContext.tsx';

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
  const [searchQuery, setSearchQuery] = useState('');
  const [filterVerdict, setFilterVerdict] = useState<'ALL' | 'ALLOWED' | 'BLOCKED'>('ALL');
  const [filterSeverity, setFilterSeverity] = useState<RiskSeverityFilter>('ALL');
  const [filterFunction, setFilterFunction] = useState<string>('ALL');
  const [filterPrincipal, setFilterPrincipal] = useState<string>('ALL');
  const [minRiskThreshold, setMinRiskThreshold] = useState<number>(0);
  const [downloadSuccess, setDownloadSuccess] = useState(false);
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

  return (
    <div className="bg-[#131c2e] border border-[#223452] p-4 sm:p-5 rounded-xl flex flex-col h-full font-mono shadow-sm">
      {/* 1. Header and Primary Actions */}
      <div className="border-b border-[#223452] pb-3 mb-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <Shield className="w-4 h-4 text-[#00ff87]" />
            Real-Time Framework Audit Streams &amp; Risk Visualizer
          </h3>
          <p className="text-[11px] text-[#6b7c96] mt-0.5">
            Cryptographic ledger tracking identity tokens, Markov sequences &amp; dynamic risk scoring
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <button
            id="btn-download-csv"
            onClick={handleDownloadCSV}
            disabled={filteredLogs.length === 0}
            className={`px-2.5 py-1.5 rounded bg-[#090d16] hover:bg-[#1a273f] border border-[#223452] text-xs flex items-center gap-1.5 transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${
              downloadSuccess ? 'text-[#00ff87] border-[#00ff87]/50' : 'text-[#94a3b8] hover:text-[#00ff87]'
            }`}
            title={
              filteredLogs.length > 0
                ? `Export ${filteredLogs.length} currently filtered logs to CSV`
                : 'No logs currently match filters to download'
            }
          >
            {downloadSuccess ? (
              <>
                <Check className="w-3.5 h-3.5 text-[#00ff87]" />
                <span className="text-[#00ff87]">Downloaded!</span>
              </>
            ) : (
              <>
                <Download className="w-3.5 h-3.5 text-[#00ff87]" />
                <span>Export CSV ({filteredLogs.length})</span>
              </>
            )}
          </button>

          <button
            id="btn-refresh-logs"
            onClick={onRefresh}
            disabled={isRefreshing}
            className="px-2.5 py-1.5 rounded bg-[#090d16] hover:bg-[#1a273f] text-[#94a3b8] hover:text-white border border-[#223452] text-xs flex items-center gap-1 transition-colors disabled:opacity-50"
            title="Refresh logs from database"
          >
            <RefreshCw className={`w-3 h-3 text-[#00d2ff] ${isRefreshing ? 'animate-spin' : ''}`} />
            <span>Sync</span>
          </button>
        </div>
      </div>

      {/* 2. Summary KPI Cards with Mini Visuals */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 mb-4">
        <div className="bg-[#090d16] border border-[#223452] p-2.5 rounded-lg">
          <div className="text-[10px] text-[#6b7c96] uppercase flex items-center justify-between">
            <span>Total Streams</span>
            <Activity className="w-3 h-3 text-[#00d2ff]" />
          </div>
          <div className="text-lg font-bold text-white mt-1">{stats.total}</div>
          <div className="text-[10px] text-slate-500 mt-0.5">
            {filteredLogs.length} in current view
          </div>
        </div>

        <div className="bg-[#090d16] border border-[#223452] p-2.5 rounded-lg">
          <div className="text-[10px] text-[#6b7c96] uppercase flex items-center justify-between">
            <span>Allowed</span>
            <CheckCircle className="w-3 h-3 text-[#00ff87]" />
          </div>
          <div className="text-lg font-bold text-[#00ff87] mt-1">{stats.allowed}</div>
          <div className="text-[10px] text-emerald-400/80 mt-0.5">
            {stats.total > 0 ? Math.round((stats.allowed / stats.total) * 100) : 100}% Pass Rate
          </div>
        </div>

        <div className="bg-[#090d16] border border-[#223452] p-2.5 rounded-lg">
          <div className="text-[10px] text-[#6b7c96] uppercase flex items-center justify-between">
            <span>Intercepted</span>
            <AlertOctagon className="w-3 h-3 text-[#ff4a6b]" />
          </div>
          <div className="text-lg font-bold text-[#ff4a6b] mt-1">{stats.blocked}</div>
          <div className="text-[10px] text-rose-400/80 mt-0.5">
            {stats.criticalCount} Critical (≥75%)
          </div>
        </div>

        <div className="bg-[#090d16] border border-[#223452] p-2.5 rounded-lg">
          <div className="text-[10px] text-[#6b7c96] uppercase flex items-center justify-between">
            <span>Avg Risk Score</span>
            <Flame className="w-3 h-3 text-amber-400" />
          </div>
          <div className="text-lg font-bold text-amber-400 mt-1">{stats.avgRisk}%</div>
          {/* Mini Gradient Progress Bar */}
          <div className="w-full bg-slate-900 h-1.5 rounded-full overflow-hidden mt-1.5 border border-slate-800">
            <div
              className={`h-full transition-all duration-300 ${
                stats.avgRisk >= 75 ? 'bg-rose-500' : stats.avgRisk >= 50 ? 'bg-amber-400' : stats.avgRisk >= 25 ? 'bg-cyan-400' : 'bg-emerald-400'
              }`}
              style={{ width: `${Math.min(stats.avgRisk, 100)}%` }}
            />
          </div>
        </div>
      </div>

      {/* 3. INTERACTIVE RISK SPECTRUM VISUALIZER (CLICK TO FILTER) */}
      <div className="bg-[#090d16] border border-[#223452] rounded-lg p-3 mb-3">
        <div className="flex items-center justify-between text-[11px] mb-2">
          <span className="text-slate-400 font-semibold flex items-center gap-1.5">
            <SlidersHorizontal className="w-3 h-3 text-[#00d2ff]" />
            Risk Spectrum Distribution (Click Tier to Filter)
          </span>
          <span className="text-[10px] text-slate-500">
            {logs.length} Total Events Evaluated
          </span>
        </div>

        {/* Segmented Gradient Distribution Bar */}
        <div className="h-3 w-full rounded-md overflow-hidden flex bg-slate-900 border border-slate-800 cursor-pointer">
          {riskSpectrum.low.count > 0 && (
            <div
              onClick={() => setFilterSeverity(filterSeverity === 'LOW' ? 'ALL' : 'LOW')}
              style={{ width: `${riskSpectrum.low.pct}%` }}
              className={`h-full bg-emerald-500 hover:brightness-125 transition-all ${
                filterSeverity === 'LOW' ? 'ring-2 ring-white ring-inset' : ''
              }`}
              title={`Nominal Low Risk (<25%): ${riskSpectrum.low.count} events (${riskSpectrum.low.pct}%)`}
            />
          )}
          {riskSpectrum.moderate.count > 0 && (
            <div
              onClick={() => setFilterSeverity(filterSeverity === 'MODERATE' ? 'ALL' : 'MODERATE')}
              style={{ width: `${riskSpectrum.moderate.pct}%` }}
              className={`h-full bg-[#00d2ff] hover:brightness-125 transition-all ${
                filterSeverity === 'MODERATE' ? 'ring-2 ring-white ring-inset' : ''
              }`}
              title={`Moderate Risk (25-49%): ${riskSpectrum.moderate.count} events (${riskSpectrum.moderate.pct}%)`}
            />
          )}
          {riskSpectrum.elevated.count > 0 && (
            <div
              onClick={() => setFilterSeverity(filterSeverity === 'ELEVATED' ? 'ALL' : 'ELEVATED')}
              style={{ width: `${riskSpectrum.elevated.pct}%` }}
              className={`h-full bg-amber-400 hover:brightness-125 transition-all ${
                filterSeverity === 'ELEVATED' ? 'ring-2 ring-white ring-inset' : ''
              }`}
              title={`Elevated Risk (50-74%): ${riskSpectrum.elevated.count} events (${riskSpectrum.elevated.pct}%)`}
            />
          )}
          {riskSpectrum.critical.count > 0 && (
            <div
              onClick={() => setFilterSeverity(filterSeverity === 'CRITICAL' ? 'ALL' : 'CRITICAL')}
              style={{ width: `${riskSpectrum.critical.pct}%` }}
              className={`h-full bg-[#ff4a6b] hover:brightness-125 transition-all ${
                filterSeverity === 'CRITICAL' ? 'ring-2 ring-white ring-inset' : ''
              }`}
              title={`Critical Risk (≥75%): ${riskSpectrum.critical.count} events (${riskSpectrum.critical.pct}%)`}
            />
          )}
        </div>

        {/* Legend / Interactive Chips */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mt-2.5 text-[10px]">
          <button
            onClick={() => setFilterSeverity(filterSeverity === 'LOW' ? 'ALL' : 'LOW')}
            className={`p-1.5 rounded border flex items-center justify-between transition-all ${
              filterSeverity === 'LOW'
                ? 'bg-emerald-500/20 border-emerald-400 text-emerald-300 ring-1 ring-emerald-400'
                : 'bg-[#131c2e] border-slate-800 text-slate-400 hover:border-emerald-500/40'
            }`}
          >
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400" />
              Low (&lt;25%)
            </span>
            <span className="font-bold text-white">{riskSpectrum.low.count}</span>
          </button>

          <button
            onClick={() => setFilterSeverity(filterSeverity === 'MODERATE' ? 'ALL' : 'MODERATE')}
            className={`p-1.5 rounded border flex items-center justify-between transition-all ${
              filterSeverity === 'MODERATE'
                ? 'bg-cyan-500/20 border-cyan-400 text-cyan-300 ring-1 ring-cyan-400'
                : 'bg-[#131c2e] border-slate-800 text-slate-400 hover:border-cyan-500/40'
            }`}
          >
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-[#00d2ff]" />
              Moderate (25-49%)
            </span>
            <span className="font-bold text-white">{riskSpectrum.moderate.count}</span>
          </button>

          <button
            onClick={() => setFilterSeverity(filterSeverity === 'ELEVATED' ? 'ALL' : 'ELEVATED')}
            className={`p-1.5 rounded border flex items-center justify-between transition-all ${
              filterSeverity === 'ELEVATED'
                ? 'bg-amber-500/20 border-amber-400 text-amber-300 ring-1 ring-amber-400'
                : 'bg-[#131c2e] border-slate-800 text-slate-400 hover:border-amber-500/40'
            }`}
          >
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-amber-400" />
              Elevated (50-74%)
            </span>
            <span className="font-bold text-white">{riskSpectrum.elevated.count}</span>
          </button>

          <button
            onClick={() => setFilterSeverity(filterSeverity === 'CRITICAL' ? 'ALL' : 'CRITICAL')}
            className={`p-1.5 rounded border flex items-center justify-between transition-all ${
              filterSeverity === 'CRITICAL'
                ? 'bg-rose-500/20 border-rose-400 text-rose-300 ring-1 ring-rose-400'
                : 'bg-[#131c2e] border-slate-800 text-slate-400 hover:border-rose-500/40'
            }`}
          >
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-[#ff4a6b]" />
              Critical (≥75%)
            </span>
            <span className="font-bold text-white">{riskSpectrum.critical.count}</span>
          </button>
        </div>
      </div>

      {/* 4. Filter & Search Controls Bar */}
      <div className="space-y-2 mb-3">
        <div className="flex flex-col sm:flex-row gap-2">
          {/* Text Search Field */}
          <div className="relative flex-1">
            <Search className="w-3.5 h-3.5 text-[#6b7c96] absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search principal, function route, risk score or heuristic reason..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-8 pr-8 py-1.5 bg-[#090d16] border border-[#223452] text-white text-xs rounded focus:outline-none focus:border-[#00d2ff]"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-2.5 top-2.5 text-slate-500 hover:text-white"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          {/* Verdict Filter Buttons */}
          <div className="flex items-center gap-1 text-xs">
            <span className="text-[10px] text-[#6b7c96] uppercase mr-1 hidden md:inline">Verdict:</span>
            {(['ALL', 'ALLOWED', 'BLOCKED'] as const).map((v) => (
              <button
                key={v}
                onClick={() => setFilterVerdict(v)}
                className={`px-2.5 py-1 rounded text-[11px] font-bold border transition-colors ${
                  filterVerdict === v
                    ? v === 'ALLOWED'
                      ? 'bg-[#00ff87]/20 border-[#00ff87] text-[#00ff87]'
                      : v === 'BLOCKED'
                      ? 'bg-[#ff4a6b]/20 border-[#ff4a6b] text-[#ff4a6b]'
                      : 'bg-[#00d2ff]/20 border-[#00d2ff] text-[#00d2ff]'
                    : 'bg-[#090d16] border-[#223452] text-[#94a3b8] hover:border-[#334e78]'
                }`}
              >
                {v}
              </button>
            ))}

            {/* Toggle Advanced Filters */}
            <button
              onClick={() => setShowAdvancedFilters(!showAdvancedFilters)}
              className={`px-2.5 py-1 rounded border text-[11px] flex items-center gap-1 transition-colors ${
                showAdvancedFilters || hasActiveFilters
                  ? 'bg-blue-500/20 border-blue-500 text-blue-300'
                  : 'bg-[#090d16] border-[#223452] text-slate-400 hover:text-white'
              }`}
              title="Toggle additional filter dimensions"
            >
              <Filter className="w-3 h-3" />
              <span>Filters</span>
              {hasActiveFilters && (
                <span className="w-1.5 h-1.5 rounded-full bg-blue-400 ml-0.5" />
              )}
            </button>
          </div>
        </div>

        {/* Collapsible Advanced Filtering Row */}
        {showAdvancedFilters && (
          <div className="p-3 bg-[#090d16] border border-[#223452] rounded-lg grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs animate-in fade-in duration-150">
            {/* Function Filter Dropdown */}
            <div>
              <label className="block text-[10px] uppercase text-[#6b7c96] font-semibold mb-1">
                Function Path:
              </label>
              <select
                value={filterFunction}
                onChange={(e) => setFilterFunction(e.target.value)}
                className="w-full px-2 py-1 bg-[#131c2e] border border-[#223452] text-white text-xs rounded focus:outline-none focus:border-[#00d2ff]"
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
              <label className="block text-[10px] uppercase text-[#6b7c96] font-semibold mb-1">
                Principal Identity:
              </label>
              <select
                value={filterPrincipal}
                onChange={(e) => setFilterPrincipal(e.target.value)}
                className="w-full px-2 py-1 bg-[#131c2e] border border-[#223452] text-white text-xs rounded focus:outline-none focus:border-[#00d2ff]"
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
              <div className="flex items-center justify-between text-[10px] uppercase text-[#6b7c96] font-semibold mb-1">
                <span>Minimum Risk Filter:</span>
                <span className="text-amber-400 font-bold">{minRiskThreshold}%</span>
              </div>
              <input
                type="range"
                min={0}
                max={100}
                step={5}
                value={minRiskThreshold}
                onChange={(e) => setMinRiskThreshold(Number(e.target.value))}
                className="w-full accent-[#00d2ff] h-1.5 bg-[#131c2e] rounded-lg cursor-pointer"
              />
            </div>
          </div>
        )}

        {/* Active Filter Indicator Tag Bar */}
        {hasActiveFilters && (
          <div className="flex items-center justify-between bg-[#090d16] px-3 py-1.5 rounded border border-[#223452] text-xs">
            <div className="flex items-center gap-1.5 flex-wrap text-[11px]">
              <span className="text-slate-500">Active Filters:</span>
              {searchQuery && (
                <span className="px-1.5 py-0.5 rounded bg-blue-500/15 text-blue-300 border border-blue-500/30">
                  Search: "{searchQuery}"
                </span>
              )}
              {filterVerdict !== 'ALL' && (
                <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                  Verdict: {filterVerdict}
                </span>
              )}
              {filterSeverity !== 'ALL' && (
                <span className="px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/30">
                  Tier: {filterSeverity}
                </span>
              )}
              {filterFunction !== 'ALL' && (
                <span className="px-1.5 py-0.5 rounded bg-purple-500/15 text-purple-300 border border-purple-500/30">
                  Route: {filterFunction}
                </span>
              )}
              {filterPrincipal !== 'ALL' && (
                <span className="px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                  User: {filterPrincipal}
                </span>
              )}
              {minRiskThreshold > 0 && (
                <span className="px-1.5 py-0.5 rounded bg-rose-500/15 text-rose-300 border border-rose-500/30">
                  Risk &ge; {minRiskThreshold}%
                </span>
              )}
            </div>

            <button
              onClick={handleResetFilters}
              className="text-[11px] text-[#00d2ff] hover:underline flex items-center gap-1 shrink-0 ml-2"
            >
              <X className="w-3 h-3" />
              Reset All
            </button>
          </div>
        )}
      </div>

      {/* 5. Enhanced Table Container with Visual Risk Meters */}
      <div className="overflow-x-auto flex-1 max-h-[540px] rounded border border-[#1e293b]">
        <table className="w-full border-collapse text-left text-xs">
          <thead className="bg-[#090d16] sticky top-0 z-10">
            <tr className="border-b border-[#1e293b] text-[#6b7c96] uppercase text-[10px] tracking-wider">
              <th className="p-3">Time</th>
              <th className="p-3">Principal</th>
              <th className="p-3">Function Path</th>
              <th className="p-3">Risk Visual Score</th>
              <th className="p-3">Latency Overhead</th>
              <th className="p-3">Verdict</th>
              <th className="p-3">Engine Mitigation Heuristics &amp; Behavioral Events</th>
            </tr>
          </thead>
          <tbody id="logs" className="divide-y divide-[#1e293b]">
            {filteredLogs.length === 0 ? (
              <tr>
                <td colSpan={6} className="text-center text-[#4a5d78] py-12">
                  {logs.length === 0 ? (
                    'No operational triggers executed yet. Fire the pipeline.'
                  ) : (
                    <div className="space-y-1">
                      <p>No audit records match the selected filter criteria.</p>
                      <button
                        onClick={handleResetFilters}
                        className="text-xs text-[#00d2ff] hover:underline"
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
                const formattedTime = new Date(item.timestamp).toLocaleTimeString();
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
                  ? 'bg-[#ff4a6b]'
                  : isElevated
                  ? 'bg-amber-400'
                  : isModerate
                  ? 'bg-[#00d2ff]'
                  : 'bg-[#00ff87]';

                const riskTierLabel = isCritical
                  ? 'CRITICAL'
                  : isElevated
                  ? 'ELEVATED'
                  : isModerate
                  ? 'MODERATE'
                  : 'NOMINAL';

                return (
                  <tr
                    key={item.id}
                    className="hover:bg-[#1a273f]/60 transition-colors group"
                  >
                    <td className="p-3 text-[#94a3b8] whitespace-nowrap">{formattedTime}</td>
                    <td className="p-3 font-semibold text-white whitespace-nowrap">
                      <button
                        onClick={() => setFilterPrincipal(item.username)}
                        className="hover:text-[#00d2ff] transition-colors"
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
                        <code className="text-[#00d2ff] bg-[#00d2ff]/10 px-1.5 py-0.5 rounded border border-[#00d2ff]/20 hover:border-[#00d2ff]/50 transition-colors">
                          {item.requested_function}
                        </code>
                      </button>
                    </td>
                    <td className="p-3 whitespace-nowrap">
                      {/* Visual Risk Gauge & Tier Indicator */}
                      <div className="flex flex-col gap-1 min-w-[120px]">
                        <div className="flex items-center justify-between gap-2">
                          <span className={`font-bold ${riskColor}`}>
                            {risk}%
                          </span>
                          <span
                            className={`text-[9px] px-1.5 py-0.2 rounded font-bold uppercase tracking-wider ${
                              isCritical
                                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                                : isElevated
                                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                                : isModerate
                                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                                : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
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
                                  isFilled ? riskBgColor : 'bg-slate-800'
                                }`}
                              />
                            );
                          })}
                        </div>
                      </div>
                    </td>
                    <td className="p-3 whitespace-nowrap">
                      {item.verification_latency_ms !== undefined ? (
                        <div className="inline-flex items-center gap-1.5 px-2 py-1 rounded-md font-mono text-xs font-semibold bg-cyan-950/40 text-cyan-300 border border-cyan-800/50">
                          <Activity className="w-3 h-3 text-cyan-400 animate-pulse" />
                          <span>{item.verification_latency_ms} ms</span>
                        </div>
                      ) : (
                        <span className="text-slate-500 font-mono text-[11px]">&lt; 1.0 ms</span>
                      )}
                    </td>
                    <td className="p-3 whitespace-nowrap">
                      <span
                        className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                          isBlocked
                            ? 'bg-[#ff4a6b]/15 text-[#ff4a6b] border border-[#ff4a6b]/30'
                            : 'bg-[#00ff87]/15 text-[#00ff87] border border-[#00ff87]/30'
                        }`}
                      >
                        {isBlocked ? (
                          <AlertOctagon className="w-2.5 h-2.5" />
                        ) : (
                          <CheckCircle className="w-2.5 h-2.5" />
                        )}
                        {item.status}
                      </span>
                    </td>
                    <td className="p-3 text-[#a0aec0] leading-relaxed max-w-xs sm:max-w-md">
                      <div className="space-y-1">
                        <div>{item.reason}</div>
                        {/* Behavioral Badges for Review Panel */}
                        <div className="flex items-center gap-1.5 flex-wrap pt-0.5">
                          {item.event_type === 'ABNORMAL_REQUEST_RATE' && (
                            <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40 font-bold uppercase tracking-wider">
                              ABNORMAL_REQUEST_RATE (+20 RISK)
                            </span>
                          )}
                          {(item.event_type === 'SECURITY_EXCEPTION_FAIL_CLOSED' || item.reason?.includes('FAIL-CLOSED')) && (
                            <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-rose-500/25 text-rose-300 border border-rose-500/50 font-bold uppercase tracking-wider">
                              FAIL-CLOSED GUARANTEE (CRITICAL 100)
                            </span>
                          )}
                          {item.event_type === 'SEQUENCE_VIOLATION' && (
                            <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-purple-500/20 text-purple-300 border border-purple-500/40 font-bold uppercase tracking-wider">
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
    </div>
  );
};
